//! `awg` carrier: our own UDP obfuscation envelope in the shape of AmneziaWG's DPI-resistance ideas
//! (junk before the handshake, padded messages, ranged type words), keyed from the invite. No
//! third-party code and NOT wire-compatible with AmneziaWG. Obfuscation only: the sealed frame
//! inside is already authenticated, so anything that fails the envelope check is dropped silently.
//!
//! Datagram = `nonce(12) || mask(P)`, `P = type(4) | padlen(2) | tag(4) | frame | zero pad`.
//! `mask` is the ChaCha20 keystream under a per-invite key and the per-packet nonce, so the whole
//! datagram (type, pad length, frame) looks like random bytes of varying length. `tag` is a keyed
//! 32-bit check that drops garbage/tampering. Every parameter derives from the invite key via
//! HKDF info `strait-awg-v1`, so both sides agree without negotiation and each invite differs.
//! Design notes: docs/TUNNEL_CARRIERS.md, "awg carrier as built".

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::udp::UdpCarrier;
use super::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, Caps, FrameIo, Health, Rng};
use crate::rendezvous::{Disclosure, ProbeStatus};

const NONCE: usize = 12;
/// type(4) + padlen(2) + tag(4)
const INNER_HDR: usize = 10;
pub const HDR: usize = NONCE + INNER_HDR;

/// Everything derived from the invite key. Public so tests can compare invites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwgParams {
    /// Type-word ranges (inclusive) for normal and bucketed (small) frames.
    pub data_type: (u32, u32),
    pub ctl_type: (u32, u32),
    /// Padding range for frames longer than `small_max`.
    pub pad_min: usize,
    pub pad_max: usize,
    /// Frames up to this size are rounded up to a multiple of `bucket`, plus 0..=`small_extra`.
    pub small_max: usize,
    pub bucket: usize,
    pub small_extra: usize,
    /// Junk burst before the first real frame to a peer (client side).
    pub junk_count: usize,
    pub junk_min: usize,
    pub junk_max: usize,
}

impl AwgParams {
    /// Worst-case bytes the envelope adds to one frame.
    pub fn overhead(&self) -> usize {
        HDR + self.pad_max.max(self.bucket - 1 + self.small_extra)
    }
}

struct Keys {
    mask: ChaCha20Poly1305,
    tag: [u8; 32],
    params: AwgParams,
}

fn derive(key: &[u8]) -> Keys {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut o = [0u8; 96];
    hk.expand(b"strait-awg-v1", &mut o).expect("96 bytes is a valid HKDF length");
    let u32at = |i: usize| u32::from_le_bytes(o[64 + i..68 + i].try_into().unwrap());
    let range = |v: u32| {
        let lo = v.min(u32::MAX - 0xFFFF);
        (lo, lo + 0xFFFF)
    };
    let pad_min = (u32at(8) % 9) as usize;
    let params = AwgParams {
        data_type: range(u32at(0)),
        ctl_type: range(u32at(4)),
        pad_min,
        pad_max: pad_min + 16 + (u32at(12) % 49) as usize,
        small_max: 80 + (u32at(16) % 48) as usize,
        bucket: 16 + 8 * (u32at(20) % 3) as usize,
        small_extra: (u32at(24) % 17) as usize,
        junk_count: 3 + (u32at(28) % 5) as usize,
        junk_min: 24 + (u32at(0) >> 8) as usize % 40,
        junk_max: 0,
    };
    let junk_max = params.junk_min + 100 + (u32at(4) >> 8) as usize % 500;
    Keys {
        mask: ChaCha20Poly1305::new(Key::from_slice(&o[..32])),
        tag: o[32..64].try_into().unwrap(),
        params: AwgParams { junk_max, ..params },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the junk burst before its first real frame to each peer.
    Client,
    /// Never sends junk; drops whatever does not verify and never answers it.
    Host,
}

pub struct AwgCarrier {
    inner: Arc<dyn FrameIo>,
    keys: Keys,
    key: Vec<u8>,
    role: Role,
    rng: Mutex<Rng>,
    junked: Mutex<HashSet<SocketAddr>>,
    scratch: Mutex<Vec<u8>>,
    rejected: super::Rejects,
}

impl AwgCarrier {
    /// Wrap any datagram carrier (raw UDP, the in-memory test link).
    pub fn wrap(inner: Arc<dyn FrameIo>, key: &[u8], role: Role) -> Self {
        Self::wrap_seeded(inner, key, role, None)
    }

    /// `seed` fixes padding/junk decisions for statistical tests; nonces are always fresh.
    pub fn wrap_seeded(inner: Arc<dyn FrameIo>, key: &[u8], role: Role, seed: Option<u64>) -> Self {
        let rng = seed.map(Rng::new).unwrap_or_else(entropy_rng);
        Self {
            inner,
            keys: derive(key),
            key: key.to_vec(),
            role,
            rng: Mutex::new(rng),
            junked: Mutex::new(HashSet::new()),
            scratch: Mutex::new(vec![0u8; 65536]),
            rejected: Default::default(),
        }
    }

    pub fn params(&self) -> &AwgParams {
        &self.keys.params
    }

    fn tag(&self, nonce: &[u8], p: &[u8]) -> [u8; 4] {
        // p has its tag field zeroed by the caller.
        let mut h = Sha256::new();
        h.update(self.keys.tag);
        h.update(nonce);
        h.update(p);
        h.finalize()[..4].try_into().unwrap()
    }

    fn seal(&self, frame: &[u8]) -> Vec<u8> {
        let pr = &self.keys.params;
        let (nonce, pad, ty) = {
            let mut r = self.rng.lock().unwrap();
            let pad = if frame.len() <= pr.small_max {
                (pr.bucket - frame.len() % pr.bucket) % pr.bucket + r.below(pr.small_extra as u64 + 1) as usize
            } else {
                pr.pad_min + r.below((pr.pad_max - pr.pad_min) as u64 + 1) as usize
            };
            let (lo, hi) = if frame.len() <= pr.small_max { pr.ctl_type } else { pr.data_type };
            (fresh_nonce(), pad, lo + r.below(hi as u64 - lo as u64 + 1) as u32)
        };
        let mut p = vec![0u8; INNER_HDR + frame.len() + pad];
        p[..4].copy_from_slice(&ty.to_le_bytes());
        p[4..6].copy_from_slice(&(pad as u16).to_le_bytes());
        p[INNER_HDR..INNER_HDR + frame.len()].copy_from_slice(frame);
        let t = self.tag(&nonce, &p);
        p[6..10].copy_from_slice(&t);
        let _ = self.keys.mask.encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut p);
        let mut out = Vec::with_capacity(NONCE + p.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&p);
        out
    }

    /// The sealed frame inside a datagram, or `None` for anything that does not verify.
    fn open(&self, dg: &[u8]) -> Option<Vec<u8>> {
        if dg.len() < HDR {
            return None;
        }
        let (nonce, body) = dg.split_at(NONCE);
        let mut p = body.to_vec();
        let _ = self.keys.mask.encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut p);
        let ty = u32::from_le_bytes(p[..4].try_into().unwrap());
        let pad = u16::from_le_bytes(p[4..6].try_into().unwrap()) as usize;
        let got: [u8; 4] = p[6..10].try_into().unwrap();
        p[6..10].fill(0);
        let pr = &self.keys.params;
        let in_range = |r: (u32, u32)| ty >= r.0 && ty <= r.1;
        // Compute the tag before branching on the cheap checks so timing does not separate them.
        let want = self.tag(nonce, &p);
        let ok = got.iter().zip(want).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
        if !ok || !(in_range(pr.data_type) || in_range(pr.ctl_type)) || pad > p.len() - INNER_HDR {
            return None;
        }
        Some(p[INNER_HDR..p.len() - pad].to_vec())
    }
}

fn entropy_rng() -> Rng {
    let (a, b) = (*uuid::Uuid::new_v4().as_bytes(), *uuid::Uuid::new_v4().as_bytes());
    Rng::new(u64::from_le_bytes(a[..8].try_into().unwrap()) ^ u64::from_le_bytes(b[8..].try_into().unwrap()).rotate_left(17))
}

/// 12 random bytes from a v4 UUID, skipping its two fixed version/variant bytes.
fn fresh_nonce() -> [u8; NONCE] {
    let u = *uuid::Uuid::new_v4().as_bytes();
    let mut n = [0u8; NONCE];
    n[..6].copy_from_slice(&u[..6]);
    n[6] = u[7];
    n[7..].copy_from_slice(&u[9..14]);
    n
}

#[async_trait::async_trait]
impl FrameIo for AwgCarrier {
    fn caps(&self) -> Caps {
        let c = self.inner.caps();
        let overhead = self.keys.params.overhead();
        Caps { id: CarrierId::Awg, max_frame: c.max_frame.saturating_sub(overhead), punchable: c.punchable, reliable_stream: false, overhead }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        let max = self.caps().max_frame;
        if frame.len() > max {
            return Err(CarrierError::FrameTooLarge { max }.into());
        }
        if self.role == Role::Client && self.junked.lock().unwrap().insert(to) {
            let pr = &self.keys.params;
            let cap = self.inner.caps().max_frame;
            for _ in 0..pr.junk_count {
                let mut j = vec![0u8; 0];
                {
                    let mut r = self.rng.lock().unwrap();
                    let n = (pr.junk_min + r.below((pr.junk_max - pr.junk_min) as u64 + 1) as usize).min(cap);
                    j.resize(n, 0);
                    r.fill(&mut j);
                }
                let _ = self.inner.send_to(&j, to).await;
            }
        }
        self.inner.send_to(&self.seal(frame), to).await?;
        Ok(frame.len())
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut s = self.scratch.lock().unwrap();
        loop {
            let (n, from) = self.inner.try_recv_from(&mut s)?;
            if let Some(f) = self.open(&s[..n]) {
                if f.len() > buf.len() {
                    return Err(CarrierError::FrameTooLarge { max: buf.len() }.into());
                }
                buf[..f.len()].copy_from_slice(&f);
                return Ok((f.len(), from));
            }
            if self.role == Role::Client {
                self.rejected.note(from);
            }
        }
    }
    fn take_rejected(&self) -> Vec<SocketAddr> {
        self.rejected.take()
    }
    async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }
    /// No junk burst: a port scan would send one to each of 64k destinations.
    async fn send_probe(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        if frame.len() > self.caps().max_frame {
            return Err(CarrierError::FrameTooLarge { max: self.caps().max_frame }.into());
        }
        self.inner.send_to(&self.seal(frame), to).await?;
        Ok(frame.len())
    }
    async fn sibling(&self) -> Option<Arc<dyn FrameIo>> {
        let inner = self.inner.sibling().await?;
        Some(Arc::new(AwgCarrier::wrap(inner, &self.key, self.role)))
    }
    /// Punch / STUN packets go through the raw socket; the envelope check drops them on receive.
    fn udp(&self) -> Option<&tokio::net::UdpSocket> {
        self.inner.udp()
    }
    fn health(&self) -> Health {
        self.inner.health()
    }
    async fn close(&self) {
        self.inner.close().await
    }
}

pub struct AwgFactory;

/// The invite key: spec param `key`, hex (even length, all hex digits) or raw text.
fn spec_key(spec: &CarrierSpec) -> Result<Vec<u8>, CarrierError> {
    let k = spec.params.iter().find(|(n, _)| n == "key").map(|(_, v)| v.as_str()).ok_or_else(|| CarrierError::Failed("awg: missing `key` param".into()))?;
    Ok(key_bytes(k))
}

fn key_bytes(k: &str) -> Vec<u8> {
    let hex = k.len() % 2 == 0 && !k.is_empty() && k.bytes().all(|b| b.is_ascii_hexdigit());
    if hex {
        (0..k.len()).step_by(2).map(|i| u8::from_str_radix(&k[i..i + 2], 16).unwrap()).collect()
    } else {
        k.as_bytes().to_vec()
    }
}

impl AwgCarrier {
    /// Host side on a port carved out of the plain UDP socket (see `shared`), keyed like the
    /// factory does from the invite key text.
    pub fn over(inner: Arc<dyn FrameIo>, invite_key: &str) -> Self {
        Self::wrap(inner, &key_bytes(invite_key), Role::Host)
    }
}

impl AwgFactory {
    async fn build(spec: &CarrierSpec, role: Role, port: Option<u16>) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let key = spec_key(spec)?;
        let u = UdpCarrier::bind(port).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
        Ok(Arc::new(AwgCarrier::wrap(Arc::new(u), &key, role)))
    }
}

#[async_trait::async_trait]
impl CarrierFactory for AwgFactory {
    fn id(&self) -> CarrierId {
        CarrierId::Awg
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Obfuscated UDP (AmneziaWG-style)",
            shared: &["A network observer sees UDP datagrams to your host with no fixed header, varying sizes, and a burst of junk datagrams at connection start"],
            not_shared: &["The payload and the keys are not shared"],
            why: "Makes the traffic harder to fingerprint on networks that block known VPN protocols. It hides the Strait wire format, not the fact that you send UDP to an IP; it is not a guarantee.",
            operator: "none: peer to peer",
        }
    }
    async fn probe(&self, _spec: &CarrierSpec, _t: Duration) -> ProbeStatus {
        match UdpCarrier::bind(None).await {
            Ok(_) => ProbeStatus::Reachable { rtt_ms: 0 },
            Err(e) => ProbeStatus::Error(e.to_string()),
        }
    }
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        Self::build(spec, Role::Host, spec.bind_port).await
    }
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        Self::build(spec, Role::Client, spec.bind_port).await
    }
}
