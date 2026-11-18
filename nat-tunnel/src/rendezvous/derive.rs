//! Key derivation and sealed candidate blobs (design section 2).
//!
//! `prk = HKDF-SHA256(salt = "strait-rv-v1", ikm = invite key bytes)`; each purpose is its own
//! `expand(info)`, so a service that sees one derived value learns nothing about the others or
//! the key. Blobs are never logged.
//!
//! The identifiers a service sees (topics, the info-hash, DHT keys) also depend on the UTC day
//! (`info = label || "@" || day`), so an operator cannot link the sessions of one invite across
//! days. Host blobs carry an Ed25519 signature by the host's record subkey for this invite
//! (derived from the invite's `hk`, see `handshake::Subkey`) after the AEAD part: a guest accepts
//! a host candidate only if the host signed it, so an invite holder cannot point guests at an
//! address of their choosing. Guest blobs are sealed to the host's X25519 key (a fresh key in
//! front, an HMAC under the record key behind), so only the host reads a guest's address.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use super::Role;

const SALT: &[u8] = b"strait-rv-v1";
const VER: u8 = 1;
/// A blob older than this is rejected (replay of a captured blob).
pub const WINDOW_PAST_SECS: u64 = 120;
/// Tolerated clock skew into the future.
pub const WINDOW_FUTURE_SECS: u64 = 30;
pub const MAX_CANDIDATES: usize = 8;
/// Length of one identifier period.
pub const EPOCH_SECS: u64 = 86_400;
const SIG_LEN: usize = 64;
/// Signed before the blob: a record signature cannot be taken for any other signed message.
const SIG_CONTEXT: &[u8] = b"strait-record-v1";

/// The current identifier period (UTC day number).
pub fn epoch_now() -> u32 {
    (now_secs() / EPOCH_SECS) as u32
}

/// Values derived from the 16-byte invite key.
#[derive(Clone, PartialEq, Eq)]
pub struct Derived {
    pub seal_key: [u8; 32],
    /// One identifier per backend, so observers of different services cannot join them.
    pub room_trk: [u8; 32],
    pub room_mqtt: [u8; 32],
    pub room_ntfy: [u8; 32],
    pub room_nostr: [u8; 32],
    pub dht_client_seed: [u8; 32],
    /// The invite key: host blobs are signed with the host's subkey for this invite.
    invite: [u8; 16],
    epoch: u32,
    /// Host side: the host key, to sign host blobs.
    pub sign: Option<[u8; 32]>,
    /// Client side: the invite's `hk`, to check host blobs.
    pub verify: Option<[u8; 32]>,
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Derived(..)") // never print key material
    }
}

/// Parse the invite's 32-hex-character key (either case). Anything else is rejected.
pub fn parse_key(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let h = (b[2 * i] as char).to_digit(16)?;
        let l = (b[2 * i + 1] as char).to_digit(16)?;
        *o = (h * 16 + l) as u8;
    }
    Some(out)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn base32_lower(b: &[u8]) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::new());
    for &x in b {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

impl Derived {
    /// Values for the current period.
    pub fn new(key: &[u8; 16]) -> Self {
        Self::for_epoch(key, epoch_now())
    }

    pub fn for_epoch(key: &[u8; 16], epoch: u32) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SALT), key);
        let ex = |info: &[u8]| {
            let mut o = [0u8; 32];
            hk.expand(info, &mut o).expect("32 bytes is a valid HKDF length");
            o
        };
        let id = |label: &[u8]| ex(&[label, b"@", &epoch.to_be_bytes()].concat());
        Self {
            seal_key: ex(b"seal"),
            room_trk: id(b"room-trk"),
            room_mqtt: id(b"room-mqtt"),
            room_ntfy: id(b"room-ntfy"),
            room_nostr: id(b"room-nostr"),
            dht_client_seed: id(b"dht-client"),
            invite: *key,
            epoch,
            sign: None,
            verify: None,
        }
    }

    /// [`Derived::new`] with both halves of the fixed test host key, for tests.
    #[doc(hidden)]
    pub fn new_test(key: &[u8; 16]) -> Self {
        let k = crate::transport::TEST_HOST_KEY;
        Self::new(key).with_host(Some(k), Some(crate::tunnel::handshake::public_of(&k)))
    }

    /// The host's DHT signing key: its subkey for this invite and this day. Only the host can
    /// publish under it (the client key below is shared by every invite holder).
    pub fn dht_host_signer(&self) -> Option<crate::tunnel::handshake::Subkey> {
        Some(crate::tunnel::handshake::Subkey::new(&self.sign?, &self.dht_context(), crate::tunnel::handshake::SUBKEY_DHT))
    }

    /// The public key the host publishes under on the DHT, from the host key or the invite's `hk`.
    pub fn dht_host_key(&self) -> Option<[u8; 32]> {
        match (self.sign, self.verify) {
            (Some(_), _) => self.dht_host_signer().map(|s| s.public()),
            (None, Some(hk)) => crate::tunnel::handshake::subkey_public(&hk, &self.dht_context(), crate::tunnel::handshake::SUBKEY_DHT),
            _ => None,
        }
    }

    fn dht_context(&self) -> Vec<u8> {
        [&self.invite[..], &self.epoch.to_be_bytes()].concat()
    }

    /// Add the host key (host side) or the invite's `hk` (client side).
    pub fn with_host(mut self, sign: Option<[u8; 32]>, verify: Option<[u8; 32]>) -> Self {
        self.sign = sign;
        self.verify = verify;
        self
    }

    /// From the invite's key string (32 hex chars).
    pub fn from_invite_key(key: &str) -> Option<Self> {
        parse_key(key).map(|k| Self::new(&k))
    }

    /// Tracker info_hash: first 20 bytes of the tracker tag.
    pub fn room_info_hash(&self) -> [u8; 20] {
        self.room_trk[..20].try_into().unwrap()
    }

    /// MQTT topic: lowercase base32 of the first 16 bytes of the MQTT tag (26 chars).
    pub fn mqtt_topic(&self) -> String {
        base32_lower(&self.room_mqtt[..16])
    }

    /// ntfy topic: same shape, own tag.
    pub fn ntfy_topic(&self) -> String {
        base32_lower(&self.room_ntfy[..16])
    }

    /// Nostr `r` tag: the full nostr tag as lowercase hex.
    pub fn room_hex(&self) -> String {
        hex(&self.room_nostr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    /// Too short, bad version, bad family, trailing bytes, or bad port.
    Malformed,
    /// AEAD tag failed: wrong key, wrong sender role, or tampering.
    BadTag,
    WrongRole,
    Stale,
    Future,
    NoCandidates,
    TooMany,
    /// A host blob without a valid signature by the invite's host key (or no key to check with).
    Unsigned,
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BlobError {}

fn role_byte(r: Role) -> u8 {
    match r {
        Role::Host => 0,
        Role::Client => 1,
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn aad(sender: Role) -> [u8; 1 + SALT.len()] {
    let mut a = [0u8; 1 + SALT.len()];
    a[0] = role_byte(sender);
    a[1..].copy_from_slice(SALT);
    a
}

/// The key of a guest record: from the invite and the exchange with the host's key.
fn client_key(d: &Derived, shared: &[u8; 32], epk: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&d.seal_key), &[&shared[..], epk].concat())
        .expand(b"strait-client-record-v1", &mut k[..])
        .expect("32 bytes is a valid HKDF length");
    k
}

/// A guest record's outer tag (HMAC-SHA256 through HKDF-Extract, keyed by the invite's record key).
fn client_tag(d: &Derived, body: &[u8]) -> [u8; 16] {
    let mut t = [0u8; 16];
    Hkdf::<Sha256>::new(Some(&d.seal_key), body).expand(b"strait-client-record-tag-v1", &mut t).expect("16 bytes is a valid HKDF length");
    t
}

/// Seal `cands` as sent by `sender`. Fails on 0 or more than 8 candidates or a zero port.
pub fn seal(d: &Derived, sender: Role, cands: &[SocketAddr]) -> Result<Vec<u8>, BlobError> {
    let nonce: [u8; 12] = ChaCha20Poly1305::generate_nonce(&mut OsRng).into();
    seal_at(d, sender, cands, now_secs(), nonce)
}

/// [`seal`] with an explicit clock and nonce (tests, pinned vectors).
pub fn seal_at(d: &Derived, sender: Role, cands: &[SocketAddr], now: u64, nonce: [u8; 12]) -> Result<Vec<u8>, BlobError> {
    if cands.is_empty() {
        return Err(BlobError::NoCandidates);
    }
    if cands.len() > MAX_CANDIDATES {
        return Err(BlobError::TooMany);
    }
    if cands.iter().any(|c| c.port() == 0) {
        return Err(BlobError::Malformed);
    }
    let mut pt = vec![VER, role_byte(sender)];
    pt.extend_from_slice(&(now as u32).to_be_bytes());
    pt.push(cands.len() as u8);
    for c in cands {
        match c.ip() {
            IpAddr::V4(a) => {
                pt.push(4);
                pt.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                pt.push(6);
                pt.extend_from_slice(&a.octets());
            }
        }
        pt.extend_from_slice(&c.port().to_be_bytes());
    }
    // A guest's record is sealed to the host's key: other invite holders cannot read its address.
    let (mut out, key) = match sender {
        Role::Host => (Vec::new(), zeroize::Zeroizing::new(d.seal_key)),
        Role::Client => {
            let hk = d.verify.ok_or(BlobError::Unsigned)?;
            let (epk, shared) = crate::tunnel::handshake::dh_to_host(&hk).ok_or(BlobError::Unsigned)?;
            (epk.to_vec(), client_key(d, &shared, &epk))
        }
    };
    let ct = ChaCha20Poly1305::new((&*key).into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad(sender) })
        .expect("encrypt");
    out.extend_from_slice(&nonce);
    out.extend(ct);
    if sender == Role::Client {
        let t = client_tag(d, &out);
        out.extend_from_slice(&t);
    }
    if sender == Role::Host {
        let key = d.sign.ok_or(BlobError::Unsigned)?;
        let sub = crate::tunnel::handshake::Subkey::new(&key, &d.invite, crate::tunnel::handshake::SUBKEY_RECORD);
        out.extend_from_slice(&sub.sign(&[SIG_CONTEXT, &out].concat()));
    }
    Ok(out)
}

/// Open a blob that must have been sent by the role opposite to `own`.
pub fn open(d: &Derived, own: Role, blob: &[u8]) -> Result<Vec<SocketAddr>, BlobError> {
    open_at(d, own, blob, now_secs())
}

pub fn open_at(d: &Derived, own: Role, blob: &[u8], now: u64) -> Result<Vec<SocketAddr>, BlobError> {
    let sender = match own {
        Role::Host => Role::Client,
        Role::Client => Role::Host,
    };
    let blob = if sender == Role::Host {
        if blob.len() < 12 + 16 + SIG_LEN {
            return Err(BlobError::Malformed);
        }
        let (body, sig) = blob.split_at(blob.len() - SIG_LEN);
        let hk = d.verify.ok_or(BlobError::Unsigned)?;
        let pk = crate::tunnel::handshake::subkey_public(&hk, &d.invite, crate::tunnel::handshake::SUBKEY_RECORD).ok_or(BlobError::Unsigned)?;
        if !crate::tunnel::handshake::verify_sig(&pk, &[SIG_CONTEXT, body].concat(), sig.try_into().unwrap()) {
            return Err(BlobError::Unsigned);
        }
        body
    } else {
        blob
    };
    let (blob, key) = match sender {
        Role::Host => (blob, zeroize::Zeroizing::new(d.seal_key)),
        Role::Client => {
            let host_key = d.sign.ok_or(BlobError::Unsigned)?;
            if blob.len() < 32 + 12 + 16 + 16 {
                return Err(BlobError::Malformed);
            }
            // The cheap check first: only an invite holder makes the host do a key exchange.
            let (body, t) = blob.split_at(blob.len() - 16);
            if client_tag(d, body).iter().zip(t).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
                return Err(BlobError::BadTag);
            }
            let epk: [u8; 32] = body[..32].try_into().unwrap();
            let shared = crate::tunnel::handshake::dh_as_host(&host_key, &epk).ok_or(BlobError::BadTag)?;
            (&body[32..], client_key(d, &shared, &epk))
        }
    };
    if blob.len() < 12 + 16 {
        return Err(BlobError::Malformed);
    }
    let (nonce, ct) = blob.split_at(12);
    let pt = ChaCha20Poly1305::new((&*key).into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad(sender) })
        .map_err(|_| BlobError::BadTag)?;
    if pt.len() < 7 || pt[0] != VER {
        return Err(BlobError::Malformed);
    }
    if pt[1] != role_byte(sender) {
        return Err(BlobError::WrongRole);
    }
    let ts = u32::from_be_bytes(pt[2..6].try_into().unwrap()) as u64;
    // The u32 timestamp is compared modulo nothing: it is simply unix seconds until 2106.
    let now32 = now & 0xffff_ffff;
    if ts + WINDOW_PAST_SECS < now32 {
        return Err(BlobError::Stale);
    }
    if ts > now32 + WINDOW_FUTURE_SECS {
        return Err(BlobError::Future);
    }
    let n = pt[6] as usize;
    if n == 0 {
        return Err(BlobError::NoCandidates);
    }
    if n > MAX_CANDIDATES {
        return Err(BlobError::TooMany);
    }
    let mut rest = &pt[7..];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (&fam, r) = rest.split_first().ok_or(BlobError::Malformed)?;
        let alen = match fam {
            4 => 4,
            6 => 16,
            _ => return Err(BlobError::Malformed),
        };
        if r.len() < alen + 2 {
            return Err(BlobError::Malformed);
        }
        let ip: IpAddr = if alen == 4 {
            Ipv4Addr::from(<[u8; 4]>::try_from(&r[..4]).unwrap()).into()
        } else {
            Ipv6Addr::from(<[u8; 16]>::try_from(&r[..16]).unwrap()).into()
        };
        let port = u16::from_be_bytes([r[alen], r[alen + 1]]);
        if port == 0 {
            return Err(BlobError::Malformed);
        }
        out.push(SocketAddr::new(ip, port));
        rest = &r[alen + 2..];
    }
    if !rest.is_empty() {
        return Err(BlobError::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const NOW: u64 = 1_800_000_000;

    const DAY: u32 = 20_000;
    const HOST: [u8; 32] = [0x42; 32];

    fn d() -> Derived {
        Derived::for_epoch(&K, DAY).with_host(Some(HOST), Some(crate::tunnel::handshake::public_of(&HOST)))
    }
    fn a4() -> SocketAddr {
        "203.0.113.7:4242".parse().unwrap()
    }
    fn a6() -> SocketAddr {
        "[2001:db8::1]:51820".parse().unwrap()
    }
    fn sealed(role: Role, c: &[SocketAddr], at: u64) -> Vec<u8> {
        seal_at(&d(), role, c, at, [7; 12]).unwrap()
    }

    /// Encrypt an arbitrary plaintext as `sender` to test the receiver's format checks.
    fn raw(sender: Role, pt: &[u8]) -> Vec<u8> {
        let ct = ChaCha20Poly1305::new((&d().seal_key).into())
            .encrypt(Nonce::from_slice(&[9; 12]), Payload { msg: pt, aad: &aad(sender) })
            .unwrap();
        let mut b = [&[9u8; 12][..], &ct].concat();
        if sender == Role::Host {
            let sub = crate::tunnel::handshake::Subkey::new(&HOST, &K, crate::tunnel::handshake::SUBKEY_RECORD);
            b.extend_from_slice(&sub.sign(&[SIG_CONTEXT, &b].concat()));
        }
        b
    }

    /// Host blobs must carry the host key's signature; an invite holder (who has the AEAD key)
    /// cannot make one, and a client without `hk` accepts none.
    #[test]
    fn host_blobs_are_signed_by_the_host_key() {
        let b = sealed(Role::Host, &[a4()], NOW);
        assert_eq!(open_at(&d(), Role::Client, &b, NOW).unwrap(), vec![a4()]);
        // Someone who knows `hk` but not this invite's key cannot check (link) the signature.
        let (body, sig) = b.split_at(b.len() - 64);
        let hk = crate::tunnel::handshake::public_of(&HOST);
        for m in [body.to_vec(), [SIG_CONTEXT, body].concat()] {
            assert!(!crate::tunnel::handshake::verify_sig(&hk, &m, sig.try_into().unwrap()));
        }
        let other = d().with_host(Some([7; 32]), Some(crate::tunnel::handshake::public_of(&[7; 32])));
        let forged = seal_at(&other, Role::Host, &[a4()], NOW, [7; 12]).unwrap();
        assert_eq!(open_at(&d(), Role::Client, &forged, NOW), Err(BlobError::Unsigned));
        let mut cut = b.clone();
        cut.truncate(b.len() - 64);
        assert!(open_at(&d(), Role::Client, &cut, NOW).is_err());
        assert_eq!(open_at(&d().with_host(None, None), Role::Client, &b, NOW), Err(BlobError::Unsigned));
        assert_eq!(seal_at(&d().with_host(None, None), Role::Host, &[a4()], NOW, [7; 12]), Err(BlobError::Unsigned));
        // Client blobs are unsigned (guests have no key) but sealed to the host's key: only the host
        // opens them, not another invite holder (who has the invite key and `hk`).
        let c = sealed(Role::Client, &[a4()], NOW);
        assert_eq!(open_at(&d(), Role::Host, &c, NOW).unwrap(), vec![a4()]);
        let guest = d().with_host(None, Some(crate::tunnel::handshake::public_of(&HOST)));
        assert_eq!(open_at(&guest, Role::Host, &c, NOW), Err(BlobError::Unsigned));
        let other_host = d().with_host(Some([7; 32]), None);
        assert_eq!(open_at(&other_host, Role::Host, &c, NOW), Err(BlobError::BadTag));
        assert!(!c.windows(4).any(|w| w == [203, 0, 113, 7]));
        let outsider = Derived::for_epoch(&[9; 16], DAY).with_host(None, Some(crate::tunnel::handshake::public_of(&HOST)));
        let o = seal_at(&outsider, Role::Client, &[a4()], NOW, [7; 12]).unwrap();
        assert_eq!(open_at(&d(), Role::Host, &o, NOW), Err(BlobError::BadTag), "no invite, no key exchange");
        assert_eq!(seal_at(&d().with_host(Some(HOST), None), Role::Client, &[a4()], NOW, [7; 12]), Err(BlobError::Unsigned), "a guest needs hk");
    }

    /// Identifiers change from one day to the next; the sealing key does not.
    #[test]
    fn identifiers_rotate_daily() {
        let (a, b) = (Derived::for_epoch(&K, DAY), Derived::for_epoch(&K, DAY + 1));
        assert_ne!(a.mqtt_topic(), b.mqtt_topic());
        assert_ne!(a.room_info_hash(), b.room_info_hash());
        assert_ne!(a.room_hex(), b.room_hex());
        let hk = Some(crate::tunnel::handshake::public_of(&HOST));
        let (ha, hb) = (a.clone().with_host(None, hk).dht_host_key(), b.clone().with_host(None, hk).dht_host_key());
        assert!(ha.is_some() && ha != hb, "the host's DHT key changes every day");
        assert!(a.clone().with_host(None, hk).dht_host_signer().is_none(), "an invite holder cannot publish as the host");
        assert_eq!(ha, a.clone().with_host(Some(HOST), None).dht_host_key(), "guest and host derive the same key");
        assert_ne!(ha, Derived::for_epoch(&[9; 16], DAY).with_host(None, hk).dht_host_key(), "and with the invite");
        assert_eq!(a.seal_key, b.seal_key);
    }
    fn pt(ver: u8, role: u8, ts: u32, n: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![ver, role];
        v.extend(ts.to_be_bytes());
        v.push(n);
        v.extend(body);
        v
    }
    const V4BODY: [u8; 7] = [4, 1, 2, 3, 4, 0x12, 0x34];

    #[test]
    fn roundtrip_both_roles_v4_and_v6() {
        let c = vec![a4(), a6(), "10.0.0.1:1".parse().unwrap()];
        for (s, r) in [(Role::Host, Role::Client), (Role::Client, Role::Host)] {
            let b = seal_at(&d(), s, &c, NOW, [1; 12]).unwrap();
            assert_eq!(open_at(&d(), r, &b, NOW).unwrap(), c);
        }
        // random-nonce path and wall clock
        let b = seal(&d(), Role::Host, &[a6()]).unwrap();
        assert_eq!(open(&d(), Role::Client, &b).unwrap(), vec![a6()]);
        assert_ne!(b, seal(&d(), Role::Host, &[a6()]).unwrap(), "nonce must be random");
    }

    #[test]
    fn eight_ok_nine_rejected_zero_rejected() {
        let eight: Vec<SocketAddr> = (1..=8).map(|i| SocketAddr::from(([1, 1, 1, i], 1000 + i as u16))).collect();
        let b = sealed(Role::Host, &eight, NOW);
        assert_eq!(open_at(&d(), Role::Client, &b, NOW).unwrap(), eight);
        let mut nine = eight.clone();
        nine.push(a4());
        assert_eq!(seal_at(&d(), Role::Host, &nine, NOW, [0; 12]), Err(BlobError::TooMany));
        assert_eq!(seal_at(&d(), Role::Host, &[], NOW, [0; 12]), Err(BlobError::NoCandidates));
        assert_eq!(seal_at(&d(), Role::Host, &["1.1.1.1:0".parse().unwrap()], NOW, [0; 12]), Err(BlobError::Malformed));
        // a hostile peer that seals 9 / 0 candidates with the right key is rejected on receipt
        let body9 = V4BODY.repeat(9);
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 0, NOW as u32, 9, &body9)), NOW), Err(BlobError::TooMany));
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 0, NOW as u32, 0, &[])), NOW), Err(BlobError::NoCandidates));
    }

    #[test]
    fn wrong_key_and_wrong_role() {
        let b = sealed(Role::Host, &[a4()], NOW);
        let other = Derived::for_epoch(&[9; 16], DAY).with_host(Some(HOST), Some(crate::tunnel::handshake::public_of(&HOST)));
        assert_eq!(open_at(&other, Role::Client, &b, NOW), Err(BlobError::Unsigned), "another invite's subkey");
        // a host must not accept its own blob (nor a reflected one)
        assert_eq!(open_at(&d(), Role::Host, &b, NOW), Err(BlobError::BadTag));
        let c = sealed(Role::Client, &[a4()], NOW);
        assert!(open_at(&d(), Role::Client, &c, NOW).is_err(), "a client blob is not a host blob");
        // correct aad but inner role byte lying
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 1, NOW as u32, 1, &V4BODY)), NOW), Err(BlobError::WrongRole));
    }

    #[test]
    fn timestamp_window() {
        let at = |t: u64| open_at(&d(), Role::Client, &sealed(Role::Host, &[a4()], t), NOW);
        assert!(at(NOW).is_ok());
        assert!(at(NOW - 120).is_ok());
        assert_eq!(at(NOW - 121), Err(BlobError::Stale));
        assert_eq!(at(NOW - 100_000), Err(BlobError::Stale));
        assert!(at(NOW + 30).is_ok());
        assert_eq!(at(NOW + 31), Err(BlobError::Future));
    }

    #[test]
    fn truncation_and_extension_rejected() {
        let b = sealed(Role::Host, &[a4(), a6()], NOW);
        for n in 0..b.len() {
            assert!(open_at(&d(), Role::Client, &b[..n], NOW).is_err(), "len {n}");
        }
        let mut longer = b.clone();
        longer.push(0);
        assert!(open_at(&d(), Role::Client, &longer, NOW).is_err());
    }

    #[test]
    fn every_bit_flip_rejected() {
        let b = sealed(Role::Host, &[a4(), a6()], NOW);
        for i in 0..b.len() * 8 {
            let mut m = b.clone();
            m[i / 8] ^= 1 << (i % 8);
            assert!(open_at(&d(), Role::Client, &m, NOW).is_err(), "bit {i}");
        }
    }

    #[test]
    fn malformed_plaintext_rejected() {
        let ts = NOW as u32;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("bad version", pt(2, 0, ts, 1, &V4BODY)),
            ("bad family", pt(1, 0, ts, 1, &[5, 1, 2, 3, 4, 0, 80])),
            ("short addr", pt(1, 0, ts, 1, &V4BODY[..5])),
            ("n larger than data", pt(1, 0, ts, 2, &V4BODY)),
            ("trailing bytes", pt(1, 0, ts, 1, &[&V4BODY[..], &[0]].concat())),
            ("port zero", pt(1, 0, ts, 1, &[4, 1, 2, 3, 4, 0, 0])),
            ("too short", vec![1, 0, 0]),
            ("empty", vec![]),
        ];
        for (name, p) in cases {
            assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &p), NOW), Err(BlobError::Malformed), "{name}");
        }
    }

    #[test]
    fn domain_separation() {
        let x = d();
        let v = [x.seal_key, x.room_trk, x.room_mqtt, x.room_ntfy, x.room_nostr, x.dht_client_seed, x.dht_host_key().unwrap()];
        for i in 0..v.len() {
            for j in i + 1..v.len() {
                assert_ne!(v[i], v[j], "{i} vs {j}");
            }
        }
        let y = Derived::for_epoch(&[K[0] ^ 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], DAY);
        assert_ne!(x.seal_key, y.seal_key);
        assert_ne!(x.room_trk, y.room_trk);
        assert_eq!(&x.room_trk[..20], &x.room_info_hash());
        // none of the derived values equals the key (or contains it as a prefix)
        assert!(v.iter().all(|s| s[..16] != K));
    }

    #[test]
    fn topic_and_hex_shapes() {
        let x = d();
        let t = x.mqtt_topic();
        assert!(t.len() == 26 && !t.contains("strait"), "{t}");
        assert_ne!(t, x.ntfy_topic());
        assert!(t.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)));
        assert_eq!(x.room_hex().len(), 64);
        // RFC 4648 vectors (lowercase, unpadded)
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"f"), "my");
    }

    #[test]
    fn parse_key_strict() {
        assert_eq!(parse_key("000102030405060708090a0b0c0d0e0f"), Some(K));
        assert_eq!(parse_key("000102030405060708090A0B0C0D0E0F"), Some(K));
        for bad in ["", "abc123", "000102030405060708090a0b0c0d0e0", "000102030405060708090a0b0c0d0e0f0", "000102030405060708090a0b0c0d0e0g", "0001020304050607 8090a0b0c0d0e0f", "ééééééééééééééééééééééééééééééé"] {
            assert!(parse_key(bad).is_none(), "{bad:?}");
        }
        assert_eq!(Derived::from_invite_key("000102030405060708090a0b0c0d0e0f"), Some(Derived::new(&K)));
    }

    /// Pinned (cross-checked against an independent Python HKDF/ChaCha20-Poly1305, and the
    /// RFC 8032 reference arithmetic for the blinded subkey signature): changing any of these breaks interop with every
    /// deployed invite and blob. Identifiers are for day 20000.
    #[test]
    fn pinned_vectors() {
        let x = d();
        assert_eq!(hex(&x.seal_key), "ba4b1c0d17e9877100c95a204557ea405205ec9dc79c8ba98db84db33fd9d127");
        assert_eq!(hex(&x.room_trk), "71bfe147da109624d46f47596fb260d7fe34443897610a2c83c400ff90d12180");
        assert_eq!(hex(&x.dht_client_seed), "902b2cb78d7a9115e5ab1b26fe1d4d70671328fef886f1a392f13d380ec8fee0");
        assert_eq!(x.mqtt_topic(), "fejq2eyp5y3pfs7woxvqpoaewe");
        assert_eq!(x.ntfy_topic(), "hbgrsajsytppsvkc252jwha7qu");
        assert_eq!(x.room_hex(), "7fe25ed48250cc9cbad77de095bcc1501c7cb5aad05597e6701b4c5560676507");
        assert_eq!(hex(&sealed(Role::Host, &[a4(), a6()], NOW)), "07070707070707070707070717cdddc391b83f73b4606bb236ae79862794eddb4967b453d1c8634716c6d8921678719d8692286c7ee3835796f9d8cb79c6ed0a3838861a890c97c62faf4a9cfc73a39772f289e4b3ce0f362f8a08676d2790c57534ef05e009fad083c1ec702a5fdb0940965fb6463e57f57546d4f90b");
    }
}
