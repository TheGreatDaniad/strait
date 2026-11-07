//! Carrier layer: how sealed tunnel frames move between two peers. See `docs/TUNNEL_CARRIERS.md`.
//!
//! A carrier moves opaque, already-sealed frames and never sees keys. [`FrameIo`] has the same poll
//! style as `UdpSocket` (`readable()` then drain `try_recv_from`), and the peer key stays a
//! `SocketAddr`, so the transport's per-peer maps stay valid. Failure is always explicit
//! ([`CarrierError`]); an oversize frame is an error, never a silent drop.
//!
//! Adding a carrier: one file implementing [`FrameIo`] + [`CarrierFactory`], one line in
//! [`registry`] behind its `cr-*` feature.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::rendezvous::{Disclosure, ProbeStatus};

pub mod ladder;
pub mod loopback;
pub mod mem;
pub mod shared;
pub mod stream;
pub mod supervisor;
pub mod udp;
#[cfg(feature = "cr-ss")]
pub mod ss;
#[cfg(feature = "cr-ws")]
pub mod ws;
#[cfg(feature = "cr-awg")]
pub mod awg;
#[cfg(feature = "cr-xray")]
pub mod xray;

/// The carriers the design knows. Whether one is compiled in is [`built_ids`], not this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CarrierId {
    Udp,
    Ss,
    Ws,
    Awg,
    Xray,
    Dns,
}

impl CarrierId {
    pub const ALL: [CarrierId; 6] =
        [CarrierId::Udp, CarrierId::Ss, CarrierId::Ws, CarrierId::Awg, CarrierId::Xray, CarrierId::Dns];

    pub fn as_str(self) -> &'static str {
        match self {
            CarrierId::Udp => "udp",
            CarrierId::Ss => "ss",
            CarrierId::Ws => "ws",
            CarrierId::Awg => "awg",
            CarrierId::Xray => "xray",
            CarrierId::Dns => "dns",
        }
    }

    pub fn parse(s: &str) -> Option<CarrierId> {
        CarrierId::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Can this carrier ride the shared UDP socket and its hole punch? (stream / DNS carriers need
    /// a reachable host.)
    pub fn default_punchable(self) -> bool {
        matches!(self, CarrierId::Udp | CarrierId::Ss | CarrierId::Awg)
    }
}

impl fmt::Display for CarrierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One carrier as listed in an invite's `cr` field (or given to the host): `id[@host:port][;k=v;k=v]`.
/// On the host `endpoint` is the local listen address; in an invite it is the public address.
/// Parameters are public settings only; secrets always derive from the invite key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierEntry {
    pub id: CarrierId,
    pub endpoint: Option<String>,
    pub params: Vec<(String, String)>,
}

/// What `CarrierEntry::parse_entry` found: a carrier this build knows, or an id it does not (kept
/// verbatim so an invite round-trips; ignored at runtime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEntry {
    Known(CarrierEntry),
    Unknown(String),
}

/// Most entries an invite may list.
pub const MAX_CARRIER_ENTRIES: usize = 8;
const MAX_PARAMS: usize = 8;
const MAX_VALUE: usize = 128;

impl CarrierEntry {
    pub fn new(id: CarrierId) -> Self {
        Self { id, endpoint: None, params: Vec::new() }
    }
    pub fn at(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
    pub fn with(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.params.push((k.into(), v.into()));
        self
    }
    pub fn param(&self, k: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// Parameters an entry of this carrier may carry in an invite. Never a secret: keys, paths
    /// tokens, UUIDs and so on derive from the invite key.
    /// ss: none (endpoint only); ws: `path` (HTTP path override), `sni`; awg: none;
    /// xray: `sni` (REALITY server name), `mode` (XHTTP mode), `port` (public port override),
    /// `target` (host side: where REALITY forwards visitors without the key, `host:port`; the client ignores it).
    pub fn allowed_params(id: CarrierId) -> &'static [&'static str] {
        match id {
            CarrierId::Ws => &["path", "sni"],
            CarrierId::Xray => &["sni", "mode", "port", "target"],
            CarrierId::Udp | CarrierId::Ss | CarrierId::Awg | CarrierId::Dns => &[],
        }
    }

    /// Drop every parameter outside the allow-list.
    pub fn sanitized(mut self) -> Self {
        let ok = Self::allowed_params(self.id);
        let id = self.id;
        self.params.retain(|(k, v)| {
            ok.contains(&k.as_str())
                && v.len() <= MAX_VALUE
                && !v.chars().any(|c| c.is_control())
                && (id != CarrierId::Xray || param_ok(k, v))
        });
        self.params.truncate(MAX_PARAMS);
        self
    }

    /// Parse the entry grammar (with `%XX` escapes). Parameters outside the allow-list of a known
    /// carrier are dropped (forward compatibility); an unknown id is returned as `Unknown`.
    pub fn parse_entry(s: &str) -> Result<ParsedEntry, String> {
        let s = s.trim();
        let (head, rest) = match s.split_once(';') {
            Some((h, r)) => (h, Some(r)),
            None => (s, None),
        };
        let (id_s, ep) = match head.split_once('@') {
            Some((i, e)) => (i, Some(e)),
            None => (head, None),
        };
        if !(1..=12).contains(&id_s.len()) || !id_s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err(format!("bad carrier id {id_s:?}"));
        }
        let mut params: Vec<(String, String)> = Vec::new();
        for kv in rest.into_iter().flat_map(|r| r.split(';')).filter(|p| !p.is_empty()) {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("bad parameter {kv:?}"))?;
            if k.is_empty() || k.len() > 16 || !k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
                return Err(format!("bad parameter name {k:?}"));
            }
            let v = pct_decode(v)?;
            if v.len() > MAX_VALUE {
                return Err(format!("parameter {k} is too long"));
            }
            if params.len() >= MAX_PARAMS {
                return Err("too many parameters".into());
            }
            params.push((k.to_string(), v));
        }
        let Some(id) = CarrierId::parse(id_s) else {
            if ep.is_some_and(|e| e.len() > 253 + 8) {
                return Err("endpoint too long".into());
            }
            return Ok(ParsedEntry::Unknown(s.to_string()));
        };
        let endpoint = match ep {
            None => None,
            Some(e) => {
                let e = pct_decode(e)?;
                e.parse::<crate::invite::Endpoint>().map_err(|m| format!("bad endpoint {e:?}: {m}"))?;
                Some(e)
            }
        };
        Ok(ParsedEntry::Known(CarrierEntry { id, endpoint, params }.sanitized()))
    }
}

/// Strict syntax for the xray parameters that end up in the sidecar config: `sni` is a bare
/// hostname, `target` is `hostname-or-IP:port` (no scheme, no path, no spaces).
pub(crate) fn param_ok(k: &str, v: &str) -> bool {
    fn host_ok(h: &str) -> bool {
        let h = h.trim_start_matches('[').trim_end_matches(']');
        h.parse::<std::net::IpAddr>().is_ok()
            || (!h.is_empty()
                && h.len() <= 253
                && h.split('.').all(|l| {
                    (1..=63).contains(&l.len())
                        && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                }))
    }
    match k {
        "sni" => host_ok(v),
        "target" => v.rsplit_once(':').is_some_and(|(h, p)| host_ok(h) && p.parse::<u16>().is_ok_and(|p| p != 0)),
        _ => true,
    }
}

/// `%XX` escapes; the result must be UTF-8 without control characters.
fn pct_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit())).ok_or("bad %-escape")?;
            out.push(u8::from_str_radix(h, 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    let v = String::from_utf8(out).map_err(|_| "value is not UTF-8".to_string())?;
    if v.chars().any(|c| c.is_control()) {
        return Err("control character in value".into());
    }
    Ok(v)
}

fn pct_encode(v: &str, out: &mut String) {
    for &c in v.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~/:[]".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
}

impl fmt::Display for CarrierEntry {
    /// The invite grammar, escaped; parameters outside the allow-list are not written.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::from(self.id.as_str());
        if let Some(e) = &self.endpoint {
            s.push('@');
            pct_encode(e, &mut s);
        }
        let ok = Self::allowed_params(self.id);
        for (k, v) in self.params.iter().filter(|(k, _)| ok.contains(&k.as_str())) {
            s.push(';');
            s.push_str(k);
            s.push('=');
            pct_encode(v, &mut s);
        }
        f.write_str(&s)
    }
}

impl std::str::FromStr for CarrierEntry {
    type Err = String;
    /// For the CLI: unknown ids are an error that lists the valid ones.
    fn from_str(s: &str) -> Result<Self, String> {
        match Self::parse_entry(s)? {
            ParsedEntry::Known(e) => {
                // An invite silently drops a bad value (forward compatibility); the CLI must not.
                if e.id == CarrierId::Xray {
                    for kv in s.split(';').skip(1) {
                        if let Some((k, v)) = kv.split_once('=') {
                            let v = pct_decode(v)?;
                            if !param_ok(k, &v) {
                                return Err(format!("invalid xray {k} {v:?}: expected a plain hostname{}", if k == "target" { ":port (no https://)" } else { "" }));
                            }
                        }
                    }
                }
                Ok(e)
            }
            ParsedEntry::Unknown(u) => Err(format!(
                "unknown carrier '{}' (valid: {})",
                u.split(['@', ';']).next().unwrap_or(&u),
                CarrierId::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }
}

/// The TUN device MTU that fits every carrier in use: the smallest `tun_mtu()`, 1400 when none.
/// A packet at this size always fits one sealed frame on all of them.
pub fn effective_mtu(carriers: &[Caps]) -> usize {
    carriers.iter().map(Caps::tun_mtu).min().unwrap_or(1400)
}

/// What a carrier can do. `max_frame` is the largest sealed frame `send_to` accepts (wire bytes of
/// the frame the transport hands over); `overhead` is what the carrier itself adds per frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub id: CarrierId,
    pub max_frame: usize,
    /// Only raw / obfuscated UDP on the shared socket.
    pub punchable: bool,
    /// Stream-backed: bounded queues, head-of-line blocking is possible.
    pub reliable_stream: bool,
    pub overhead: usize,
}

impl Caps {
    /// AEAD (16 B header + 16 B tag) plus the 3 B mux header.
    pub const SEAL_OVERHEAD: usize = 35;
    /// Largest IP packet the TUN may carry over this carrier.
    pub fn tun_mtu(&self) -> usize {
        let mut m = self.max_frame.saturating_sub(Self::SEAL_OVERHEAD).min(1400);
        if self.reliable_stream {
            m = m.min(1300); // a stream carrier sits on top of a TCP MSS the path may shrink
        } else if self.overhead > 0 {
            // A wrapped datagram must not outgrow the biggest plain UDP one (1435 B sealed).
            m = m.min(1435usize.saturating_sub(self.overhead + Self::SEAL_OVERHEAD));
        }
        m
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierError {
    /// Not in this build / not for this platform.
    Unsupported,
    /// Blocked by the network or by policy. Not retried.
    Blocked(String),
    Failed(String),
    /// The frame exceeds the carrier's limit. Never dropped silently.
    FrameTooLarge { max: usize },
    /// Orderly end of a stream.
    Eof,
    /// Connection reset / broken (a typical DPI sign).
    Reset(String),
    /// The carrier was closed or has no live connection left.
    Closed,
    /// `to` is not a peer this carrier knows.
    UnknownPeer,
}

impl fmt::Display for CarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CarrierError::Unsupported => f.write_str("not supported"),
            CarrierError::Blocked(s) => write!(f, "blocked: {s}"),
            CarrierError::Failed(s) => f.write_str(s),
            CarrierError::FrameTooLarge { max } => write!(f, "frame larger than the carrier limit of {max} bytes"),
            CarrierError::Eof => f.write_str("connection closed by peer"),
            CarrierError::Reset(s) => write!(f, "connection reset: {s}"),
            CarrierError::Closed => f.write_str("carrier closed"),
            CarrierError::UnknownPeer => f.write_str("unknown peer"),
        }
    }
}
impl std::error::Error for CarrierError {}

impl From<CarrierError> for io::Error {
    fn from(e: CarrierError) -> Self {
        let kind = match &e {
            CarrierError::Unsupported => io::ErrorKind::Unsupported,
            CarrierError::Blocked(_) => io::ErrorKind::PermissionDenied,
            CarrierError::Failed(_) => io::ErrorKind::Other,
            CarrierError::FrameTooLarge { .. } => io::ErrorKind::InvalidInput,
            CarrierError::Eof => io::ErrorKind::UnexpectedEof,
            CarrierError::Reset(_) => io::ErrorKind::ConnectionReset,
            CarrierError::Closed => io::ErrorKind::BrokenPipe,
            CarrierError::UnknownPeer => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, e)
    }
}

impl CarrierError {
    /// Recover the typed reason from an `io::Error` returned by a [`FrameIo`] method.
    pub fn from_io(e: &io::Error) -> Option<&CarrierError> {
        e.get_ref()?.downcast_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// Sidecar exited, TLS reset, ...
    Down(String),
}

/// Sealed-frame I/O. Datagram semantics, best effort. Peer key = `SocketAddr`.
#[async_trait::async_trait]
pub trait FrameIo: Send + Sync + 'static {
    fn caps(&self) -> Caps;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// `to` is a peer key previously returned by `try_recv_from` (or the fixed host address on the
    /// client side). A frame over `caps().max_frame` is `Err(CarrierError::FrameTooLarge)`.
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize>;
    /// Same contract as `UdpSocket::try_recv_from` (`Err(WouldBlock)` when empty).
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn readable(&self) -> io::Result<()>;
    /// Only the raw UDP carrier returns Some: STUN, signal registration and punching use it.
    fn udp(&self) -> Option<&tokio::net::UdpSocket> {
        None
    }
    /// STUN mapping of a socket this carrier owns when `udp()` is `None` (ss as a rendezvous
    /// client: the answers must be read before the carrier's own decoder sees them).
    /// One mapping per answering server (more than one distinct value = symmetric NAT).
    async fn stun_mapped(&self, _servers: &[SocketAddr], _wait: Duration) -> Vec<SocketAddr> {
        Vec::new()
    }
    /// A hole-punch probe (JOIN) of a birthday scan or fan-out: like `send_to`, but a carrier
    /// whose first frame to a new destination costs more (awg junk burst) skips that.
    async fn send_probe(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.send_to(frame, to).await
    }
    /// A fresh carrier of the same kind and keys on a new socket (new NAT mapping), for the
    /// birthday fan-out. `None` when the carrier cannot be duplicated.
    async fn sibling(&self) -> Option<Arc<dyn FrameIo>> {
        None
    }
    /// Sources of datagrams this carrier's codec rejected since the last call (a rendezvous client
    /// only; at most [`Rejects::MAX`]). The host's plain punch is such a datagram for ss / awg: the
    /// transport probes the source with a valid JOIN (the source alone authenticates nothing).
    fn take_rejected(&self) -> Vec<SocketAddr> {
        Vec::new()
    }
    fn health(&self) -> Health {
        Health::Ok
    }
    async fn close(&self) {}
}

/// Distinct sources of rejected datagrams, bounded (see [`FrameIo::take_rejected`]).
#[derive(Default)]
pub struct Rejects(std::sync::Mutex<Vec<SocketAddr>>);

impl Rejects {
    pub const MAX: usize = 16;
    pub fn note(&self, from: SocketAddr) {
        let mut v = self.0.lock().unwrap();
        if v.len() < Self::MAX && !v.contains(&from) {
            v.push(from);
        }
    }
    pub fn take(&self) -> Vec<SocketAddr> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// Parameters for building a carrier. Secrets are derived by the carrier from the invite key.
#[derive(Debug, Clone, Default)]
pub struct CarrierSpec {
    /// `host:port` the carrier talks to (client) or the local listen address (host).
    pub endpoint: Option<String>,
    pub bind_port: Option<u16>,
    pub params: Vec<(String, String)>,
}

#[async_trait::async_trait]
pub trait CarrierFactory: Send + Sync {
    fn id(&self) -> CarrierId;
    fn disclosure(&self) -> Disclosure;
    /// Reachability only: publishes nothing. Must finish within `timeout`.
    async fn probe(&self, spec: &CarrierSpec, timeout: Duration) -> ProbeStatus;
    /// Host side.
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError>;
    /// Client side.
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError>;
}

/// Every compiled-in carrier. Add carriers here, behind their `cr-*` feature.
pub fn registry() -> Vec<Arc<dyn CarrierFactory>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn CarrierFactory>> = vec![Arc::new(udp::UdpFactory)];
    #[cfg(feature = "cr-ss")]   v.push(Arc::new(ss::SsFactory));
    #[cfg(feature = "cr-ws")]   v.push(Arc::new(ws::WsFactory));
    #[cfg(feature = "cr-awg")]  v.push(Arc::new(awg::AwgFactory));
    #[cfg(feature = "cr-xray")] v.push(Arc::new(xray::XrayFactory));
    v
}

/// The carriers named in `ids`, in that order. Unknown / not-compiled-in ids are skipped.
pub fn by_ids(ids: &[String]) -> Vec<Arc<dyn CarrierFactory>> {
    let all = registry();
    let mut out: Vec<Arc<dyn CarrierFactory>> = Vec::new();
    for id in ids {
        if let Some(f) = all.iter().find(|f| f.id().as_str() == id) {
            if !out.iter().any(|o| o.id() == f.id()) {
                out.push(f.clone());
            }
        }
    }
    out
}

pub fn built_ids() -> Vec<CarrierId> {
    registry().iter().map(|f| f.id()).collect()
}

pub fn all_disclosures() -> Vec<(CarrierId, Disclosure)> {
    registry().iter().map(|f| (f.id(), f.disclosure())).collect()
}

/// What a reachability probe can honestly say. `ProbeStatus` has no "unknown", and a UDP carrier's
/// probe only opens a local socket, so the CLI reports through this instead of printing a wrong yes/no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Reachable { rtt_ms: u32 },
    Blocked(String),
    /// The probe cannot tell (not a failure, not a success), with the reason and the way out.
    Unverifiable(String),
    Error(String),
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Reachable { rtt_ms } => write!(f, "reachable {rtt_ms} ms"),
            Verdict::Blocked(m) => write!(f, "blocked: {m}"),
            Verdict::Unverifiable(m) => write!(f, "unverifiable: {m}"),
            Verdict::Error(m) => write!(f, "error: {m}"),
        }
    }
}

/// Interpret a probe made WITHOUT the host's invite key (`carrier-test`, `check-host --carriers`).
/// UDP carriers answer "reachable" after opening a local socket only; a keyed TCP carrier rejects a
/// throwaway key the same way a blocking network would; a missing address is a usage gap.
pub fn keyless_verdict(id: CarrierId, st: &ProbeStatus) -> Verdict {
    const UDP: &str = "UDP gives no answer without the host's key, so this only shows that a socket can be opened here; connect with a real invite to find out";
    match st {
        ProbeStatus::Reachable { .. } if matches!(id, CarrierId::Udp | CarrierId::Ss | CarrierId::Awg) => Verdict::Unverifiable(UDP.into()),
        ProbeStatus::Reachable { rtt_ms } => Verdict::Reachable { rtt_ms: *rtt_ms },
        ProbeStatus::Blocked(m) if id == CarrierId::Ws && (m.contains("invalid peer certificate") || m.contains("404")) => Verdict::Unverifiable(
            "a web server answered, but a test without the invite key cannot pass its certificate pin / secret path (not the same as blocked)".into(),
        ),
        ProbeStatus::Blocked(m) => Verdict::Blocked(m.clone()),
        ProbeStatus::Error(m) if m.contains("no endpoint") || m.contains("missing endpoint") => {
            Verdict::Unverifiable("no address to test: pass --endpoint host:port".into())
        }
        ProbeStatus::Error(m) => Verdict::Error(m.clone()),
    }
}

/// Small deterministic PRNG (splitmix64): padding, jitter and the in-memory test link. Not for
/// secrets.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn from_entropy() -> Self {
        let b = *uuid::Uuid::new_v4().as_bytes();
        Rng(u64::from_le_bytes(b[..8].try_into().unwrap()))
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in [0, 1).
    pub fn f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Uniform in [0, n); `n == 0` gives 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for c in buf.chunks_mut(8) {
            let r = self.next_u64().to_le_bytes();
            c.copy_from_slice(&r[..c.len()]);
        }
    }
}
