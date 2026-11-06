//! Self-contained invite strings.
//!
//! Everything needed to reach a host travels in one string the user copies
//! offline (chat, paper, QR). No lookup, no directory, no third server is
//! required to interpret it.
//!
//! Current format:
//!
//! ```text
//! STRAIT2|<key>|<host>[,<host>...]|<signal>[,<signal>...]|<room>|<rv>[,<rv>...]|<cr>[,<cr>...]
//! ```
//!
//! * `key`       — pre-shared AEAD key. The signaling room is derived from it,
//!                 so it never appears in the string.
//! * `host`      — public UDP endpoint(s) the guest may dial directly. This is
//!                 the whole connection for a host with a public address.
//! * `signal`    — optional rendezvous service(s) used only to exchange
//!                 observed addresses when the host is behind NAT.
//!
//! * `rv`       — optional rendezvous method ids (`sig`, `trk`, `nostr`, `dht`, ...), each
//!                 `[a-z0-9]{1,12}`, at most 8. Unknown ids are kept (forward compatibility).
//!                 It follows the (normally empty) legacy `room` field, so older parsers,
//!                 which ignore extra fields, still read the rest unchanged. For
//!                 convenience a lone 4th field that is a comma list or a known method id
//!                 (`sig`, `trk`, `nostr`, `dht`, `ntfy`, `mqtt`) is read as `rv`, not `room`.
//!
//! * `cr`       — optional tunnel carriers in the host's preference order, at most 8, each
//!                 `id[@host:port][;k=v;k=v]` with `%XX` escapes (`, ; = | % @` and anything
//!                 outside `A-Za-z0-9-._~/:[]` are escaped). Ids are [`CarrierId`]s; unknown ids
//!                 are kept verbatim and ignored at run time. Parameters are an allow-list per
//!                 carrier ([`CarrierEntry::allowed_params`]: ws `path`/`sni`, xray
//!                 `sni`/`mode`/`port`, ss and awg none), never secrets: every secret derives
//!                 from `key`. `udp` is implicit and need not be listed.
//!                 e.g. `STRAIT2|key|1.2.3.4:7100||||ss@1.2.3.4:8388,ws@h.example:443;sni=h.example`.
//!
//! Empty trailing fields may be omitted, so a public-IP host produces
//! `STRAIT2|<key>|<host>`. The previous `signal:port|room|key` form is still
//! accepted when parsing, and an explicit room is still honoured for it.

use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use crate::carrier::{CarrierEntry, ParsedEntry, MAX_CARRIER_ENTRIES};

/// A `host:port` the invite points at: an IP literal or a DNS name.
/// Parsing never touches the network; call [`resolve`] at connect time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Addr(SocketAddr),
    Name { host: String, port: u16 },
}

impl From<SocketAddr> for Endpoint {
    fn from(a: SocketAddr) -> Self {
        Endpoint::Addr(a)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Addr(a) => write!(f, "{a}"),
            Endpoint::Name { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl FromStr for Endpoint {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            if a.port() == 0 {
                return Err("port must be 1-65535".into());
            }
            return Ok(Endpoint::Addr(a));
        }
        let (host, port) = s.rsplit_once(':').ok_or("expected host:port")?;
        let port: u16 = port.parse().map_err(|_| "bad port")?;
        if port == 0 {
            return Err("port must be 1-65535".into());
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.is_empty() || host.len() > 253 {
            return Err("bad hostname length".into());
        }
        let labels: Vec<&str> = host.split('.').collect();
        for l in &labels {
            let b = l.as_bytes();
            if b.is_empty()
                || b.len() > 63
                || b[0] == b'-'
                || b[b.len() - 1] == b'-'
                || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            {
                return Err("bad hostname label".into());
            }
        }
        // An all-numeric last label would be a malformed IPv4 literal, not a name.
        if labels.last().is_some_and(|l| l.bytes().all(|c| c.is_ascii_digit())) {
            return Err("invalid IP address".into());
        }
        Ok(Endpoint::Name { host: host.to_string(), port })
    }
}

/// Resolve endpoints off the async runtime. Per entry, IPv6 results come
/// before IPv4; entry order is kept. One failing entry does not fail the
/// others; if nothing resolves at all the error names every entry.
pub async fn resolve(endpoints: &[Endpoint]) -> Result<Vec<SocketAddr>, String> {
    if endpoints.is_empty() {
        return Ok(Vec::new());
    }
    let eps = endpoints.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut out: Vec<SocketAddr> = Vec::new();
        let mut errs = Vec::new();
        for ep in &eps {
            match ep {
                Endpoint::Addr(a) => out.push(*a),
                Endpoint::Name { host, port } => match (host.as_str(), *port).to_socket_addrs() {
                    Ok(it) => {
                        let mut v: Vec<SocketAddr> = it.collect();
                        v.sort_by_key(|a| a.is_ipv4()); // stable: v6 first
                        if v.is_empty() {
                            errs.push(format!("{ep}: no addresses"));
                        }
                        for a in v {
                            if !out.contains(&a) {
                                out.push(a);
                            }
                        }
                    }
                    Err(e) => errs.push(format!("{ep}: {e}")),
                },
            }
        }
        if out.is_empty() {
            Err(format!("could not resolve {}", errs.join("; ")))
        } else {
            Ok(out)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Like [`resolve`], but IPv4 only: the signaling protocol cannot carry IPv6.
pub async fn resolve_signals(endpoints: &[Endpoint]) -> Result<Vec<SocketAddr>, String> {
    let mut v = resolve(endpoints).await?;
    v.retain(|a| a.is_ipv4());
    if v.is_empty() && !endpoints.is_empty() {
        return Err("signal server has no IPv4 address (signaling is IPv4-only)".into());
    }
    Ok(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub key: String,
    /// Direct host endpoint(s), tried in order.
    pub hosts: Vec<Endpoint>,
    /// Optional signaling server(s), tried in order.
    pub signals: Vec<Endpoint>,
    /// Legacy explicit room. Empty means "derive from the key".
    pub room: String,
    /// Rendezvous method ids chosen by the host (empty = none listed).
    pub rv: Vec<String>,
    /// Carriers this build knows, in the host's preference order (empty = plain UDP).
    pub cr: Vec<CarrierEntry>,
    /// Entries with an id this version does not know: `(position in the original list, text)`.
    /// Kept so the invite re-encodes unchanged; ignored at run time.
    pub cr_unknown: Vec<(usize, String)>,
}

pub const MAX_RV: usize = 8;
const KNOWN_RV: &[&str] = &["sig", "trk", "nostr", "dht", "ntfy", "mqtt"];

fn valid_rv_id(s: &str) -> bool {
    (1..=12).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Parse a comma list of rv ids; `None` if any id is invalid or there are more than [`MAX_RV`].
/// Empty items are skipped and duplicates dropped.
fn parse_rv(value: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if !valid_rv_id(part) {
            return None;
        }
        if !out.iter().any(|o| o == part) {
            out.push(part.to_string());
        }
    }
    (out.len() <= MAX_RV).then_some(out)
}

impl Invite {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            hosts: Vec::new(),
            signals: Vec::new(),
            room: String::new(),
            rv: Vec::new(),
            cr: Vec::new(),
            cr_unknown: Vec::new(),
        }
    }

    /// Add a carrier entry. Parameters outside its allow-list are dropped; anything past
    /// [`MAX_CARRIER_ENTRIES`] is ignored.
    pub fn carrier(&self, entry: CarrierEntry) -> Self {
        let mut next = self.clone();
        if next.cr.len() + next.cr_unknown.len() < MAX_CARRIER_ENTRIES {
            next.cr.push(entry.sanitized());
        }
        next
    }

    /// Add a rendezvous method id. Invalid ids, duplicates and anything past [`MAX_RV`] are ignored.
    pub fn rv(&self, id: impl Into<String>) -> Self {
        let id = id.into();
        let mut next = self.clone();
        if valid_rv_id(&id) && !next.rv.contains(&id) && next.rv.len() < MAX_RV {
            next.rv.push(id);
        }
        next
    }

    /// The 16-byte rendezvous key, if `key` is 32 hex characters.
    pub fn key_bytes(&self) -> Option<[u8; 16]> {
        crate::rendezvous::derive::parse_key(&self.key)
    }

    pub fn host(&self, addr: impl Into<Endpoint>) -> Self {
        let mut next = self.clone();
        next.hosts.push(addr.into());
        next
    }

    pub fn signal(&self, addr: impl Into<Endpoint>) -> Self {
        let mut next = self.clone();
        next.signals.push(addr.into());
        next
    }

    pub fn room(mut self, room: impl Into<String>) -> Self {
        self.room = room.into();
        self
    }

    /// First endpoint to dial, if the invite carries one.
    pub fn host_endpoint(&self) -> Option<&Endpoint> {
        self.hosts.first()
    }

    /// First signaling server, if the invite carries one.
    pub fn signal_server(&self) -> Option<&Endpoint> {
        self.signals.first()
    }

    pub fn encode(&self) -> String {
        let hosts = self
            .hosts
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let signals = self
            .signals
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // The room is derived from the key, so it is not emitted. Trailing fields are kept only as
        // far as needed, so invites without `cr` stay byte-identical to the older format.
        let cr = self.encode_cr();
        let n = if !cr.is_empty() {
            6
        } else if !self.rv.is_empty() || rv_shaped(&self.room) {
            5 // a legacy room that looks like rv ids must not be read as rv
        } else if !self.room.is_empty() {
            4
        } else if !signals.is_empty() {
            3
        } else {
            2
        };
        let rv = self.rv.join(",");
        let fields = [self.key.as_str(), &hosts, &signals, &self.room, &rv, &cr];
        format!("STRAIT2|{}", fields[..n].join("|"))
    }

    /// The `cr` field: known and unknown entries back in their original order.
    fn encode_cr(&self) -> String {
        let total = self.cr.len() + self.cr_unknown.len();
        let (mut known, mut out) = (self.cr.iter(), Vec::with_capacity(total));
        for i in 0..total {
            match self.cr_unknown.iter().find(|(p, _)| *p == i) {
                Some((_, raw)) => out.push(raw.clone()),
                None => out.extend(known.next().map(|e| e.to_string())),
            }
        }
        out.join(",")
    }

    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        if let Some(rest) = value.strip_prefix("STRAIT2|") {
            return Self::parse_current(rest);
        }
        // Legacy: `signal:port|room|key`.
        let parts: Vec<&str> = value.split('|').map(str::trim).collect();
        if parts.len() == 3 && !parts[1].contains(':') {
            let server: Endpoint = parts[0].parse().ok()?;
            let room = parts[1];
            let key = parts[2];
            if room.is_empty() || key.is_empty() {
                return None;
            }
            return Some(Self {
                key: key.to_string(),
                hosts: Vec::new(),
                signals: vec![server],
                room: room.to_string(),
                rv: Vec::new(),
                cr: Vec::new(),
                cr_unknown: Vec::new(),
            });
        }
        // Bare `STRAIT2|<key>|<host>` without the prefix is also accepted.
        Self::parse_current(value)
    }

    fn parse_current(rest: &str) -> Option<Self> {
        let fields: Vec<&str> = rest.split('|').map(str::trim).collect();
        let key = *fields.first()?;
        if key.is_empty() || key.contains('@') {
            return None;
        }
        let hosts = parse_addrs(fields.get(1).copied().unwrap_or(""))?;
        let signals = parse_addrs(fields.get(2).copied().unwrap_or(""))?;
        let mut room = fields.get(3).copied().unwrap_or("").to_string();
        let mut rv = Vec::new();
        if let Some(f) = fields.get(4) {
            rv = parse_rv(f)?;
        } else if rv_shaped(&room) {
            rv = parse_rv(&room)?;
            room.clear();
        }
        let (cr, cr_unknown) = match fields.get(5) {
            Some(f) => parse_cr(f)?,
            None => (Vec::new(), Vec::new()),
        };
        // An invite with no host, signal server, rendezvous method or carrier endpoint cannot
        // connect to anything, so a bare word is not an invite.
        if hosts.is_empty() && signals.is_empty() && rv.is_empty() && cr.iter().all(|c| c.endpoint.is_none()) {
            return None;
        }
        Some(Self {
            key: key.to_string(),
            hosts,
            signals,
            room,
            rv,
            cr,
            cr_unknown,
        })
    }
}

/// Parse the `cr` field; `None` if any entry is malformed or there are more than 8.
fn parse_cr(value: &str) -> Option<(Vec<CarrierEntry>, Vec<(usize, String)>)> {
    let (mut known, mut unknown) = (Vec::new(), Vec::new());
    let mut n = 0;
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match CarrierEntry::parse_entry(part).ok()? {
            ParsedEntry::Known(e) => known.push(e),
            ParsedEntry::Unknown(raw) => unknown.push((n, raw)),
        }
        n += 1;
        if n > MAX_CARRIER_ENTRIES {
            return None;
        }
    }
    Some((known, unknown))
}

/// A lone 4th field is `rv` (not a legacy room) if it is a comma list or a known method id.
fn rv_shaped(f: &str) -> bool {
    !f.is_empty()
        && f.split(',').all(|p| valid_rv_id(p.trim()))
        && (f.contains(',') || KNOWN_RV.contains(&f))
}

fn parse_addrs(value: &str) -> Option<Vec<Endpoint>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(part.parse::<Endpoint>().ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_host_invite_round_trips() {
        let host: SocketAddr = "203.0.113.10:7100".parse().unwrap();
        let invite = Invite::new("abc123").host(host);
        let text = invite.encode();
        assert_eq!(text, "STRAIT2|abc123|203.0.113.10:7100");
        let parsed = Invite::parse(&text).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.host_endpoint(), Some(&Endpoint::Addr(host)));
        assert_eq!(parsed.signal_server(), None);
    }

    #[test]
    fn nat_host_invite_carries_a_signal_server() {
        let signal: SocketAddr = "203.0.113.5:7000".parse().unwrap();
        // The room is derived from the key, so it is not in the string.
        let invite = Invite::new("abc123").signal(signal);
        let text = invite.encode();
        assert_eq!(text, "STRAIT2|abc123||203.0.113.5:7000");
        let parsed = Invite::parse(&text).unwrap();
        assert_eq!(parsed.signal_server(), Some(&Endpoint::Addr(signal)));
        assert_eq!(parsed.room, "");
        assert_eq!(parsed.host_endpoint(), None);
    }

    #[test]
    fn legacy_invite_still_parses() {
        let parsed = Invite::parse("203.0.113.10:7000|srvtest|01234567").unwrap();
        assert_eq!(parsed.room, "srvtest");
        assert_eq!(parsed.key, "01234567");
        assert_eq!(
            parsed.signal_server(),
            Some(&Endpoint::Addr("203.0.113.10:7000".parse().unwrap()))
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Invite::parse("").is_none());
        assert!(Invite::parse("hello").is_none());
        assert!(Invite::parse("STRAIT2|key|not-an-address").is_none());
    }

    #[test]
    fn hostnames_parse_and_round_trip() {
        let text = "STRAIT2|k|a-b.example.com:7100,203.0.113.10:1,[2001:db8::1]:7100|signal.example.com:7000";
        let p = Invite::parse(text).unwrap();
        assert_eq!(
            p.hosts[0],
            Endpoint::Name { host: "a-b.example.com".into(), port: 7100 }
        );
        assert_eq!(p.hosts.len(), 3);
        assert_eq!(p.encode(), text);
        assert!(Invite::parse("STRAIT2|k||localhost:65535").is_some());
    }

    #[test]
    fn bad_hostnames_rejected() {
        let long_label = "a".repeat(64);
        let long_name = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        for bad in [
            "-a.com:1", "a-.com:1", "a..com:1", ".com:1", "a b.com:1", "a.com:0",
            "a.com:65536", "a.com:", "a.com", "a_b.com:1", "a\u{7}.com:1", "999.1.1.1:80",
            "exämple.com:1", ":80",
        ] {
            assert!(Invite::parse(&format!("STRAIT2|k||{bad}")).is_none(), "{bad}");
        }
        assert!(Invite::parse(&format!("STRAIT2|k||{long_label}.com:1")).is_none());
        assert!(Invite::parse(&format!("STRAIT2|k||{long_name}:1")).is_none());
    }

    #[test]
    fn legacy_accepts_hostname() {
        let p = Invite::parse("sig.example.com:7000|room|key").unwrap();
        assert_eq!(p.signals[0].to_string(), "sig.example.com:7000");
    }

    #[tokio::test]
    async fn resolve_skips_failures_and_names_them() {
        let eps: Vec<Endpoint> = vec![
            "nonexistent.invalid:1".parse().unwrap(),
            "localhost:4242".parse().unwrap(),
        ];
        let got = resolve(&eps).await.unwrap();
        assert!(!got.is_empty() && got.iter().all(|a| a.port() == 4242 && a.ip().is_loopback()));
        let err = resolve(&eps[..1]).await.unwrap_err();
        assert!(err.contains("nonexistent.invalid:1"), "{err}");
    }
}
