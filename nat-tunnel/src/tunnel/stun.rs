//! STUN Client
//!
//! Minimal RFC 5389 Binding support over UDP: just enough to learn the
//! public address a NAT gives us. No authentication is needed for Binding.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

/// STUN Server Configuration
#[derive(Debug, Clone)]
pub struct StunServerConfig {
    /// Host name or IP address of the STUN server
    pub address: String,
    /// UDP port of the STUN server
    pub port: u16,
}

/// NAT Type Enumeration
///
/// Produced by comparing the mappings several STUN servers (distinct IPs) see
/// for one local socket (RFC 4787 mapping behaviour), not by the RFC 3489
/// test sequence. Filtering behaviour is not measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No evidence of port rewriting; the mapping looks endpoint-independent.
    FullCone,
    /// Same mapping from both servers but no test of inbound reachability was
    /// performed, so this is the best guess for an endpoint-independent mapping.
    RestrictedCone,
    /// The mapping depends on the destination (address or port), or the
    /// public IP differs per server.
    Symmetric,
    /// No STUN server answered at all.
    Block,
    /// Not enough evidence to classify (e.g. only one server was reachable).
    Unknown,
}

/// STUN Client
///
/// Handles STUN protocol communication for NAT discovery.
#[derive(Debug, Clone)]
pub struct StunClient {
    /// STUN server configuration
    config: StunServerConfig,
    /// Timeout for a single Binding request
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client with a 3 second request timeout.
    pub fn new(config: StunServerConfig) -> Self {
        Self {
            config,
            timeout: Duration::from_secs(3),
        }
    }

    /// Query the configured server from a fresh local UDP socket and return
    /// the reflexive (public) address it reports.
    pub async fn mapped_addr(&self) -> Result<SocketAddr, StunError> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| StunError::NetworkError(format!("bind local UDP socket: {e}")))?;
        self.mapped_addr_on(&socket).await
    }

    /// Query the configured server over an existing socket.
    ///
    /// Sharing the socket matters for NAT classification: two servers must see
    /// the same local 5-tuple for their answers to be comparable.
    pub async fn mapped_addr_on(&self, socket: &UdpSocket) -> Result<SocketAddr, StunError> {
        let server = resolve(&self.config.address, self.config.port)
            .await
            .map_err(StunError::ServerUnreachable)?;
        binding_request(socket, server, self.timeout).await
    }
}

/// STUN Error
#[derive(Debug)]
pub enum StunError {
    /// The server name could not be resolved or the request could not be sent
    ServerUnreachable(String),
    /// The server answered, but with an error response
    RequestFailed(String),
    /// The response was malformed or carried no usable mapping
    InvalidResponse,
    /// No matching response arrived before the timeout
    Timeout,
    /// Local socket error while sending or receiving
    NetworkError(String),
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StunError::ServerUnreachable(msg) => write!(f, "STUN server not reachable: {msg}"),
            StunError::RequestFailed(msg) => write!(f, "STUN request failed: {msg}"),
            StunError::InvalidResponse => write!(f, "invalid STUN response"),
            StunError::Timeout => write!(f, "STUN request timed out"),
            StunError::NetworkError(msg) => write!(f, "network error: {msg}"),
        }
    }
}

impl std::error::Error for StunError {}

/// The fixed STUN magic cookie (`"STUN"` in ASCII).
pub(crate) const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Send a Binding request on `socket` without waiting for the answer.
///
/// Used to refresh a NAT mapping. The response carries the public address, but
/// keeping the mapping alive only needs traffic on the same 5-tuple; for a cone
/// NAT one server is enough because the mapping is shared.
pub async fn poke(socket: &UdpSocket, server: SocketAddr) -> Result<(), StunError> {
    let transaction_id = new_transaction_id();
    remember_poke(transaction_id);
    let request = message(BINDING_REQUEST, &[], &transaction_id);
    socket
        .send_to(&request, server)
        .await
        .map(|_| ())
        .map_err(|e| StunError::ServerUnreachable(format!("send to {server}: {e}")))
}

/// Send one Binding request and wait for the matching success response.
async fn binding_request(
    socket: &UdpSocket,
    server: SocketAddr,
    wait: Duration,
) -> Result<SocketAddr, StunError> {
    let transaction_id = new_transaction_id();
    let request = message(BINDING_REQUEST, &[], &transaction_id);
    socket
        .send_to(&request, server)
        .await
        .map_err(|e| StunError::ServerUnreachable(format!("send to {server}: {e}")))?;

    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = [0u8; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StunError::Timeout);
        }
        let received = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| StunError::Timeout)?;
        let (len, _from) =
            received.map_err(|e| StunError::NetworkError(format!("receive: {e}")))?;
        match parse_binding_response(&buf[..len], &transaction_id)? {
            Some(mapped) => return Ok(mapped),
            // A late answer to an earlier transaction: keep waiting.
            None => continue,
        }
    }
}

/// Transaction ids of the most recent [`poke`]s of this process. An answer must carry one of
/// them, so nobody off the path can forge a mapping by spoofing a STUN server's address.
static POKES: std::sync::Mutex<std::collections::VecDeque<[u8; 12]>> = std::sync::Mutex::new(std::collections::VecDeque::new());
const POKES_KEPT: usize = 256;

fn remember_poke(id: [u8; 12]) {
    let mut p = POKES.lock().unwrap();
    if p.len() >= POKES_KEPT {
        p.pop_front();
    }
    p.push_back(id);
}

/// The mapped address in a Binding success response that answers one of this process's recent
/// [`poke`]s. For callers that fire `poke`s on a shared socket and read the answers from their
/// own receive loop.
pub fn mapped_from_response(packet: &[u8]) -> Option<SocketAddr> {
    let id: [u8; 12] = packet.get(8..20)?.try_into().ok()?;
    if !POKES.lock().unwrap().contains(&id) {
        return None;
    }
    parse_binding_response(packet, &id).ok().flatten()
}

/// Parse a message, returning `Ok(None)` when it is not the answer to
/// `transaction_id` (stray or late traffic) and an error only when the message
/// is ours but malformed.
fn parse_binding_response(
    packet: &[u8],
    transaction_id: &[u8; 12],
) -> Result<Option<SocketAddr>, StunError> {
    if packet.len() < 20 {
        return Ok(None);
    }
    if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != MAGIC_COOKIE {
        return Ok(None);
    }
    if &packet[8..20] != transaction_id {
        return Ok(None);
    }

    let attributes = attributes(packet)?;
    match u16::from_be_bytes([packet[0], packet[1]]) {
        BINDING_ERROR => {
            let reason = attributes
                .iter()
                .find(|(kind, _)| *kind == ATTR_ERROR_CODE)
                .map(|(_, value)| describe_error_code(value))
                .unwrap_or_else(|| "unspecified error".to_string());
            Err(StunError::RequestFailed(reason))
        }
        BINDING_SUCCESS => {
            let xor_mapped = attributes
                .iter()
                .find(|(kind, _)| *kind == ATTR_XOR_MAPPED_ADDRESS)
                .and_then(|(_, value)| parse_xor_address(value));
            let mapped = attributes
                .iter()
                .find(|(kind, _)| *kind == ATTR_MAPPED_ADDRESS)
                .and_then(|(_, value)| parse_plain_address(value));
            xor_mapped
                .or(mapped)
                .map(Some)
                .ok_or(StunError::InvalidResponse)
        }
        _ => Err(StunError::InvalidResponse),
    }
}

/// Split a STUN message into `(type, value)` attribute pairs.
///
/// Values are returned without the 4-byte alignment padding.
pub(crate) fn attributes(packet: &[u8]) -> Result<Vec<(u16, &[u8])>, StunError> {
    if packet.len() < 20 {
        return Err(StunError::InvalidResponse);
    }
    let body_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = 20usize
        .checked_add(body_len)
        .ok_or(StunError::InvalidResponse)?;
    if packet.len() < end {
        return Err(StunError::InvalidResponse);
    }

    let mut attributes = Vec::new();
    let mut offset = 20;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let start = offset + 4;
        let stop = start.checked_add(len).ok_or(StunError::InvalidResponse)?;
        if stop > end {
            return Err(StunError::InvalidResponse);
        }
        attributes.push((kind, &packet[start..stop]));
        // Each attribute is padded to a 4-byte boundary.
        offset = stop + (4 - len % 4) % 4;
    }
    Ok(attributes)
}

/// Parse an XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS value (RFC 5389 §15.2).
///
/// Only IPv4 is handled; an IPv6 mapping yields `None`.
pub(crate) fn parse_xor_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 || value[1] != 0x01 {
        return None;
    }
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
    let address = Ipv4Addr::new(
        value[4] ^ cookie[0],
        value[5] ^ cookie[1],
        value[6] ^ cookie[2],
        value[7] ^ cookie[3],
    );
    Some(SocketAddr::new(IpAddr::V4(address), port))
}

/// Parse a plain MAPPED-ADDRESS value, which only some servers still send.
fn parse_plain_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 || value[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    let address = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
    Some(SocketAddr::new(IpAddr::V4(address), port))
}

/// Render an ERROR-CODE attribute value as `"<code> <reason>"`.
pub(crate) fn describe_error_code(value: &[u8]) -> String {
    if value.len() < 4 {
        return "malformed ERROR-CODE".to_string();
    }
    let class = u16::from(value[2] & 0x07);
    let number = u16::from(value[3]);
    let reason = String::from_utf8_lossy(&value[4..])
        .trim_matches('\0')
        .trim()
        .to_string();
    format!("{} {}", class * 100 + number, reason)
}

/// Build a STUN message header plus the already-encoded attribute bytes.
pub fn message(message_type: u16, attributes: &[u8], transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + attributes.len());
    packet.extend_from_slice(&message_type.to_be_bytes());
    packet.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(transaction_id);
    packet.extend_from_slice(attributes);
    packet
}

/// A random 96-bit STUN transaction id.
pub(crate) fn new_transaction_id() -> [u8; 12] {
    let uuid = uuid::Uuid::new_v4().into_bytes();
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&uuid[..12]);
    transaction_id
}

/// Resolve a host and port, preferring IPv4 because the STUN socket is IPv4.
pub(crate) async fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("{host}:{port}: {e}"))?
        .collect();
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
        .ok_or_else(|| format!("{host}:{port}: no addresses"))
}

/// One answered Binding request: which server, and what it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub server: SocketAddr,
    pub mapped: SocketAddr,
}

/// Public default servers from independent operators (>= 3 distinct IPv4s).
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.l.google.com:3478",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
    "stun.sipgate.net:3478",
];

/// Resolve `host:port` entries to IPv4 socket addresses concurrently, dropping
/// failures and exact duplicates (same IP and port).
pub async fn resolve_servers(entries: &[String]) -> Vec<SocketAddr> {
    let lookups = entries.iter().map(|e| async move {
        let (host, port) = e.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let found = tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((host, port)))
            .await
            .ok()?
            .ok()?;
        found.into_iter().find(SocketAddr::is_ipv4)
    });
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in futures::future::join_all(lookups).await.into_iter().flatten() {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Query all `servers` from the same `socket` at once (responses matched by
/// transaction id): per-round timeout `round`, one retry for silent servers.
/// Samples come back in the order of `servers`.
pub async fn survey(socket: &UdpSocket, servers: &[SocketAddr], round: Duration) -> Vec<Sample> {
    let mut pending: HashMap<[u8; 12], SocketAddr> = HashMap::new();
    let mut got: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut buf = [0u8; 1500];
    for _attempt in 0..2 {
        for server in servers.iter().filter(|s| !got.contains_key(*s)) {
            let id = new_transaction_id();
            if socket.send_to(&message(BINDING_REQUEST, &[], &id), server).await.is_ok() {
                pending.insert(id, *server);
            }
        }
        let deadline = tokio::time::Instant::now() + round;
        while got.len() < servers.len() {
            let (len, _) = match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok(r)) => r,
                // Windows reports an ICMP "port unreachable" from an earlier send (a dead server)
                // as ConnectionReset on the next receive; the other servers may still answer.
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                _ => break,
            };
            if len < 20 {
                continue;
            }
            let id: [u8; 12] = buf[8..20].try_into().unwrap();
            if let Some(server) = pending.get(&id).copied() {
                if let Ok(Some(mapped)) = parse_binding_response(&buf[..len], &id) {
                    got.insert(server, mapped);
                }
            }
        }
        if got.len() == servers.len() {
            break;
        }
    }
    servers
        .iter()
        .filter_map(|s| got.get(s).map(|m| Sample { server: *s, mapped: *m }))
        .collect()
}

/// Classify mapping behaviour from per-server observations (RFC 4787).
///
/// Needs answers from at least two servers with different IPs; otherwise
/// the result is `Unknown` (or `Block` when nobody answered). An
/// endpoint-independent mapping is reported as `RestrictedCone` because
/// filtering is not measured. The string explains the verdict and lists the
/// evidence. Port-prediction hints are informational only.
pub fn classify(samples: &[Sample]) -> (NatType, String) {
    let mut s: Vec<Sample> = Vec::new();
    for x in samples.iter().filter(|x| x.server.is_ipv4() && x.mapped.is_ipv4()) {
        if !s.iter().any(|y| y.server == x.server) {
            s.push(*x);
        }
    }
    if s.is_empty() {
        return (NatType::Block, "no STUN server answered over IPv4".into());
    }
    let evidence = s
        .iter()
        .map(|x| format!("{}->{}", x.server, x.mapped))
        .collect::<Vec<_>>()
        .join(", ");
    let mut ips: Vec<_> = s.iter().map(|x| x.server.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.len() < 2 {
        return (
            NatType::Unknown,
            format!("only one distinct STUN server IP answered, cannot compare mappings ({evidence})"),
        );
    }
    let mut pub_ips: Vec<_> = s.iter().map(|x| x.mapped.ip()).collect();
    pub_ips.sort();
    pub_ips.dedup();
    let first = s[0].mapped.port();
    let deltas = || {
        s.iter()
            .map(|x| format!("{:+}", i32::from(x.mapped.port()) - i32::from(first)))
            .collect::<Vec<_>>()
            .join(",")
    };
    if pub_ips.len() > 1 {
        return (
            NatType::Symmetric,
            format!("public IP differs between servers (multi-WAN or CGNAT pool); port deltas {} ({evidence})", deltas()),
        );
    }
    if s.iter().all(|x| x.mapped.port() == first) {
        return (
            NatType::RestrictedCone,
            format!("endpoint-independent mapping across {} server IPs (filtering not measured) ({evidence})", ips.len()),
        );
    }
    // Same mapped port toward every IP but varying per port of one IP?
    let by_ip_consistent = ips.iter().all(|ip| {
        let mut it = s.iter().filter(|x| x.server.ip() == *ip).map(|x| x.mapped.port());
        let f = it.next();
        it.all(|p| Some(p) == f)
    });
    let ports: Vec<u16> = s.iter().map(|x| x.mapped.port()).collect();
    let kind = if by_ip_consistent { "address-dependent mapping" } else { "port-dependent mapping" };
    let mut sorted = ports.clone();
    sorted.sort();
    let sequential = sorted.windows(2).all(|w| w[1] - w[0] <= 8);
    let hint = if sequential { "; ports look sequential (predictable allocation)" } else { "" };
    (
        NatType::Symmetric,
        format!("{kind}: mapped port differs per destination; deltas {}{hint} ({evidence})", deltas()),
    )
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    fn smp(server: &str, mapped: &str) -> Sample {
        Sample { server: server.parse().unwrap(), mapped: mapped.parse().unwrap() }
    }

    #[test]
    fn classify_table() {
        use NatType::*;
        let cases: Vec<(&str, Vec<Sample>, NatType, &str)> = vec![
            ("all same", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("2.2.2.2:3478", "9.9.9.9:5000"), smp("2.2.2.2:19302", "9.9.9.9:5000")], RestrictedCone, "endpoint-independent"),
            ("differs by ip", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("2.2.2.2:3478", "9.9.9.9:5001"), smp("2.2.2.2:19302", "9.9.9.9:5001")], Symmetric, "address-dependent"),
            ("differs by port only", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("2.2.2.2:3478", "9.9.9.9:5000"), smp("2.2.2.2:19302", "9.9.9.9:6000")], Symmetric, "port-dependent"),
            ("one server", vec![smp("1.1.1.1:3478", "9.9.9.9:5000")], Unknown, "only one distinct"),
            ("none", vec![], Block, "no STUN"),
            ("same ip twice is one", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("1.1.1.1:19302", "9.9.9.9:5000")], Unknown, "only one distinct"),
            ("mixed public ips", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("2.2.2.2:3478", "8.8.8.8:5000")], Symmetric, "public IP differs"),
            ("ipv6 ignored", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("[2001:db8::1]:3478", "[2001:db8::2]:5001")], Unknown, "only one distinct"),
            ("sequential hint", vec![smp("1.1.1.1:3478", "9.9.9.9:5000"), smp("2.2.2.2:3478", "9.9.9.9:5001")], Symmetric, "sequential"),
        ];
        for (name, samples, want, text) in cases {
            let (kind, detail) = classify(&samples);
            assert_eq!(kind, want, "{name}: {detail}");
            assert!(detail.contains(text), "{name}: {detail}");
        }
    }
}
