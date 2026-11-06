//! TURN Server Integration
//!
//! Minimal RFC 5766 Allocate/Refresh over UDP, used to obtain a relayed
//! address when direct connectivity is not possible.
//!
//! Limitation: MESSAGE-INTEGRITY is not implemented (no crypto crate is
//! available), so only servers that allow unauthenticated allocations work.
//! Servers that demand long-term credentials answer 401 and the error is
//! reported verbatim instead of pretending the allocation succeeded.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    /// Host name or IP address of the TURN server
    pub address: String,
    /// UDP port of the TURN server
    pub port: u16,
    /// Long-term credential user name (sent, but not used for integrity)
    pub username: String,
    /// Long-term credential password (unused without MESSAGE-INTEGRITY)
    pub password: String,
}

/// TURN Allocation
#[derive(Debug)]
pub struct Allocation {
    /// Client-side identifier for this allocation
    pub id: String,
    /// Relay address the TURN server allocated for us
    pub relayed_addr: SocketAddr,
    /// Lifetime granted by the server, in seconds
    pub lifetime: u32,
    /// Server this allocation lives on
    server: SocketAddr,
    /// Socket that owns the allocation's 5-tuple
    socket: UdpSocket,
}

/// TURN Server
///
/// Handles TURN server communication for NAT hole punching.
#[derive(Debug, Clone)]
pub struct TurnServer {
    /// TURN server configuration
    config: TurnServerConfig,
    /// Timeout for a single TURN transaction
    timeout: Duration,
}

impl TurnServer {
    /// Create a new TURN server client with a 3 second request timeout.
    pub fn new(config: TurnServerConfig) -> Self {
        Self {
            config,
            timeout: Duration::from_secs(3),
        }
    }

    /// Request a relayed address (Allocate).
    ///
    /// The allocation's UDP socket is kept inside the returned [`Allocation`]
    /// so it can be refreshed or released later.
    pub async fn allocate(&self) -> Result<Allocation, TurnError> {
        let server = stun::resolve(&self.config.address, self.config.port)
            .await
            .map_err(TurnError::ServerUnreachable)?;
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| TurnError::NetworkError(format!("bind local UDP socket: {e}")))?;

        let mut attributes = Vec::new();
        // REQUESTED-TRANSPORT: UDP (17), then three reserved zero bytes.
        push_attribute(&mut attributes, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        push_attribute(
            &mut attributes,
            ATTR_LIFETIME,
            &DEFAULT_LIFETIME.to_be_bytes(),
        );
        if !self.config.username.is_empty() {
            push_attribute(
                &mut attributes,
                ATTR_USERNAME,
                self.config.username.as_bytes(),
            );
        }

        let (message_type, attributes) =
            exchange(&socket, server, ALLOCATE_REQUEST, &attributes, self.timeout).await?;
        match message_type {
            ALLOCATE_SUCCESS => {}
            ALLOCATE_ERROR => return Err(message_error(&attributes)),
            _ => return Err(TurnError::InvalidResponse),
        }

        let relayed_addr = attributes
            .iter()
            .find(|(kind, _)| *kind == ATTR_XOR_RELAYED_ADDRESS)
            .and_then(|(_, value)| stun::parse_xor_address(value))
            .ok_or(TurnError::InvalidResponse)?;
        let lifetime = attributes
            .iter()
            .find(|(kind, _)| *kind == ATTR_LIFETIME)
            .and_then(|(_, value)| value.get(..4))
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .unwrap_or(DEFAULT_LIFETIME);

        log::debug!("TURN allocation on {server} relays {relayed_addr}");
        Ok(Allocation {
            id: uuid::Uuid::new_v4().to_string(),
            relayed_addr,
            lifetime,
            server,
            socket,
        })
    }

    /// Refresh an allocation, or release it when `lifetime` is zero
    /// (Refresh with lifetime 0 is the protocol's way to cancel).
    pub async fn refresh(&self, allocation: &Allocation, lifetime: u32) -> Result<(), TurnError> {
        let mut attributes = Vec::new();
        push_attribute(&mut attributes, ATTR_LIFETIME, &lifetime.to_be_bytes());
        if !self.config.username.is_empty() {
            push_attribute(
                &mut attributes,
                ATTR_USERNAME,
                self.config.username.as_bytes(),
            );
        }

        let (message_type, response) = exchange(
            &allocation.socket,
            allocation.server,
            REFRESH_REQUEST,
            &attributes,
            self.timeout,
        )
        .await?;
        match message_type {
            REFRESH_SUCCESS => Ok(()),
            REFRESH_ERROR => Err(message_error(&response)),
            _ => Err(TurnError::InvalidResponse),
        }
    }
}

/// TURN Error
#[derive(Debug)]
pub enum TurnError {
    /// The server name could not be resolved or the request could not be sent
    ServerUnreachable(String),
    /// The server answered, but with an error response
    RequestFailed(String),
    /// The response was malformed or lacked a relayed address
    InvalidResponse,
    /// No matching response arrived before the timeout
    Timeout,
    /// Local socket error while sending or receiving
    NetworkError(String),
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TurnError::ServerUnreachable(msg) => write!(f, "TURN server not reachable: {msg}"),
            TurnError::RequestFailed(msg) => write!(f, "TURN request failed: {msg}"),
            TurnError::InvalidResponse => write!(f, "invalid TURN response"),
            TurnError::Timeout => write!(f, "TURN request timed out"),
            TurnError::NetworkError(msg) => write!(f, "network error: {msg}"),
        }
    }
}

impl std::error::Error for TurnError {}

use crate::tunnel::stun;

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;
const REFRESH_ERROR: u16 = 0x0114;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_ERROR_CODE: u16 = 0x0009;

/// Lifetime requested when the caller does not specify one (10 minutes).
const DEFAULT_LIFETIME: u32 = 600;

/// Append one attribute, padding the value to a 4-byte boundary.
fn push_attribute(attributes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    attributes.extend_from_slice(&kind.to_be_bytes());
    attributes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attributes.extend_from_slice(value);
    while attributes.len() % 4 != 0 {
        attributes.push(0);
    }
}

/// Send one TURN request and return the matching response type and attributes.
async fn exchange(
    socket: &UdpSocket,
    server: SocketAddr,
    request_type: u16,
    attributes: &[u8],
    wait: Duration,
) -> Result<(u16, Vec<(u16, Vec<u8>)>), TurnError> {
    let transaction_id = stun::new_transaction_id();
    let request = stun::message(request_type, attributes, &transaction_id);
    socket
        .send_to(&request, server)
        .await
        .map_err(|e| TurnError::ServerUnreachable(format!("send to {server}: {e}")))?;

    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = [0u8; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TurnError::Timeout);
        }
        let received = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| TurnError::Timeout)?;
        let (len, _from) =
            received.map_err(|e| TurnError::NetworkError(format!("receive: {e}")))?;
        let packet = &buf[..len];
        if packet.len() < 20
            || u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]])
                != stun::MAGIC_COOKIE
            || &packet[8..20] != transaction_id
        {
            // Stray or late datagram, not the answer we are waiting for.
            continue;
        }

        let message_type = u16::from_be_bytes([packet[0], packet[1]]);
        let attributes = stun::attributes(packet)
            .map_err(|_| TurnError::InvalidResponse)?
            .into_iter()
            .map(|(kind, value)| (kind, value.to_vec()))
            .collect();
        return Ok((message_type, attributes));
    }
}

/// Turn an error response's ERROR-CODE attribute into a precise error.
fn message_error(attributes: &[(u16, Vec<u8>)]) -> TurnError {
    let detail = attributes
        .iter()
        .find(|(kind, _)| *kind == ATTR_ERROR_CODE)
        .map(|(_, value)| stun::describe_error_code(value))
        .unwrap_or_else(|| "error response without ERROR-CODE".to_string());
    TurnError::RequestFailed(detail)
}
