//! WireGuard Module
//!
//! Configuration only. No WireGuard crypto is available in this build, so the
//! module renders and validates `wg-quick` configuration files and leaves the
//! actual interface to the system's `wg`/`wg-quick` tools. It deliberately
//! performs no handshake of its own.

/// WireGuard interface and peer configuration
#[derive(Debug, Clone)]
pub struct WireguardConfig {
    /// Interface private key (32 bytes, base64)
    pub private_key: String,
    /// Interface listen port
    pub listen_port: u16,
    /// Interface address, e.g. `10.8.0.2/24`
    pub address: String,
    /// Peer public key (32 bytes, base64)
    pub peer_public_key: String,
    /// Peer allowed IPs, e.g. `10.8.0.0/24, 192.168.1.0/24`
    pub allowed_ips: String,
    /// Peer endpoint as `host:port`, when the peer is reachable directly
    pub endpoint: Option<String>,
    /// Persistent keepalive interval in seconds, when behind NAT
    pub persistent_keepalive: Option<u16>,
}

impl WireguardConfig {
    /// Render a `wg-quick` compatible configuration file.
    ///
    /// This does not validate; call [`WireguardConfig::validate`] first when the
    /// values come from user input.
    pub fn to_config_string(&self) -> String {
        let mut config = String::new();
        config.push_str("[Interface]\n");
        config.push_str(&format!("PrivateKey = {}\n", self.private_key.trim()));
        config.push_str(&format!("ListenPort = {}\n", self.listen_port));
        config.push_str(&format!("Address = {}\n", self.address.trim()));
        config.push_str("\n[Peer]\n");
        config.push_str(&format!("PublicKey = {}\n", self.peer_public_key.trim()));
        config.push_str(&format!("AllowedIPs = {}\n", self.allowed_ips.trim()));
        if let Some(endpoint) = self.endpoint.as_deref().map(str::trim) {
            if !endpoint.is_empty() {
                config.push_str(&format!("Endpoint = {endpoint}\n"));
            }
        }
        if let Some(keepalive) = self.persistent_keepalive {
            if keepalive > 0 {
                config.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
            }
        }
        config
    }

    /// Check that keys, port, address and endpoint are usable.
    pub fn validate(&self) -> Result<(), WireguardError> {
        if !is_key(&self.private_key) {
            return Err(WireguardError::InvalidKey("PrivateKey"));
        }
        if !is_key(&self.peer_public_key) {
            return Err(WireguardError::InvalidKey("PublicKey"));
        }
        if self.listen_port == 0 {
            return Err(WireguardError::InvalidPort(self.listen_port));
        }
        if self.address.trim().is_empty() {
            return Err(WireguardError::MissingField("Address"));
        }
        if self
            .allowed_ips
            .split(',')
            .all(|entry| entry.trim().is_empty())
        {
            return Err(WireguardError::MissingField("AllowedIPs"));
        }
        if let Some(endpoint) = self.endpoint.as_deref().map(str::trim) {
            if !endpoint.is_empty() && !is_endpoint(endpoint) {
                return Err(WireguardError::InvalidEndpoint(endpoint.to_string()));
            }
        }
        Ok(())
    }
}

/// WireGuard configuration validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireguardError {
    /// Field is not a base64-encoded 32-byte key
    InvalidKey(&'static str),
    /// Port number is not usable
    InvalidPort(u16),
    /// Required field is empty
    MissingField(&'static str),
    /// Endpoint is not in `host:port` form
    InvalidEndpoint(String),
}

impl std::fmt::Display for WireguardError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WireguardError::InvalidKey(field) => {
                write!(f, "{field} must be a base64-encoded 32-byte key")
            }
            WireguardError::InvalidPort(port) => write!(f, "invalid WireGuard port: {port}"),
            WireguardError::MissingField(field) => write!(f, "{field} must not be empty"),
            WireguardError::InvalidEndpoint(endpoint) => {
                write!(
                    f,
                    "invalid WireGuard endpoint '{endpoint}' (expected host:port)"
                )
            }
        }
    }
}

impl std::error::Error for WireguardError {}

/// A WireGuard key is 32 bytes in standard base64: 44 characters, the last of
/// which is `=`.
fn is_key(key: &str) -> bool {
    let key = key.trim();
    key.len() == 44
        && key.ends_with('=')
        && key[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// Accept `host:port` and `[ipv6]:port` with a non-zero numeric port.
fn is_endpoint(endpoint: &str) -> bool {
    let valid_port = |port: &str| port.parse::<u16>().map(|port| port > 0).unwrap_or(false);
    if let Some(rest) = endpoint.strip_prefix('[') {
        return match rest.split_once("]:") {
            Some((host, port)) => !host.is_empty() && valid_port(port),
            None => false,
        };
    }
    match endpoint.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && valid_port(port),
        None => false,
    }
}
