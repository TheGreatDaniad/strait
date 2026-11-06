//! Configuration management for NAT Tunnel
//!
//! Handles loading and validation of configuration files,
//! environment variables, and user preferences.

use serde::{Deserialize, Serialize};

/// Configuration for NAT Tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// WireGuard configuration
    pub wireguard: WireguardConfig,
    /// NAT traversal settings
    pub nat_traversal: NatTraversalConfig,
    /// Remote access settings
    pub remote_access: RemoteAccessConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// WireGuard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardConfig {
    /// Listen port for WireGuard
    pub listen_port: u16,
    /// WireGuard private key (generated or loaded)
    pub private_key: Option<String>,
    /// WireGuard public key (generated or loaded)
    pub public_key: Option<String>,
    /// Allowed IP addresses
    pub allowed_ips: String,
    /// WireGuard endpoint
    pub endpoint: Option<String>,
}

/// NAT traversal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalConfig {
    /// Public TURN server address
    pub turn_server: String,
    /// TURN server port
    pub turn_port: u16,
    /// TURN server credentials
    pub turn_username: String,
    pub turn_password: String,
    /// STUN server address
    pub stun_server: String,
    /// STUN server port
    pub stun_port: u16,
    /// `host:port` STUN servers used for NAT classification (distinct IPs
    /// needed); the primary above is always queried too.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,
    /// Use TURN servers (false = NAT hole punching only)
    pub use_turn: bool,
}

/// Remote access configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAccessConfig {
    /// Port for remote access connections
    pub port: u16,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Device name for identification
    pub device_name: String,
    /// Unique identifier for the device
    pub device_id: String,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    pub level: String,
    /// Log file path (empty for stdout only)
    pub log_file: Option<String>,
}

fn default_stun_servers() -> Vec<String> {
    crate::tunnel::stun::DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
}

/// Read an env var and parse it, falling back to `default`.
fn var<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl Config {
    /// Load configuration from a YAML file
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&content)?)
    }

    /// Load configuration from environment variables
    pub fn load_from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Config {
            wireguard: WireguardConfig {
                listen_port: var("WIREGUARD_PORT", 51820),
                private_key: std::env::var("WIREGUARD_PRIVATE_KEY").ok(),
                public_key: std::env::var("WIREGUARD_PUBLIC_KEY").ok(),
                allowed_ips: var("WIREGUARD_ALLOWED_IPS", "0.0.0.0/0".to_string()),
                endpoint: std::env::var("WIREGUARD_ENDPOINT").ok(),
            },
            nat_traversal: NatTraversalConfig {
                turn_server: var("TURN_SERVER", "1.1.1.1".to_string()),
                turn_port: var("TURN_PORT", 443),
                turn_username: var("TURN_USERNAME", "user".to_string()),
                turn_password: var("TURN_PASSWORD", "pass".to_string()),
                stun_server: var("STUN_SERVER", "stun.l.google.com".to_string()),
                stun_port: var("STUN_PORT", 3478),
                stun_servers: std::env::var("STUN_SERVERS")
                    .ok()
                    .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                    .unwrap_or_else(default_stun_servers),
                use_turn: var("USE_TURN", false),
            },
            remote_access: RemoteAccessConfig {
                port: var("REMOTE_PORT", 8080),
                max_connections: var("MAX_CONNECTIONS", 10),
                device_name: var("DEVICE_NAME", "nat-tunnel".to_string()),
                device_id: var("DEVICE_ID", "000000000000".to_string()),
            },
            logging: LoggingConfig {
                level: var("LOG_LEVEL", "info".to_string()),
                log_file: std::env::var("LOG_FILE").ok(),
            },
        })
    }
}
