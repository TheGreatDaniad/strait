//! NAT Traversal Module
//!
//! Public-address discovery over STUN, a cheap NAT classification heuristic,
//! TURN allocations for relayed addresses, and WireGuard config rendering.

pub mod crypto;
pub mod reliable;
pub mod stun;
pub mod turn;
pub mod wireguard;

pub use stun::{classify, resolve_servers, survey, NatType, Sample, StunClient, StunError, StunServerConfig};
pub use turn::{Allocation, TurnError, TurnServer, TurnServerConfig};
pub use wireguard::{WireguardConfig, WireguardError};

use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Result of a NAT classification run.
#[derive(Debug, Clone)]
pub struct NatReport {
    pub kind: NatType,
    /// Why: per-server mapped addresses and observed patterns.
    pub detail: String,
    /// First mapped (public) address seen, in server-list order.
    pub observed: Option<SocketAddr>,
}

/// NAT Traversal Module
///
/// Manages NAT traversal using STUN/TURN servers.
#[derive(Debug, Clone)]
pub struct NatTraversalModule {
    /// Configured STUN server
    stun: StunClient,
    /// `host:port` list used for classification (primary first)
    servers: Vec<String>,
    /// TURN server, present only when `use_turn` is enabled
    turn: Option<TurnServerConfig>,
}

impl NatTraversalModule {
    /// Build the module from the configuration file's NAT traversal section.
    pub fn from_config(cfg: &crate::config::NatTraversalConfig) -> Self {
        let stun = StunClient::new(StunServerConfig {
            address: cfg.stun_server.clone(),
            port: cfg.stun_port,
        });

        let mut servers = vec![format!("{}:{}", cfg.stun_server, cfg.stun_port)];
        servers.extend(cfg.stun_servers.iter().cloned());

        let turn = cfg.use_turn.then(|| TurnServerConfig {
            address: cfg.turn_server.clone(),
            port: cfg.turn_port,
            username: cfg.turn_username.clone(),
            password: cfg.turn_password.clone(),
        });

        Self {
            stun,
            servers,
            turn,
        }
    }

    /// Ask the configured STUN server for our public address.
    pub async fn mapped_addr(&self) -> Result<SocketAddr, StunError> {
        self.stun.mapped_addr().await
    }

    /// Classify the NAT from a fresh socket; see [`Self::classify_on`].
    pub async fn detect_nat_type(&self) -> Result<NatType, StunError> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| StunError::NetworkError(format!("bind local UDP socket: {e}")))?;
        Ok(self.classify_on(&socket).await.kind)
    }

    /// Query every configured server (deduplicated by address) from `socket`
    /// and classify the observed mappings with [`classify`].
    pub async fn classify_on(&self, socket: &UdpSocket) -> NatReport {
        let servers = resolve_servers(&self.servers).await;
        self.classify_servers(socket, &servers).await
    }

    /// Like [`Self::classify_on`] with an explicit server list (tests).
    pub async fn classify_servers(&self, socket: &UdpSocket, servers: &[SocketAddr]) -> NatReport {
        let samples = survey(socket, servers, std::time::Duration::from_millis(1500)).await;
        let (kind, mut detail) = classify(&samples);
        let local = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        if !samples.is_empty() && samples.iter().all(|s| s.mapped.port() == local) {
            detail.push_str("; router preserves the source port");
        }
        log::debug!("NAT {kind:?}: {detail}");
        NatReport { kind, detail, observed: samples.first().map(|s| s.mapped) }
    }

    /// Check whether this machine can host a direct tunnel.
    ///
    /// Samples are taken from the socket the host will actually use (bound to
    /// `bind_port`): a mapping belongs to a socket, not the machine.
    pub async fn probe_host(
        &self,
        bind_port: u16,
    ) -> Result<(NatType, Option<SocketAddr>), StunError> {
        let r = self.probe_host_detailed(bind_port).await?;
        Ok((r.kind, r.observed))
    }

    /// [`Self::probe_host`] plus the human-readable evidence.
    pub async fn probe_host_detailed(&self, bind_port: u16) -> Result<NatReport, StunError> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, bind_port))
            .await
            .map_err(|e| StunError::NetworkError(format!("bind udp/{bind_port}: {e}")))?;
        Ok(self.classify_on(&socket).await)
    }

    /// Query this machine's own egress address without any server.
    ///
    /// Comparing it with the STUN mapping tells a public host from a NATed
    /// one: a `connect` on a UDP socket only sets the route, it sends nothing.
    pub fn local_egress_ip() -> Option<std::net::Ipv4Addr> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.connect((std::net::Ipv4Addr::new(1, 1, 1, 1), 80)).ok()?;
        match socket.local_addr().ok()?.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        }
    }

    /// TURN client for the configured server, if TURN is enabled.
    pub fn turn_server(&self) -> Option<TurnServer> {
        self.turn
            .as_ref()
            .map(|config| TurnServer::new(config.clone()))
    }
}
