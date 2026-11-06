//! Network Simulation Module
//!
//! Provides network simulation and testing utilities for validating
//! the tunnel implementation under various network conditions.
//!
//! All randomness (packet loss and jitter) is driven by a small
//! seedable xorshift generator, so a given [`SimulationConfig`] always
//! produces the same packet stream.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{
    Allocation, AllocationStatus, ConnectionState, ConnectionStatus, NatState, NatType, Packet,
    TurnState,
};

/// Simulation configuration
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Packet loss probability (0.0 to 1.0)
    pub packet_loss: f32,
    /// One-way latency
    pub latency: Duration,
    /// Maximum additional per-packet latency on top of `latency`
    pub jitter: Duration,
    /// Bandwidth cap in Mbps
    pub bandwidth: Option<f64>,
    /// Enable NAT simulation
    pub enable_nat: bool,
    /// Enable TURN simulation
    pub enable_turn: bool,
    /// Enable firewall simulation
    pub enable_firewall: bool,
    /// Seed for the deterministic loss and jitter generator
    pub seed: u64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            latency: Duration::from_millis(20),
            jitter: Duration::from_millis(5),
            bandwidth: None,
            enable_nat: false,
            enable_turn: false,
            enable_firewall: false,
            seed: 0x5EED_5EED_5EED_5EED,
        }
    }
}

/// Deterministic xorshift64* generator used for loss and jitter
#[derive(Debug, Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform value in `[0.0, 1.0)`
    fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn packet_lost(&mut self, loss: f32) -> bool {
        self.next_unit() < loss.clamp(0.0, 1.0) as f64
    }

    /// Uniform offset in `[0, max)`
    fn jitter_offset(&mut self, max: Duration) -> Duration {
        Duration::from_nanos((self.next_unit() * max.as_nanos() as f64) as u64)
    }
}

/// Network Simulation Module
///
/// Tracks simulated NAT, TURN and connection state and produces
/// deterministic packet loss and delivery delays for a given seed.
#[derive(Clone)]
pub struct NetworkSimulationModule {
    config: SimulationConfig,
    rng: DeterministicRng,
    nat: Option<NatState>,
    turn: Option<TurnState>,
    connections: HashMap<String, ConnectionState>,
    next_packet_id: u64,
}

impl NetworkSimulationModule {
    /// Create a new simulation module
    pub fn new(config: &SimulationConfig) -> Self {
        Self {
            config: config.clone(),
            rng: DeterministicRng::new(config.seed),
            nat: None,
            turn: None,
            connections: HashMap::new(),
            next_packet_id: 0,
        }
    }

    /// Enable NAT simulation and start with an empty mapping table
    pub fn start_nat_simulation(&mut self) {
        self.config.enable_nat = true;
        if self.nat.is_none() {
            self.nat = Some(NatState {
                mappings: HashMap::new(),
                nat_type: NatType::FullCone,
            });
        }
        log::info!("NAT simulation enabled");
    }

    /// Enable TURN simulation and start with an empty allocation set
    pub fn start_turn_simulation(&mut self) {
        self.config.enable_turn = true;
        if self.turn.is_none() {
            self.turn = Some(TurnState {
                servers: HashMap::new(),
                allocations: HashMap::new(),
            });
        }
        log::info!("TURN simulation enabled");
    }

    /// Enable firewall simulation
    ///
    /// While enabled, connections are blocked unless a NAT mapping exists.
    pub fn start_firewall_simulation(&mut self) {
        self.config.enable_firewall = true;
        log::info!("firewall simulation enabled");
    }

    /// Clear simulated state and rewind the packet generator to its seed
    pub fn clear_state(&mut self) {
        self.nat = None;
        self.turn = None;
        self.connections.clear();
        self.next_packet_id = 0;
        self.rng = DeterministicRng::new(self.config.seed);
    }

    /// Add a NAT port mapping
    ///
    /// Returns `false` when NAT simulation has not been started.
    pub fn map_port(&mut self, local_port: u16, external_port: u16) -> bool {
        match self.nat.as_mut() {
            Some(nat) => {
                nat.mappings.insert(local_port, external_port);
                log::debug!("NAT mapping {} -> {}", local_port, external_port);
                true
            }
            None => false,
        }
    }

    /// Create a TURN allocation
    ///
    /// Returns the allocation ID, or `None` when TURN simulation has not
    /// been started.
    pub fn allocate(
        &mut self,
        remote_address: &str,
        remote_port: u16,
        lifetime: u32,
    ) -> Option<String> {
        let turn = self.turn.as_mut()?;
        let id = format!("alloc_{}", uuid::Uuid::new_v4());
        turn.allocations.insert(
            id.clone(),
            Allocation {
                id: id.clone(),
                remote_address: remote_address.to_string(),
                remote_port,
                status: AllocationStatus::Active,
                lifetime,
            },
        );
        log::debug!(
            "TURN allocation {} -> {}:{}",
            id,
            remote_address,
            remote_port
        );
        Some(id)
    }

    /// Open a simulated connection
    ///
    /// Returns the connection ID. With firewall simulation enabled and no
    /// NAT mapping present the connection is recorded as [`ConnectionStatus::Failed`].
    pub fn open_connection(&mut self, remote_address: &str, remote_port: u16) -> String {
        let id = format!("conn_{}", uuid::Uuid::new_v4());
        let now = Instant::now();
        let allowed = !(self.config.enable_firewall && self.nat.is_none());
        let status = if allowed {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Failed
        };

        self.connections.insert(
            id.clone(),
            ConnectionState {
                id: id.clone(),
                remote_address: remote_address.to_string(),
                remote_port,
                status,
                established: if allowed { Some(now) } else { None },
                last_activity: now,
            },
        );

        if allowed {
            log::info!(
                "connection {} to {}:{} established",
                id,
                remote_address,
                remote_port
            );
        } else {
            log::debug!(
                "connection {} to {}:{} blocked by firewall",
                id,
                remote_address,
                remote_port
            );
        }

        id
    }

    /// Build a packet and decide, deterministically, whether the link drops it
    pub fn simulate_packet(
        &mut self,
        source: (&str, u16),
        destination: (&str, u16),
        payload_len: usize,
    ) -> Packet {
        self.next_packet_id += 1;
        let loss = self.rng.packet_lost(self.config.packet_loss);
        let packet = Packet {
            id: format!("pkt_{}", self.next_packet_id),
            source_ip: source.0.to_string(),
            source_port: source.1,
            destination_ip: destination.0.to_string(),
            destination_port: destination.1,
            payload: vec![0; payload_len],
            timestamp: Instant::now(),
            loss,
        };
        log::debug!(
            "packet {} {}:{} -> {}:{} ({} bytes){}",
            packet.id,
            packet.source_ip,
            packet.source_port,
            packet.destination_ip,
            packet.destination_port,
            payload_len,
            if loss { " dropped" } else { "" }
        );
        packet
    }

    /// Delivery delay for the next packet: latency plus a seeded jitter offset
    pub fn next_delivery_delay(&mut self) -> Duration {
        let jitter = self.rng.jitter_offset(self.config.jitter);
        self.config.latency.saturating_add(jitter)
    }

    /// Current NAT state, if NAT simulation has been started
    pub fn nat_state(&self) -> Option<&NatState> {
        self.nat.as_ref()
    }

    /// Current TURN state, if TURN simulation has been started
    pub fn turn_state(&self) -> Option<&TurnState> {
        self.turn.as_ref()
    }

    /// Open simulated connections by ID
    pub fn connections(&self) -> &HashMap<String, ConnectionState> {
        &self.connections
    }
}
