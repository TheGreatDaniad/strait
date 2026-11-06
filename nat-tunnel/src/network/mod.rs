//! Network Testing Module
//!
//! Provides network simulation and testing utilities for validating
//! the tunnel implementation under various network conditions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub mod simulation;

pub use simulation::{NetworkSimulationModule, SimulationConfig};

/// NAT type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    FullCone,
    RestrictedCone,
    Symmetric,
    Block,
}

/// Simulated NAT state
#[derive(Debug, Clone)]
pub struct NatState {
    /// Local port to external port mappings
    pub mappings: HashMap<u16, u16>,
    /// Simulated NAT behaviour
    pub nat_type: NatType,
}

/// Simulated TURN state
#[derive(Debug, Clone)]
pub struct TurnState {
    /// Server name to address mappings
    pub servers: HashMap<String, String>,
    /// Allocations keyed by allocation ID
    pub allocations: HashMap<String, Allocation>,
}

/// TURN allocation
#[derive(Debug, Clone)]
pub struct Allocation {
    /// Allocation ID
    pub id: String,
    /// Relay address
    pub remote_address: String,
    /// Relay port
    pub remote_port: u16,
    /// Allocation status
    pub status: AllocationStatus,
    /// Lifetime in seconds
    pub lifetime: u32,
}

/// Allocation status
#[derive(Debug, Clone, PartialEq)]
pub enum AllocationStatus {
    Active,
    Expired,
    Failed,
    Cancelled,
}

/// Connection status
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
    Failed,
}

/// Simulated connection
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Connection ID
    pub id: String,
    /// Remote address
    pub remote_address: String,
    /// Remote port
    pub remote_port: u16,
    /// Current status
    pub status: ConnectionStatus,
    /// Time the connection was established, if it was
    pub established: Option<Instant>,
    /// Time of the most recent activity
    pub last_activity: Instant,
}

/// Simulated datagram
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet ID
    pub id: String,
    /// Source address
    pub source_ip: String,
    /// Source port
    pub source_port: u16,
    /// Destination address
    pub destination_ip: String,
    /// Destination port
    pub destination_port: u16,
    /// Packet payload
    pub payload: Vec<u8>,
    /// Time the packet was created
    pub timestamp: Instant,
    /// Whether the simulated link dropped this packet
    pub loss: bool,
}

/// Test configuration
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Maximum test duration
    pub duration: Duration,
    /// Number of concurrent tests
    pub concurrency: usize,
    /// Simulated network conditions shared by all tests
    pub simulation: SimulationConfig,
}

/// Test type
#[derive(Debug, Clone, PartialEq)]
pub enum TestType {
    Connectivity,
    Latency,
    Bandwidth,
    PacketLoss,
    Failover,
    Performance,
}

/// Test result
///
/// A result carries no `passed` flag: callers derive pass/fail from the
/// metrics that the individual tests report.
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Unique ID of the test run
    pub test_id: String,
    /// Kind of test that produced this result
    pub test_type: TestType,
    /// Measurements collected by the test
    pub metrics: HashMap<String, f64>,
}

/// Network Testing Module
///
/// Runs simulated network tests over a [`NetworkSimulationModule`] built
/// from the configured [`SimulationConfig`].
#[derive(Clone)]
pub struct NetworkTestModule {
    /// Test configuration
    config: TestConfig,
    /// Simulated link used to produce the measurements
    simulation: NetworkSimulationModule,
    /// Test results by test ID
    results: HashMap<String, TestResult>,
}

impl NetworkTestModule {
    /// Create a new network test module
    pub fn new(config: &TestConfig) -> Self {
        Self {
            config: config.clone(),
            simulation: NetworkSimulationModule::new(&config.simulation),
            results: HashMap::new(),
        }
    }

    /// Run a connectivity test against one destination
    ///
    /// Sends a single simulated datagram of 1024 bytes and reports whether
    /// it reached the destination along with the delivery latency.
    pub async fn run_connectivity_test(&mut self, target: &str, port: u16) -> TestResult {
        let test_id = format!("conn_{}", uuid::Uuid::new_v4());
        log::debug!("connectivity test against {}:{}", target, port);

        let packet = self
            .simulation
            .simulate_packet(("127.0.0.1", 0), (target, port), 1024);
        let delivered = !packet.loss;
        let latency_ms = if delivered {
            self.simulation.next_delivery_delay().as_secs_f64() * 1000.0
        } else {
            0.0
        };

        let mut metrics = HashMap::new();
        metrics.insert("packets_sent".to_string(), 1.0);
        metrics.insert(
            "packets_delivered".to_string(),
            if delivered { 1.0 } else { 0.0 },
        );
        metrics.insert("latency_ms".to_string(), latency_ms);

        self.record(TestResult {
            test_id,
            test_type: TestType::Connectivity,
            metrics,
        })
    }

    /// Run a latency test
    ///
    /// Times a sample of 20 simulated datagrams through the configured
    /// latency and jitter. Lost datagrams are not sampled.
    pub async fn run_latency_test(&mut self) -> TestResult {
        const SAMPLES: usize = 20;
        let test_id = format!("latency_{}", uuid::Uuid::new_v4());

        let mut samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let packet = self
                .simulation
                .simulate_packet(("127.0.0.1", 0), ("127.0.0.1", 0), 64);
            if !packet.loss {
                samples.push(self.simulation.next_delivery_delay());
            }
        }

        let (min, max, avg, jitter) = summarise_latencies(&samples);

        let mut metrics = HashMap::new();
        metrics.insert("packets_sent".to_string(), SAMPLES as f64);
        metrics.insert("packets_delivered".to_string(), samples.len() as f64);
        metrics.insert("min_latency_ms".to_string(), min);
        metrics.insert("avg_latency_ms".to_string(), avg);
        metrics.insert("max_latency_ms".to_string(), max);
        metrics.insert("jitter_ms".to_string(), jitter);

        self.record(TestResult {
            test_id,
            test_type: TestType::Latency,
            metrics,
        })
    }

    /// Run a bandwidth test
    ///
    /// Models a 1 MiB transfer as 64 datagrams of 16 KiB each, then reports
    /// the throughput implied by the simulated delivery time and the
    /// configured bandwidth cap (if any).
    pub async fn run_bandwidth_test(&mut self) -> TestResult {
        const PACKETS: usize = 64;
        const PAYLOAD: usize = 16 * 1024;

        let test_id = format!("bandwidth_{}", uuid::Uuid::new_v4());

        let mut delivered_bytes = 0usize;
        let mut elapsed = Duration::ZERO;
        for _ in 0..PACKETS {
            let packet =
                self.simulation
                    .simulate_packet(("127.0.0.1", 0), ("127.0.0.1", 0), PAYLOAD);
            if !packet.loss {
                delivered_bytes += PAYLOAD;
            }
            elapsed += self.simulation.next_delivery_delay();
        }

        let seconds = elapsed.as_secs_f64();
        let modelled_mbps = if seconds > 0.0 {
            delivered_bytes as f64 * 8.0 / seconds / 1_000_000.0
        } else {
            0.0
        };
        let throughput_mbps = match self.config.simulation.bandwidth {
            Some(cap) => modelled_mbps.min(cap),
            None => modelled_mbps,
        };

        let mut metrics = HashMap::new();
        metrics.insert("packets_sent".to_string(), PACKETS as f64);
        metrics.insert("bytes_delivered".to_string(), delivered_bytes as f64);
        metrics.insert("throughput_mbps".to_string(), throughput_mbps);

        self.record(TestResult {
            test_id,
            test_type: TestType::Bandwidth,
            metrics,
        })
    }

    /// Run a packet loss test
    ///
    /// Sends 1000 small datagrams and reports the observed drop rate.
    pub async fn run_packet_loss_test(&mut self) -> TestResult {
        const PACKETS: usize = 1000;

        let test_id = format!("packetloss_{}", uuid::Uuid::new_v4());

        let mut lost = 0usize;
        for _ in 0..PACKETS {
            let packet = self
                .simulation
                .simulate_packet(("127.0.0.1", 0), ("127.0.0.1", 0), 512);
            if packet.loss {
                lost += 1;
            }
        }

        let loss_percent = lost as f64 / PACKETS as f64 * 100.0;

        let mut metrics = HashMap::new();
        metrics.insert("packets_sent".to_string(), PACKETS as f64);
        metrics.insert("packets_lost".to_string(), lost as f64);
        metrics.insert("loss_percent".to_string(), loss_percent);

        self.record(TestResult {
            test_id,
            test_type: TestType::PacketLoss,
            metrics,
        })
    }

    /// Run a failover test
    ///
    /// Creates a simulated TURN allocation when TURN simulation is enabled
    /// and reports the time taken to switch to it. When TURN simulation is
    /// disabled the result records that no failover path was available
    /// instead of inventing a success.
    pub async fn run_failover_test(&mut self) -> TestResult {
        let test_id = format!("failover_{}", uuid::Uuid::new_v4());

        let allocation = self.simulation.allocate("turn.local", 3478, 600);

        let mut metrics = HashMap::new();
        metrics.insert(
            "turn_available".to_string(),
            if self.config.simulation.enable_turn {
                1.0
            } else {
                0.0
            },
        );
        match allocation {
            Some(_) => {
                metrics.insert("switched_allocation".to_string(), 1.0);
                metrics.insert(
                    "failover_time_ms".to_string(),
                    self.simulation.next_delivery_delay().as_secs_f64() * 1000.0,
                );
            }
            None => {
                log::debug!("failover test: TURN simulation disabled");
                metrics.insert("switched_allocation".to_string(), 0.0);
                metrics.insert("failover_time_ms".to_string(), 0.0);
            }
        }

        self.record(TestResult {
            test_id,
            test_type: TestType::Failover,
            metrics,
        })
    }

    /// Run all configured tests
    pub async fn run_all_tests(&mut self) -> Vec<TestResult> {
        let mut results = Vec::new();

        results.push(self.run_connectivity_test("127.0.0.1", 8080).await);
        results.push(self.run_latency_test().await);
        results.push(self.run_bandwidth_test().await);
        results.push(self.run_packet_loss_test().await);
        results.push(self.run_failover_test().await);

        results
    }

    /// Get test results
    pub fn get_results(&self) -> &HashMap<String, TestResult> {
        &self.results
    }

    /// Clear test results
    pub fn clear_results(&mut self) {
        self.results.clear();
    }

    /// Store a result and log a one-line summary
    fn record(&mut self, result: TestResult) -> TestResult {
        log::info!(
            "test {} ({:?}) finished: {:?}",
            result.test_id,
            result.test_type,
            result.metrics
        );
        self.results.insert(result.test_id.clone(), result.clone());
        result
    }
}

/// Summarise latency samples as `(min_ms, max_ms, avg_ms, jitter_ms)`
///
/// Jitter is the mean absolute difference between consecutive samples.
/// An empty sample set yields all zeroes.
fn summarise_latencies(samples: &[Duration]) -> (f64, f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    let min = ms.iter().copied().fold(f64::INFINITY, f64::min);
    let max = ms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = ms.iter().sum::<f64>() / ms.len() as f64;

    let jitter = if ms.len() > 1 {
        let total: f64 = ms.windows(2).map(|pair| (pair[1] - pair[0]).abs()).sum();
        total / (ms.len() - 1) as f64
    } else {
        0.0
    };

    (min, max, avg, jitter)
}
