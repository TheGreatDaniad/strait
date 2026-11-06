//! Rendezvous methods: channels that carry the few bytes two peers need to exchange (their
//! reachable endpoints) before a UDP hole punch. See `docs/RENDEZVOUS_DESIGN.md`.
//!
//! Adding a backend: one file `src/rendezvous/<id>.rs` implementing [`Rendezvous`], one line in
//! [`registry`] behind its cargo feature, one feature in `Cargo.toml`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::invite::Endpoint;

pub mod derive;
pub mod live;
pub mod mock;
pub mod runner;
pub mod sig;
#[cfg(feature = "rv-trk")]
pub mod trackers;
#[cfg(feature = "rv-nostr")]
pub mod nostr;
#[cfg(feature = "rv-dht")]
pub mod dht;
#[cfg(feature = "rv-ntfy")]
pub mod ntfy;
#[cfg(feature = "rv-mqtt")]
pub mod mqtt;

pub use runner::{Runner, RunnerHandle, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Host,
    Client,
}

impl Role {
    pub fn other(self) -> Role {
        match self {
            Role::Host => Role::Client,
            Role::Client => Role::Host,
        }
    }
}

/// A peer endpoint learned through a method. `via` = method id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub via: &'static str,
}

/// Reports live progress from a backend to the runner's status channel. Cloning is cheap; a
/// default sink (outside a [`Runner`]) discards everything.
#[derive(Clone, Default)]
pub struct StatusSink(Option<Arc<dyn Fn(Status) + Send + Sync>>);

impl StatusSink {
    pub fn new(f: impl Fn(Status) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(f)))
    }
    /// Call with `Publishing` once my candidates are out and `Waiting` while polling. `GotPeer`
    /// and `Failed`/`Blocked` are set by the runner itself.
    pub fn set(&self, s: Status) {
        if let Some(f) = &self.0 {
            f(s)
        }
    }
}

/// Built by the transport layer. Use [`RvCtx::new`]; fields may be added later.
#[derive(Clone)]
#[non_exhaustive]
pub struct RvCtx {
    /// Invite key (16 bytes, from the invite's 32-hex key).
    pub key: [u8; 16],
    pub role: Role,
    /// My reachable candidates (STUN-mapped v4 from the punch socket, global v6).
    pub local: Vec<SocketAddr>,
    /// Optional: the punch socket. Only `sig` uses it (the signal server must observe the same
    /// mapping the punch will use). While a backend holds it for recv, nobody else may read it.
    pub sock: Option<Arc<UdpSocket>>,
    /// Filled in by the runner.
    pub status: StatusSink,
    /// Filled in by the runner: fires when the HOST first learned a client candidate through some
    /// other method. A backend with a periodic publish should announce again right away (one
    /// permit, so at most one extra announce); ignoring it is always safe.
    pub nudge: Arc<tokio::sync::Notify>,
}

impl RvCtx {
    pub fn new(key: [u8; 16], role: Role, local: Vec<SocketAddr>) -> Self {
        Self { key, role, local, sock: None, status: StatusSink::default(), nudge: Arc::new(tokio::sync::Notify::new()) }
    }
    pub fn with_sock(mut self, sock: Arc<UdpSocket>) -> Self {
        self.sock = Some(sock);
        self
    }
    pub fn derived(&self) -> derive::Derived {
        derive::Derived::new(&self.key)
    }
}

/// Shown verbatim in CLI/GUI/app before the method is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    pub title: &'static str,
    pub shared: &'static [&'static str],
    pub not_shared: &'static [&'static str],
    pub why: &'static str,
    pub operator: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    Reachable { rtt_ms: u32 },
    Blocked(String),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RvError {
    /// The service is unreachable by policy/network (region block, filtered). Not retried.
    Blocked(String),
    /// Anything else. The runner restarts the backend with backoff (max 3).
    Failed(String),
}

impl fmt::Display for RvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RvError::Blocked(s) => write!(f, "blocked: {s}"),
            RvError::Failed(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for RvError {}

#[async_trait::async_trait]
pub trait Rendezvous: Send + Sync {
    /// "sig" | "trk" | "nostr" | "dht" | "ntfy" | "mqtt"
    fn id(&self) -> &'static str;
    fn disclosure(&self) -> Disclosure;
    /// Reachability only: handshake-level, publishes NOTHING. Must finish within `timeout`.
    async fn probe(&self, timeout: Duration) -> ProbeStatus;
    /// Publish my sealed candidates, keep them fresh and poll for the OTHER role's. Send every
    /// newly seen peer candidate on `tx` (the runner dedups). Report progress through
    /// `ctx.status`. Run until `cancel` fires, then clean up (you get ~1 s) and return `Ok(())`.
    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError>;
}

/// Optional per-backend overrides. Empty / `None` = the backend's own built-in list.
#[derive(Debug, Clone, Default)]
pub struct RvConfig {
    /// Signal servers for `sig` (normally the invite's `signals` field).
    pub signals: Vec<Endpoint>,
    pub trackers: Vec<String>,
    pub relays: Vec<String>,
    pub ntfy_base: Option<String>,
    pub mqtt_broker: Option<String>,
}

/// Every compiled-in backend, constructed from `cfg`. Add backends here, behind their feature.
pub fn registry(cfg: &RvConfig) -> Vec<Arc<dyn Rendezvous>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn Rendezvous>> = vec![Arc::new(sig::Sig::new(cfg.signals.clone()))];
    #[cfg(feature = "rv-trk")]   v.push(Arc::new(trackers::Trackers::new(cfg)));
    #[cfg(feature = "rv-nostr")] v.push(Arc::new(nostr::Nostr::new(cfg)));
    #[cfg(feature = "rv-dht")]   v.push(Arc::new(dht::Dht::new(cfg)));
    #[cfg(feature = "rv-ntfy")]  v.push(Arc::new(ntfy::Ntfy::new(cfg)));
    #[cfg(feature = "rv-mqtt")]  v.push(Arc::new(mqtt::Mqtt::new(cfg)));
    v
}

/// The backends named in `ids`, in that order. Unknown / not-compiled-in ids are skipped.
pub fn by_ids(ids: &[String], cfg: &RvConfig) -> Vec<Arc<dyn Rendezvous>> {
    let all = registry(cfg);
    let mut out: Vec<Arc<dyn Rendezvous>> = Vec::new();
    for id in ids {
        if let Some(b) = all.iter().find(|b| b.id() == id) {
            if !out.iter().any(|o| o.id() == b.id()) {
                out.push(b.clone());
            }
        }
    }
    out
}

/// `(id, disclosure)` for every compiled-in method, for the pick-a-method UI.
pub fn all_disclosures() -> Vec<(&'static str, Disclosure)> {
    registry(&RvConfig::default()).iter().map(|b| (b.id(), b.disclosure())).collect()
}
