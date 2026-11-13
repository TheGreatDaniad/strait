//! Carrier fallback order as pure code (doc section 7.3): no I/O, no clock, no sockets. The
//! connect driver feeds in what it knows, runs the attempts (staggered, first sealed ACCEPT wins)
//! and reports each failure back; this module owns the order and the explicit reasons.
//!
//! Integration note: map [`LadderError`] to a new `ConnectError::CarriersFailed(String)` carrying
//! `LadderError::to_string()` (permanent for the retry loop in `app.rs`, like `NoRendezvous`), and
//! show the per-carrier summary verbatim in the GUI / CLI. Never fall back to a relay.

use std::fmt;
use std::io;
use std::time::Duration;

use super::CarrierId;
use crate::rendezvous::ProbeStatus;

/// Why one carrier is not (or no longer) in the running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    NotInInvite,
    DisabledLocally,
    /// Not compiled into this build.
    NotBuilt,
    /// An id this version does not know.
    UnknownId,
    NeedsReachableHost,
    /// No longer produced: an ss / awg entry without an address of its own now rides the host's
    /// plain UDP socket (kept so older callers still compile).
    NeedsOwnAddress,
    NoPunch,
    Blocked(String),
    ProbeError(String),
    Timeout,
    /// Timed out, and the carrier itself knows why (its health said down). Text carries no secrets.
    TimedOutWith(String),
    SidecarMissing,
    SidecarExited(Option<i32>),
    ConnectionRefused,
    /// Typical DPI sign.
    Reset,
    TlsFailed,
    CertMismatch,
    /// Wrong invite or a non-Strait peer answered.
    HandshakeRejected,
    PeerCollision,
    MtuTooSmall,
    ThrottledSuspected,
    Failed(String),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::NotInInvite => f.write_str("not offered by the host"),
            Reason::DisabledLocally => f.write_str("disabled on this device"),
            Reason::NotBuilt => f.write_str("not supported by this build"),
            Reason::UnknownId => f.write_str("unknown carrier"),
            Reason::NeedsReachableHost => f.write_str("needs a reachable host"),
            Reason::NeedsOwnAddress => f.write_str("needs its own host:port in the invite (it cannot be found through rendezvous or the plain UDP address)"),
            Reason::NoPunch => f.write_str("no punch"),
            Reason::Blocked(s) if s.is_empty() => f.write_str("blocked"),
            Reason::Blocked(s) => write!(f, "blocked ({s})"),
            Reason::ProbeError(s) => write!(f, "probe failed ({s})"),
            Reason::Timeout => f.write_str("timed out"),
            Reason::TimedOutWith(s) => write!(f, "timed out ({s})"),
            Reason::SidecarMissing => f.write_str("sidecar missing"),
            Reason::SidecarExited(Some(c)) => write!(f, "sidecar exited ({c})"),
            Reason::SidecarExited(None) => f.write_str("sidecar exited"),
            Reason::ConnectionRefused => f.write_str("connection refused"),
            Reason::Reset => f.write_str("connection reset"),
            Reason::TlsFailed => f.write_str("TLS failed"),
            Reason::CertMismatch => f.write_str("certificate mismatch"),
            Reason::HandshakeRejected => f.write_str("handshake rejected"),
            Reason::PeerCollision => f.write_str("peer address collision"),
            Reason::MtuTooSmall => f.write_str("MTU too small"),
            Reason::ThrottledSuspected => f.write_str("throttling suspected"),
            Reason::Failed(s) => f.write_str(s),
        }
    }
}

pub struct LadderInput<'a> {
    /// The invite's carrier list in the host's preference order. Entries are `id` or
    /// `id@host:port;k=v`. Empty = plain UDP only (an invite without the `cr` field).
    pub invite: &'a [String],
    pub disabled: &'a [String],
    /// Compiled-in carriers ([`super::built_ids`]).
    pub built: &'a [CarrierId],
    /// Results of `CarrierFactory::probe`; a carrier missing here was not probed.
    pub probes: &'a [(CarrierId, ProbeStatus)],
    /// The host has an endpoint reachable without punching (VPS, forwarded port).
    pub host_reachable: bool,
    /// The only way to find the host is rendezvous / signal (no direct address in the invite). Informational.
    pub rendezvous_only: bool,
    /// Hole punching can work from here (false e.g. both sides symmetric, UDP blocked).
    pub punch_ok: bool,
    /// Last carrier that worked on this network: tried first when eligible.
    pub last_working: Option<CarrierId>,
    pub stagger: Duration,
}

impl<'a> LadderInput<'a> {
    pub fn new(invite: &'a [String], built: &'a [CarrierId]) -> Self {
        Self {
            invite,
            disabled: &[],
            built,
            probes: &[],
            host_reachable: false,
            rendezvous_only: false,
            punch_ok: true,
            last_working: None,
            stagger: Duration::from_millis(300),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub id: CarrierId,
    /// The raw invite entry (carries endpoint and parameters).
    pub entry: String,
    /// Start offset from the first attempt (Happy-Eyeballs style stagger).
    pub delay: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub attempts: Vec<Attempt>,
    /// Never attempted, with the reason.
    pub skipped: Vec<(String, Reason)>,
    /// Carrier labels in invite order (for the summary).
    order: Vec<String>,
}

/// "id" from "id@host:port;k=v".
pub fn entry_id(entry: &str) -> &str {
    entry.split(['@', ';']).next().unwrap_or(entry).trim()
}

pub fn plan(inp: &LadderInput) -> Plan {
    let default = [String::from("udp")];
    let invite: &[String] = if inp.invite.is_empty() { &default } else { inp.invite };
    let mut order: Vec<String> = Vec::new();
    let mut skipped = Vec::new();
    // (rank, original index, id, entry)
    let mut ok: Vec<(u8, usize, CarrierId, String)> = Vec::new();

    for (i, entry) in invite.iter().enumerate() {
        let label = entry_id(entry).to_string();
        if order.contains(&label) {
            continue; // duplicate entry: first one wins
        }
        order.push(label.clone());
        let Some(id) = CarrierId::parse(&label) else {
            skipped.push((label, Reason::UnknownId));
            continue;
        };
        if inp.disabled.iter().any(|d| d == &label) {
            skipped.push((label, Reason::DisabledLocally));
            continue;
        }
        if !inp.built.contains(&id) {
            skipped.push((label, Reason::NotBuilt));
            continue;
        }
        // An ss / awg entry without its own address rides the host's plain UDP socket, the one
        // rendezvous publishes (`MuxConfig::shared`); a host that predates this simply stays silent
        // and the attempt times out like any other.
        if !inp.host_reachable {
            // ws without an address finds the host through rendezvous and a TCP punch.
            if !id.default_punchable() && (id != CarrierId::Ws || entry.contains('@')) {
                skipped.push((label, Reason::NeedsReachableHost));
                continue;
            }
            if !inp.punch_ok {
                skipped.push((label, Reason::NoPunch));
                continue;
            }
        }
        let mut rank = 1;
        match inp.probes.iter().find(|(p, _)| *p == id).map(|(_, s)| s) {
            Some(ProbeStatus::Blocked(s)) => {
                skipped.push((label, Reason::Blocked(s.clone())));
                continue;
            }
            Some(ProbeStatus::Error(_)) => rank = 2, // unknown, maybe transient: last resort
            _ => {}
        }
        if inp.last_working == Some(id) {
            rank = 0;
        }
        ok.push((rank, i, id, entry.clone()));
    }
    ok.sort_by_key(|(rank, i, _, _)| (*rank, *i));
    let attempts = ok
        .into_iter()
        .enumerate()
        .map(|(n, (_, _, id, entry))| Attempt { id, entry, delay: inp.stagger * n as u32 })
        .collect();
    Plan { attempts, skipped, order }
}

/// Every carrier failed or was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderError {
    /// In invite order.
    pub reasons: Vec<(String, Reason)>,
}

impl fmt::Display for LadderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reasons.is_empty() {
            return f.write_str("no carrier available");
        }
        let parts: Vec<String> = self.reasons.iter().map(|(c, r)| format!("{c}: {r}")).collect();
        f.write_str(&parts.join("; "))
    }
}
impl std::error::Error for LadderError {}

impl From<LadderError> for io::Error {
    fn from(e: LadderError) -> Self {
        io::Error::new(io::ErrorKind::TimedOut, e)
    }
}

impl LadderError {
    pub fn from_io(e: &io::Error) -> Option<&LadderError> {
        e.get_ref()?.downcast_ref()
    }
}

/// Run-time state over a [`Plan`].
pub struct Ladder {
    plan: Plan,
    failed: Vec<(String, Reason)>,
    winner: Option<CarrierId>,
}

impl Ladder {
    pub fn new(plan: Plan) -> Self {
        Self { plan, failed: Vec::new(), winner: None }
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    /// Attempts not yet failed (the winner stays listed until `succeed`).
    pub fn pending(&self) -> Vec<&Attempt> {
        if self.winner.is_some() {
            return Vec::new();
        }
        self.plan.attempts.iter().filter(|a| !self.failed.iter().any(|(c, _)| c == a.id.as_str())).collect()
    }
    pub fn fail(&mut self, id: CarrierId, why: Reason) {
        if !self.failed.iter().any(|(c, _)| c == id.as_str()) {
            self.failed.push((id.as_str().to_string(), why));
        }
    }
    pub fn succeed(&mut self, id: CarrierId) {
        self.winner = Some(id);
    }
    pub fn winner(&self) -> Option<CarrierId> {
        self.winner
    }
    /// `Some` once nothing is left to try and nobody won.
    pub fn error(&self) -> Option<LadderError> {
        if self.winner.is_some() || !self.pending().is_empty() {
            return None;
        }
        let reasons = self
            .plan
            .order
            .iter()
            .filter_map(|l| {
                self.plan
                    .skipped
                    .iter()
                    .chain(self.failed.iter())
                    .find(|(c, _)| c == l)
                    .map(|(c, r)| (c.clone(), r.clone()))
            })
            .collect();
        Some(LadderError { reasons })
    }
    /// "udp: no punch; ws: blocked; xray: not supported by this build"
    pub fn summary(&self) -> String {
        self.error().map(|e| e.to_string()).unwrap_or_default()
    }
}
