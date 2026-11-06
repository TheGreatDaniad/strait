//! In-process fake rendezvous service for tests (unit and integration; always compiled, it is
//! tiny and has no dependencies). A [`MockHub`] is the "internet": backends made from the same
//! hub share sealed mailboxes keyed by (method id, derived room, role), so a Host-role and a
//! Client-role [`RvCtx`] find each other exactly as they would through a real service, including
//! the real `seal`/`open`. Latency, failure and blocking are injectable per backend.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::derive::{open, seal};
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvCtx, RvError, Status};

type Boxes = Mutex<HashMap<(&'static str, String, Role), Vec<u8>>>;

#[derive(Clone, Default)]
pub struct MockHub {
    boxes: Arc<Boxes>,
}

impl MockHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A backend with method id `id` on this hub. Two backends with different ids model two
    /// independent services (each has its own mailboxes).
    pub fn backend(&self, id: &'static str) -> MockBackend {
        MockBackend {
            hub: self.clone(),
            id,
            k: Arc::new(Knobs {
                latency_ms: AtomicUsize::new(0),
                probe_ms: AtomicUsize::new(0),
                fail_runs: AtomicUsize::new(0),
                blocked: AtomicBool::new(false),
                runs: AtomicUsize::new(0),
                cleaned: AtomicUsize::new(0),
            }),
        }
    }

    /// Number of mailboxes currently held (0 after every run has cleaned up).
    pub fn mailboxes(&self) -> usize {
        self.boxes.lock().unwrap().len()
    }
}

struct Knobs {
    latency_ms: AtomicUsize,
    probe_ms: AtomicUsize,
    fail_runs: AtomicUsize,
    blocked: AtomicBool,
    runs: AtomicUsize,
    cleaned: AtomicUsize,
}

/// Cloning shares the knobs, so a test keeps a handle after boxing the backend as `Arc<dyn _>`.
#[derive(Clone)]
pub struct MockBackend {
    hub: MockHub,
    id: &'static str,
    k: Arc<Knobs>,
}

impl MockBackend {
    /// Delay before this backend publishes / starts finding peers.
    pub fn latency(self, d: Duration) -> Self {
        self.k.latency_ms.store(d.as_millis() as usize, SeqCst);
        self
    }
    /// `probe` takes this long before answering.
    pub fn probe_delay(self, d: Duration) -> Self {
        self.k.probe_ms.store(d.as_millis() as usize, SeqCst);
        self
    }
    /// The first `n` calls to `run` return `RvError::Failed` (`usize::MAX` = always).
    pub fn fail_first(self, n: usize) -> Self {
        self.k.fail_runs.store(n, SeqCst);
        self
    }
    /// `probe` says Blocked and `run` returns `RvError::Blocked`.
    pub fn blocked(self) -> Self {
        self.k.blocked.store(true, SeqCst);
        self
    }
    /// How many times `run` was entered (restart counting).
    pub fn runs(&self) -> usize {
        self.k.runs.load(SeqCst)
    }
    /// How many runs ended by cancellation after removing their mailbox.
    pub fn clean_exits(&self) -> usize {
        self.k.cleaned.load(SeqCst)
    }
    pub fn arc(&self) -> Arc<dyn Rendezvous> {
        Arc::new(self.clone())
    }
}

#[async_trait::async_trait]
impl Rendezvous for MockBackend {
    fn id(&self) -> &'static str {
        self.id
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Mock (tests only)",
            shared: &["nothing, in-process"],
            not_shared: &["everything"],
            why: "test double",
            operator: "this process",
        }
    }

    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let d = Duration::from_millis(self.k.probe_ms.load(SeqCst) as u64);
        tokio::time::sleep(d.min(timeout)).await;
        if self.k.blocked.load(SeqCst) {
            ProbeStatus::Blocked("mock blocked".into())
        } else if d > timeout {
            ProbeStatus::Error("timeout".into())
        } else {
            ProbeStatus::Reachable { rtt_ms: d.as_millis() as u32 }
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        self.k.runs.fetch_add(1, SeqCst);
        if self.k.blocked.load(SeqCst) {
            return Err(RvError::Blocked("mock blocked".into()));
        }
        let left = self.k.fail_runs.load(SeqCst);
        if left > 0 {
            if left != usize::MAX {
                self.k.fail_runs.store(left - 1, SeqCst);
            }
            return Err(RvError::Failed("mock failure".into()));
        }
        let lat = Duration::from_millis(self.k.latency_ms.load(SeqCst) as u64);
        tokio::select! { _ = tokio::time::sleep(lat) => {}, _ = cancel.cancelled() => return Ok(()) }

        let d = ctx.derived();
        let room = d.room_hex();
        let mine = (self.id, room.clone(), ctx.role);
        let theirs = (self.id, room, ctx.role.other());
        let mut seen: Vec<SocketAddr> = Vec::new();
        ctx.status.set(Status::Publishing);
        loop {
            if let Ok(blob) = seal(&d, ctx.role, &ctx.local) {
                self.hub.boxes.lock().unwrap().insert(mine.clone(), blob);
            }
            ctx.status.set(Status::Waiting);
            let blob = self.hub.boxes.lock().unwrap().get(&theirs).cloned();
            if let Some(Ok(addrs)) = blob.map(|b| open(&d, ctx.role, &b)) {
                for a in addrs {
                    if !seen.contains(&a) {
                        seen.push(a);
                        if tx.send(Candidate { addr: a, via: self.id }).await.is_err() {
                            break;
                        }
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                _ = cancel.cancelled() => {
                    self.hub.boxes.lock().unwrap().remove(&mine);
                    self.k.cleaned.fetch_add(1, SeqCst);
                    return Ok(());
                }
            }
        }
    }
}
