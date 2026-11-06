//! Runs several rendezvous backends at once and merges what they find (design section 3).
//!
//! * candidates from all backends arrive on one deduplicated stream ([`RunnerHandle::next`]);
//! * live per-method [`Status`] is published through a `watch` channel;
//! * a backend that fails is restarted with exponential backoff, at most [`MAX_RESTARTS`] times;
//!   `RvError::Blocked` is not retried;
//! * cancel / drop stops everything (a backend gets ~1 s after cancel to clean up).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{Candidate, ProbeStatus, Rendezvous, Role, RvCtx, RvError, StatusSink};

pub const MAX_RESTARTS: u32 = 3;
const CLEANUP_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Starting,
    Publishing,
    Waiting,
    GotPeer(SocketAddr),
    Failed(String),
    Blocked(String),
}

/// One entry per backend, in the order given to [`Runner::new`].
pub type StatusMap = Vec<(&'static str, Status)>;

pub struct Runner {
    backends: Vec<Arc<dyn Rendezvous>>,
    backoff: Duration,
}

impl Runner {
    pub fn new(backends: Vec<Arc<dyn Rendezvous>>) -> Self {
        Self { backends, backoff: Duration::from_millis(500) }
    }

    /// Base restart delay (doubles per restart, capped at 8 s). Default 500 ms.
    pub fn with_backoff(mut self, base: Duration) -> Self {
        self.backoff = base;
        self
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.backends.iter().map(|b| b.id()).collect()
    }

    /// Start every backend. Must be called inside a tokio runtime.
    pub fn start(&self, ctx: RvCtx) -> RunnerHandle {
        let cancel = CancellationToken::new();
        let init: StatusMap = self.backends.iter().map(|b| (b.id(), Status::Starting)).collect();
        let (st_tx, st_rx) = watch::channel(init);
        let st_tx = Arc::new(st_tx);
        let (out_tx, out_rx) = mpsc::channel::<Candidate>(64);
        let seen = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
        let mut tasks = Vec::new();
        let role = ctx.role;
        // One wake-up per backend: the first client candidate the host learns (through any
        // method) makes every OTHER method announce again at once, so a client that polls slowly
        // on a different method finds a fresh record sooner.
        let nudges: Arc<Vec<Arc<Notify>>> = Arc::new(self.backends.iter().map(|_| Arc::new(Notify::new())).collect());
        let nudged = Arc::new(AtomicBool::new(false));

        for (idx, b) in self.backends.iter().enumerate() {
            let (c_tx, mut c_rx) = mpsc::channel::<Candidate>(16);
            let (out, seen, st) = (out_tx.clone(), seen.clone(), st_tx.clone());
            let (nd, nudged) = (nudges.clone(), nudged.clone());
            tasks.push(tokio::spawn(async move {
                while let Some(c) = c_rx.recv().await {
                    set(&st, idx, role, Status::GotPeer(c.addr), true);
                    if role == Role::Host && !nudged.swap(true, Ordering::Relaxed) {
                        for (i, n) in nd.iter().enumerate() {
                            if i != idx {
                                n.notify_one();
                            }
                        }
                    }
                    if seen.lock().unwrap().insert(c.addr) && out.send(c).await.is_err() {
                        break;
                    }
                }
            }));
            let mut cx = ctx.clone();
            let st = st_tx.clone();
            cx.status = StatusSink::new(move |s| set(&st, idx, role, s, false));
            cx.nudge = nudges[idx].clone();
            tasks.push(tokio::spawn(supervise(
                b.clone(),
                cx,
                idx,
                c_tx,
                st_tx.clone(),
                cancel.clone(),
                self.backoff,
            )));
        }
        RunnerHandle { rx: out_rx, status: st_rx, cancel, tasks, role, started: Instant::now(), summarized: false }
    }

    /// Probe every method concurrently ("Test services", `check-host`). Each result is bounded
    /// by `timeout` even if a backend ignores it.
    pub async fn probe_all(&self, timeout: Duration) -> Vec<(&'static str, ProbeStatus)> {
        futures::future::join_all(self.backends.iter().map(|b| async move {
            let r = tokio::time::timeout(timeout + Duration::from_millis(250), b.probe(timeout))
                .await
                .unwrap_or_else(|_| ProbeStatus::Error("timed out".into()));
            (b.id(), r)
        }))
        .await
    }
}

fn role_name(r: Role) -> &'static str {
    if r == Role::Host { "host" } else { "client" }
}

fn set(st: &watch::Sender<StatusMap>, idx: usize, role: Role, s: Status, force: bool) {
    st.send_if_modified(|v| {
        let id = v[idx].0;
        let cur = &mut v[idx].1;
        // A found peer stays visible while the backend keeps polling.
        let soft = matches!(s, Status::Starting | Status::Publishing | Status::Waiting);
        if (!force && soft && matches!(cur, Status::GotPeer(_))) || *cur == s {
            return false;
        }
        log::info!("rendezvous {}: {id} -> {s:?}", role_name(role));
        *cur = s;
        true
    });
}

async fn supervise(
    b: Arc<dyn Rendezvous>,
    ctx: RvCtx,
    idx: usize,
    tx: mpsc::Sender<Candidate>,
    st: Arc<watch::Sender<StatusMap>>,
    cancel: CancellationToken,
    base: Duration,
) {
    let role = ctx.role;
    let mut restarts = 0u32;
    loop {
        let mut fut = Box::pin(b.run(ctx.clone(), tx.clone(), cancel.clone()));
        let res = tokio::select! {
            r = &mut fut => r,
            _ = cancel.cancelled() => {
                let _ = tokio::time::timeout(CLEANUP_GRACE, &mut fut).await;
                return;
            }
        };
        drop(fut);
        match res {
            Ok(()) => return,
            Err(RvError::Blocked(m)) => return set(&st, idx, role, Status::Blocked(m), true),
            Err(RvError::Failed(m)) => {
                set(&st, idx, role, Status::Failed(m), true);
                if restarts >= MAX_RESTARTS {
                    return;
                }
                let delay = (base * 2u32.pow(restarts)).min(Duration::from_secs(8));
                restarts += 1;
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.cancelled() => return,
                }
                set(&st, idx, role, Status::Starting, true);
            }
        }
    }
}

pub struct RunnerHandle {
    rx: mpsc::Receiver<Candidate>,
    status: watch::Receiver<StatusMap>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    role: Role,
    started: Instant,
    summarized: bool,
}

impl RunnerHandle {
    /// Next new (deduplicated) peer candidate; `None` once every backend has ended.
    pub async fn next(&mut self) -> Option<Candidate> {
        self.rx.recv().await
    }

    pub fn try_next(&mut self) -> Option<Candidate> {
        self.rx.try_recv().ok()
    }

    /// Snapshot of per-method status.
    pub fn status(&self) -> StatusMap {
        self.status.borrow().clone()
    }

    /// Live status updates (for the UI).
    pub fn status_watch(&self) -> watch::Receiver<StatusMap> {
        self.status.clone()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Cancel and wait for backends to finish cleanup (bounded by ~1 s each).
    pub async fn stop(mut self) {
        self.summarize();
        self.cancel.cancel();
        for t in std::mem::take(&mut self.tasks) {
            let _ = t.await;
        }
    }
}

impl RunnerHandle {
    /// One info line when the runner ends: `rendezvous host: ended after 12.3 s: trk=GotPeer, dht=Waiting`.
    fn summarize(&mut self) {
        if std::mem::replace(&mut self.summarized, true) {
            return;
        }
        let per: Vec<String> = self
            .status
            .borrow()
            .iter()
            .map(|(id, s)| {
                let w = match s {
                    Status::Starting => "Starting",
                    Status::Publishing => "Publishing",
                    Status::Waiting => "Waiting",
                    Status::GotPeer(_) => "GotPeer",
                    Status::Failed(_) => "Failed",
                    Status::Blocked(_) => "Blocked",
                };
                format!("{id}={w}")
            })
            .collect();
        log::info!("rendezvous {}: ended after {:.1} s: {}", role_name(self.role), self.started.elapsed().as_secs_f32(), per.join(", "));
    }
}

impl Drop for RunnerHandle {
    fn drop(&mut self) {
        self.summarize();
        self.cancel.cancel(); // backends clean up on their own tasks
    }
}
