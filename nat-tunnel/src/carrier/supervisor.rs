//! Supervisor for sidecar child processes (Xray, wstunnel binary, ...). Doc section 6.7.
//!
//! Safety properties, all enforced here:
//! * no shell: the program is executed directly and every arg is passed as one argv entry;
//! * a relative `program` is refused unless `allow_relative` (no PATH lookups by accident);
//! * the child's environment is cleared; only `env` from the config is set (on Windows add
//!   `SystemRoot` yourself if the program needs it);
//! * stdin is closed; stdout/stderr go to a bounded line ring (lines truncated, optional redaction);
//! * restart with exponential backoff up to `max_restarts`, then [`SidecarState::GaveUp`];
//! * stop = SIGTERM, wait `stop_grace`, then kill (non-unix: kill). Dropping the supervisor kills
//!   the child without grace (`kill_on_drop`).
//!
//! Not done (documented gap): kill-on-parent-death after a hard crash of this process
//! (`PR_SET_PDEATHSIG`, Job Objects); the sidecar then keeps running until the OS reaps it.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout, Instant};
use tokio_util::sync::CancellationToken;

use super::ladder::Reason;
use super::loopback::Guard;
use super::Health;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheck {
    /// Ready as soon as the process is spawned; only exit is detected.
    None,
    Tcp(SocketAddr),
    /// Send `probe`, expect a reply starting with `expect` (empty = any reply).
    Udp { addr: SocketAddr, probe: Vec<u8>, expect: Vec<u8> },
    /// Ready when a stdout line contains this text. Cannot detect a hang afterwards.
    StdoutLine(String),
}

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    pub max_restarts: u32,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// A run at least this long resets the restart counter.
    pub reset_after: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            reset_after: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<PathBuf>,
    pub allow_relative: bool,
    pub health: HealthCheck,
    /// Max time from spawn to healthy.
    pub start_timeout: Duration,
    /// After ready, probe this often (Tcp / Udp checks only); `None` = only watch for exit.
    pub monitor_interval: Option<Duration>,
    /// Consecutive failed probes that count as a hang (the child is killed and restarted).
    pub monitor_failures: u32,
    pub restart: RestartPolicy,
    pub stop_grace: Duration,
    pub log_lines: usize,
    /// Substrings replaced by `***` in captured logs (keys, UUIDs).
    pub redact: Vec<String>,
}

impl SidecarConfig {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            working_dir: None,
            allow_relative: false,
            health: HealthCheck::None,
            start_timeout: Duration::from_secs(10),
            monitor_interval: None,
            monitor_failures: 3,
            restart: RestartPolicy::default(),
            stop_grace: Duration::from_secs(3),
            log_lines: 200,
            redact: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCause {
    Exited,
    /// Alive but failing health probes; killed by the supervisor.
    Hung,
    /// Never became healthy; killed by the supervisor.
    StartTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub cause: ExitCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarState {
    Starting { restarts: u32 },
    Ready { pid: u32, restarts: u32 },
    Backoff { restarts: u32, last: Exit },
    GaveUp { last: Exit },
    Failed(SidecarError),
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarError {
    RelativeProgram(PathBuf),
    Missing(PathBuf),
    Spawn(String),
    /// Restarts exhausted; the last exit.
    GaveUp(Exit),
    /// `stop` was called before the sidecar became ready.
    Stopped,
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SidecarError::RelativeProgram(p) => write!(f, "refusing relative sidecar path {}", p.display()),
            SidecarError::Missing(p) => write!(f, "sidecar not found: {}", p.display()),
            SidecarError::Spawn(s) => write!(f, "cannot start sidecar: {s}"),
            SidecarError::GaveUp(e) => match e.cause {
                ExitCause::StartTimeout => f.write_str("sidecar never became ready"),
                ExitCause::Hung => f.write_str("sidecar stopped answering"),
                ExitCause::Exited => write!(f, "sidecar exited ({:?}, signal {:?})", e.code, e.signal),
            },
            SidecarError::Stopped => f.write_str("stopped"),
        }
    }
}
impl std::error::Error for SidecarError {}

impl SidecarError {
    /// For the carrier ladder.
    pub fn to_reason(&self) -> Reason {
        match self {
            SidecarError::Missing(_) | SidecarError::RelativeProgram(_) => Reason::SidecarMissing,
            SidecarError::GaveUp(e) if e.cause == ExitCause::StartTimeout => Reason::Timeout,
            SidecarError::GaveUp(e) => Reason::SidecarExited(e.code),
            other => Reason::Failed(other.to_string()),
        }
    }
}

struct Inner {
    state: watch::Sender<SidecarState>,
    logs: Mutex<VecDeque<String>>,
    cap: usize,
    spawns: AtomicU32,
    graceful: AtomicBool,
    redact: Vec<String>,
}

impl Inner {
    fn log(&self, tag: &str, line: &str) {
        let mut l: String = line.chars().take(512).collect();
        for r in self.redact.iter().filter(|r| !r.is_empty()) {
            l = l.replace(r.as_str(), "***");
        }
        let mut q = self.logs.lock().unwrap();
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(format!("{tag}: {l}"));
    }
}

pub struct Supervisor {
    inner: Arc<Inner>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.task.abort(); // drops the Child: kill_on_drop
    }
}

impl Guard for Supervisor {
    fn health(&self) -> Health {
        match self.state() {
            SidecarState::Ready { .. } => Health::Ok,
            SidecarState::Starting { .. } | SidecarState::Backoff { .. } => Health::Down("sidecar restarting".into()),
            SidecarState::GaveUp { last } => Health::Down(SidecarError::GaveUp(last).to_string()),
            SidecarState::Failed(e) => Health::Down(e.to_string()),
            SidecarState::Stopped => Health::Down("sidecar stopped".into()),
        }
    }
}

fn validate(cfg: &SidecarConfig) -> Result<(), SidecarError> {
    let p = &cfg.program;
    if !p.is_absolute() {
        if !cfg.allow_relative {
            return Err(SidecarError::RelativeProgram(p.clone()));
        }
        if p.components().count() < 2 {
            return Ok(()); // bare name: PATH lookup, NotFound is reported at spawn
        }
    }
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() => Ok(()),
        _ => Err(SidecarError::Missing(p.clone())),
    }
}

fn spawn_child(cfg: &SidecarConfig) -> Result<Child, SidecarError> {
    let mut c = Command::new(&cfg.program);
    c.args(&cfg.args)
        .env_clear()
        .envs(cfg.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(d) = &cfg.working_dir {
        c.current_dir(d);
    }
    c.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SidecarError::Missing(cfg.program.clone())
        } else {
            SidecarError::Spawn(e.to_string())
        }
    })
}

fn pump<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    inner: Arc<Inner>,
    tag: &'static str,
    ready: Option<(String, mpsc::Sender<()>)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut part: Vec<u8> = Vec::new();
        let emit = |bytes: &[u8]| {
            let line = String::from_utf8_lossy(bytes);
            let line = line.trim_end_matches('\r');
            inner.log(tag, line);
            if let Some((pat, tx)) = &ready {
                if line.contains(pat.as_str()) {
                    let _ = tx.try_send(());
                }
            }
        };
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    for &b in &buf[..n] {
                        if b == b'\n' {
                            emit(&part);
                            part.clear();
                        } else {
                            part.push(b);
                            if part.len() >= 4096 {
                                emit(&part);
                                part.clear();
                            }
                        }
                    }
                }
            }
        }
        if !part.is_empty() {
            emit(&part);
        }
    })
}

async fn probe_ok(h: &HealthCheck) -> bool {
    let t = Duration::from_millis(500);
    match h {
        HealthCheck::None | HealthCheck::StdoutLine(_) => true,
        HealthCheck::Tcp(a) => matches!(timeout(t, tokio::net::TcpStream::connect(a)).await, Ok(Ok(_))),
        HealthCheck::Udp { addr, probe, expect } => {
            let bind = if addr.is_ipv6() { "[::1]:0" } else { "127.0.0.1:0" };
            let Ok(s) = tokio::net::UdpSocket::bind(bind).await else { return false };
            if s.send_to(probe, addr).await.is_err() {
                return false;
            }
            let mut b = [0u8; 2048];
            match timeout(t, s.recv_from(&mut b)).await {
                Ok(Ok((n, from))) => from == *addr && b[..n].starts_with(expect),
                _ => false,
            }
        }
    }
}

fn exit_of(st: std::io::Result<std::process::ExitStatus>, cause: ExitCause) -> Exit {
    match st {
        Ok(s) => {
            #[cfg(unix)]
            let signal = std::os::unix::process::ExitStatusExt::signal(&s);
            #[cfg(not(unix))]
            let signal = None;
            Exit { code: s.code(), signal, cause }
        }
        Err(_) => Exit { code: None, signal: None, cause },
    }
}

/// SIGTERM, wait `grace`, then kill. Returns true when it exited on its own.
async fn stop_child(child: &mut Child, grace: Duration) -> bool {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: plain signal to a child pid we own.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = child.start_kill();
    match timeout(grace, child.wait()).await {
        Ok(_) => true,
        Err(_) => {
            let _ = child.kill().await;
            false
        }
    }
}

async fn kill_child(child: &mut Child, cause: ExitCause) -> Exit {
    let _ = child.kill().await;
    let st = child.wait().await;
    exit_of(st, cause)
}

enum Outcome {
    Stop,
    Exit(Exit),
}

async fn run_once(cfg: &SidecarConfig, inner: &Arc<Inner>, stop: &CancellationToken, restarts: u32) -> Result<Outcome, SidecarError> {
    inner.state.send_replace(SidecarState::Starting { restarts });
    inner.spawns.fetch_add(1, Ordering::Relaxed);
    let mut child = spawn_child(cfg)?;
    let pid = child.id().unwrap_or(0);
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let ready_pat = match &cfg.health {
        HealthCheck::StdoutLine(p) => Some((p.clone(), tx)),
        _ => None,
    };
    let pumps = [
        child.stdout.take().map(|o| pump(o, inner.clone(), "out", ready_pat)),
        child.stderr.take().map(|e| pump(e, inner.clone(), "err", None)),
    ];

    let ready = async {
        match &cfg.health {
            HealthCheck::None => {}
            HealthCheck::StdoutLine(_) => {
                if rx.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            }
            h => {
                while !probe_ok(h).await {
                    sleep(Duration::from_millis(50)).await;
                }
            }
        }
    };
    let outcome = tokio::select! {
        biased;
        _ = stop.cancelled() => {
            let g = stop_child(&mut child, cfg.stop_grace).await;
            inner.graceful.store(g, Ordering::Relaxed);
            Some(Outcome::Stop)
        }
        st = child.wait() => Some(Outcome::Exit(exit_of(st, ExitCause::Exited))),
        _ = sleep(cfg.start_timeout) => Some(Outcome::Exit(kill_child(&mut child, ExitCause::StartTimeout).await)),
        _ = ready => None,
    };
    let outcome = match outcome {
        Some(o) => o,
        None => {
            inner.state.send_replace(SidecarState::Ready { pid, restarts });
            let mut fails = 0u32;
            loop {
                let tick = async {
                    match cfg.monitor_interval {
                        Some(i) if matches!(cfg.health, HealthCheck::Tcp(_) | HealthCheck::Udp { .. }) => sleep(i).await,
                        _ => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => {
                        let g = stop_child(&mut child, cfg.stop_grace).await;
                        inner.graceful.store(g, Ordering::Relaxed);
                        break Outcome::Stop;
                    }
                    st = child.wait() => break Outcome::Exit(exit_of(st, ExitCause::Exited)),
                    _ = tick => {
                        if probe_ok(&cfg.health).await {
                            fails = 0;
                        } else {
                            fails += 1;
                            if fails >= cfg.monitor_failures.max(1) {
                                break Outcome::Exit(kill_child(&mut child, ExitCause::Hung).await);
                            }
                        }
                    }
                }
            }
        }
    };
    // Let the pipes drain so the last lines (usually the reason) are in the ring.
    for p in pumps.into_iter().flatten() {
        let _ = timeout(Duration::from_millis(300), p).await;
    }
    Ok(outcome)
}

async fn run(cfg: SidecarConfig, inner: Arc<Inner>, stop: CancellationToken) {
    let mut restarts = 0u32;
    loop {
        let started = Instant::now();
        let out = match run_once(&cfg, &inner, &stop, restarts).await {
            Ok(o) => o,
            Err(e) => {
                inner.state.send_replace(SidecarState::Failed(e));
                return;
            }
        };
        let last = match out {
            Outcome::Stop => {
                inner.state.send_replace(SidecarState::Stopped);
                return;
            }
            Outcome::Exit(e) => e,
        };
        if started.elapsed() >= cfg.restart.reset_after {
            restarts = 0;
        }
        if restarts >= cfg.restart.max_restarts {
            inner.state.send_replace(SidecarState::GaveUp { last });
            return;
        }
        restarts += 1;
        inner.state.send_replace(SidecarState::Backoff { restarts, last });
        let back = cfg
            .restart
            .backoff_initial
            .saturating_mul(1u32 << (restarts - 1).min(16))
            .min(cfg.restart.backoff_max);
        tokio::select! {
            _ = sleep(back) => {}
            _ = stop.cancelled() => {
                inner.state.send_replace(SidecarState::Stopped);
                return;
            }
        }
    }
}

impl Supervisor {
    /// Validate, spawn, and wait until the sidecar is healthy (restarts included) or the policy
    /// gives up.
    pub async fn start(cfg: SidecarConfig) -> Result<Supervisor, SidecarError> {
        validate(&cfg)?;
        let (tx, _rx) = watch::channel(SidecarState::Starting { restarts: 0 });
        let inner = Arc::new(Inner {
            state: tx,
            logs: Mutex::new(VecDeque::new()),
            cap: cfg.log_lines.max(1),
            spawns: AtomicU32::new(0),
            graceful: AtomicBool::new(false),
            redact: cfg.redact.clone(),
        });
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(cfg, inner.clone(), stop.clone()));
        let sup = Supervisor { inner, stop, task };
        let mut w = sup.watch();
        loop {
            let st = w.borrow_and_update().clone();
            match st {
                SidecarState::Ready { .. } => return Ok(sup),
                SidecarState::GaveUp { last } => return Err(SidecarError::GaveUp(last)),
                SidecarState::Failed(e) => return Err(e),
                SidecarState::Stopped => return Err(SidecarError::Stopped),
                _ => {}
            }
            if w.changed().await.is_err() {
                return Err(SidecarError::Stopped);
            }
        }
    }

    pub fn state(&self) -> SidecarState {
        self.inner.state.borrow().clone()
    }
    pub fn watch(&self) -> watch::Receiver<SidecarState> {
        self.inner.state.subscribe()
    }
    /// Captured stdout/stderr, oldest first, tagged `out:` / `err:`.
    pub fn logs(&self) -> Vec<String> {
        self.inner.logs.lock().unwrap().iter().cloned().collect()
    }
    /// How many times the process was spawned (1 = never restarted).
    pub fn spawns(&self) -> u32 {
        self.inner.spawns.load(Ordering::Relaxed)
    }
    /// SIGTERM, grace, kill. Returns true if the sidecar exited on SIGTERM within the grace.
    pub async fn stop(mut self) -> bool {
        self.stop.cancel();
        let _ = (&mut self.task).await;
        self.inner.graceful.load(Ordering::Relaxed)
    }
}
