//! In-memory [`FrameIo`] pair for tests: injectable loss, duplication, reordering, latency, an MTU
//! limit, and a `punchable: false` mode. Deterministic for a given seed (the decisions come from
//! one seeded [`Rng`] per direction; delivery times use the wall clock, so keep latencies small).
//!
//! Loss is the network's loss: `send_to` still returns `Ok`. An oversize frame is an error, like
//! on every real carrier.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::{CarrierError, CarrierId, Caps, FrameIo, Health, Rng};

#[derive(Debug, Clone)]
pub struct MemCfg {
    pub id: CarrierId,
    pub seed: u64,
    /// Probabilities in [0, 1].
    pub loss: f64,
    pub dup: f64,
    /// A reordered frame is delayed by `reorder_extra` so later frames overtake it.
    pub reorder: f64,
    pub reorder_extra: Duration,
    pub latency: Duration,
    /// Largest frame accepted by `send_to` (becomes `caps().max_frame`).
    pub mtu: usize,
    pub punchable: bool,
    pub reliable_stream: bool,
}

impl Default for MemCfg {
    fn default() -> Self {
        Self {
            id: CarrierId::Udp,
            seed: 1,
            loss: 0.0,
            dup: 0.0,
            reorder: 0.0,
            reorder_extra: Duration::from_millis(20),
            latency: Duration::ZERO,
            mtu: 1472,
            punchable: true,
            reliable_stream: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemStats {
    pub sent: u64,
    pub lost: u64,
    pub duplicated: u64,
    pub reordered: u64,
}

struct Item {
    due: Instant,
    seq: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct Link {
    q: Mutex<Vec<Item>>,
    notify: Notify,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    lost: AtomicU64,
    duplicated: AtomicU64,
    reordered: AtomicU64,
}

pub struct MemIo {
    cfg: MemCfg,
    local: SocketAddr,
    peer: SocketAddr,
    inbox: Arc<Link>,
    outbox: Arc<Link>,
    rng: Mutex<Rng>,
    seq: AtomicU64,
    n: Counters,
    dead: Arc<AtomicBool>,
}

pub const ADDR_A: &str = "10.0.0.1:1000";
pub const ADDR_B: &str = "10.0.0.2:2000";

/// Two connected ends: `a` talks to `b` at [`ADDR_B`] and vice versa.
pub fn pair(cfg: MemCfg) -> (MemIo, MemIo) {
    let (la, lb) = (Arc::new(Link::default()), Arc::new(Link::default()));
    let dead = Arc::new(AtomicBool::new(false));
    let (a_addr, b_addr): (SocketAddr, SocketAddr) = (ADDR_A.parse().unwrap(), ADDR_B.parse().unwrap());
    let mk = |local, peer, inbox: &Arc<Link>, outbox: &Arc<Link>, salt: u64| MemIo {
        cfg: cfg.clone(),
        local,
        peer,
        inbox: inbox.clone(),
        outbox: outbox.clone(),
        rng: Mutex::new(Rng::new(cfg.seed ^ salt)),
        seq: AtomicU64::new(0),
        n: Counters::default(),
        dead: dead.clone(),
    };
    (mk(a_addr, b_addr, &la, &lb, 0xA), mk(b_addr, a_addr, &lb, &la, 0xB))
}

impl MemIo {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    /// Simulate the carrier dying (sidecar exit, TLS reset): both ends fail with `Closed`.
    pub fn kill(&self) {
        self.dead.store(true, Ordering::Relaxed);
        self.inbox.notify.notify_one();
        self.outbox.notify.notify_one();
    }
    pub fn stats(&self) -> MemStats {
        MemStats {
            sent: self.n.sent.load(Ordering::Relaxed),
            lost: self.n.lost.load(Ordering::Relaxed),
            duplicated: self.n.duplicated.load(Ordering::Relaxed),
            reordered: self.n.reordered.load(Ordering::Relaxed),
        }
    }
}

#[async_trait::async_trait]
impl FrameIo for MemIo {
    fn caps(&self) -> Caps {
        Caps {
            id: self.cfg.id,
            max_frame: self.cfg.mtu,
            punchable: self.cfg.punchable,
            reliable_stream: self.cfg.reliable_stream,
            overhead: 0,
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(CarrierError::Closed.into());
        }
        if to != self.peer {
            return Err(CarrierError::UnknownPeer.into());
        }
        if frame.len() > self.cfg.mtu {
            return Err(CarrierError::FrameTooLarge { max: self.cfg.mtu }.into());
        }
        self.n.sent.fetch_add(1, Ordering::Relaxed);
        let (lost, dup, reord) = {
            let mut r = self.rng.lock().unwrap();
            (r.f64() < self.cfg.loss, r.f64() < self.cfg.dup, r.f64() < self.cfg.reorder)
        };
        if lost {
            self.n.lost.fetch_add(1, Ordering::Relaxed);
            return Ok(frame.len());
        }
        let mut due = Instant::now() + self.cfg.latency;
        if reord {
            due += self.cfg.reorder_extra;
            self.n.reordered.fetch_add(1, Ordering::Relaxed);
        }
        let copies = if dup {
            self.n.duplicated.fetch_add(1, Ordering::Relaxed);
            2
        } else {
            1
        };
        {
            let mut q = self.outbox.q.lock().unwrap();
            for _ in 0..copies {
                q.push(Item { due, seq: self.seq.fetch_add(1, Ordering::Relaxed), data: frame.to_vec() });
            }
        }
        self.outbox.notify.notify_one();
        Ok(frame.len())
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let now = Instant::now();
        let mut q = self.inbox.q.lock().unwrap();
        let best = q.iter().enumerate().filter(|(_, i)| i.due <= now).min_by_key(|(_, i)| (i.due, i.seq)).map(|(k, _)| k);
        match best {
            Some(k) => {
                let it = q.remove(k);
                if it.data.len() > buf.len() {
                    return Err(CarrierError::FrameTooLarge { max: buf.len() }.into());
                }
                buf[..it.data.len()].copy_from_slice(&it.data);
                Ok((it.data.len(), self.peer))
            }
            None if self.dead.load(Ordering::Relaxed) => Err(CarrierError::Closed.into()),
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    async fn readable(&self) -> io::Result<()> {
        loop {
            let n = self.inbox.notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            let next = {
                if self.dead.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let q = self.inbox.q.lock().unwrap();
                q.iter().map(|i| i.due).min()
            };
            match next {
                Some(due) if due <= Instant::now() => return Ok(()),
                Some(due) => {
                    tokio::select! {
                        _ = tokio::time::sleep(due.saturating_duration_since(Instant::now())) => {}
                        _ = &mut n => {}
                    }
                }
                None => n.await,
            }
        }
    }

    fn health(&self) -> Health {
        if self.dead.load(Ordering::Relaxed) { Health::Down("killed".into()) } else { Health::Ok }
    }

    async fn close(&self) {
        self.kill();
    }
}
