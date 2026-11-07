//! `dht` rendezvous: raw BEP 44 mutable items on the public Mainline DHT (no pkarr).
//!
//! Each role publishes `seal(candidates)` under its own ed25519 key (derived from the invite key,
//! `Derived::dht_host_seed` / `dht_client_seed`), salt = current 10-minute window id. It polls
//! the other role's key (current window, then previous) with exponential backoff, because a
//! missed GET costs 100-170 DHT nodes. Client-mode node only: it never serves other peers.
//!
//! Politeness: one PUT per role every ~4.5 min (plus one at each window rollover, two early
//! re-PUTs at +12 s and +32 s, and up to three low-replica retries); GETs at
//! 1, 1, 2, 2, 2, 2, 3, 3, 3, 5, 5, 5, 8, 8, 12, 12, then every 20 s. Readers look in the current and previous window, and in the
//! next one during the last 90 s of a window (the writer's clock may be ahead). `ctx.local` is fixed for one `run`, so "re-publish when local
//! changes" is done by the runner restarting `run`.
//!
//! Blob freshness: `derive::open` rejects blobs older than 120 s but we only re-publish every
//! ~4.5 min, so readers also try `open_at` with "now" shifted back (accepts blobs up to ~7 min
//! old). A DHT record lives for hours anyway; the blob is sealed under the invite key.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mainline::{async_dht::AsyncDht, errors::PutMutableError, Dht as Node, MutableItem, SigningKey, DEFAULT_BOOTSTRAP_NODES};
use mainline::errors::PutQueryError;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::derive::{open_at, seal, Derived};
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError, Status};

const WINDOW_SECS: u64 = 600;
/// Within this many seconds of a window's end the next window is read too (clock offset).
const NEAR_END_SECS: u64 = 90;

/// Windows a reader looks in, most likely first: current, previous, and next near the boundary.
pub fn poll_windows(clock: u64) -> Vec<u64> {
    let w = clock / WINDOW_SECS;
    let mut v = vec![w, w.saturating_sub(1)];
    if clock % WINDOW_SECS >= WINDOW_SECS - NEAR_END_SECS {
        v.push(w + 1);
    }
    v
}

/// Timing knobs. Defaults are the polite production values; tests shrink them.
#[derive(Clone, Debug)]
pub struct Tune {
    pub poll_steps: Vec<Duration>,
    pub republish: Duration,
    pub bootstrap_timeout: Duration,
    /// PUT again after these delays (in order) even when we already saw the peer: whether the peer
    /// sees US is unknown, and a first PUT from a cold routing table may sit on poor replicas.
    pub early: Vec<Duration>,
    /// A PUT acknowledged by fewer nodes than this is repeated (at most 3 times) after `retry`.
    pub min_stored: u32,
    pub retry: Duration,
}

/// A host that has learned a client's candidate is being used: stop the frequent re-announcing.
fn joined(role: Role, seen: &HashSet<SocketAddr>) -> bool {
    role == Role::Host && !seen.is_empty()
}

/// What to wait before the next PUT and why (pure, so the schedule is testable).
#[derive(Default, Debug)]
pub struct PutSchedule {
    quick: u32,
    early: usize,
}

impl PutSchedule {
    pub fn after_put(&mut self, t: &Tune, stored: u32) -> Duration {
        if stored < t.min_stored && self.quick < 3 {
            self.quick += 1;
            return t.retry;
        }
        if self.early < t.early.len() {
            self.early += 1;
            return t.early[self.early - 1];
        }
        t.republish
    }
}

impl Default for Tune {
    fn default() -> Self {
        Self {
            poll_steps: [1, 1, 2, 2, 2, 2, 3, 3, 3, 5, 5, 5, 8, 8, 12, 12, 20].map(Duration::from_secs).to_vec(),
            republish: Duration::from_secs(270),
            bootstrap_timeout: Duration::from_secs(20),
            early: vec![Duration::from_secs(12), Duration::from_secs(20)],
            min_stored: 3,
            retry: Duration::from_secs(4),
        }
    }
}

pub struct Dht {
    bootstrap: Option<Vec<String>>,
    bind: Option<Ipv4Addr>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    tune: Tune,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Dht {
    pub fn new(_cfg: &RvConfig) -> Self {
        Self { bootstrap: None, bind: None, clock: Arc::new(unix_now), tune: Tune::default() }
    }

    /// Test/dev: own bootstrap list (e.g. a local testnet), bind address, window clock, timings.
    /// The clock only picks the salt (window id); blob timestamps always use the real time.
    pub fn with_network(bootstrap: Vec<String>, bind: Ipv4Addr, clock: Arc<dyn Fn() -> u64 + Send + Sync>, tune: Tune) -> Self {
        Self { bootstrap: Some(bootstrap), bind: Some(bind), clock, tune }
    }

    fn salt(&self, back: u64) -> Vec<u8> {
        ((self.clock)() / WINDOW_SECS).saturating_sub(back).to_be_bytes().to_vec()
    }

    fn build_node(&self) -> Result<AsyncDht, RvError> {
        let mut b = Node::builder(); // client mode is the default: we never serve other peers
        if let Some(h) = &self.bootstrap {
            b.bootstrap(h);
        }
        if let Some(a) = self.bind {
            b.bind_address(a);
        }
        b.build().map(|d| d.as_async()).map_err(|e| RvError::Failed(format!("dht bind: {e}")))
    }
}

/// `open` with shifted clocks, see module doc. Shifts forward too: a peer whose clock is more
/// than 30 s ahead of ours would otherwise be rejected as "from the future" forever, which made
/// the lagging machine deaf to the other one (accepts blobs from -7 min to +5.5 min of skew).
fn open_any(d: &Derived, own: Role, blob: &[u8], now: u64) -> Vec<SocketAddr> {
    for shift in [0i64, -150, -300, 150, 300] {
        if let Ok(c) = open_at(d, own, blob, now.saturating_add_signed(shift)) {
            return c;
        }
    }
    Vec::new()
}

#[async_trait::async_trait]
impl Rendezvous for Dht {
    fn id(&self) -> &'static str {
        "dht"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "BitTorrent Mainline DHT",
            shared: &["your IP address (to the DHT nodes that store or fetch the record), timing, and an unreadable sealed record under a key derived from the invite"],
            not_shared: &["your traffic", "the invite key", "your address in readable form"],
            why: "to tell the other device where you are so both can connect directly",
            operator: "the public BitTorrent Mainline DHT: millions of independent nodes, no single operator, no uptime promise; the first connection is slower (about 10-20 seconds)",
        }
    }

    /// Raw KRPC `ping` to the bootstrap hosts (queries only, nothing is published).
    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let hosts: Vec<String> = self.bootstrap.clone().unwrap_or_else(|| DEFAULT_BOOTSTRAP_NODES.iter().map(|s| s.to_string()).collect());
        let start = Instant::now();
        let mut addrs = Vec::new();
        for h in &hosts {
            if let Ok(Ok(it)) = tokio::time::timeout(timeout, tokio::net::lookup_host(h.as_str())).await {
                addrs.extend(it.filter(|a| a.is_ipv4()));
            }
        }
        let Ok(sock) = UdpSocket::bind((self.bind.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)).await else {
            return ProbeStatus::Error("cannot bind a UDP socket".into());
        };
        // bencoded {"a":{"id":<20 bytes>},"q":"ping","t":"rv","y":"q"}; any 20 bytes work as an id
        let mut pkt = b"d1:ad2:id20:".to_vec();
        pkt.extend_from_slice(&unix_now().to_be_bytes().repeat(3)[..20]);
        pkt.extend_from_slice(b"e1:q4:ping1:t2:rv1:y1:qe");
        let t0 = Instant::now();
        for a in &addrs {
            let _ = sock.send_to(&pkt, a).await;
        }
        let mut buf = [0u8; 1500];
        let r = tokio::time::timeout(timeout.saturating_sub(start.elapsed()), async {
            loop {
                let (n, _) = sock.recv_from(&mut buf).await.ok()?;
                if buf[..n].windows(6).any(|w| w == b"1:y1:r") {
                    return Some(t0.elapsed().as_millis() as u32);
                }
            }
        })
        .await;
        match r {
            Ok(Some(rtt_ms)) => ProbeStatus::Reachable { rtt_ms },
            _ => ProbeStatus::Blocked("no DHT bootstrap node answered".into()),
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let d = ctx.derived();
        let (my_seed, their_seed) = match ctx.role {
            Role::Host => (d.dht_host_seed, d.dht_client_seed),
            Role::Client => (d.dht_client_seed, d.dht_host_seed),
        };
        let my_sk = SigningKey::from_bytes(&my_seed);
        let their_key = SigningKey::from_bytes(&their_seed).verifying_key().to_bytes();

        let dht = self.build_node()?;
        let up = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            r = tokio::time::timeout(self.tune.bootstrap_timeout, dht.bootstrapped()) => r,
        };
        if !matches!(up, Ok(true)) {
            return Err(RvError::Blocked("DHT bootstrap did not complete (UDP blocked or filtered?)".into()));
        }

        let mut seq = unix_now() as i64; // time-based so a restart never goes below a stored seq
        let mut cas: Option<i64> = None;
        let mut published_window: Option<u64> = None;
        let mut put_ok = false; // at least one PUT was acknowledged
        let mut next_pub = Instant::now();
        let mut sched = PutSchedule::default();
        let mut poll_i = 0usize;
        let mut next_poll = Instant::now() + self.tune.poll_steps[0];
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        let my_key = my_sk.verifying_key().to_bytes();

        loop {
            let window = (self.clock)() / WINDOW_SECS;
            if Instant::now() >= next_pub || published_window != Some(window) {
                if published_window != Some(window) {
                    cas = None; // a new window is a new target: nothing of ours is stored there
                }
                let blob = seal(&d, ctx.role, &ctx.local).map_err(|e| RvError::Failed(format!("cannot seal candidates: {e}")))?;
                seq += 1;
                let item = MutableItem::new(my_sk.clone(), &blob, seq, Some(&self.salt(0)));
                let r = tokio::select! { _ = cancel.cancelled() => return Ok(()), r = dht.put_mutable(item, cas) => r };
                published_window = Some(window);
                match r {
                    Ok(o) => {
                        log::info!("dht: published, acknowledged by {} nodes", o.stored_at);
                        cas = Some(seq);
                        put_ok = true;
                        let wait = sched.after_put(&self.tune, o.stored_at);
                        // A host a client already found only re-announces slowly (for reconnects).
                        next_pub = Instant::now() + if joined(ctx.role, &seen) { self.tune.republish } else { wait };
                        ctx.status.set(Status::Publishing);
                    }
                    Err(e) => {
                        log::info!("dht: publish failed: {e}");
                        let conflict = matches!(e, PutMutableError::Concurrency(_) | PutMutableError::Query(PutQueryError::ErrorResponse(_)));
                        let soft = matches!(e, PutMutableError::Query(PutQueryError::NoClosestNodes | PutQueryError::Timeout));
                        cas = None;
                        next_pub = Instant::now() + Duration::from_secs(if soft { 5 } else { 15 }).min(self.tune.republish);
                        if conflict {
                            // Something of ours is already stored (an earlier run, or a clock that was
                            // ahead): read it first, then write above it with the right cas.
                            let salt = self.salt(0);
                            let cur = tokio::select! { _ = cancel.cancelled() => return Ok(()), r = dht.get_mutable_most_recent(&my_key, Some(&salt)) => r };
                            if let Some(it) = cur {
                                seq = seq.max(it.seq());
                                cas = Some(it.seq());
                                next_pub = Instant::now() + Duration::from_secs(1).min(self.tune.republish);
                            }
                        }
                    }
                }
                continue;
            }

            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(next_pub.min(next_poll).into()) => {}
            }
            if Instant::now() < next_poll {
                continue;
            }
            // poll: current window, previous, and next near the boundary; first one that opens wins
            let mut got = Vec::new();
            for w in poll_windows((self.clock)()) {
                let salt = w.to_be_bytes();
                let r = tokio::select! { _ = cancel.cancelled() => return Ok(()), r = dht.get_mutable_most_recent(&their_key, Some(&salt)) => r };
                if let Some(it) = r {
                    got = open_any(&d, ctx.role, it.value(), unix_now());
                    if !got.is_empty() {
                        break;
                    }
                }
            }
            if got.is_empty() {
                ctx.status.set(Status::Waiting);
            }
            for a in got {
                if seen.insert(a) && tx.send(Candidate { addr: a, via: "dht" }).await.is_err() {
                    return Ok(());
                }
            }
            if joined(ctx.role, &seen) && put_ok {
                // The early/retry PUTs are no longer needed: push the next one out to the slow rate.
                next_pub = next_pub.max(Instant::now() + self.tune.republish);
            }
            poll_i = (poll_i + 1).min(self.tune.poll_steps.len() - 1);
            next_poll = Instant::now() + self.tune.poll_steps[poll_i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_host_that_met_a_client_goes_quiet() {
        let mut seen = HashSet::new();
        assert!(!joined(Role::Host, &seen));
        seen.insert("1.2.3.4:5".parse().unwrap());
        assert!(joined(Role::Host, &seen));
        assert!(!joined(Role::Client, &seen), "a client keeps its early PUTs");
    }
}
