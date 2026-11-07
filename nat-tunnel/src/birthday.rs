//! Birthday-paradox punching for "cone host <- symmetric client".
//!
//! A symmetric NAT gives the client a new external port per destination, so the port the host
//! learned from STUN/rendezvous is useless toward the host. The host (port-restricted filter)
//! therefore sprays tiny punch frames at many random ports of the client's IP, and the client
//! opens many sockets (hence many external ports) toward the host. With N sprayed ports and K
//! client ports out of ~64k, the expected number of matching pairs is N*K/64512 (512*256 -> ~2).
//! A match opens the host's filter for that client port and the JOIN gets through.
//!
//! Direct only: no frame ever goes anywhere but the peer's IP. Kill switch: `NAT_TUNNEL_BIRTHDAY=0`.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Lowest port sprayed at (below it live well-known services, rarely a NAT external port).
pub const PORT_MIN: u16 = 1024;
/// A round of `spray` ports is spread over this long, so the router sees a trickle, not a burst.
const SPREAD: Duration = Duration::from_secs(2);
/// Concurrent client IPs sprayed at (the oldest is dropped past it).
const MAX_IPS: usize = 8;

/// How long an unreplied UDP mapping lives in a typical NAT/conntrack table (Linux: 30 s).
pub const FLOW_TTL: Duration = Duration::from_secs(30);

/// Bounds the NAT-table entries our own probes can have alive at once. Every probe to a new
/// (ip, port) opens a mapping that lingers ~[`FLOW_TTL`] on the sender's router, so the number of
/// probes sent in the last TTL is the live-entry estimate. Consumer routers hold only 4k-64k
/// entries; a scan must not evict the user's other flows.
pub struct FlowBudget {
    cap: usize,
    sent: VecDeque<(Instant, usize)>,
    live: usize,
}

impl FlowBudget {
    pub fn new(cap: usize) -> Self {
        Self { cap, sent: VecDeque::new(), live: 0 }
    }

    /// Change the cap (a ramp stage). Entries already alive keep counting until they expire.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// Permission to send up to `want` new-flow probes at `now`; returns how many (and counts them).
    pub fn take(&mut self, now: Instant, want: usize) -> usize {
        while let Some(&(t, n)) = self.sent.front() {
            if now.saturating_duration_since(t) < FLOW_TTL {
                break;
            }
            self.live -= n;
            self.sent.pop_front();
        }
        let n = want.min(self.cap.saturating_sub(self.live));
        if n > 0 {
            self.sent.push_back((now, n));
            self.live += n;
        }
        n
    }
}

#[derive(Clone, Debug)]
pub struct Birthday {
    /// Master switch (env `NAT_TUNNEL_BIRTHDAY=0` turns it off).
    pub enabled: bool,
    /// Host: random ports per round (env `NAT_TUNNEL_BIRTHDAY_SPRAY`, default 512).
    pub spray: usize,
    /// Host: total spray packets per client (default 4000).
    pub spray_cap: usize,
    /// Host: a fresh random set every this long while the client has not joined.
    pub round_gap: Duration,
    /// Guest: extra sockets (env `NAT_TUNNEL_BIRTHDAY_FAN`, default 256).
    pub fan: usize,
    /// Guest: single-socket punch time before the extra sockets open.
    pub fan_delay: Duration,
    /// Guest: port-scan rate in packets/s (env `NAT_TUNNEL_BIRTHDAY_SCAN`; 0 = off; default
    /// `scan_flows / 30`, i.e. 400). The scan finds a symmetric HOST's per-destination port: see
    /// [`Scanner`]. An explicit rate raises the live-flow budget to `rate * 30`.
    pub scan_pps: usize,
    /// Max NAT-table entries our probes keep alive at once (env `NAT_TUNNEL_BIRTHDAY_SCAN_FLOWS`,
    /// default 12000). Also bounds the host's spray (all clients together).
    pub scan_flows: usize,
    /// Guest: raise the scan rate in stages (see [`RAMP`]) when it stays unanswered. Off when
    /// `NAT_TUNNEL_BIRTHDAY_SCAN_FLOWS` or `NAT_TUNNEL_BIRTHDAY_SCAN` is set (strict router-safe mode).
    pub scan_ramp: bool,
    /// Guest: sweeps of the whole port range per host IP before giving up (default: no limit,
    /// the scan runs until the rendezvous deadline, `scan_window`).
    pub scan_passes: usize,
    /// Guest: how long the scan may run before the join attempt gives up (extends the budget).
    pub scan_window: Duration,
    /// Guest: silence (since the first host candidate) before the scan starts. After the
    /// fan-out and the usual cone/symmetric-client cases, which finish in ~4 s, had their chance.
    pub scan_delay: Duration,
}

fn env_num(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Scan ramp: (seconds since the scan started, packets/s). A router whose conntrack table fills
/// drops only NEW flows for ~30 s, so escalating after the cheap stage failed is acceptable.
pub const RAMP: [(u64, usize); 3] = [(0, 400), (20, 1500), (45, 4000)];
/// Live-flow ceiling of the ramp stages (stage 2's 1500 pps * 30 s). Beyond ~50k new flows alive a
/// t3.medium Windows peer lost ~35 % of the probes, so stage 3 only changes the burst, not this.
pub const RAMP_FLOWS: usize = 45_000;

impl Birthday {
    /// (stage, pps, max live flows) of the scan `since` its start. Without the ramp: the fixed
    /// configured rate. With it: never below the configured rate/budget (tests raise those).
    /// `sweeps`: full sweeps already done; after the first the rate stays at stage 2 (the
    /// ramp's burst is only for the first cycle).
    pub fn scan_stage(&self, since: Duration, sweeps: usize) -> (usize, usize, usize) {
        if !self.scan_ramp {
            return (0, self.scan_pps, self.scan_cap());
        }
        let k = if sweeps > 0 { 1 } else { RAMP.iter().rposition(|(t, _)| since.as_secs() >= *t).unwrap_or(0) };
        let pps = if k == 0 { self.scan_pps } else { RAMP[k].1.max(self.scan_pps) };
        (k, pps, self.scan_cap().max(pps.saturating_mul(FLOW_TTL.as_secs() as usize).min(RAMP_FLOWS)))
    }

    /// Live-flow budget for the scan: the configured one, or what an explicit rate needs.
    pub fn scan_cap(&self) -> usize {
        self.scan_flows.max(self.scan_pps.saturating_mul(FLOW_TTL.as_secs() as usize))
    }
}

impl Default for Birthday {
    fn default() -> Self {
        let flows = env_num("NAT_TUNNEL_BIRTHDAY_SCAN_FLOWS", 12_000);
        Self {
            enabled: std::env::var("NAT_TUNNEL_BIRTHDAY").map(|v| v != "0").unwrap_or(true),
            spray: env_num("NAT_TUNNEL_BIRTHDAY_SPRAY", 512),
            spray_cap: 4000,
            round_gap: Duration::from_secs(3),
            fan: env_num("NAT_TUNNEL_BIRTHDAY_FAN", 256),
            fan_delay: Duration::from_millis(1500),
            scan_pps: env_num("NAT_TUNNEL_BIRTHDAY_SCAN", flows / FLOW_TTL.as_secs() as usize),
            scan_flows: flows,
            scan_ramp: std::env::var_os("NAT_TUNNEL_BIRTHDAY_SCAN_FLOWS").is_none() && std::env::var_os("NAT_TUNNEL_BIRTHDAY_SCAN").is_none(),
            scan_passes: usize::MAX,
            scan_window: Duration::from_secs(180),
            scan_delay: Duration::from_secs(3),
        }
    }
}

/// Small non-cryptographic PRNG (splitmix64): port choice needs spread, not secrecy.
pub struct Rng(u64);

impl Rng {
    pub fn new() -> Self {
        let b = *uuid::Uuid::new_v4().as_bytes();
        Self(u64::from_le_bytes(b[..8].try_into().unwrap()))
    }
    pub fn from_seed(s: u64) -> Self {
        Self(s)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// `n` distinct ports drawn uniformly from `PORT_MIN..=65535`, never `exclude`. Exactly
/// `min(n, 64512 - [exclude in range])` of them.
pub fn random_ports(n: usize, exclude: u16, rng: &mut Rng) -> Vec<u16> {
    let mut all: Vec<u16> = (PORT_MIN..=u16::MAX).filter(|p| *p != exclude).collect();
    let n = n.min(all.len());
    for i in 0..n {
        let j = i + (rng.next() % (all.len() - i) as u64) as usize;
        all.swap(i, j);
    }
    all.truncate(n);
    all
}

/// Guest-side sweep of a HOST's destination ports from the main socket. A host behind a symmetric
/// NAT sends from a fresh external port per destination, so the port it announced is useless
/// toward us; it fires a punch at our known endpoint, which opens its NAT for our main-socket
/// source, and whichever of our probes lands on that fresh port is answered. Each sweep visits
/// every port once: the announced port's neighbours first (sequential allocators; sweep 1 only),
/// then all other ports in a fresh uniform shuffle per sweep.
pub struct Scanner {
    pub ip: Ipv4Addr,
    announced: u16,
    order: Vec<u16>,
    pos: usize,
    passes_left: usize,
    sweeps: usize,
    rng: Rng,
}

/// Neighbours of the announced port tried first (sweep 1 only).
const SCAN_NEAR: u16 = 64;

/// One sweep: every port once. Sweep 1 starts with the announced port's neighbours; all the rest
/// (and every later sweep) is one uniform shuffle of the whole range, so a port lost in one
/// sweep (a lossy late period of the sender's path) is unlikely to be lost again in the next.
fn scan_order(announced: u16, rng: &mut Rng, first: bool) -> Vec<u16> {
    let (lo, hi) = if first { (announced.saturating_sub(SCAN_NEAR).max(PORT_MIN), announced.saturating_add(SCAN_NEAR)) } else { (1, 0) };
    let mut order: Vec<u16> = (lo..=hi).collect();
    let mut v: Vec<u16> = (PORT_MIN..=u16::MAX).filter(|p| *p < lo || *p > hi).collect();
    for i in 0..v.len() {
        let j = i + (rng.next() % (v.len() - i) as u64) as usize;
        v.swap(i, j);
    }
    order.extend(v);
    order
}

impl Scanner {
    /// `passes`: sweeps before giving up (`usize::MAX` = until the caller's deadline).
    pub fn new(ip: Ipv4Addr, announced: u16, passes: usize) -> Self {
        let mut rng = Rng::new();
        let order = scan_order(announced, &mut rng, true);
        Self { ip, announced, order, pos: 0, passes_left: passes, sweeps: 0, rng }
    }

    /// Ports of one pass.
    pub fn pass_len(&self) -> usize {
        self.order.len()
    }

    /// Sweeps completed so far.
    pub fn sweeps(&self) -> usize {
        self.sweeps
    }

    /// Next `n` ports (fewer at a pass end); empty once every pass is done.
    pub fn next(&mut self, n: usize) -> Vec<u16> {
        if self.passes_left == 0 {
            return Vec::new();
        }
        let end = (self.pos + n).min(self.order.len());
        let out = self.order[self.pos..end].to_vec();
        self.pos = end;
        if self.pos == self.order.len() {
            self.passes_left -= 1;
            self.sweeps += 1;
            self.pos = 0;
            self.order = scan_order(self.announced, &mut self.rng, false);
        }
        out
    }

    pub fn done(&self) -> bool {
        self.passes_left == 0
    }
}

/// Scan probe tally: only probes the socket accepted count as sent.
#[derive(Default)]
pub struct ProbeTally {
    pub sent: usize,
    pub failed: usize,
}

impl ProbeTally {
    pub fn note(&mut self, to: SocketAddr, r: std::io::Result<usize>) {
        match r {
            Ok(_) => self.sent += 1,
            Err(e) => {
                if self.failed == 0 {
                    log::warn!("birthday scan: sending a probe to {to} failed: {e} (further failures are only counted)");
                }
                self.failed += 1;
            }
        }
    }
}

struct Spray {
    ip: Ipv4Addr,
    known: u16,
    first: Instant,
    /// Packets queued so far (never exceeds the cap).
    planned: usize,
    queue: Vec<u16>,
    round_at: Option<Instant>,
    last: Instant,
}

/// Host-side schedule: which ports to fire at, when. Pure logic; the caller does the sending.
pub struct Sprayer {
    cfg: Birthday,
    list: Vec<Spray>,
    rng: Rng,
    /// Spray probes open mappings on the HOST's NAT: all clients together stay within `scan_flows`.
    budget: FlowBudget,
}

impl Sprayer {
    pub fn new(cfg: Birthday) -> Self {
        let budget = FlowBudget::new(cfg.scan_flows);
        Self { cfg, list: Vec::new(), rng: Rng::new(), budget }
    }

    /// Start spraying at a client candidate (IPv4 only). A running spray for that IP is kept.
    pub fn add(&mut self, addr: SocketAddr, total: Duration) {
        let IpAddr::V4(ip) = addr.ip() else { return };
        if !self.cfg.enabled || self.cfg.spray == 0 || self.cfg.spray_cap == 0 {
            return;
        }
        let now = Instant::now();
        if let Some(s) = self.list.iter_mut().find(|s| s.ip == ip) {
            if s.first.elapsed() < total {
                return;
            }
            self.list.retain(|s| s.ip != ip);
        }
        if self.list.len() >= MAX_IPS {
            self.list.remove(0);
        }
        log::info!(
            "birthday spray: client {ip} (known port {}): firing at {} random ports per round, up to {} packets",
            addr.port(),
            self.cfg.spray,
            self.cfg.spray_cap
        );
        self.list.push(Spray { ip, known: addr.port(), first: now, planned: 0, queue: Vec::new(), round_at: None, last: now });
    }

    /// Stop for clients that joined.
    pub fn joined(&mut self, ips: &[Ipv4Addr]) {
        self.list.retain(|s| {
            let hit = ips.contains(&s.ip);
            if hit {
                log::info!(
                    "birthday spray: client {} joined after {} spray packets in {:.1}s",
                    s.ip,
                    s.planned - s.queue.len(),
                    s.first.elapsed().as_secs_f32()
                );
            }
            !hit
        });
    }

    /// IPs currently being sprayed (tests).
    pub fn ips(&self) -> Vec<Ipv4Addr> {
        self.list.iter().map(|s| s.ip).collect()
    }

    /// Destinations to fire at right now.
    pub fn due(&mut self, now: Instant, total: Duration) -> Vec<SocketAddr> {
        let (spray, cap, gap) = (self.cfg.spray, self.cfg.spray_cap, self.cfg.round_gap);
        let mut out = Vec::new();
        let (rng, budget) = (&mut self.rng, &mut self.budget);
        self.list.retain_mut(|s| {
            if now.duration_since(s.first) >= total || (s.planned >= cap && s.queue.is_empty()) {
                log::info!("birthday spray: client {} gave up after {} packets", s.ip, s.planned - s.queue.len());
                return false;
            }
            if s.queue.is_empty() && s.round_at.is_none_or(|t| now.duration_since(t) >= gap) {
                let n = spray.min(cap - s.planned);
                s.queue = random_ports(n, s.known, rng);
                s.planned += s.queue.len();
                s.round_at = Some(now);
                s.last = now;
            }
            if !s.queue.is_empty() {
                let dt = now.duration_since(s.last).min(Duration::from_millis(250));
                let k = ((spray as f64 * dt.as_secs_f64() / SPREAD.as_secs_f64()).ceil() as usize).clamp(1, s.queue.len());
                let k = budget.take(now, k);
                s.last = now;
                for _ in 0..k {
                    let p = s.queue.pop().unwrap();
                    out.push(SocketAddr::new(s.ip.into(), p));
                }
            }
            true
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ports_distinct_in_range_exclude_known() {
        let mut rng = Rng::from_seed(7);
        for exclude in [0u16, 1023, 1024, 5000, 65535] {
            let v = random_ports(512, exclude, &mut rng);
            assert_eq!(v.len(), 512);
            assert_eq!(v.iter().collect::<HashSet<_>>().len(), 512, "distinct");
            assert!(v.iter().all(|p| *p >= PORT_MIN && *p != exclude));
        }
        // asking for more than exist yields all of them
        assert_eq!(random_ports(100_000, 5000, &mut rng).len(), 64511);
        assert_eq!(random_ports(100_000, 80, &mut rng).len(), 64512);
        assert!(random_ports(0, 5000, &mut rng).is_empty());
        // two draws differ, and are spread (not a prefix)
        let (a, b) = (random_ports(512, 0, &mut rng), random_ports(512, 0, &mut rng));
        assert_ne!(a, b);
        assert!(a.iter().any(|p| *p > 40000) && a.iter().any(|p| *p < 20000));
    }

    #[test]
    fn scanner_covers_every_port_once_per_pass_near_ones_first() {
        let mut sc = Scanner::new(Ipv4Addr::new(10, 0, 0, 1), 40000, 2);
        let first = sc.next(129);
        assert_eq!(first.iter().collect::<HashSet<_>>().len(), 129);
        assert!(first.iter().all(|p| p.abs_diff(40000) <= SCAN_NEAR), "neighbours first");
        let mut all = first;
        while all.len() < 64512 {
            all.extend(sc.next(1000));
        }
        assert_eq!(all.iter().collect::<HashSet<_>>().len(), 64512, "pass 1: every unprivileged port once");
        assert!(!sc.done());
        let mut n = 0;
        loop {
            let v = sc.next(1000);
            if v.is_empty() {
                break;
            }
            n += v.len();
        }
        assert_eq!(n, 64512, "pass 2 is the same size, then it stops (hard packet cap)");
        assert!(sc.done());
        // later sweeps: a fresh order over the whole range, not the ranges in a fixed sequence
        let mut sc = Scanner::new(Ipv4Addr::new(10, 0, 0, 1), 40000, 3);
        let mut sweep = || {
            let mut v = Vec::new();
            while v.len() < 64512 {
                v.extend(sc.next(1000));
            }
            v
        };
        let (s1, s2, s3) = (sweep(), sweep(), sweep());
        for s in [&s2, &s3] {
            assert_eq!(s.iter().collect::<HashSet<_>>().len(), 64512, "every port once");
            assert!(s.iter().any(|p| p.abs_diff(40000) <= SCAN_NEAR) && s[..129].iter().any(|p| p.abs_diff(40000) > SCAN_NEAR), "no neighbours-first in later sweeps");
        }
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        // the tail of sweep 1 is not the tail of sweep 2 (the old order always ended in 1024-32767)
        let tail = |v: &[u16]| v[v.len() - 20000..].iter().filter(|p| **p < 32768).count();
        assert!(tail(&s1) > 5000 && tail(&s1) < 15000 && tail(&s2) > 5000 && tail(&s2) < 15000, "{} {}", tail(&s1), tail(&s2));
        let late: HashSet<_> = s1[s1.len() - 20000..].iter().collect();
        let overlap = s2[s2.len() - 20000..].iter().filter(|p| late.contains(p)).count();
        assert!(overlap < 10000, "late ports of sweep 1 mostly differ from sweep 2's: {overlap}");
        assert_eq!(sc.sweeps(), 3);
        // announced port near the edge of the range
        let mut e = Scanner::new(Ipv4Addr::new(10, 0, 0, 1), 1030, 1);
        assert!(e.next(10).iter().all(|p| *p >= PORT_MIN));
    }

    /// Drive a pacer on a simulated clock and check no sliding FLOW_TTL window holds more
    /// probes than the budget, however the caller asks (steady pps or huge bursts).
    fn sim(cap: usize, want_per_tick: impl Fn(usize) -> usize, secs: u64) -> usize {
        let t0 = Instant::now();
        let mut b = FlowBudget::new(cap);
        let mut sent: Vec<(u64, usize)> = Vec::new();
        for tick in 0..secs * 20 {
            let ms = tick * 50;
            let n = b.take(t0 + Duration::from_millis(ms), want_per_tick(tick as usize));
            sent.push((ms, n));
        }
        let ttl = FLOW_TTL.as_millis() as u64;
        for (ms, _) in &sent {
            let live: usize = sent.iter().filter(|(m, _)| *m <= *ms && ms - m < ttl).map(|(_, n)| n).sum();
            assert!(live <= cap, "live {live} > cap {cap} at {ms} ms");
        }
        sent.iter().map(|(_, n)| n).sum()
    }

    #[test]
    fn pacing_never_exceeds_the_live_flow_budget() {
        let b = Birthday::default();
        assert_eq!((b.scan_flows, b.scan_pps), (12_000, 400));
        // steady 400 pps (20 per 50 ms tick) for 5 min: exactly the budget rate, never over
        let total = sim(12_000, |_| 20, 300);
        assert_eq!(total, 20 * 20 * 300, "a steady rate at flows/30 is never throttled");
        // a caller asking for far more (jitter bursts, bug): clamped to cap per 30 s
        let total = sim(12_000, |_| 5000, 90);
        assert_eq!(total, 12_000 * 3, "cap per TTL window");
        // a small budget, 3 windows
        assert_eq!(sim(300, |_| 100, 90), 900);
    }

    #[test]
    fn ramp_schedule_raises_rate_in_stages_within_each_stage_budget() {
        let b = Birthday { scan_ramp: true, scan_pps: 400, scan_flows: 12_000, ..Birthday::default() };
        let at = |s: u64| b.scan_stage(Duration::from_secs(s), 0);
        assert_eq!(at(0), (0, 400, 12_000));
        assert_eq!(at(19), (0, 400, 12_000));
        assert_eq!(at(20), (1, 1500, 45_000));
        assert_eq!(at(44), (1, 1500, 45_000));
        // stage 3 keeps the stage-2 live-flow cap (a lossy sender path above ~50k live flows)
        assert_eq!(at(45), (2, 4000, 45_000));
        assert_eq!(at(170), (2, 4000, 45_000));
        // after the first full sweep: stage-2 rate for good
        assert_eq!(b.scan_stage(Duration::from_secs(60), 1), (1, 1500, 45_000));
        assert_eq!(b.scan_stage(Duration::from_secs(5), 2), (1, 1500, 45_000));
        // strict mode: fixed
        let strict = Birthday { scan_ramp: false, ..b.clone() };
        assert_eq!(strict.scan_stage(Duration::from_secs(100), 0), (0, 400, 12_000));
        // simulated clock: pace like the scan loop (want = pps*50 ms, cap per stage)
        let t0 = Instant::now();
        let mut fb = FlowBudget::new(12_000);
        let mut sent: Vec<(u64, usize)> = Vec::new();
        let mut stage = 0;
        for tick in 0..180 * 20u64 {
            let ms = tick * 50;
            let (k, pps, cap) = b.scan_stage(Duration::from_millis(ms), 0);
            if k != stage {
                stage = k;
                fb.set_cap(cap);
            }
            let n = fb.take(t0 + Duration::from_millis(ms), pps / 20);
            sent.push((ms, n));
        }
        let ttl = FLOW_TTL.as_millis() as u64;
        let mut peak = [0usize; 3];
        for (ms, _) in &sent {
            let live: usize = sent.iter().filter(|(m, _)| m <= ms && ms - m < ttl).map(|(_, n)| n).sum();
            let (k, _, cap) = b.scan_stage(Duration::from_millis(*ms), 0);
            assert!(live <= cap, "stage {k}: live {live} > cap {cap} at {ms} ms");
            peak[k] = peak[k].max(live);
        }
        // stage 1 lasts 20 s at 400 pps, so at most 8000 probes are alive before stage 2 starts
        assert_eq!(peak[0], 8_000);
        assert!(peak[1] > 12_000 && peak[1] <= 45_000, "{peak:?}");
        assert!(peak[2] > 40_000 && peak[2] <= 45_000, "{peak:?}");
        let in_stage1: usize = sent.iter().filter(|(m, _)| (20_000..45_000).contains(m)).map(|(_, n)| n).sum();
        assert!(in_stage1 > 25 * 1000, "stage 2 really runs faster: {in_stage1}");
    }

    /// Simulated clock: the default scan keeps sweeping (fresh order each time) until the 183 s
    /// deadline, at stage-2 rate after sweep 1, never above 45k live flows.
    #[test]
    fn failed_sends_are_not_counted_as_sent() {
        let mut t = ProbeTally::default();
        let to: SocketAddr = "10.0.0.1:2000".parse().unwrap();
        t.note(to, Ok(40));
        t.note(to, Err(std::io::Error::other("no buffer space")));
        t.note(to, Err(std::io::Error::other("no buffer space")));
        t.note(to, Ok(40));
        assert_eq!((t.sent, t.failed), (2, 2));
    }

    #[test]
    fn scan_continues_past_two_sweeps_until_the_deadline() {
        let b = Birthday::default();
        assert_eq!(b.scan_passes, usize::MAX);
        let mut sc = Scanner::new(Ipv4Addr::new(10, 0, 0, 1), 5000, b.scan_passes);
        let t0 = Instant::now();
        let mut fb = FlowBudget::new(b.scan_cap());
        let mut stage = 0;
        let mut sent: Vec<(u64, usize)> = Vec::new();
        let mut seen: HashSet<u16> = HashSet::new();
        let mut sweep_end: Vec<u64> = Vec::new();
        for slice in 0..183 * 100u64 {
            let ms = slice * 10;
            let (k, pps, cap) = b.scan_stage(Duration::from_millis(ms), sc.sweeps());
            if k != stage {
                stage = k;
                fb.set_cap(cap);
            }
            let n = fb.take(t0 + Duration::from_millis(ms), pps / 100);
            let before = sc.sweeps();
            seen.extend(sc.next(n));
            if sc.sweeps() != before {
                sweep_end.push(ms);
            }
            sent.push((ms, n));
            assert!(!sc.done());
        }
        assert!(sweep_end.len() >= 3, "sweeps finished at {sweep_end:?}");
        assert!(sweep_end[0] < 70_000, "first cycle (ramp) done early: {sweep_end:?}");
        assert_eq!(seen.len(), 64512);
        let ttl = FLOW_TTL.as_millis() as u64;
        for (ms, _) in sent.iter().step_by(37) {
            let live: usize = sent.iter().filter(|(m, _)| m <= ms && ms - m < ttl).map(|(_, n)| n).sum();
            assert!(live <= 45_000, "live {live} at {ms} ms");
        }
    }

    #[test]
    fn spray_of_many_clients_stays_in_budget() {
        let c = Birthday { scan_flows: 600, ..cfg(512, 4000) };
        let mut s = Sprayer::new(c);
        for i in 1..=6u8 {
            s.add(format!("10.1.2.{i}:5000").parse().unwrap(), Duration::from_secs(600));
        }
        let t0 = Instant::now();
        let mut at: Vec<u64> = Vec::new();
        for i in 0..=1200u64 {
            let ms = i * 50;
            for _ in s.due(t0 + Duration::from_millis(ms), Duration::from_secs(600)) {
                at.push(ms);
            }
        }
        assert!(at.len() > 600, "it does keep spraying across windows: {}", at.len());
        for ms in &at {
            let live = at.iter().filter(|m| **m <= *ms && *ms - **m < 30_000).count();
            assert!(live <= 600, "live {live} at {ms}");
        }
    }

    fn cfg(spray: usize, cap: usize) -> Birthday {
        Birthday { enabled: true, spray, spray_cap: cap, round_gap: Duration::from_millis(100), ..Birthday::default() }
    }

    fn run(s: &mut Sprayer, ms: u64) -> Vec<SocketAddr> {
        let t0 = Instant::now();
        let mut all = Vec::new();
        for i in 0..=ms / 10 {
            all.extend(s.due(t0 + Duration::from_millis(i * 10), Duration::from_secs(60)));
        }
        all
    }

    #[test]
    fn cap_per_client_is_exact() {
        let mut s = Sprayer::new(cfg(100, 250));
        s.add("10.1.2.3:5000".parse().unwrap(), Duration::from_secs(60));
        let all = run(&mut s, 5000);
        assert_eq!(all.len(), 250, "100 + 100 + 50, then it stops");
        assert!(all.iter().all(|a| a.ip() == IpAddr::from([10, 1, 2, 3]) && a.port() != 5000 && a.port() >= PORT_MIN));
        assert!(s.ips().is_empty(), "finished entry is dropped");
    }

    #[test]
    fn first_round_is_spread_not_a_burst() {
        let mut s = Sprayer::new(cfg(512, 4000));
        s.add("10.1.2.3:5000".parse().unwrap(), Duration::from_secs(60));
        let t0 = Instant::now();
        let first = s.due(t0, Duration::from_secs(60));
        assert!(first.len() <= 2, "{}", first.len());
        let after_100ms = s.due(t0 + Duration::from_millis(100), Duration::from_secs(60));
        assert!(after_100ms.len() <= 30, "{}", after_100ms.len());
    }

    #[test]
    fn only_ipv4_enabled_and_joined_stop() {
        let mut s = Sprayer::new(cfg(10, 100));
        s.add("[2001:db8::1]:5000".parse().unwrap(), Duration::from_secs(60));
        assert!(s.ips().is_empty());
        s.add("10.1.2.3:5000".parse().unwrap(), Duration::from_secs(60));
        s.add("10.1.2.3:5001".parse().unwrap(), Duration::from_secs(60));
        assert_eq!(s.ips().len(), 1, "one spray per IP");
        s.joined(&[Ipv4Addr::new(10, 1, 2, 3)]);
        assert!(s.ips().is_empty());
        let mut off = Sprayer::new(Birthday { enabled: false, ..cfg(10, 100) });
        off.add("10.1.2.3:5000".parse().unwrap(), Duration::from_secs(60));
        assert!(off.ips().is_empty());
    }
}
