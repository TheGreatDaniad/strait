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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Lowest port sprayed at (below it live well-known services, rarely a NAT external port).
pub const PORT_MIN: u16 = 1024;
/// A round of `spray` ports is spread over this long, so the router sees a trickle, not a burst.
const SPREAD: Duration = Duration::from_secs(2);
/// Concurrent client IPs sprayed at (the oldest is dropped past it).
const MAX_IPS: usize = 8;

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
}

fn env_num(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Default for Birthday {
    fn default() -> Self {
        Self {
            enabled: std::env::var("NAT_TUNNEL_BIRTHDAY").map(|v| v != "0").unwrap_or(true),
            spray: env_num("NAT_TUNNEL_BIRTHDAY_SPRAY", 512),
            spray_cap: 4000,
            round_gap: Duration::from_secs(3),
            fan: env_num("NAT_TUNNEL_BIRTHDAY_FAN", 256),
            fan_delay: Duration::from_millis(1500),
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
}

impl Sprayer {
    pub fn new(cfg: Birthday) -> Self {
        Self { cfg, list: Vec::new(), rng: Rng::new() }
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
        let rng = &mut self.rng;
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
