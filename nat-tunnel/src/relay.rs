//! Rendezvous / signaling server.
//!
//! Peers register into a room; the server reports each peer's observed address
//! to the others so they can attempt a direct hole punch. The server never
//! forwards payload and cannot decrypt anything.
//!
//! A room holds one host and up to [`MAX_CLIENTS`] clients. That reflects the
//! product model: one host accepts many clients, and each client gets its own
//! tunnel session.
//!
//! Wire format:
//!
//! ```text
//! peer -> server
//!   REGISTER:   [0x01][room u32 BE][role u8]        role 0 = host, 1 = client
//!   DEREGISTER: [0x04][room u32 BE][role u8]
//!   PING:       [0x05][nonce u32 BE]                reachability / latency probe
//!
//! server -> peer
//!   PONG:       [0x06][nonce u32 BE]
//!   PEER:       [0x03][room u32 BE][role u8][ip 4][port u16 BE]
//! ```
//!
//! A `PEER` with role 0 is the host's address; role 1 is a client's address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

const REGISTER: u8 = 0x01;
const PEER: u8 = 0x03;
const DEREGISTER: u8 = 0x04;
const PING: u8 = 0x05;
const PONG: u8 = 0x06;

/// Hard server-side cap per room. The host may choose a lower limit.
pub const MAX_CLIENTS: usize = 1024;

/// Peers re-register every ~15 s; drop anything older than this.
const EXPIRY: Duration = Duration::from_secs(45);

/// Legacy: 32-bit room id derived from a room name.
pub fn room_id(name: &str) -> u32 {
    let digest = Sha256::digest(name.as_bytes());
    u32::from_be_bytes(digest[..4].try_into().unwrap())
}

/// Room id derived from the invite key.
///
/// The key never leaves the two peers, so an observer of the server cannot
/// guess the room, and the invite does not need to carry a room field.
pub fn room_for_key(key: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(b"strait-room");
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    u32::from_be_bytes(digest[..4].try_into().unwrap())
}

pub fn encode_register(room: u32, role: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(REGISTER);
    out.extend_from_slice(&room.to_be_bytes());
    out.push(role);
    out
}

/// Leave the room. The server only removes the entry if it still belongs to
/// the sender, so a late deregistration cannot evict a newer session.
pub fn encode_deregister(room: u32, role: u8) -> Vec<u8> {
    let mut out = encode_register(room, role);
    out[0] = DEREGISTER;
    out
}

/// Reachability probe used by the host preflight.
pub fn encode_ping(nonce: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(PING);
    out.extend_from_slice(&nonce.to_be_bytes());
    out
}

/// Something a client receives from the server.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Someone in the room, with the role they registered as.
    Peer { role: u8, addr: SocketAddr },
    /// Answer to a [`encode_ping`], echoing the nonce.
    Pong(u32),
}

pub fn decode(buf: &[u8]) -> Option<Incoming> {
    if buf.len() < 5 {
        return None;
    }
    match buf[0] {
        PONG if buf.len() == 5 => Some(Incoming::Pong(u32::from_be_bytes(
            buf[1..5].try_into().ok()?,
        ))),
        PEER if buf.len() == 12 => {
            let role = buf[5];
            let ip = std::net::Ipv4Addr::new(buf[6], buf[7], buf[8], buf[9]);
            let port = u16::from_be_bytes([buf[10], buf[11]]);
            Some(Incoming::Peer {
                role,
                addr: SocketAddr::from((ip, port)),
            })
        }
        _ => None,
    }
}

/// Max PEER messages sent per REGISTER, to the registrant and (separately) to
/// other peers. Clients re-register every ~15 s and each re-registration
/// re-introduces them to the host, so truncation only delays discovery.
///
/// Amplification: a 6-byte REGISTER yields at most 8 x 12 = 96 bytes to the
/// source address (16x) plus at most 96 bytes to other registered peers. The
/// per-IP rate limit bounds the total; PING/PONG is 1:1 (5 -> 5 bytes).
pub const MAX_PEERS_PER_REGISTER: usize = 8;

/// Server limits. `Default` is the production configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// PING: sustained messages per second per source IP.
    pub rate_per_sec: f64,
    /// PING: token bucket depth (burst) per source IP.
    pub burst: f64,
    /// REGISTER/DEREGISTER: sustained rate per source IP. Separate from PING
    /// so a probe flood cannot starve registrations and vice versa.
    pub reg_rate_per_sec: f64,
    /// REGISTER/DEREGISTER: per-IP burst. Sized so a household or campus NAT
    /// (many clients, one IP, all re-registering every ~15 s) is not locked out.
    pub reg_burst: f64,
    /// REGISTER/DEREGISTER: global cap across all IPs (rate and burst); bounds
    /// total amplification no matter how many source IPs an attacker spoofs.
    pub reg_global_rate_per_sec: f64,
    pub reg_global_burst: f64,
    /// Registration lifetime without refresh.
    pub expiry: Duration,
    pub max_rooms: usize,
    pub max_clients: usize,
    /// Cap on tracked source IPs; beyond it new IPs are dropped.
    pub max_buckets: usize,
}

impl Config {
    /// Defaults overridden by `STRAIT_SIGNAL_RATE` (PING msgs/s per IP),
    /// `STRAIT_SIGNAL_BURST` (PING burst, and REGISTER burst scaled 3x) and
    /// `STRAIT_SIGNAL_EXPIRY` (seconds). Invalid values are an error, not
    /// silently ignored.
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).ok();
        Self::from_vars(get("STRAIT_SIGNAL_RATE").as_deref(), get("STRAIT_SIGNAL_BURST").as_deref(), get("STRAIT_SIGNAL_EXPIRY").as_deref())
    }

    pub fn from_vars(rate: Option<&str>, burst: Option<&str>, expiry: Option<&str>) -> Result<Self, String> {
        fn num(name: &str, v: &str, min: f64, max: f64) -> Result<f64, String> {
            let n: f64 = v.trim().parse().map_err(|_| format!("{name}={v:?} is not a number"))?;
            if !n.is_finite() || n < min || n > max {
                return Err(format!("{name}={v} out of range {min}..={max}"));
            }
            Ok(n)
        }
        let mut c = Self::default();
        if let Some(v) = rate {
            c.rate_per_sec = num("STRAIT_SIGNAL_RATE", v, 0.1, 1e6)?;
            c.reg_rate_per_sec = c.rate_per_sec;
        }
        if let Some(v) = burst {
            c.burst = num("STRAIT_SIGNAL_BURST", v, 1.0, 1e6)?;
            c.reg_burst = c.burst * 3.0;
        }
        if let Some(v) = expiry {
            // Peers refresh every ~15 s; below 20 s they would flap.
            c.expiry = Duration::from_secs_f64(num("STRAIT_SIGNAL_EXPIRY", v, 20.0, 86_400.0)?);
        }
        Ok(c)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rate_per_sec: 20.0,
            burst: 40.0,
            // 100 clients per NAT: 100/15 s ~ 7/s sustained, 120 burst.
            reg_rate_per_sec: 20.0,
            reg_burst: 120.0,
            reg_global_rate_per_sec: 2_000.0,
            reg_global_burst: 4_000.0,
            expiry: EXPIRY,
            max_rooms: 65_536,
            max_clients: MAX_CLIENTS,
            max_buckets: 65_536,
        }
    }
}

struct Registration {
    addr: SocketAddr,
    seen: Instant,
}

#[derive(Default)]
struct Room {
    host: Option<Registration>,
    clients: Vec<Registration>,
}

impl Room {
    fn expire(&mut self, now: Instant, expiry: Duration) {
        if self
            .host
            .as_ref()
            .is_some_and(|h| now.saturating_duration_since(h.seen) >= expiry)
        {
            self.host = None;
        }
        self.clients
            .retain(|c| now.saturating_duration_since(c.seen) < expiry);
    }

    fn is_empty(&self) -> bool {
        self.host.is_none() && self.clients.is_empty()
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Pure state machine: feed it datagrams, get back datagrams to send.
pub struct State {
    cfg: Config,
    rooms: HashMap<u32, Room>,
    buckets: HashMap<IpAddr, Bucket>,
    reg_buckets: HashMap<IpAddr, Bucket>,
    reg_global: Bucket,
    last_sweep: Instant,
}

impl State {
    pub fn new(cfg: Config, now: Instant) -> Self {
        let reg_global = Bucket { tokens: cfg.reg_global_burst, last: now };
        Self {
            cfg,
            rooms: HashMap::new(),
            buckets: HashMap::new(),
            reg_buckets: HashMap::new(),
            reg_global,
            last_sweep: now,
        }
    }

    fn sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) < self.cfg.expiry / 3 {
            return;
        }
        self.last_sweep = now;
        let expiry = self.cfg.expiry;
        self.rooms.retain(|_, r| {
            r.expire(now, expiry);
            !r.is_empty()
        });
        // A bucket idle long enough to be full again carries no information.
        let refill = Duration::from_secs_f64(self.cfg.burst / self.cfg.rate_per_sec);
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < refill);
        let refill = Duration::from_secs_f64(self.cfg.reg_burst / self.cfg.reg_rate_per_sec);
        self.reg_buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < refill);
    }

    fn take(b: &mut Bucket, rate: f64, burst: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * rate).min(burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Per-IP budget; `reg` selects the REGISTER/DEREGISTER budget, which is
    /// also subject to the global cap. The global token is only spent once the
    /// per-IP check passed, so one flooding IP cannot drain it by itself
    /// beyond its own burst/rate.
    fn allow(&mut self, ip: IpAddr, reg: bool, now: Instant) -> bool {
        let (rate, burst) = if reg {
            (self.cfg.reg_rate_per_sec, self.cfg.reg_burst)
        } else {
            (self.cfg.rate_per_sec, self.cfg.burst)
        };
        let map = if reg { &mut self.reg_buckets } else { &mut self.buckets };
        if !map.contains_key(&ip) && map.len() >= self.cfg.max_buckets {
            return false;
        }
        let b = map.entry(ip).or_insert(Bucket { tokens: burst, last: now });
        if !Self::take(b, rate, burst, now) {
            return false;
        }
        !reg || Self::take(&mut self.reg_global, self.cfg.reg_global_rate_per_sec, self.cfg.reg_global_burst, now)
    }

    /// Process one datagram; returns `(destination, payload)` replies.
    pub fn handle(&mut self, buf: &[u8], from: SocketAddr, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        self.sweep(now);
        // IPv6 is not served: replies and PEER messages are IPv4-only, so a v6
        // source gets silence and consumes no state. A v4-mapped v6 source
        // (::ffff:a.b.c.d, as seen on a dual-stack socket) is plain IPv4.
        let from = match normalize(from) {
            Some(a) => a,
            None => return Vec::new(),
        };
        if buf.len() > 8 {
            return Vec::new();
        }
        let reg = matches!(buf.first(), Some(&REGISTER) | Some(&DEREGISTER));
        if !self.allow(from.ip(), reg, now) {
            return Vec::new();
        }
        let mut out = Vec::new();
        match (buf.first(), buf.len()) {
            (Some(&PING), 5) => {
                let nonce = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                out.push((from, pong_msg(nonce)));
            }
            (Some(&REGISTER), 6) | (Some(&DEREGISTER), 6) if buf[5] <= 1 => {
                let room = u32::from_be_bytes(buf[1..5].try_into().unwrap());
                let role = buf[5];
                if buf[0] == REGISTER {
                    self.register(room, role, from, now, &mut out);
                } else {
                    self.deregister(room, role, from, &mut out);
                }
            }
            _ => {}
        }
        out.retain(|(_, m)| !m.is_empty());
        out
    }

    fn register(&mut self, room: u32, role: u8, from: SocketAddr, now: Instant, out: &mut Vec<(SocketAddr, Vec<u8>)>) {
        if !self.rooms.contains_key(&room) && self.rooms.len() >= self.cfg.max_rooms {
            return;
        }
        let expiry = self.cfg.expiry;
        let max_clients = self.cfg.max_clients;
        let entry = self.rooms.entry(room).or_default();
        entry.expire(now, expiry);
        let reg = Registration { addr: from, seen: now };
        if role == 0 {
            entry.host = Some(reg);
            for c in entry.clients.iter().take(MAX_PEERS_PER_REGISTER) {
                out.push((from, peer_msg(room, 1, c.addr)));
                out.push((c.addr, peer_msg(room, 0, from)));
            }
        } else {
            entry.clients.retain(|c| c.addr != from);
            if entry.clients.len() >= max_clients {
                return;
            }
            entry.clients.push(reg);
            if let Some(h) = &entry.host {
                out.push((from, peer_msg(room, 0, h.addr)));
                out.push((h.addr, peer_msg(room, 1, from)));
            }
        }
    }

    fn deregister(&mut self, room: u32, role: u8, from: SocketAddr, out: &mut Vec<(SocketAddr, Vec<u8>)>) {
        let Some(entry) = self.rooms.get_mut(&room) else { return };
        if role == 0 {
            if entry.host.as_ref().map(|h| h.addr) == Some(from) {
                entry.host = None;
                for c in entry.clients.iter().take(MAX_PEERS_PER_REGISTER) {
                    out.push((c.addr, peer_msg(room, 0, from)));
                }
            }
        } else {
            entry.clients.retain(|c| c.addr != from);
        }
        if entry.is_empty() {
            self.rooms.remove(&room);
        }
    }

    #[cfg(test)]
    fn sizes(&self) -> (usize, usize) {
        (self.rooms.len(), self.buckets.len() + self.reg_buckets.len())
    }
}

/// `Some(v4 addr)` for IPv4 and v4-mapped IPv6 sources, `None` for real IPv6.
pub fn normalize(a: SocketAddr) -> Option<SocketAddr> {
    match a.ip() {
        IpAddr::V4(_) => Some(a),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(|v4| SocketAddr::from((v4, a.port()))),
    }
}

/// Run the signaling loop forever with the default limits.
pub async fn run_server(port: u16) -> std::io::Result<()> {
    run_server_with(port, Config::default()).await
}

/// Like [`run_server`] with explicit limits, e.g. from [`Config::from_env`].
pub async fn run_server_with(port: u16, cfg: Config) -> std::io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    log::info!("signal listening on udp://0.0.0.0:{} ({cfg:?})", port);
    serve(socket, cfg).await
}

/// Serve on an already-bound socket (tests bind to port 0).
pub async fn serve(socket: UdpSocket, cfg: Config) -> std::io::Result<()> {
    let mut state = State::new(cfg, Instant::now());
    let v6_socket = socket.local_addr().is_ok_and(|a| a.is_ipv6());
    let mut buf = [0u8; 2048];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("signal recv error: {}", e);
                continue;
            }
        };
        for (to, msg) in state.handle(&buf[..len], from, Instant::now()) {
            // A dual-stack socket needs the v4-mapped form of the v4 target.
            let to = match (v6_socket, to.ip()) {
                (true, IpAddr::V4(ip)) => SocketAddr::from((ip.to_ipv6_mapped(), to.port())),
                _ => to,
            };
            let _ = socket.send_to(&msg, to).await;
        }
    }
}

fn peer_msg(room: u32, role: u8, addr: SocketAddr) -> Vec<u8> {
    let mut out = vec![PEER];
    out.extend_from_slice(&room.to_be_bytes());
    out.push(role);
    match addr.ip() {
        IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        // The signaling channel is IPv4; IPv6 peers exchange endpoints through
        // the invite instead of through rendezvous. Empty = not sent.
        IpAddr::V6(_) => return Vec::new(),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

fn pong_msg(nonce: u32) -> Vec<u8> {
    let mut out = vec![PONG];
    out.extend_from_slice(&nonce.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_ids_are_stable_and_distinct() {
        assert_eq!(room_id("demo"), room_id("demo"));
        assert_ne!(room_id("demo"), room_id("other"));
        assert_eq!(room_for_key("abc"), room_for_key("abc"));
        assert_ne!(room_for_key("abc"), room_for_key("abd"));
        assert_ne!(room_for_key("abc"), room_id("abc"));
    }

    /// Canonical form SHA256("strait-room" || key)[0..4]; clients on every
    /// platform must agree, so this must never change silently.
    #[test]
    fn room_for_key_is_pinned() {
        assert_eq!(room_for_key("k"), 0x52b8_2d2f);
        assert_eq!(
            room_for_key("0123456789abcdef0123456789abcdef"),
            0xecff_e956
        );
    }

    #[test]
    fn register_codec() {
        let room = room_id("demo");
        assert_eq!(decode(&encode_register(room, 0)), None);
        assert_eq!(&encode_deregister(room, 1)[..1], &[0x04]);
    }

    #[test]
    fn peer_message_carries_role_and_address() {
        let room = room_id("demo");
        let addr: SocketAddr = "203.0.113.9:51820".parse().unwrap();
        assert_eq!(
            decode(&peer_msg(room, 1, addr)),
            Some(Incoming::Peer { role: 1, addr })
        );
    }

    #[test]
    fn ping_round_trips() {
        assert_eq!(decode(&pong_msg(42)), Some(Incoming::Pong(42)));
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rate_limit_and_tables_stay_bounded() {
        let t0 = Instant::now();
        let cfg = Config { rate_per_sec: 1.0, burst: 2.0, expiry: Duration::from_secs(3), max_buckets: 4, ..Config::default() };
        let mut st = State::new(cfg, t0);
        let a = sa("10.0.0.1:1000");
        let ping = encode_ping(1);
        assert_eq!(st.handle(&ping, a, t0).len(), 1);
        assert_eq!(st.handle(&ping, a, t0).len(), 1);
        assert!(st.handle(&ping, a, t0).is_empty());
        // Other IPs fill the table; extra IPs are dropped.
        for i in 2..=4 {
            st.handle(&ping, sa(&format!("10.0.0.{i}:1")), t0);
        }
        assert!(st.handle(&ping, sa("10.0.0.9:1"), t0).is_empty());
        // Idle buckets and rooms are swept.
        st.handle(&encode_register(7, 1), a, t0 + Duration::from_secs(1));
        let later = t0 + Duration::from_secs(10);
        st.handle(&ping, a, later);
        assert_eq!(st.sizes(), (0, 1));
    }

    #[test]
    fn caps_peers_per_register_and_rooms() {
        let t0 = Instant::now();
        let mut st = State::new(Config { rate_per_sec: 1e6, burst: 1e6, max_rooms: 1, ..Config::default() }, t0);
        for i in 0..20 {
            st.handle(&encode_register(1, 1), sa(&format!("10.0.1.{i}:5")), t0);
        }
        let out = st.handle(&encode_register(1, 0), sa("10.0.2.1:5"), t0);
        assert_eq!(out.len(), 2 * MAX_PEERS_PER_REGISTER);
        assert!(st.handle(&encode_register(2, 1), sa("10.0.3.1:5"), t0).is_empty());
        assert_eq!(st.sizes().0, 1);
    }

    #[test]
    fn nat_household_reregisters_while_flood_is_dropped() {
        let t0 = Instant::now();
        let mut st = State::new(Config::default(), t0);
        let nat_ip = "198.51.100.7";
        // 30 clients behind one IP, plus the host elsewhere, re-register
        // every 15 s for a minute: every REGISTER must be answered.
        st.handle(&encode_register(1, 0), sa("203.0.113.1:9"), t0);
        for round in 0..4u64 {
            let now = t0 + Duration::from_secs(15 * round);
            st.handle(&encode_register(1, 0), sa("203.0.113.1:9"), now);
            for c in 0..30 {
                let out = st.handle(&encode_register(1, 1), sa(&format!("{nat_ip}:{}", 2000 + c)), now);
                assert!(!out.is_empty(), "round {round} client {c} dropped");
            }
        }
        // A ping flood from the same IP does not consume the REGISTER budget.
        let now = t0 + Duration::from_secs(60);
        let pongs = (0..1000).filter(|i| !st.handle(&encode_ping(*i), sa(&format!("{nat_ip}:1")), now).is_empty()).count();
        assert!(pongs <= 41, "ping burst bounded, got {pongs}");
        assert!(!st.handle(&encode_register(1, 1), sa(&format!("{nat_ip}:3000")), now).is_empty());
        // A REGISTER flood from one IP is cut off at its burst.
        let mut st = State::new(Config::default(), t0);
        st.handle(&encode_register(2, 0), sa("203.0.113.1:9"), t0);
        let answered = (0..5000)
            .filter(|i| !st.handle(&encode_register(2, 1), sa(&format!("192.0.2.9:{}", 1000 + i)), t0).is_empty())
            .count();
        // reg_burst tokens, minus the host's own (different IP, own bucket).
        assert_eq!(answered, Config::default().reg_burst as usize);
    }

    #[test]
    fn global_register_cap_bounds_many_source_ips() {
        let t0 = Instant::now();
        let cfg = Config { reg_global_burst: 50.0, reg_global_rate_per_sec: 1.0, ..Config::default() };
        let mut st = State::new(cfg, t0);
        st.handle(&encode_register(3, 0), sa("203.0.113.1:9"), t0);
        let answered = (0..1000u32)
            .filter(|i| {
                let ip = format!("10.{}.{}.1:5", (i >> 8) & 255, i & 255);
                !st.handle(&encode_register(3, 1), sa(&ip), t0).is_empty()
            })
            .count();
        assert!(answered <= 50, "global cap leaked: {answered}");
    }

    #[test]
    fn ipv6_is_ignored_and_v4_mapped_is_normalised() {
        let t0 = Instant::now();
        let mut st = State::new(Config::default(), t0);
        // Real IPv6: no reply, no state (neither buckets nor rooms).
        for msg in [encode_ping(1), encode_register(1, 0), encode_register(1, 1), encode_deregister(1, 0)] {
            assert!(st.handle(&msg, sa("[2001:db8::1]:5000"), t0).is_empty());
        }
        assert_eq!(st.sizes(), (0, 0));
        // v4-mapped behaves exactly like the plain v4 address.
        let out = st.handle(&encode_ping(9), sa("[::ffff:192.0.2.5]:7"), t0);
        assert_eq!(out, vec![(sa("192.0.2.5:7"), pong_msg(9))]);
        st.handle(&encode_register(1, 0), sa("[::ffff:192.0.2.5]:7"), t0);
        let out = st.handle(&encode_register(1, 1), sa("198.51.100.1:8"), t0);
        assert!(out.contains(&(sa("198.51.100.1:8"), peer_msg(1, 0, sa("192.0.2.5:7")))));
        assert!(out.contains(&(sa("192.0.2.5:7"), peer_msg(1, 1, sa("198.51.100.1:8")))));
    }

    #[test]
    fn config_from_vars_validates() {
        let d = Config::default();
        assert_eq!(Config::from_vars(None, None, None).unwrap().rate_per_sec, d.rate_per_sec);
        let c = Config::from_vars(Some("5"), Some("10"), Some("60")).unwrap();
        assert_eq!((c.rate_per_sec, c.burst, c.expiry), (5.0, 10.0, Duration::from_secs(60)));
        assert_eq!(c.reg_burst, 30.0);
        for (r, b, e) in [
            (Some("abc"), None, None), (Some("0"), None, None), (Some("-1"), None, None), (Some("NaN"), None, None),
            (Some("inf"), None, None), (None, Some("0"), None), (None, Some(""), None), (None, None, Some("5")),
            (None, None, Some("1e9")),
        ] {
            assert!(Config::from_vars(r, b, e).is_err(), "{r:?} {b:?} {e:?}");
        }
    }
}
