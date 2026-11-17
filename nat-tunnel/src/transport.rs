//! End-to-end tunnel transport.
//!
//! Owns the UDP socket, the AEAD session, the reliable stream and signaling.
//!
//! Two ways to find the peer, both direct:
//!
//! * the invite carries the host's public `ip:port`, so the guest sends to it
//!   immediately and no third server is involved at all;
//! * the invite carries a signaling server instead, which only reports the
//!   peer's observed address (STUN-like rendezvous). The server never sees
//!   payload.
//!
//! If a direct path cannot be established (for example both peers are behind
//! symmetric NAT) the session fails instead of silently relaying data.
//!
//! # Host multiplexing
//!
//! [`MuxHost`] owns one UDP port and serves N peers, each with its own AEAD
//! session. [`Tunnel`] with `ConnectOpts::mux` is the matching client; forward
//! mode (`mux: false`, one guest, a TCP bridge) runs the same join handshake.
//!
//! Join handshake v3: Noise `NKpsk0` (see `tunnel::handshake` and
//! `docs/HANDSHAKE.md`). `base = SHA256("strait-mux-v3" || invite key)` is the
//! Noise pre-shared key and the key of the outer tag
//! `mac = HMAC-SHA256(base, ..)[..16]`:
//!
//! ```text
//! client -> host  JOIN   [F8][cn 16][Noise msg 1: e, es; payload clock | token?][mac("join", cn, msg1)]
//! host   -> client ACCEPT [F9][cn 16][Noise msg 2: e, ee; payload slot | cn | verdict][mac("accept", cn, msg2)]
//! data    [F4][slot u16][AeadSession datagram]      both directions (forward mode: no slot header)
//! host -> client sealed control ASSIGN [C0][ip 4][prefix][gateway 4]
//! either way     sealed control KEEPALIVE [C1], BYE [C2]
//! ```
//!
//! Older handshakes (F1-F3, F5-F7) have other tags and lengths and are dropped.
//!
//! Threat model:
//!
//! * The invite key is the admission capability: without it no JOIN passes the
//!   outer tag and no Noise message opens.
//! * The host is authenticated: the client encrypts message 1 to the host key
//!   the invite names (`hk`) and only its holder can produce a readable message
//!   2, so an invite holder cannot pose as the host. Refusals (full, withdrawn
//!   invite, wrong clock) are message 2 as well, so they cannot be forged.
//! * Both sides add ephemeral keys: a recording stays unreadable when the
//!   invite or the host key leaks later, and one peer cannot read another's.
//! * Replays: message 1 carries the client's clock and is refused outside
//!   `handshake::JOIN_MAX_SKEW`; inside it the host remembers `cn`s. A join holds
//!   a slot only once a packet under its session key arrives.
//! * Personal tokens (in message 1, encrypted to the host) name a guest; the
//!   host can withdraw one, or take personal invites only.
//!
//! Slots map to addresses in 10.7.0.0/16 (host 10.7.0.1, slot i -> offset i+2).
//! The host drops IPv4 packets whose source is not the sender's assigned
//! address. Idle peers get a sealed keepalive after 15 s and are evicted after
//! 60 s of silence; each peer has non-blocking token buckets (`rate_bytes`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::birthday::{Birthday, FlowBudget, ProbeTally, Scanner, Sprayer};
use crate::carrier::shared::Port;
use crate::carrier::udp::{norm as norm_addr, to_wire, UdpCarrier};
use crate::carrier::{Caps, CarrierError, CarrierId, FrameIo, Health};
pub use crate::carrier::effective_mtu;

use crate::rendezvous::{self, Rendezvous, Role, RunnerHandle, RvConfig, RvCtx, Runner, Status};

use crate::relay;
use crate::tunnel::crypto::{AeadSession, CryptoError};
use crate::tunnel::handshake;
use sha2::{Digest, Sha256};
use crate::tunnel::reliable::{self, Frame, Reliable};

const PEER_WAIT: Duration = Duration::from_secs(15);
const PUNCH_WINDOW: Duration = Duration::from_secs(4);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// Mux JOIN budget (answer + ASSIGN). A host serving hundreds of simultaneous
/// joins on a loaded machine can take seconds; past this the join fails with
/// `HostUnreachable` instead of waiting.
const MUX_JOIN_WINDOW: Duration = Duration::from_secs(8);
const REGISTER_INTERVAL: Duration = Duration::from_secs(2);
/// How long a direct host waits for the first authenticated datagram. There is
/// no signaling server to time out against, so this is the whole lobby.
const DIRECT_WAIT: Duration = Duration::from_secs(60);
/// NAT UDP mappings expire when idle; refresh well inside the usual minimum.
const STUN_POKE_INTERVAL: Duration = Duration::from_secs(15);

/// Per-endpoint punch window while other endpoints remain to be tried.
const FAMILY_WINDOW: Duration = Duration::from_millis(1500);

/// Overall time a guest spends finding and punching to a host through rendezvous methods
/// (the Mainline DHT alone needs up to ~20 s to publish and find a record).
pub const RV_BUDGET: Duration = Duration::from_secs(60);
/// A rendezvous candidate is fired at this often for its first [`RV_FAST`], then every [`RV_SLOW`].
const RV_FAST_INTERVAL: Duration = Duration::from_millis(250);
const RV_FAST: Duration = Duration::from_secs(10);
const RV_SLOW_INTERVAL: Duration = Duration::from_secs(2);
/// Fan-out sockets that fire per 50 ms tick (a full cycle of 256 takes under a second).
const FAN_BATCH: usize = 16;
/// Most punch frames the fan sends per tick in total (candidates are not trusted input).
const FAN_TICK_PACKETS: usize = 256;
/// A host stops firing at a client candidate that never joined after this long.
/// Long enough to outlast a guest's full-range port scan (`Birthday::scan_window`, 3 min): the
/// punch keeps the host's fresh NAT mapping toward the client alive for the scan to hit.
const RV_HOST_PUNCH_TOTAL: Duration = Duration::from_secs(200);
/// Candidates the birthday fan fires at (256 sockets x this = its live NAT entries).
const FAN_MAX_TARGETS: usize = 4;
const RV_MAX_TARGETS: usize = 64;
/// Distinct client addresses a host port-sprays per hour.
const SPRAY_IPS_PER_HOUR: usize = 16;
/// Distinct client IPs a host punches per hour, UDP and TCP alike, and ports per IP: any invite
/// holder can seal a client record, so this bounds what they can make the host send to. Sharing
/// again (a new invite) starts a new budget.
const PUNCH_IPS_PER_HOUR: usize = 64;
const PUNCH_PORTS_PER_IP: usize = 8;
/// Host IPs port-scanned at once (candidates are not trusted input).
const SCAN_MAX_IPS: usize = 2;
/// Source addresses of undecodable datagrams probed per attempt (see `FrameIo::take_rejected`).
const HINT_MAX: usize = 8;

/// A candidate on this side's own public IP is our own (stale) announce coming back, not the host.
/// LAN-private addresses are never "own": a host on the same LAN is reached through them.
fn is_own_announce(addr: SocketAddr, own: &[IpAddr]) -> bool {
    let ip = norm_addr(addr).ip();
    let private = match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
    };
    !private && own.contains(&ip)
}

/// Why a connection could not be set up. Distinct variants so UIs can show
/// the right advice without matching on strings.
#[derive(Debug)]
pub enum ConnectError {
    /// The invite only has IPv6 hosts and this network has no IPv6 route.
    NoIpv6Route,
    /// Every direct endpoint stayed silent.
    HostUnreachable,
    /// Signaling punch failed and this side is known to be behind a symmetric NAT.
    Symmetric,
    /// The host answered but has no free client slot.
    HostFull,
    /// The host answered and refused this invite (revoked, expired, or named guests only).
    Refused,
    /// The host refused the join because this device's clock is far off.
    Clock,
    /// The requested UDP port is already bound by another socket or process.
    PortInUse(u16),
    /// The invite lists rendezvous methods but none is usable here (all disabled or unknown).
    NoRendezvous,
    /// Rendezvous ran out of time or services. One line, `method: outcome; ...`.
    RendezvousFailed(String),
    /// Every carrier listed in the invite failed or was skipped. One line, `carrier: reason; ...`.
    CarriersFailed(String),
    Io(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoIpv6Route => f.write_str("No IPv6 on this network; the host is IPv6-only."),
            Self::HostUnreachable => {
                f.write_str("Host unreachable - check the invite or UDP reachability.")
            }
            Self::Symmetric => {
                f.write_str("Direct path unavailable - both networks are symmetric.")
            }
            Self::HostFull => f.write_str("Host is full - it has no free client slot."),
            Self::Clock => f.write_str("The host refused the connection because this device's clock is more than 10 minutes off. Set the date and time automatically and try again."),
            Self::Refused => f.write_str("The host did not accept this invite: it was withdrawn, has expired, or the host only takes personal invites."),
            Self::PortInUse(p) => write!(f, "UDP port {p} is already in use by another process."),
            Self::NoRendezvous => f.write_str(
                "None of the ways listed in the invite to find the host are available on this device.",
            ),
            Self::RendezvousFailed(s) => write!(
                f,
                "The host could not be found or reached through {s}. Check that they are sharing and that these services work from your network."
            ),
            Self::CarriersFailed(s) => {
                write!(f, "Could not connect with any of the ways listed in the invite: {s}.")
            }
            Self::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<io::Error> for ConnectError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ConnectError> for io::Error {
    fn from(e: ConnectError) -> Self {
        match e {
            ConnectError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::TimedOut, other),
        }
    }
}

impl ConnectError {
    /// Recover the typed reason from an `io::Error` returned by `Tunnel::connect`.
    pub fn from_io(e: &io::Error) -> Option<&ConnectError> {
        e.get_ref()?.downcast_ref()
    }
}

/// IPv6 first, then IPv4; order within a family is preserved.
pub fn order_endpoints(hosts: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut v = hosts.to_vec();
    v.sort_by_key(|a| a.is_ipv4());
    v.dedup();
    v
}

/// Whether this machine can route to the global IPv6 internet.
pub fn has_v6_route() -> bool {
    std::net::UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:4860:4860::8888]:53"))
        .is_ok()
}

/// Is `ip` something a remote client could use as a host address?
/// Global unicast only (2000::/3): rejects ::1, fe80::/10, fc00::/7, multicast,
/// v4-mapped. The documentation prefix 2001:db8::/32 is rejected too (never
/// routable) unless `allow_doc` is set, which tests and demos can use.
pub fn is_publishable_v6(ip: &std::net::Ipv6Addr, allow_doc: bool) -> bool {
    let s = ip.segments();
    let global = (s[0] & 0xe000) == 0x2000;
    let doc = s[0] == 0x2001 && s[1] == 0x0db8;
    global && (allow_doc || !doc)
}

/// True when a single IPv6 socket can also serve IPv4 on this host.
pub fn dual_stack_available() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        dual_socket(0).map(|(_, dual)| dual).unwrap_or(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

/// How to reach the other side. Everything here comes from the invite string.
pub struct ConnectOpts<'a> {
    /// Rendezvous service used only to exchange observed addresses. `None`
    /// means the invite already contains the host endpoint.
    pub signal: Option<SocketAddr>,
    /// Host endpoint taken from the invite (guest side only).
    pub peer: Option<SocketAddr>,
    pub room: &'a str,
    pub key: &'a str,
    /// This side is the host: it owns the listening port.
    pub host: bool,
    /// Local UDP port to bind; `None` falls back to `NAT_TUNNEL_BIND_PORT`, then ephemeral.
    pub bind_port: Option<u16>,
    /// All direct endpoints from the invite (guest side). `peer` is tried
    /// instead when it is not among them.
    pub hosts: Vec<SocketAddr>,
    /// Join a [`MuxHost`] (TUN modes) instead of a legacy 1:1 peer.
    pub mux: bool,
    /// What the invite says about the host's identity and this guest (mux joins only).
    pub auth: JoinAuth,
}

/// The security fields of an invite, as the join handshake uses them.
#[derive(Debug, Clone, Default)]
pub struct JoinAuth {
    /// The host's public key. `None`: derived from the invite key (no protection beyond the invite).
    pub host_key: Option<[u8; 32]>,
    /// This guest's personal token, sent encrypted to the host.
    pub token: Option<[u8; handshake::TOKEN_LEN]>,
    /// Host side only: the host's private key (forward mode; a full-tunnel host has it in
    /// [`MuxConfig::host_key`]). Never part of an invite.
    pub host_secret: Option<[u8; 32]>,
    /// Host side only (forward mode): which personal invites are admitted.
    pub guests: GuestPolicy,
}

impl JoinAuth {
    /// Both halves of one fixed test key, for tests and labs. Never use it for a real host.
    #[doc(hidden)]
    pub fn test() -> Self {
        Self { host_key: Some(handshake::public_of(&TEST_HOST_KEY)), host_secret: Some(TEST_HOST_KEY), ..Default::default() }
    }
}

/// The key behind [`JoinAuth::test`].
#[doc(hidden)]
pub const TEST_HOST_KEY: [u8; 32] = [0x42; 32];

/// Guest-side rendezvous inputs for [`Tunnel::connect_rv`]. `sig` is not run here: the legacy
/// inline signal path (`ConnectOpts::signal`) carries it.
#[derive(Clone, Default)]
pub struct RvJoin {
    /// Method ids listed in the invite.
    pub ids: Vec<String>,
    /// Ids this device must never use.
    pub disable: Vec<String>,
    pub cfg: RvConfig,
    /// Test hook: use these backends (filtered by `ids` and `disable`) instead of the registry.
    pub backends: Option<Vec<Arc<dyn Rendezvous>>>,
    /// Overall budget; `None` = [`RV_BUDGET`].
    pub budget: Option<Duration>,
    /// Do not add a global IPv6 candidate (tests).
    pub no_v6: bool,
    /// Birthday-paradox fan-out against a symmetric NAT on this side.
    pub birthday: Birthday,
}

impl RvJoin {
    /// The backends that will run: listed, not disabled, known, and not `sig`.
    pub fn usable(&self) -> Vec<Arc<dyn Rendezvous>> {
        let mut v = match &self.backends {
            Some(b) => b
                .iter()
                .filter(|b| self.ids.is_empty() || self.ids.iter().any(|i| i == b.id()))
                .cloned()
                .collect(),
            None => rendezvous::by_ids(&self.ids, &self.cfg),
        };
        v.retain(|b| b.id() != "sig" && !self.disable.iter().any(|d| d == b.id()));
        v
    }
}

/// Host-side rendezvous settings for [`MuxConfig::rv`].
#[derive(Clone, Default)]
pub struct RvHost {
    /// Methods the host chose (`sig` is ignored: it stays on the inline signal path).
    pub ids: Vec<String>,
    pub cfg: RvConfig,
    /// Test hook: use these backends instead of the registry.
    pub backends: Option<Vec<Arc<dyn Rendezvous>>>,
    pub no_v6: bool,
}

impl std::fmt::Debug for RvHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RvHost").field("ids", &self.ids).finish_non_exhaustive()
    }
}

/// STUN servers to ask: `STUN_SERVER[:STUN_PORT]` when set (port default 3478, as the legacy
/// keepalive), else the first three public defaults.
async fn stun_servers() -> Vec<SocketAddr> {
    if let Ok(host) = std::env::var("STUN_SERVER") {
        let port = std::env::var("STUN_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(3478);
        return crate::tunnel::stun::resolve(&host, port).await.into_iter().collect();
    }
    let entries: Vec<String> =
        crate::tunnel::stun::DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect();
    let mut v = crate::tunnel::stun::resolve_servers(&entries).await;
    v.truncate(3);
    v
}

/// This machine's global IPv6 source address, if it routes IPv6 (nothing is sent).
fn global_v6() -> Option<std::net::Ipv6Addr> {
    let s = std::net::UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:4860:4860::8888]:53").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(a) if is_publishable_v6(&a, false) => Some(a),
        _ => None,
    }
}

/// Keeps the published per-method status board (`rendezvous::live`) current for one runner.
fn spawn_publisher(session: &'static str, h: &RunnerHandle) -> JoinHandle<()> {
    let mut w = h.status_watch();
    tokio::spawn(async move {
        loop {
            let s = w.borrow_and_update().clone();
            rendezvous::live::publish(session, s);
            if w.changed().await.is_err() {
                break;
            }
        }
    })
}

/// What the guest's punch loop did, for an accurate failure line.
#[derive(Default)]
struct WaitStats {
    /// Usable host candidates fired at.
    tried: usize,
    punched: Duration,
    /// Candidates dropped because their address family cannot route from here.
    skipped_v6: usize,
}

/// Can this machine send to `addr`? IPv4 always; IPv6 only with a route (loopback for tests).
pub fn usable_family(addr: SocketAddr, v6_route: bool) -> bool {
    addr.is_ipv4() || v6_route || addr.ip().is_loopback()
}

/// `trk: blocked; dht: found the host but could not connect (punched 60 s at 2 addresses, no answer)`
fn rv_summary(st: &[(&'static str, Status)], w: &WaitStats) -> String {
    st.iter()
        .map(|(id, s)| {
            let what = match s {
                Status::Blocked(_) => "blocked".to_string(),
                Status::Failed(_) => "failed".to_string(),
                Status::GotPeer(_) if w.tried == 0 && w.skipped_v6 > 0 => format!(
                    "found the host but could not connect (only IPv6 addresses, and this network has no IPv6; {} skipped)",
                    w.skipped_v6
                ),
                Status::GotPeer(_) => format!(
                    "found the host but could not connect (punched {} s at {} address{}, no answer)",
                    w.punched.as_secs(),
                    w.tried,
                    if w.tried == 1 { "" } else { "es" }
                ),
                _ => "no peer found".to_string(),
            };
            format!("{id}: {what}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Next datagram on any fan-out socket: (index, result). Pending while none is readable.
async fn fan_recv(fan: &[Arc<dyn FrameIo>], buf: &mut [u8]) -> (usize, io::Result<(usize, SocketAddr)>) {
    loop {
        let (r, i, _) = futures::future::select_all(fan.iter().map(|s| s.readable())).await;
        if r.is_err() {
            return (i, Err(io::ErrorKind::Other.into()));
        }
        match fan[i].try_recv_from(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            r => return (i, r),
        }
    }
}

/// One peer endpoint being fired at: first seen, last sent.
struct Target {
    addr: SocketAddr,
    /// Reported by a signed host record (see `Candidate::verified`): only these are scanned.
    verified: bool,
    first: Instant,
    last: Option<Instant>,
}

impl Target {
    fn due(&self, now: Instant) -> bool {
        let every = if now.duration_since(self.first) < RV_FAST { RV_FAST_INTERVAL } else { RV_SLOW_INTERVAL };
        self.last.is_none_or(|l| now.duration_since(l) >= every)
    }
}

/// Whether `addr`, learned from a rendezvous method or a signal server, may be fired at.
///
/// Those sources are not trusted (a tracker returns whatever was announced), and peers only ever
/// publish their public STUN mapping or a global IPv6 address. Anything else would aim this
/// machine's packets at its own LAN, at loopback or at a broadcast address, so it is dropped.
/// `NAT_TUNNEL_RV_ALLOW_LOCAL=1` (or `STRAIT_RV_ALLOW_LOCAL=1`) admits private and loopback
/// addresses again, for labs and overlay networks.
pub fn candidate_ok(addr: SocketAddr) -> bool {
    static LOCAL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let local = *LOCAL.get_or_init(|| {
        ["NAT_TUNNEL_RV_ALLOW_LOCAL", "STRAIT_RV_ALLOW_LOCAL"].iter().any(|k| std::env::var(k).is_ok_and(|v| v == "1"))
    });
    candidate_allowed(addr, local)
}

fn candidate_allowed(addr: SocketAddr, local: bool) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match norm_addr(addr).ip() {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            let never = v.is_unspecified() || v.is_multicast() || v.is_broadcast() || o[0] == 0 || o[0] >= 240;
            let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
            !never && (local || !(v.is_loopback() || v.is_private() || v.is_link_local() || cgnat))
        }
        std::net::IpAddr::V6(v) => {
            let s0 = v.segments()[0];
            let never = v.is_unspecified() || v.is_multicast();
            let (link_local, ula) = (s0 & 0xffc0 == 0xfe80, s0 & 0xfe00 == 0xfc00);
            !never && (local || !(v.is_loopback() || link_local || ula))
        }
    }
}

/// True when the answer `m` may be trusted: two servers report its IP, or only one is configured.
fn stun_agreed(votes: &HashMap<SocketAddr, SocketAddr>, m: SocketAddr, servers: usize) -> bool {
    servers <= 1 || votes.values().filter(|v| v.ip() == m.ip()).count() >= 2
}

/// Most targets only an unsigned source reported, kept at once.
const RV_MAX_UNVERIFIED: usize = 8;

fn add_target(targets: &mut Vec<Target>, addr: SocketAddr, verified: bool) {
    if !candidate_ok(addr) {
        log::debug!("rendezvous: candidate {addr} is not a public address; ignored");
        return;
    }
    if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
        t.verified |= verified; // a signed record confirms what an unsigned source said first
        return;
    }
    // Unsigned entries (tracker peers, a bare punch byte) are few and rotate among themselves:
    // spoofed ones cannot make the guest send JOINs to many addresses.
    if !verified && targets.iter().filter(|t| !t.verified).count() >= RV_MAX_UNVERIFIED {
        if let Some(i) = targets.iter().position(|t| !t.verified) {
            targets.remove(i);
        }
    }
    // Full: the oldest unverified entry gives way; a flood of unsigned records never pushes out a
    // signed one, and an unsigned newcomer does not get in at all once only signed ones are left.
    if targets.len() >= RV_MAX_TARGETS {
        match targets.iter().position(|t| !t.verified) {
            Some(i) => {
                targets.remove(i);
            }
            None if !verified => return,
            None => {
                targets.remove(0);
            }
        }
    }
    targets.push(Target { addr, verified, first: Instant::now(), last: None });
}

#[derive(Debug)]
pub enum Event {
    Data(Vec<u8>),
    /// The peer closed the stream (or gave up retransmitting).
    Closed,
}

pub struct Tunnel {
    /// The carrier every sealed frame goes through (raw UDP unless a ladder attempt supplied one).
    io: Arc<dyn FrameIo>,
    /// The raw UDP socket is an IPv6 socket that also accepts IPv4 (v4-mapped): STUN only.
    dual: bool,
    /// Frames the carrier refused as too large (never silent: counted and logged, rate-limited).
    oversize: DropCount,
    crypto: AeadSession,
    reliable: Reliable,
    /// Rendezvous service, when the invite names one. `None` is the pure
    /// peer-to-peer case: no third server participates.
    signal: Option<SocketAddr>,
    room: u32,
    /// The invite key when `room` derives from it: the room changes with the UTC day.
    room_key: Option<String>,
    role: u8,
    peer: Option<SocketAddr>,
    punched: bool,
    last_register: Instant,
    /// Frames decrypted during the punch window, replayed into the reliable
    /// stream once the session starts. Discarding them lost `Bye` frames and
    /// left the old session alive.
    pending: VecDeque<Vec<u8>>,
    /// Payloads delivered by the ARQ but not yet returned as events.
    ready: VecDeque<Vec<u8>>,
    /// TUN mode: carry each IP packet as one sealed datagram, no ARQ. The
    /// inner TCP stack handles loss and ordering; adding reliability on top
    /// doubles retransmissions and adds head-of-line blocking.
    packet_mode: bool,
    /// Tunnel wire bytes (ciphertext) sent and received in this session.
    sent_bytes: u64,
    received_bytes: u64,
    /// A public STUN server used to keep the host's NAT mapping alive when no
    /// signaling server is involved.
    stun: Option<SocketAddr>,
    last_stun_poke: Instant,
    /// The client's side of the join handshake (full-tunnel and forward mode alike).
    mux: Option<MuxClient>,
    /// Forward-mode host: the host's side of the join handshake.
    fwd_host: Option<FwdHost>,
    /// Forward-mode host: a handshake answer waiting to be sent.
    reply: Option<Vec<u8>>,
    /// Forward-mode host: a new session replaced the previous guest's (see `take_replaced`).
    replaced: bool,
}

/// A guest's invite must name a usable host key: without one the host cannot be authenticated.
pub fn check_host_key(auth: &JoinAuth) -> Result<(), &'static str> {
    match auth.host_key {
        None => Err(NO_HOST_KEY),
        Some(hk) if !handshake::valid_public(&hk) => Err(BAD_HOST_KEY),
        Some(_) => Ok(()),
    }
}

pub(crate) const BAD_HOST_KEY: &str = "this invite's host key (hk=) is not a valid key: the invite is damaged. Ask the host for a new invite";
pub(crate) const NO_HOST_KEY: &str =
    "this invite has no host key (hk=): it cannot prove who the host is. Ask the host for a new invite";
/// A client renews its JOIN (new clock, new nonce) after this long.
const JOIN_RENEW: Duration = Duration::from_secs(240);

/// Forward mode (one guest): the host's side of the join handshake.
struct FwdHost {
    base: [u8; 32],
    key: [u8; 32],
    token_key: [u8; 32],
    joined: bool,
    /// The JOIN of the current session and the answer it got (repeated for a retried JOIN).
    cur: Option<([u8; 16], Vec<u8>)>,
    /// Where the current session's guest is, and when it was last heard from.
    guest: Option<(SocketAddr, Instant)>,
    /// Ephemeral keys of JOINs already read (see [`join_epk`]), oldest first in `seen_order`.
    seen: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    /// When this host started (Unix seconds): see [`handshake::fresh_since`].
    started: u32,
    guests: GuestPolicy,
    limit: JoinLimit,
}

/// Forward mode serves one guest: while its session is live (heard from within this time), a
/// JOIN from another address is refused as full instead of taking the session over.
const FWD_TAKEOVER_AFTER: Duration = Duration::from_secs(30);
/// A forward-mode guest's keepalive while its stream is idle (well inside `FWD_TAKEOVER_AFTER`).
const FWD_KEEPALIVE: Duration = Duration::from_secs(10);

impl FwdHost {
    fn new(invite_key: &str, key: Option<[u8; 32]>, guests: GuestPolicy) -> Self {
        let key = key.unwrap_or([0; 32]); // checked by the caller: a host always has one
        Self {
            base: mux_base(invite_key),
            token_key: handshake::token_key(&key, invite_key),
            key,
            joined: false,
            cur: None,
            guest: None,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            started: handshake::now_secs(),
            guests,
            limit: JoinLimit::default(),
        }
    }

    /// An authenticated packet of the current session arrived from `from`.
    fn heard(&mut self, from: SocketAddr) {
        self.guest = Some((from, Instant::now()));
    }

    /// Answer a JOIN from `from`: `(datagram to send back, session key when a new session starts)`.
    fn join(&mut self, d: &[u8], from: SocketAddr) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
        let (cn, msg1) = split_join(&self.base, d)?;
        if let Some((c, accept)) = &self.cur {
            if *c == cn {
                // A retry gets the same answer, only where the session's guest is: never reflected
                // at another address.
                return self.guest.is_some_and(|(at, _)| at == from).then(|| (accept.clone(), None));
            }
        }
        let epk = join_epk(&msg1);
        if self.seen.contains(&epk) || !self.limit.allow(from) {
            return None;
        }
        let (hs, payload) = handshake::HostHs::read(&self.base, &self.key, &msg1).ok()?;
        // Remembered before any verdict: a recorded JOIN, fresh or stale, costs one key exchange.
        // Oldest forgotten first, never all at once (that would reopen every recorded JOIN).
        if self.seen.insert(epk) {
            self.seen_order.push_back(epk);
            if self.seen_order.len() > SEEN_CN_CAP {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
        let (ts, token) = handshake::parse_join_payload(&payload)?;
        let now = handshake::now_secs();
        // Another address, not only another IP: guests behind one carrier-grade NAT share an IP. A
        // restarted guest that comes back on a new port waits out the 30 s like anyone else.
        let live = self.guest.is_some_and(|(at, when)| at != from && when.elapsed() < FWD_TAKEOVER_AFTER);
        let verdict = if !handshake::fresh_since(ts, now, self.started) {
            VERDICT_CLOCK
        } else if token.is_empty() {
            if self.guests.require_token.load(Ordering::Relaxed) { VERDICT_REFUSED } else { VERDICT_OK }
        } else {
            match handshake::verify(&self.token_key, token, now) {
                Ok(t) if !self.guests.revoked.lock().unwrap().contains(&t.id) => {
                    if self.limit.allow_invite(t.id) { VERDICT_OK } else { return None }
                }
                _ => VERDICT_REFUSED,
            }
        };
        let verdict = if verdict == VERDICT_OK && live { VERDICT_FULL } else { verdict };
        let (msg2, key) = hs.write(&verdict_payload(0, &cn, verdict)).ok()?;
        let dgram = accept_dgram(&self.base, &cn, &msg2);
        if verdict != VERDICT_OK {
            log::info!("refused a forward-mode join from {from} ({})", match verdict {
                VERDICT_CLOCK => "stale: clock off by more than 10 minutes, or made before this host started",
                VERDICT_FULL => "another guest's session is live",
                _ => "this invite is not admitted",
            });
            return Some((dgram, None));
        }
        self.cur = Some((cn, dgram.clone()));
        self.guest = Some((from, Instant::now()));
        self.joined = true;
        Some((dgram, Some(key)))
    }
}

impl Tunnel {
    /// Reach the other peer using only what the invite contains.
    ///
    /// Order of preference:
    /// 1. a direct endpoint from the invite (no server of any kind);
    /// 2. the signaling server, if the invite names one;
    /// 3. as a host with neither, just wait on the already-bound port.
    pub async fn connect(opts: ConnectOpts<'_>) -> io::Result<Self> {
        let mut hosts = opts.hosts.clone();
        if let Some(p) = opts.peer {
            if !hosts.contains(&p) {
                hosts = vec![p];
            }
        } else {
            hosts.clear();
        }
        Ok(Self::connect_ladder(opts, &hosts, has_v6_route(), false).await?)
    }

    /// [`Self::connect`] plus rendezvous methods: after the invite's direct endpoints (if any)
    /// stay silent, find the host through `rv` and punch toward every endpoint they report.
    pub async fn connect_rv(opts: ConnectOpts<'_>, rv: RvJoin) -> Result<Self, ConnectError> {
        let mut hosts = opts.hosts.clone();
        if let Some(p) = opts.peer {
            if !hosts.contains(&p) {
                hosts = vec![p];
            }
        } else {
            hosts.clear();
        }
        Self::connect_ladder_rv(opts, &hosts, has_v6_route(), false, Some(rv)).await
    }

    /// Full path ladder. `hosts` are the invite's direct endpoints (any order,
    /// they are sorted IPv6-first); `opts.peer` is ignored. `v6_route` says
    /// whether this machine can reach global IPv6 (inject it in tests);
    /// `symmetric_hint` is true only when the caller measured a symmetric NAT
    /// on this side, which lets a failed punch be reported as such.
    pub async fn connect_ladder(
        opts: ConnectOpts<'_>,
        hosts: &[SocketAddr],
        v6_route: bool,
        symmetric_hint: bool,
    ) -> Result<Self, ConnectError> {
        Self::connect_ladder_rv(opts, hosts, v6_route, symmetric_hint, None).await
    }

    /// [`Self::connect_ladder`] with optional rendezvous methods (guest side only).
    pub async fn connect_ladder_rv(
        opts: ConnectOpts<'_>,
        hosts: &[SocketAddr],
        v6_route: bool,
        symmetric_hint: bool,
        rv: Option<RvJoin>,
    ) -> Result<Self, ConnectError> {
        Self::connect_inner(opts, hosts, v6_route, symmetric_hint, rv, None).await
    }

    /// [`Self::connect_ladder_rv`] over a carrier the caller built (a ladder attempt, a test link).
    /// `hosts` are the peer keys the carrier understands (its resolved endpoint). Signaling and
    /// rendezvous run only when the carrier is punchable; the legacy `signal` server only on raw UDP.
    pub async fn connect_with_io(
        opts: ConnectOpts<'_>,
        hosts: &[SocketAddr],
        v6_route: bool,
        symmetric_hint: bool,
        rv: Option<RvJoin>,
        io: Arc<dyn FrameIo>,
    ) -> Result<Self, ConnectError> {
        Self::connect_inner(opts, hosts, v6_route, symmetric_hint, rv, Some(io)).await
    }

    async fn connect_inner(
        opts: ConnectOpts<'_>,
        hosts: &[SocketAddr],
        v6_route: bool,
        symmetric_hint: bool,
        rv: Option<RvJoin>,
        io: Option<Arc<dyn FrameIo>>,
    ) -> Result<Self, ConnectError> {
        let mux = opts.mux && !opts.host;
        let mut tunnel = Self::ladder(opts, hosts, v6_route, symmetric_hint, rv, io).await?;
        if mux {
            tunnel.await_assign().await?;
        }
        Ok(tunnel)
    }

    async fn ladder(
        opts: ConnectOpts<'_>,
        hosts: &[SocketAddr],
        v6_route: bool,
        symmetric_hint: bool,
        rv: Option<RvJoin>,
        io: Option<Arc<dyn FrameIo>>,
    ) -> Result<Self, ConnectError> {
        // An invite without the host's key cannot authenticate the host: refuse it outright.
        let host_secret = match (opts.host, opts.auth.host_key, opts.auth.host_secret) {
            (false, _, _) => {
                check_host_key(&opts.auth).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                None
            }
            (true, _, Some(k)) => Some(k),
            (true, _, None) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "the host needs its host key").into()),
        };
        let mut peers = order_endpoints(hosts);
        let had_v6 = peers.iter().any(|a| a.is_ipv6());
        // Never wait out a punch window on a family that cannot route.
        peers.retain(|a| a.is_ipv4() || v6_route || a.ip().is_loopback());
        let (io, dual): (Arc<dyn FrameIo>, bool) = match io {
            Some(io) => {
                let dual = io.udp().and_then(|u| u.local_addr().ok()).is_some_and(|a| a.is_ipv6());
                (io, dual)
            }
            None => {
                let bind_port = opts.bind_port.or_else(|| {
                    std::env::var("NAT_TUNNEL_BIND_PORT")
                        .ok()
                        .and_then(|v| v.parse::<u16>().ok())
                });
                let (socket, dual) = bind_marked(bind_port).await?;
                (Arc::new(UdpCarrier::from_socket(socket, dual)), dual)
            }
        };
        let caps = io.caps();
        // The legacy 1:1 mode seals ARQ frames of up to MAX_PAYLOAD + 5 bytes; a smaller carrier
        // would refuse them, so it is rejected here instead of stalling later.
        if !opts.mux && caps.max_frame < LEGACY_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the {} carrier moves frames of at most {} bytes; the forward mode needs {LEGACY_FRAME} (use the TUN mode)",
                    caps.id, caps.max_frame
                ),
            )
            .into());
        }
        // Signaling and rendezvous speak to servers over the raw socket and read the answers
        // from it: only a punchable carrier can, and the legacy signal server only on plain UDP.
        let signal = opts.signal.filter(|_| caps.id == CarrierId::Udp);
        let rv = rv.filter(|_| caps.punchable);
        let rv_listed = !opts.host && rv.as_ref().is_some_and(|r| !r.ids.is_empty());
        let rv_backends = if opts.host { Vec::new() } else { rv.as_ref().map(RvJoin::usable).unwrap_or_default() };
        if peers.is_empty() && had_v6 && signal.is_none() && rv_backends.is_empty() {
            return Err(ConnectError::NoIpv6Route);
        }
        let mut tunnel = Self {
            io,
            dual,
            oversize: DropCount::default(),
            // Replaced by the handshake's key; nothing is ever sealed or opened under this one.
            crypto: AeadSession::from_key(&handshake::new_host_key(), opts.host),
            reliable: Reliable::new(),
            signal,
            room: if opts.room.is_empty() {
                // No room in the invite: derive it from the shared key so the
                // string stays short and the room cannot be guessed.
                relay::room_for_key(opts.key)
            } else {
                relay::room_id(opts.room)
            },
            room_key: opts.room.is_empty().then(|| opts.key.to_string()),
            role: if opts.host { 0 } else { 1 },
            peer: None,
            punched: false,
            last_register: Instant::now(),
            pending: VecDeque::new(),
            ready: VecDeque::new(),
            packet_mode: false,
            sent_bytes: 0,
            received_bytes: 0,
            stun: None,
            last_stun_poke: Instant::now(),
            // Every guest joins through the Noise handshake; forward mode just skips the slot header.
            mux: (!opts.host).then(|| MuxClient::new(opts.key, opts.auth.clone(), !opts.mux)),
            fwd_host: opts.host.then(|| FwdHost::new(opts.key, host_secret, opts.auth.guests.clone())),
            reply: None,
            replaced: false,
        };

        // A host with a public endpoint keeps its own NAT mapping open by
        // poking a public STUN server. No payload and no state go through it.
        if opts.host && signal.is_none() && tunnel.io.udp().is_some() && caps.punchable {
            let host = std::env::var("STUN_SERVER").unwrap_or_else(|_| "stun.l.google.com".into());
            let port = std::env::var("STUN_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(3478);
            match crate::tunnel::stun::resolve(&host, port).await {
                Ok(server) => {
                    if let Some(sock) = tunnel.io.udp() {
                        let _ = crate::tunnel::stun::poke(sock, tunnel.wire(server)).await;
                    }
                    tunnel.stun = Some(server);
                    tunnel.last_stun_poke = Instant::now();
                    log::info!("keeping NAT mapping alive via STUN {}", server);
                }
                Err(e) => log::debug!("no STUN keepalive: {e}"),
            }
        }

        let n = peers.len();
        for (i, peer) in peers.iter().enumerate() {
            // Only the last endpoint gets the full window.
            let window = if i + 1 == n { PUNCH_WINDOW } else { FAMILY_WINDOW };
            if tunnel.punch_direct(*peer, window).await.is_ok() {
                return Ok(tunnel);
            }
            if let Some(e) = tunnel.reject_error() {
                return Err(e);
            }
            log::debug!("endpoint {peer} did not answer");
        }
        if !rv_backends.is_empty() {
            let Some(key) = rendezvous::derive::parse_key(opts.key) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "rendezvous methods need a 32-hex-character invite key",
                )
                .into());
            };
            let rv = rv.as_ref().expect("backends imply rv");
            tunnel.rv_phase(rv, rv_backends, key, symmetric_hint, v6_route).await?;
            return Ok(tunnel);
        }
        if n > 0 && tunnel.signal.is_none() {
            return Err(ConnectError::HostUnreachable);
        }

        if tunnel.signal.is_some() {
            tunnel.discover_peer().await?;
            if let Err(e) = tunnel.punch().await {
                if let Some(e) = tunnel.reject_error() {
                    return Err(e);
                }
                return Err(if symmetric_hint {
                    ConnectError::Symmetric
                } else {
                    e.into()
                });
            }
        } else if opts.host {
            tunnel.await_peer().await?;
        } else if rv_listed {
            return Err(ConnectError::NoRendezvous);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invite contains no host endpoint and no signaling server",
            )
            .into());
        }
        Ok(tunnel)
    }

    /// My reachable endpoints as the punch socket looks from outside: the STUN-mapped IPv4 plus a
    /// global IPv6 on the same port. Empty when STUN stays silent.
    /// The flag says the STUN servers saw this socket under different ports (symmetric NAT).
    async fn rv_local(&self, no_v6: bool) -> (Vec<SocketAddr>, bool) {
        let mut out = Vec::new();
        let mut symmetric = false;
        let servers: Vec<SocketAddr> = stun_servers().await.into_iter().map(|s| self.wire(s)).collect();
        let Some(sock) = self.io.udp() else {
            // A carrier with a socket of its own that it keeps reading (ss): it taps the answers.
            let seen = self.io.stun_mapped(&servers, Duration::from_millis(1500)).await;
            if let Some(first) = seen.first() {
                out.push(*first);
                symmetric = seen.iter().any(|m| m != first);
            }
            return (out, symmetric);
        };
        let samples = crate::tunnel::stun::survey(sock, &servers, Duration::from_millis(1500)).await;
        if let Some(m) = samples.first() {
            out.push(m.mapped);
            symmetric = samples.iter().any(|x| x.mapped != m.mapped);
        }
        if !no_v6 && self.dual {
            if let (Some(v6), Ok(a)) = (global_v6(), sock.local_addr()) {
                out.push(SocketAddr::new(v6.into(), a.port()));
            }
        }
        (out, symmetric)
    }

    /// Guest side of rendezvous: announce my mapped endpoint through `backends` and fire at every
    /// host endpoint they (or the legacy signal server) report until one answers. The runner stays
    /// announced for the whole wait, so the host can learn about me and fire back, and is cancelled
    /// (backends clean up) on every exit.
    async fn rv_phase(
        &mut self,
        rv: &RvJoin,
        backends: Vec<Arc<dyn Rendezvous>>,
        key: [u8; 16],
        symmetric_hint: bool,
        v6_route: bool,
    ) -> Result<(), ConnectError> {
        let (local, local_symmetric) = self.rv_local(rv.no_v6).await;
        if local.is_empty() {
            return Err(ConnectError::RendezvousFailed("stun: no answer (UDP or STUN appears blocked on this network; try a TCP carrier such as ws if the invite lists one)".into()));
        }
        let own_ips: Vec<IpAddr> = local.iter().map(|a| norm_addr(*a).ip()).collect();
        let hk = self.mux.as_ref().and_then(|m| m.auth.host_key);
        let mut handle = Runner::new(backends).start(RvCtx::new(key, Role::Client, local).with_keys(None, hk));
        let publisher = spawn_publisher("guest", &handle);
        let mut stats = WaitStats::default();
        // An explicit budget is a hard limit; only the default one stretches to let a scan finish.
        let mut bd = rv.birthday.clone();
        if rv.budget.is_some() {
            bd.scan_window = Duration::ZERO;
        }
        let r = self.rv_wait(&mut handle, rv.budget.unwrap_or(RV_BUDGET), v6_route, &bd, local_symmetric, &own_ips, &mut stats).await;
        let status = handle.status();
        publisher.abort();
        rendezvous::live::publish("guest", status.clone());
        tokio::spawn(handle.stop());
        match r {
            Err(ConnectError::RendezvousFailed(_)) => {
                let found = status.iter().any(|(_, s)| matches!(s, Status::GotPeer(_)));
                Err(if found && symmetric_hint {
                    ConnectError::Symmetric
                } else {
                    ConnectError::RendezvousFailed(rv_summary(&status, &stats))
                })
            }
            other => other,
        }
    }

    /// Returns `Err(RendezvousFailed(""))` when time or services ran out (the caller fills in why).
    async fn rv_wait(
        &mut self,
        h: &mut RunnerHandle,
        budget: Duration,
        v6_route: bool,
        bd: &Birthday,
        local_symmetric: bool,
        own_ips: &[IpAddr],
        stats: &mut WaitStats,
    ) -> Result<(), ConnectError> {
        let t0 = Instant::now();
        let mut deadline = t0 + budget;
        let mut targets: Vec<Target> = Vec::new();
        let mut done = false;
        let mut last_register = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buf = [0u8; 2048];
        let mut fan_buf = [0u8; 2048];
        // Birthday fan-out: extra sockets when the single-socket punch stays silent.
        let mut fan: Vec<Arc<dyn FrameIo>> = Vec::new();
        let mut fan_cursor = 0usize;
        let mut fan_done = !(bd.enabled && bd.fan > 0 && self.io.caps().punchable);
        let mut first_target: Option<Instant> = None;
        // Port scan of a symmetric host's destination ports (see `birthday::Scanner`).
        // Not from behind a symmetric NAT: every probed port would cost a NAT mapping of its own
        // (a CGNAT's per-subscriber port quota, a small router's flow table).
        let scan_on = bd.enabled && bd.scan_pps > 0 && bd.scan_passes > 0 && self.io.caps().punchable && !local_symmetric;
        if local_symmetric {
            log::info!("this side's NAT is symmetric: no port scan of the host (a sweep would open one NAT mapping per port)");
        }
        let mut scans: Vec<Scanner> = Vec::new();
        let mut scan_last = Instant::now();
        let mut scan_budget = FlowBudget::new(bd.scan_cap());
        let mut tally = ProbeTally::default();
        let mut scan_sweep = 0usize;
        let mut scan_tick = tokio::time::interval(Duration::from_millis(10));
        scan_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut scan_started: Option<Instant> = None;
        let mut scan_stage = 0usize;
        // Sources of datagrams the carrier codec rejected (the host's plain punch, for ss / awg).
        let mut hints: Vec<SocketAddr> = Vec::new();
        if self.signal.is_some() {
            let _ = self.register().await;
        }
        loop {
            if let Some(e) = self.reject_error() {
                return Err(e);
            }
            stats.tried = targets.len();
            stats.punched = t0.elapsed();
            if Instant::now() >= deadline && tally.sent + tally.failed > 0 {
                log::info!("birthday scan: gave up after {} probes sent ({} sends failed) in {:.0}s", tally.sent, tally.failed, t0.elapsed().as_secs_f32());
            }
            if Instant::now() >= deadline || (done && targets.is_empty() && self.signal.is_none()) {
                return Err(ConnectError::RendezvousFailed(String::new()));
            }
            tokio::select! {
                c = h.next(), if !done => match c {
                    Some(c) if !usable_family(c.addr, v6_route) => {
                        // stays on the status board, but never costs a punch window
                        log::debug!("rendezvous: host candidate {} via {} skipped (no IPv6 route)", c.addr, c.via);
                        stats.skipped_v6 += 1;
                    }
                    Some(c) if is_own_announce(c.addr, own_ips) => {
                        log::info!("rendezvous: ignoring own announce {} via {} (a stale record of a previous run with this key)", c.addr, c.via);
                    }
                    Some(c) => {
                        log::debug!("rendezvous: host candidate {} via {}", c.addr, c.via);
                        add_target(&mut targets, c.addr, c.verified);
                        first_target.get_or_insert_with(Instant::now);
                    }
                    None => done = true,
                },
                (i, r) = fan_recv(&fan, &mut fan_buf), if !fan.is_empty() => {
                    if let Ok((len, from)) = r {
                        if let Ok((plain, restarted)) = self.open_dgram(&fan_buf[..len], from) {
                            let from = norm_addr(from);
                            if restarted {
                                self.reset_stream();
                            }
                            self.pending.push_back(plain);
                            self.learn_direct(from);
                            // This socket's external port is the one the host's filter let through.
                            self.io = fan.swap_remove(i);
                            log::info!("direct path open to {from} (rendezvous, birthday socket {i} of {})", fan.len() + 1);
                            return Ok(());
                        }
                    }
                }
                r = self.recv_from(&mut buf) => match r {
                    Ok((len, from)) if Some(from) == self.signal => {
                        if let Some(relay::Incoming::Peer { addr, .. }) = relay::decode_for(self.room, &buf[..len]) {
                            add_target(&mut targets, addr, false);
                        }
                    }
                    // A host behind a symmetric NAT fires its 1-byte punch from a port nobody announced.
                    // That source is only a place to send our (authenticated) JOIN to; the path is
                    // adopted when a sealed ACCEPT comes back from there, never on this hint.
                    Ok((1, from)) if self.mux.is_some() && buf[0] == T_PUNCH => {
                        add_target(&mut targets, norm_addr(from), false);
                    }
                    Ok((len, from)) => {
                        // The AEAD tag authenticates the sender, wherever the NAT says it is.
                        match self.open_dgram(&buf[..len], from) {
                            Ok((plain, restarted)) => {
                                if restarted {
                                    self.reset_stream();
                                }
                                self.pending.push_back(plain);
                                self.learn_direct(from);
                                let scanned = scans.iter().any(|s| IpAddr::V4(s.ip) == from.ip()) && !targets.iter().any(|t| t.addr == from);
                                log::info!("direct path open to {from} (rendezvous{})", if scanned { ", found by port scan" } else { "" });
                                return Ok(());
                            }
                            Err(CryptoError::Replay) if Some(from) == self.peer => {
                                self.learn_direct(from);
                                return Ok(());
                            }
                            Err(_) => {}
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(e) => return Err(e.into()),
                },
                // Probes go out in 10 ms slices, not one burst per 50 ms tick.
                _ = scan_tick.tick(), if !scans.is_empty() => {
                    let dt = scan_last.elapsed().min(Duration::from_millis(250));
                    scan_last = Instant::now();
                    let live = scans.iter().filter(|s| !s.done()).count();
                    if let (Some(frame), true) = (self.punch_frame(), live > 0) {
                        let sweep = scans.iter().map(|s| s.sweeps()).min().unwrap_or(0);
                        let (stage, pps, cap) = bd.scan_stage(scan_started.map_or(Duration::ZERO, |t| t.elapsed()), sweep);
                        if stage != scan_stage {
                            scan_stage = stage;
                            scan_budget.set_cap(cap);
                            log::info!("birthday scan: no answer yet, raising to {pps} packets/s (at most ~{} NAT entries alive)", cap.min(scans[0].pass_len()));
                        }
                        if sweep != scan_sweep {
                            scan_sweep = sweep;
                            log::info!("birthday scan: sweep {sweep} done after {} probes ({} sends failed), starting sweep {} at {pps} packets/s in a fresh port order", tally.sent, tally.failed, sweep + 1);
                        }
                        let want = (pps as f64 * dt.as_secs_f64()).ceil() as usize;
                        let n = scan_budget.take(Instant::now(), want).div_ceil(live);
                        for k in 0..scans.len() {
                            let was_live = !scans[k].done();
                            for port in scans[k].next(n) {
                                let to = SocketAddr::new(scans[k].ip.into(), port);
                                let r = self.io.send_probe(&frame, self.wire(to)).await;
                                tally.note(to, r);
                            }
                            if was_live && scans[k].done() {
                                log::info!("birthday scan: host {} gave up after {} sweeps ({} probes sent, {} sends failed)", scans[k].ip, bd.scan_passes, tally.sent, tally.failed);
                            }
                        }
                    }
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    for a in self.io.take_rejected() {
                        let a = norm_addr(a);
                        let from_candidate = targets.iter().any(|t| t.verified && norm_addr(t.addr).ip() == a.ip());
                        if from_candidate && hints.len() < HINT_MAX && !hints.contains(&a) && !is_own_announce(a, own_ips) && !targets.iter().any(|t| t.addr == a) {
                            log::info!("direct path hint: host punch seen from {a} (undecodable by the {} codec), probing it", self.io.caps().id);
                            hints.push(a);
                            // only a JOIN goes there; the path opens when a valid ACCEPT comes back
                            add_target(&mut targets, a, false);
                        }
                    }
                    for i in 0..targets.len() {
                        if targets[i].due(now) {
                            targets[i].last = Some(now);
                            let addr = targets[i].addr;
                            self.send_punch(addr).await;
                        }
                    }
                    if self.signal.is_some() && last_register.elapsed() >= REGISTER_INTERVAL {
                        let _ = self.register().await;
                        last_register = Instant::now();
                    }
                    if !fan_done && first_target.is_some_and(|t| t.elapsed() >= bd.fan_delay) {
                        fan_done = true;
                        fan = self.open_fan(bd.fan).await;
                        log::info!("no answer on the main socket; fanning out over {} sockets", fan.len());
                    }
                    if scan_on && first_target.is_some_and(|t| t.elapsed() >= bd.scan_delay) {
                        // Only addresses the host itself signed: an unsigned record must never
                        // turn this guest into a port scanner of someone else's address.
                        for t in targets.iter().filter(|t| t.verified) {
                            if let IpAddr::V4(ip) = norm_addr(t.addr).ip() {
                                if scans.len() < SCAN_MAX_IPS
                                    && !scans.iter().any(|s| s.ip == ip)
                                    && crate::birthday::SCAN_BUDGET.lock().unwrap().try_start(ip, Instant::now())
                                {
                                    let sc = Scanner::new(ip, t.addr.port(), bd.scan_passes);
                                    log::info!(
                                        "birthday scan: host {ip} (announced port {}): probing its ports from the main socket at {} packets/s (at most ~{} NAT entries alive), repeated sweeps of {} ports, for up to {} s",
                                        t.addr.port(), bd.scan_pps, bd.scan_cap(), sc.pass_len(), bd.scan_window.as_secs()
                                    );
                                    scans.push(sc);
                                    scan_started.get_or_insert_with(Instant::now);
                                    // the scan outlives the usual rendezvous budget (a sweep takes minutes at a safe rate)
                                    deadline = deadline.max(Instant::now() + bd.scan_window);
                                }
                            }
                        }
                    }
                    let signed: Vec<SocketAddr> = targets.iter().filter(|t| t.verified).map(|t| t.addr).collect();
                    if !fan.is_empty() && !signed.is_empty() {
                        if let Some(frame) = self.punch_frame() {
                            // A fixed packet budget per tick, however many candidates there are.
                            let mut budget = FAN_TICK_PACKETS;
                            let nt = signed.len().min(FAN_MAX_TARGETS);
                            for _ in 0..FAN_BATCH.min(fan.len()) {
                                for k in 0..nt {
                                    if budget == 0 {
                                        break;
                                    }
                                    budget -= 1;
                                    let t = signed[(fan_cursor + k) % nt];
                                    let _ = fan[fan_cursor].send_probe(&frame, self.wire(t)).await;
                                }
                                fan_cursor = (fan_cursor + 1) % fan.len();
                            }
                        }
                    }
                }
            }
        }
    }

    /// Destination as the socket expects it: IPv4 peers are addressed through
    /// their v4-mapped form on a dual-stack socket.
    fn wire(&self, addr: SocketAddr) -> SocketAddr {
        to_wire(self.dual, addr)
    }

    /// Normalize a received address back to plain IPv4 for logging, signaling
    /// and comparisons.
    #[allow(dead_code)]
    fn norm(addr: SocketAddr) -> SocketAddr {
        norm_addr(addr)
    }

    /// Every frame this tunnel sends goes through here, so the carrier's own wrapping (the awg
    /// envelope) covers punch, JOIN and keepalive frames too. An oversize frame is counted.
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let r = self.io.send_to(data, addr).await;
        if let Err(e) = &r {
            if let Some(CarrierError::FrameTooLarge { max }) = CarrierError::from_io(e) {
                self.oversize.note(data.len(), *max, self.io.caps().id);
            }
        }
        r
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            self.io.readable().await?;
            match self.io.try_recv_from(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                r => return r,
            }
        }
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.io.try_recv_from(buf)
    }

    /// What the carrier under this tunnel can do.
    pub fn caps(&self) -> Caps {
        self.io.caps()
    }

    /// Largest IP packet [`Self::send_packet`] accepts; the TUN device must not be bigger.
    pub fn tun_mtu(&self) -> usize {
        self.io.caps().tun_mtu()
    }

    /// Frames/packets refused for being too large for the carrier since the tunnel was built.
    pub fn oversize_drops(&self) -> u64 {
        self.oversize.total()
    }

    /// Carrier health (sidecar exit, TLS reset).
    pub fn health(&self) -> Health {
        self.io.health()
    }

    /// Switch to raw IP datagrams (TUN mode). Must be called after connect.
    pub fn enable_packet_mode(&mut self) {
        self.packet_mode = true;
        self.reliable.reset();
        self.pending.clear();
        self.ready.clear();
    }

    /// Send one IP packet with no retransmission. The inner TCP handles loss.
    pub async fn send_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let caps = self.io.caps();
        if packet.len() > caps.tun_mtu() {
            // The device MTU comes from `effective_mtu`, so this means a misconfigured device.
            self.oversize.note(packet.len() + Caps::SEAL_OVERHEAD, caps.max_frame, caps.id);
            return Ok(());
        }
        if !self.punched {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "direct path is not established",
            ));
        }
        let sealed = self.seal_dgram(packet);
        self.sent_bytes += sealed.len() as u64;
        if let Some(m) = self.mux.as_mut() {
            m.last_tx = Instant::now();
        }
        if let Some(peer) = self.peer {
            let _ = self.send_to(&sealed, peer).await;
        }
        Ok(())
    }

    /// Address the host assigned to this client (mux mode): `(ip, prefix, gateway)`.
    pub fn assigned(&self) -> Option<(Ipv4Addr, u8, Ipv4Addr)> {
        self.mux.as_ref().and_then(|m| m.assigned)
    }

    /// Override keepalive interval and host-silence timeout (mux mode).
    pub fn set_timers(&mut self, keepalive: Duration, idle: Duration) {
        if let Some(m) = self.mux.as_mut() {
            m.keepalive = keepalive;
            m.idle = idle;
        }
    }

    fn rejected(&self) -> bool {
        self.mux.as_ref().is_some_and(|m| m.rejected.is_some())
    }

    /// The host's refusal as an error, once it sent one.
    fn reject_error(&self) -> Option<ConnectError> {
        self.mux.as_ref()?.rejected.map(|why| match why {
            VERDICT_FULL => ConnectError::HostFull,
            VERDICT_CLOCK => ConnectError::Clock,
            _ => ConnectError::Refused,
        })
    }

    /// Frame a sealed datagram; mux clients prefix the slot header once joined.
    fn seal_dgram(&mut self, plain: &[u8]) -> Vec<u8> {
        let d = self.crypto.seal(plain);
        match &self.mux {
            Some(m) if m.joined && !m.forward => {
                let mut out = Vec::with_capacity(3 + d.len());
                out.push(T_DATA);
                out.extend_from_slice(&m.slot.to_be_bytes());
                out.extend_from_slice(&d);
                out
            }
            _ => d,
        }
    }

    /// Verify one received datagram. Mux clients complete the handshake here
    /// (an ACCEPT counts as an authenticated datagram, like a legacy Hello).
    fn open_dgram(&mut self, d: &[u8], from: SocketAddr) -> Result<(Vec<u8>, bool), CryptoError> {
        if let Some(h) = self.fwd_host.as_mut() {
            if d.first() == Some(&T_JOIN) {
                let was_joined = h.joined;
                return match h.join(d, from) {
                    Some((reply, key)) => {
                        self.reply = Some(reply);
                        match key {
                            Some(k) => {
                                self.replaced |= was_joined;
                                self.crypto = AeadSession::from_key(&k, true);
                                Ok((reliable::encode(&Frame::Hello), true))
                            }
                            None => Err(CryptoError::BadTag), // a refusal or a retried JOIN: just answer it
                        }
                    }
                    None => Err(CryptoError::BadTag),
                };
            }
            if !h.joined {
                return Err(CryptoError::BadTag);
            }
            let r = self.crypto.open(d);
            if r.is_ok() {
                h.heard(from);
            }
            return r;
        }
        let Some(m) = self.mux.as_mut() else {
            return Err(CryptoError::BadTag);
        };
        match d.first() {
            Some(&T_ACCEPT) if !m.joined && d.len() == ACCEPT_LEN => {
                // Only the holder of the host key the invite names can produce a readable message 2.
                let done = m.hs.as_mut().and_then(|hs| open_accept(&m.base, hs, &m.cn, d));
                let Some((slot, verdict, key)) = done else {
                    if d[1..17] == m.cn {
                        // The pending handshake stays: a forged answer cannot end the join.
                        log::warn!("a host answered the join but could not prove the host key of this invite; ignored");
                    }
                    return Err(CryptoError::BadTag);
                };
                if verdict != VERDICT_OK {
                    m.rejected = Some(verdict);
                    m.restart();
                    return Err(CryptoError::BadTag);
                }
                self.crypto = AeadSession::from_key(&key, false);
                m.slot = slot;
                m.joined = true;
                m.hs = None;
                m.last_rx = Instant::now();
                Ok((reliable::encode(&Frame::Hello), true))
            }
            _ if m.joined && m.forward => self.crypto.open(d),
            Some(&T_DATA) if m.joined && d.len() > 3 => {
                let r = self.crypto.open(&d[3..]);
                if r.is_ok() {
                    m.last_rx = Instant::now();
                }
                r
            }
            _ => Err(CryptoError::BadTag),
        }
    }

    /// Forward-mode host: send the handshake answer `open_dgram` prepared, if any.
    async fn flush_reply(&mut self, to: SocketAddr) {
        if let Some(r) = self.reply.take() {
            let _ = self.send_to(&r, to).await;
        }
    }

    /// Sealed control frames from the host.
    fn control(&mut self, plain: &[u8]) {
        let Some(m) = self.mux.as_mut() else { return };
        match plain.first() {
            Some(&C_ASSIGN) if plain.len() == 10 => {
                let ip = Ipv4Addr::new(plain[1], plain[2], plain[3], plain[4]);
                let gw = Ipv4Addr::new(plain[6], plain[7], plain[8], plain[9]);
                // Only a client address of the tunnel network: a host must not be able to hand
                // out an address or prefix that captures the guest's LAN or default route.
                if AddrPool::slot_of(ip).is_some() && plain[5] == MUX_PREFIX && gw == MUX_HOST_IP {
                    m.assigned = Some((ip, plain[5], gw));
                } else {
                    log::warn!("host assigned {ip}/{} via {gw}, outside the tunnel network 10.7.0.0/{MUX_PREFIX}; ignored", plain[5]);
                }
            }
            Some(&C_BYE) => m.bye = true,
            _ => {}
        }
    }

    fn join_frame(&mut self) -> Option<Vec<u8>> {
        let m = self.mux.as_mut()?;
        // The JOIN carries the client's clock: renew it well before the host would call it stale.
        if !m.joined && m.made.elapsed() >= JOIN_RENEW {
            m.restart();
        }
        Some(m.join.clone()).filter(|j| !j.is_empty())
    }

    async fn send_join(&mut self) {
        let Some(d) = self.join_frame() else { return };
        if let Some(peer) = self.peer {
            let _ = self.send_to(&d, peer).await;
        }
    }

    /// The frame a punch sends: the client's JOIN (until joined); a host only opens its NAT.
    fn punch_frame(&mut self) -> Option<Vec<u8>> {
        match self.mux.as_ref() {
            Some(m) if m.joined => None,
            Some(_) => self.join_frame(),
            None => Some(vec![T_PUNCH]),
        }
    }

    /// Open up to `n` extra sockets of the main socket's family (each gets its own external port
    /// from a symmetric NAT). Stops quietly at the first failure (fd limit).
    async fn open_fan(&self, n: usize) -> Vec<Arc<dyn FrameIo>> {
        let mut v: Vec<Arc<dyn FrameIo>> = Vec::with_capacity(n);
        for _ in 0..n {
            // The plain UDP carrier keeps its marked/pinned sockets; ss and awg dial siblings.
            let next: Option<Arc<dyn FrameIo>> = if self.io.caps().id == CarrierId::Udp {
                match bind_marked(None).await {
                    Ok((s, d)) if d == self.dual => Some(Arc::new(UdpCarrier::from_socket(s, d))),
                    Ok(_) => None,
                    Err(e) => {
                        log::warn!("birthday fan-out: stopped at {} sockets ({e})", v.len());
                        None
                    }
                }
            } else {
                self.io.sibling().await
            };
            match next {
                Some(io) => v.push(io),
                None => break,
            }
        }
        v
    }

    /// Wait for the host's ASSIGN control frame, re-sending JOIN (which makes
    /// the host repeat ACCEPT + ASSIGN) in case it was lost.
    async fn await_assign(&mut self) -> Result<(), ConnectError> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut buf = [0u8; 2048];
        while self.assigned().is_none() {
            if let Some(e) = self.reject_error() {
                return Err(e);
            }
            if Instant::now() >= deadline {
                return Err(ConnectError::HostUnreachable);
            }
            self.send_join().await;
            if let Ok(Ok((len, from))) =
                tokio::time::timeout(Duration::from_millis(300), self.recv_from(&mut buf)).await
            {
                if let Ok((plain, _)) = self.open_dgram(&buf[..len], from) {
                    self.control(&plain);
                }
            }
        }
        // The host holds this slot "unconfirmed" until a packet opens under the new session key:
        // send two at once (one may be lost) and a third at the next tick, 1 s on.
        if let Some(peer) = self.peer {
            for _ in 0..2 {
                let d = self.seal_dgram(&[C_KEEPALIVE]);
                let _ = self.send_to(&d, peer).await;
            }
        }
        if let Some(m) = self.mux.as_mut() {
            let now = Instant::now();
            m.last_tx = now.checked_sub(m.keepalive).map_or(now, |t| t + Duration::from_secs(1));
        }
        Ok(())
    }

    pub fn is_direct(&self) -> bool {
        self.punched
    }

    /// True while bytes are queued or awaiting an ACK.
    pub fn has_pending(&self) -> bool {
        self.reliable.has_pending()
    }

    /// Whether the caller may send more bytes without overrunning the ARQ.
    pub fn can_send(&self) -> bool {
        self.reliable.can_accept()
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn bytes_sent(&self) -> u64 {
        self.sent_bytes
    }

    /// (cwnd, in-flight frames, queued payloads)
    pub fn arq(&self) -> (usize, usize, usize) {
        self.reliable.status()
    }

    pub fn bytes_received(&self) -> u64 {
        self.received_bytes
    }

    /// Await socket readability (used by the pump's select).
    pub async fn readable(&self) -> io::Result<()> {
        self.io.readable().await
    }

    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let frames = self.reliable.send(data, Instant::now());
        self.transmit(frames, false).await
    }

    /// Drain one datagram. Ok(None) means "nothing pending right now".
    pub async fn try_recv(&mut self) -> io::Result<Option<Event>> {
        if self.packet_mode {
            return self.try_recv_packet().await;
        }

        // Payloads released by the sliding window, in order.
        if let Some(data) = self.ready.pop_front() {
            return Ok(Some(Event::Data(data)));
        }

        // Frames decrypted while punching were buffered in arrival order.
        while let Some(plain) = self.pending.pop_front() {
            if let Some(event) = self.consume(plain).await? {
                return Ok(Some(event));
            }
        }

        let mut buf = [0u8; 2048];
        loop {
            let (len, from) = match self.try_recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            };

            let plain = if Some(from) == self.signal {
                match relay::decode_for(self.room, &buf[..len]) {
                    Some(relay::Incoming::Peer { addr, .. }) => {
                        self.peer = Some(addr);
                        continue;
                    }
                    _ => None,
                }
            } else {
                // The AEAD tag authenticates the sender, so a datagram that
                // decrypts proves the direct path works even if a NAT between
                // the peers rewrites the source address in one direction.
                match self.open_dgram(&buf[..len], from) {
                    Ok((p, restarted)) => {
                        self.received_bytes += len as u64;
                        if restarted {
                            self.reset_stream();
                            self.flush_reply(from).await; // forward-mode host: the handshake answer
                        }
                        self.learn_direct(from);
                        if self.replaced {
                            return Ok(None); // the caller starts over for the new session (`take_replaced`)
                        }
                        Some(p)
                    }
                    Err(CryptoError::Replay) if Some(from) == self.peer => {
                        self.punched = true;
                        None
                    }
                    Err(_) => {
                        self.flush_reply(from).await;
                        None
                    }
                }
            };

            let Some(plain) = plain else { continue };
            if let Some(event) = self.consume(plain).await? {
                return Ok(Some(event));
            }
        }
    }


    /// Forward-mode host: true once after a new guest session replaced the previous one. The
    /// caller must not hand the new session anything that belonged to the old one (such as its
    /// connection to the forwarded service).
    pub fn take_replaced(&mut self) -> bool {
        std::mem::take(&mut self.replaced)
    }

    /// A restarted peer starts its sequence numbers from zero again.
    fn reset_stream(&mut self) {
        log::info!("peer restarted; resetting stream state");
        self.reliable.reset();
        self.pending.clear();
        self.ready.clear();
    }

    /// Raw datagram receive path used by TUN mode.
    async fn try_recv_packet(&mut self) -> io::Result<Option<Event>> {
        let mut buf = [0u8; 2048];
        loop {
            if let Some(m) = self.mux.as_mut() {
                if m.bye || (m.joined && m.last_rx.elapsed() >= m.idle) {
                    m.bye = false;
                    m.last_rx = Instant::now();
                    return Ok(Some(Event::Closed));
                }
            }
            let (len, from) = match self.try_recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            };

            if Some(from) == self.signal {
                match relay::decode_for(self.room, &buf[..len]) {
                    Some(relay::Incoming::Peer { addr, .. }) => {
                        self.peer = Some(addr);
                        continue;
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(packet) = self.accept_packet(&buf[..len], from) {
                self.learn_direct(from);
                return Ok(Some(Event::Data(packet)));
            }
            log::debug!(
                "direct datagram rejected ({} bytes from {}, first byte {:?})",
                len,
                from,
                buf.first()
            );
        }
    }

    fn accept_packet(&mut self, datagram: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        match self.open_dgram(datagram, from) {
            Ok((plain, restarted)) => {
                self.received_bytes += datagram.len() as u64;
                if restarted {
                    self.reliable.reset();
                }
                // Control frames (Bye/Hello/ACK) are not IP packets.
                if plain.first().is_some_and(|b| b >> 4 == 4) {
                    Some(plain)
                } else {
                    self.control(&plain);
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Feed one decrypted frame into the reliable stream.
    async fn consume(&mut self, plain: Vec<u8>) -> io::Result<Option<Event>> {
        let Some(frame) = reliable::decode(&plain) else {
            return Ok(None);
        };
        if frame == Frame::Bye {
            self.reliable.reset();
            return Ok(Some(Event::Closed));
        }
        let (delivered, out) = self.reliable.recv(frame, Instant::now());
        self.transmit(out, false).await?;
        let mut delivered = delivered.into_iter();
        let first = delivered.next();
        self.ready.extend(delivered);
        Ok(first.map(Event::Data))
    }

    /// Periodic work: keep the signal registration fresh, retransmit if due.
    pub async fn tick(&mut self) -> io::Result<()> {
        self.crypto.age(); // an idle direction drops its old key too
        if self.signal.is_some() && self.last_register.elapsed() >= REGISTER_INTERVAL {
            self.register().await?;
        }
        if let (Some(stun), Some(sock)) = (self.stun, self.io.udp()) {
            if self.last_stun_poke.elapsed() >= STUN_POKE_INTERVAL {
                let _ = crate::tunnel::stun::poke(sock, self.wire(stun)).await;
                self.last_stun_poke = Instant::now();
            }
        }
        if self.packet_mode {
            if self.mux.as_ref().is_some_and(|m| m.joined && m.last_tx.elapsed() >= m.keepalive) {
                let d = self.seal_dgram(&[C_KEEPALIVE]);
                if let Some(peer) = self.peer {
                    let _ = self.send_to(&d, peer).await;
                }
                if let Some(m) = self.mux.as_mut() {
                    m.last_tx = Instant::now();
                }
            }
            return Ok(());
        }
        let frames = self.reliable.poll(Instant::now());
        // Forward mode: an idle guest still says it is there, so the host keeps its session (and
        // refuses another guest) while a connection is merely quiet.
        if frames.is_empty() && self.punched && self.mux.as_ref().is_some_and(|m| m.joined && m.last_tx.elapsed() >= FWD_KEEPALIVE) {
            let d = self.seal_dgram(&[C_KEEPALIVE]);
            if let Some(peer) = self.peer {
                let _ = self.send_to(&d, peer).await;
            }
            if let Some(m) = self.mux.as_mut() {
                m.last_tx = Instant::now();
            }
        }
        self.transmit(frames, true).await
    }

    /// Tell the peer this stream is done and drop local ARQ state.
    ///
    /// `Bye` is not acknowledged, so it is sent a few times. The gap stays well
    /// below the app's 200 ms pause before the next session, otherwise a late
    /// copy could close the new session.
    pub async fn close(&mut self) -> io::Result<()> {
        for _ in 0..3 {
            let bye = if self.mux.as_ref().is_some_and(|m| !m.forward) {
                self.seal_dgram(&[C_BYE])
            } else {
                self.crypto.seal(&reliable::encode(&Frame::Bye))
            };
            if self.punched {
                if let Some(peer) = self.peer {
                    let _ = self.send_to(&bye, peer).await;
                }
            }
            if let Some(signal) = self.signal {
                let _ = self
                    .send_to(&relay::encode_deregister(self.room, self.role), signal)
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        self.reliable.reset();
        self.pending.clear();
        self.ready.clear();
        Ok(())
    }

    async fn register(&mut self) -> io::Result<()> {
        let Some(signal) = self.signal else {
            return Ok(());
        };
        self.last_register = Instant::now();
        if let Some(room) = self.room_key.as_deref().map(relay::room_for_key).filter(|r| *r != self.room) {
            let _ = self.send_to(&relay::encode_deregister(self.room, self.role), signal).await;
            self.room = room; // a new UTC day: guests starting now look in the new room
        }
        self.send_to(&relay::encode_register(self.room, self.role), signal)
            .await?;
        Ok(())
    }

    async fn discover_peer(&mut self) -> io::Result<()> {
        let Some(signal) = self.signal else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no signaling server in this invite",
            ));
        };
        let deadline = Instant::now() + PEER_WAIT;
        let mut buf = [0u8; 2048];
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "peer did not join the room",
                ));
            }
            self.register().await?;
            let wait = Duration::from_millis(500).min(deadline - Instant::now());
            if let Ok(Ok((len, from))) =
                tokio::time::timeout(wait, self.recv_from(&mut buf)).await
            {
                if Some(from) == self.signal {
                    if let Some(relay::Incoming::Peer { addr, .. }) = relay::decode_for(self.room, &buf[..len]) {
                        log::info!("peer at {} (via signal {})", addr, signal);
                        self.peer = Some(addr);
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Simultaneous send to open both NAT bindings; give up after the window.
    async fn punch(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + PUNCH_WINDOW;
        let mut buf = [0u8; 2048];
        let mut next_send = Instant::now();
        let mut last_register = Instant::now();

        while Instant::now() < deadline && !self.rejected() {
            // Send at most once per interval. Looping as fast as packets arrive
            // turns the two peers into a Hello feedback loop.
            if Instant::now() >= next_send {
                if let Some(peer) = self.peer {
                    self.send_punch(peer).await;
                }
                next_send = Instant::now() + PUNCH_INTERVAL;
            }
            if last_register.elapsed() >= REGISTER_INTERVAL {
                let _ = self.register().await;
                last_register = Instant::now();
            }

            let wait = next_send
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            match tokio::time::timeout(wait, self.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) if Some(from) == self.signal => match relay::decode_for(self.room, &buf[..len]) {
                    Some(relay::Incoming::Peer { addr, .. }) => {
                        if self.peer != Some(addr) {
                            log::debug!("peer address updated to {}", addr);
                            self.peer = Some(addr);
                        }
                    }
                    _ => {}
                },
                Ok(Ok((len, from))) => {
                    // A decryptable datagram proves the punch worked even when a NAT rewrites the
                    // source address between the peers.
                    match self.open_dgram(&buf[..len], from) {
                        Ok((plain, restarted)) => {
                            if restarted {
                                self.reset_stream();
                            }
                            self.pending.push_back(plain);
                            self.learn_direct(from);
                            self.flush_reply(from).await; // forward-mode host: the handshake answer
                            log::info!("direct hole punch open to {}", from);
                            return Ok(());
                        }
                        Err(CryptoError::Replay)
                            if Some(from) == self.peer =>
                        {
                            self.learn_direct(from);
                            log::info!("direct hole punch open to {}", from);
                            return Ok(());
                        }
                        Err(_) => self.flush_reply(from).await,
                    }
                }
                _ => {}
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "direct path unavailable (symmetric NAT or UDP blocked); no relay is used",
        ))
    }

    /// Punch straight at an endpoint taken from the invite.
    ///
    /// This is the whole connection setup when the host has a public address:
    /// the guest sends first, the host answers, and no third server ever sees
    /// a packet.
    async fn punch_direct(&mut self, peer: SocketAddr, window: Duration) -> io::Result<()> {
        let full_tunnel = self.mux.as_ref().is_some_and(|m| !m.forward);
        let window = if full_tunnel { window.max(MUX_JOIN_WINDOW) } else { window };
        let deadline = Instant::now() + window;
        let mut buf = [0u8; 2048];
        let mut next_send = Instant::now();
        let mut sent = 0u32;
        self.peer = Some(peer);

        while Instant::now() < deadline && !self.rejected() {
            if Instant::now() >= next_send {
                self.send_punch(peer).await;
                // Mux JOINs back off (100ms .. 800ms) so a burst of clients
                // does not keep re-flooding a host that is already behind.
                let backoff = if full_tunnel { 1 << sent.min(3) } else { 1 };
                sent += 1;
                next_send = Instant::now() + PUNCH_INTERVAL * backoff;
            }
            let wait = next_send
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            if let Ok(Ok((len, from))) =
                tokio::time::timeout(wait, self.recv_from(&mut buf)).await
            {
                match self.open_dgram(&buf[..len], from) {
                    Ok((plain, restarted)) => {
                        if restarted {
                            self.reset_stream();
                        }
                        self.pending.push_back(plain);
                        self.learn_direct(from);
                        log::info!("direct path open to {}", from);
                        return Ok(());
                    }
                    Err(_) => {}
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no answer from the host endpoint",
        ))
    }

    /// Host side without any signaling server: wait for the guest's first
    /// authenticated datagram and answer it.
    async fn await_peer(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + DIRECT_WAIT;
        let mut buf = [0u8; 2048];
        log::info!("host waiting for a direct guest (no signaling server)");
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no guest reached the host port; check the invite and UDP reachability",
                ));
            }
            let wait = (deadline - Instant::now()).min(Duration::from_millis(500));
            match tokio::time::timeout(wait, self.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => match self.open_dgram(&buf[..len], from) {
                    Ok((plain, restarted)) => {
                        if restarted {
                            self.reset_stream();
                        }
                        self.pending.push_back(plain);
                        self.learn_direct(from);
                        // Tell the guest where we are before its punch window ends.
                        self.send_punch(from).await;
                        log::info!("direct guest at {}", from);
                        return Ok(());
                    }
                    // A retried JOIN or a refusal still gets its answer; anything else is
                    // ignored and the host keeps listening.
                    Err(_) => self.flush_reply(from).await,
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
    }

    /// Remember where authenticated direct datagrams actually arrive from.
    ///
    /// Source-address rewriting by a NAT makes the address advertised
    /// through the rendezvous server wrong in one direction; the AEAD tag, not
    /// the source address, is what authenticates the peer.
    fn learn_direct(&mut self, from: SocketAddr) {
        if self.peer != Some(from) {
            log::debug!("direct peer address {} (was {:?})", from, self.peer);
            self.peer = Some(from);
        }
        self.punched = true;
    }

    async fn send_punch(&mut self, peer: SocketAddr) {
        if self.mux.is_some() {
            self.peer = Some(peer);
            if !self.mux.as_ref().is_some_and(|m| m.joined) {
                self.send_join().await;
            }
            return;
        }
        // Forward-mode host: the handshake answer when one is due, else a sealed Hello once the
        // session exists, else a bare punch byte (nothing to say before the guest's JOIN).
        if self.reply.is_some() {
            return self.flush_reply(peer).await;
        }
        let d = if self.fwd_host.as_ref().is_some_and(|h| h.joined) {
            self.crypto.seal(&reliable::encode(&Frame::Hello))
        } else {
            vec![T_PUNCH]
        };
        let _ = self.send_to(&d, peer).await;
    }

    /// Send frames.
    ///
    /// Frames go to the peer's direct address only; nothing is ever sent through a third party.
    async fn transmit(&mut self, frames: Vec<Frame>, _retransmit: bool) -> io::Result<()> {
        if let Some(m) = self.mux.as_mut().filter(|_| !frames.is_empty()) {
            m.last_tx = Instant::now();
        }
        for frame in frames {
            let sealed = self.seal_dgram(&reliable::encode(&frame));
            self.sent_bytes += sealed.len() as u64;

            if !self.punched {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "direct path is not established",
                ));
            }
            if let Some(peer) = self.peer {
                let _ = self.send_to(&sealed, peer).await;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Host multiplexing (see the module docs for the wire format).
// ---------------------------------------------------------------------------

const T_PUNCH: u8 = 0xF0;
// Handshake v2 tags (v1 used 0xF1-0xF3, without DH).
// v3 handshake (Noise NKpsk0, `tunnel::handshake`). 0xF5..0xF7 were v2 and are ignored.
const T_JOIN: u8 = 0xF8;
const T_ACCEPT: u8 = 0xF9;
// 0xFA was a separate REJECT; refusals are ACCEPTs with a verdict now.
/// JOIN = type | cn (16) | Noise message 1 (payload: clock (4) | optional guest token) | tag (16).
const JOIN_MIN: usize = 1 + 16 + 4 + handshake::OVERHEAD + 16;
const JOIN_MAX: usize = JOIN_MIN + handshake::TOKEN_LEN;
/// ACCEPT = type | cn (16) | Noise message 2 (payload: slot (2) | cn (16) | verdict (1)) | tag (16).
/// A refusal travels the same way, so only the host can send one.
const ACCEPT_LEN: usize = 1 + 16 + 19 + handshake::OVERHEAD + 16;
const VERDICT_OK: u8 = 0;
const VERDICT_FULL: u8 = 1;
const VERDICT_REFUSED: u8 = 2;
const VERDICT_CLOCK: u8 = 3;
const T_DATA: u8 = 0xF4;
const C_ASSIGN: u8 = 0xC0;
const C_KEEPALIVE: u8 = 0xC1;
const C_BYE: u8 = 0xC2;

/// Idle time before a sealed keepalive is sent.
pub const MUX_KEEPALIVE: Duration = Duration::from_secs(15);
/// A personal invite's session counts as live (blocking a second device) while heard from this recently.
const PERSONAL_LIVE: Duration = Duration::from_secs(40);
/// Silence after which a peer is evicted (or the host declared dead).
pub const MUX_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard ceiling on clients per host.
pub const MUX_MAX_CLIENTS: usize = 1024;
/// Health text a stream carrier reports when its last connection ended normally for a host.
fn routine_leave(why: &str) -> bool {
    why.starts_with("connection closed by peer") || why.starts_with("connection reset:")
}

/// The host's address inside the tunnel network.
pub const MUX_HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
/// Prefix length of the tunnel network (10.7.0.0/16).
pub const MUX_PREFIX: u8 = 16;
/// How many past `cn`s the host remembers to refuse replayed JOINs. A JOIN older than
/// `handshake::JOIN_MAX_SKEW` is refused anyway, so the cache only has to span that time.
const SEEN_CN_CAP: usize = 65536;
/// Fewest slots one source address may hold (three quarters of the pool, at least this many):
/// a household behind one NAT fits, yet one address never takes every slot.
const MUX_MIN_PER_SOURCE: usize = 4;
/// Unconfirmed joins one invite (each personal one, or the shared one) may hold at a time.
const MUX_UNCONFIRMED_PER_INVITE: usize = 4;

/// A join that came through a local sidecar (the loopback address, or the synthetic 240.0.0.0/8
/// addresses a header-demuxed loopback carrier gives its clients): the real source is unknown.
fn via_sidecar(a: SocketAddr) -> bool {
    match a.ip().to_canonical() {
        IpAddr::V4(v) => v.is_loopback() || v.octets()[0] == 240,
        IpAddr::V6(v) => v.is_loopback(),
    }
}

/// An unconfirmed join younger than this is never pushed out by another source's join: the
/// round trip to confirm it fits well within it.
const UNCONFIRMED_GRACE: Duration = Duration::from_secs(3);
/// New join handshakes (key exchanges) one network may start per `JOIN_LIMIT_WINDOW`. Retries of
/// a JOIN the host already answered cost nothing and are not counted.
const JOIN_LIMIT: u32 = 20;
const JOIN_LIMIT_WINDOW: Duration = Duration::from_secs(10);

/// Networks the join limiter tracks at once; past this it forgets the older half.
const JOIN_LIMIT_NETS: usize = 4096;

/// Per-network budget of new join handshakes, so a flood of JOINs cannot tie up the host, and a
/// per-personal-invite budget of new sessions.
#[derive(Default)]
struct JoinLimit {
    at: HashMap<(IpAddr, u8), (Instant, u32)>,
    /// Budget of everything that comes through a sidecar (at least `JOIN_LIMIT * 8`): every
    /// client of a full host may rejoin at once, twice over.
    sidecar: u32,
    invites: HashMap<u32, (Instant, u32)>,
}

/// Count one event in `e`'s window; true while it stays within `limit`.
fn count(e: &mut (Instant, u32), now: Instant, limit: u32) -> bool {
    if now.duration_since(e.0) >= JOIN_LIMIT_WINDOW {
        *e = (now, 0);
    }
    e.1 = e.1.saturating_add(1);
    e.1 <= limit
}

impl JoinLimit {
    fn key(&self, from: SocketAddr) -> ((IpAddr, u8), u32) {
        // Everything through a sidecar shares one budget, a larger one.
        if via_sidecar(from) {
            ((IpAddr::V4(Ipv4Addr::LOCALHOST), 0), self.sidecar.max(JOIN_LIMIT * 8))
        } else {
            (source_net(from), JOIN_LIMIT)
        }
    }

    fn allow(&mut self, from: SocketAddr) -> bool {
        let now = Instant::now();
        let (key, limit) = self.key(from);
        if self.at.len() >= JOIN_LIMIT_NETS && !self.at.contains_key(&key) {
            self.at.retain(|_, (t, _)| now.duration_since(*t) < JOIN_LIMIT_WINDOW);
            if self.at.len() >= JOIN_LIMIT_NETS {
                // Still full: forget the older half (amortised O(1) per join). Never refuse
                // everyone because many networks are sending: that would let one sender with many
                // addresses lock every guest out.
                let mut ts: Vec<Instant> = self.at.values().map(|v| v.0).collect();
                let mid = ts.len() / 2;
                let cut = *ts.select_nth_unstable(mid).1;
                self.at.retain(|_, (t, _)| *t > cut);
            }
        }
        count(self.at.entry(key).or_insert((now, 0)), now, limit)
    }

    /// New sessions one personal invite may start per window, wherever it joins from (it works on
    /// one device at a time).
    fn allow_invite(&mut self, id: u32) -> bool {
        let now = Instant::now();
        if self.invites.len() >= JOIN_LIMIT_NETS {
            self.invites.retain(|_, (t, _)| now.duration_since(*t) < JOIN_LIMIT_WINDOW);
        }
        count(self.invites.entry(id).or_insert((now, 0)), now, JOIN_LIMIT)
    }
}

/// A refusal kept to answer retries of the same JOIN without a new key exchange.
struct Refusal {
    cn: [u8; 16],
    to: SocketAddr,
    dgram: Vec<u8>,
    sent: Instant,
}
const REFUSALS_KEPT: usize = 64;

/// The network a source counts against: its IPv4 address, or its IPv6 /48 (one site: a single
/// customer can hold thousands of /64s).
fn source_net(a: SocketAddr) -> (IpAddr, u8) {
    match a.ip().to_canonical() {
        IpAddr::V6(v) => {
            let s = v.segments();
            (IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)), 48)
        }
        v4 => (v4, 32),
    }
}
/// How long a join may stay unconfirmed (no packet under the new session key yet). Longer than
/// `MUX_KEEPALIVE`, so on a lossy path the client's regular keepalive still confirms it.
const MUX_UNCONFIRMED_TTL: Duration = Duration::from_secs(20);

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let (mut ik, mut ok) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 {
        ik[i] ^= key[i];
        ok[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(ik);
    for p in parts {
        h.update(p);
    }
    let inner = h.finalize();
    let mut h = Sha256::new();
    h.update(ok);
    h.update(inner);
    h.finalize().into()
}

fn mux_base(psk: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"strait-mux-v3");
    h.update(psk.as_bytes());
    h.finalize().into()
}

/// The outer tag's key, derived from `base` (which is also the Noise PSK) so the two never share
/// a key.
fn tag_key(base: &[u8; 32]) -> [u8; 32] {
    hmac(base, &[b"strait-outer-tag-v1"])
}

fn tag(base: &[u8; 32], label: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut all = vec![label];
    all.extend_from_slice(parts);
    hmac(&tag_key(base), &all)[..16].try_into().unwrap()
}

/// Message 1's ephemeral key: the replay memory's key. `cn` is no good for that: it sits outside
/// Noise, so an invite holder could re-wrap a captured message 1 under a fresh `cn`.
fn join_epk(msg1: &[u8]) -> [u8; 32] {
    msg1[..32].try_into().unwrap() // JOIN_MIN guarantees a full ephemeral key
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn join_dgram(base: &[u8; 32], cn: &[u8; 16], msg1: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(JOIN_MAX);
    d.push(T_JOIN);
    d.extend_from_slice(cn);
    d.extend_from_slice(msg1);
    d.extend_from_slice(&tag(base, b"join", &[cn, msg1]));
    d
}

fn accept_dgram(base: &[u8; 32], cn: &[u8; 16], msg2: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(ACCEPT_LEN);
    d.push(T_ACCEPT);
    d.extend_from_slice(cn);
    d.extend_from_slice(msg2);
    d.extend_from_slice(&tag(base, b"accept", &[cn, msg2]));
    d
}

/// Message 2's payload.
fn verdict_payload(slot: u16, cn: &[u8; 16], verdict: u8) -> Vec<u8> {
    let mut p = slot.to_be_bytes().to_vec();
    p.extend_from_slice(cn);
    p.push(verdict);
    p
}

/// A JOIN that passed the invite tag: (cn, Noise message 1).
fn split_join(base: &[u8; 32], d: &[u8]) -> Option<([u8; 16], Vec<u8>)> {
    if d.len() < JOIN_MIN || d.len() > JOIN_MAX || d[0] != T_JOIN {
        return None;
    }
    let cn: [u8; 16] = d[1..17].try_into().unwrap();
    let msg1 = &d[17..d.len() - 16];
    ct_eq(&tag(base, b"join", &[&cn, msg1]), &d[d.len() - 16..]).then(|| (cn, msg1.to_vec()))
}

/// Client side: open an ACCEPT for handshake `hs` / nonce `cn`: (slot, verdict, session key).
fn open_accept(base: &[u8; 32], hs: &mut handshake::ClientHs, cn: &[u8; 16], d: &[u8]) -> Option<(u16, u8, [u8; 32])> {
    if d.len() != ACCEPT_LEN || d[0] != T_ACCEPT || d[1..17] != cn[..] {
        return None;
    }
    let msg2 = &d[17..ACCEPT_LEN - 16];
    if !ct_eq(&tag(base, b"accept", &[cn, msg2]), &d[ACCEPT_LEN - 16..]) {
        return None;
    }
    let (p, key) = hs.finish(msg2).ok()?;
    (p.len() == 19 && p[2..18] == cn[..]).then(|| (u16::from_be_bytes([p[0], p[1]]), p[18], key))
}

/// The handshake's pre-shared key for an invite key. Test helper.
#[doc(hidden)]
pub fn hs_base(invite_key: &str) -> [u8; 32] {
    mux_base(invite_key)
}

/// A JOIN datagram around an arbitrary handshake message (valid outer tag). Test helper.
#[doc(hidden)]
pub fn hs_join_raw(base: &[u8; 32], cn: &[u8; 16], msg1: &[u8]) -> Vec<u8> {
    join_dgram(base, cn, msg1)
}

/// A client's JOIN and its handshake state, as a real client builds them (clock = now unless
/// `at` is given). For the handshake security tests.
#[doc(hidden)]
pub fn hs_join_at(invite_key: &str, cn: &[u8; 16], auth: JoinAuth, at: Option<u32>) -> (handshake::ClientHs, Vec<u8>) {
    let base = mux_base(invite_key);
    let payload = handshake::join_payload(at.unwrap_or_else(handshake::now_secs), auth.token.as_ref());
    let hs = handshake::ClientHs::new(&base, &auth.host_key.expect("test auth names a host key"), &payload).expect("handshake");
    let d = join_dgram(&base, cn, &hs.msg1);
    (hs, d)
}

#[doc(hidden)]
pub fn hs_join(invite_key: &str, cn: &[u8; 16], auth: JoinAuth) -> (handshake::ClientHs, Vec<u8>) {
    hs_join_at(invite_key, cn, auth, None)
}

/// Finish a client handshake from the host's ACCEPT: the slot and the session, if accepted.
/// Test helper.
#[doc(hidden)]
pub fn hs_finish(invite_key: &str, hs: &mut handshake::ClientHs, cn: &[u8; 16], accept: &[u8]) -> Option<(u16, AeadSession)> {
    let (slot, verdict, key) = open_accept(&mux_base(invite_key), hs, cn, accept)?;
    (verdict == VERDICT_OK).then(|| (slot, AeadSession::from_key(&key, false)))
}

/// What a host holding `host_key` answers to `join`: the ACCEPT for `slot` and the host-side
/// session. Test helper (a hand-made host).
#[doc(hidden)]
pub fn hs_accept(invite_key: &str, host_key: [u8; 32], slot: u16, join: &[u8]) -> Option<(Vec<u8>, AeadSession)> {
    let base = mux_base(invite_key);
    let (cn, msg1) = split_join(&base, join)?;
    let (hs, _) = handshake::HostHs::read(&base, &host_key, &msg1).ok()?;
    let (msg2, k) = hs.write(&verdict_payload(slot, &cn, VERDICT_OK)).ok()?;
    Some((accept_dgram(&base, &cn, &msg2), AeadSession::from_key(&k, true)))
}

fn rand16() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

/// Sealed bytes of the largest legacy (forward mode) ARQ frame: type + seq + MAX_PAYLOAD + AEAD.
const LEGACY_FRAME: usize = reliable::MAX_PAYLOAD + 5 + 32;

/// Counts frames a carrier refused as too large. Never silent: the total is exposed and a
/// warning is logged at most every few seconds.
#[derive(Default)]
struct DropCount {
    total: std::sync::atomic::AtomicU64,
    last_log: std::sync::Mutex<Option<Instant>>,
}

impl DropCount {
    fn note(&self, len: usize, max: usize, id: CarrierId) {
        let n = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self.last_log.lock().unwrap();
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            *last = Some(Instant::now());
            log::warn!(
                "{id} carrier refused a {len}-byte frame (limit {max}); {n} refused so far. \
                 The TUN MTU must not exceed {}",
                max.saturating_sub(Caps::SEAL_OVERHEAD)
            );
        }
    }
    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// TUN device MTU for this process; set from [`effective_mtu`] before the device is created.
static TUN_MTU: AtomicUsize = AtomicUsize::new(1400);

/// Choose the TUN device MTU (clamped to 576..=1400). Call before `tunmode::open`.
pub fn set_tun_mtu(mtu: usize) {
    TUN_MTU.store(mtu.clamp(576, 1400), Ordering::Relaxed);
}

/// The MTU the next TUN device gets (1400 unless [`set_tun_mtu`] lowered it).
pub fn tun_mtu() -> usize {
    TUN_MTU.load(Ordering::Relaxed)
}

/// Client-side handshake and liveness state of a [`Tunnel`] in mux mode.
struct MuxClient {
    base: [u8; 32],
    auth: JoinAuth,
    /// Forward mode: one guest, no slot header, no ASSIGN.
    forward: bool,
    /// When `join` was made (its clock is renewed before it goes stale).
    made: Instant,
    cn: [u8; 16],
    /// Handshake state until the host's ACCEPT is read.
    hs: Option<handshake::ClientHs>,
    /// The JOIN datagram, identical on every retry.
    join: Vec<u8>,
    slot: u16,
    joined: bool,
    assigned: Option<(Ipv4Addr, u8, Ipv4Addr)>,
    /// The host's refusal (`REJECT_*`), once it sent one.
    rejected: Option<u8>,
    bye: bool,
    last_rx: Instant,
    last_tx: Instant,
    keepalive: Duration,
    idle: Duration,
}

impl MuxClient {
    fn new(key: &str, auth: JoinAuth, forward: bool) -> Self {
        let mut m = Self {
            base: mux_base(key),
            auth,
            forward,
            made: Instant::now(),
            cn: [0; 16],
            hs: None,
            join: Vec::new(),
            slot: 0,
            joined: false,
            assigned: None,
            rejected: None,
            bye: false,
            last_rx: Instant::now(),
            last_tx: Instant::now(),
            keepalive: MUX_KEEPALIVE,
            idle: MUX_TIMEOUT,
        };
        m.restart();
        m
    }

    /// A fresh handshake under a new nonce.
    fn restart(&mut self) {
        self.cn = rand16();
        self.made = Instant::now();
        let payload = handshake::join_payload(handshake::now_secs(), self.auth.token.as_ref());
        // No host key (refused before this runs) or an invalid one: no JOIN at all.
        self.hs = self.auth.host_key.and_then(|hk| handshake::ClientHs::new(&self.base, &hk, &payload).ok());
        self.join = self.hs.as_ref().map(|hs| join_dgram(&self.base, &self.cn, &hs.msg1)).unwrap_or_default();
    }
}

/// Client address allocator over 10.7.0.0/16: slot `i` is offset `i + 2`
/// (10.7.0.0 is the network, 10.7.0.1 the host).
pub struct AddrPool {
    used: Vec<bool>,
}

impl AddrPool {
    pub fn new(max: usize) -> Self {
        Self { used: vec![false; max.clamp(1, MUX_MAX_CLIENTS)] }
    }

    pub fn capacity(&self) -> usize {
        self.used.len()
    }

    pub fn in_use(&self) -> usize {
        self.used.iter().filter(|u| **u).count()
    }

    /// Lowest free slot and its address.
    pub fn alloc(&mut self) -> Option<(usize, Ipv4Addr)> {
        let slot = self.used.iter().position(|u| !*u)?;
        self.used[slot] = true;
        Some((slot, Self::addr_of(slot)))
    }

    pub fn free(&mut self, slot: usize) {
        if let Some(u) = self.used.get_mut(slot) {
            *u = false;
        }
    }

    pub fn addr_of(slot: usize) -> Ipv4Addr {
        let off = slot + 2;
        Ipv4Addr::new(10, 7, (off >> 8) as u8, (off & 0xff) as u8)
    }

    pub fn slot_of(ip: Ipv4Addr) -> Option<usize> {
        let [a, b, hi, lo] = ip.octets();
        let off = (hi as usize) << 8 | lo as usize;
        (a == 10 && b == 7 && off >= 2).then(|| off - 2)
    }
}

/// Non-blocking token bucket: over-rate packets are dropped, never delayed,
/// so one noisy peer cannot stall the shared loop.
struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: u64) -> Self {
        Self { rate: rate as f64, tokens: rate as f64, last: Instant::now() }
    }

    fn allow(&mut self, bytes: usize) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.rate);
        self.last = now;
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

struct Peer {
    addr: SocketAddr,
    /// Index of the carrier this peer arrived on; replies leave on the same one.
    via: usize,
    ip: Ipv4Addr,
    cn: [u8; 16],
    /// The client's ephemeral key (start of its Noise message): tells a retry from a replay.
    cpub: [u8; 32],
    /// The ACCEPT this join got, repeated for a retried JOIN.
    accept: Vec<u8>,
    /// The personal invite this peer joined with, if any.
    guest: Option<u32>,
    crypto: AeadSession,
    last_rx: Instant,
    last_tx: Instant,
    rx: Bucket,
    tx: Bucket,
    /// Joined at; a peer that sends nothing under its session key is dropped after
    /// `MUX_UNCONFIRMED_TTL` (a replayed JOIN cannot produce such a packet).
    since: Instant,
    /// When the ACCEPT was last sent again for a duplicate JOIN.
    resent: Instant,
    confirmed: bool,
}

#[derive(Clone, Debug)]
pub struct MuxConfig {
    pub max_clients: usize,
    /// Per-peer cap in bytes/sec, each direction (0 = unlimited).
    pub rate_bytes: u64,
    pub keepalive: Duration,
    pub timeout: Duration,
    /// Rendezvous server to stay registered with (host behind NAT).
    pub signal: Option<SocketAddr>,
    /// Keep the NAT mapping open with a public STUN poke (no signal only).
    pub stun: bool,
    pub bind_port: Option<u16>,
    /// Find clients through rendezvous methods and fire at them (host behind a restrictive NAT).
    /// Implies `stun`: the announced endpoint is the STUN mapping of this socket.
    pub rv: Option<RvHost>,
    /// Also listen on raw UDP at `bind_port` (default true). Off only for a host that serves
    /// other carriers exclusively.
    pub udp: bool,
    /// Further carriers to serve next to UDP. Replies leave on the carrier the peer arrived on.
    /// STUN, signal registration and NAT keepalive stay on the raw UDP carrier.
    pub carriers: IoList,
    /// Carriers (`ss`, `awg`) served on the plain UDP socket itself instead of one of their own:
    /// the only socket a rendezvous method publishes and punches from. Needs `udp`.
    pub shared: Vec<CarrierId>,
    /// Port spraying at client candidates (cone host <- symmetric client).
    pub birthday: Birthday,
    /// The host's private key. `None`: derived from the invite key (an invite without a host key).
    pub host_key: Option<[u8; 32]>,
    /// Who may join beyond holding the invite.
    pub guests: GuestPolicy,
}

/// Admission rules for personal invites. The default admits every invite holder.
#[derive(Clone, Debug, Default)]
pub struct GuestPolicy {
    /// Refuse joins without a valid personal token (shared, so it can change while hosting).
    pub require_token: Arc<AtomicBool>,
    /// Ids of withdrawn personal invites (shared, so it can change while hosting).
    pub revoked: Arc<std::sync::Mutex<HashSet<u32>>>,
}

/// Carriers handed to a [`MuxHost`].
#[derive(Clone, Default)]
pub struct IoList(pub Vec<Arc<dyn FrameIo>>);

impl std::fmt::Debug for IoList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|c| c.caps().id)).finish()
    }
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_clients: 8,
            rate_bytes: 0,
            keepalive: MUX_KEEPALIVE,
            timeout: MUX_TIMEOUT,
            signal: None,
            stun: false,
            bind_port: None,
            rv: None,
            udp: true,
            carriers: IoList::default(),
            shared: Vec::new(),
            birthday: Birthday::default(),
            host_key: None,
            guests: GuestPolicy::default(),
        }
    }
}

/// Live rendezvous session of a [`MuxHost`]: one runner per STUN-mapped endpoint.
struct RvState {
    backends: Vec<Arc<dyn Rendezvous>>,
    key: [u8; 16],
    /// Signs this host's records.
    host_key: [u8; 32],
    /// The identifier period the runner publishes under; a new day restarts it.
    epoch: u32,
    v6: Option<std::net::Ipv6Addr>,
    /// Whether client candidates in IPv6 are worth firing at (this host routes IPv6).
    v6_route: bool,
    local: Vec<SocketAddr>,
    handle: Option<RunnerHandle>,
    publisher: Option<JoinHandle<()>>,
}

impl RvState {
    fn restart(&mut self, local: Vec<SocketAddr>) {
        self.handle = None; // dropping cancels the old runner; its backends clean up on their own
        if let Some(p) = self.publisher.take() {
            p.abort();
        }
        log::info!("rendezvous: announcing {:?}", local);
        let ctx = RvCtx::new(self.key, Role::Host, local.clone()).with_keys(Some(self.host_key), None);
        self.epoch = ctx.epoch;
        let h = Runner::new(self.backends.clone()).start(ctx);
        self.publisher = Some(spawn_publisher("host", &h));
        self.handle = Some(h);
        self.local = local;
    }
}

/// A client endpoint the host is firing at so the client's JOIN passes the host's NAT filter.
type PunchTarget = Target;

#[derive(Clone, Debug)]
pub enum MuxEvent {
    /// `guest`: the personal invite the client used, if any.
    Joined { id: usize, ip: Ipv4Addr, from: SocketAddr, guest: Option<u32> },
    /// A validated IPv4 packet whose source is the peer's assigned address.
    Packet { id: usize, data: Vec<u8> },
    Left { id: usize, ip: Ipv4Addr, reason: &'static str },
}

/// One UDP port, one room, N peers.
pub struct MuxHost {
    /// Raw UDP first (when enabled), then the configured carriers.
    ios: Vec<Arc<dyn FrameIo>>,
    /// A carrier that failed for good (not UDP): skipped by the receive loop.
    dead: Vec<AtomicBool>,
    /// A stream carrier with no connection reports an error until one arrives: poll it slowly
    /// instead of spinning.
    muted: Vec<std::sync::Mutex<Option<Instant>>>,
    was_down: Vec<bool>,
    rr: usize,
    /// The plain UDP carrier: signal registration, STUN and the NAT keepalive live here.
    udp_io: Option<usize>,
    /// Ports of the plain UDP socket that `shared` carriers read from.
    ports: Vec<Arc<Port>>,
    /// Where T_PUNCH goes: the UDP carrier, else the first punchable one (through its wrapping).
    punch_io: Option<usize>,
    /// The raw socket of `udp_io` is dual-stack (STUN servers are addressed v4-mapped).
    dual: bool,
    oversize: DropCount,
    base: [u8; 32],
    /// Private half of the host key; `token_key` derives from it.
    host_key: [u8; 32],
    token_key: [u8; 32],
    cfg: MuxConfig,
    pool: AddrPool,
    peers: Vec<Option<Peer>>,
    /// Ephemeral keys of JOINs already read (see [`join_epk`]), oldest first in `seen_order`.
    seen: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    /// When this host started (Unix seconds): see [`handshake::fresh_since`].
    started: u32,
    limit: JoinLimit,
    refusals: VecDeque<Refusal>,
    events: VecDeque<MuxEvent>,
    signal: Option<SocketAddr>,
    room: u32,
    /// The invite key when `room` derives from it: the room changes with the UTC day.
    room_key: Option<String>,
    last_register: Instant,
    /// STUN servers poked to keep the mapping alive (and, with rendezvous, to learn it).
    stun: Vec<SocketAddr>,
    /// The server whose answers are trusted for `mapped` once two servers agreed.
    stun_pin: Option<SocketAddr>,
    /// Answers so far, per server, until two servers agree on this host's public address.
    stun_votes: HashMap<SocketAddr, SocketAddr>,
    mapped: Option<SocketAddr>,
    last_stun_poke: Instant,
    rv: Option<RvState>,
    punch: Vec<PunchTarget>,
    spray: Sprayer,
    /// Addresses port-sprayed in the last hour (bounded, see `SPRAY_IPS_PER_HOUR`).
    sprayed: std::collections::HashMap<IpAddr, Instant>,
    /// IPs punched in the last hour, with the ports (bounded, see `PUNCH_IPS_PER_HOUR`).
    punched: std::collections::HashMap<IpAddr, (Instant, Vec<u16>)>,
    sent_bytes: u64,
    received_bytes: u64,
}

impl MuxHost {
    pub async fn bind(key: &str, cfg: MuxConfig) -> io::Result<Self> {
        let bind_port = cfg.bind_port.or_else(|| {
            std::env::var("NAT_TUNNEL_BIND_PORT").ok().and_then(|v| v.parse::<u16>().ok())
        });
        let mut ios: Vec<Arc<dyn FrameIo>> = Vec::new();
        let mut dual = false;
        if cfg.udp {
            let (socket, d) = bind_marked(bind_port).await?;
            dual = d;
            ios.push(Arc::new(UdpCarrier::from_socket(socket, d)));
        }
        ios.extend(cfg.carriers.0.iter().cloned());
        let mut ports = Vec::new();
        for id in &cfg.shared {
            let Some(raw) = ios.iter().find(|io| io.caps().id == CarrierId::Udp).cloned() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the {id} carrier without its own address rides the plain UDP socket, which is off (--no-udp)"),
                ));
            };
            let port = Port::new(raw)?;
            let io: Arc<dyn FrameIo> = match id {
                #[cfg(feature = "cr-ss")]
                CarrierId::Ss => Arc::new(crate::carrier::ss::SsCarrier::over(port.clone(), key)?),
                #[cfg(feature = "cr-awg")]
                CarrierId::Awg => Arc::new(crate::carrier::awg::AwgCarrier::over(port.clone(), key)),
                other => {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the {other} carrier cannot ride the plain UDP socket")))
                }
            };
            ports.push(port);
            ios.push(io);
        }
        if ios.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no carrier to listen on"));
        }
        let udp_io = ios.iter().position(|io| io.caps().id == CarrierId::Udp);
        let punch_io = udp_io.or_else(|| ios.iter().position(|io| io.caps().punchable));
        if udp_io.is_none() && (cfg.signal.is_some() || cfg.stun || cfg.rv.is_some()) {
            log::warn!("signal server, STUN and rendezvous need the plain UDP carrier; skipped");
        }
        let pool = AddrPool::new(cfg.max_clients);
        let sidecar_joins = pool.capacity() as u32 * 2;
        let mut host = Self {
            dead: ios.iter().map(|_| AtomicBool::new(false)).collect(),
            muted: ios.iter().map(|_| std::sync::Mutex::new(None)).collect(),
            was_down: vec![false; ios.len()],
            rr: 0,
            udp_io,
            ports,
            punch_io,
            oversize: DropCount::default(),
            ios,
            dual,
            base: mux_base(key),
            host_key: cfg.host_key.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the host needs its host key"))?,
            token_key: [0; 32],
            peers: (0..pool.capacity()).map(|_| None).collect(),
            pool,
            signal: cfg.signal.filter(|_| udp_io.is_some()),
            room: relay::room_for_key(key),
            room_key: Some(key.to_string()),
            last_register: Instant::now(),
            stun: Vec::new(),
            stun_pin: None,
            stun_votes: HashMap::new(),
            mapped: None,
            last_stun_poke: Instant::now(),
            rv: None,
            punch: Vec::new(),
            spray: Sprayer::new(cfg.birthday.clone()),
            sprayed: Default::default(),
            punched: Default::default(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            started: handshake::now_secs(),
            limit: JoinLimit { sidecar: sidecar_joins, ..Default::default() },
            refusals: VecDeque::new(),
            events: VecDeque::new(),
            sent_bytes: 0,
            received_bytes: 0,
            cfg,
        };
        host.token_key = handshake::token_key(&host.host_key, key);
        if let Some(rv) = host.cfg.rv.clone().filter(|_| udp_io.is_some()) {
            let backends = match &rv.backends {
                Some(b) => b.iter().filter(|b| b.id() != "sig").cloned().collect(),
                None => {
                    let ids: Vec<String> = rv.ids.iter().filter(|i| *i != "sig").cloned().collect();
                    rendezvous::by_ids(&ids, &rv.cfg)
                }
            };
            match rendezvous::derive::parse_key(key) {
                Some(kb) if !backends.is_empty() => {
                    host.rv = Some(RvState {
                        backends,
                        key: kb,
                        host_key: host.host_key,
                        epoch: 0,
                        v6: if rv.no_v6 || !host.dual { None } else { global_v6() },
                        v6_route: host.dual && has_v6_route(),
                        local: Vec::new(),
                        handle: None,
                        publisher: None,
                    });
                }
                Some(_) => log::warn!("rendezvous: none of the chosen methods is available"),
                None => log::warn!("rendezvous needs a 32-hex-character invite key; skipped"),
            }
        }
        if host.signal.is_some() {
            host.register().await;
        }
        // Without a signal server the host keeps its mapping open with STUN; rendezvous also
        // needs the mapping itself, which the answers carry.
        if udp_io.is_some() && (host.cfg.stun || host.rv.is_some()) {
            host.stun = stun_servers().await;
            host.poke_stun().await;
        }
        Ok(host)
    }

    async fn poke_stun(&mut self) {
        self.last_stun_poke = Instant::now();
        let servers: Vec<SocketAddr> = match self.stun_pin {
            Some(p) => vec![p],
            None => self.stun.clone(),
        };
        let Some(sock) = self.udp_io.and_then(|i| self.ios[i].udp()) else { return };
        for s in servers {
            let _ = crate::tunnel::stun::poke(sock, to_wire(self.dual, s)).await;
        }
    }

    /// The public endpoint STUN reports for this socket, once an answer has arrived.
    pub fn mapped(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// Fire at a client endpoint learned through a rendezvous method, so its JOIN passes this
    /// host's NAT filter. Repeats for a bounded time; a known peer address is ignored.
    /// `verified`: the record came sealed with the invite key (an unsigned source such as a
    /// tracker or a signal server could name any address, so it gets nothing).
    pub fn add_punch_target(&mut self, addr: SocketAddr, verified: bool) {
        if !candidate_ok(addr) {
            log::debug!("rendezvous: client candidate {addr} is not a public address; ignored");
            return;
        }
        if !verified {
            log::debug!("rendezvous: client candidate {addr} came from an unsigned source; not punched");
            return;
        }
        if self.peers.iter().flatten().any(|p| p.addr == addr) {
            return;
        }
        // A guest's NAT maps it to a high port; a low one would only aim the host at a service.
        if addr.port() < 1024 {
            log::debug!("rendezvous: client candidate {addr} has a port below 1024; not punched");
            return;
        }
        let now = Instant::now();
        self.punched.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(3600));
        let ip = addr.ip().to_canonical();
        if !self.punched.contains_key(&ip) && self.punched.len() >= PUNCH_IPS_PER_HOUR {
            log::info!("rendezvous: {addr} not punched: {PUNCH_IPS_PER_HOUR} addresses punched in the last hour");
            return;
        }
        let ports = &mut self.punched.entry(ip).or_insert((now, Vec::new())).1;
        if !ports.contains(&addr.port()) {
            if ports.len() >= PUNCH_PORTS_PER_IP {
                log::info!("rendezvous: {addr} not punched: {PUNCH_PORTS_PER_IP} ports of that address punched in the last hour");
                return;
            }
            ports.push(addr.port());
        }
        match self.punch.iter_mut().find(|t| t.addr == addr) {
            Some(t) => {
                if t.first.elapsed() > RV_HOST_PUNCH_TOTAL {
                    t.first = Instant::now();
                    t.last = None;
                }
            }
            None => {
                if self.punch.len() >= RV_MAX_TARGETS {
                    self.punch.remove(0);
                }
                self.punch.push(Target { addr, verified, first: Instant::now(), last: None });
            }
        }
        // Even sealed records can come from any invite holder: spray (thousands of packets per
        // address) at a bounded number of distinct addresses per hour.
        self.sprayed.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
        let ip = addr.ip().to_canonical();
        if self.sprayed.contains_key(&ip) || self.sprayed.len() < SPRAY_IPS_PER_HOUR {
            self.sprayed.entry(ip).or_insert(now);
            self.spray.add(addr, RV_HOST_PUNCH_TOTAL);
        } else {
            log::info!("rendezvous: no port spray at {ip}: {SPRAY_IPS_PER_HOUR} addresses sprayed in the last hour");
        }
    }

    /// Restart the runner when the mapping changed and turn new client candidates into punch targets.
    fn rv_tick(&mut self) {
        let (mapped, port) = (self.mapped, self.local_port().unwrap_or(0));
        let mut found = Vec::new();
        if let (Some(rv), Some(m)) = (self.rv.as_mut(), mapped) {
            let mut want = vec![m];
            if let Some(v6) = rv.v6 {
                want.push(SocketAddr::new(v6.into(), port));
            }
            // A stream carrier that punches on its own port (TCP) is found at that port.
            for a in self.ios.iter().flat_map(|io| io.extra_candidates(m.ip())) {
                if !want.contains(&a) && want.len() < rendezvous::derive::MAX_CANDIDATES {
                    want.push(a);
                }
            }
            // shortcut: a guest whose clock is on the other side of midnight (UTC) than the host's
            // misses this host until both agree; its connect loop retries. Publish under both days
            // around midnight if that ever matters.
            if rv.handle.is_none() || want != rv.local || rv.epoch != rendezvous::derive::epoch_now() {
                rv.restart(want);
            }
        }
        if let Some(h) = self.rv.as_mut().and_then(|r| r.handle.as_mut()) {
            while let Some(c) = h.try_next() {
                found.push((c.addr, c.verified));
            }
        }
        let v6_route = self.rv.as_ref().is_some_and(|r| r.v6_route);
        for (a, verified) in found {
            if usable_family(a, v6_route) {
                self.add_punch_target(a, verified);
            } else {
                log::debug!("rendezvous: client candidate {a} skipped (no IPv6 route)");
            }
        }
    }

    /// Test hook: client endpoints currently being fired at.
    #[doc(hidden)]
    pub fn punch_targets(&self) -> Vec<SocketAddr> {
        self.punch.iter().map(|t| t.addr).collect()
    }

    /// Test hook: pretend this host does (not) route IPv6.
    #[doc(hidden)]
    pub fn set_v6_route(&mut self, on: bool) {
        if let Some(r) = self.rv.as_mut() {
            r.v6_route = on;
        }
    }

    /// Port of the plain UDP carrier (the first carrier when UDP is off).
    pub fn local_port(&self) -> io::Result<u16> {
        Ok(self.ios[self.udp_io.unwrap_or(0)].local_addr()?.port())
    }

    /// Local address of every carrier, in the order they were added.
    pub fn local_addrs(&self) -> Vec<(CarrierId, io::Result<SocketAddr>)> {
        self.ios.iter().map(|io| (io.caps().id, io.local_addr())).collect()
    }

    /// What every carrier can do.
    pub fn caps(&self) -> Vec<Caps> {
        self.ios.iter().map(|io| io.caps()).collect()
    }

    /// The TUN MTU that fits every carrier this host serves ([`effective_mtu`]).
    pub fn tun_mtu(&self) -> usize {
        effective_mtu(&self.caps())
    }

    /// Frames/packets refused for being too large for a carrier.
    pub fn oversize_drops(&self) -> u64 {
        self.oversize.total()
    }

    /// Per-carrier health; a carrier that failed for good is `Down`.
    pub fn carrier_status(&self) -> Vec<(CarrierId, Health)> {
        self.ios
            .iter()
            .enumerate()
            .map(|(i, io)| {
                let h = if self.dead[i].load(Ordering::Relaxed) {
                    Health::Down("receive failed".into())
                } else {
                    io.health()
                };
                (io.caps().id, h)
            })
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.pool.in_use()
    }

    pub fn bytes_sent(&self) -> u64 {
        self.sent_bytes
    }

    pub fn bytes_received(&self) -> u64 {
        self.received_bytes
    }

    /// Resolves when any live carrier has something to read.
    pub async fn readable(&self) -> io::Result<()> {
        let live: Vec<usize> = (0..self.ios.len()).filter(|&i| !self.dead[i].load(Ordering::Relaxed)).collect();
        let wait = |i: usize| async move {
            let until = *self.muted[i].lock().unwrap();
            match until.filter(|t| *t > Instant::now()) {
                Some(t) => {
                    tokio::time::sleep_until(t.into()).await;
                    (i, Ok(()))
                }
                None => (i, self.ios[i].readable().await),
            }
        };
        let (i, r) = match live[..] {
            [] => return std::future::pending().await,
            [i] => wait(i).await,
            _ => futures::future::select_all(live.iter().map(|&i| Box::pin(wait(i)))).await.0,
        };
        match r {
            Err(e) if self.udp_io == Some(i) => Err(e),
            Err(e) => {
                log::warn!("{} carrier stopped: {e}", self.ios[i].caps().id);
                self.dead[i].store(true, Ordering::Relaxed);
                Ok(())
            }
            ok => ok,
        }
    }

    async fn register(&mut self) {
        if let (Some(signal), Some(u)) = (self.signal, self.udp_io) {
            self.last_register = Instant::now();
            if let Some(room) = self.room_key.as_deref().map(relay::room_for_key).filter(|r| *r != self.room) {
                let _ = self.ios[u].send_to(&relay::encode_deregister(self.room, 0), signal).await;
                self.room = room; // a new UTC day: guests starting now look in the new room
            }
            let _ = self.ios[u].send_to(&relay::encode_register(self.room, 0), signal).await;
        }
    }

    /// Send one frame through carrier `via` (its wrapping applies). Too large is counted.
    async fn raw_send(&mut self, d: &[u8], to: SocketAddr, via: usize) {
        self.sent_bytes += d.len() as u64;
        let Some(io) = self.ios.get(via) else { return };
        if let Err(e) = io.send_to(d, to).await {
            match CarrierError::from_io(&e) {
                Some(CarrierError::FrameTooLarge { max }) => self.oversize.note(d.len(), *max, io.caps().id),
                _ => log::debug!("{} send to {to} failed: {e}", io.caps().id),
            }
        }
    }

    /// Seal `plain` for peer `slot` and send it.
    async fn send_sealed(&mut self, slot: usize, plain: &[u8]) {
        let Some(p) = self.peers.get_mut(slot).and_then(|p| p.as_mut()) else { return };
        let d = p.crypto.seal(plain);
        p.last_tx = Instant::now();
        let (to, via) = (p.addr, p.via);
        let mut out = Vec::with_capacity(3 + d.len());
        out.push(T_DATA);
        out.extend_from_slice(&(slot as u16).to_be_bytes());
        out.extend_from_slice(&d);
        self.raw_send(&out, to, via).await;
    }

    /// Send one IP packet to a peer. Returns false when dropped (unknown peer
    /// or over its rate cap).
    pub async fn send_to_peer(&mut self, id: usize, packet: &[u8]) -> bool {
        let Some(via) = self.peers.get(id).and_then(|p| p.as_ref()).map(|p| p.via) else { return false };
        let caps = self.ios[via].caps();
        if packet.len() > caps.tun_mtu() {
            self.oversize.note(packet.len() + Caps::SEAL_OVERHEAD, caps.max_frame, caps.id);
            return false;
        }
        match self.peers.get_mut(id).and_then(|p| p.as_mut()) {
            Some(p) => {
                if !p.tx.allow(packet.len()) {
                    return false;
                }
            }
            None => return false,
        }
        self.send_sealed(id, packet).await;
        true
    }

    /// Route by destination address.
    pub async fn send_to_ip(&mut self, ip: Ipv4Addr, packet: &[u8]) -> bool {
        match AddrPool::slot_of(ip) {
            Some(id) => self.send_to_peer(id, packet).await,
            None => false,
        }
    }

    fn remember(&mut self, epk: [u8; 32]) {
        if self.seen.insert(epk) {
            self.seen_order.push_back(epk);
            if self.seen_order.len() > SEEN_CN_CAP {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    fn evict(&mut self, slot: usize, reason: &'static str) {
        if let Some(p) = self.peers.get_mut(slot).and_then(|p| p.take()) {
            self.pool.free(slot);
            if p.confirmed {
                self.events.push_back(MuxEvent::Left { id: slot, ip: p.ip, reason });
            }
        }
    }

    async fn send_assign(&mut self, slot: usize) {
        let ip = AddrPool::addr_of(slot).octets();
        let gw = MUX_HOST_IP.octets();
        let plain = [C_ASSIGN, ip[0], ip[1], ip[2], ip[3], MUX_PREFIX, gw[0], gw[1], gw[2], gw[3]];
        self.send_sealed(slot, &plain).await;
    }

    /// True when `d` is a JOIN authenticated with the invite key (whatever came of it).
    async fn handle_join(&mut self, d: &[u8], from: SocketAddr, via: usize) -> bool {
        let Some((cn, msg1)) = split_join(&self.base, d) else { return false };
        self.join_authenticated(cn, &msg1, from, via).await;
        true
    }

    /// Answer a refused join. The refusal is Noise message 2, so only this host can send it.
    async fn refuse(&mut self, hs: handshake::HostHs, cn: &[u8; 16], verdict: u8, to: SocketAddr, via: usize) {
        if let Ok((msg2, _)) = hs.write(&verdict_payload(0, cn, verdict)) {
            let d = accept_dgram(&self.base, cn, &msg2);
            self.raw_send(&d, to, via).await;
            if self.refusals.len() >= REFUSALS_KEPT {
                self.refusals.pop_front();
            }
            self.refusals.push_back(Refusal { cn: *cn, to, dgram: d, sent: Instant::now() });
        }
    }

    async fn join_authenticated(&mut self, cn: [u8; 16], msg1: &[u8], from: SocketAddr, via: usize) {
        let cpub = join_epk(msg1);
        // Duplicate JOIN from the peer's own address: repeat ACCEPT + ASSIGN.
        // A JOIN for a known cn from elsewhere is a replay; ignore it.
        if let Some(slot) = (0..self.peers.len())
            .find(|&i| self.peers[i].as_ref().is_some_and(|p| p.cn == cn))
        {
            let p = self.peers[slot].as_mut().unwrap();
            // At most once a second, so a replayed JOIN cannot make the host send the guest more
            // than it sends.
            if p.addr == from && p.via == via && p.cpub == cpub && p.resent.elapsed() >= Duration::from_secs(1) {
                p.resent = Instant::now();
                let accept = p.accept.clone();
                self.raw_send(&accept, from, via).await;
                self.send_assign(slot).await;
            }
            return;
        }
        if self.seen.contains(&cpub) {
            // A retry of a refused JOIN gets the same refusal (at most once a second, only to
            // where the first went); any other known JOIN is a replay and gets nothing.
            if let Some(r) = self.refusals.iter_mut().find(|r| r.cn == cn && r.to == from) {
                if r.sent.elapsed() >= Duration::from_secs(1) {
                    r.sent = Instant::now();
                    let d = r.dgram.clone();
                    self.raw_send(&d, from, via).await;
                }
            }
            return;
        }
        if !self.limit.allow(from) {
            log::debug!("join from {from} ignored: too many new joins from its network");
            return;
        }
        let Ok((hs, payload)) = handshake::HostHs::read(&self.base, &self.host_key, msg1) else {
            log::debug!("join from {from}: the handshake message does not open (another host key, or damaged)");
            return;
        };
        // Remembered before any verdict: a recorded JOIN, fresh or stale, costs one key exchange.
        // Keyed on the ephemeral key, not on `cn`: `cn` is outside Noise, so any invite holder could
        // re-wrap a captured message 1 under a fresh one.
        self.remember(cpub);
        let Some((ts, token)) = handshake::parse_join_payload(&payload) else { return };
        let now = handshake::now_secs();
        if !handshake::fresh_since(ts, now, self.started) {
            // A replay, or a client with a wrong clock.
            log::info!("refused {from}: its JOIN is stale (clock off by more than {} s, or made before this host started)", handshake::JOIN_MAX_SKEW);
            return self.refuse(hs, &cn, VERDICT_CLOCK, from, via).await;
        }
        // Personal invite: who is this, and may they still come in?
        let guest = if token.is_empty() {
            None
        } else {
            match handshake::verify(&self.token_key, token, now) {
                Ok(t) if !self.cfg.guests.revoked.lock().unwrap().contains(&t.id) => {
                    if !self.limit.allow_invite(t.id) {
                        log::info!("join from {from} ignored: personal invite {} started too many sessions", t.id);
                        return;
                    }
                    Some(t.id)
                }
                r => {
                    log::info!("refused {from}: personal invite {}", match r {
                        Ok(_) => "was withdrawn",
                        Err(handshake::TokenError::Expired) => "has expired",
                        Err(_) => "is not one of this host's",
                    });
                    return self.refuse(hs, &cn, VERDICT_REFUSED, from, via).await;
                }
            }
        };
        if guest.is_none() && self.cfg.guests.require_token.load(Ordering::Relaxed) {
            log::info!("refused {from}: this host only takes personal invites");
            return self.refuse(hs, &cn, VERDICT_REFUSED, from, via).await;
        }
        // A personal invite works on one device at a time, so a copy cannot hide behind its owner:
        // while the session is live, a join from another address is refused; a silent one is
        // replaced once the new join confirms (see `confirm`).
        if let Some(id) = guest {
            if self.peers.iter().flatten().any(|p| p.confirmed && p.guest == Some(id) && p.addr != from && p.last_rx.elapsed() < PERSONAL_LIVE) {
                log::info!("refused {from}: personal invite {id} is in use on another device");
                return self.refuse(hs, &cn, VERDICT_FULL, from, via).await;
            }
        }
        // One network (an IPv4 address, an IPv6 /48) may hold a bounded share of the slots
        // (sidecar joins have no known network and are not capped here).
        let src = source_net(from);
        let sidecar = via_sidecar(from);
        let same = move |a: SocketAddr| if sidecar { a == from } else { source_net(a) == src };
        let cap = (self.pool.capacity() * 3 / 4).max(MUX_MIN_PER_SOURCE);
        let held = |s: &Self| s.peers.iter().flatten().filter(|p| source_net(p.addr) == src).count();
        while !sidecar && held(self) >= cap {
            if !self.drop_unconfirmed(|p| source_net(p.addr) == src) {
                log::info!("rejected {from}: too many slots for one network");
                return self.refuse(hs, &cn, VERDICT_FULL, from, via).await;
            }
        }
        // Each source holds a few unconfirmed joins per invite; its own oldest makes room.
        let mine = move |p: &Peer| !p.confirmed && p.guest == guest && same(p.addr);
        while self.peers.iter().flatten().filter(|p| mine(p)).count() >= MUX_UNCONFIRMED_PER_INVITE && self.drop_unconfirmed(mine) {}
        // A full host frees an unconfirmed slot: this source's own, or one past its grace time,
        // so nobody can push out another source's join before it had the time to confirm. A
        // restarted client on the same address replaces its old slot once its first packet
        // confirms (see `confirm`), so a replayed JOIN cannot evict a bystander.
        let mut alloc = self.pool.alloc();
        if alloc.is_none() && self.drop_unconfirmed(|p| same(p.addr) || p.since.elapsed() >= UNCONFIRMED_GRACE) {
            alloc = self.pool.alloc();
        }
        let Some((slot, ip)) = alloc else {
            if self.peers.iter().flatten().any(|p| !p.confirmed) {
                // Busy with other sources' fresh joins: no answer and no memory of this one, so
                // the client's next retry is taken once a slot confirms or passes its grace time.
                self.seen.remove(&cpub);
                self.seen_order.retain(|c| *c != cpub);
                log::debug!("join from {from} deferred: every free slot holds a fresh unconfirmed join");
                return;
            }
            log::info!("rejected {from}: host is full");
            return self.refuse(hs, &cn, VERDICT_FULL, from, via).await;
        };
        let Ok((msg2, key)) = hs.write(&verdict_payload(slot as u16, &cn, VERDICT_OK)) else {
            self.pool.free(slot);
            return;
        };
        log::info!(
            "join request from {from}{}",
            if self.punch.iter().any(|t| t.addr == from) { "" } else { " (not an announced candidate: the client's NAT maps this destination to another port)" }
        );
        let accept = accept_dgram(&self.base, &cn, &msg2);
        self.peers[slot] = Some(Peer {
            addr: from,
            via,
            ip,
            cn,
            cpub,
            accept: accept.clone(),
            guest,
            crypto: AeadSession::from_key(&key, true),
            last_rx: Instant::now(),
            last_tx: Instant::now(),
            rx: Bucket::new(self.cfg.rate_bytes),
            tx: Bucket::new(self.cfg.rate_bytes),
            since: Instant::now(),
            resent: Instant::now(),
            confirmed: false,
        });
        self.raw_send(&accept, from, via).await;
        self.send_assign(slot).await;
    }

    /// Disconnect a client now (the host's "remove" button). It may join again unless its
    /// personal invite is also withdrawn.
    pub async fn kick(&mut self, slot: usize) {
        if self.peers.get(slot).is_some_and(|p| p.is_some()) {
            self.send_sealed(slot, &[C_BYE]).await;
            self.evict(slot, "removed by the host");
        }
    }

    /// Disconnect every client that joined with personal invite `id`.
    pub async fn kick_guest(&mut self, id: u32) {
        for slot in 0..self.peers.len() {
            if self.peers[slot].as_ref().is_some_and(|p| p.guest == Some(id)) {
                self.kick(slot).await;
            }
        }
    }

    /// First packet under the new session key: the join is real. Announce it, and let it replace
    /// an older peer of the same address (a restarted client).
    fn confirm(&mut self, slot: usize) {
        let Some(p) = self.peers[slot].as_mut() else { return };
        p.confirmed = true;
        let (ip, from, via, guest) = (p.ip, p.addr, p.via, p.guest);
        if let Some(old) = (0..self.peers.len()).find(|&i| {
            i != slot
                && self.peers[i].as_ref().is_some_and(|q| q.confirmed && ((q.addr == from && q.via == via) || (guest.is_some() && q.guest == guest)))
        }) {
            self.evict(old, "replaced by a new join");
        }
        log::info!("client {from} joined as {ip} via {}", self.ios[via].caps().id);
        self.events.push_back(MuxEvent::Joined { id: slot, ip, from, guest });
    }

    /// Free the oldest unconfirmed slot (of source `ip` when given). True when one was freed.
    fn drop_unconfirmed(&mut self, which: impl Fn(&Peer) -> bool) -> bool {
        let oldest = (0..self.peers.len())
            .filter(|&i| self.peers[i].as_ref().is_some_and(|p| !p.confirmed && which(p)))
            .min_by_key(|&i| self.peers[i].as_ref().map(|p| p.since));
        oldest.is_some_and(|i| {
            self.evict(i, "unconfirmed");
            true
        })
    }

    /// True when `d` opened under a peer's session.
    async fn handle_data(&mut self, d: &[u8], from: SocketAddr, via: usize) -> bool {
        if d.len() < 4 {
            return false;
        }
        let slot = u16::from_be_bytes([d[1], d[2]]) as usize;
        let Some(p) = self.peers.get_mut(slot).and_then(|p| p.as_mut()) else { return false };
        let Ok((plain, _)) = p.crypto.open(&d[3..]) else { return false };
        p.last_rx = Instant::now();
        let first = !p.confirmed;
        // The tag authenticates the peer, so a new source address is a NAT
        // rebinding, not a spoof.
        p.addr = from;
        p.via = via;
        if first {
            self.confirm(slot);
        }
        let Some(p) = self.peers.get_mut(slot).and_then(|p| p.as_mut()) else { return true };
        match plain.first() {
            Some(b) if b >> 4 == 4 => {
                if plain.len() < 20 || plain[12..16] != p.ip.octets() || !p.rx.allow(plain.len()) {
                    return true;
                }
                self.events.push_back(MuxEvent::Packet { id: slot, data: plain });
            }
            Some(&C_BYE) => self.evict(slot, "client left"),
            _ => {} // keepalive: last_rx already refreshed
        }
        true
    }

    /// Next event, draining the socket. `Ok(None)` means nothing is pending.
    pub async fn try_recv(&mut self) -> io::Result<Option<MuxEvent>> {
        let mut buf = [0u8; 2048];
        'next: loop {
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(e));
            }
            let n = self.ios.len();
            let mut got = None;
            for k in 0..n {
                let i = (self.rr + k) % n;
                if self.dead[i].load(Ordering::Relaxed)
                    || self.muted[i].lock().unwrap().is_some_and(|t| t > Instant::now())
                {
                    continue;
                }
                match self.ios[i].try_recv_from(&mut buf) {
                    Ok((l, f)) => {
                        self.rr = (i + 1) % n;
                        got = Some((i, l, f));
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset && self.udp_io == Some(i) => {
                        continue 'next
                    }
                    Err(e) if self.udp_io == Some(i) => return Err(e),
                    // An optional carrier failing must not stop the others.
                    Err(e) if matches!(CarrierError::from_io(&e), Some(CarrierError::Closed)) => {
                        log::warn!("{} carrier stopped: {e}", self.ios[i].caps().id);
                        self.dead[i].store(true, Ordering::Relaxed);
                    }
                    // One oversize datagram is dropped on its own; the carrier keeps serving.
                    Err(e) if matches!(CarrierError::from_io(&e), Some(CarrierError::FrameTooLarge { .. })) => {
                        log::debug!("{} carrier: dropped an oversize datagram", self.ios[i].caps().id);
                        continue 'next;
                    }
                    Err(e) => {
                        log::debug!("{} carrier: {e}", self.ios[i].caps().id);
                        *self.muted[i].lock().unwrap() = Some(Instant::now() + Duration::from_millis(50));
                    }
                }
            }
            let Some((via, len, from)) = got else { return Ok(None) };
            if len == 0 {
                continue;
            }
            self.received_bytes += len as u64;
            if self.udp_io == Some(via) && Some(from) == self.signal {
                if let Some(relay::Incoming::Peer { role: 1, addr }) = relay::decode_for(self.room, &buf[..len]) {
                    let known = self.peers.iter().flatten().any(|p| p.addr == addr);
                    if !known && candidate_ok(addr) {
                        if let Some(v) = self.punch_io {
                            self.raw_send(&[T_PUNCH], addr, v).await;
                        }
                    }
                }
                continue;
            }
            let claimed = match buf[0] {
                T_JOIN => self.handle_join(&buf[..len], from, via).await,
                T_DATA => self.handle_data(&buf[..len], from, via).await,
                _ if self.udp_io == Some(via)
                    && self.stun.contains(&from)
                    && self.stun_pin.is_none_or(|p| p == from) =>
                {
                    let m = crate::tunnel::stun::mapped_from_response(&buf[..len]);
                    if let Some(m) = m {
                        if self.stun_pin.is_none() {
                            self.stun_votes.insert(from, m);
                        }
                        // The address this host signs and every guest scans: one server's word
                        // is not enough unless it is the only one configured.
                        if self.stun_pin.is_some() || stun_agreed(&self.stun_votes, m, self.stun.len()) {
                            self.stun_pin = Some(from);
                            self.stun_votes.clear();
                            if self.mapped != Some(m) {
                                log::info!("STUN mapping of the host socket: {m}");
                            }
                            self.mapped = Some(m);
                            // A guest must not reach the router's own services or its port forwards.
                            crate::userspace::note_public_addr(m.ip());
                        }
                    }
                    m.is_some()
                }
                _ => len == 1 && buf[0] == T_PUNCH,
            };
            // What the plain protocol did not claim may be an ss / awg datagram for a carrier
            // that shares this socket; those keep what authenticates and drop the rest.
            if !claimed && self.udp_io == Some(via) {
                for p in &self.ports {
                    p.push(&buf[..len], from);
                }
            }
        }
    }

    /// Periodic work: signal registration, keepalives, eviction.
    pub async fn tick(&mut self) -> io::Result<()> {
        if self.signal.is_some() && self.last_register.elapsed() >= REGISTER_INTERVAL {
            self.register().await;
        }
        // Until the mapping is known, ask every second.
        let poke_every = if self.rv.is_some() && self.mapped.is_none() {
            Duration::from_secs(1)
        } else {
            STUN_POKE_INTERVAL
        };
        if !self.stun.is_empty() && self.last_stun_poke.elapsed() >= poke_every {
            self.poke_stun().await;
        }
        self.rv_tick();
        let now = Instant::now();
        let joined: Vec<SocketAddr> = self.peers.iter().flatten().map(|p| p.addr).collect();
        self.punch.retain(|t| now.duration_since(t.first) < RV_HOST_PUNCH_TOTAL && !joined.contains(&t.addr));
        for i in 0..self.punch.len() {
            if self.punch[i].due(now) {
                self.punch[i].last = Some(now);
                let addr = self.punch[i].addr;
                if let Some(v) = self.punch_io {
                    self.raw_send(&[T_PUNCH], addr, v).await;
                }
                for io in &self.ios {
                    io.punch(addr);
                }
            }
        }
        let ips: Vec<Ipv4Addr> = self
            .peers
            .iter()
            .flatten()
            .filter_map(|p| match p.addr.ip() {
                std::net::IpAddr::V4(v) => Some(v),
                _ => None,
            })
            .collect();
        self.spray.joined(&ips);
        for to in self.spray.due(now, RV_HOST_PUNCH_TOTAL) {
            if let Some(v) = self.punch_io {
                self.raw_send(&[T_PUNCH], to, v).await;
            }
        }
        for i in 0..self.ios.len() {
            let down = matches!(self.ios[i].health(), Health::Down(_));
            if down && !self.was_down[i] {
                let h = self.ios[i].health();
                // The last client of a stream carrier leaving (EOF / reset / no TLS close_notify) is routine.
                if matches!(&h, Health::Down(w) if routine_leave(w)) {
                    log::debug!("{} carrier has no client left: {h:?}", self.ios[i].caps().id);
                } else {
                    log::warn!("{} carrier is down: {h:?}", self.ios[i].caps().id);
                }
            }
            self.was_down[i] = down;
        }
        let (keepalive, timeout) = (self.cfg.keepalive, self.cfg.timeout);
        for p in self.peers.iter_mut().flatten() {
            p.crypto.age();
        }
        for slot in 0..self.peers.len() {
            let Some(p) = self.peers[slot].as_ref() else { continue };
            if !p.confirmed {
                if p.since.elapsed() >= MUX_UNCONFIRMED_TTL {
                    self.evict(slot, "unconfirmed");
                }
            } else if p.last_rx.elapsed() >= timeout {
                self.send_sealed(slot, &[C_BYE]).await;
                self.evict(slot, "timed out");
            } else if p.last_tx.elapsed() >= keepalive {
                self.send_sealed(slot, &[C_KEEPALIVE]).await;
            }
        }
        Ok(())
    }

    /// Tell every peer goodbye, leave the signaling room and withdraw from rendezvous services.
    pub async fn close(&mut self) {
        if let Some(mut rv) = self.rv.take() {
            if let Some(p) = rv.publisher.take() {
                p.abort();
            }
            if let Some(h) = rv.handle.take() {
                h.stop().await;
            }
            rendezvous::live::clear("host");
        }
        for _ in 0..2 {
            for slot in 0..self.peers.len() {
                self.send_sealed(slot, &[C_BYE]).await;
            }
            if let (Some(signal), Some(u)) = (self.signal, self.udp_io) {
                let d = relay::encode_deregister(self.room, 0);
                self.raw_send(&d, signal, u).await;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        for slot in 0..self.peers.len() {
            self.evict(slot, "host closed");
        }
        for io in &self.ios {
            io.close().await;
        }
    }
}

/// Bind the tunnel's UDP socket.
///
/// On Linux the socket carries [`crate::tunmode::TUNNEL_MARK`], so a guest with
/// a TUN default route keeps its own datagrams on the physical path (see
/// `tunmode::route_policy`). Elsewhere this is a plain bind.
async fn bind_marked(bind_port: Option<u16>) -> io::Result<(UdpSocket, bool)> {
    let port = bind_port.unwrap_or(0);

    #[cfg(target_os = "linux")]
    {
        let (socket, dual) = dual_socket(port)?;
        // A 512-frame window puts ~700 KiB in flight; default socket buffers
        // are far smaller and would drop the burst.
        let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
        if let Err(e) = socket.set_mark(crate::tunmode::TUNNEL_MARK) {
            log::debug!(
                "SO_MARK unavailable ({}); tunnel traffic follows the main route",
                e
            );
        }
        socket.set_nonblocking(true)?;
        return Ok((UdpSocket::from_std(socket.into())?, dual));
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;

        let (socket, dual) = dual_socket(port)?;
        let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
        if let Some(index) = crate::tunmode::physical_ifindex() {
            let value = index as libc::c_int;
            let rc = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    &value as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                log::debug!("IP_BOUND_IF failed: {}", io::Error::last_os_error());
            }
        }
        socket.set_nonblocking(true)?;
        return Ok((UdpSocket::from_std(socket.into())?, dual));
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET,
        };

        let (socket, dual) = dual_socket(port)?;
        let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
        if let Some(index) = crate::tunmode::physical_ifindex() {
            // IP_UNICAST_IF takes the interface index in network byte order.
            let value = index.to_be();
            let rc = unsafe {
                setsockopt(
                    socket.as_raw_socket() as SOCKET,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    &value as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as i32,
                )
            };
            if rc != 0 {
                log::debug!("IP_UNICAST_IF failed: {}", io::Error::last_os_error());
            }
        }
        socket.set_nonblocking(true)?;
        return Ok((UdpSocket::from_std(socket.into())?, dual));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        // Android lands here: honour the requested port (the host binds the one its check mapped).
        Ok((UdpSocket::bind(("0.0.0.0", port)).await?, false))
    }
}

/// Bind an IPv6 socket that also accepts IPv4, falling back to plain IPv4 when
/// the host has no IPv6 stack.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn dual_socket(port: u16) -> io::Result<(socket2::Socket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};

    // No SO_REUSEADDR/SO_REUSEPORT: a taken port must fail, not double-bind.
    let in_use = |e: io::Error| match e.kind() {
        io::ErrorKind::AddrInUse => io::Error::new(
            io::ErrorKind::AddrInUse,
            ConnectError::PortInUse(port),
        ),
        _ => e,
    };
    // macOS/BSD let a v4 wildcard and a dual-stack v6 wildcard coexist on one
    // port, so probe the v4 side first (a held port must not be shadowed).
    if port != 0 {
        let probe = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        probe
            .bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())
            .map_err(in_use)?;
    }
    if let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        // One socket for both families: an IPv6 peer addresses us directly,
        // an IPv4 peer arrives as a v4-mapped address.
        if socket.set_only_v6(false).is_ok() {
            let addr = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 0], port));
            match socket.bind(&addr.into()) {
                Ok(()) => return Ok((socket, true)),
                // Falling back to v4 here would silently shadow the other owner.
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Err(in_use(e)),
                Err(_) => {}
            }
        }
    }
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket
        .bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())
        .map_err(in_use)?;
    Ok((socket, false))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests {
    /// Unsigned targets are capped and never push out a signed one; a signed record upgrades an
    /// address an unsigned source reported first.
    #[test]
    fn unsigned_targets_are_capped_and_signed_ones_stay() {
        let mut t = Vec::new();
        add_target(&mut t, "198.51.100.1:5000".parse().unwrap(), true);
        for i in 0..100u16 {
            add_target(&mut t, format!("203.0.113.9:{}", 1000 + i).parse().unwrap(), false);
        }
        assert_eq!(t.iter().filter(|x| !x.verified).count(), RV_MAX_UNVERIFIED);
        assert!(t.iter().any(|x| x.verified && x.addr.port() == 5000));
        add_target(&mut t, "203.0.113.9:1099".parse().unwrap(), true);
        assert!(t.iter().any(|x| x.verified && x.addr.port() == 1099), "upgraded in place");
    }

    /// Forward mode serves one guest: another address cannot take a live session over, and the
    /// host's personal-invite rules apply there too.
    #[test]
    fn forward_host_keeps_a_live_session_and_applies_guest_rules() {
        let key = "fwd-takeover-test-key";
        let mut h = FwdHost::new(key, Some(TEST_HOST_KEY), GuestPolicy::default());
        let (a, b): (SocketAddr, SocketAddr) = ("203.0.113.1:1000".parse().unwrap(), "198.51.100.2:2000".parse().unwrap());
        let verdict = |hs: &mut handshake::ClientHs, cn: &[u8; 16], reply: &[u8]| open_accept(&mux_base(key), hs, cn, reply).unwrap().1;
        let (_, ja) = hs_join(key, &rand16(), JoinAuth::test());
        assert!(h.join(&ja, a).unwrap().1.is_some());
        h.heard(a);
        let cn = rand16();
        let (mut hb, jb) = hs_join(key, &cn, JoinAuth::test());
        let (reply, k) = h.join(&jb, b).unwrap();
        assert!(k.is_none());
        assert_eq!(verdict(&mut hb, &cn, &reply), VERDICT_FULL, "another address while the session is live");
        let (_, ja2) = hs_join(key, &rand16(), JoinAuth::test());
        assert!(h.join(&ja2, "203.0.113.1:1001".parse().unwrap()).unwrap().1.is_none(), "the same IP, another port: behind one carrier-grade NAT that can be someone else");
        // A retry of the current JOIN is answered only at the guest's own address.
        assert!(h.join(&ja, a).unwrap().1.is_none() && h.join(&ja, b).is_none());
        h.guest = Some((a, Instant::now() - FWD_TAKEOVER_AFTER));
        let (_, jc) = hs_join(key, &rand16(), JoinAuth::test());
        assert!(h.join(&jc, b).unwrap().1.is_some(), "after the guest went quiet");
        // Personal invites only: the shared invite is refused.
        let mut strict = FwdHost::new(key, Some(TEST_HOST_KEY), GuestPolicy { require_token: Arc::new(true.into()), ..Default::default() });
        let cn = rand16();
        let (mut hs, j) = hs_join(key, &cn, JoinAuth::test());
        let (reply, k) = strict.join(&j, a).unwrap();
        assert!(k.is_none());
        assert_eq!(verdict(&mut hs, &cn, &reply), VERDICT_REFUSED);
    }

    /// Invite holders can seal client records naming anyone: the host punches at most
    /// `PUNCH_IPS_PER_HOUR` addresses and `PUNCH_PORTS_PER_IP` ports of each an hour, and never a
    /// port below 1024.
    #[tokio::test]
    async fn host_punch_targets_are_bounded() {
        let mut h = MuxHost::bind("punch-budget-key", MuxConfig { bind_port: Some(0), host_key: Some(TEST_HOST_KEY), ..Default::default() }).await.unwrap();
        h.add_punch_target("203.0.113.9:443".parse().unwrap(), true);
        assert!(h.punch.is_empty(), "port below 1024");
        for i in 0..20u16 {
            h.add_punch_target(SocketAddr::new(Ipv4Addr::new(203, 0, 113, 9).into(), 2000 + i), true);
        }
        assert_eq!(h.punch.len(), PUNCH_PORTS_PER_IP, "ports of one address");
        for i in 0..PUNCH_IPS_PER_HOUR as u32 + 10 {
            h.add_punch_target(SocketAddr::new(Ipv4Addr::from(0xcb00_7100 + i).into(), 5000), true);
        }
        assert_eq!(h.punched.len(), PUNCH_IPS_PER_HOUR);
    }

    /// A captured message 1 re-wrapped under a fresh `cn` (any invite holder can make the outer
    /// tag) is a replay: no key exchange, no slot, no answer.
    #[tokio::test]
    async fn a_rewrapped_join_is_a_replay() {
        let key = "rewrap-test-key";
        let mut h = MuxHost::bind(key, MuxConfig { bind_port: Some(0), host_key: Some(TEST_HOST_KEY), ..Default::default() }).await.unwrap();
        let (hs, d) = hs_join(key, &rand16(), JoinAuth::test());
        let from: SocketAddr = "203.0.113.7:1000".parse().unwrap();
        assert!(h.handle_join(&d, from, 0).await);
        assert_eq!(h.peer_count(), 1);
        for to in [from, "198.51.100.1:9".parse().unwrap()] {
            let rewrapped = join_dgram(&mux_base(key), &rand16(), &hs.msg1);
            assert!(h.handle_join(&rewrapped, to, 0).await, "the outer tag is valid");
        }
        assert_eq!(h.peer_count(), 1, "no second slot");
        // Forward mode: the same.
        let mut f = FwdHost::new(key, Some(TEST_HOST_KEY), GuestPolicy::default());
        let (hs, d) = hs_join(key, &rand16(), JoinAuth::test());
        assert!(f.join(&d, from).unwrap().1.is_some());
        assert!(f.join(&join_dgram(&mux_base(key), &rand16(), &hs.msg1), from).is_none());
    }

    /// Many senders cannot lock everyone out of joining; IPv6 counts per /48; a personal invite
    /// has its own budget.
    #[test]
    fn the_join_limiter_never_locks_everyone_out() {
        let mut l = JoinLimit::default();
        for i in 0..5000u16 {
            l.allow(SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 7, i, 0, 0, 0, 1).into(), 1));
        }
        assert_eq!(l.at.len(), 1, "one /48 is one network");
        assert!(!l.allow("[2001:db8:7:ffff::9]:1".parse().unwrap()), "and its budget is spent");
        for i in 0..10_000u32 {
            l.allow(SocketAddr::new(Ipv4Addr::from(0x0a00_0000 + i).into(), 1));
        }
        assert!(l.at.len() <= JOIN_LIMIT_NETS);
        assert!(l.allow("198.51.100.9:1".parse().unwrap()), "a newcomer still gets in");
        assert!((0..JOIN_LIMIT).all(|_| l.allow_invite(7)) && !l.allow_invite(7) && l.allow_invite(8));
    }

    /// A recorded JOIN, however old, costs the host one key exchange: its nonce is remembered
    /// before the verdict, and a replay from elsewhere gets nothing.
    #[tokio::test]
    async fn a_stale_join_is_answered_once() {
        let key = "stale-join-test-key";
        let mut h = MuxHost::bind(key, MuxConfig { bind_port: Some(0), host_key: Some(TEST_HOST_KEY), ..Default::default() }).await.unwrap();
        let cn = rand16();
        let (hs, _) = hs_join_at(key, &cn, JoinAuth::test(), Some(handshake::now_secs() - 3600));
        let from: SocketAddr = "203.0.113.7:1000".parse().unwrap();
        h.join_authenticated(cn, &hs.msg1, from, 0).await;
        assert!(h.seen.contains(&join_epk(&hs.msg1)) && h.refusals.len() == 1);
        h.join_authenticated(cn, &hs.msg1, "198.51.100.1:9".parse().unwrap(), 0).await;
        h.join_authenticated(cn, &hs.msg1, from, 0).await;
        assert_eq!(h.refusals.len(), 1, "no second key exchange");
        assert_eq!(h.peer_count(), 0);
    }

    #[test]
    fn a_guest_needs_a_usable_host_key() {
        assert_eq!(check_host_key(&JoinAuth::default()), Err(NO_HOST_KEY));
        let bad = JoinAuth { host_key: Some([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ..Default::default() };
        assert_eq!(check_host_key(&bad), Err(BAD_HOST_KEY), "a low-order point");
        assert_eq!(check_host_key(&JoinAuth::test()), Ok(()));
    }

    #[test]
    fn a_stun_mapping_needs_two_servers_unless_one_is_configured() {
        let s = |a: &str| -> SocketAddr { a.parse().unwrap() };
        let mut v = HashMap::new();
        v.insert(s("192.0.2.1:3478"), s("203.0.113.5:4000"));
        assert!(!stun_agreed(&v, s("203.0.113.5:4000"), 3), "one server's word");
        assert!(stun_agreed(&v, s("203.0.113.5:4000"), 1), "the only configured server");
        v.insert(s("192.0.2.2:3478"), s("198.51.100.9:4000"));
        assert!(!stun_agreed(&v, s("198.51.100.9:4000"), 3), "two servers disagree");
        v.insert(s("192.0.2.3:3478"), s("203.0.113.5:4001"));
        assert!(stun_agreed(&v, s("203.0.113.5:4001"), 3), "same IP from two servers (port may differ)");
    }

    #[test]
    fn own_public_announce_is_ignored_but_lan_and_others_are_not() {
        let own: Vec<IpAddr> = vec!["203.0.113.7".parse().unwrap()];
        let yes = |a: &str| is_own_announce(a.parse().unwrap(), &own);
        assert!(yes("203.0.113.7:4000"), "own mapped IP, any port");
        assert!(yes("[::ffff:203.0.113.7]:4000"), "v4-mapped form");
        assert!(!yes("203.0.113.8:4000"), "another host");
        assert!(!yes("192.168.1.5:4000"), "LAN address stays a candidate");
        assert!(!is_own_announce("10.0.0.2:1".parse().unwrap(), &["10.0.0.2".parse().unwrap()]), "private is never own");
    }

    /// Slots per source address: confirmed joins from one non-loopback address stop at the cap
    /// (three quarters of the pool, at least 4); another address and loopback are unaffected.
    #[tokio::test]
    async fn slots_per_source_address_are_capped() {
        let key = "per-source-cap-test-key";
        let mut h = MuxHost::bind(key, MuxConfig { bind_port: Some(0), max_clients: 8, host_key: Some(TEST_HOST_KEY), ..Default::default() })
            .await
            .unwrap();
        async fn join(h: &mut MuxHost, from: &str) -> Option<usize> {
            let cn = rand16();
            let (hs, _) = hs_join("per-source-cap-test-key", &cn, JoinAuth::test());
            h.join_authenticated(cn, &hs.msg1, from.parse().unwrap(), 0).await;
            h.peers.iter().position(|p| p.as_ref().is_some_and(|p| p.cn == cn))
        }
        let mut slots = vec![];
        for i in 0..6 {
            let s = join(&mut h, &format!("203.0.113.7:{}", 1000 + i)).await.expect("under the cap");
            h.confirm(s);
            slots.push(s);
        }
        assert!(join(&mut h, "203.0.113.7:2000").await.is_none(), "over the cap");
        assert!(join(&mut h, "203.0.113.8:1000").await.is_some(), "another address is fine");
        // An unconfirmed join of the same source gives way to a newcomer instead of blocking it.
        h.evict(slots[0], "test");
        let a = join(&mut h, "203.0.113.7:3000").await.expect("freed slot");
        let b = join(&mut h, "203.0.113.7:3001").await.expect("replaces the unconfirmed one");
        assert!(h.peers[a].is_none() || a == b, "oldest unconfirmed was dropped");
        // Loopback (a sidecar) is exempt from the per-network cap. The pool is now full, and a
        // fresh unconfirmed join of another source is not pushed out within its grace time...
        assert!(join(&mut h, "127.0.0.1:4000").await.is_some(), "the last free slot");
        assert!(join(&mut h, "127.0.0.1:4001").await.is_none(), "others' fresh joins stay");
        // ...but once past it, it gives way.
        for p in h.peers.iter_mut().flatten() {
            p.since -= UNCONFIRMED_GRACE;
        }
        for i in 2..4 {
            assert!(join(&mut h, &format!("127.0.0.1:{}", 4000 + i)).await.is_some());
        }
    }

    #[test]
    fn client_leave_is_routine_but_sidecar_death_is_not() {
        assert!(super::routine_leave("connection reset: peer closed connection without sending TLS close_notify"));
        assert!(super::routine_leave("connection closed by peer"));
        assert!(!super::routine_leave("sidecar exited (1)"));
    }

    #[test]
    fn rendezvous_candidates_must_be_public() {
        let ok = |a: &str, local| super::candidate_allowed(a.parse().unwrap(), local);
        for a in ["8.8.8.8:7100", "203.0.113.10:1", "[2a01:4f9::1]:7100"] {
            assert!(ok(a, false), "{a}");
        }
        for a in [
            "127.0.0.1:7100", "10.1.2.3:7100", "172.16.0.1:7100", "192.168.1.1:80", "169.254.169.254:80",
            "100.64.0.1:7100", "[::1]:7100", "[fe80::1]:7100", "[fd00::1]:7100", "[::ffff:192.168.1.1]:80",
        ] {
            assert!(!ok(a, false), "{a}");
            assert!(ok(a, true), "{a} with the lab switch");
        }
        for a in ["8.8.8.8:0", "0.0.0.0:7100", "224.0.0.251:5353", "255.255.255.255:9", "240.0.0.1:9", "[::]:9", "[ff02::1]:9"] {
            assert!(!ok(a, false) && !ok(a, true), "{a}");
        }
    }

    use super::*;
    use std::net::UdpSocket as StdUdp;

    #[test]
    fn publishable_v6_rules() {
        let p = |s: &str, doc| is_publishable_v6(&s.parse().unwrap(), doc);
        assert!(!p("fe80::1", true));
        assert!(!p("fc00::1", true));
        assert!(!p("fd12:3456::1", true));
        assert!(!p("::1", true));
        assert!(!p("::", true));
        assert!(!p("ff02::1", true));
        assert!(!p("::ffff:1.2.3.4", true));
        assert!(!p("2001:db8::1", false));
        assert!(p("2001:db8::1", true));
        assert!(p("2a00:1450:4001:81b::200e", false));
        assert!(p("2606:4700:4700::1111", false));
    }

    #[test]
    fn order_is_v6_first_stable() {
        let a = |s: &str| -> SocketAddr { s.parse().unwrap() };
        let got = order_endpoints(&[a("1.1.1.1:1"), a("[2a00::1]:1"), a("2.2.2.2:1"), a("[2a00::2]:1")]);
        assert_eq!(got, vec![a("[2a00::1]:1"), a("[2a00::2]:1"), a("1.1.1.1:1"), a("2.2.2.2:1")]);
    }

    #[test]
    fn norm_unmaps_v4_and_keeps_v6() {
        let mapped: SocketAddr = "[::ffff:10.1.2.3]:99".parse().unwrap();
        assert_eq!(Tunnel::norm(mapped), "10.1.2.3:99".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:99".parse().unwrap();
        assert_eq!(Tunnel::norm(v6), v6);
    }

    #[test]
    fn dual_socket_serves_v4_and_v6_clients() {
        let (sock, dual) = dual_socket(0).expect("bind");
        if !dual {
            eprintln!("skip: no dual-stack socket on this host");
            return;
        }
        let sock: StdUdp = sock.into();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let port = sock.local_addr().unwrap().port();

        let v4 = StdUdp::bind("127.0.0.1:0").unwrap();
        v4.send_to(b"v4", ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 8];
        let (n, from) = sock.recv_from(&mut buf).expect("v4 client reaches socket");
        assert_eq!(&buf[..n], b"v4");
        assert!(from.ip().is_ipv6(), "v4 arrives v4-mapped on a dual socket");
        assert_eq!(Tunnel::norm(from), v4.local_addr().unwrap());

        match StdUdp::bind("[::1]:0") {
            Ok(v6) => {
                v6.send_to(b"v6", ("::1", port)).unwrap();
                let (n, from) = sock.recv_from(&mut buf).expect("v6 client reaches socket");
                assert_eq!(&buf[..n], b"v6");
                assert_eq!(Tunnel::norm(from), v6.local_addr().unwrap());
            }
            Err(e) => eprintln!("skip v6 assertion: no IPv6 loopback ({e})"),
        }
    }

    #[test]
    fn address_allocator_hands_out_and_reuses_slots() {
        let mut pool = AddrPool::new(3);
        assert_eq!(pool.alloc(), Some((0, Ipv4Addr::new(10, 7, 0, 2))));
        assert_eq!(pool.alloc(), Some((1, Ipv4Addr::new(10, 7, 0, 3))));
        assert_eq!(pool.alloc(), Some((2, Ipv4Addr::new(10, 7, 0, 4))));
        assert_eq!(pool.alloc(), None, "full");
        pool.free(1);
        assert_eq!(pool.alloc(), Some((1, Ipv4Addr::new(10, 7, 0, 3))), "lowest free slot");
        assert_eq!(pool.in_use(), 3);
    }

    #[test]
    fn address_allocator_ceiling_and_mapping() {
        let mut pool = AddrPool::new(5000);
        assert_eq!(pool.capacity(), MUX_MAX_CLIENTS);
        let mut seen = HashSet::new();
        while let Some((slot, ip)) = pool.alloc() {
            assert!(seen.insert(ip), "unique address {ip}");
            assert_ne!(ip, MUX_HOST_IP);
            assert_eq!(AddrPool::slot_of(ip), Some(slot));
        }
        assert_eq!(seen.len(), 1024);
        assert!(seen.contains(&Ipv4Addr::new(10, 7, 4, 1)));
        assert_eq!(AddrPool::slot_of(MUX_HOST_IP), None);
        assert_eq!(AddrPool::slot_of(Ipv4Addr::new(192, 168, 0, 5)), None);
    }

    /// One simulated join through the real handshake: (client session, host session, JOIN, ACCEPT).
    fn join(key: &str) -> (AeadSession, AeadSession, Vec<u8>, Vec<u8>) {
        let cn = rand16();
        let (mut hs, j) = hs_join(key, &cn, JoinAuth::test());
        let (accept, h) = hs_accept(key, TEST_HOST_KEY, 3, &j).expect("host answers");
        let (slot, c) = hs_finish(key, &mut hs, &cn, &accept).expect("client finishes");
        assert_eq!(slot, 3);
        (c, h, j, accept)
    }

    #[test]
    fn taken_udp_port_fails_loudly_for_either_family() {
        // Holder A: dual-stack (what a running host uses); holder B: plain v4.
        let (a, _) = dual_socket(0).unwrap();
        let port = a.local_addr().unwrap().as_socket().unwrap().port();
        let e = dual_socket(port).err().expect("second bind must fail");
        assert!(matches!(ConnectError::from_io(&e), Some(ConnectError::PortInUse(p)) if *p == port), "{e}");
        let b = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port_b = b.local_addr().unwrap().port();
        let e = dual_socket(port_b).err().expect("v4-held port must fail");
        assert!(matches!(ConnectError::from_io(&e), Some(ConnectError::PortInUse(_))), "{e}");
        assert_eq!(
            ConnectError::PortInUse(7100).to_string(),
            "UDP port 7100 is already in use by another process."
        );
    }

    #[test]
    fn peer_sessions_are_isolated() {
        let (mut client_a, mut host_a, ..) = join("invite-key");
        let (mut client_b, mut host_b, ..) = join("invite-key");

        let from_a = client_a.seal(b"secret of A");
        assert_eq!(host_b.open(&from_a), Err(CryptoError::BadTag), "B cannot read A");
        assert_eq!(host_a.open(&from_a).unwrap().0, b"secret of A");
        assert_eq!(host_a.open(&from_a), Err(CryptoError::Replay), "per-peer replay window");

        let to_b = host_b.seal(b"for B");
        assert_eq!(client_a.open(&to_b), Err(CryptoError::BadTag), "A cannot read B");
        assert_eq!(client_b.open(&to_b).unwrap().0, b"for B");
    }

    /// Mallory has the invite and a full capture of A's handshake, but not the host key: she
    /// cannot even read A's JOIN, let alone answer it.
    #[test]
    fn invite_holder_with_full_capture_cannot_derive_peer_key() {
        let (mut client_a, mut host_a, join_a, _accept_a) = join("invite-key");
        let sealed = client_a.seal(b"secret of A");
        assert!(hs_accept("invite-key", handshake::new_host_key(), 3, &join_a).is_none());
        assert_eq!(host_a.open(&sealed).unwrap().0, b"secret of A");
    }

    #[test]
    fn different_invite_key_derives_unrelated_session() {
        let (mut c, ..) = join("invite-key");
        let sealed = c.seal(b"x");
        let (_, mut other_host, ..) = join("other-key");
        assert_eq!(other_host.open(&sealed), Err(CryptoError::BadTag));
    }

    /// An invite that names a host key: the invite alone no longer lets anyone answer as the host.
    #[test]
    fn an_invite_with_a_host_key_binds_the_host() {
        let host = handshake::new_host_key();
        let auth = JoinAuth { host_key: Some(handshake::public_of(&host)), ..Default::default() };
        let cn = rand16();
        let (mut hs, j) = hs_join("invite-key", &cn, auth);
        // Another key (all an invite holder could have) cannot read the JOIN.
        assert!(hs_accept("invite-key", TEST_HOST_KEY, 0, &j).is_none());
        let (accept, mut h) = hs_accept("invite-key", host, 9, &j).expect("the real host answers");
        let (slot, mut c) = hs_finish("invite-key", &mut hs, &cn, &accept).unwrap();
        assert_eq!(slot, 9);
        assert_eq!(h.open(&c.seal(b"hi")).unwrap().0, b"hi");
    }
}
