//! `ss` carrier: our sealed frames ride as Shadowsocks-2022 (AEAD) UDP datagrams.
//!
//! Both ends embed the `shadowsocks` crate's `ProxySocket`; there is no `ssserver` process and
//! nothing is proxied. The SS "target address" is the constant [`PLACEHOLDER`]; the host delivers
//! the payload to its own `FrameIo` queue and drops any packet naming another target.
//!
//! * Key: SS-2022 PSK = HKDF(invite key, info `strait-ss-key`), 16 bytes, aes-128-gcm variant. It is
//!   never the AEAD or rendezvous key (see [`derive_psk`]). The invite key comes in
//!   `CarrierSpec.params` as `("key", <32 hex chars>)`.
//! * Peers: the host keys each client by its SS session id. The peer `SocketAddr` is the first
//!   source address that session was seen from and stays stable when the client roams; replies go
//!   to the latest validated source address.
//! * Replay: the crate checks AEAD and the 30 s timestamp but keeps no packet-id window, so this
//!   file does (128 packets, per session, both directions). Wrong key, garbage, truncated or
//!   replayed datagrams are dropped silently (no logging per packet).
//! * Rendezvous: an entry without `@host:port` rides the host's plain UDP socket (the one whose
//!   STUN mapping rendezvous publishes): the host serves it on a [`Port`] carved out of that socket
//!   ([`SsCarrier::over`]); a client without an endpoint ([`SsFactory::dial`]) uses an unconnected
//!   socket, learns its own mapping with STUN through that socket (`stun_mapped`) and talks to
//!   whichever candidate answers. Packets are authenticated by the key and session id, not by address.
//! * Limit: a replay of a very old session's first packets inside the 30 s timestamp window after
//!   that session was evicted from the table is accepted once (the table holds 1024 sessions).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::task::{Context as TaskCx, Poll};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::net::UdpSocket as ShadowUdpSocket;
use shadowsocks::relay::udprelay::proxy_socket::{ProxySocketError, UdpSocketType};
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket};
use shadowsocks::relay::{Address, udprelay::ProxySocket};
use tokio::io::ReadBuf;
use tokio::sync::Notify;

use super::shared::Port;

use super::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, Caps, FrameIo, Health};
use crate::rendezvous::{Disclosure, ProbeStatus};

/// The constant SS "target". Nothing is ever sent there.
pub const PLACEHOLDER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7100);
/// 1500 B path MTU minus IPv4 + UDP headers.
const UDP_PAYLOAD: usize = 1472;
/// Worst case (server to client): 16 separate header + type 1 + timestamp 8 + client session 8 +
/// padding length 2 + IPv4 address 7 + 16 tag. Padding is only added to empty payloads.
pub const SS_OVERHEAD: usize = 58;
pub const SS_MAX_FRAME: usize = UDP_PAYLOAD - SS_OVERHEAD;
const MAX_SESSIONS: usize = 1024;
const QUEUE_CAP: usize = 1024;

/// SS-2022 PSK from the 16-byte invite key. Distinct HKDF info from `seal`, `room`, `dht-*`.
pub fn derive_psk(invite: &[u8; 16]) -> [u8; 16] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"strait-rv-v1"), invite);
    let mut o = [0u8; 16];
    hk.expand(b"strait-ss-key", &mut o).expect("16 bytes is a valid HKDF length");
    o
}

pub fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn server_cfg(spec: &CarrierSpec, addr: SocketAddr) -> Result<ServerConfig, CarrierError> {
    let key = spec
        .params
        .iter()
        .find(|(k, _)| k == "key")
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| CarrierError::Failed("ss: missing invite key".into()))?;
    cfg_for_key(key, addr)
}

fn cfg_for_key(key: &str, addr: SocketAddr) -> Result<ServerConfig, CarrierError> {
    let k = crate::rendezvous::derive::parse_key(key).ok_or_else(|| CarrierError::Failed("ss: bad invite key".into()))?;
    ServerConfig::new(addr, b64(&derive_psk(&k)), CipherKind::AEAD2022_BLAKE3_AES_128_GCM)
        .map_err(|e| CarrierError::Failed(format!("ss: {e}")))
}

/// 128-packet sliding replay window.
#[derive(Default)]
struct Window {
    top: u64,
    bits: u128,
    init: bool,
}

impl Window {
    /// True if `pid` is new (and records it).
    fn accept(&mut self, pid: u64) -> bool {
        if !self.init {
            *self = Window { top: pid, bits: 1, init: true };
            return true;
        }
        if pid > self.top {
            let shift = pid - self.top;
            self.bits = if shift >= 128 { 0 } else { self.bits << shift } | 1;
            self.top = pid;
            return true;
        }
        let d = self.top - pid;
        if d >= 128 || self.bits & (1u128 << d) != 0 {
            return false;
        }
        self.bits |= 1u128 << d;
        true
    }
}

struct Sess {
    peer: SocketAddr,
    real: SocketAddr,
    server_sid: u64,
    next_pid: u64,
    win: Window,
    seen: Instant,
}

#[derive(Default)]
struct Table {
    by_sid: HashMap<u64, Sess>,
    by_peer: HashMap<SocketAddr, u64>,
}

enum Role {
    Host(Mutex<Table>),
    /// `host: None` is the rendezvous client: an unconnected socket, any source that
    /// authenticates is the host.
    Client { host: Option<SocketAddr>, sid: u64, next_pid: AtomicU64, win: Mutex<Window>, target: SocketAddr },
}

/// STUN answers to our own requests; they must not reach the SS decoder, which would drop them
/// as garbage.
#[derive(Default)]
struct Tap {
    servers: Mutex<Vec<SocketAddr>>,
    mapped: Mutex<Option<SocketAddr>>,
    notify: Notify,
}

impl Tap {
    fn offer(&self, from: SocketAddr, d: &[u8]) -> bool {
        if d.len() < 20 || !self.servers.lock().unwrap().contains(&from) {
            return false;
        }
        let Some(m) = crate::tunnel::stun::mapped_from_response(d) else { return false };
        *self.mapped.lock().unwrap() = Some(m);
        self.notify.notify_one();
        true
    }
}

/// What the SS crate reads and writes: a socket of ours, or a port of the host's plain UDP socket.
enum PortSock {
    Real { sock: Arc<ShadowUdpSocket>, tap: Arc<Tap> },
    Shared(Arc<Port>),
}

fn not_connected<T>() -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
}

impl DatagramSocket for PortSock {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            PortSock::Real { sock, .. } => sock.local_addr(),
            PortSock::Shared(p) => p.local_addr(),
        }
    }
}

impl DatagramReceive for PortSock {
    fn poll_recv(&self, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            PortSock::Real { sock, .. } => sock.poll_recv(cx, buf),
            PortSock::Shared(p) => p.poll_recv_from(cx, buf).map(|r| r.map(|_| ())),
        }
    }
    fn poll_recv_from(&self, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        match self {
            PortSock::Real { sock, tap } => loop {
                let before = buf.filled().len();
                let from = match sock.poll_recv_from(cx, buf) {
                    Poll::Ready(Ok(a)) => a,
                    other => return other,
                };
                if !tap.offer(from, &buf.filled()[before..]) {
                    return Poll::Ready(Ok(from));
                }
                buf.set_filled(before);
            },
            PortSock::Shared(p) => p.poll_recv_from(cx, buf),
        }
    }
    fn poll_recv_ready(&self, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        match self {
            PortSock::Real { sock, .. } => sock.poll_recv_ready(cx),
            PortSock::Shared(p) => p.poll_recv_ready(cx),
        }
    }
}

impl DatagramSend for PortSock {
    fn poll_send(&self, cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            PortSock::Real { sock, .. } => sock.poll_send(cx, buf),
            PortSock::Shared(_) => not_connected(),
        }
    }
    fn poll_send_to(&self, cx: &mut TaskCx<'_>, buf: &[u8], to: SocketAddr) -> Poll<io::Result<usize>> {
        match self {
            PortSock::Real { sock, .. } => sock.poll_send_to(cx, buf, to),
            PortSock::Shared(p) => p.poll_send_to(cx, buf, to),
        }
    }
    fn poll_send_ready(&self, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        match self {
            PortSock::Real { sock, .. } => sock.poll_send_ready(cx),
            PortSock::Shared(_) => Poll::Ready(Ok(())),
        }
    }
}

fn real_sock(s: ShadowUdpSocket) -> (PortSock, Arc<ShadowUdpSocket>, Arc<Tap>) {
    let (sock, tap) = (Arc::new(s), Arc::new(Tap::default()));
    (PortSock::Real { sock: sock.clone(), tap: tap.clone() }, sock, tap)
}

struct Shared {
    sock: ProxySocket<PortSock>,
    /// The socket and its STUN tap, when this carrier owns the socket.
    stun: Option<(Arc<ShadowUdpSocket>, Arc<Tap>)>,
    role: Role,
    q: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    notify: Notify,
    closed: AtomicBool,
    down: Mutex<Option<String>>,
}

impl Shared {
    fn push(&self, frame: &[u8], from: SocketAddr) {
        let mut q = self.q.lock().unwrap();
        if q.len() < QUEUE_CAP {
            q.push_back((frame.to_vec(), from)); // full queue = socket-buffer overflow: newest dropped
            drop(q);
            self.notify.notify_one();
        }
    }

    fn on_host(&self, t: &Mutex<Table>, buf: &[u8], src: SocketAddr, target: Address, ctrl: Option<UdpSocketControlData>) {
        let Some(c) = ctrl else { return };
        if target != Address::SocketAddress(PLACEHOLDER) || buf.len() > SS_MAX_FRAME {
            return; // this host is not a proxy
        }
        let mut t = t.lock().unwrap();
        let t = &mut *t;
        if let Some(s) = t.by_sid.get_mut(&c.client_session_id) {
            if !s.win.accept(c.packet_id) {
                return;
            }
            s.real = src;
            s.seen = Instant::now();
            let peer = s.peer;
            self.push(buf, peer);
            return;
        }
        if t.by_sid.len() >= MAX_SESSIONS {
            let oldest = t.by_sid.iter().min_by_key(|(_, s)| s.seen).map(|(k, _)| *k);
            if let Some(k) = oldest {
                if let Some(s) = t.by_sid.remove(&k) {
                    t.by_peer.remove(&s.peer);
                }
            }
        }
        // A restarted client reuses its source address with a new session id: the new session
        // takes over the peer key.
        if let Some(old) = t.by_peer.remove(&src) {
            t.by_sid.remove(&old);
        }
        let mut win = Window::default();
        win.accept(c.packet_id);
        let sid = c.client_session_id;
        let server_sid = u64::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap()) | 1;
        t.by_sid.insert(sid, Sess { peer: src, real: src, server_sid, next_pid: 0, win, seen: Instant::now() });
        t.by_peer.insert(src, sid);
        self.push(buf, src);
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            match self.sock.recv_from_with_ctrl(&mut buf).await {
                Ok((n, src, target, _, ctrl)) => match &self.role {
                    Role::Host(t) => self.on_host(t, &buf[..n], src, target, ctrl),
                    Role::Client { host, sid, win, .. } => {
                        let ok = ctrl.is_some_and(|c| c.client_session_id == *sid && win.lock().unwrap().accept(c.packet_id));
                        if ok && host.is_none_or(|h| h == src) && n <= SS_MAX_FRAME {
                            self.push(&buf[..n], src);
                        }
                    }
                },
                // Bad key, garbage, truncated, stale timestamp: not ours, drop quietly.
                Err(ProxySocketError::ProtocolErrorWithPeer(..) | ProxySocketError::ProtocolError(_)) => {}
                Err(ProxySocketError::IoError(e))
                    if matches!(e.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted) =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await; // ICMP unreachable from a not-yet-up peer
                }
                Err(e) => {
                    *self.down.lock().unwrap() = Some(e.to_string());
                    return;
                }
            }
        }
    }
}

pub struct SsCarrier {
    sh: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SsCarrier {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SsCarrier {
    /// Host side on a port carved out of the plain UDP socket (see `shared`); `invite_key` is the
    /// 32-hex invite key.
    pub fn over(port: Arc<Port>, invite_key: &str) -> Result<Self, CarrierError> {
        let cfg = cfg_for_key(invite_key, PLACEHOLDER)?;
        let sock = ProxySocket::from_socket(UdpSocketType::Server, Context::new_shared(ServerType::Server), &cfg, PortSock::Shared(port));
        Ok(Self::start(sock, None, Role::Host(Mutex::new(Table::default()))))
    }

    fn start(sock: ProxySocket<PortSock>, stun: Option<(Arc<ShadowUdpSocket>, Arc<Tap>)>, role: Role) -> Self {
        let sh = Arc::new(Shared {
            sock,
            stun,
            role,
            q: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            down: Mutex::new(None),
        });
        let task = tokio::spawn(sh.clone().recv_loop());
        Self { sh, task }
    }
}

#[async_trait::async_trait]
impl FrameIo for SsCarrier {
    fn caps(&self) -> Caps {
        Caps { id: CarrierId::Ss, max_frame: SS_MAX_FRAME, punchable: true, reliable_stream: false, overhead: SS_OVERHEAD }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sh.sock.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        if self.sh.closed.load(Ordering::Relaxed) {
            return Err(CarrierError::Closed.into());
        }
        if frame.len() > SS_MAX_FRAME {
            return Err(CarrierError::FrameTooLarge { max: SS_MAX_FRAME }.into());
        }
        let ph = Address::SocketAddress(match &self.sh.role {
            Role::Client { target, .. } => *target,
            Role::Host(_) => PLACEHOLDER,
        });
        let mut c = UdpSocketControlData::default();
        let real = match &self.sh.role {
            Role::Host(t) => {
                let mut t = t.lock().unwrap();
                let sid = *t.by_peer.get(&to).ok_or(io::Error::from(CarrierError::UnknownPeer))?;
                let s = t.by_sid.get_mut(&sid).unwrap();
                c.client_session_id = sid;
                c.server_session_id = s.server_sid;
                c.packet_id = s.next_pid;
                s.next_pid += 1;
                s.real
            }
            Role::Client { host, sid, next_pid, .. } => {
                if host.is_some_and(|h| h != to) {
                    return Err(CarrierError::UnknownPeer.into());
                }
                c.client_session_id = *sid;
                c.packet_id = next_pid.fetch_add(1, Ordering::Relaxed);
                to
            }
        };
        let r = match &self.sh.role {
            Role::Client { host: Some(_), .. } => self.sh.sock.send_with_ctrl(&ph, &c, frame).await,
            _ => self.sh.sock.send_to_with_ctrl(real, &ph, &c, frame).await,
        };
        r.map(|_| frame.len()).map_err(io::Error::from)
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some((f, from)) = self.sh.q.lock().unwrap().pop_front() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let n = f.len().min(buf.len());
        buf[..n].copy_from_slice(&f[..n]);
        Ok((n, from))
    }
    async fn readable(&self) -> io::Result<()> {
        loop {
            if !self.sh.q.lock().unwrap().is_empty() {
                return Ok(());
            }
            if let Some(e) = self.sh.down.lock().unwrap().clone() {
                return Err(CarrierError::Reset(e).into());
            }
            if self.sh.closed.load(Ordering::Relaxed) {
                return Err(CarrierError::Closed.into());
            }
            self.sh.notify.notified().await;
        }
    }
    async fn stun_mapped(&self, servers: &[SocketAddr], wait: Duration) -> Option<SocketAddr> {
        let (sock, tap) = self.sh.stun.as_ref()?;
        *tap.servers.lock().unwrap() = servers.to_vec();
        let deadline = tokio::time::Instant::now() + wait;
        // One request per server and round (a lost one is asked again), until an answer is tapped.
        while tokio::time::Instant::now() < deadline {
            for s in servers {
                let _ = crate::tunnel::stun::poke(sock, *s).await;
            }
            let round = Duration::from_millis(500).min(deadline - tokio::time::Instant::now());
            let _ = tokio::time::timeout(round, tap.notify.notified()).await;
            if let Some(m) = *tap.mapped.lock().unwrap() {
                return Some(m);
            }
        }
        None
    }
    fn health(&self) -> Health {
        match self.sh.down.lock().unwrap().clone() {
            Some(e) => Health::Down(e),
            None => Health::Ok,
        }
    }
    async fn close(&self) {
        self.sh.closed.store(true, Ordering::Relaxed);
        self.task.abort();
        self.sh.notify.notify_waiters();
    }
}

pub struct SsFactory;

async fn resolve(ep: &str) -> Result<SocketAddr, CarrierError> {
    tokio::net::lookup_host(ep)
        .await
        .map_err(|e| CarrierError::Failed(format!("ss: resolve {ep}: {e}")))?
        .next()
        .ok_or_else(|| CarrierError::Failed(format!("ss: {ep} did not resolve")))
}

#[async_trait::async_trait]
impl CarrierFactory for SsFactory {
    fn id(&self) -> CarrierId {
        CarrierId::Ss
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Shadowsocks-style encrypted UDP",
            shared: &[
                "UDP datagrams to your host that look like random bytes (the \"fully encrypted traffic\" pattern; some networks block exactly that pattern)",
                "Packet sizes and timing",
            ],
            not_shared: &["The payload", "Any key"],
            why: "Makes the traffic independent of our own wire format and compatible with Shadowsocks tooling.",
            operator: "none: peer to peer, no third party",
        }
    }
    /// UDP has no handshake, so this proves only that the key is valid, a local UDP socket binds and
    /// the endpoint resolves. It cannot tell whether the peer is up or the path is open.
    async fn probe(&self, spec: &CarrierSpec, timeout: Duration) -> ProbeStatus {
        let t0 = Instant::now();
        let r = tokio::time::timeout(timeout, async {
            // No endpoint = rides the plain UDP socket (rendezvous): nothing to resolve.
            let a = match spec.endpoint.as_deref() {
                Some(ep) => resolve(ep).await?,
                None => PLACEHOLDER,
            };
            server_cfg(spec, a)?;
            let bind = if a.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            tokio::net::UdpSocket::bind(bind).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
            Ok::<(), CarrierError>(())
        })
        .await;
        match r {
            Ok(Ok(())) => ProbeStatus::Reachable { rtt_ms: t0.elapsed().as_millis() as u32 },
            Ok(Err(e)) => ProbeStatus::Error(e.to_string()),
            Err(_) => ProbeStatus::Error("timeout".into()),
        }
    }
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let addr = match (&spec.endpoint, spec.bind_port) {
            (Some(e), _) => resolve(e).await?,
            (None, p) => SocketAddr::from(([0, 0, 0, 0], p.unwrap_or(0))),
        };
        let cfg = server_cfg(spec, addr)?;
        let raw = ShadowUdpSocket::listen(&addr).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
        let (ps, sock, tap) = real_sock(raw);
        let ps = ProxySocket::from_socket(UdpSocketType::Server, Context::new_shared(ServerType::Server), &cfg, ps);
        Ok(Arc::new(SsCarrier::start(ps, Some((sock, tap)), Role::Host(Mutex::new(Table::default())))))
    }
    /// With an endpoint: a socket connected to that host. Without one: the rendezvous client,
    /// an unconnected IPv4 socket (see the module docs).
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let host = match spec.endpoint.as_deref() {
            Some(ep) => Some(resolve(ep).await?),
            None => None,
        };
        let cfg = server_cfg(spec, host.unwrap_or(PLACEHOLDER))?;
        let bind = match host {
            Some(h) if h.is_ipv6() => SocketAddr::from(([0u16; 8], 0)),
            _ => SocketAddr::from(([0, 0, 0, 0], spec.bind_port.filter(|_| host.is_none()).unwrap_or(0))),
        };
        let raw = tokio::net::UdpSocket::bind(bind).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
        if let Some(h) = host {
            raw.connect(h).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
        }
        let (ps, sock, tap) = real_sock(ShadowUdpSocket::from(raw));
        let ps = ProxySocket::from_socket(UdpSocketType::Client, Context::new_shared(ServerType::Local), &cfg, ps);
        let sid = u64::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap()) | 1;
        // Optional `target` param: the address a real ssserver would forward to (interop tests only;
        // our own host requires PLACEHOLDER).
        let target = match spec.params.iter().find(|(k, _)| k == "target") {
            Some((_, t)) => t.parse().map_err(|_| CarrierError::Failed("ss: bad target".into()))?,
            None => PLACEHOLDER,
        };
        let role = Role::Client { host, sid, next_pid: AtomicU64::new(0), win: Mutex::new(Window::default()), target };
        Ok(Arc::new(SsCarrier::start(ps, Some((sock, tap)), role)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_rejects_replays_and_old() {
        let mut w = Window::default();
        assert!(w.accept(5) && !w.accept(5));
        assert!(w.accept(3) && !w.accept(3));
        assert!(w.accept(200) && !w.accept(5)); // 5 fell out of the 128 window
        assert!(w.accept(199) && !w.accept(199));
    }

    #[test]
    fn b64_known() {
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64(b"fo"), "Zm8=");
    }
}
