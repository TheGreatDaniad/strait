//! Userspace exit stack for hosts that cannot forward kernel TUN traffic.
//!
//! The Windows kernel refuses to forward packets whose source address is not
//! assigned to the outgoing interface (the Wintun source is the client's IP),
//! and WinNAT is not available on every Windows image. Instead of relying on
//! kernel forwarding we terminate TCP/UDP in a userspace stack and proxy the
//! streams/datagrams through ordinary host sockets. This is the same model the
//! mobile exit uses.
//!
//! The tunnel still carries raw IPv4 packets on the wire; only the exit side
//! differs.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{Stack, StackBuilder, TcpListener, UdpSocket};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// smoltcp socket buffer per direction and flow. The TCP window is capped by this: 64 KiB gave
/// about 7.5 Mbit/s at 66 ms RTT (window / RTT), 256 KiB about 21 Mbit/s at 92 ms, 1 MiB allows
/// about 90 Mbit/s at 92 ms. Memory is at most 2 x this per open flow (2 MiB, and only the part a
/// flow really fills is touched); `ExitConfig::max_tcp` = 256 flows keeps the worst case at 512 MiB.
pub const TCP_BUF: u32 = 1024 * 1024;

// ---- exit destination policy -------------------------------------------------------------
//
// A guest names the destination of every packet, so without a filter any invite holder could dial
// the host's loopback services, its LAN/router or the cloud metadata endpoint. Default: public
// internet only. `--allow-lan` / STRAIT_ALLOW_LAN=1 (or NAT_TUNNEL_ALLOW_LAN=1) additionally allows
// RFC1918, CGNAT and IPv6 ULA. Loopback needs the separate STRAIT_EXIT_ALLOW_LOOPBACK=1 (tests, labs);
// link-local (169.254/16 incl. metadata), multicast, broadcast, 240/4 and unspecified are never allowed.
// shortcut: the host's own non-loopback interface addresses (public IP of the box) are not enumerated
// and stay dialable; close that with a firewall rule or by listing interface addresses here.

/// The tunnel's own gateway address; the stack answers ICMP echo for it, nothing is ever dialled.
const HOST_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);

const POLICY_INIT: u8 = 1;
const POLICY_LAN: u8 = 2;
const POLICY_LOOPBACK: u8 = 4;
static POLICY: AtomicU8 = AtomicU8::new(0);

fn env_on(names: &[&str]) -> bool {
    names.iter().any(|n| matches!(std::env::var(n).as_deref(), Ok("1") | Ok("true") | Ok("yes")))
}

fn policy_bits() -> u8 {
    let v = POLICY.load(Ordering::Relaxed);
    if v & POLICY_INIT != 0 {
        return v;
    }
    let mut v = POLICY_INIT;
    if env_on(&["STRAIT_ALLOW_LAN", "NAT_TUNNEL_ALLOW_LAN"]) {
        v |= POLICY_LAN;
    }
    if env_on(&["STRAIT_EXIT_ALLOW_LOOPBACK"]) {
        v |= POLICY_LOOPBACK;
    }
    match POLICY.compare_exchange(0, v, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => v,
        Err(cur) => cur,
    }
}

/// Process-global override (the `--allow-lan` flag, tests). Replaces whatever the env said.
pub fn set_exit_policy(allow_lan: bool, allow_loopback: bool) {
    let v = POLICY_INIT | if allow_lan { POLICY_LAN } else { 0 } | if allow_loopback { POLICY_LOOPBACK } else { 0 };
    POLICY.store(v, Ordering::Relaxed);
}

/// Turn on LAN access (the `--allow-lan` flag) without touching the loopback setting.
pub fn enable_allow_lan() {
    let v = policy_bits() | POLICY_LAN;
    POLICY.store(v, Ordering::Relaxed);
}

fn v4_allowed(a: Ipv4Addr, lan: bool, loopback: bool) -> bool {
    let o = a.octets();
    if a.is_loopback() {
        return loopback;
    }
    if a.is_unspecified() || o[0] == 0 || a.is_multicast() || a.is_broadcast() || a.is_link_local() || o[0] >= 240 {
        return false;
    }
    let private = a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64);
    !private || lan
}

/// Pure policy: may the exit dial `ip` under the given opt-ins?
pub fn exit_dest_allowed_with(ip: IpAddr, lan: bool, loopback: bool) -> bool {
    match ip {
        IpAddr::V4(a) => v4_allowed(a, lan, loopback),
        IpAddr::V6(a) => {
            let s = a.segments();
            // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d)
            // embed an IPv4 address: judge that.
            let embedded = if s[..5] == [0; 5] && (s[5] == 0xffff || (s[5] == 0 && !a.is_unspecified() && !a.is_loopback())) {
                true
            } else {
                s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
            };
            if embedded {
                let o = a.octets();
                return v4_allowed(Ipv4Addr::new(o[12], o[13], o[14], o[15]), lan, loopback);
            }
            if a.is_loopback() {
                return loopback;
            }
            if a.is_unspecified() || a.is_multicast() || (s[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            !((s[0] & 0xfe00) == 0xfc00) || lan
        }
    }
}

/// Policy under the process-wide settings.
pub fn exit_dest_allowed(ip: IpAddr) -> bool {
    let b = policy_bits();
    exit_dest_allowed_with(ip, b & POLICY_LAN != 0, b & POLICY_LOOPBACK != 0)
}

/// Log a refusal at most once per 5 s so a scanning guest cannot flood the log.
fn note_refused(dst: IpAddr, what: &str) {
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let now = START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64 + 5000;
    let last = LAST_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 5000 && LAST_MS.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        log::warn!("exit refused {what} to {dst} (private/loopback/link-local destination; --allow-lan permits LAN ranges); further refusals are logged at most every 5 s");
    }
}

fn check_dest(remote: SocketAddr, what: &str) -> io::Result<()> {
    if exit_dest_allowed(remote.ip()) {
        Ok(())
    } else {
        note_refused(remote.ip(), what);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "destination refused by exit policy"))
    }
}

/// Run the smoltcp engine so that a panic inside it (smoltcp 0.12 can panic on a TCP segment whose
/// sequence arithmetic underflows) ends only this stack: the future is dropped, its channels close
/// and the host builds a new stack. Without this the panic took the whole host down.
pub async fn contain_panic<F: std::future::Future>(f: F) -> Option<F::Output> {
    use futures::FutureExt;
    match std::panic::AssertUnwindSafe(f).catch_unwind().await {
        Ok(v) => Some(v),
        Err(_) => {
            log::error!("userspace stack: the TCP engine panicked; its flows are dropped and the stack is rebuilt");
            None
        }
    }
}

pub struct UserspaceHost {
    pub stack: Stack,
    pub tcp: TcpListener,
    pub udp: UdpSocket,
}

/// Build a stack that owns no addresses and accepts every destination
/// (`any_ip`). The first packet from a client establishes the flow.
pub fn build(mtu: usize) -> io::Result<UserspaceHost> {
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .stack_buffer_size(2048)
        .tcp_buffer_size(2048)
        .udp_buffer_size(2048)
        .tcp_recv_buffer_size(TCP_BUF)
        .tcp_send_buffer_size(TCP_BUF)
        .enable_udp(true)
        .enable_tcp(true)
        .enable_icmp(true)
        .mtu(mtu.max(576))
        // Refuse before the stack allocates a socket/buffers. The gateway address stays so ICMP echo
        // to it keeps working (a TCP/UDP flow to it is still refused at the dial point).
        .add_ip_filter_fn(|_src, dst| {
            if *dst == IpAddr::V4(HOST_TUNNEL_IP) {
                return true;
            }
            let ok = exit_dest_allowed(*dst);
            if !ok {
                note_refused(*dst, "packet");
            }
            ok
        })
        .build()?;

    // The runner drives TCP timers (retransmits, FIN handling).
    if let Some(runner) = runner {
        tokio::spawn(contain_panic(runner));
    }

    Ok(UserspaceHost {
        stack,
        tcp: tcp.ok_or_else(|| io::Error::other("netstack did not return a TCP listener"))?,
        udp: udp.ok_or_else(|| io::Error::other("netstack did not return a UDP socket"))?,
    })
}


#[cfg(windows)]
async fn connect_remote(remote: SocketAddr, guest: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    check_dest(guest, "tcp")?;
    use socket2::{Domain, Protocol, Socket, Type};

    let join = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        let _ = crate::tunmode::pin_socket(&socket);
        socket.connect_timeout(&remote.into(), Duration::from_secs(10))?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    });
    let stream = tokio::time::timeout(Duration::from_secs(20), join)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
        .map_err(io::Error::other)??;
    tokio::net::TcpStream::from_std(stream)
}

#[cfg(not(windows))]
async fn connect_remote(remote: SocketAddr, guest: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    check_dest(guest, "tcp")?;
    tokio::net::TcpStream::connect(remote).await
}

#[cfg(windows)]
async fn udp_socket(remote: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    check_dest(remote, "udp")?;
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = crate::tunmode::pin_socket(&socket);
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
    socket.connect(&remote.into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(not(windows))]
async fn udp_socket(remote: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    check_dest(remote, "udp")?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote).await?;
    Ok(socket)
}


/// Longest preamble line, newline included: `[ffff:..:ffff]:65535\n` is < 64.
pub const MAX_PREAMBLE: usize = 64;

/// Test/lab hook: route outer TCP connections through a local proxy that
/// understands a leading `host:port\n` line. This lets a host and a client on
/// the same machine be verified without the client's VPN route capturing the
/// host's own outbound socket.
///
/// Fails closed: if the variable is set but is not a socket address, the flow
/// is refused instead of silently dialling the destination directly (which is
/// exactly what the hook exists to avoid).
fn exit_target(remote: SocketAddr) -> Result<(SocketAddr, Option<Vec<u8>>), String> {
    exit_target_from(std::env::var("STRAIT_EXIT_PROXY").ok().as_deref(), remote)
}

pub fn exit_target_from(proxy: Option<&str>, remote: SocketAddr) -> Result<(SocketAddr, Option<Vec<u8>>), String> {
    match proxy {
        None => Ok((remote, None)),
        Some(p) => match p.trim().parse::<SocketAddr>() {
            Ok(addr) => Ok((addr, Some(format!("{remote}\n").into_bytes()))),
            Err(_) => Err(format!("STRAIT_EXIT_PROXY {p:?} is not a socket address")),
        },
    }
}

/// Reference reader for the preamble (what a lab proxy must implement):
/// one `ip:port\n` line of at most [`MAX_PREAMBLE`] bytes arriving within
/// `timeout`. Reads byte-wise so nothing after the newline is consumed.
pub async fn read_exit_preamble<R: tokio::io::AsyncRead + Unpin>(r: &mut R, timeout: Duration) -> io::Result<SocketAddr> {
    use tokio::io::AsyncReadExt;
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    tokio::time::timeout(timeout, async {
        let mut line = Vec::with_capacity(MAX_PREAMBLE);
        loop {
            let b = r.read_u8().await?;
            if b == b'\n' {
                break;
            }
            if line.len() + 1 >= MAX_PREAMBLE {
                return Err(bad("preamble too long"));
            }
            line.push(b);
        }
        std::str::from_utf8(&line)
            .ok()
            .and_then(|s| s.parse::<SocketAddr>().ok())
            .ok_or_else(|| bad("malformed preamble"))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "preamble timed out"))?
}

/// Reply datagrams queued between flow tasks and the stack writer.
pub const UDP_REPLY_QUEUE: usize = 256;

/// Replies dropped because the queue was full (drop-newest; UDP is lossy by
/// contract, and this bounds memory to `UDP_REPLY_QUEUE` datagrams).
pub static UDP_REPLIES_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Limits for the userspace exit. Permits are held only while a flow is alive
/// and are released on close, error or idle timeout.
#[derive(Clone, Debug)]
pub struct ExitConfig {
    pub max_tcp: usize,
    pub max_udp: usize,
    /// Per guest address (the flow's source in the tunnel network), within the global caps, so one
    /// guest cannot take every permit.
    pub per_guest_tcp: usize,
    pub per_guest_udp: usize,
    pub tcp_idle: Duration,
    pub udp_idle: Duration,
    pub dial_timeout: Duration,
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            max_tcp: 256,
            max_udp: 1024,
            per_guest_tcp: 128,
            per_guest_udp: 256,
            tcp_idle: Duration::from_secs(60),
            udp_idle: Duration::from_secs(30),
            dial_timeout: Duration::from_secs(10),
        }
    }
}

/// Live flows per guest address. A [`GuestSlot`] holds one and gives it back on drop, so every
/// close path (error, idle, panic) releases it.
#[derive(Clone, Default)]
struct GuestCounts(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>>);

struct GuestSlot(GuestCounts, IpAddr);

impl GuestCounts {
    fn take(&self, ip: IpAddr, cap: usize) -> Option<GuestSlot> {
        let mut m = self.0.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(GuestSlot(self.clone(), ip))
    }
}

impl Drop for GuestSlot {
    fn drop(&mut self) {
        let mut m = (self.0).0.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// Accept TCP flows from the tunnel and connect them to real destinations.
pub async fn serve_tcp(listener: TcpListener) {
    serve_tcp_with(listener, ExitConfig::default(), None).await
}

type Flow<S> = (S, SocketAddr, SocketAddr);

/// Generic over the inner stream so tests can drive it without a netstack.
/// `sem` lets the caller observe permits; defaults to `cfg.max_tcp`.
pub async fn serve_tcp_with<St, S>(
    mut flows: St,
    cfg: ExitConfig,
    sem: Option<std::sync::Arc<tokio::sync::Semaphore>>,
) where
    St: futures::Stream<Item = Flow<S>> + Unpin,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let limit = sem.unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.max_tcp)));
    let refusals = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let guests = GuestCounts::default();
    while let Some((mut inner, local, remote)) = flows.next().await {
        // Backstop for the stack filter, and the only check on the STRAIT_EXIT_PROXY path
        // (where the dial address is the proxy, not the guest's destination).
        if let Err(e) = check_dest(remote, "tcp") {
            log::debug!("exit tcp {remote}: {e}");
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(1), inner.shutdown()).await;
            });
            continue;
        }
        let permit = match guests.take(local.ip(), cfg.per_guest_tcp).zip(limit.clone().try_acquire_owned().ok()) {
            Some(permit) => permit,
            None => {
                log::warn!("exit connection limit reached; refusing {remote} from {}", local.ip());
                // The netstack yields a flow at SYN time. Dropping it before the
                // handshake finished removes the socket silently (no FIN/RST), so the
                // client would hang. Hold it briefly (bounded by `refusals`) until the
                // first byte/EOF, then close so the client sees EOF.
                if let Ok(slot) = refusals.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _slot = slot;
                        use tokio::io::AsyncReadExt;
                        let _ = tokio::time::timeout(Duration::from_secs(2), inner.read(&mut [0u8; 1])).await;
                        let _ = tokio::time::timeout(Duration::from_secs(1), inner.shutdown()).await;
                    });
                }
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let (dial_addr, preamble) = match exit_target(remote) {
                Ok(t) => t,
                Err(e) => {
                    log::error!("exit refused {remote}: {e}");
                    let _ = inner.shutdown().await;
                    return;
                }
            };
            let dial = tokio::time::timeout(cfg.dial_timeout, connect_remote(dial_addr, remote)).await;
            let mut outer = match dial {
                Ok(Ok(s)) => s,
                _ => {
                    log::debug!("exit dial {remote} failed");
                    let _ = inner.shutdown().await;
                    return;
                }
            };
            if let Some(preamble) = preamble {
                let sent = tokio::time::timeout(cfg.dial_timeout, outer.write_all(&preamble)).await;
                if !matches!(sent, Ok(Ok(()))) {
                    let _ = inner.shutdown().await;
                    return;
                }
            }
            match proxy(&mut inner, &mut outer, cfg.tcp_idle).await {
                Ok(()) => log::debug!("exit tcp {remote} closed"),
                Err(e) => log::debug!("exit tcp {remote} ended: {e}"),
            }
            let _ = outer.shutdown().await;
            let _ = inner.shutdown().await;
        });
    }
}

/// Bidirectional copy with half-close support, 8 KiB buffers per direction
/// and a shared idle timeout (no bytes in either direction for `idle`).
async fn proxy<A, B>(a: &mut A, b: &mut B, idle: Duration) -> io::Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use tokio::io::AsyncReadExt;
    let start = tokio::time::Instant::now();
    let last = AtomicU64::new(0);
    let now = || start.elapsed().as_millis() as u64;

    async fn pump<R, W>(r: &mut R, w: &mut W, last: &AtomicU64, now: &(impl Fn() -> u64 + Sync), idle: Duration) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8192];
        loop {
            let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
                Ok(n) => n?,
                Err(_) => {
                    if now().saturating_sub(last.load(Relaxed)) >= idle.as_millis() as u64 {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
                    }
                    continue;
                }
            };
            if n == 0 {
                return w.shutdown().await; // propagate half-close
            }
            last.store(now(), Relaxed);
            w.write_all(&buf[..n]).await?;
        }
    }
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::try_join!(
        pump(&mut ar, &mut bw, &last, &now, idle),
        pump(&mut br, &mut aw, &last, &now, idle)
    )
    .map(|_| ())
}

/// Forward UDP datagrams from the tunnel through host sockets.
///
/// One host socket per (client, destination) flow, reaped after `udp_idle`
/// without traffic; flows beyond `max_udp` are dropped.
pub async fn serve_udp(udp: UdpSocket) {
    let (read, mut write) = udp.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(UDP_REPLY_QUEUE);
    tokio::spawn(async move {
        while let Some(pkt) = reply_rx.recv().await {
            if let Err(e) = write.send(pkt).await {
                log::debug!("exit udp reply write failed: {e}");
                break;
            }
        }
    });
    serve_udp_with(read, reply_tx, ExitConfig::default(), None).await
}

pub async fn serve_udp_with<St>(
    mut read: St,
    reply_tx: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    cfg: ExitConfig,
    sem: Option<std::sync::Arc<tokio::sync::Semaphore>>,
) where
    St: futures::Stream<Item = (Vec<u8>, SocketAddr, SocketAddr)> + Unpin,
{
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    type Key = (SocketAddr, SocketAddr);
    let limit = sem.unwrap_or_else(|| Arc::new(tokio::sync::Semaphore::new(cfg.max_udp)));
    let flows: Arc<Mutex<HashMap<Key, mpsc::Sender<Vec<u8>>>>> = Default::default();
    let guests = GuestCounts::default();

    while let Some((data, local, remote)) = read.next().await {
        if !exit_dest_allowed(remote.ip()) {
            note_refused(remote.ip(), "udp");
            continue;
        }
        let key = (local, remote);
        let existing = flows.lock().unwrap().get(&key).cloned();
        if let Some(tx) = existing {
            if tx.try_send(data.clone()).is_ok() || !tx.is_closed() {
                continue; // delivered, or queue full (drop datagram)
            }
        }
        let Some(permit) = guests.take(local.ip(), cfg.per_guest_udp).zip(limit.clone().try_acquire_owned().ok()) else {
            log::warn!("exit udp flow limit reached; dropping {remote} from {}", local.ip());
            continue;
        };
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
        let _ = tx.try_send(data);
        flows.lock().unwrap().insert(key, tx);
        let (reply_tx, flows, idle) = (reply_tx.clone(), flows.clone(), cfg.udp_idle);
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(sock) = udp_socket(remote).await {
                let mut buf = vec![0u8; 4096];
                loop {
                    tokio::select! {
                        d = rx.recv() => match d {
                            Some(d) => if sock.send(&d).await.is_err() { break },
                            None => break,
                        },
                        r = sock.recv(&mut buf) => match r {
                            Ok(n) => {
                                if reply_tx.try_send((buf[..n].to_vec(), remote, local)).is_err() {
                                    UDP_REPLIES_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            Err(_) => break,
                        },
                        _ = tokio::time::sleep(idle) => break,
                    }
                }
            }
            // Idle is reset by any select wakeup because the sleep is re-created each loop.
            rx.close();
            let mut m = flows.lock().unwrap();
            if m.get(&key).is_some_and(|t| t.is_closed()) {
                m.remove(&key);
            }
        });
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn exit_policy_table() {
        // (address, default, allow_lan, allow_loopback)
        let t: &[(&str, bool, bool, bool)] = &[
            ("8.8.8.8", true, true, true),
            ("1.1.1.1", true, true, true),
            ("2606:4700::1111", true, true, true),
            ("100.63.255.255", true, true, true),
            ("100.128.0.1", true, true, true),
            ("172.15.0.1", true, true, true),
            ("172.32.0.1", true, true, true),
            ("::ffff:8.8.8.8", true, true, true),
            ("10.1.2.3", false, true, false),
            ("10.7.0.1", false, true, false),
            ("172.16.0.1", false, true, false),
            ("172.31.255.255", false, true, false),
            ("192.168.1.1", false, true, false),
            ("100.64.0.1", false, true, false),
            ("100.127.255.255", false, true, false),
            ("fc00::1", false, true, false),
            ("fd12::1", false, true, false),
            ("::ffff:192.168.1.1", false, true, false),
            ("::192.168.1.1", false, true, false),
            ("64:ff9b::10.0.0.1", false, true, false),
            ("127.0.0.1", false, false, true),
            ("127.9.9.9", false, false, true),
            ("::1", false, false, true),
            ("::ffff:127.0.0.1", false, false, true),
            ("::127.0.0.1", false, false, true),
            ("0.0.0.0", false, false, false),
            ("0.1.2.3", false, false, false),
            ("::", false, false, false),
            ("169.254.169.254", false, false, false),
            ("169.254.0.1", false, false, false),
            ("fe80::1", false, false, false),
            ("::ffff:169.254.169.254", false, false, false),
            ("224.0.0.1", false, false, false),
            ("239.255.255.250", false, false, false),
            ("ff02::1", false, false, false),
            ("255.255.255.255", false, false, false),
            ("240.0.0.1", false, false, false),
            ("::ffff:224.0.0.1", false, false, false),
        ];
        for &(a, def, lan, lo) in t {
            let ip: IpAddr = a.parse().unwrap();
            assert_eq!(exit_dest_allowed_with(ip, false, false), def, "{a} default");
            // LAN opt-in alone: only the private ranges open up, loopback never does.
            let lan_only = if lo || !lan { def } else { true };
            assert_eq!(exit_dest_allowed_with(ip, true, false), lan_only, "{a} allow-lan");
            // Loopback opt-in alone opens only loopback.
            assert_eq!(exit_dest_allowed_with(ip, false, true), def || (lo && !lan), "{a} allow-loopback");
        }
    }
}

#[cfg(test)]
mod panic_tests {
    #[tokio::test]
    async fn a_panicking_engine_is_contained() {
        let r = super::contain_panic(async { panic!("attempt to subtract sequence numbers with underflow") }).await;
        assert!(r.is_none());
        assert_eq!(super::contain_panic(async { 7 }).await, Some(7));
    }
}
