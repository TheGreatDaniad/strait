//! Birthday-paradox punching: cone host (port-restricted filter) <- symmetric client.
//!
//! Loopback emulation, no real NAT involved:
//! * the host sits behind `ConeIo`, a `FrameIo` around one stable socket that drops inbound
//!   datagrams from any (ip, port) the host has not sent to (port-restricted cone NAT);
//! * the client sits behind `sym_nat`, a userspace NAT box on 127.0.0.1: the guest believes the
//!   box's inside socket is the host; the box gives every (guest socket, destination) its own
//!   external socket on a uniformly random port in 1024..65535 and lets only the destination in
//!   (symmetric NAT). The guest's STUN-observed port is a fixed unrelated one.
//! Without birthday punching the host fires only at that STUN port and the JOIN never passes.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use nat_tunnel::birthday::{Birthday, Rng};
use nat_tunnel::carrier::{Caps, CarrierId, FrameIo};
use nat_tunnel::rendezvous::{Candidate, Disclosure, ProbeStatus, Rendezvous, RvCtx, RvError};
use nat_tunnel::transport::{
    ConnectError, ConnectOpts, Event, IoList, MuxConfig, MuxEvent, MuxHost, RvJoin, Tunnel, MUX_HOST_IP,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const KEY: &str = "00112233445566778899aabbccddeeff";

/// The port scan sweeps all of 127.0.0.1's ports, which would reach the other tests' sockets (and
/// their "external port" counters), so attempts run one at a time.
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

fn stun_init() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut b) else { continue };
                if n < 20 || b[0..2] != [0, 1] {
                    continue;
                }
                let SocketAddr::V4(m) = from else { continue };
                let mut r = vec![0x01, 0x01, 0, 12];
                r.extend_from_slice(&b[4..20]);
                r.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
                r.extend_from_slice(&(m.port() ^ 0x2112).to_be_bytes());
                for (o, c) in m.ip().octets().iter().zip(0x2112_A442u32.to_be_bytes()) {
                    r.push(o ^ c);
                }
                let _ = sock.send_to(&r, from);
            }
        });
        std::env::set_var("STUN_SERVER", "127.0.0.1");
        std::env::set_var("STUN_PORT", port.to_string());
    });
}

// ------------------------------------------------------------ port-restricted cone NAT

struct ConeIo {
    sock: UdpSocket,
    sent_to: Mutex<HashSet<SocketAddr>>,
    dropped: AtomicUsize,
    /// Full-cone: no filter at all.
    open: bool,
}

impl ConeIo {
    fn new() -> Arc<Self> {
        Self::with(false)
    }
    fn with(open: bool) -> Arc<Self> {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        Arc::new(Self { sock: UdpSocket::from_std(s).unwrap(), sent_to: Default::default(), dropped: Default::default(), open })
    }
}

/// `Arc<ConeIo>` is what the test keeps; the host gets this thin handle.
struct ConeHandle(Arc<ConeIo>);

#[async_trait::async_trait]
impl FrameIo for ConeHandle {
    fn caps(&self) -> Caps {
        Caps { id: CarrierId::Udp, max_frame: 1472, punchable: true, reliable_stream: false, overhead: 0 }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.sock.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.0.sent_to.lock().unwrap().insert(to);
        self.0.sock.send_to(frame, to).await
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let (n, from) = self.0.sock.try_recv_from(buf)?;
            if self.0.open || self.0.sent_to.lock().unwrap().contains(&from) {
                return Ok((n, from));
            }
            self.0.dropped.fetch_add(1, SeqCst);
        }
    }
    async fn readable(&self) -> io::Result<()> {
        self.0.sock.readable().await
    }
}

// ------------------------------------------------------------ symmetric NAT box

/// Returns the box's inside address (what the guest takes for the host). `mappings` counts the
/// external ports allocated.
async fn sym_nat(host_pub: SocketAddr, mappings: Arc<AtomicUsize>) -> SocketAddr {
    let s_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let front = s_in.local_addr().unwrap();
    let table: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::default();
    tokio::spawn(async move {
        let mut rng = Rng::new();
        let mut b = [0u8; 2048];
        while let Ok((n, src)) = s_in.recv_from(&mut b).await {
            let existing = table.lock().unwrap().get(&src).cloned();
            let out = match existing {
                Some(o) => o,
                None => {
                    let o = loop {
                        let port = 1024 + (rng.next() % 64512) as u16;
                        if let Ok(o) = UdpSocket::bind(("127.0.0.1", port)).await {
                            break Arc::new(o);
                        }
                    };
                    mappings.fetch_add(1, SeqCst);
                    table.lock().unwrap().insert(src, o.clone());
                    let (o2, s_in) = (o.clone(), s_in.clone());
                    tokio::spawn(async move {
                        let mut b = [0u8; 2048];
                        while let Ok((n, from)) = o2.recv_from(&mut b).await {
                            if from == host_pub {
                                let _ = s_in.send_to(&b[..n], src).await;
                            }
                        }
                    });
                    o
                }
            };
            let _ = out.send_to(&b[..n], host_pub).await;
        }
    });
    front
}

// ------------------------------------------------------------ rendezvous stand-in

/// Tells the guest where the host is (the rendezvous result); publishes nothing.
struct FixedHost(SocketAddr);

#[async_trait::async_trait]
impl Rendezvous for FixedHost {
    fn id(&self) -> &'static str {
        "trk"
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure { title: "fixed", shared: &[], not_shared: &[], why: "test", operator: "test" }
    }
    async fn probe(&self, _t: Duration) -> ProbeStatus {
        ProbeStatus::Reachable { rtt_ms: 0 }
    }
    async fn run(&self, _ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let _ = tx.send(Candidate { addr: self.0, via: "trk" }).await;
        cancel.cancelled().await;
        Ok(())
    }
}

// ------------------------------------------------------------ scenario

fn pkt(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

struct Outcome {
    connected: bool,
    elapsed: Duration,
    data_both_ways: bool,
    host_dropped: usize,
    mappings: usize,
    err: Option<String>,
}

/// One full attempt with the given birthday settings on both sides.
async fn attempt(bd: Birthday, budget: Duration) -> Outcome {
    attempt_with(bd, budget, false).await
}

async fn attempt_with(bd: Birthday, budget: Duration, full_cone: bool) -> Outcome {
    attempt_carrier(bd, budget, full_cone, None).await
}

/// The key as the carriers take it (`CarrierSpec` param `key`).
#[cfg(all(feature = "cr-ss", feature = "cr-awg"))]
async fn dial_rendezvous_carrier(id: CarrierId, bind_port: Option<u16>) -> Arc<dyn FrameIo> {
    use nat_tunnel::carrier::{awg::AwgFactory, ss::SsFactory, CarrierFactory, CarrierSpec};
    let spec = CarrierSpec { endpoint: None, bind_port, params: vec![("key".into(), KEY.into())] };
    match id {
        CarrierId::Ss => SsFactory.dial(&spec).await.unwrap(),
        CarrierId::Awg => AwgFactory.dial(&spec).await.unwrap(),
        other => panic!("{other} does not ride the shared socket"),
    }
}

/// `carrier`: `None` = plain UDP on both sides; `Some(ss|awg)` = the guest dials that carrier
/// without an endpoint and the host serves it on its shared UDP socket (rendezvous-only invite).
async fn attempt_carrier(bd: Birthday, budget: Duration, full_cone: bool, carrier: Option<CarrierId>) -> Outcome {
    let _serial = serial().await;
    stun_init();
    let cone = ConeIo::with(full_cone);
    let host_pub = cone.sock.local_addr().unwrap();
    let mut mux = MuxHost::bind(
        KEY,
        MuxConfig {
            udp: false,
            carriers: IoList(vec![Arc::new(ConeHandle(cone.clone()))]),
            shared: carrier.into_iter().collect(),
            birthday: bd.clone(),
            ..MuxConfig::default()
        },
    )
    .await
    .unwrap();
    // The client's STUN-observed endpoint: valid toward STUN only, not toward the host.
    mux.add_punch_target("127.0.0.1:50000".parse().unwrap());
    let host_got = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let hg = host_got.clone();
    let (stop, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        loop {
            while let Some(ev) = mux.try_recv().await.unwrap() {
                if let MuxEvent::Packet { data, .. } = ev {
                    if data[16..20] == MUX_HOST_IP.octets() {
                        hg.lock().unwrap().push(data[20..].to_vec());
                        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                        mux.send_to_ip(src, &pkt(MUX_HOST_IP, src, &data[20..])).await;
                    }
                }
            }
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
                _ = &mut stop_rx => break,
            }
        }
        mux.close().await;
    });

    let mappings = Arc::new(AtomicUsize::new(0));
    let front = sym_nat(host_pub, mappings.clone()).await;
    let rv = RvJoin {
        ids: vec!["trk".into()],
        backends: Some(vec![Arc::new(FixedHost(front))]),
        budget: Some(budget),
        no_v6: true,
        birthday: bd,
        ..Default::default()
    };
    let t0 = Instant::now();
    let opts = ConnectOpts { signal: None, peer: None, room: "", key: KEY, host: false, bind_port: None, hosts: vec![], mux: true };
    let r = match carrier {
        None => Tunnel::connect_rv(opts, rv).await,
        #[cfg(all(feature = "cr-ss", feature = "cr-awg"))]
        Some(id) => Tunnel::connect_with_io(opts, &[], false, false, Some(rv), dial_rendezvous_carrier(id, None).await).await,
        #[cfg(not(all(feature = "cr-ss", feature = "cr-awg")))]
        Some(_) => unreachable!("needs cr-ss and cr-awg"),
    };
    let elapsed = t0.elapsed();
    let mut out = Outcome { connected: false, elapsed, data_both_ways: false, host_dropped: 0, mappings: 0, err: None };
    match r {
        Ok(mut t) => {
            out.connected = true;
            t.enable_packet_mode();
            let me = t.assigned().expect("assigned").0;
            t.send_packet(&pkt(me, MUX_HOST_IP, b"hello host")).await.unwrap();
            let end = Instant::now() + Duration::from_secs(5);
            while Instant::now() < end && !out.data_both_ways {
                t.tick().await.unwrap();
                if let Some(Event::Data(d)) = t.try_recv().await.unwrap() {
                    out.data_both_ways = &d[20..] == b"hello host";
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(host_got.lock().unwrap().iter().any(|p| p == b"hello host"), "host got the packet");
        }
        Err(e) => {
            assert!(matches!(e, ConnectError::RendezvousFailed(_)), "typed error kept: {e:?}");
            out.err = Some(e.to_string());
        }
    }
    out.host_dropped = cone.dropped.load(SeqCst);
    out.mappings = mappings.load(SeqCst);
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    out
}

#[tokio::test]
async fn kill_switch_off_symmetric_client_fails() {
    let bd = Birthday { enabled: false, ..Birthday::default() };
    let o = attempt(bd, Duration::from_secs(6)).await;
    assert!(!o.connected, "symmetric x port-restricted must fail without birthday punching");
    assert!(o.elapsed < Duration::from_secs(9), "bounded by the budget: {:?}", o.elapsed);
    assert!(o.host_dropped > 0, "the filter really dropped the JOINs");
    assert_eq!(o.mappings, 1, "no extra sockets were opened");
    eprintln!("OFF: failed in {:?} ({:?}), host filter dropped {}", o.elapsed, o.err, o.host_dropped);
}

/// Matrix cells d/e (full-cone / address-restricted host) <- symmetric client with
/// `NAT_TUNNEL_BIRTHDAY=0`: the spec says it works. The host answers the source its JOIN really
/// came from, not the port the rendezvous announced, so the plain path needs no birthday punching.
/// (This passes before and after the v3 changes: the lab failures were not caused by this code.)
#[tokio::test]
async fn full_cone_host_symmetric_client_connects_without_birthday() {
    let bd = Birthday { enabled: false, ..Birthday::default() };
    let o = attempt_with(bd, Duration::from_secs(15), true).await;
    assert!(o.connected, "{:?}", o.err);
    assert!(o.data_both_ways);
    assert_eq!(o.mappings, 1, "one external port, no fan-out");
    assert!(o.elapsed < Duration::from_secs(3), "{:?}", o.elapsed);
}

#[tokio::test]
async fn birthday_on_symmetric_client_connects() {
    let o = attempt(Birthday { enabled: true, ..Birthday::default() }, Duration::from_secs(30)).await;
    assert!(o.connected, "{:?}", o.err);
    assert!(o.data_both_ways, "packet echoed through the tunnel");
    assert!(o.elapsed >= Duration::from_millis(1400), "fan-out waits for the single-socket punch: {:?}", o.elapsed);
    assert!(o.elapsed < Duration::from_secs(12), "{:?}", o.elapsed);
    // The fan-out ramps up under a per-tick packet budget, so a lucky early hit uses few ports.
    assert!(o.mappings > 8, "fan-out opened many external ports: {}", o.mappings);
    eprintln!("ON: connected in {:?}, {} external ports used, host filter dropped {}", o.elapsed, o.mappings, o.host_dropped);
}

#[tokio::test]
async fn success_rate_over_ten_runs() {
    let mut ok = 0;
    let mut times = Vec::new();
    for _ in 0..10 {
        let o = attempt(Birthday { enabled: true, ..Birthday::default() }, Duration::from_secs(30)).await;
        if o.connected && o.data_both_ways {
            ok += 1;
            times.push(o.elapsed.as_secs_f32());
        }
    }
    eprintln!("RATE: {ok}/10 connected with data both ways; connect times (s): {times:?}");
    assert!(ok >= 9, "{ok}/10");
}

// ------------------------------------------------------------ symmetric host <- public client

/// A host behind a symmetric NAT: every destination gets its own external socket on a random port,
/// and only that destination can answer through it. The host sees the remote's real address.
struct SymHostIo {
    inside: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
    ext: Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>,
    wake: tokio::sync::Notify,
    local: SocketAddr,
}

struct SymHostHandle(Arc<SymHostIo>);

#[async_trait::async_trait]
impl FrameIo for SymHostHandle {
    fn caps(&self) -> Caps {
        Caps { id: CarrierId::Udp, max_frame: 1472, punchable: true, reliable_stream: false, overhead: 0 }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.local)
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        let existing = self.0.ext.lock().unwrap().get(&to).cloned();
        let out = match existing {
            Some(o) => o,
            None => {
                let o = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
                self.0.ext.lock().unwrap().insert(to, o.clone());
                let (io, o2) = (self.0.clone(), o.clone());
                tokio::spawn(async move {
                    let mut b = [0u8; 2048];
                    while let Ok((n, from)) = o2.recv_from(&mut b).await {
                        if from == to {
                            io.inside.lock().unwrap().push_back((b[..n].to_vec(), from));
                            io.wake.notify_one();
                        }
                    }
                });
                o
            }
        };
        out.send_to(frame, to).await
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.0.inside.lock().unwrap().pop_front() {
            Some((d, from)) => {
                buf[..d.len()].copy_from_slice(&d);
                Ok((d.len(), from))
            }
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    async fn readable(&self) -> io::Result<()> {
        loop {
            let n = self.0.wake.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if !self.0.inside.lock().unwrap().is_empty() {
                return Ok(());
            }
            n.await;
        }
    }
}

/// A client behind a port-restricted cone NAT: a stable socket whose filter only admits datagrams
/// from an (ip, port) it has sent to. The host's punch comes from a fresh port nobody announced,
/// so the filter drops it, as an AWS security group or a port-restricted router does.
struct RestrictedClient(Arc<ConeIo>);

#[async_trait::async_trait]
impl FrameIo for RestrictedClient {
    fn caps(&self) -> Caps {
        ConeHandle(self.0.clone()).caps()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.sock.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        ConeHandle(self.0.clone()).send_to(frame, to).await
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        ConeHandle(self.0.clone()).try_recv_from(buf)
    }
    async fn readable(&self) -> io::Result<()> {
        self.0.sock.readable().await
    }
    /// STUN goes out on the raw socket (the filter is about the host's datagrams).
    fn udp(&self) -> Option<&UdpSocket> {
        Some(&self.0.sock)
    }
}

/// Symmetric host (emulated), client with `restricted` filter or public; the client only knows the
/// host's STUN port (useless here). Returns the connect result and how long it took.
async fn sym_host_attempt(restricted: bool, guest_bd: Birthday, budget: Duration) -> (Result<Tunnel, ConnectError>, Duration) {
    sym_host_carrier(restricted, guest_bd, budget, None).await
}

/// `carrier` as in [`attempt_carrier`]; a restricted client is plain UDP only (its filter wraps
/// a raw socket).
async fn sym_host_carrier(restricted: bool, guest_bd: Birthday, budget: Duration, carrier: Option<CarrierId>) -> (Result<Tunnel, ConnectError>, Duration) {
    assert!(!(restricted && carrier.is_some()));
    let _serial = serial().await;
    let _ = env_logger::builder().is_test(true).try_init();
    stun_init();
    let sym = Arc::new(SymHostIo {
        inside: Default::default(),
        ext: Default::default(),
        wake: Default::default(),
        local: "127.0.0.1:50002".parse().unwrap(),
    });
    // The host's own birthday spray is for cone hosts; off here (one emulated socket per destination).
    let host_bd = Birthday { enabled: false, ..Birthday::default() };
    let mut mux = MuxHost::bind(
        KEY,
        MuxConfig {
            udp: false,
            carriers: IoList(vec![Arc::new(SymHostHandle(sym))]),
            shared: carrier.into_iter().collect(),
            birthday: host_bd,
            ..MuxConfig::default()
        },
    )
    .await
    .unwrap();
    let cone = ConeIo::new();
    let client_addr = cone.sock.local_addr().unwrap();
    mux.add_punch_target(client_addr);
    let (stop, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        loop {
            while mux.try_recv().await.unwrap().is_some() {}
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
                _ = &mut stop_rx => break,
            }
        }
        mux.close().await;
    });
    let wrong: SocketAddr = "127.0.0.1:50001".parse().unwrap(); // the host's STUN-announced port
    let rv = RvJoin {
        ids: vec!["trk".into()],
        backends: Some(vec![Arc::new(FixedHost(wrong))]),
        budget: Some(budget),
        no_v6: true,
        birthday: guest_bd,
        ..Default::default()
    };
    let opts = ConnectOpts { signal: None, peer: None, room: "", key: KEY, host: false, bind_port: None, hosts: vec![], mux: true };
    let t0 = Instant::now();
    let r = if restricted {
        // the other branch uses a plain socket: bind the filter socket's port for it too
        Tunnel::connect_with_io(opts, &[], false, false, Some(rv), Arc::new(RestrictedClient(cone))).await
    } else {
        drop(cone);
        match carrier {
            None => Tunnel::connect_rv(ConnectOpts { bind_port: Some(client_addr.port()), ..opts }, rv).await,
            #[cfg(all(feature = "cr-ss", feature = "cr-awg"))]
            Some(id) => {
                let io = dial_rendezvous_carrier(id, Some(client_addr.port())).await;
                Tunnel::connect_with_io(opts, &[], false, false, Some(rv), io).await
            }
            #[cfg(not(all(feature = "cr-ss", feature = "cr-awg")))]
            Some(_) => unreachable!("needs cr-ss and cr-awg"),
        }
    };
    let elapsed = t0.elapsed();
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    (r, elapsed)
}

/// Spec 6.3 matrix 2: symmetric host, public client. The client only knows the host's STUN port
/// (useless here); the host's punch comes from a fresh port, and the client must answer there.
#[tokio::test]
async fn symmetric_host_public_client_connects_without_birthday() {
    let bd = Birthday { enabled: false, ..Birthday::default() };
    let (r, _) = sym_host_attempt(false, bd, Duration::from_secs(15)).await;
    assert!(r.expect("a public client must reach a symmetric host").assigned().is_some());
}

/// Same, with the default birthday settings: the host's punch is found before the scan would start.
#[tokio::test]
async fn symmetric_host_public_client_is_quick_with_scan_enabled() {
    let bd = Birthday { fan: 0, ..Birthday::default() };
    let (r, took) = sym_host_attempt(false, bd.clone(), Duration::from_secs(15)).await;
    assert!(r.expect("connects").assigned().is_some());
    assert!(took < bd.scan_delay, "the scan must not be needed: {took:?}");
}

/// Matrix cells b/c/f (symmetric host) <- e (filtered client): the host's punch is dropped by the
/// client's filter and the client does not know the host's port. The client must sweep the host's
/// ports from its main socket. (With `scan_pps: 0` this is the old behaviour: it never connects.)
#[tokio::test]
async fn symmetric_host_filtered_client_connects_by_port_scan() {
    // generous: an overloaded CI box sends far fewer than 30k packets/s in a debug build
    let bd = Birthday { fan: 0, scan_pps: 30_000, scan_passes: 4, scan_delay: Duration::from_millis(500), ..Birthday::default() };
    let (r, took) = sym_host_attempt(true, bd, Duration::from_secs(120)).await;
    let t = r.unwrap_or_else(|e| panic!("filtered client must reach a symmetric host by scanning: {e:?} after {took:?}"));
    assert!(t.assigned().is_some());
    eprintln!("SCAN: connected in {took:?}");
}

#[tokio::test]
async fn symmetric_host_filtered_client_without_scan_fails() {
    let bd = Birthday { fan: 0, scan_pps: 0, ..Birthday::default() };
    let (r, _) = sym_host_attempt(true, bd, Duration::from_secs(6)).await;
    assert!(r.is_err(), "no scan, no way to learn the host's port");
}

// ------------------------------------------------------------ ss / awg on the shared socket

/// The rendezvous-only carriers (invite `...|trk||ss,awg`, no endpoint) must get the same birthday
/// fan-out and port scan as plain UDP: a symmetric client NAT against a port-restricted host
/// needs the fan-out (probes from fresh ss/awg sockets), a symmetric host needs the scan.
#[cfg(all(feature = "cr-ss", feature = "cr-awg"))]
mod shared_socket_carriers {
    use super::*;

    async fn symmetric_client(id: CarrierId) {
        let o = attempt_carrier(Birthday { enabled: true, ..Birthday::default() }, Duration::from_secs(40), false, Some(id)).await;
        assert!(o.connected, "{id}: symmetric client x port-restricted host must connect by fan-out: {:?}", o.err);
        assert!(o.data_both_ways, "{id}: packet echoed through the tunnel");
        eprintln!("{id} symmetric client: connected in {:?}, {} external ports", o.elapsed, o.mappings);
    }

    async fn symmetric_host(id: CarrierId) {
        let bd = Birthday { fan: 0, scan_pps: 30_000, scan_passes: 4, scan_delay: Duration::from_millis(500), ..Birthday::default() };
        let (r, took) = sym_host_carrier(false, bd, Duration::from_secs(120), Some(id)).await;
        let t = r.unwrap_or_else(|e| panic!("{id}: public client must reach a symmetric host by port scan: {e:?} after {took:?}"));
        assert!(t.assigned().is_some());
        assert_eq!(t.caps().id, id, "stays on the {id} carrier");
        eprintln!("{id} symmetric host: connected in {took:?}");
    }

    /// A public / address-restricted client: the symmetric host's plain punch reaches the socket
    /// but the codec rejects it. Its source must be probed with a JOIN, with the scan disabled.
    async fn symmetric_host_hint(id: CarrierId) {
        let bd = Birthday { fan: 0, scan_pps: 0, ..Birthday::default() };
        let (r, took) = sym_host_carrier(false, bd, Duration::from_secs(15), Some(id)).await;
        let t = r.unwrap_or_else(|e| panic!("{id}: the host's punch source must be probed without a scan: {e:?} after {took:?}"));
        assert_eq!(t.caps().id, id, "stays on the {id} carrier");
        assert!(took < Duration::from_secs(5), "{id}: took {took:?}");
    }

    #[tokio::test]
    async fn ss_client_reaches_symmetric_host_by_punch_hint_without_scan() {
        symmetric_host_hint(CarrierId::Ss).await;
    }
    #[tokio::test]
    async fn awg_client_reaches_symmetric_host_by_punch_hint_without_scan() {
        symmetric_host_hint(CarrierId::Awg).await;
    }

    #[tokio::test]
    async fn ss_symmetric_client_reaches_port_restricted_host() {
        symmetric_client(CarrierId::Ss).await;
    }
    #[tokio::test]
    async fn awg_symmetric_client_reaches_port_restricted_host() {
        symmetric_client(CarrierId::Awg).await;
    }
    #[tokio::test]
    async fn ss_client_reaches_symmetric_host_by_port_scan() {
        symmetric_host(CarrierId::Ss).await;
    }
    #[tokio::test]
    async fn awg_client_reaches_symmetric_host_by_port_scan() {
        symmetric_host(CarrierId::Awg).await;
    }
}
