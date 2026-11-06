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
}

impl ConeIo {
    fn new() -> Arc<Self> {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        Arc::new(Self { sock: UdpSocket::from_std(s).unwrap(), sent_to: Default::default(), dropped: Default::default() })
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
            if self.0.sent_to.lock().unwrap().contains(&from) {
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
    stun_init();
    let cone = ConeIo::new();
    let host_pub = cone.sock.local_addr().unwrap();
    let mut mux = MuxHost::bind(
        KEY,
        MuxConfig {
            udp: false,
            carriers: IoList(vec![Arc::new(ConeHandle(cone.clone()))]),
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
    let r = Tunnel::connect_rv(
        ConnectOpts { signal: None, peer: None, room: "", key: KEY, host: false, bind_port: None, hosts: vec![], mux: true },
        rv,
    )
    .await;
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

#[tokio::test]
async fn birthday_on_symmetric_client_connects() {
    let o = attempt(Birthday { enabled: true, ..Birthday::default() }, Duration::from_secs(30)).await;
    assert!(o.connected, "{:?}", o.err);
    assert!(o.data_both_ways, "packet echoed through the tunnel");
    assert!(o.elapsed >= Duration::from_millis(1400), "fan-out waits for the single-socket punch: {:?}", o.elapsed);
    assert!(o.elapsed < Duration::from_secs(12), "{:?}", o.elapsed);
    assert!(o.mappings > 100, "fan-out opened many external ports: {}", o.mappings);
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
