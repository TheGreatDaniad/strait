//! Rendezvous methods wired through the transport (host `MuxHost` + guest `Tunnel::connect_rv`).
//! Loopback only: a fake STUN server on 127.0.0.1 gives every socket its own address as "mapped"
//! (or a forwarder's address, to model a NAT), and `MockHub` is the rendezvous internet.
//!
//! NAT matrix (`nat_matrix_*`; host behind a cone NAT, client cone or symmetric; a symmetric
//! client's published port P differs from the port E its packets use toward the host):
//!
//! | client \ host | FullCone | AddressRestricted | PortRestricted |
//! |---------------|----------|-------------------|----------------|
//! | Cone          | connects | connects          | connects       |
//! | Symmetric     | connects | connects          | RendezvousFailed |
//!
//! Symmetric x AddressRestricted works because the host's fire at the client's published
//! IP:P opens the host NAT for that IP; the JOIN from IP:E then passes and the ACCEPT goes back
//! to the observed source. Symmetric x PortRestricted cannot: the host never learns E.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use nat_tunnel::rendezvous::mock::{MockBackend, MockHub};
use nat_tunnel::rendezvous::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvCtx, RvError};
use nat_tunnel::transport::{
    ConnectError, ConnectOpts, Event, MuxConfig, MuxEvent, MuxHost, RvHost, RvJoin, Tunnel, MUX_HOST_IP,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const KEY: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------- fake STUN

static REMAP: LazyLock<Mutex<HashMap<u16, SocketAddr>>> = LazyLock::new(Default::default);

/// One STUN server for the whole test binary. It answers with the sender's own address unless a
/// test registered a different "mapped" address for that source port (a NAT in front of it).
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
                let m = REMAP.lock().unwrap().get(&from.port()).copied().unwrap_or(from);
                let SocketAddr::V4(m) = m else { continue };
                let mut r = vec![0x01, 0x01, 0, 12];
                r.extend_from_slice(&b[4..20]);
                r.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
                r.extend_from_slice(&(m.port() ^ 0x2112).to_be_bytes());
                let cookie = 0x2112_A442u32.to_be_bytes();
                for (o, c) in m.ip().octets().iter().zip(cookie) {
                    r.push(o ^ c);
                }
                let _ = sock.send_to(&r, from);
            }
        });
        std::env::set_var("STUN_SERVER", "127.0.0.1");
        std::env::set_var("STUN_PORT", port.to_string());
    });
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------- packets

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

// ---------------------------------------------------------------- host

struct Host {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    joined: Arc<AtomicUsize>,
}

impl Host {
    /// A rendezvous-only host: nothing is published except through `rv`. Echoes packets
    /// addressed to the host back to the sender.
    async fn start(rv: RvHost, bind_port: u16) -> Host {
        stun_init();
        let mut mux = MuxHost::bind(
            KEY,
            MuxConfig { bind_port: Some(bind_port), stun: true, rv: Some(rv), ..MuxConfig::default() },
        )
        .await
        .unwrap();
        let port = mux.local_port().unwrap();
        let joined = Arc::new(AtomicUsize::new(0));
        let j = joined.clone();
        let (stop, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                while let Some(ev) = mux.try_recv().await.unwrap() {
                    match ev {
                        MuxEvent::Packet { data, .. } if data[16..20] == MUX_HOST_IP.octets() => {
                            let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                            mux.send_to_ip(src, &pkt(MUX_HOST_IP, src, &data[20..])).await;
                        }
                        MuxEvent::Joined { .. } => {
                            j.fetch_add(1, SeqCst);
                        }
                        _ => {}
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
        Host { port, stop: Some(stop), task, joined }
    }

    async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(10), self.task).await.expect("host closes").unwrap();
    }
}

fn rv_host(backends: Vec<Arc<dyn Rendezvous>>) -> RvHost {
    RvHost { ids: vec![], backends: Some(backends), no_v6: true, ..Default::default() }
}

fn rv_join(ids: &[&str], backends: Vec<Arc<dyn Rendezvous>>) -> RvJoin {
    RvJoin {
        ids: ids.iter().map(|s| s.to_string()).collect(),
        backends: Some(backends),
        budget: Some(Duration::from_secs(20)),
        no_v6: true,
        ..Default::default()
    }
}

// ---------------------------------------------------------------- guest

/// Invite = key + rv only: no host endpoint, no signal server.
async fn join(rv: RvJoin, bind_port: Option<u16>) -> Result<Tunnel, ConnectError> {
    stun_init();
    let mut t = Tunnel::connect_rv(
        ConnectOpts {
            signal: None,
            peer: None,
            room: "",
            key: KEY,
            host: false,
            bind_port,
            hosts: vec![],
            mux: true,
        },
        rv,
    )
    .await?;
    t.enable_packet_mode();
    Ok(t)
}

async fn recv_pkt(t: &mut Tunnel, within: Duration) -> Option<Vec<u8>> {
    let end = Instant::now() + within;
    while Instant::now() < end {
        t.tick().await.unwrap();
        if let Some(Event::Data(d)) = t.try_recv().await.unwrap() {
            return Some(d);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}

/// Guest -> host -> guest.
async fn echo(t: &mut Tunnel, tag: &[u8]) -> bool {
    let me = t.assigned().expect("assigned").0;
    t.send_packet(&pkt(me, MUX_HOST_IP, tag)).await.unwrap();
    match recv_pkt(t, Duration::from_secs(5)).await {
        Some(p) => p[12..16] == MUX_HOST_IP.octets() && &p[20..] == tag,
        None => false,
    }
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < end, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn bound<F: std::future::Future>(f: F) -> impl std::future::Future<Output = F::Output> {
    async { tokio::time::timeout(Duration::from_secs(90), f).await.expect("test timed out") }
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn guest_finds_host_with_no_published_endpoint() {
    bound(async {
        let hub = MockHub::new();
        let (hb, gb) = (hub.backend("trk"), hub.backend("trk"));
        let host = Host::start(rv_host(vec![hb.arc()]), 0).await;
        let mut g = join(rv_join(&["trk"], vec![gb.arc()]), None).await.ok().expect("guest connects");
        assert_eq!(g.assigned().unwrap().2, MUX_HOST_IP);
        assert!(echo(&mut g, b"one").await);
        assert!(echo(&mut g, b"two").await);
        assert_eq!(host.joined.load(SeqCst), 1);

        // The guest's runner is cancelled right after the tunnel is up and cleans up.
        until("guest runner cleanup", || gb.clean_exits() == 1).await;
        assert_eq!(hb.clean_exits(), 0, "host stays announced while serving");
        host.shutdown().await;
        assert_eq!(hb.clean_exits(), 1, "host runner cancelled on close");
        assert_eq!((gb.runs(), hb.runs()), (1, 1));
        assert_eq!(hub.mailboxes(), 0);
    })
    .await;
}

#[tokio::test]
async fn late_candidate_still_connects() {
    bound(async {
        let hub = MockHub::new();
        let host = Host::start(rv_host(vec![hub.backend("nostr").latency(Duration::from_secs(3)).arc()]), 0).await;
        let t0 = Instant::now();
        let mut g = join(rv_join(&["nostr"], vec![hub.backend("nostr").arc()]), None).await.ok().expect("connects");
        assert!(t0.elapsed() >= Duration::from_millis(2500), "host only appeared after ~3 s: {:?}", t0.elapsed());
        assert!(echo(&mut g, b"late").await);
        host.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn two_guests_join_one_rendezvous_only_host() {
    bound(async {
        let hub = MockHub::new();
        let host = Host::start(rv_host(vec![hub.backend("trk").arc()]), 0).await;
        let g1b = hub.backend("trk");
        let mut g1 = join(rv_join(&["trk"], vec![g1b.arc()]), None).await.ok().expect("guest 1");
        until("guest 1 runner cleanup", || g1b.clean_exits() == 1).await;
        let mut g2 = join(rv_join(&["trk"], vec![hub.backend("trk").arc()]), None).await.ok().expect("guest 2");
        assert_ne!(g1.assigned().unwrap().0, g2.assigned().unwrap().0);
        assert!(echo(&mut g1, b"first").await);
        assert!(echo(&mut g2, b"second").await);
        assert!(echo(&mut g1, b"first again").await);
        assert_eq!(host.joined.load(SeqCst), 2);
        host.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn one_method_blocked_one_works() {
    bound(async {
        let hub = MockHub::new();
        let (hbad, gbad) = (hub.backend("trk").blocked(), hub.backend("trk").blocked());
        let host = Host::start(rv_host(vec![hbad.arc(), hub.backend("nostr").arc()]), 0).await;
        let mut g = join(rv_join(&["trk", "nostr"], vec![gbad.arc(), hub.backend("nostr").arc()]), None)
            .await
            .ok()
            .expect("the working method carries it");
        assert!(echo(&mut g, b"x").await);
        assert_eq!((gbad.runs(), hbad.runs()), (1, 1), "blocked methods are tried once, not retried");
        host.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn all_methods_blocked_is_rendezvous_failed() {
    bound(async {
        let hub = MockHub::new();
        let r = join(
            rv_join(&["trk", "nostr"], vec![hub.backend("trk").blocked().arc(), hub.backend("nostr").blocked().arc()]),
            None,
        )
        .await;
        let Err(e) = r else { panic!("must fail") };
        match &e {
            ConnectError::RendezvousFailed(s) => assert_eq!(s, "trk: blocked; nostr: blocked"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            e.to_string(),
            "The host could not be found or reached through trk: blocked; nostr: blocked. \
             Check that they are sharing and that these services work from your network."
        );
        // and it survives the io::Error wrapping the app uses
        let io: std::io::Error = e.into();
        assert!(matches!(ConnectError::from_io(&io), Some(ConnectError::RendezvousFailed(_))));
    })
    .await;
}

#[tokio::test]
async fn disabled_and_unknown_methods() {
    bound(async {
        let hub = MockHub::new();
        let host = Host::start(rv_host(vec![hub.backend("trk").arc(), hub.backend("nostr").arc()]), 0).await;

        // one disabled: its backend is never started, the other carries the join
        let (gt, gn) = (hub.backend("trk"), hub.backend("nostr"));
        let mut rv = rv_join(&["trk", "nostr"], vec![gt.arc(), gn.arc()]);
        rv.disable = vec!["trk".into()];
        let mut g = join(rv, None).await.ok().expect("nostr works");
        assert!(echo(&mut g, b"x").await);
        assert_eq!(gt.runs(), 0, "disabled method never runs");
        assert_eq!(gn.runs(), 1);

        // unknown ids are ignored
        let rv = rv_join(&["quantum", "nostr"], vec![hub.backend("nostr").arc()]);
        let mut g2 = join(rv, None).await.ok().expect("unknown id ignored");
        assert!(echo(&mut g2, b"y").await);
        host.shutdown().await;

        // everything disabled / only unknown ids: a typed error, immediately, no network
        let mut rv = rv_join(&["trk"], vec![hub.backend("trk").arc()]);
        rv.disable = vec!["trk".into()];
        let t0 = Instant::now();
        let Err(e) = join(rv, None).await else { panic!("must fail") };
        assert!(matches!(e, ConnectError::NoRendezvous), "{e:?}");
        assert_eq!(
            e.to_string(),
            "None of the ways listed in the invite to find the host are available on this device."
        );
        let rv = RvJoin { ids: vec!["quantum".into()], ..Default::default() };
        assert!(matches!(join(rv, None).await, Err(ConnectError::NoRendezvous)));
        assert!(t0.elapsed() < Duration::from_secs(2));
    })
    .await;
}

// ------------------------------------------------ port-restricted NAT model

/// Two sockets between a guest and a host. `fa` is the host's published endpoint (the guest sends
/// there); `fb` is the guest's published endpoint (the host sends there and sees the guest's
/// datagrams coming from it). Port-restricted filter at the host: a datagram toward the host is
/// dropped unless the host has already sent to `fb`. The guest's own filter needs the guest to
/// have sent to `fa` first (it always has when the host's replies arrive).
struct Nat {
    fa: SocketAddr,
    fb: SocketAddr,
    dropped: Arc<AtomicUsize>,
    delivered: Arc<AtomicUsize>,
    host_sent: Arc<AtomicBool>,
}

async fn nat(host: SocketAddr) -> Nat {
    let fa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let n = Nat {
        fa: fa.local_addr().unwrap(),
        fb: fb.local_addr().unwrap(),
        dropped: Arc::default(),
        delivered: Arc::default(),
        host_sent: Arc::default(),
    };
    let guest: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    {
        let (fa, fb, guest) = (fa.clone(), fb.clone(), guest.clone());
        let (hs, dropped, delivered) = (n.host_sent.clone(), n.dropped.clone(), n.delivered.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((len, from)) = fa.recv_from(&mut b).await {
                *guest.lock().unwrap() = Some(from);
                if hs.load(SeqCst) {
                    delivered.fetch_add(1, SeqCst);
                    let _ = fb.send_to(&b[..len], host).await;
                } else {
                    dropped.fetch_add(1, SeqCst);
                }
            }
        });
    }
    {
        let (hs, fa, fb) = (n.host_sent.clone(), fa.clone(), fb.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((len, from)) = fb.recv_from(&mut b).await {
                if from.port() != host.port() {
                    continue;
                }
                hs.store(true, SeqCst);
                let g = *guest.lock().unwrap();
                if let Some(g) = g {
                    let _ = fa.send_to(&b[..len], g).await;
                }
            }
        });
    }
    n
}

#[derive(Clone, Copy)]
enum HostNat {
    Full,
    Addr,
    Port,
}

/// Host-side filter plus a client NAT. The guest sends to `front` (the host's published
/// endpoint); its packets leave through external socket E (E == P for a cone client, a fresh
/// port for a symmetric one) toward the host, which sees E as the source. P is what the client
/// published. Filter at the host: Full accepts all, Addr accepts once the host has sent to any
/// port of the client's IP, Port only from a port the host sent to. A symmetric client NAT
/// drops anything arriving on P (its mapping is bound to the STUN destination).
async fn nat2(host: SocketAddr, mode: HostNat, symmetric: bool) -> (SocketAddr, SocketAddr) {
    use std::collections::HashSet;
    let sock = || async { Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()) };
    let (front, p) = (sock().await, sock().await);
    let e = if symmetric { sock().await } else { p.clone() };
    let guest: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let sent: Arc<Mutex<HashSet<u16>>> = Arc::default();
    {
        let (front, e, guest, sent) = (front.clone(), e.clone(), guest.clone(), sent.clone());
        let ep = e.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = front.recv_from(&mut b).await {
                *guest.lock().unwrap() = Some(from);
                let ok = match mode {
                    HostNat::Full => true,
                    HostNat::Addr => !sent.lock().unwrap().is_empty(),
                    HostNat::Port => sent.lock().unwrap().contains(&ep),
                };
                if ok {
                    let _ = e.send_to(&b[..n], host).await;
                }
            }
        });
    }
    let mut socks = vec![(p.clone(), !symmetric)];
    if symmetric {
        socks.push((e, true));
    }
    for (s, is_e) in socks {
        let (front, guest, sent) = (front.clone(), guest.clone(), sent.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let port = s.local_addr().unwrap().port();
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                if from != host {
                    continue;
                }
                sent.lock().unwrap().insert(port); // the host sent to this client port
                let g = *guest.lock().unwrap();
                if let (true, Some(g)) = (is_e, g) {
                    let _ = front.send_to(&b[..n], g).await;
                }
            }
        });
    }
    (front.local_addr().unwrap(), p.local_addr().unwrap())
}

async fn matrix(mode: HostNat, symmetric: bool, expect_ok: bool) {
    bound(async {
        stun_init();
        let (hp, gp) = (free_port(), free_port());
        let (front, publ) = nat2(format!("127.0.0.1:{hp}").parse().unwrap(), mode, symmetric).await;
        REMAP.lock().unwrap().insert(hp, front);
        REMAP.lock().unwrap().insert(gp, publ);
        let hub = MockHub::new();
        let host = Host::start(rv_host(vec![hub.backend("trk").arc()]), hp).await;
        let mut rv = rv_join(&["trk"], vec![hub.backend("trk").arc()]);
        rv.budget = Some(Duration::from_secs(if expect_ok { 20 } else { 5 }));
        let t0 = Instant::now();
        let r = join(rv, Some(gp)).await;
        if expect_ok {
            let mut g = r.ok().expect("must connect");
            assert!(echo(&mut g, b"matrix").await);
        } else {
            let Err(e) = r else { panic!("must not connect") };
            assert!(matches!(e, ConnectError::RendezvousFailed(_)), "{e:?}");
            assert!(t0.elapsed() < Duration::from_secs(10), "bounded by the budget: {:?}", t0.elapsed());
        }
        host.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn nat_matrix_cone_client_full() { matrix(HostNat::Full, false, true).await }
#[tokio::test]
async fn nat_matrix_cone_client_addr() { matrix(HostNat::Addr, false, true).await }
#[tokio::test]
async fn nat_matrix_cone_client_port() { matrix(HostNat::Port, false, true).await }
#[tokio::test]
async fn nat_matrix_symmetric_client_full() { matrix(HostNat::Full, true, true).await }
#[tokio::test]
async fn nat_matrix_symmetric_client_addr() { matrix(HostNat::Addr, true, true).await }
#[tokio::test]
async fn nat_matrix_symmetric_client_port() { matrix(HostNat::Port, true, false).await }

/// Wraps a backend so the host never learns the client's endpoint (it still publishes its own).
struct DeafHost(MockBackend);

#[async_trait::async_trait]
impl Rendezvous for DeafHost {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn disclosure(&self) -> Disclosure {
        self.0.disclosure()
    }
    async fn probe(&self, t: Duration) -> ProbeStatus {
        self.0.probe(t).await
    }
    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        if ctx.role == Role::Host {
            let (sink, mut drain) = mpsc::channel(16);
            tokio::spawn(async move { while drain.recv().await.is_some() {} });
            return self.0.run(ctx, sink, cancel).await;
        }
        self.0.run(ctx, tx, cancel).await
    }
}

/// Host and guest sockets live on known ports so the fake STUN can report the forwarder's
/// addresses as their "mapped" endpoints.
async fn behind_nat(host_fires: bool, budget: Duration) -> (Result<Tunnel, ConnectError>, Nat, MockBackend, Option<Host>) {
    stun_init();
    let (hp, gp) = (free_port(), free_port());
    let n = nat(format!("127.0.0.1:{hp}").parse().unwrap()).await;
    REMAP.lock().unwrap().insert(hp, n.fa);
    REMAP.lock().unwrap().insert(gp, n.fb);

    let hub = MockHub::new();
    let hb = hub.backend("trk");
    let hb_arc: Arc<dyn Rendezvous> = if host_fires { hb.arc() } else { Arc::new(DeafHost(hb.clone())) };
    let host = Host::start(rv_host(vec![hb_arc]), hp).await;
    let gb = hub.backend("trk");
    let mut rv = rv_join(&["trk"], vec![gb.arc()]);
    rv.budget = Some(budget);
    let r = join(rv, Some(gp)).await;
    (r, n, gb, Some(host))
}

#[tokio::test]
async fn punch_needs_the_host_to_fire_first() {
    bound(async {
        let (r, n, gb, host) = behind_nat(true, Duration::from_secs(20)).await;
        let mut g = r.ok().expect("connects once the host fires at the client's endpoint");
        assert!(n.host_sent.load(SeqCst), "the host sent to the client candidate");
        assert!(n.delivered.load(SeqCst) > 0);
        assert!(echo(&mut g, b"through the filter").await);
        until("runner cleanup", || gb.clean_exits() == 1).await;
        host.unwrap().shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn without_the_host_firing_the_filter_wins() {
    bound(async {
        let (r, n, gb, host) = behind_nat(false, Duration::from_secs(4)).await;
        let Err(e) = r else { panic!("the host never fired, the NAT must drop every JOIN") };
        assert!(
            matches!(&e, ConnectError::RendezvousFailed(s) if s.starts_with("trk: found the host but could not connect (punched ") && s.ends_with(" at 1 address, no answer)")),
            "{e:?}"
        );
        assert!(!n.host_sent.load(SeqCst));
        assert_eq!(n.delivered.load(SeqCst), 0);
        assert!(n.dropped.load(SeqCst) >= 8, "the guest kept firing: {}", n.dropped.load(SeqCst));
        // error path cancels the runner too
        until("runner cleanup after timeout", || gb.clean_exits() == 1).await;
        host.unwrap().shutdown().await;
    })
    .await;
}

// ------------------------------------------------ real tracker backend

#[cfg(feature = "rv-trk")]
mod trk {
    use super::*;
    use nat_tunnel::rendezvous::RvConfig;

    /// BEP 15 tracker: CONNECT and ANNOUNCE, returns every stored endpoint for the info_hash
    /// (the caller too, like real trackers). Copied in spirit from tests/rv_trackers.rs.
    fn fake_tracker() -> (String, Arc<Mutex<Vec<(u32, u16)>>>) {
        const CONN: u64 = 0xdead_beef_1234;
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let log = Arc::new(Mutex::new(Vec::new()));
        let l2 = log.clone();
        tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut swarm: Vec<([u8; 20], SocketAddr)> = Vec::new();
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let b = &buf[..n];
                if n < 16 {
                    continue;
                }
                let (action, tid) = (u32::from_be_bytes(b[8..12].try_into().unwrap()), &b[12..16]);
                let mut out = Vec::new();
                if action == 0 && n == 16 {
                    out.extend_from_slice(&0u32.to_be_bytes());
                    out.extend_from_slice(tid);
                    out.extend_from_slice(&CONN.to_be_bytes());
                } else if action == 1 && n == 98 && u64::from_be_bytes(b[0..8].try_into().unwrap()) == CONN {
                    let ih: [u8; 20] = b[16..36].try_into().unwrap();
                    let event = u32::from_be_bytes(b[80..84].try_into().unwrap());
                    let port = u16::from_be_bytes(b[96..98].try_into().unwrap());
                    l2.lock().unwrap().push((event, port));
                    let ep = SocketAddr::new(from.ip(), port);
                    swarm.retain(|(h, e)| !(h == &ih && e == &ep));
                    if event != 3 {
                        swarm.push((ih, ep));
                    }
                    out.extend_from_slice(&1u32.to_be_bytes());
                    out.extend_from_slice(tid);
                    out.extend_from_slice(&[0, 0, 7, 8, 0, 0, 0, 1, 0, 0, 0, 1]);
                    for (_, e) in swarm.iter().filter(|(h, _)| h == &ih) {
                        if let SocketAddr::V4(v) = e {
                            out.extend_from_slice(&v.ip().octets());
                            out.extend_from_slice(&v.port().to_be_bytes());
                        }
                    }
                } else {
                    continue;
                }
                let _ = sock.send_to(&out, from).await;
            }
        });
        (addr, log)
    }

    #[tokio::test]
    async fn host_announced_via_real_tracker_backend_is_found_and_joined() {
        bound(async {
            let (tracker, log) = fake_tracker();
            let cfg = RvConfig { trackers: vec![tracker], ..Default::default() };
            let host = Host::start(
                RvHost { ids: vec!["trk".into()], cfg: cfg.clone(), backends: None, no_v6: true },
                0,
            )
            .await;
            // The announced port is the STUN-mapped port of the punch socket (== its real port here).
            until("host announce", || log.lock().unwrap().iter().any(|(e, p)| *e == 2 && *p == host.port)).await;

            let rv = RvJoin {
                ids: vec!["trk".into()],
                cfg,
                budget: Some(Duration::from_secs(30)),
                no_v6: true,
                ..Default::default()
            };
            let mut g = join(rv, None).await.ok().expect("guest finds the host through the tracker");
            assert!(echo(&mut g, b"via tracker").await);
            host.shutdown().await;
            // the host said `stopped` (event 3) on its way out
            until("stopped announce", || log.lock().unwrap().iter().any(|(e, p)| *e == 3 && *p != 0)).await;
        })
        .await;
    }
}

// ---------------------------------------------------------------- address families

/// Reports fixed candidates, whatever its role, then idles until cancelled.
struct Fixed(Vec<SocketAddr>);

#[async_trait::async_trait]
impl Rendezvous for Fixed {
    fn id(&self) -> &'static str {
        "trk"
    }
    fn disclosure(&self) -> Disclosure {
        MockHub::new().backend("trk").disclosure()
    }
    async fn probe(&self, _: Duration) -> ProbeStatus {
        ProbeStatus::Reachable { rtt_ms: 0 }
    }
    async fn run(&self, _: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        for &addr in &self.0 {
            let _ = tx.send(Candidate { addr, via: "trk" }).await;
        }
        cancel.cancelled().await;
        Ok(())
    }
}

#[tokio::test]
async fn guest_without_ipv6_says_so_when_only_v6_addresses_exist() {
    bound(async {
        stun_init();
        let mut rv = rv_join(&["trk"], vec![Arc::new(Fixed(vec!["[2001:db8::1]:5555".parse().unwrap()]))]);
        rv.budget = Some(Duration::from_secs(3));
        let opts = ConnectOpts { signal: None, peer: None, room: "", key: KEY, host: false, bind_port: None, hosts: vec![], mux: true };
        let Err(e) = Tunnel::connect_ladder_rv(opts, &[], false, false, Some(rv)).await else { panic!("must fail") };
        match &e {
            ConnectError::RendezvousFailed(s) => assert_eq!(
                s,
                "trk: found the host but could not connect (only IPv6 addresses, and this network has no IPv6; 1 skipped)"
            ),
            other => panic!("{other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn host_only_fires_at_client_addresses_it_can_route() {
    bound(async {
        stun_init();
        let (v4, v6): (SocketAddr, SocketAddr) = ("127.0.0.1:9".parse().unwrap(), "[2001:db8::1]:5555".parse().unwrap());
        for (route, want) in [(false, vec![v4]), (true, vec![v4, v6])] {
            let rv = rv_host(vec![Arc::new(Fixed(vec![v6, v4]))]);
            let mut mux = MuxHost::bind(KEY, MuxConfig { bind_port: Some(0), stun: true, rv: Some(rv), ..MuxConfig::default() })
                .await
                .unwrap();
            mux.set_v6_route(route);
            let end = Instant::now() + Duration::from_millis(1500);
            while Instant::now() < end {
                while mux.try_recv().await.unwrap().is_some() {}
                mux.tick().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut got = mux.punch_targets();
            got.sort();
            let mut want = want;
            want.sort();
            assert_eq!(got, want, "v6 route = {route}");
            mux.close().await;
        }
    })
    .await;
}
