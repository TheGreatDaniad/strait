//! ss and awg found through rendezvous: the host serves them on the plain UDP socket whose STUN
//! mapping is published (`MuxConfig::shared`), the guest punches from the carrier's own socket.
//! Loopback with a fake STUN server and a port-restricted NAT model in front of the host (the
//! real-kernel-NAT runs are in docs/research/e2e-rendezvous-carriers.md).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use nat_tunnel::carrier::awg::AwgFactory;
use nat_tunnel::carrier::ss::SsFactory;
use nat_tunnel::carrier::{CarrierFactory, CarrierId, CarrierSpec, FrameIo};
use nat_tunnel::rendezvous::mock::MockHub;
use nat_tunnel::rendezvous::Rendezvous;
use nat_tunnel::transport::{
    ConnectError, ConnectOpts, Event, MuxConfig, MuxEvent, MuxHost, RvHost, RvJoin, Tunnel, MUX_HOST_IP,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

const KEY: &str = "00112233445566778899aabbccddeeff";

static REMAP: LazyLock<Mutex<HashMap<u16, SocketAddr>>> = LazyLock::new(Default::default);

/// Fake STUN: answers with the registered "mapped" address for the sender's source port (a NAT in
/// front of it), else the sender's own address.
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

/// Port-restricted NAT between one guest and the host: `fa` is the host's published endpoint,
/// `fb` the guest's. A datagram toward the host passes only once the host has sent to `fb`.
struct Nat {
    fa: SocketAddr,
    fb: SocketAddr,
    host_sent: Arc<AtomicBool>,
}

async fn nat(host: SocketAddr) -> Nat {
    let fa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let n = Nat { fa: fa.local_addr().unwrap(), fb: fb.local_addr().unwrap(), host_sent: Arc::default() };
    let guest: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    {
        let (fa, fb, guest, hs) = (fa.clone(), fb.clone(), guest.clone(), n.host_sent.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((len, from)) = fa.recv_from(&mut b).await {
                *guest.lock().unwrap() = Some(from);
                if hs.load(SeqCst) {
                    let _ = fb.send_to(&b[..len], host).await;
                }
            }
        });
    }
    let hs = n.host_sent.clone();
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
    n
}

struct Host {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    joined: Arc<Mutex<Vec<(Ipv4Addr, SocketAddr)>>>,
}

impl Host {
    async fn start(rv: Option<RvHost>, bind_port: u16, shared: Vec<CarrierId>) -> Host {
        stun_init();
        let mut mux = MuxHost::bind(
            KEY,
            MuxConfig { bind_port: Some(bind_port), stun: true, rv, shared, ..MuxConfig::default() },
        )
        .await
        .unwrap();
        let port = mux.local_port().unwrap();
        let joined: Arc<Mutex<Vec<(Ipv4Addr, SocketAddr)>>> = Arc::default();
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
                        MuxEvent::Joined { ip, from, .. } => j.lock().unwrap().push((ip, from)),
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

fn rv_host(b: Arc<dyn Rendezvous>) -> RvHost {
    RvHost { ids: vec![], backends: Some(vec![b]), no_v6: true, ..Default::default() }
}

fn rv_join(b: Arc<dyn Rendezvous>, budget: Duration) -> RvJoin {
    RvJoin { ids: vec!["trk".into()], backends: Some(vec![b]), budget: Some(budget), no_v6: true, ..Default::default() }
}

fn opts<'a>(hosts: Vec<SocketAddr>) -> ConnectOpts<'a> {
    ConnectOpts { signal: None, peer: hosts.first().copied(), room: "", key: KEY, host: false, bind_port: None, hosts, mux: true }
}

fn spec(endpoint: Option<String>, bind_port: Option<u16>) -> CarrierSpec {
    CarrierSpec { endpoint, bind_port, params: vec![("key".into(), KEY.into())] }
}

async fn dial(id: CarrierId, endpoint: Option<String>, bind_port: Option<u16>) -> Arc<dyn FrameIo> {
    let s = spec(endpoint, bind_port);
    match id {
        CarrierId::Ss => SsFactory.dial(&s).await.unwrap(),
        CarrierId::Awg => AwgFactory.dial(&s).await.unwrap(),
        _ => unreachable!(),
    }
}

async fn echo(t: &mut Tunnel, tag: &[u8]) -> bool {
    let me = t.assigned().expect("assigned").0;
    t.send_packet(&pkt(me, MUX_HOST_IP, tag)).await.unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        t.tick().await.unwrap();
        if let Some(Event::Data(p)) = t.try_recv().await.unwrap() {
            return p[12..16] == MUX_HOST_IP.octets() && &p[20..] == tag;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn bound<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), f).await.expect("test timed out")
}

/// One guest per carrier, all against one host behind a port-restricted NAT.
async fn through_nat(id: CarrierId, shared: Vec<CarrierId>, budget: u64) -> Result<(), ConnectError> {
    stun_init();
    let (hp, gp) = (free_port(), free_port());
    let n = nat(format!("127.0.0.1:{hp}").parse().unwrap()).await;
    REMAP.lock().unwrap().insert(hp, n.fa);
    REMAP.lock().unwrap().insert(gp, n.fb);
    let hub = MockHub::new();
    let host = Host::start(Some(rv_host(hub.backend("trk").arc())), hp, shared).await;
    let io = dial(id, None, Some(gp)).await;
    let r = Tunnel::connect_with_io(opts(vec![]), &[], false, false, Some(rv_join(hub.backend("trk").arc(), Duration::from_secs(budget))), io).await;
    let out = match r {
        Ok(mut t) => {
            t.enable_packet_mode();
            assert!(echo(&mut t, b"through the nat").await, "{id}: no echo");
            assert!(echo(&mut t, b"again").await, "{id}: no second echo");
            let j = host.joined.lock().unwrap().clone();
            assert_eq!(j.len(), 1);
            // the host saw the guest at its published (mapped) endpoint
            assert_eq!(j[0].1, n.fb, "{id}: joined from the mapped endpoint");
            Ok(())
        }
        Err(e) => Err(e),
    };
    host.shutdown().await;
    out
}

#[tokio::test]
async fn ss_through_rendezvous_to_a_nated_host() {
    bound(async { through_nat(CarrierId::Ss, vec![CarrierId::Ss, CarrierId::Awg], 8).await.expect("ss connects") }).await;
}

#[tokio::test]
async fn awg_through_rendezvous_to_a_nated_host() {
    bound(async { through_nat(CarrierId::Awg, vec![CarrierId::Ss, CarrierId::Awg], 8).await.expect("awg connects") }).await;
}

/// A host that does not serve the carrier on its plain socket (an older host) cannot be reached:
/// the guest ends with an explicit rendezvous failure, not a hang.
#[tokio::test]
async fn host_without_the_shared_carrier_fails_explicitly() {
    bound(async {
        for id in [CarrierId::Ss, CarrierId::Awg] {
            let Err(e) = through_nat(id, vec![], 3).await else { panic!("{id} must not connect") };
            assert!(matches!(e, ConnectError::RendezvousFailed(_)), "{id}: {e:?}");
        }
    })
    .await;
}

/// plain, ss and awg guests at the same time on one host and one socket; each is served over the
/// carrier it came in on.
#[tokio::test]
async fn plain_ss_awg_share_one_socket() {
    bound(async {
        stun_init();
        let hp = free_port();
        let host = Host::start(None, hp, vec![CarrierId::Ss, CarrierId::Awg]).await;
        let addr: SocketAddr = format!("127.0.0.1:{}", host.port).parse().unwrap();
        let mut plain = Tunnel::connect(opts(vec![addr])).await.expect("plain");
        plain.enable_packet_mode();
        let mut ss = Tunnel::connect_with_io(opts(vec![addr]), &[addr], false, false, None, dial(CarrierId::Ss, Some(addr.to_string()), None).await)
            .await
            .expect("ss");
        ss.enable_packet_mode();
        let mut awg = Tunnel::connect_with_io(opts(vec![addr]), &[addr], false, false, None, dial(CarrierId::Awg, Some(addr.to_string()), None).await)
            .await
            .expect("awg");
        awg.enable_packet_mode();
        for round in 0..3 {
            for (name, t) in [("plain", &mut plain), ("ss", &mut ss), ("awg", &mut awg)] {
                assert!(echo(t, format!("{name} {round}").as_bytes()).await, "{name} round {round}");
            }
        }
        assert_eq!(host.joined.lock().unwrap().len(), 3);
        host.shutdown().await;
    })
    .await;
}

/// `shared` without the plain socket is a startup error, not a silent no-op.
#[tokio::test]
async fn shared_needs_the_plain_socket() {
    let e = MuxHost::bind(KEY, MuxConfig { udp: false, shared: vec![CarrierId::Ss], ..MuxConfig::default() }).await.err().expect("must fail");
    assert!(e.to_string().contains("plain UDP socket"), "{e}");
    let e = MuxHost::bind(KEY, MuxConfig { shared: vec![CarrierId::Ws], ..MuxConfig::default() }).await.err().expect("must fail");
    assert!(e.to_string().contains("cannot ride"), "{e}");
}

/// ws without an address on either side: the host announces its TCP port next to the UDP
/// mapping, the guest finds it through rendezvous and the join runs over the punched TCP
/// connection.
#[cfg(feature = "cr-ws")]
#[tokio::test]
async fn ws_without_an_address_connects_through_rendezvous() {
    use nat_tunnel::carrier::ws::WsFactory;
    use nat_tunnel::transport::IoList;
    bound(async {
        stun_init();
        std::env::set_var("STUN_TCP_SERVERS", "127.0.0.1:9"); // no TCP STUN: the port number is announced as is
        let hub = MockHub::new();
        let ws = WsFactory.listen(&spec(None, None)).await.unwrap();
        let ws_port = ws.local_addr().unwrap().port();
        let mut mux = MuxHost::bind(
            KEY,
            MuxConfig { stun: true, rv: Some(rv_host(hub.backend("trk").arc())), carriers: IoList(vec![ws]), ..MuxConfig::default() },
        )
        .await
        .unwrap();
        let joined: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
        let j = joined.clone();
        let host = tokio::spawn(async move {
            loop {
                while let Some(ev) = mux.try_recv().await.unwrap() {
                    match ev {
                        MuxEvent::Packet { data, .. } => {
                            let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                            mux.send_to_ip(src, &pkt(MUX_HOST_IP, src, &data[20..])).await;
                        }
                        MuxEvent::Joined { from, .. } => j.lock().unwrap().push(from),
                        _ => {}
                    }
                }
                tokio::select! {
                    _ = mux.readable() => {}
                    _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
                }
            }
        });
        let io = WsFactory.dial(&spec(None, None)).await.unwrap();
        assert!(io.caps().punchable);
        let guest_port = io.local_addr().unwrap().port();
        let rv = rv_join(hub.backend("trk").arc(), Duration::from_secs(10));
        let mut t = Tunnel::connect_with_io(opts(vec![]), &[], false, false, Some(rv), io).await.expect("ws connects");
        t.enable_packet_mode();
        assert!(echo(&mut t, b"over punched tcp").await);
        assert_eq!(t.peer().map(|p| p.port()), Some(ws_port), "the tunnel runs to the host's TCP port");
        assert_eq!(joined.lock().unwrap().iter().map(|a| a.port()).collect::<Vec<_>>(), vec![guest_port]);
        host.abort();
    })
    .await;
}
