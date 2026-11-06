//! Carriers through the REAL transport (`MuxHost`, `Tunnel`, the guest ladder): loopback only, the
//! only thing faked is the network path (an in-memory link, a capturing UDP proxy, and for xray a
//! fake sidecar that re-executes this test binary). No Xray, no third-party software.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat_tunnel::app::{self, CarrierCfg, GuestOpts};
use nat_tunnel::carrier::mem::{self, MemCfg};
use nat_tunnel::carrier::{CarrierEntry, CarrierId, Caps, FrameIo};
use nat_tunnel::transport::{
    effective_mtu, ConnectError, ConnectOpts, Event, IoList, MuxConfig, MuxEvent, MuxHost, Tunnel, MUX_HOST_IP,
};

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const BAD_KEY: &str = "ffeeddccbbaa99887766554433221100";
const SNI: &str = "www.example.org";

// ------------------------------------------------------------------ fixtures

fn pkt(src: Ipv4Addr, dst: Ipv4Addr, total: usize) -> Vec<u8> {
    let mut p = vec![0u8; total.max(20)];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    for (i, b) in p[20..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    p
}

fn src_of(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[12], p[13], p[14], p[15])
}

fn free_port() -> u16 {
    static USED: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    loop {
        let p = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() && !USED.lock().unwrap().contains(&p) {
            USED.lock().unwrap().push(p);
            return p;
        }
    }
}

static N_TMP: AtomicU32 = AtomicU32::new(0);
struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("strait-ci-{}-{}", std::process::id(), N_TMP.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn file(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A mux host that echoes packets for itself and forwards packets between clients.
struct Host {
    rx: Arc<AtomicUsize>,
    max_rx: Arc<AtomicUsize>,
    oversize: Arc<AtomicU64>,
    tun_mtu: usize,
    caps: Vec<Caps>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Host {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_host(udp: bool, ios: Vec<Arc<dyn FrameIo>>, setup: impl FnOnce(&mut MuxHost)) -> (Host, Option<u16>) {
    let mut mux = MuxHost::bind(
        KEY,
        MuxConfig { max_clients: 8, bind_port: Some(0), udp, carriers: IoList(ios), ..MuxConfig::default() },
    )
    .await
    .unwrap();
    setup(&mut mux);
    let port = udp.then(|| mux.local_port().unwrap());
    let (rx, max_rx, oversize) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicU64::new(0)));
    let (tun_mtu, caps) = (mux.tun_mtu(), mux.caps());
    let (r, m, o) = (rx.clone(), max_rx.clone(), oversize.clone());
    let task = tokio::spawn(async move {
        loop {
            while let Some(ev) = mux.try_recv().await.unwrap() {
                if let MuxEvent::Packet { data, .. } = ev {
                    r.fetch_add(1, Ordering::Relaxed);
                    m.fetch_max(data.len(), Ordering::Relaxed);
                    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                    if dst == MUX_HOST_IP {
                        let reply = pkt(MUX_HOST_IP, src_of(&data), data.len());
                        mux.send_to_ip(src_of(&data), &reply).await;
                    } else {
                        mux.send_to_ip(dst, &data).await;
                    }
                }
            }
            o.store(mux.oversize_drops(), Ordering::Relaxed);
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
            }
        }
    });
    (Host { rx, max_rx, oversize, tun_mtu, caps, task }, port)
}

async fn recv(t: &mut Tunnel, within: Duration) -> Option<Event> {
    let end = Instant::now() + within;
    loop {
        if let Some(e) = t.try_recv().await.unwrap() {
            return Some(e);
        }
        t.tick().await.unwrap();
        let left = end.checked_duration_since(Instant::now())?;
        tokio::select! {
            _ = t.readable() => {}
            _ = tokio::time::sleep(left.min(Duration::from_millis(20))) => {}
        }
    }
}

async fn recv_data(t: &mut Tunnel, within: Duration) -> Option<Vec<u8>> {
    match recv(t, within).await {
        Some(Event::Data(d)) => Some(d),
        _ => None,
    }
}

fn guest(carriers: Vec<CarrierEntry>, tmp: &Tmp) -> GuestOpts {
    GuestOpts {
        key: KEY.into(),
        carriers,
        last_working_file: Some(tmp.file("last_carrier")),
        ladder_stagger: Some(Duration::from_millis(100)),
        ..Default::default()
    }
}

async fn join(opts: &GuestOpts) -> Result<Tunnel, ConnectError> {
    let mut t = app::guest_connect(opts, true).await?;
    t.enable_packet_mode();
    Ok(t)
}

fn my_ip(t: &Tunnel) -> Ipv4Addr {
    t.assigned().expect("assigned").0
}

async fn ping(t: &mut Tunnel, total: usize) -> Option<Vec<u8>> {
    let p = pkt(my_ip(t), MUX_HOST_IP, total);
    t.send_packet(&p).await.unwrap();
    recv_data(t, Duration::from_secs(3)).await
}

// ------------------------------------------------------------------ the scenario every carrier runs

struct Scenario {
    id: CarrierId,
    /// What the host listens on (local address) and what the invite advertises.
    host: CarrierEntry,
    client: CarrierEntry,
    cfg: CarrierCfg,
}

/// host + two guests through the carrier only (no UDP endpoint anywhere): data both ways, guest to
/// guest, the MTU contract, and a reconnect after Bye.
async fn run_scenario(sc: &Scenario) -> Caps {
    let _ = env_logger::try_init();
    let tmp = Tmp::new();
    let (ios, failed) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    assert!(failed.is_empty(), "{failed:?}");
    let (host, _) = start_host(false, ios, |_| {}).await;
    let mut opts = guest(vec![sc.client.clone()], &tmp);
    opts.carrier_cfg = sc.cfg.clone();

    let mut a = join(&opts).await.unwrap_or_else(|e| panic!("{}: {e}", sc.id));
    assert_eq!(a.caps().id, sc.id, "connected through the wrong carrier");
    assert_eq!(std::fs::read_to_string(tmp.file("last_carrier")).unwrap(), sc.id.as_str(), "last working remembered");

    // both directions: the echo is host -> client
    let echo = ping(&mut a, 120).await.expect("echo");
    assert_eq!((echo.len(), src_of(&echo)), (120, MUX_HOST_IP));

    // two guests, guest to guest through the host
    let mut b = join(&opts).await.unwrap();
    assert_ne!(my_ip(&a), my_ip(&b));
    let p = pkt(my_ip(&a), my_ip(&b), 200);
    a.send_packet(&p).await.unwrap();
    assert_eq!(recv_data(&mut b, Duration::from_secs(3)).await.as_deref(), Some(&p[..]));

    // MTU: the contract is caps-derived and shared by both ends
    let mtu = a.tun_mtu();
    assert_eq!(mtu, a.caps().tun_mtu());
    assert_eq!(mtu, effective_mtu(&host.caps), "host and client agree on the TUN MTU");
    assert_eq!(host.tun_mtu, mtu);
    assert!(mtu >= 1280, "{} gives only {mtu}", sc.id);
    assert!(mtu + 35 <= a.caps().max_frame || mtu == 1400);
    let at_max = ping(&mut a, mtu).await.unwrap_or_else(|| panic!("{}: a packet of the max TUN MTU ({mtu}) must pass", sc.id));
    assert_eq!(at_max.len(), mtu);
    let before = host.rx.load(Ordering::Relaxed);
    assert_eq!(a.oversize_drops(), 0);
    a.send_packet(&pkt(my_ip(&a), MUX_HOST_IP, mtu + 1)).await.unwrap();
    assert_eq!(a.oversize_drops(), 1, "an oversize packet is counted, not silently dropped");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(host.rx.load(Ordering::Relaxed), before, "it never reached the host");
    assert!(host.max_rx.load(Ordering::Relaxed) <= mtu);
    // the session still works afterwards
    assert!(ping(&mut a, 64).await.is_some());

    // reconnect after Bye
    a.close().await.unwrap();
    let mut a2 = join(&opts).await.expect("reconnect after Bye");
    assert!(ping(&mut a2, 90).await.is_some());
    assert_eq!(b.oversize_drops(), 0);
    a2.caps()
}

/// A wrong invite key never gets in; the failure names the carrier.
async fn run_wrong_key(sc: &Scenario) {
    let tmp = Tmp::new();
    let (ios, failed) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    assert!(failed.is_empty(), "{failed:?}");
    let (_host, _) = start_host(false, ios, |_| {}).await;
    let mut opts = guest(vec![sc.client.clone()], &tmp);
    opts.carrier_cfg = sc.cfg.clone();
    opts.key = BAD_KEY.into();
    match join(&opts).await {
        Err(ConnectError::CarriersFailed(s)) => assert!(s.starts_with(sc.id.as_str()), "{s}"),
        Err(e) => panic!("unexpected {e}"),
        Ok(_) => panic!("a wrong key connected"),
    }
    assert!(!tmp.file("last_carrier").exists());
}

// ------------------------------------------------------------------ ss

#[cfg(feature = "cr-ss")]
fn ss_scenario() -> Scenario {
    let ep = format!("127.0.0.1:{}", free_port());
    Scenario {
        id: CarrierId::Ss,
        host: CarrierEntry::new(CarrierId::Ss).at(ep.clone()),
        client: CarrierEntry::new(CarrierId::Ss).at(ep),
        cfg: CarrierCfg::default(),
    }
}

#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn ss_carrier_end_to_end() {
    let caps = run_scenario(&ss_scenario()).await;
    // 1414 byte frames: the TUN MTU shrinks below today's 1400
    assert_eq!(effective_mtu(&[caps]), caps.max_frame - 35);
    assert_eq!(caps.tun_mtu(), 1379);
}

#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn ss_wrong_key() {
    run_wrong_key(&ss_scenario()).await;
}

// ------------------------------------------------------------------ awg

#[cfg(feature = "cr-awg")]
fn awg_scenario() -> Scenario {
    let ep = format!("127.0.0.1:{}", free_port());
    Scenario {
        id: CarrierId::Awg,
        host: CarrierEntry::new(CarrierId::Awg).at(ep.clone()),
        client: CarrierEntry::new(CarrierId::Awg).at(ep),
        cfg: CarrierCfg::default(),
    }
}

#[cfg(feature = "cr-awg")]
#[tokio::test]
async fn awg_carrier_end_to_end() {
    run_scenario(&awg_scenario()).await;
}

#[cfg(feature = "cr-awg")]
#[tokio::test]
async fn awg_wrong_key() {
    run_wrong_key(&awg_scenario()).await;
}

/// A loopback UDP proxy standing in for the middlebox: it forwards and records every datagram
/// it sees, in both directions.
struct Proxy {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn proxy(upstream: SocketAddr) -> Proxy {
    let l = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (l2, seen2) = (l.clone(), seen.clone());
    tokio::spawn(async move {
        let mut flows: HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> = HashMap::new();
        let mut b = vec![0u8; 4096];
        loop {
            let (n, src) = l2.recv_from(&mut b).await.unwrap();
            seen2.lock().unwrap().push(b[..n].to_vec());
            let up = match flows.get(&src) {
                Some(u) => u.clone(),
                None => {
                    let u = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    u.connect(upstream).await.unwrap();
                    flows.insert(src, u.clone());
                    let (u2, l3, seen3) = (u.clone(), l2.clone(), seen2.clone());
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 4096];
                        while let Ok(n) = u2.recv(&mut b).await {
                            seen3.lock().unwrap().push(b[..n].to_vec());
                            let _ = l3.send_to(&b[..n], src).await;
                        }
                    });
                    u
                }
            };
            let _ = up.send(&b[..n]).await;
        }
    });
    Proxy { addr: l.local_addr().unwrap(), seen }
}

/// Longest run of leading bytes shared by at least two of `dgs`.
fn longest_shared_prefix(dgs: &[Vec<u8>]) -> usize {
    let mut best = 0;
    for (i, a) in dgs.iter().enumerate() {
        for b in &dgs[i + 1..] {
            best = best.max(a.iter().zip(b).take_while(|(x, y)| x == y).count());
        }
    }
    best
}

/// Everything a middlebox sees between a guest and an awg host, punch and hello frames included:
/// no datagram starts with a constant. Control: the same exchange over plain UDP does.
#[cfg(feature = "cr-awg")]
#[tokio::test]
async fn awg_punch_and_hello_are_obfuscated() {
    const N: usize = 14;
    let tmp = Tmp::new();
    let port = free_port();
    let host_entry = CarrierEntry::new(CarrierId::Awg).at(format!("127.0.0.1:{port}"));
    let (ios, failed) = app::start_carriers(&[host_entry], KEY, &CarrierCfg::default()).await;
    assert!(failed.is_empty());
    let px = proxy(format!("127.0.0.1:{port}").parse().unwrap()).await;
    // The host also fires its PUNCH frame at the proxy (what it does for a rendezvous candidate).
    let target = px.addr;
    let (_host, _) = start_host(false, ios, move |m| m.add_punch_target(target)).await;

    let opts = guest(vec![CarrierEntry::new(CarrierId::Awg).at(px.addr.to_string())], &tmp);
    let mut t = join(&opts).await.expect("connect through the proxy");
    for _ in 0..8 {
        assert!(ping(&mut t, 100).await.is_some());
    }
    tokio::time::sleep(Duration::from_millis(600)).await; // a few host PUNCH frames
    let seen = px.seen.lock().unwrap().clone();
    assert!(seen.len() >= N, "only {} datagrams captured", seen.len());
    let first = &seen[..N];
    assert!(longest_shared_prefix(first) < 4, "a constant 4-byte prefix is visible: {:02x?}", first.iter().map(|d| d[..4].to_vec()).collect::<Vec<_>>());
    assert!(first.iter().all(|d| d.len() > 1), "a bare 1-byte PUNCH frame crossed the wire");
    let tags: std::collections::HashSet<u8> = seen.iter().map(|d| d[0]).collect();
    assert!(tags.len() > 4, "first bytes are not varied");

    // control: plain UDP through the same kind of proxy shows constants (JOIN / T_DATA tags)
    let (uh, uport) = start_host(true, vec![], |_| {}).await;
    let px2 = proxy(format!("127.0.0.1:{}", uport.unwrap()).parse().unwrap()).await;
    let mut c = Tunnel::connect(ConnectOpts {
        signal: None,
        peer: Some(px2.addr),
        room: "",
        key: KEY,
        host: false,
        bind_port: None,
        hosts: vec![],
        mux: true,
    })
    .await
    .unwrap();
    c.enable_packet_mode();
    for _ in 0..8 {
        assert!(ping(&mut c, 100).await.is_some());
    }
    let plain = px2.seen.lock().unwrap().clone();
    assert!(longest_shared_prefix(&plain[..N.min(plain.len())]) >= 3, "the control should show a constant tag + slot");
    drop(uh);
}

// ------------------------------------------------------------------ xray (fake sidecar)

#[cfg(all(feature = "cr-xray", unix))]
mod xray_fake {
    use super::*;
    use serde_json::Value;
    use std::net::UdpSocket;

    fn bridge(listen: u16, to: SocketAddr) {
        let l = Arc::new(UdpSocket::bind(("127.0.0.1", listen)).unwrap());
        std::thread::spawn(move || {
            let mut flows: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut b = [0u8; 4096];
            loop {
                let (n, src) = l.recv_from(&mut b).unwrap();
                let out = flows.entry(src).or_insert_with(|| {
                    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
                    s.connect(to).unwrap();
                    let (s2, l2) = (s.clone(), l.clone());
                    std::thread::spawn(move || {
                        let mut b = [0u8; 4096];
                        while let Ok(n) = s2.recv(&mut b) {
                            let _ = l2.send_to(&b[..n], src);
                        }
                    });
                    s
                });
                let _ = out.send(&b[..n]);
            }
        });
    }

    /// With STRAIT_FAKE_XRAY set this "test" is the Xray binary: `version`, `run -test -c f`, `run -c f`.
    #[test]
    fn fake_xray_entry() {
        if std::env::var("STRAIT_FAKE_XRAY").is_err() {
            return;
        }
        let args: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
        println!();
        fn forever() -> ! {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        match args.first().map(String::as_str) {
            Some("version") => {
                println!("Xray 26.10.31 (Xray, Penetrates Everything.) fake (go1.27.3 linux/arm64)");
                std::process::exit(0)
            }
            Some("run") => {}
            _ => std::process::exit(2),
        }
        let cfgp = &args[args.iter().position(|a| a == "-c").expect("-c") + 1];
        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(cfgp).unwrap()).expect("config parses");
        let (inb, outb) = (&cfg["inbounds"][0], &cfg["outbounds"][0]);
        let host = inb["protocol"] == "vless";
        if args.iter().any(|a| a == "-test") {
            std::process::exit(0)
        }
        let port = inb["port"].as_u64().unwrap() as u16;
        if host {
            bridge(port, outb["settings"]["redirect"].as_str().unwrap().parse().unwrap());
            let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
            println!("started");
            for s in tcp.incoming() {
                drop(s);
            }
        } else {
            let srv = format!("{}:{}", outb["settings"]["address"].as_str().unwrap(), outb["settings"]["port"]);
            bridge(port, srv.parse().unwrap());
            println!("started");
            forever()
        }
    }

    pub fn fake_bin(tmp: &Tmp) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let s = format!(
            "#!/bin/sh\nexport STRAIT_FAKE_XRAY=1\nexec '{}' --exact xray_fake::fake_xray_entry --nocapture --test-threads=1 -- \"$@\"\n",
            std::env::current_exe().unwrap().display()
        );
        let p = tmp.file("xray");
        std::fs::write(&p, s).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    pub fn scenario(tmp: &Tmp) -> Scenario {
        let ep = format!("127.0.0.1:{}", free_port());
        let cfg = CarrierCfg {
            xray_bin: Some(fake_bin(tmp).to_str().unwrap().into()),
            extra: vec![
                ("xray_run_dir".into(), tmp.0.to_str().unwrap().into()),
                ("xray_backoff_ms".into(), "30".into()),
                ("xray_monitor_ms".into(), "100".into()),
                ("xray_settle_ms".into(), "800".into()),
                ("xray_warmup_ms".into(), "0".into()),
            ],
            ..Default::default()
        };
        Scenario {
            id: CarrierId::Xray,
            host: CarrierEntry::new(CarrierId::Xray).at(ep.clone()).with("sni", SNI),
            client: CarrierEntry::new(CarrierId::Xray).at(ep).with("sni", SNI),
            cfg,
        }
    }

    #[tokio::test]
    async fn xray_carrier_end_to_end() {
        let tmp = Tmp::new();
        let sc = scenario(&tmp);
        run_scenario(&sc).await;
    }

    #[tokio::test]
    async fn xray_wrong_key() {
        let tmp = Tmp::new();
        let sc = scenario(&tmp);
        run_wrong_key(&sc).await;
    }

    #[tokio::test]
    async fn xray_without_binary_is_a_typed_failure() {
        let tmp = Tmp::new();
        let mut opts = guest(vec![CarrierEntry::new(CarrierId::Xray).at("127.0.0.1:9").with("sni", SNI)], &tmp);
        opts.carrier_cfg = CarrierCfg { xray_bin: Some("/nonexistent/xray".into()), ..Default::default() };
        match join(&opts).await {
            Err(ConnectError::CarriersFailed(s)) => assert!(s.starts_with("xray:"), "{s}"),
            other => panic!("{:?}", other.map(|_| ())),
        }
    }
}

// ------------------------------------------------------------------ ws

#[cfg(feature = "cr-ws")]
fn ws_scenario() -> Scenario {
    let ep = format!("127.0.0.1:{}", free_port());
    Scenario {
        id: CarrierId::Ws,
        host: CarrierEntry::new(CarrierId::Ws).at(ep.clone()),
        client: CarrierEntry::new(CarrierId::Ws).at(ep),
        cfg: CarrierCfg::default(),
    }
}

#[cfg(feature = "cr-ws")]
#[tokio::test]
async fn ws_carrier_end_to_end() {
    run_scenario(&ws_scenario()).await;
}

#[cfg(feature = "cr-ws")]
#[tokio::test]
async fn ws_wrong_key() {
    run_wrong_key(&ws_scenario()).await;
}

#[cfg(feature = "cr-ws")]
#[tokio::test]
async fn ws_closed_port_is_blocked() {
    let tmp = Tmp::new();
    let opts = guest(vec![CarrierEntry::new(CarrierId::Ws).at(format!("127.0.0.1:{}", free_port()))], &tmp);
    match join(&opts).await {
        Err(ConnectError::CarriersFailed(s)) => assert!(s.starts_with("ws: blocked"), "{s}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

// ------------------------------------------------------------------ several carriers on one host

/// One host serves plain UDP and ss at once: each client's replies leave on the carrier it came in
/// on (a client never sees a frame from the other carrier), and a packet crosses between them.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn one_host_serves_udp_and_ss_together() {
    let tmp = Tmp::new();
    let sc = ss_scenario();
    let (ios, _) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    let (host, udp_port) = start_host(true, ios, |_| {}).await;
    assert_eq!(host.caps.iter().map(|c| c.id).collect::<Vec<_>>(), [CarrierId::Udp, CarrierId::Ss]);
    assert_eq!(host.tun_mtu, 1379, "the smaller carrier decides");

    let mut over_udp = Tunnel::connect(ConnectOpts {
        signal: None,
        peer: Some(format!("127.0.0.1:{}", udp_port.unwrap()).parse().unwrap()),
        room: "",
        key: KEY,
        host: false,
        bind_port: None,
        hosts: vec![],
        mux: true,
    })
    .await
    .unwrap();
    over_udp.enable_packet_mode();
    let mut over_ss = join(&guest(vec![sc.client.clone()], &tmp)).await.unwrap();
    assert_eq!((over_udp.caps().id, over_ss.caps().id), (CarrierId::Udp, CarrierId::Ss));
    assert!(ping(&mut over_udp, 300).await.is_some());
    assert!(ping(&mut over_ss, 300).await.is_some());
    let p = pkt(my_ip(&over_udp), my_ip(&over_ss), 150);
    over_udp.send_packet(&p).await.unwrap();
    assert_eq!(recv_data(&mut over_ss, Duration::from_secs(3)).await.as_deref(), Some(&p[..]));
    let q = pkt(my_ip(&over_ss), my_ip(&over_udp), 151);
    over_ss.send_packet(&q).await.unwrap();
    assert_eq!(recv_data(&mut over_udp, Duration::from_secs(3)).await.as_deref(), Some(&q[..]));
}

/// An optional carrier that fails to start is reported and does not stop the others.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn failing_optional_carrier_is_reported_and_udp_survives() {
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let busy = format!("127.0.0.1:{}", taken.local_addr().unwrap().port());
    let entries = vec![
        CarrierEntry::new(CarrierId::Ss).at(busy),
        CarrierEntry::new(CarrierId::Dns).at("127.0.0.1:1"), // not built anywhere
        CarrierEntry::new(CarrierId::Udp),                    // implicit: no listener of its own
    ];
    let (ios, failed) = app::start_carriers(&entries, KEY, &CarrierCfg::default()).await;
    assert!(ios.is_empty());
    assert_eq!(failed.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [CarrierId::Ss, CarrierId::Dns]);
    assert!(failed[1].1.contains("not supported by this build"), "{failed:?}");
    // the host still comes up on UDP
    let (host, port) = start_host(true, ios, |_| {}).await;
    assert!(port.is_some() && host.tun_mtu == 1400);
}

// ------------------------------------------------------------------ the MTU contract on the in-memory link

fn mem_cfg(mtu: usize) -> MemCfg {
    MemCfg { id: CarrierId::Ss, mtu, ..MemCfg::default() }
}

#[test]
fn effective_mtu_takes_the_smallest_carrier() {
    let c = |id, max_frame| Caps { id, max_frame, punchable: true, reliable_stream: false, overhead: 0 };
    assert_eq!(effective_mtu(&[]), 1400);
    assert_eq!(effective_mtu(&[c(CarrierId::Udp, 1472)]), 1400);
    // today's biggest sealed frame is 1435; ss 1414, awg ~1378, xray 1335
    assert_eq!(effective_mtu(&[c(CarrierId::Ss, 1414)]), 1379);
    assert_eq!(effective_mtu(&[c(CarrierId::Udp, 1472), c(CarrierId::Ss, 1414), c(CarrierId::Awg, 1378), c(CarrierId::Xray, 1335)]), 1300);
    assert_eq!(c(CarrierId::Udp, 1435).tun_mtu(), 1400);
}

/// Through the real Tunnel and MuxHost over an MTU-limited link: the largest packet the MTU
/// allows passes both ways, one byte more is refused and counted at each sender.
#[tokio::test]
async fn mtu_limited_link_refuses_oversize_loudly() {
    let (a, b) = mem::pair(mem_cfg(1300));
    let peer = a.peer_addr();
    let mut mux = MuxHost::bind(
        KEY,
        MuxConfig { udp: false, carriers: IoList(vec![Arc::new(b)]), ..MuxConfig::default() },
    )
    .await
    .unwrap();
    let mtu = mux.tun_mtu();
    assert_eq!(mtu, 1265);

    let host = tokio::spawn(async move {
        let (mut got, mut refused) = (Vec::new(), None);
        let mut sent_oversize_to: Option<usize> = None;
        let end = Instant::now() + Duration::from_secs(6);
        while Instant::now() < end {
            while let Some(ev) = mux.try_recv().await.unwrap() {
                if let MuxEvent::Packet { id, data } = ev {
                    got.push(data.len());
                    let reply = pkt(MUX_HOST_IP, src_of(&data), data.len());
                    assert!(mux.send_to_peer(id, &reply).await);
                    if data.len() == 100 {
                        // the host side of the contract: more than the carrier carries is refused
                        let big = pkt(MUX_HOST_IP, src_of(&data), mtu + 1);
                        refused = Some(!mux.send_to_peer(id, &big).await);
                        sent_oversize_to = Some(id);
                    }
                }
            }
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
            }
        }
        (got, refused, mux.oversize_drops(), sent_oversize_to)
    });

    let o = ConnectOpts { signal: None, peer: Some(peer), room: "", key: KEY, host: false, bind_port: None, hosts: vec![peer], mux: true };
    let mut t = Tunnel::connect_with_io(o, &[peer], false, false, None, Arc::new(a)).await.expect("join over the mem link");
    t.enable_packet_mode();
    assert_eq!(t.tun_mtu(), mtu);
    assert!(ping(&mut t, 100).await.is_some());
    assert_eq!(ping(&mut t, mtu).await.map(|p| p.len()), Some(mtu), "max MTU passes both ways");
    t.send_packet(&pkt(my_ip(&t), MUX_HOST_IP, mtu + 1)).await.unwrap();
    assert_eq!(t.oversize_drops(), 1);
    drop(t);
    let (got, refused, host_drops, _) = host.await.unwrap();
    assert_eq!(got, vec![100, mtu], "the oversize packet never reached the host");
    assert_eq!(refused, Some(true));
    assert_eq!(host_drops, 1);
}

/// The legacy forward mode needs 1437-byte frames: a smaller carrier is refused up front.
#[tokio::test]
async fn forward_mode_refuses_a_small_carrier() {
    let (a, _b) = mem::pair(mem_cfg(1300));
    let peer = a.peer_addr();
    let o = ConnectOpts { signal: None, peer: Some(peer), room: "", key: KEY, host: false, bind_port: None, hosts: vec![peer], mux: false };
    let e = match Tunnel::connect_with_io(o, &[peer], false, false, None, Arc::new(a)).await {
        Err(e) => e,
        Ok(_) => panic!("connected"),
    };
    assert!(e.to_string().contains("forward mode needs"), "{e}");
}

// ------------------------------------------------------------------ the ladder

fn dead_udp() -> (std::net::UdpSocket, SocketAddr) {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap(); // bound, never answers
    let a = s.local_addr().unwrap();
    (s, a)
}

fn opts_with_dead_udp(carriers: Vec<CarrierEntry>, tmp: &Tmp, dead: SocketAddr) -> GuestOpts {
    let mut o = guest(carriers, tmp);
    o.hosts = vec![dead];
    o.peer = Some(dead);
    o
}

/// UDP is unreachable: the ladder falls back to ss, and remembers it.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn ladder_falls_back_from_dead_udp_to_ss() {
    let tmp = Tmp::new();
    let sc = ss_scenario();
    let (ios, _) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    let (_host, _) = start_host(false, ios, |_| {}).await;
    let (_keep, dead) = dead_udp();
    let opts = opts_with_dead_udp(vec![sc.client.clone()], &tmp, dead);
    let t0 = Instant::now();
    let mut t = join(&opts).await.expect("falls back");
    assert_eq!(t.caps().id, CarrierId::Ss);
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    assert!(ping(&mut t, 80).await.is_some());
    assert_eq!(std::fs::read_to_string(tmp.file("last_carrier")).unwrap(), "ss");
}

/// last_working moves a carrier to the front: with a long stagger, the order shows in the delay.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn last_working_carrier_is_tried_first() {
    let tmp = Tmp::new();
    let sc = ss_scenario();
    let (ios, _) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    let (_host, _) = start_host(false, ios, |_| {}).await;
    let (_keep, dead) = dead_udp();
    let mut opts = opts_with_dead_udp(vec![sc.client.clone()], &tmp, dead);
    opts.ladder_stagger = Some(Duration::from_millis(1500));

    // nothing remembered: udp goes first, ss waits one stagger
    let t0 = Instant::now();
    let t = join(&opts).await.unwrap();
    let cold = t0.elapsed();
    assert_eq!(t.caps().id, CarrierId::Ss);
    assert!(cold >= Duration::from_millis(1500), "{cold:?}");
    drop(t);

    // the file now says ss: it starts at once
    assert_eq!(std::fs::read_to_string(tmp.file("last_carrier")).unwrap(), "ss");
    let t0 = Instant::now();
    let t = join(&opts).await.unwrap();
    let warm = t0.elapsed();
    assert_eq!(t.caps().id, CarrierId::Ss);
    assert!(warm < Duration::from_millis(1200), "warm {warm:?} vs cold {cold:?}");
}

/// Every way failed or was skipped: the typed error carries the exact per-carrier summary.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn all_carriers_failing_gives_the_exact_summary() {
    let tmp = Tmp::new();
    let (_keep, dead) = dead_udp();
    let (_keep2, silent) = dead_udp(); // an ss "server" that never answers
    let mut opts = opts_with_dead_udp(
        vec![
            CarrierEntry::new(CarrierId::Awg).at("127.0.0.1:9"),
            CarrierEntry::new(CarrierId::Dns).at("127.0.0.1:9"),
            CarrierEntry::new(CarrierId::Ss).at(silent.to_string()),
        ],
        &tmp,
        dead,
    );
    opts.carrier_disable = vec!["awg".into()];
    let e = match join(&opts).await {
        Err(e) => e,
        Ok(_) => panic!("connected"),
    };
    let ConnectError::CarriersFailed(summary) = &e else { panic!("{e}") };
    assert_eq!(summary, "udp: no punch; awg: disabled on this device; dns: not supported by this build; ss: timed out");
    assert_eq!(
        e.to_string(),
        "Could not connect with any of the ways listed in the invite: udp: no punch; awg: disabled on this device; dns: not supported by this build; ss: timed out."
    );
    assert!(!tmp.file("last_carrier").exists());
}

/// A disabled carrier is never attempted, even when it is the only one that would work.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn carrier_disable_is_honoured() {
    let tmp = Tmp::new();
    let sc = ss_scenario();
    let (ios, _) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    let (host, _) = start_host(false, ios, |_| {}).await;
    let mut opts = guest(vec![sc.client.clone()], &tmp);
    opts.carrier_disable = vec!["ss".into()];
    let t0 = Instant::now();
    match join(&opts).await {
        Err(ConnectError::CarriersFailed(s)) => assert_eq!(s, "ss: disabled on this device"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "no attempt means no waiting");
    assert_eq!(host.rx.load(Ordering::Relaxed), 0);
}

/// A host that is full is final: no other carrier changes that.
#[cfg(feature = "cr-ss")]
#[tokio::test]
async fn host_full_is_not_hidden_by_the_ladder() {
    let tmp = Tmp::new();
    let sc = ss_scenario();
    let (ios, _) = app::start_carriers(&[sc.host.clone()], KEY, &sc.cfg).await;
    let mut mux = MuxHost::bind(KEY, MuxConfig { max_clients: 1, udp: false, carriers: IoList(ios), ..MuxConfig::default() })
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        loop {
            while mux.try_recv().await.unwrap().is_some() {}
            tokio::select! { _ = mux.readable() => {} _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); } }
        }
    });
    let opts = guest(vec![sc.client.clone()], &tmp);
    let _first = join(&opts).await.unwrap();
    match join(&opts).await {
        Err(ConnectError::HostFull) => {}
        other => panic!("{:?}", other.map(|_| ())),
    }
    task.abort();
}
