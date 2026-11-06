//! M2: one host port, one room, N peers, each with its own AEAD session.
//! Loopback only (no TUN, no sudo): packets are hand-built IPv4 datagrams.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat_tunnel::relay;
use nat_tunnel::transport::{
    ConnectError, ConnectOpts, Event, MuxConfig, MuxEvent, MuxHost, Tunnel, MUX_HOST_IP,
};
use tokio::sync::{mpsc, Barrier};

const KEY: &str = "multi-peer-test-key";

fn pkt(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let len = (20 + payload.len()) as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

fn src_of(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[12], p[13], p[14], p[15])
}

struct Host {
    port: u16,
    count: Arc<AtomicUsize>,
    events: mpsc::UnboundedReceiver<MuxEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl Host {
    fn addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.port).parse().unwrap()
    }
    /// Wait for a Left event.
    async fn left(&mut self, within: Duration) -> Option<Ipv4Addr> {
        let end = Instant::now() + within;
        loop {
            let left = end.checked_duration_since(Instant::now())?;
            match tokio::time::timeout(left, self.events.recv()).await {
                Ok(Some(MuxEvent::Left { ip, .. })) => return Some(ip),
                Ok(Some(_)) => {}
                _ => return None,
            }
        }
    }
}

/// A router: packets for the host are echoed back, packets for another
/// client are forwarded to that client only.
async fn start_host(cfg: MuxConfig) -> Host {
    let mut mux = MuxHost::bind(KEY, MuxConfig { bind_port: Some(0), ..cfg }).await.unwrap();
    let port = mux.local_port().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let (tx, events) = mpsc::unbounded_channel();
    let c = count.clone();
    let task = tokio::spawn(async move {
        loop {
            while let Some(ev) = mux.try_recv().await.unwrap() {
                match ev {
                    MuxEvent::Packet { data, .. } => {
                        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                        if dst == MUX_HOST_IP {
                            let reply = pkt(MUX_HOST_IP, src_of(&data), &data[20..]);
                            mux.send_to_ip(src_of(&data), &reply).await;
                        } else {
                            mux.send_to_ip(dst, &data).await;
                        }
                    }
                    other => {
                        let _ = tx.send(other);
                    }
                }
            }
            c.store(mux.peer_count(), Ordering::Relaxed);
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
            }
        }
    });
    Host { port, count, events, task }
}

fn fast(max: usize) -> MuxConfig {
    MuxConfig { max_clients: max, ..MuxConfig::default() }
}

async fn join_with(host: Option<SocketAddr>, signal: Option<SocketAddr>) -> io::Result<Tunnel> {
    let mut t = Tunnel::connect(ConnectOpts {
        signal,
        peer: host,
        room: "",
        key: KEY,
        host: false,
        bind_port: None,
        hosts: vec![],
        mux: true,
    })
    .await?;
    t.enable_packet_mode();
    Ok(t)
}
use std::io;

async fn join(host: &Host) -> Tunnel {
    join_with(Some(host.addr()), None).await.expect("client joins")
}

async fn recv(t: &mut Tunnel, within: Duration) -> Option<Event> {
    let end = Instant::now() + within;
    while Instant::now() < end {
        t.tick().await.unwrap();
        if let Some(ev) = t.try_recv().await.unwrap() {
            return Some(ev);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}

async fn recv_pkt(t: &mut Tunnel, within: Duration) -> Option<Vec<u8>> {
    match recv(t, within).await {
        Some(Event::Data(d)) => Some(d),
        _ => None,
    }
}

fn ip_of(t: &Tunnel) -> Ipv4Addr {
    t.assigned().expect("assigned").0
}

/// Send to the host and wait for its echo.
async fn echo(t: &mut Tunnel, tagb: &[u8]) -> bool {
    let me = ip_of(t);
    t.send_packet(&pkt(me, MUX_HOST_IP, tagb)).await.unwrap();
    match recv_pkt(t, Duration::from_secs(5)).await {
        Some(p) => src_of(&p) == MUX_HOST_IP && &p[20..] == tagb,
        None => false,
    }
}

async fn load(n: usize) {
    // A stuck wait must fail the test, not hang the suite.
    tokio::time::timeout(Duration::from_secs(120), load_inner(n)).await.expect("load test timed out");
}

async fn load_inner(n: usize) {
    let host = start_host(fast(n)).await;
    let addr = host.addr();
    let barrier = Arc::new(Barrier::new(n));
    let ips = Arc::new(Mutex::new(vec![Ipv4Addr::UNSPECIFIED; n]));
    let mut tasks = Vec::new();
    for i in 0..n {
        let (barrier, ips) = (barrier.clone(), ips.clone());
        tasks.push(tokio::spawn(async move {
            // Reach the barrier even when the join fails, so one failure
            // reports an error instead of leaving every other client waiting.
            let joined = join_with(Some(addr), None).await;
            if joined.is_err() {
                barrier.wait().await;
            }
            let mut t = joined.expect("client ready");
            let me = ip_of(&t);
            let (ip, prefix, gw) = t.assigned().unwrap();
            assert_eq!((prefix, gw), (16, MUX_HOST_IP));
            ips.lock().unwrap()[i] = ip;
            barrier.wait().await;
            let next = ips.lock().unwrap()[(i + 1) % n];
            let prev = ips.lock().unwrap()[(i + n - 1) % n];

            t.send_packet(&pkt(me, MUX_HOST_IP, format!("echo-{i}").as_bytes())).await.unwrap();
            t.send_packet(&pkt(me, next, format!("from-{i}").as_bytes())).await.unwrap();

            let mut got = Vec::new();
            while got.len() < 2 {
                match recv_pkt(&mut t, Duration::from_secs(20)).await {
                    Some(p) => got.push(p),
                    None => panic!("client {i} timed out with {} packets", got.len()),
                }
            }
            // No cross-talk: nothing else may arrive.
            if let Some(extra) = recv_pkt(&mut t, Duration::from_millis(300)).await {
                panic!("client {i} got an unexpected packet from {}", src_of(&extra));
            }
            for p in &got {
                assert_eq!(Ipv4Addr::new(p[16], p[17], p[18], p[19]), me, "delivered to the owner only");
                if src_of(p) == MUX_HOST_IP {
                    assert_eq!(&p[20..], format!("echo-{i}").as_bytes());
                } else {
                    assert_eq!(src_of(p), prev);
                    assert_eq!(&p[20..], format!("from-{}", (i + n - 1) % n).as_bytes());
                }
            }
            ip
        }));
    }
    let mut seen = std::collections::HashSet::new();
    for t in tasks {
        assert!(seen.insert(t.await.expect("client task")), "duplicate address");
    }
    assert_eq!(seen.len(), n);
    assert_eq!(host.count.load(Ordering::Relaxed), n);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_clients_one_port() {
    load(8).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_clients_one_port() {
    load(32).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hundred_fifty_six_clients_one_port() {
    load(256).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_clients_rejects_extra_peer_and_keeps_existing() {
    let host = start_host(fast(2)).await;
    let mut a = join(&host).await;
    let mut b = join(&host).await;
    let err = join_with(Some(host.addr()), None).await.err().expect("third is rejected");
    assert!(matches!(ConnectError::from_io(&err), Some(ConnectError::HostFull)), "{err}");
    assert!(echo(&mut a, b"a still works").await);
    assert!(echo(&mut b, b"b still works").await);
    assert_eq!(host.count.load(Ordering::Relaxed), 2);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_client_frees_slot_and_host_accepts_new_and_returning_guests() {
    let mut host = start_host(MuxConfig {
        max_clients: 1,
        keepalive: Duration::from_millis(300),
        timeout: Duration::from_millis(1200),
        ..MuxConfig::default()
    })
    .await;

    // Guest 1 connects, exchanges data, leaves politely.
    let mut g1 = join(&host).await;
    let ip1 = ip_of(&g1);
    assert!(echo(&mut g1, b"one").await);
    g1.close().await.unwrap();
    drop(g1);
    assert_eq!(host.left(Duration::from_secs(3)).await, Some(ip1), "Bye frees the slot");

    // A different guest takes the freed slot.
    let mut g2 = join(&host).await;
    assert!(echo(&mut g2, b"two").await);

    // It vanishes without a Bye; the same guest comes back from a new port.
    drop(g2);
    assert!(host.left(Duration::from_secs(5)).await.is_some(), "silent peer is evicted");
    let mut g3 = join(&host).await;
    assert!(echo(&mut g3, b"three").await);
    assert_eq!(host.count.load(Ordering::Relaxed), 1);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_stays_findable_through_signaling_across_guests() {
    let sig_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    tokio::spawn(async move { relay::run_server(sig_port).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let signal: SocketAddr = format!("127.0.0.1:{sig_port}").parse().unwrap();

    let mut host = start_host(MuxConfig { signal: Some(signal), ..fast(4) }).await;
    let mut g1 = join_with(None, Some(signal)).await.expect("first guest via signal");
    assert!(echo(&mut g1, b"first").await);
    g1.close().await.unwrap();
    drop(g1);
    assert!(host.left(Duration::from_secs(3)).await.is_some());

    // Longer than the host's re-register interval: it must still be listed.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut g2 = join_with(None, Some(signal)).await.expect("later guest via signal");
    assert!(echo(&mut g2, b"second").await);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_client_is_evicted_while_keepalive_client_survives() {
    let mut host = start_host(MuxConfig {
        keepalive: Duration::from_millis(300),
        timeout: Duration::from_millis(1200),
        ..fast(2)
    })
    .await;
    let silent = join(&host).await;
    let silent_ip = ip_of(&silent);
    let mut alive = join(&host).await;
    alive.set_timers(Duration::from_millis(300), Duration::from_millis(1200));

    // `alive` only polls (which sends its keepalives); `silent` never does.
    assert!(recv_pkt(&mut alive, Duration::from_millis(2500)).await.is_none());
    assert_eq!(host.left(Duration::from_secs(2)).await, Some(silent_ip));
    assert_eq!(host.count.load(Ordering::Relaxed), 1);
    assert!(echo(&mut alive, b"still here").await);
    drop(silent);

    // The freed slot is usable.
    let mut c = join(&host).await;
    assert!(echo(&mut c, b"new").await);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_source_address_is_dropped() {
    let host = start_host(fast(2)).await;
    let mut a = join(&host).await;
    let b = join(&host).await;
    let forged = pkt(ip_of(&b), MUX_HOST_IP, b"i am b");
    a.send_packet(&forged).await.unwrap();
    assert!(recv_pkt(&mut a, Duration::from_millis(500)).await.is_none(), "forged packet dropped");
    assert!(echo(&mut a, b"honest").await);
    host.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_peer_rate_limit_drops_excess() {
    let host = start_host(MuxConfig { rate_bytes: 3000, ..fast(2) }).await;
    let mut a = join(&host).await;
    let me = ip_of(&a);
    for i in 0..40u8 {
        a.send_packet(&pkt(me, MUX_HOST_IP, &[i; 480])).await.unwrap();
    }
    let mut got = 0;
    while recv_pkt(&mut a, Duration::from_millis(500)).await.is_some() {
        got += 1;
    }
    assert!((1..40).contains(&got), "rate cap should drop some but not all, got {got}");
    host.task.abort();
}
