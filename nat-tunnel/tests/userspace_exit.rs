use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::poll_fn;
use nat_tunnel::userspace::{serve_tcp_with, serve_udp_with, ExitConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

type Flow = (tokio::io::DuplexStream, SocketAddr, SocketAddr);

async fn echo() -> SocketAddr {
    nat_tunnel::userspace::set_exit_policy(false, true); // lab: echo server on 127.0.0.1
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

fn start(cfg: ExitConfig) -> (mpsc::UnboundedSender<Flow>, Arc<Semaphore>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Flow>();
    let sem = Arc::new(Semaphore::new(cfg.max_tcp));
    let stream = poll_fn(move |cx| rx.poll_recv(cx));
    tokio::spawn(serve_tcp_with(Box::pin(stream), cfg, Some(sem.clone())));
    (tx, sem)
}

fn open(tx: &mpsc::UnboundedSender<Flow>, remote: SocketAddr) -> tokio::io::DuplexStream {
    let (client, inner) = tokio::io::duplex(64 * 1024);
    tx.send((inner, "10.0.0.2:1234".parse().unwrap(), remote)).unwrap();
    client
}

async fn wait_permits(sem: &Semaphore, n: usize) {
    for _ in 0..200 {
        if sem.available_permits() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("permits {} != {n}", sem.available_permits());
}

#[tokio::test]
async fn thousand_sequential_connections_return_permits() {
    let addr = echo().await;
    let (tx, sem) = start(ExitConfig { max_tcp: 16, ..Default::default() });
    for i in 0..1000u32 {
        let mut c = open(&tx, addr);
        let msg = i.to_be_bytes();
        c.write_all(&msg).await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
        drop(c);
    }
    wait_permits(&sem, 16).await;
}

#[tokio::test]
async fn cap_serves_and_rest_refused_promptly() {
    let addr = echo().await;
    let (tx, sem) = start(ExitConfig { max_tcp: 50, ..Default::default() });
    let mut conns: Vec<_> = (0..300).map(|_| open(&tx, addr)).collect();
    let (mut served, mut refused) = (0, 0);
    for c in conns.iter_mut() {
        let _ = c.write_all(b"x").await;
        let mut b = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), c.read(&mut b)).await {
            Ok(Ok(1)) => served += 1,
            Ok(_) => refused += 1, // EOF/reset: refused
            Err(_) => panic!("connection hung"),
        }
    }
    assert_eq!((served, refused), (50, 250));
    drop(conns);
    wait_permits(&sem, 50).await;
}

#[tokio::test]
async fn idle_connection_is_reaped() {
    let addr = echo().await;
    let (tx, sem) = start(ExitConfig { max_tcp: 4, tcp_idle: Duration::from_millis(300), ..Default::default() });
    let mut c = open(&tx, addr);
    c.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    c.read_exact(&mut b).await.unwrap();
    // keep `c` open and silent: the exit must reap it.
    wait_permits(&sem, 4).await;
    assert_eq!(c.read(&mut b).await.unwrap(), 0);
}

#[tokio::test]
async fn half_close_still_delivers_reply() {
    let addr = echo().await;
    let (tx, sem) = start(ExitConfig { max_tcp: 4, ..Default::default() });
    let mut c = open(&tx, addr);
    c.write_all(b"payload").await.unwrap();
    c.shutdown().await.unwrap(); // client FIN, still reading
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut out)).await.unwrap().unwrap();
    assert_eq!(out, b"payload");
    wait_permits(&sem, 4).await;
}

#[tokio::test]
async fn udp_flow_expires_and_replies() {
    let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = srv.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        while let Ok((n, from)) = srv.recv_from(&mut b).await {
            let _ = srv.send_to(&b[..n], from).await;
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut rep_rx) = mpsc::channel(16);
    let sem = Arc::new(Semaphore::new(8));
    let cfg = ExitConfig { max_udp: 8, udp_idle: Duration::from_millis(300), ..Default::default() };
    tokio::spawn(serve_udp_with(Box::pin(poll_fn(move |cx| in_rx.poll_recv(cx))), rep_tx, cfg, Some(sem.clone())));
    let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    for _ in 0..3 {
        in_tx.send((b"ping".to_vec(), local, remote)).unwrap();
        let (d, src, dst) = tokio::time::timeout(Duration::from_secs(2), rep_rx.recv()).await.unwrap().unwrap();
        assert_eq!((d.as_slice(), src, dst), (&b"ping"[..], remote, local));
    }
    assert_eq!(sem.available_permits(), 7);
    wait_permits(&sem, 8).await;
}

#[tokio::test]
async fn udp_reply_flood_is_bounded_and_counted() {
    use std::sync::atomic::Ordering::Relaxed;
    // Remote answers one datagram with a 3000-datagram burst.
    let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = srv.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        while let Ok((_, from)) = srv.recv_from(&mut b).await {
            for i in 0..3000u32 {
                let _ = srv.send_to(&i.to_be_bytes(), from).await;
            }
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut rep_rx) = mpsc::channel(8); // consumer is stalled
    let before = nat_tunnel::userspace::UDP_REPLIES_DROPPED.load(Relaxed);
    tokio::spawn(serve_udp_with(Box::pin(poll_fn(move |cx| in_rx.poll_recv(cx))), rep_tx, ExitConfig::default(), None));
    in_tx.send((b"go".to_vec(), "10.0.0.2:5000".parse().unwrap(), remote)).unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    let mut queued = 0;
    while rep_rx.try_recv().is_ok() {
        queued += 1;
    }
    let dropped = nat_tunnel::userspace::UDP_REPLIES_DROPPED.load(Relaxed) - before;
    assert_eq!(queued, 8, "queue never exceeds its bound");
    assert!(dropped > 0, "overflow is counted, not buffered");
}

#[tokio::test]
async fn one_guest_cannot_take_every_tcp_permit() {
    let addr = echo().await;
    let (tx, sem) = start(ExitConfig { max_tcp: 8, per_guest_tcp: 2, ..Default::default() });
    let flow = |guest: &str| {
        let (client, inner) = tokio::io::duplex(64 * 1024);
        tx.send((inner, format!("{guest}:1234").parse().unwrap(), addr)).unwrap();
        client
    };
    let mut held: Vec<_> = (0..2).map(|_| flow("10.7.0.2")).collect();
    for c in &mut held {
        c.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        c.read_exact(&mut b).await.unwrap();
    }
    // The third flow of the same guest is refused (closed, not proxied) ...
    let mut over = flow("10.7.0.2");
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(5), over.read(&mut b)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)), "over-limit flow must be closed");
    assert_eq!(sem.available_permits(), 6, "refused flow took no global permit");
    // ... another guest is unaffected ...
    let mut other = flow("10.7.0.3");
    other.write_all(b"y").await.unwrap();
    other.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"y");
    // ... and closing one of the first guest's flows gives its slot back.
    drop(held.pop());
    wait_permits(&sem, 6).await;
    let mut again = flow("10.7.0.2");
    again.write_all(b"z").await.unwrap();
    again.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"z");
}

#[tokio::test]
async fn one_guest_cannot_take_every_udp_flow() {
    nat_tunnel::userspace::set_exit_policy(false, true); // lab: echo server on 127.0.0.1
    let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = srv.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        while let Ok((n, from)) = srv.recv_from(&mut b).await {
            let _ = srv.send_to(&b[..n], from).await;
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut rep_rx) = mpsc::channel(16);
    let sem = Arc::new(Semaphore::new(8));
    let cfg = ExitConfig { max_udp: 8, per_guest_udp: 2, udp_idle: Duration::from_millis(400), ..Default::default() };
    tokio::spawn(serve_udp_with(Box::pin(poll_fn(move |cx| in_rx.poll_recv(cx))), rep_tx, cfg, Some(sem.clone())));
    let a = |port: u16| -> SocketAddr { format!("10.7.0.2:{port}").parse().unwrap() };
    for p in [5000, 5001, 5002] {
        in_tx.send((b"a".to_vec(), a(p), remote)).unwrap();
    }
    // Only two of guest A's three flows get an answer.
    let mut got = vec![];
    while let Ok(Some((_, _, dst))) = tokio::time::timeout(Duration::from_millis(300), rep_rx.recv()).await {
        got.push(dst);
    }
    got.sort();
    assert_eq!(got, vec![a(5000), a(5001)]);
    // Guest B still has room, and everything is released after the idle timeout.
    let b: SocketAddr = "10.7.0.3:5000".parse().unwrap();
    in_tx.send((b"b".to_vec(), b, remote)).unwrap();
    let (_, _, dst) = tokio::time::timeout(Duration::from_secs(2), rep_rx.recv()).await.unwrap().unwrap();
    assert_eq!(dst, b);
    wait_permits(&sem, 8).await;
    in_tx.send((b"a".to_vec(), a(5002), remote)).unwrap();
    let (_, _, dst) = tokio::time::timeout(Duration::from_secs(2), rep_rx.recv()).await.unwrap().unwrap();
    assert_eq!(dst, a(5002));
}
