//! Mux joins through a lossy UDP proxy: JOIN/ACCEPT/ASSIGN loss must be
//! retransmitted away, and anything that still fails must fail typed and
//! within a bounded time (never hang).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nat_tunnel::transport::{ConnectError, ConnectOpts, MuxConfig, MuxHost, Tunnel};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const KEY: &str = "mux-loss-test-key";
const CLIENTS: usize = 32;

/// Deterministic xorshift64 so a failing run can be replayed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn lose(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// Forwards datagrams between many clients and one host, dropping `pct`% in
/// both directions and, if `drop_first`, the first datagram of every client.
async fn proxy(host: SocketAddr, pct: u64, drop_first: bool, seed: u64) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let rng = Arc::new(std::sync::Mutex::new(Rng(seed)));
    let ups: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Default::default();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, client) = match front.recv_from(&mut buf).await {
                Ok(r) => r,
                // Windows: ICMP port-unreachable for a client that went away shows up as ConnectionReset.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(_) => return,
            };
            let (up, first) = {
                let mut m = ups.lock().await;
                if let Some(u) = m.get(&client) {
                    (u.clone(), false)
                } else {
                    let u = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    u.connect(host).await.unwrap();
                    m.insert(client, u.clone());
                    let (u2, f2, r2) = (u.clone(), front.clone(), rng.clone());
                    tokio::spawn(async move {
                        let mut b = [0u8; 2048];
                        loop {
                            let n = match u2.recv(&mut b).await {
                                Ok(n) => n,
                                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                                Err(_) => break,
                            };
                            if !r2.lock().unwrap().lose(pct) {
                                let _ = f2.send_to(&b[..n], client).await;
                            }
                        }
                    });
                    (u, true)
                }
            };
            if first && drop_first {
                continue; // the first JOIN of this client is lost
            }
            if !rng.lock().unwrap().lose(pct) {
                let _ = up.send(&buf[..n]).await;
            }
        }
    });
    addr
}

async fn run(pct: u64, drop_first: bool, seed: u64) {
    let mut mux = MuxHost::bind(KEY, MuxConfig { max_clients: CLIENTS, bind_port: Some(0), ..MuxConfig::default() })
        .await
        .unwrap();
    let host: SocketAddr = format!("127.0.0.1:{}", mux.local_port().unwrap()).parse().unwrap();
    let hosttask = tokio::spawn(async move {
        loop {
            while mux.try_recv().await.unwrap().is_some() {}
            tokio::select! {
                _ = mux.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(20)) => { mux.tick().await.unwrap(); }
            }
        }
    });
    let front = proxy(host, pct, drop_first, seed).await;

    let mut tasks = Vec::new();
    for _ in 0..CLIENTS {
        tasks.push(tokio::spawn(async move {
            let r = tokio::time::timeout(
                Duration::from_secs(60),
                Tunnel::connect(ConnectOpts {
                    signal: None,
                    peer: Some(front),
                    room: "",
                    key: KEY,
                    host: false,
                    bind_port: None,
                    hosts: vec![],
                    mux: true,
                }),
            )
            .await
            .expect("join must be bounded");
            r.map(|t| t.assigned().map(|a| a.0))
        }));
    }
    let mut ips = std::collections::HashSet::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok(Some(ip)) => assert!(ips.insert(ip), "duplicate address"),
            Ok(None) => panic!("joined without an assignment"),
            Err(e) => assert!(
                ConnectError::from_io(&e).is_some(),
                "failure must be a typed ConnectError, got {e}"
            ),
        }
    }
    // 20% loss with retransmission: every client is expected to get in.
    assert_eq!(ips.len(), CLIENTS, "all clients should join despite loss");
    hosttask.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joins_survive_twenty_percent_loss_both_ways() {
    run(20, false, 0x9E37_79B9_7F4A_7C15).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joins_survive_first_join_dropped() {
    run(0, true, 1).await;
}
