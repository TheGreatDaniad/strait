//! Real-UDP loopback tests for the signaling server.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::relay::{self, decode, encode_deregister, encode_ping, encode_register, Config, Incoming};
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn server(cfg: Config) -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(relay::serve(s, cfg));
    addr
}

fn loose() -> Config {
    Config { rate_per_sec: 1e6, burst: 1e6, ..Config::default() }
}

async fn peer() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn recv(s: &UdpSocket) -> Option<Incoming> {
    let mut b = [0u8; 64];
    let n = timeout(Duration::from_millis(500), s.recv(&mut b)).await.ok()?.ok()?;
    decode(&b[..n])
}

fn peer_in(role: u8, addr: SocketAddr) -> Option<Incoming> {
    Some(Incoming::Peer { role, addr })
}

#[tokio::test]
async fn ping_pong() {
    let srv = server(loose()).await;
    let c = peer().await;
    c.send_to(&encode_ping(0xdead_beef), srv).await.unwrap();
    assert_eq!(recv(&c).await, Some(Incoming::Pong(0xdead_beef)));
}

#[tokio::test]
async fn client_then_host_and_host_then_client() {
    let srv = server(loose()).await;
    let (h, c1, c2) = (peer().await, peer().await, peer().await);
    let (ha, a1, a2) = (h.local_addr().unwrap(), c1.local_addr().unwrap(), c2.local_addr().unwrap());

    // Clients first, host later: host learns all clients, clients learn host.
    c1.send_to(&encode_register(5, 1), srv).await.unwrap();
    c2.send_to(&encode_register(5, 1), srv).await.unwrap();
    assert_eq!(recv(&c1).await, None); // no host yet: silence
    h.send_to(&encode_register(5, 0), srv).await.unwrap();
    let mut got = vec![recv(&h).await, recv(&h).await];
    got.sort_by_key(|p| format!("{p:?}"));
    let mut want = vec![peer_in(1, a1), peer_in(1, a2)];
    want.sort_by_key(|p| format!("{p:?}"));
    assert_eq!(got, want);
    assert_eq!(recv(&c1).await, peer_in(0, ha));
    assert_eq!(recv(&c2).await, peer_in(0, ha));

    // Late client: both sides are told.
    let c3 = peer().await;
    c3.send_to(&encode_register(5, 1), srv).await.unwrap();
    assert_eq!(recv(&c3).await, peer_in(0, ha));
    assert_eq!(recv(&h).await, peer_in(1, c3.local_addr().unwrap()));

    // Deregister: the host leaving notifies remaining clients; a client leaving is silent.
    c3.send_to(&encode_deregister(5, 1), srv).await.unwrap();
    h.send_to(&encode_deregister(5, 0), srv).await.unwrap();
    assert_eq!(recv(&c1).await, peer_in(0, ha));
}

#[tokio::test]
async fn rooms_are_isolated() {
    let srv = server(loose()).await;
    let (ha, ca, hb, cb) = (peer().await, peer().await, peer().await, peer().await);
    ha.send_to(&encode_register(1, 0), srv).await.unwrap();
    hb.send_to(&encode_register(2, 0), srv).await.unwrap();
    ca.send_to(&encode_register(1, 1), srv).await.unwrap();
    cb.send_to(&encode_register(2, 1), srv).await.unwrap();
    assert_eq!(recv(&ca).await, peer_in(0, ha.local_addr().unwrap()));
    assert_eq!(recv(&cb).await, peer_in(0, hb.local_addr().unwrap()));
    assert_eq!(recv(&ha).await, peer_in(1, ca.local_addr().unwrap()));
    assert_eq!(recv(&hb).await, peer_in(1, cb.local_addr().unwrap()));
    // Nothing further leaks to either side.
    assert_eq!(recv(&ca).await, None);
    assert_eq!(recv(&ha).await, None);
}

#[tokio::test]
async fn registrations_expire() {
    let srv = server(Config { expiry: Duration::from_millis(200), ..loose() }).await;
    let (h, c) = (peer().await, peer().await);
    h.send_to(&encode_register(9, 0), srv).await.unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    c.send_to(&encode_register(9, 1), srv).await.unwrap();
    assert_eq!(recv(&c).await, None); // stale host was dropped
}

#[tokio::test]
async fn rate_limit_drops_excess() {
    let srv = server(Config { rate_per_sec: 0.5, burst: 5.0, ..Config::default() }).await;
    let c = peer().await;
    for i in 0..50 {
        c.send_to(&encode_ping(i), srv).await.unwrap();
    }
    let mut pongs = 0;
    while recv(&c).await.is_some() {
        pongs += 1;
    }
    assert!((5..=6).contains(&pongs), "pongs = {pongs}");
}

#[tokio::test]
async fn malformed_packets_get_no_reply_and_server_survives() {
    let srv = server(loose()).await;
    let c = peer().await;
    let junk: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x01],
        vec![0x01, 0, 0, 0, 1],            // short REGISTER
        vec![0x01, 0, 0, 0, 1, 7],         // bad role
        vec![0x01, 0, 0, 0, 1, 0, 0],      // long REGISTER
        vec![0x05, 0, 0],                  // short PING
        vec![0x06, 0, 0, 0, 1],            // PONG is server-only
        vec![0x03; 12],                    // PEER is server-only
        vec![0xff; 1500],                  // oversize
    ];
    for j in &junk {
        c.send_to(j, srv).await.unwrap();
    }
    assert_eq!(recv(&c).await, None);
    c.send_to(&encode_ping(7), srv).await.unwrap();
    assert_eq!(recv(&c).await, Some(Incoming::Pong(7)));
}

#[tokio::test]
async fn thirty_clients_behind_one_ip_all_register_but_flood_is_dropped() {
    // Real default limits. All sockets share 127.0.0.1, i.e. one NAT'd source IP.
    let srv = server(Config::default()).await;
    let h = peer().await;
    h.send_to(&encode_register(77, 0), srv).await.unwrap();
    let clients = futures_clients(30).await;
    // Two re-registration rounds inside the same 15 s window.
    for _ in 0..2 {
        for c in &clients {
            c.send_to(&encode_register(77, 1), srv).await.unwrap();
        }
    }
    for c in &clients {
        assert!(recv(c).await.is_some(), "client got no host PEER");
    }
    // A flood from that same IP is still cut off at the burst: count PEER
    // replies to the host's socket.
    let f = peer().await;
    for i in 0..2000u32 {
        f.send_to(&encode_register(78 + (i % 3), 1), srv).await.unwrap();
    }
    let hb = peer().await;
    hb.send_to(&encode_register(78, 0), srv).await.unwrap();
    // The host registration itself is over budget: silence.
    assert_eq!(recv(&hb).await, None);
}

async fn futures_clients(n: usize) -> Vec<UdpSocket> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(peer().await);
    }
    v
}

#[tokio::test]
async fn config_env_names_are_validated() {
    assert!(Config::from_vars(Some("x"), None, None).is_err());
    assert!(Config::from_vars(Some("50"), Some("100"), Some("90")).is_ok());
}
