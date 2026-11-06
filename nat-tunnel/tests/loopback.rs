//! M0 loopback smoke tests (no TUN, no sudo): invite-only and signaling paths.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::invite::Invite;
use nat_tunnel::relay;
use nat_tunnel::transport::{ConnectOpts, Event, Tunnel};
use tokio::net::UdpSocket;

async fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

async fn next_data(t: &mut Tunnel) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            t.tick().await.unwrap();
            if let Some(ev) = t.try_recv().await.unwrap() {
                match ev {
                    Event::Data(d) => return d,
                    Event::Closed => panic!("closed early"),
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("data before timeout")
}

/// Connect both sides from the invite string, assert direct path and data both ways.
async fn run_pair(invite: &str, host_port: Option<u16>) {
    let inv = Invite::parse(invite).expect("invite parses");
    let peer = nat_tunnel::invite::resolve(&inv.hosts).await.unwrap().first().copied();
    let signal = nat_tunnel::invite::resolve_signals(&inv.signals).await.unwrap().first().copied();
    let key = inv.key.clone();
    let room = inv.room.clone();

    let (k, r) = (key.clone(), room.clone());
    let host = tokio::spawn(async move {
        let mut t = Tunnel::connect(ConnectOpts {
            signal,
            peer: None,
            room: &r,
            key: &k,
            host: true,
            bind_port: host_port,
            hosts: vec![],
            mux: false,
        })
        .await
        .expect("host ready");
        assert!(t.is_direct(), "host direct");
        t.send(b"from-host").await.unwrap();
        assert_eq!(next_data(&mut t).await, b"from-guest");
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let guest = tokio::spawn(async move {
        let mut t = Tunnel::connect(ConnectOpts {
            signal,
            peer,
            room: &room,
            key: &key,
            host: false,
            bind_port: None,
            hosts: vec![],
            mux: false,
        })
        .await
        .expect("guest ready");
        assert!(t.is_direct(), "guest direct");
        t.send(b"from-guest").await.unwrap();
        assert_eq!(next_data(&mut t).await, b"from-host");
    });
    host.await.unwrap();
    guest.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_only_direct_path() {
    let port = free_port().await;
    run_pair(&format!("STRAIT2|k|127.0.0.1:{port}"), Some(port)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signaling_path() {
    let sig = free_port().await;
    tokio::spawn(async move { relay::run_server(sig).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _: SocketAddr = format!("127.0.0.1:{sig}").parse().unwrap();
    run_pair(&format!("STRAIT2|k||127.0.0.1:{sig}"), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostname_invite_direct_path() {
    let port = free_port().await;
    run_pair(&format!("STRAIT2|k|localhost:{port}"), Some(port)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostname_signaling_path() {
    let sig = free_port().await;
    tokio::spawn(async move { relay::run_server(sig).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    run_pair(&format!("STRAIT2|k||localhost:{sig}"), None).await;
}
