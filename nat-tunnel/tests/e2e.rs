//! Loopback end-to-end test: relay rendezvous + encrypted tunnel + ARQ.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::relay;
use nat_tunnel::transport::{ConnectOpts, Event, Tunnel};
use tokio::net::UdpSocket;

/// Wait for an event, driving retransmits and relay registrations meanwhile.
async fn next_event(tunnel: &mut Tunnel) -> Event {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tunnel.tick().await.expect("tick");
            if let Some(event) = tunnel.try_recv().await.expect("recv") {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("event before timeout")
}

fn opts<'a>(signal: SocketAddr, room: &'a str, key: &'a str, host: bool) -> ConnectOpts<'a> {
    ConnectOpts {
        signal: Some(signal),
        peer: None,
        room,
        key,
        host,
        bind_port: None,
        hosts: vec![],
        mux: false,
    }
}

async fn free_udp_port() -> u16 {
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_moves_data_both_ways_and_closes() {
    let port = free_udp_port().await;
    tokio::spawn(async move {
        relay::run_server(port).await.expect("relay runs");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let relay_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let host = tokio::spawn(async move {
        let mut tunnel = Tunnel::connect(opts(relay_addr, "test-room", "test-key", true))
            .await
            .expect("host connects");
        tunnel.send(b"ping from host").await.expect("send ping");
        let reply = match next_event(&mut tunnel).await {
            Event::Data(data) => data,
            Event::Closed => panic!("host got Closed before the reply"),
        };
        tunnel.close().await.expect("close");
        reply
    });

    let guest = tokio::spawn(async move {
        let mut tunnel = Tunnel::connect(opts(relay_addr, "test-room", "test-key", false))
            .await
            .expect("guest connects");
        let request = match next_event(&mut tunnel).await {
            Event::Data(data) => data,
            Event::Closed => panic!("guest got Closed before the request"),
        };
        tunnel.send(b"pong from guest").await.expect("send pong");

        // Keep the session alive until the host's Bye arrives.
        match next_event(&mut tunnel).await {
            Event::Closed => {}
            Event::Data(_) => panic!("unexpected extra data"),
        }
        request
    });

    let (host_reply, guest_request) = tokio::join!(host, guest);
    assert_eq!(guest_request.expect("guest task"), b"ping from host");
    assert_eq!(host_reply.expect("host task"), b"pong from guest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_key_never_delivers() {
    let port = free_udp_port().await;
    tokio::spawn(async move {
        relay::run_server(port).await.expect("relay runs");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let relay_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let host = tokio::spawn(async move {
        let mut tunnel = Tunnel::connect(opts(relay_addr, "wrong-key", "key-a", true))
            .await
            .expect("host connects");
        tunnel.send(b"secret").await.expect("send");
        // Any delivery here would be a real security bug.
        let delivered = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tunnel.tick().await.ok();
                if let Some(event) = tunnel.try_recv().await.ok().flatten() {
                    return Some(event);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(delivered.is_err() || matches!(delivered, Ok(None)));
    });

    let guest = tokio::spawn(async move {
        let mut tunnel = Tunnel::connect(opts(relay_addr, "wrong-key", "key-b", false))
            .await
            .expect("guest connects");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tunnel.tick().await.ok();
                if tunnel.try_recv().await.ok().flatten().is_some() {
                    panic!("ciphertext from a different key was accepted");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .ok();
    });

    tokio::join!(host, guest);
}
