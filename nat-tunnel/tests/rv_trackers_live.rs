//! LIVE check against the real public trackers (ignored by default; polite: one run = a few
//! announces per tracker). Run the same binary on two hosts with the same TRK_KEY:
//!   TRK_KEY=<32 hex> TRK_ROLE=host|client TRK_PORT=<local udp port or 0> TRK_START_AT=<unix secs>
//!   cargo test --release --features rv-trk --test rv_trackers_live -- --ignored --nocapture
#![cfg(feature = "rv-trk")]
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nat_tunnel::rendezvous::derive::parse_key;
use nat_tunnel::rendezvous::trackers::Trackers;
use nat_tunnel::rendezvous::{Rendezvous, Role, RvConfig, RvCtx};
use nat_tunnel::tunnel::stun::{StunClient, StunServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

#[tokio::test]
#[ignore]
async fn live_punch_through_trackers() {
    let key = parse_key(&env("TRK_KEY")).expect("32 hex");
    let role = if env("TRK_ROLE") == "host" { Role::Host } else { Role::Client };
    let port: u16 = env("TRK_PORT").parse().unwrap();
    let start_at: u64 = env("TRK_START_AT").parse().unwrap();
    let sock = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await.unwrap());

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
    tokio::time::sleep(Duration::from_secs_f64((start_at as f64 - now).max(0.0))).await;

    let mapped = StunClient::new(StunServerConfig { address: "stun.l.google.com".into(), port: 19302 })
        .mapped_addr_on(&sock)
        .await
        .expect("stun");
    println!("LIVE {role:?} local={} mapped={mapped}", sock.local_addr().unwrap());

    let ctx = RvCtx::new(key, role, vec![mapped]).with_sock(sock.clone());
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (c2, t0) = (cancel.clone(), Instant::now());
    let run = tokio::spawn(async move { Trackers::new(&RvConfig::default()).run(ctx, tx, c2).await });
    let peer = tokio::time::timeout(Duration::from_secs(40), rx.recv()).await.expect("no peer within 40 s").expect("closed");
    println!("LIVE {role:?} peer={} after {:.2}s", peer.addr, t0.elapsed().as_secs_f64());
    cancel.cancel(); // sends event=stopped, frees the socket for the punch
    assert_eq!(run.await.unwrap(), Ok(()));

    let (me, mut got, mut buf) = (format!("trk-live-{role:?}"), false, [0u8; 128]);
    let end = Instant::now() + Duration::from_secs(8);
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    while Instant::now() < end && !got {
        tokio::select! {
            _ = tick.tick() => { let _ = sock.send_to(me.as_bytes(), peer.addr).await; }
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, from)) = r {
                    if from == peer.addr && buf[..n].starts_with(b"trk-live-") { got = true; }
                }
            }
        }
    }
    // keep sending briefly so the other side still receives after we got ours
    for _ in 0..15 {
        let _ = sock.send_to(me.as_bytes(), peer.addr).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!("LIVE {role:?} received_from_peer={got}");
    assert!(got, "no datagram from the peer");
}
