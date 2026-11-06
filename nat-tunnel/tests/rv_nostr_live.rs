//! LIVE check against the real public relays. `#[ignore]`: run by hand, once on each machine:
//!
//!   STRAIT_LIVE_ROLE=host|client STRAIT_LIVE_KEY=<32 hex> STRAIT_LIVE_T0=<unix ms, shared start> \
//!   cargo test --release --no-default-features --features rv-nostr --test rv_nostr_live -- --ignored --nocapture
//!
//! Both sides use the same fresh random key per run (so a fresh room tag) and fake documentation-range
//! candidates. Each side stops ~8 s after T0 (3 events per relay per side at most). Prints
//! `LIVE role=.. first_peer_ms=..` (relative to the shared T0; includes clock skew between machines).
#![cfg(feature = "rv-nostr")]

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nat_tunnel::rendezvous::derive::parse_key;
use nat_tunnel::rendezvous::nostr::Nostr;
use nat_tunnel::rendezvous::{Rendezvous, Role, RvConfig, RvCtx};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

#[tokio::test]
#[ignore]
async fn live_relays_find_each_other() {
    let role = match std::env::var("STRAIT_LIVE_ROLE").expect("STRAIT_LIVE_ROLE").as_str() {
        "host" => Role::Host,
        "client" => Role::Client,
        o => panic!("bad role {o}"),
    };
    let key = parse_key(&std::env::var("STRAIT_LIVE_KEY").expect("STRAIT_LIVE_KEY")).expect("32 hex chars");
    let t0: u128 = std::env::var("STRAIT_LIVE_T0").expect("STRAIT_LIVE_T0").parse().unwrap();
    let (mine, theirs): (SocketAddr, SocketAddr) = match role {
        Role::Host => ("192.0.2.1:4000".parse().unwrap(), "192.0.2.2:4000".parse().unwrap()),
        Role::Client => ("192.0.2.2:4000".parse().unwrap(), "192.0.2.1:4000".parse().unwrap()),
    };
    let n = Nostr::new(&RvConfig::default());
    let ctx = RvCtx::new(key, role, vec![mine]);
    let (tx, mut rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    while now_ms() < t0 {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let c2 = cancel.clone();
    let h = tokio::spawn(async move { n.run(ctx, tx, c2).await });
    let got = tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("no peer within 20 s").unwrap();
    let ms = now_ms() as i128 - t0 as i128;
    // stay up so the other side can still receive our events
    while now_ms() < t0 + 8000 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cancel.cancel();
    let r = tokio::time::timeout(Duration::from_secs(2), h).await.expect("run did not stop").unwrap();
    println!("LIVE role={role:?} first_peer_ms={ms} via={} addr={}", got.via, got.addr);
    assert_eq!(got.addr, theirs);
    assert_eq!(got.via, "nostr");
    assert_eq!(r, Ok(()));
}
