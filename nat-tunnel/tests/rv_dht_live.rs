//! LIVE check against the real Mainline DHT. `#[ignore]`: run by hand, once per machine:
//!   RV_LIVE_ROLE=host|client RV_LIVE_KEY=<32 hex> cargo test --release --features rv-dht \
//!     --test rv_dht_live -- --ignored --nocapture
//! Throwaway key per run, documentation-range fake candidates, ~1 PUT and a handful of GETs.
#![cfg(feature = "rv-dht")]

use std::time::{Duration, Instant};

use nat_tunnel::rendezvous::derive::parse_key;
use nat_tunnel::rendezvous::dht::Dht;
use nat_tunnel::rendezvous::{Rendezvous, Role, RvConfig, RvCtx};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn live_rendezvous_with_real_dht() {
    let host = std::env::var("RV_LIVE_ROLE").expect("RV_LIVE_ROLE") == "host";
    let key = parse_key(&std::env::var("RV_LIVE_KEY").expect("RV_LIVE_KEY")).expect("32 hex");
    let (role, mine, theirs) = if host {
        (Role::Host, "192.0.2.1:41001", "198.51.100.2:41002")
    } else {
        (Role::Client, "198.51.100.2:41002", "192.0.2.1:41001")
    };
    let b = Dht::new(&RvConfig::default());
    let (tx, mut rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let t0 = Instant::now();
    let h = tokio::spawn(async move { b.run(RvCtx::new(key, role, vec![mine.parse().unwrap()]), tx, c2).await });
    let got = tokio::time::timeout(Duration::from_secs(75), rx.recv()).await;
    println!("LIVE role={role:?} found_after_ms={} got={:?}", t0.elapsed().as_millis(), got);
    cancel.cancel();
    let t1 = Instant::now();
    let r = h.await.unwrap();
    println!("LIVE shutdown_ms={} result={r:?}", t1.elapsed().as_millis());
    assert_eq!(got.ok().flatten().map(|c| c.addr), Some(theirs.parse().unwrap()));
    assert!(r.is_ok());
}
