//! LIVE check against the real https://ntfy.sh. `cargo test --release --no-default-features
//! --features rv-ntfy --test rv_ntfy_live -- --ignored --nocapture`. One run = fresh random key
//! (fresh random topic), fake documentation-range candidates, a handful of publishes at most.
#![cfg(feature = "rv-ntfy")]
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nat_tunnel::rendezvous::ntfy::Ntfy;
use nat_tunnel::rendezvous::{ProbeStatus, Rendezvous, Role, RvConfig, RvCtx};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore]
async fn live_ntfy_sh_roundtrip() {
    let key = *uuid::Uuid::new_v4().as_bytes();
    let n = std::sync::Arc::new(Ntfy::new(&RvConfig::default()));
    println!("probe: {:?}", n.probe(Duration::from_secs(10)).await);
    let (ha, ca): (SocketAddr, SocketAddr) = ("192.0.2.10:40001".parse().unwrap(), "198.51.100.20:40002".parse().unwrap());
    let cancel = CancellationToken::new();
    let t0 = Instant::now();
    let mut rx = Vec::new();
    let mut joins = Vec::new();
    for (role, a) in [(Role::Host, ha), (Role::Client, ca)] {
        let (tx, r) = mpsc::channel(8);
        rx.push(r);
        let (n, c) = (n.clone(), cancel.clone());
        joins.push(tokio::spawn(async move { n.run(RvCtx::new(key, role, vec![a]), tx, c).await }));
    }
    let mut got = Vec::new();
    for r in rx.iter_mut() {
        let c = timeout(Duration::from_secs(25), r.recv()).await.expect("peer within 25 s").expect("candidate");
        got.push((c.addr, t0.elapsed()));
    }
    cancel.cancel();
    for j in joins {
        assert_eq!(j.await.unwrap(), Ok(()));
    }
    println!("host got {} after {:?}; client got {} after {:?}", got[0].0, got[0].1, got[1].0, got[1].1);
    assert_eq!(got[0].0, ca);
    assert_eq!(got[1].0, ha);
    assert!(matches!(n.probe(Duration::from_secs(10)).await, ProbeStatus::Reachable { .. }));
}
