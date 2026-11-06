//! LIVE check against the real public brokers (HiveMQ, EMQX). `#[ignore]`: run by hand with
//! `cargo test --release --no-default-features --features rv-mqtt --test rv_mqtt_live -- --ignored --nocapture`.
//! Polite: fresh random key (so a fresh random topic) per scenario, documentation-range fake
//! candidates, stops as soon as both sides have the other's candidate, no retain, run once = a
//! handful of publishes per broker.
#![cfg(feature = "rv-mqtt")]
use std::time::{Duration, Instant};

use nat_tunnel::rendezvous::mqtt::Mqtt;
use nat_tunnel::rendezvous::{Candidate, Rendezvous, Role, RvConfig, RvCtx};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Both roles through `brokers`; returns (host got client's after, client got host's after).
async fn pair(brokers: &str) -> Result<(Duration, Duration), String> {
    let key = *uuid::Uuid::new_v4().as_bytes();
    let b = std::sync::Arc::new(Mqtt::new(&RvConfig { mqtt_broker: Some(brokers.into()), ..Default::default() }));
    let t0 = Instant::now();
    let cancel = CancellationToken::new();
    let mk = |role, addr: &str| {
        let (tx, rx) = mpsc::channel(8);
        let (b, c, ctx) = (b.clone(), cancel.clone(), RvCtx::new(key, role, vec![addr.parse().unwrap()]));
        (tokio::spawn(async move { b.run(ctx, tx, c).await }), rx)
    };
    let (hj, mut hrx) = mk(Role::Host, "203.0.113.1:4000");
    let (cj, mut crx) = mk(Role::Client, "203.0.113.2:5000");
    async fn wait(rx: &mut mpsc::Receiver<Candidate>, t0: Instant) -> Option<(Candidate, Duration)> {
        let c = tokio::time::timeout(Duration::from_secs(14), rx.recv()).await.ok().flatten()?;
        Some((c, t0.elapsed()))
    }
    let (h, c) = tokio::join!(wait(&mut hrx, t0), wait(&mut crx, t0));
    cancel.cancel();
    let (hr, cr) = (hj.await.unwrap(), cj.await.unwrap());
    if hr.is_err() || cr.is_err() {
        return Err(format!("run errors: {hr:?} / {cr:?}"));
    }
    match (h, c) {
        (Some((hc, ht)), Some((cc, ct))) if hc.addr.to_string() == "203.0.113.2:5000" && cc.addr.to_string() == "203.0.113.1:4000" => Ok((ht, ct)),
        (h, c) => Err(format!("not delivered: host={:?} client={:?}", h.map(|x| x.0), c.map(|x| x.0))),
    }
}

#[tokio::test]
#[ignore]
async fn live_real_brokers() {
    let (hive, emqx) = ("broker.hivemq.com:8883", "broker.emqx.io:8883");
    for b in [hive, emqx] {
        let m = Mqtt::new(&RvConfig { mqtt_broker: Some(b.into()), ..Default::default() });
        eprintln!("LIVE probe {b}: {:?}", m.probe(Duration::from_secs(10)).await);
    }
    if std::env::var("LIVE_PROBE_ONLY").is_ok() {
        return; // zero publishes: used from the VPS to respect the publish budget
    }
    for run in 0..3 {
        let mut ok = 0;
        let scenarios: &[(&str, String)] = if run == 0 {
            &[("hivemq", hive.into()), ("emqx", emqx.into()), ("both", format!("{hive},{emqx}"))]
        } else {
            &[("hivemq", hive.into()), ("emqx", emqx.into())]
        };
        for (name, spec) in scenarios {
            match pair(spec).await {
                Ok((h, c)) => {
                    ok += 1;
                    eprintln!("LIVE run {run} {name}: host got client after {} ms, client got host after {} ms", h.as_millis(), c.as_millis());
                }
                Err(e) => panic!("LIVE run {run} {name}: FAILED {e} (stopping: error signal)"),
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        assert!(ok >= 1, "run {run}: no broker delivered, stopping");
    }
}
