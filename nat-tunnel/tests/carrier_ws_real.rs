//! REAL-network ws carrier checks (ignored by default). Needs a `carrier_peer host --carrier ws` already running on a
//! remote machine and the built example. See docs/research/e2e-ws-awg-real.md for the full procedure.
//!   STRAIT_REAL_PEER=target/fast/examples/carrier_peer STRAIT_REAL_WS_ENDPOINT=1.2.3.4:9443 STRAIT_REAL_KEY=<32hex> \
//!   cargo test --profile fast --no-default-features --features cr-ws --test carrier_ws_real -- --ignored --nocapture
#![cfg(feature = "cr-ws")]
use std::process::Command;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn run(args: &[&str]) -> serde_json::Value {
    let peer = env("STRAIT_REAL_PEER").expect("STRAIT_REAL_PEER");
    let out = Command::new(peer).arg("client").args(args).output().expect("run carrier_peer");
    let line = String::from_utf8_lossy(&out.stdout).lines().last().unwrap_or("").to_string();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad JSON {line:?}: {e}"))
}

#[test]
#[ignore]
fn real_ws_paced_no_loss_and_wrong_key_is_blocked() {
    let (Some(ep), Some(key)) = (env("STRAIT_REAL_WS_ENDPOINT"), env("STRAIT_REAL_KEY")) else {
        panic!("set STRAIT_REAL_WS_ENDPOINT and STRAIT_REAL_KEY");
    };
    let max_p95: f64 = env("STRAIT_REAL_MAX_P95_MS").map_or(500.0, |v| v.parse().unwrap());
    for size in ["100", "500", "1335"] {
        let j = run(&["--carrier", "ws", "--key", &key, "--endpoint", &ep, "--size", size, "--pps", "50", "--secs", "10"]);
        assert_eq!(j["loss_pct"].as_f64().unwrap(), 0.0, "size {size}: {j}");
        assert!(j["rtt_ms"]["p95"].as_f64().unwrap() < max_p95, "size {size}: {j}");
    }
    // a different key must not authenticate: typed TLS failure at dial time, never a silent hang
    let bad = "ffeeddccbbaa99887766554433221100";
    let j = run(&["--carrier", "ws", "--key", bad, "--endpoint", &ep, "--secs", "1"]);
    assert!(j["dial_error"].as_str().unwrap_or("").contains("Blocked"), "{j}");
}
