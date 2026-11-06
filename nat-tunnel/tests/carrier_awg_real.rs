//! REAL-network awg carrier checks (ignored by default). Needs a `carrier_peer host --carrier awg` already running on a
//! remote machine and the built example. See docs/research/e2e-ws-awg-real.md.
//!   STRAIT_REAL_PEER=target/fast/examples/carrier_peer STRAIT_REAL_AWG_ENDPOINT=1.2.3.4:9460 STRAIT_REAL_KEY=<32hex> \
//!   cargo test --profile fast --no-default-features --features cr-awg --test carrier_awg_real -- --ignored --nocapture
#![cfg(feature = "cr-awg")]
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
fn real_awg_paced_no_loss_wrong_key_silent_oversize_typed() {
    let (Some(ep), Some(key)) = (env("STRAIT_REAL_AWG_ENDPOINT"), env("STRAIT_REAL_KEY")) else {
        panic!("set STRAIT_REAL_AWG_ENDPOINT and STRAIT_REAL_KEY");
    };
    let max_p95: f64 = env("STRAIT_REAL_MAX_P95_MS").map_or(500.0, |v| v.parse().unwrap());
    for size in ["100", "500", "1425"] {
        let j = run(&["--carrier", "awg", "--key", &key, "--endpoint", &ep, "--size", size, "--pps", "50", "--secs", "10"]);
        assert_eq!(j["loss_pct"].as_f64().unwrap(), 0.0, "size {size}: {j}");
        assert!(j["rtt_ms"]["p95"].as_f64().unwrap() < max_p95, "size {size}: {j}");
    }
    // wrong key: the host never answers (silent drop by design), so everything is lost and nothing is echoed
    let j = run(&["--carrier", "awg", "--key", "ffeeddccbbaa99887766554433221100", "--endpoint", &ep, "--pps", "10", "--secs", "2"]);
    assert_eq!(j["recv"].as_u64().unwrap(), 0, "{j}");
    // one byte over max_frame is a typed FrameTooLarge, not a silent drop
    let j = run(&["--carrier", "awg", "--key", &key, "--endpoint", &ep, "--size", "1426", "--pps", "10", "--secs", "1"]);
    assert!(j["events"].to_string().contains("FrameTooLarge"), "{j}");
}
