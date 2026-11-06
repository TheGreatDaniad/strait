//! The real binary's carrier probes must not print wrong verdicts (e2e-carriers finding 7).
#![cfg(feature = "cr-awg")]

use std::process::Command;

fn run(args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_nat-tunnel")).args(args).output().expect("run nat-tunnel");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn carrier_test_does_not_call_a_closed_udp_port_reachable() {
    // Nothing listens on this port (we just freed it): UDP cannot tell, and must say so.
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let out = run(&["carrier-test", "--carriers", "awg", "--endpoint", &format!("127.0.0.1:{port}")]);
    assert!(out.contains("unverifiable") && !out.contains("reachable 0 ms"), "{out}");
}

#[test]
fn check_host_carriers_prints_local_results_for_each_carrier() {
    // Hold awg's default port: the local check must say it cannot start (and not "reachable").
    let held = std::net::UdpSocket::bind("0.0.0.0:7202");
    let out = run(&["check-host", "--port", "0", "--carriers", "awg"]);
    assert!(out.contains("awg "), "carrier line missing even though the host check may fail:\n{out}");
    assert!(!out.contains("reachable 0 ms"), "{out}");
    if held.is_ok() {
        assert!(out.contains("cannot start here"), "{out}");
    }
}
