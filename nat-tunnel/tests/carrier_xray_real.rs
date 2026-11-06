//! REAL Xray validation (no fakes). Every test is `#[ignore]` and env-driven; see
//! docs/research/e2e-xray-real.md for the exact commands.
//!
//! Local env:   XRAY_BIN (absolute path of the client binary), XRAY_SHA256 (optional pin).
//! Remote env:  XRAY_REMOTE (`ip:port` of the Xray host), XRAY_KEY (32 hex invite key),
//!              XRAY_SNI (REALITY serverName = the target site), optional XRAY_FP, XRAY_MODE,
//!              XRAY_XUDP (0|1), XRAY_DEMUX (header|none), XRAY_LOG (xray loglevel).
//! Config dump: XRAY_OUT (dir), XRAY_HOST_PORT, XRAY_TARGET (host:port), XRAY_STRAIT_PORT,
//!              XRAY_HOST_LOG (log file path on the host).
//! Load:        XRAY_PPS (10), XRAY_SECS (300).
//! Control:     XRAY_REMOTE_KILL_CMD / XRAY_REMOTE_START_CMD (shell) for the host-restart test.
//!
//! Result lines start with `RESULT` and carry no secrets.
#![cfg(feature = "cr-xray")]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nat_tunnel::carrier::xray::xray_config::{client_config, host_config, Secrets, XhttpMode, XrayParams};
use nat_tunnel::carrier::xray::XrayFactory;
use nat_tunnel::carrier::{CarrierError, CarrierFactory, CarrierSpec, FrameIo};
use serde_json::Value;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}
fn need(k: &str) -> String {
    env(k).unwrap_or_else(|| panic!("env {k} is required for this ignored test"))
}
fn num(k: &str, d: u64) -> u64 {
    env(k).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn key16(s: &str) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn spec(endpoint: &str, key: &str, extra: &[(&str, &str)]) -> CarrierSpec {
    let mut p: Vec<(String, String)> = vec![
        ("xray_bin".into(), need("XRAY_BIN")),
        ("invite_key".into(), key.into()),
        ("xray_sni".into(), need("XRAY_SNI")),
        ("xray_fp".into(), env("XRAY_FP").unwrap_or_else(|| "firefox".into())),
        ("xray_mode".into(), env("XRAY_MODE").unwrap_or_else(|| "packet-up".into())),
        ("xray_xudp".into(), env("XRAY_XUDP").unwrap_or_else(|| "0".into())),
        ("xray_demux".into(), env("XRAY_DEMUX").unwrap_or_else(|| "header".into())),
        ("xray_log".into(), env("XRAY_LOG").unwrap_or_else(|| "warning".into())),
        ("xray_start_timeout_ms".into(), "15000".into()),
        ("xray_settle_ms".into(), "500".into()),
        ("xray_backoff_ms".into(), "300".into()),
        ("xray_monitor_ms".into(), "500".into()),
    ];
    if let Some(h) = env("XRAY_SHA256") {
        p.push(("xray_sha256".into(), h));
    }
    p.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    CarrierSpec { endpoint: Some(endpoint.into()), bind_port: None, params: p }
}

async fn dial(key: &str, extra: &[(&str, &str)]) -> Result<(Arc<dyn FrameIo>, SocketAddr), CarrierError> {
    let ep = need("XRAY_REMOTE");
    let to = tokio::net::lookup_host(&ep).await.unwrap().next().unwrap();
    let c = XrayFactory.dial(&spec(&ep, key, extra)).await?;
    Ok((c, to))
}

// frame: "TUXR" | tag u32 | seq u64 | padding to size
fn mk(tag: u32, seq: u64, size: usize) -> Vec<u8> {
    let mut f = vec![0u8; size.max(16)];
    f[..4].copy_from_slice(b"TUXR");
    f[4..8].copy_from_slice(&tag.to_be_bytes());
    f[8..16].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in f[16..].iter_mut().enumerate() {
        *b = (i as u8) ^ (seq as u8);
    }
    f
}
fn parse(f: &[u8]) -> Option<(u32, u64)> {
    (f.len() >= 16 && &f[..4] == b"TUXR").then(|| (u32::from_be_bytes(f[4..8].try_into().unwrap()), u64::from_be_bytes(f[8..16].try_into().unwrap())))
}

#[derive(Default, Debug)]
struct Stats {
    sent: u64,
    recvd: u64,
    dup: u64,
    reorder: u64,
    corrupt: u64,
    bytes_rx: u64,
    rtts_us: Vec<u64>,
    first_rx_after_ms: Option<u128>,
}
impl Stats {
    fn pct(&self, p: f64) -> u64 {
        let mut v = self.rtts_us.clone();
        v.sort();
        if v.is_empty() { 0 } else { v[((v.len() - 1) as f64 * p) as usize] }
    }
    fn line(&self, name: &str, secs: f64) -> String {
        let lost = self.sent.saturating_sub(self.recvd.saturating_sub(self.dup));
        format!(
            "RESULT {name} sent={} recv={} lost={} loss_pct={:.2} dup={} reorder={} corrupt={} rtt_ms min/med/p95/max={:.1}/{:.1}/{:.1}/{:.1} rx_mbit_s={:.2}",
            self.sent,
            self.recvd,
            lost,
            100.0 * lost as f64 / self.sent.max(1) as f64,
            self.dup,
            self.reorder,
            self.corrupt,
            self.pct(0.0) as f64 / 1e3,
            self.pct(0.5) as f64 / 1e3,
            self.pct(0.95) as f64 / 1e3,
            self.pct(1.0) as f64 / 1e3,
            self.bytes_rx as f64 * 8.0 / secs / 1e6,
        )
    }
}

/// Send `pps` frames/s of `size(seq)` bytes for `secs`; receive concurrently; wait `tail` for stragglers.
async fn load(io: &Arc<dyn FrameIo>, to: SocketAddr, tag: u32, pps: u64, secs: u64, size: impl Fn(u64) -> usize + Send + 'static, tail: Duration) -> Stats {
    let t0 = Instant::now();
    let sent_at = Arc::new(std::sync::Mutex::new(Vec::<Instant>::new()));
    let (io2, sa) = (io.clone(), sent_at.clone());
    let sender = tokio::spawn(async move {
        let total = pps * secs;
        let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / pps as f64));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        let mut errs = 0u64;
        for seq in 0..total {
            tick.tick().await;
            sa.lock().unwrap().push(Instant::now());
            if io2.send_to(&mk(tag, seq, size(seq)), to).await.is_err() {
                errs += 1;
            }
        }
        (total, errs)
    });
    let mut st = Stats::default();
    let mut seen = std::collections::HashSet::new();
    let mut max_seq: i64 = -1;
    let mut buf = vec![0u8; 2048];
    let mut done_at: Option<Instant> = None;
    loop {
        if sender.is_finished() && done_at.is_none() {
            done_at = Some(Instant::now());
        }
        if done_at.is_some_and(|d| d.elapsed() > tail) {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(100), io.readable()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => break,
            Err(_) => continue,
        }
        while let Ok((n, _)) = io.try_recv_from(&mut buf) {
            let Some((t, seq)) = parse(&buf[..n]) else { st.corrupt += 1; continue };
            if t != tag || buf[..n] != mk(tag, seq, n)[..] {
                st.corrupt += 1;
                continue;
            }
            st.recvd += 1;
            st.bytes_rx += n as u64;
            st.first_rx_after_ms.get_or_insert(t0.elapsed().as_millis());
            if !seen.insert(seq) {
                st.dup += 1;
                continue;
            }
            if (seq as i64) < max_seq {
                st.reorder += 1;
            }
            max_seq = max_seq.max(seq as i64);
            if let Some(s) = sent_at.lock().unwrap().get(seq as usize) {
                st.rtts_us.push(s.elapsed().as_micros() as u64);
            }
        }
    }
    let (total, errs) = sender.await.unwrap();
    st.sent = total;
    // missing runs, in sequence numbers (seq / pps = seconds into the run)
    let mut runs = Vec::new();
    let mut start: Option<u64> = None;
    for q in 0..=total {
        let miss = q < total && !seen.contains(&q);
        match (miss, start) {
            (true, None) => start = Some(q),
            (false, Some(a)) => {
                runs.push(format!("{:.1}s-{:.1}s", a as f64 / pps as f64, q as f64 / pps as f64));
                start = None;
            }
            _ => {}
        }
    }
    if !runs.is_empty() && runs.len() <= 40 {
        println!("RESULT lost_runs tag={tag} {}", runs.join(" "));
    }
    if errs > 0 {
        println!("RESULT send_errors={errs}");
    }
    st
}

/// Wait until one echo comes back (the sidecar and the REALITY session need a moment).
async fn warm(io: &Arc<dyn FrameIo>, to: SocketAddr, tag: u32) -> Option<Duration> {
    let t0 = Instant::now();
    let mut buf = [0u8; 2048];
    for i in 0..40u64 {
        io.send_to(&mk(tag, 1_000_000 + i, 64), to).await.ok()?;
        if tokio::time::timeout(Duration::from_millis(500), io.readable()).await.is_ok() && io.try_recv_from(&mut buf).is_ok() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            while io.try_recv_from(&mut buf).is_ok() {}
            return Some(t0.elapsed());
        }
    }
    None
}

// ------------------------------------------------------------------------------------------ 1

/// Generate the host and client configs with OUR generators, write them to XRAY_OUT, and run the
/// real `xray version` + `xray run -test -c` on the local binary.
#[test]
#[ignore]
fn real_dump_and_validate_configs() {
    let out = need("XRAY_OUT");
    let key = need("XRAY_KEY");
    let s = Secrets::derive(&key16(&key));
    let p = XrayParams {
        public_port: num("XRAY_HOST_PORT", 8443) as u16,
        strait_port: num("XRAY_STRAIT_PORT", 7100) as u16,
        local_port: 10800,
        server_addr: "127.0.0.1".into(),
        server_port: num("XRAY_HOST_PORT", 8443) as u16,
        target: need("XRAY_TARGET"),
        server_name: need("XRAY_SNI"),
        mode: XhttpMode::parse(&env("XRAY_MODE").unwrap_or_else(|| "packet-up".into())).unwrap(),
        log_file: env("XRAY_HOST_LOG").map(Into::into),
        ..XrayParams::default()
    };
    let host = host_config(&p, &s).unwrap();
    let client = client_config(&XrayParams { log_file: Some(Path::new(&out).join("client.log")), ..p.clone() }, &s).unwrap();
    let clientx = client_config(&XrayParams { xudp: true, log_file: Some(Path::new(&out).join("client.log")), ..p }, &s).unwrap();
    let bin = need("XRAY_BIN");
    let ver = std::process::Command::new(&bin).arg("version").output().unwrap();
    println!("RESULT version: {}", String::from_utf8_lossy(&ver.stdout).lines().next().unwrap_or(""));
    for (name, v) in [("host.json", &host), ("client.json", &client), ("client_xudp.json", &clientx)] {
        let path = Path::new(&out).join(name);
        std::fs::write(&path, serde_json::to_string_pretty(v).unwrap()).unwrap();
        let t = std::process::Command::new(&bin).args(["run", "-test", "-c"]).arg(&path).output().unwrap();
        let txt = format!("{}{}", String::from_utf8_lossy(&t.stdout), String::from_utf8_lossy(&t.stderr));
        println!("RESULT {name}: exit={} ok={}", t.status.code().unwrap_or(-1), txt.contains("Configuration OK"));
        assert!(t.status.success() && txt.contains("Configuration OK"), "{name} rejected: {txt}");
    }
}

/// `xray run -test` only parses; prove that a wrong *value* is rejected, so a pass means something.
/// (Unknown *keys* are silently ignored by Xray's JSON loader: that is why field names were
/// verified against the source, see the doc.)
#[test]
#[ignore]
fn real_test_rejects_bad_values() {
    let bin = need("XRAY_BIN");
    let d = std::env::temp_dir().join(format!("xr-bad-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let cases = [
        ("bad_redirect", r#"{"inbounds":[{"port":1,"protocol":"vless","settings":{"clients":[],"decryption":"none"}}],"outbounds":[{"protocol":"freedom","settings":{"redirect":"nonsense"}}]}"#),
        ("bad_mode", r#"{"inbounds":[{"port":1,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"mode":"bogus"}}}],"outbounds":[{"protocol":"freedom"}]}"#),
        ("bad_protocol", r#"{"inbounds":[{"port":1,"protocol":"nosuch"}],"outbounds":[{"protocol":"freedom"}]}"#),
    ];
    for (n, c) in cases {
        let p = d.join(format!("{n}.json"));
        std::fs::write(&p, c).unwrap();
        let t = std::process::Command::new(&bin).args(["run", "-test", "-c"]).arg(&p).output().unwrap();
        println!("RESULT {n}: exit={}", t.status.code().unwrap_or(-1));
        assert!(!t.status.success(), "{n} should be rejected");
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------------------------------ 2

#[tokio::test]
#[ignore]
async fn real_remote_sizes() {
    let (c, to) = dial(&need("XRAY_KEY"), &[]).await.expect("dial");
    let w = warm(&c, to, 1).await.expect("no echo through the tunnel");
    println!("RESULT first_echo_after_ms={}", w.as_millis());
    let max = c.caps().max_frame;
    println!("RESULT caps max_frame={max} overhead={}", c.caps().overhead);
    let e = c.send_to(&vec![0u8; max + 1], to).await.unwrap_err();
    assert!(matches!(CarrierError::from_io(&e), Some(CarrierError::FrameTooLarge { .. })));
    let sizes = [16usize, 17, 32, 64, 100, 128, 256, 400, 512, 576, 800, 1000, 1200, 1280, 1300, max - 1, max];
    for s in sizes {
        let st = load(&c, to, 7, 100, 3, move |_| s, Duration::from_secs(2)).await;
        println!("{}", st.line(&format!("size_{s}"), 3.0));
    }
}

#[tokio::test]
#[ignore]
async fn real_remote_rtt() {
    let (c, to) = dial(&need("XRAY_KEY"), &[]).await.expect("dial");
    warm(&c, to, 1).await.expect("no echo through the tunnel");
    let secs = num("XRAY_SECS", 300);
    let pps = num("XRAY_PPS", 10);
    let st = load(&c, to, 2, pps, secs, |s| 200 + (s as usize * 37) % 1000, Duration::from_secs(5)).await;
    println!("{}", st.line(&format!("rtt_{pps}pps_{secs}s"), secs as f64));
}

#[tokio::test]
#[ignore]
async fn real_remote_burst() {
    let (c, to) = dial(&need("XRAY_KEY"), &[]).await.expect("dial");
    warm(&c, to, 1).await.expect("no echo through the tunnel");
    for pps in [100u64, 500, 1000, 2000, 4000] {
        let st = load(&c, to, 3, pps, 8, |_| 1300, Duration::from_secs(3)).await;
        println!("{}", st.line(&format!("burst_{pps}pps_1300B_8s"), 8.0));
    }
}

/// Two Mac clients at once, each with its own tag: no cross-delivery, both complete.
#[tokio::test]
#[ignore]
async fn real_remote_two_clients() {
    let key = need("XRAY_KEY");
    let (a, to) = dial(&key, &[]).await.expect("dial a");
    let (b, _) = dial(&key, &[]).await.expect("dial b");
    warm(&a, to, 11).await.expect("a: no echo");
    warm(&b, to, 22).await.expect("b: no echo");
    let (a2, b2) = (a.clone(), b.clone());
    let ta = tokio::spawn(async move { load(&a2, to, 11, 50, 20, |_| 600, Duration::from_secs(3)).await });
    let tb = tokio::spawn(async move { load(&b2, to, 22, 50, 20, |_| 600, Duration::from_secs(3)).await });
    println!("{}", ta.await.unwrap().line("two_clients_a", 20.0));
    println!("{}", tb.await.unwrap().line("two_clients_b", 20.0));
}

/// Kill the Xray client mid-run (the supervisor must restart it), then the remote Xray.
#[tokio::test]
#[ignore]
async fn real_remote_reconnect() {
    let (c, to) = dial(&need("XRAY_KEY"), &[]).await.expect("dial");
    warm(&c, to, 1).await.expect("no echo");
    let pat = format!("strait-xray-{}-", std::process::id());
    let sh = |cmd: String| {
        let o = std::process::Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
        println!("RESULT sh `{}` exit={}", cmd.split_whitespace().next().unwrap_or(""), o.status.code().unwrap_or(-1));
    };
    let c2 = c.clone();
    let probe = tokio::spawn(async move { load(&c2, to, 5, 10, 80, |_| 300, Duration::from_secs(3)).await });
    tokio::time::sleep(Duration::from_secs(10)).await;
    println!("RESULT t=10s killing the local Xray client; health before: {:?}", c.health());
    sh(format!("pkill -9 -f '{pat}.*config.json'"));
    tokio::time::sleep(Duration::from_secs(25)).await;
    println!("RESULT t=35s health: {:?}", c.health());
    if let (Some(k), Some(s)) = (env("XRAY_REMOTE_KILL_CMD"), env("XRAY_REMOTE_START_CMD")) {
        println!("RESULT t=35s killing the REMOTE Xray");
        sh(k);
        tokio::time::sleep(Duration::from_secs(10)).await;
        println!("RESULT t=45s restarting the REMOTE Xray");
        sh(s);
    }
    let st = probe.await.unwrap();
    // outage windows: count consecutive lost seq runs from rtts (seq order is lost in `Stats`), so
    // report totals plus time of first echo; the per-second timeline is printed by the caller's log.
    println!("{}", st.line("reconnect_10pps_80s", 80.0));
    println!("RESULT health at end: {:?}", c.health());
}

/// A client derived from a different invite key: REALITY auth must fail; report what the carrier says.
#[tokio::test]
#[ignore]
async fn real_remote_wrong_key() {
    let wrong = env("XRAY_WRONG_KEY").unwrap_or_else(|| "ffeeddccbbaa99887766554433221100".into());
    match dial(&wrong, &[]).await {
        Err(e) => println!("RESULT wrong_key dial error (typed): {e:?}"),
        Ok((c, to)) => {
            let w = warm(&c, to, 9).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!("RESULT wrong_key dial=Ok warm_echo={:?} health={:?}", w, c.health());
            assert!(w.is_none(), "a wrong key must never carry traffic");
            assert!(matches!(c.health(), nat_tunnel::carrier::Health::Down(_)), "REALITY rejection must surface as Health::Down");
        }
    }
}

/// The destination pin: a client that asks the host to reach ANOTHER address/port (here the decoy
/// UDP echo on the VPS loopback and on its public IP) must still land on the pinned target.
/// XRAY_DECOY_PORT: decoy port the client asks for (rewritePort). The caller inspects the decoy log.
#[tokio::test]
#[ignore]
async fn real_remote_open_proxy_negative() {
    let key = need("XRAY_KEY");
    let ep = need("XRAY_REMOTE");
    let bin = need("XRAY_BIN");
    let decoy = num("XRAY_DECOY_PORT", 7301) as u16;
    let s = Secrets::derive(&key16(&key));
    let (h, p) = ep.rsplit_once(':').unwrap();
    for addr in ["127.0.0.1", &env("XRAY_DECOY_ADDR").unwrap_or_else(|| h.to_string())] {
        let dir = std::env::temp_dir().join(format!("xr-neg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let prm = XrayParams {
            server_addr: h.into(),
            server_port: p.parse().unwrap(),
            server_name: need("XRAY_SNI"),
            mode: XhttpMode::PacketUp,
            local_port: lp,
            strait_port: decoy,
            log_file: Some(dir.join("c.log")),
            ..XrayParams::default()
        };
        let mut cfg = client_config(&prm, &s).unwrap();
        cfg["inbounds"][0]["settings"]["rewriteAddress"] = Value::String(addr.to_string()); // the attack
        std::fs::write(dir.join("c.json"), cfg.to_string()).unwrap();
        let mut child = std::process::Command::new(&bin).args(["run", "-c"]).arg(dir.join("c.json")).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut got = None;
        let mut buf = [0u8; 2048];
        for i in 0..20u64 {
            sock.send_to(&mk(99, i, 100), ("127.0.0.1", lp)).await.unwrap();
            if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
                got = Some(buf[..n].to_vec());
                break;
            }
        }
        println!("RESULT open_proxy_negative asked={addr}:{decoy} reply_len={:?}", got.as_ref().map(Vec::len));
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ------------------------------------------------------------------------------------------ 3

#[tokio::test]
#[ignore]
async fn real_pins() {
    // hash pin mismatch -> Blocked, nothing executed
    let mut sp = spec("127.0.0.1:9", &"00".repeat(16), &[]);
    sp.params.retain(|(k, _)| k != "xray_sha256");
    sp.params.push(("xray_sha256".into(), "ab".repeat(32)));
    let e = XrayFactory.dial(&sp).await.err().expect("hash pin must fail");
    println!("RESULT hash_pin_mismatch -> {e:?}");
    assert!(matches!(e, CarrierError::Blocked(_)));
    // version pin: a wrapper that reports an old version, otherwise exec's the real binary
    let d = std::env::temp_dir().join(format!("xr-ver-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let w = d.join("xray-old");
    std::fs::write(&w, format!("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 26.10.30 (wrapper) (go1.27.3)'; exit 0; fi\nexec '{}' \"$@\"\n", need("XRAY_BIN"))).unwrap();
    std::process::Command::new("chmod").arg("755").arg(&w).status().unwrap();
    let mut sp = spec("127.0.0.1:9", &"00".repeat(16), &[]);
    sp.params.retain(|(k, _)| k != "xray_sha256" && k != "xray_bin");
    sp.params.push(("xray_bin".into(), w.to_string_lossy().into()));
    let e = XrayFactory.dial(&sp).await.err().expect("old version must fail");
    println!("RESULT version_pin_old -> {e:?}");
    assert!(matches!(e, CarrierError::Blocked(_)));
    let _ = std::fs::remove_dir_all(&d);
    // correct hash passes check_binary: probe reaches the TCP stage
    let st = XrayFactory.probe(&spec("127.0.0.1:9", &"00".repeat(16), &[]), Duration::from_secs(5)).await;
    println!("RESULT probe_with_real_binary -> {st:?}");
}
