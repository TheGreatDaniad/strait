//! Xray sidecar carrier against a FAKE sidecar: a shell wrapper re-executes this test binary
//! (`fake_xray_entry`) with the arguments our code passes. No Xray is downloaded, built or run.
#![cfg(feature = "cr-xray")]
#![cfg(unix)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use nat_tunnel::carrier::xray::xray_config::{self, client_config, host_config, violations, Role, Secrets, XhttpMode, XrayParams, N};
use nat_tunnel::carrier::xray::{parse_version, untrusted_install, XrayFactory};
use nat_tunnel::carrier::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, FrameIo, Health};
use nat_tunnel::rendezvous::ProbeStatus;
use serde_json::{json, Value};

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const KEY2: &str = "ffeeddccbbaa99887766554433221100";
const SNI: &str = "www.example.org";

// ---------------------------------------------------------------- the fake sidecar

fn free_port() -> u16 {
    static USED: Mutex<Vec<u16>> = Mutex::new(Vec::new()); // no two tests in this process share a port
    loop {
        let p = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() && !USED.lock().unwrap().contains(&p) {
            USED.lock().unwrap().push(p);
            return p;
        }
    }
}

fn bridge(listen: u16, to: SocketAddr) {
    use std::net::UdpSocket;
    let l = Arc::new(UdpSocket::bind(("127.0.0.1", listen)).unwrap());
    std::thread::spawn(move || {
        let mut flows: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut b = [0u8; 4096];
        loop {
            let (n, src) = l.recv_from(&mut b).unwrap();
            let out = flows.entry(src).or_insert_with(|| {
                let s = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
                s.connect(to).unwrap();
                let (s2, l2) = (s.clone(), l.clone());
                std::thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    while let Ok(n) = s2.recv(&mut b) {
                        let _ = l2.send_to(&b[..n], src);
                    }
                });
                s
            });
            let _ = out.send(&b[..n]);
        }
    });
}

/// With STRAIT_FAKE_XRAY set this "test" is the Xray binary: `version`, `run -test -c f`, `run -c f`.
#[test]
fn fake_xray_entry() {
    use std::io::Write;
    if std::env::var("STRAIT_FAKE_XRAY").is_err() {
        return;
    }
    let env = |k: &str| std::env::var(k).ok();
    let num = |k: &str, d: u64| env(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let args: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
    println!(); // libtest printed "test ... " without a newline
    if let Some(f) = env("FAKE_ARGS_FILE") {
        let mut o = std::fs::OpenOptions::new().append(true).create(true).open(f).unwrap();
        writeln!(o, "{}", args.join("|")).unwrap();
    }
    fn forever() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("Xray {} (Xray, Penetrates Everything.) fake (go1.27.3 linux/arm64)", env("FAKE_VERSION").unwrap_or("26.10.31".into()));
            std::process::exit(0)
        }
        Some("run") => {}
        _ => std::process::exit(2),
    }
    let cfgp = &args[args.iter().position(|a| a == "-c").expect("-c") + 1];
    let cfg: Value = match serde_json::from_str(&std::fs::read_to_string(cfgp).unwrap()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("config does not parse: {e}");
            std::process::exit(23)
        }
    };
    let (inb, outb) = (&cfg["inbounds"][0], &cfg["outbounds"][0]);
    let host = inb["protocol"] == "vless";
    assert!(host || inb["protocol"] == "tunnel", "unknown inbound protocol");
    if args.iter().any(|a| a == "-test") {
        if env("FAKE_TEST_FAIL").is_some() {
            eprintln!("Failed to start: bad privateKey {}", inb["streamSettings"]["realitySettings"]["privateKey"].as_str().unwrap_or(""));
            std::process::exit(23)
        }
        std::process::exit(0)
    }
    let run = match env("FAKE_STATE") {
        Some(p) => {
            let n = std::fs::read_to_string(&p).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0) + 1;
            std::fs::write(&p, n.to_string()).unwrap();
            n
        }
        None => 1,
    };
    let mode = env("FAKE_MODE").unwrap_or("ok".into());
    match mode.as_str() {
        "crash" => {
            println!("boot failed");
            std::process::exit(9)
        }
        "crash_runs" if run <= num("FAKE_CRASH_RUNS", 2) => std::process::exit(7),
        "never_ready" => forever(),
        "slow" => std::thread::sleep(Duration::from_millis(num("FAKE_DELAY_MS", 800))),
        _ => {}
    }
    let port = inb["port"].as_u64().unwrap() as u16;
    if host {
        let to: SocketAddr = outb["settings"]["redirect"].as_str().unwrap().parse().unwrap();
        bridge(port, to);
        let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        println!("started");
        if mode == "hang_once" && run == 1 {
            std::thread::sleep(Duration::from_millis(400));
            drop(tcp); // stops answering on the public port; the supervisor must notice
            forever()
        }
        for s in tcp.incoming() {
            drop(s);
        }
    } else {
        let srv = format!("{}:{}", outb["settings"]["address"].as_str().unwrap(), outb["settings"]["port"]);
        bridge(port, srv.parse().unwrap());
        println!("started");
        forever()
    }
    std::process::exit(0)
}

// ---------------------------------------------------------------- fixtures

static N_TMP: AtomicU32 = AtomicU32::new(0);

struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("strait-xt-{}-{}", std::process::id(), N_TMP.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn join(&self, s: &str) -> PathBuf {
        self.0.join(s)
    }
    /// A fake `xray`: a script that re-executes this test binary with the caller's arguments.
    fn xray(&self, env: &[(&str, &str)]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let mut s = String::from("#!/bin/sh\nexport STRAIT_FAKE_XRAY=1");
        s += &format!(" FAKE_ARGS_FILE='{}'", self.join("args.txt").display());
        for (k, v) in env {
            s += &format!(" {k}='{v}'");
        }
        s += &format!("\nexec '{}' --exact fake_xray_entry --nocapture --test-threads=1 -- \"$@\"\n", std::env::current_exe().unwrap().display());
        let p = self.join(&format!("xray{}", N_TMP.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&p, s).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
    fn runs(&self) -> Vec<String> {
        std::fs::read_to_string(self.join("args.txt")).unwrap_or_default().lines().map(String::from).collect()
    }
    fn run_dirs(&self) -> Vec<PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(&self.0).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        v.sort();
        v
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
struct Cap;
impl log::Log for Cap {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        LOGS.lock().unwrap().push(format!("{} {}", r.target(), r.args()));
    }
    fn flush(&self) {}
}
fn init_logs() {
    static O: Once = Once::new();
    O.call_once(|| {
        log::set_logger(&Cap).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
}

/// A real local TCP listener standing in for the REALITY target (the host refuses to start without one).
fn target_addr() -> String {
    static L: std::sync::OnceLock<std::net::TcpListener> = std::sync::OnceLock::new();
    L.get_or_init(|| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).local_addr().unwrap().to_string()
}

fn spec(bin: &Path, t: &Tmp, endpoint: Option<String>, extra: &[(&str, &str)]) -> CarrierSpec {
    init_logs();
    let mut params: Vec<(String, String)> = extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let target = target_addr();
    let base = [
        ("xray_target", target.as_str()),
        ("xray_bin", bin.to_str().unwrap()),
        ("invite_key", KEY),
        ("xray_sni", SNI),
        ("xray_run_dir", t.0.to_str().unwrap()),
        ("xray_backoff_ms", "30"),
        ("xray_monitor_ms", "100"),
        ("xray_settle_ms", "800"),
        ("xray_warmup_ms", "0"),
    ];
    params.extend(base.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    CarrierSpec { endpoint, bind_port: None, params }
}

fn va(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

async fn recv(io: &Arc<dyn FrameIo>) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut b = [0u8; 2048];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            io.readable().await?;
            match io.try_recv_from(&mut b) {
                Ok((n, a)) => return Ok((b[..n].to_vec(), a)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no frame"))?
}

/// Client -> host with resends (the sidecar may still be binding), then drain duplicates.
async fn first_frame(client: &Arc<dyn FrameIo>, to: SocketAddr, host: &Arc<dyn FrameIo>, frame: &[u8]) -> SocketAddr {
    for _ in 0..20 {
        client.send_to(frame, to).await.unwrap();
        if let Ok(Ok((f, peer))) = tokio::time::timeout(Duration::from_millis(300), recv(host)).await {
            assert_eq!(f, frame);
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut b = [0u8; 2048];
            while host.try_recv_from(&mut b).is_ok() {}
            return peer;
        }
    }
    panic!("no frame reached the host through the fake sidecar");
}

async fn pair(t: &Tmp, bin: &Path, extra: &[(&str, &str)]) -> (Arc<dyn FrameIo>, Arc<dyn FrameIo>, SocketAddr) {
    let l = free_port();
    let host = XrayFactory.listen(&spec(bin, t, Some(format!("0.0.0.0:{l}")), extra)).await.unwrap();
    let client = XrayFactory.dial(&spec(bin, t, Some(format!("127.0.0.1:{l}")), extra)).await.unwrap();
    (host, client, va(l))
}

// ---------------------------------------------------------------- end to end through the fake

#[tokio::test]
async fn frames_flow_both_ways_through_the_fake() {
    let t = Tmp::new();
    let bin = t.xray(&[]);
    let sha: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(std::fs::read(&bin).unwrap()).iter().map(|b| format!("{b:02x}")).collect()
    };
    let (host, client, vh) = pair(&t, &bin, &[("xray_sha256", &sha.to_uppercase())]).await;
    for io in [&host, &client] {
        let c = io.caps();
        assert_eq!(c.id, CarrierId::Xray);
        assert!(!c.punchable && c.reliable_stream);
        assert!(io.udp().is_none() && io.health() == Health::Ok);
    }
    let peer = first_frame(&client, vh, &host, b"hello from client").await;
    host.send_to(b"hello from host", peer).await.unwrap();
    let (f, from) = recv(&client).await.unwrap();
    assert_eq!((f.as_slice(), from), (&b"hello from host"[..], vh), "client sees the fixed virtual host");
    for i in 0..50u8 {
        client.send_to(&[i; 100], vh).await.unwrap();
        let (f, p) = recv(&host).await.unwrap();
        assert_eq!((f, p), (vec![i; 100], peer));
    }
    let big = vec![1u8; 1336];
    let e = client.send_to(&big, vh).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::FrameTooLarge { max: 1335 }));
}

#[tokio::test]
async fn each_client_is_a_distinct_peer() {
    let t = Tmp::new();
    let bin = t.xray(&[]);
    let (host, c1, vh) = pair(&t, &bin, &[]).await;
    let c2 = XrayFactory.dial(&spec(&bin, &t, Some(vh.to_string()), &[])).await.unwrap();
    let p1 = first_frame(&c1, vh, &host, b"one").await;
    let p2 = first_frame(&c2, vh, &host, b"two").await;
    assert_ne!(p1, p2);
    host.send_to(b"to-one", p1).await.unwrap();
    host.send_to(b"to-two", p2).await.unwrap();
    assert_eq!(recv(&c1).await.unwrap().0, b"to-one");
    assert_eq!(recv(&c2).await.unwrap().0, b"to-two");
}

#[tokio::test]
async fn demux_none_uses_the_real_loopback_sources() {
    let t = Tmp::new();
    let bin = t.xray(&[]);
    let (host, c1, vh) = pair(&t, &bin, &[("xray_demux", "none")]).await;
    let c2 = XrayFactory.dial(&spec(&bin, &t, Some(vh.to_string()), &[("xray_demux", "none")])).await.unwrap();
    let p1 = first_frame(&c1, vh, &host, b"one").await;
    let p2 = first_frame(&c2, vh, &host, b"two").await;
    assert!(p1.ip().is_loopback() && p2.ip().is_loopback() && p1 != p2, "fake gives each client its own source port");
}

#[tokio::test]
async fn fake_sees_exactly_the_intended_args_and_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new();
    let bin = t.xray(&[]);
    let l = free_port();
    let host = XrayFactory.listen(&spec(&bin, &t, Some(format!("0.0.0.0:{l}")), &[])).await.unwrap();
    let dirs = t.run_dirs();
    assert_eq!(dirs.len(), 1);
    let dir = &dirs[0];
    let cfg = dir.join("config.json");
    assert_eq!(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let want = if e.file_name() == "xray-verified" { 0o500 } else { 0o600 }; // the verified private copy
        assert_eq!(e.metadata().unwrap().permissions().mode() & 0o777, want, "{:?}", e.path());
    }
    assert_eq!(std::fs::read(dir.join("xray-verified")).unwrap(), std::fs::read(&bin).unwrap(), "the copy is the verified file");
    assert_eq!(
        t.runs(),
        vec!["version".to_string(), format!("run|-test|-c|{}", cfg.display()), format!("run|-c|{}", cfg.display())],
        "no shell, no extra flags"
    );
    // The file holds a config that passes our own audit and names our loopback port as the redirect.
    let v: Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    assert!(violations(&v, Role::Host).is_none());
    let redirect = v["outbounds"][0]["settings"][N.freedom_redirect].as_str().unwrap().to_string();
    assert_eq!(redirect, format!("127.0.0.1:{}", host.local_addr().unwrap().port()));
    assert_eq!(v["log"][N.log_error], dir.join("xray.log").to_str().unwrap());
    drop(host);
    for _ in 0..40 {
        if !dir.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("run dir with the secrets was not removed");
}

// ---------------------------------------------------------------- typed failures

fn failed_with(e: Result<Arc<dyn FrameIo>, CarrierError>, needle: &str) -> CarrierError {
    let e = e.err().expect("must fail");
    assert!(e.to_string().contains(needle), "{e} should contain {needle:?}");
    e
}

#[tokio::test]
async fn binary_problems_are_typed_and_nothing_runs() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new();
    let ep = || Some("0.0.0.0:45999".to_string());
    // missing
    let s = spec(&t.join("nope"), &t, ep(), &[]);
    assert!(matches!(failed_with(XrayFactory.listen(&s).await, "Xray not installed"), CarrierError::Failed(_)));
    // no xray_bin at all
    let mut s = spec(&t.join("nope"), &t, ep(), &[]);
    s.params.retain(|(k, _)| k != "xray_bin");
    failed_with(XrayFactory.listen(&s).await, "xray_bin is required");
    // relative
    failed_with(XrayFactory.listen(&spec(Path::new("xray"), &t, ep(), &[])).await, "absolute");
    failed_with(XrayFactory.dial(&spec(Path::new("./bin/xray"), &t, ep(), &[])).await, "absolute");
    // not executable
    let bin = t.xray(&[]);
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
    failed_with(XrayFactory.listen(&spec(&bin, &t, ep(), &[])).await, "not executable");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    // hash mismatch: Blocked, and the binary was never executed
    let e = failed_with(XrayFactory.listen(&spec(&bin, &t, ep(), &[("xray_sha256", &"0".repeat(64))])).await, "SHA-256");
    assert!(matches!(e, CarrierError::Blocked(_)));
    assert!(t.runs().is_empty(), "an unverified binary must not run: {:?}", t.runs());
    // too old
    let old = t.xray(&[("FAKE_VERSION", "1.8.24")]);
    let e = failed_with(XrayFactory.listen(&spec(&old, &t, ep(), &[])).await, "version too old");
    assert!(matches!(e, CarrierError::Blocked(_)));
    let older_year = t.xray(&[("FAKE_VERSION", "26.10.30")]);
    failed_with(XrayFactory.dial(&spec(&older_year, &t, ep(), &[])).await, "26.10.30");
    // missing key / sni
    let mut s = spec(&bin, &t, ep(), &[]);
    s.params.retain(|(k, _)| k != "invite_key");
    failed_with(XrayFactory.listen(&s).await, "invite_key");
    let mut s = spec(&bin, &t, ep(), &[("xray_sni", "")]);
    s.params.retain(|(k, v)| !(k == "xray_sni" && !v.is_empty()));
    failed_with(XrayFactory.listen(&s).await, "serverNames");
}

#[tokio::test]
async fn pin_mismatch_is_refused_before_anything_runs_and_leaves_no_run_dir() {
    let t = Tmp::new();
    let bin = t.xray(&[]);
    for pin in ["0".repeat(64), "not hex".to_string()] {
        let e = failed_with(XrayFactory.listen(&spec(&bin, &t, Some("0.0.0.0:45998".into()), &[("xray_sha256", &pin)])).await, "pinned SHA-256");
        assert!(matches!(e, CarrierError::Blocked(_)));
        let e = failed_with(XrayFactory.dial(&spec(&bin, &t, Some("127.0.0.1:45998".into()), &[("xray_sha256", &pin)])).await, "pinned SHA-256");
        assert!(matches!(e, CarrierError::Blocked(_)));
    }
    assert!(t.runs().is_empty(), "{:?}", t.runs());
    assert!(t.run_dirs().is_empty(), "the private copy dir is removed on failure");
}

#[tokio::test]
async fn binary_replaced_after_verification_is_not_what_runs() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new();
    let state = t.join("state");
    // hang_once: run 1 stops answering, the supervisor kills it and RESTARTS from the verified copy.
    let bin = t.xray(&[("FAKE_MODE", "hang_once"), ("FAKE_STATE", state.to_str().unwrap())]);
    let sha: String = Sha256::digest(std::fs::read(&bin).unwrap()).iter().map(|b| format!("{b:02x}")).collect();
    let l = free_port();
    let host = XrayFactory.listen(&spec(&bin, &t, Some(format!("0.0.0.0:{l}")), &[("xray_sha256", &sha)])).await.unwrap();
    // Swap the file at the original path for a script that would leave a marker if it were ever run.
    let marker = t.join("EVIL_RAN");
    let evil = t.join("evil");
    std::fs::write(&evil, format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display())).unwrap();
    std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&evil, &bin).unwrap();
    let t0 = Instant::now();
    loop {
        let runs: u32 = std::fs::read_to_string(&state).unwrap().trim().parse().unwrap();
        if runs >= 2 && host.health() == Health::Ok {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "no restart after the hang (runs={runs})");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!marker.exists(), "the swapped binary was executed");
    // A new start of the carrier sees the changed file and refuses it (pin mismatch).
    let e = failed_with(XrayFactory.listen(&spec(&bin, &t, Some("0.0.0.0:45995".into()), &[("xray_sha256", &sha)])).await, "pinned SHA-256");
    assert!(matches!(e, CarrierError::Blocked(_)));
    assert!(!marker.exists());
}

#[test]
fn root_ownership_rule() {
    let p = |s: &str| std::path::PathBuf::from(s);
    let good = vec![(p("/usr/local/bin/xray"), 0, 0o100755), (p("/usr/local/bin"), 0, 0o40755), (p("/usr/local"), 0, 0o40755), (p("/"), 0, 0o40755)];
    assert_eq!(untrusted_install(0, &good), None);
    // not root: the rule does not apply, even for a user-owned writable file
    assert_eq!(untrusted_install(501, &[(p("/home/u/xray"), 501, 0o100777)]), None);
    // root: file owned by someone else
    let mut c = good.clone();
    c[0].1 = 1000;
    assert!(untrusted_install(0, &c).unwrap().contains("xray is owned by uid 1000"));
    // root: a parent directory writable by group, and by others
    for bad in [0o40775, 0o40757, 0o41777] {
        let mut c = good.clone();
        c[2].2 = bad;
        assert!(untrusted_install(0, &c).unwrap().contains("/usr/local is writable"), "{bad:o}");
    }
    // root: user-owned parent
    let mut c = good.clone();
    c[1].1 = 501;
    assert!(untrusted_install(0, &c).unwrap().contains("/usr/local/bin is owned by uid 501"));
    // a non-root euid other than 0 never triggers, an empty chain is fine
    assert_eq!(untrusted_install(0, &[]), None);
}

#[tokio::test]
async fn config_rejected_by_xray_is_reported_without_secrets() {
    let t = Tmp::new();
    let bin = t.xray(&[("FAKE_TEST_FAIL", "1")]);
    let e = failed_with(XrayFactory.listen(&spec(&bin, &t, Some("0.0.0.0:45998".into()), &[])).await, "rejected the generated config");
    let s = Secrets::derive(&hex16(KEY));
    let msg = e.to_string();
    assert!(msg.contains("***") && !msg.contains(&s.private_key), "{msg}");
    assert!(t.runs().iter().all(|r| !r.starts_with("run|-c|")), "must not start after a failed config test");
}

#[tokio::test]
async fn crash_then_restart_recovers() {
    let t = Tmp::new();
    let state = t.join("state");
    let bin = t.xray(&[("FAKE_MODE", "crash_runs"), ("FAKE_CRASH_RUNS", "2"), ("FAKE_STATE", state.to_str().unwrap())]);
    let ok = t.xray(&[]);
    let l = free_port();
    let host = XrayFactory.listen(&spec(&bin, &t, Some(format!("0.0.0.0:{l}")), &[])).await.unwrap();
    assert_eq!(std::fs::read_to_string(&state).unwrap().trim(), "3", "two crashes, third run healthy");
    let client = XrayFactory.dial(&spec(&ok, &t, Some(format!("127.0.0.1:{l}")), &[])).await.unwrap();
    first_frame(&client, va(l), &host, b"after restart").await;
}

#[tokio::test]
async fn crash_loop_gives_up_with_a_typed_error() {
    let t = Tmp::new();
    let bin = t.xray(&[("FAKE_MODE", "crash")]);
    let started = Instant::now();
    let e = failed_with(XrayFactory.listen(&spec(&bin, &t, Some("0.0.0.0:45997".into()), &[("xray_max_restarts", "2")])).await, "exited");
    assert!(matches!(e, CarrierError::Failed(_)));
    let runs = t.runs().iter().filter(|r| r.starts_with("run|-c|")).count();
    assert_eq!(runs, 3, "first start + 2 restarts, then give up");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(t.run_dirs().is_empty(), "config dir removed after failure");
}

#[tokio::test]
async fn slow_start_is_waited_for_and_never_ready_times_out() {
    let t = Tmp::new();
    let slow = t.xray(&[("FAKE_MODE", "slow"), ("FAKE_DELAY_MS", "800")]);
    let l = free_port();
    let h = XrayFactory.listen(&spec(&slow, &t, Some(format!("0.0.0.0:{l}")), &[("xray_start_timeout_ms", "6000")])).await;
    assert!(h.is_ok(), "{:?}", h.err());
    drop(h);
    let never = t.xray(&[("FAKE_MODE", "never_ready")]);
    let t0 = Instant::now();
    failed_with(
        XrayFactory.listen(&spec(&never, &t, Some("0.0.0.0:45996".into()), &[("xray_start_timeout_ms", "300"), ("xray_max_restarts", "1")])).await,
        "never became ready",
    );
    assert!(t0.elapsed() < Duration::from_secs(8));
}

#[tokio::test]
async fn hung_sidecar_is_killed_and_restarted() {
    let t = Tmp::new();
    let state = t.join("state");
    let bin = t.xray(&[("FAKE_MODE", "hang_once"), ("FAKE_STATE", state.to_str().unwrap())]);
    let ok = t.xray(&[]);
    let l = free_port();
    let host = XrayFactory.listen(&spec(&bin, &t, Some(format!("0.0.0.0:{l}")), &[])).await.unwrap();
    let client = XrayFactory.dial(&spec(&ok, &t, Some(format!("127.0.0.1:{l}")), &[])).await.unwrap();
    let t0 = Instant::now();
    loop {
        let runs: u32 = std::fs::read_to_string(&state).unwrap().trim().parse().unwrap();
        if runs >= 2 && host.health() == Health::Ok {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "no restart after the hang (runs={runs})");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    first_frame(&client, va(l), &host, b"after hang").await;
}

// ---------------------------------------------------------------- probe, disclosure, parsing

#[tokio::test]
async fn probe_reports_plain_reasons() {
    let t = Tmp::new();
    let tmo = Duration::from_secs(30);
    let missing = spec(&t.join("nope"), &t, None, &[]);
    let ProbeStatus::Error(m) = XrayFactory.probe(&missing, tmo).await else { panic!() };
    assert!(m.contains("Xray not installed"), "{m}");
    let old = t.xray(&[("FAKE_VERSION", "1.8.24")]);
    let ProbeStatus::Error(m) = XrayFactory.probe(&spec(&old, &t, None, &[]), tmo).await else { panic!() };
    assert!(m.contains("version too old"), "{m}");
    let bin = t.xray(&[]);
    assert_eq!(XrayFactory.probe(&spec(&bin, &t, None, &[]), tmo).await, ProbeStatus::Reachable { rtt_ms: 0 });
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ep = ln.local_addr().unwrap().to_string();
    assert!(matches!(XrayFactory.probe(&spec(&bin, &t, Some(ep.clone()), &[]), tmo).await, ProbeStatus::Reachable { .. }));
    drop(ln);
    let ProbeStatus::Error(m) = XrayFactory.probe(&spec(&bin, &t, Some(ep), &[]), tmo).await else { panic!() };
    assert!(m.contains("nothing is listening"), "{m}");
    let ProbeStatus::Error(m) = XrayFactory.probe(&spec(&bin, &t, Some("host.invalid:443".into()), &[]), tmo).await else { panic!() };
    assert!(m.contains("resolve") || m.contains("connect"), "{m}");
}

#[test]
fn disclosure_is_honest() {
    let d = XrayFactory.disclosure();
    let all = format!("{:?} {:?} {} {}", d.shared, d.not_shared, d.why, d.operator);
    for w in ["imitates a real website", "extra program (Xray)", "payload", "keys", "mixed", "no guarantee", "None"] {
        assert!(all.contains(w), "missing {w:?}");
    }
    assert_eq!(XrayFactory.id(), CarrierId::Xray);
}

#[test]
fn version_parsing() {
    assert_eq!(parse_version("Xray 26.10.31 (Xray, Penetrates Everything.) abc (go1.27.3 linux/amd64)"), Some((26, 10, 31)));
    assert_eq!(parse_version("banner\nXray 1.8.24 (x)\n"), Some((1, 8, 24)));
    assert_eq!(parse_version("sing-box 1.14.4"), None);
    assert_eq!(parse_version("Xray dev"), None);
    assert_eq!(parse_version(""), None);
}

#[test]
fn no_secret_is_ever_logged() {
    // Runs real listen/dial (log lines are produced) and then scans every captured log line.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let t = Tmp::new();
        let bin = t.xray(&[("FAKE_TEST_FAIL", "1")]);
        let _ = XrayFactory.listen(&spec(&bin, &t, Some("0.0.0.0:45995".into()), &[])).await;
        let bin = t.xray(&[]);
        let (_h, _c, _) = pair(&t, &bin, &[]).await;
    });
    let logs = LOGS.lock().unwrap().join("\n");
    assert!(logs.contains("starting sidecar"), "the test is only meaningful if something was logged");
    for k in [KEY, KEY2] {
        let s = Secrets::derive(&hex16(k));
        for sec in s.redact_list() {
            assert!(!logs.contains(&sec), "secret leaked into logs");
        }
    }
    assert_eq!(format!("{:?}", Secrets::derive(&hex16(KEY))), "Secrets(<redacted>)");
}

// ---------------------------------------------------------------- config generators

fn hex16(s: &str) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn b64url_dec(s: &str) -> Vec<u8> {
    let a = |c: u8| b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".iter().position(|x| *x == c).unwrap() as u32;
    let mut out = Vec::new();
    for c in s.as_bytes().chunks(4) {
        let n = c.iter().enumerate().fold(0u32, |n, (i, &ch)| n | a(ch) << (18 - 6 * i));
        for i in 0..c.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn host_params() -> XrayParams {
    XrayParams { server_name: SNI.into(), log_file: Some("/run/strait/xray.log".into()), ..XrayParams::default() }
}
fn client_params() -> XrayParams {
    XrayParams { server_addr: "203.0.113.7".into(), ..host_params() }
}
fn secrets() -> Secrets {
    Secrets::derive(&hex16(KEY))
}

fn golden(name: &str, v: &Value) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/xray").join(name);
    let text = serde_json::to_string_pretty(v).unwrap() + "\n";
    if std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {name}; run with UPDATE_GOLDEN=1"));
    assert_eq!(text, want, "golden {name} differs (UPDATE_GOLDEN=1 regenerates)");
}

#[test]
fn golden_host() {
    golden("host.json", &host_config(&host_params(), &secrets()).unwrap());
}
#[test]
fn golden_client() {
    golden("client.json", &client_config(&client_params(), &secrets()).unwrap());
}
#[test]
fn golden_client_xudp_stream_one() {
    golden("client_xudp.json", &client_config(&XrayParams { xudp: true, mode: XhttpMode::StreamOne, ..client_params() }, &secrets()).unwrap());
}

#[test]
fn derivation_is_deterministic_and_per_invite() {
    let (a, a2, b) = (Secrets::derive(&hex16(KEY)), Secrets::derive(&hex16(KEY)), Secrets::derive(&hex16(KEY2)));
    assert_eq!(a.redact_list(), a2.redact_list());
    for (x, y) in a.redact_list().iter().zip(b.redact_list()) {
        assert_ne!(*x, y, "every derived value differs between invites");
    }
    let (ha, hb) = (host_config(&host_params(), &a).unwrap(), host_config(&host_params(), &b).unwrap());
    assert_ne!(ha, hb);
    assert_eq!(a.short_id.len(), 16);
    assert!(a.path.starts_with('/') && uuid::Uuid::parse_str(&a.uuid).is_ok());
    // public key is the x25519 public of the private key
    let sk: [u8; 32] = b64url_dec(&a.private_key).try_into().unwrap();
    let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk));
    assert_eq!(b64url_dec(&a.public_key), pk.as_bytes());
    // host and client agree on every shared secret
    let (h, c) = (host_config(&host_params(), &a).unwrap(), client_config(&client_params(), &a).unwrap());
    let (hs, cs) = (&h["inbounds"][0]["streamSettings"], &c["outbounds"][0]["streamSettings"]);
    assert_eq!(hs["xhttpSettings"]["path"], cs["xhttpSettings"]["path"]);
    assert_eq!(hs["realitySettings"]["shortIds"][0], cs["realitySettings"]["shortId"]);
    assert_eq!(h["inbounds"][0]["settings"]["clients"][0]["id"], c["outbounds"][0]["settings"]["id"]);
    assert_eq!(cs["realitySettings"]["publicKey"], a.public_key);
}

#[test]
fn generated_configs_avoid_everything_on_the_avoid_list() {
    let s = secrets();
    let host = host_config(&host_params(), &s).unwrap();
    let c1 = client_config(&client_params(), &s).unwrap();
    let c2 = client_config(&XrayParams { xudp: true, ..client_params() }, &s).unwrap();
    for (cfg, role) in [(&host, Role::Host), (&c1, Role::Client), (&c2, Role::Client)] {
        let text = cfg.to_string();
        assert!(!text.contains("xtls-rprx-vision") && !text.to_lowercase().contains("vision"));
        for bad in ["api", "stats", "dns", "policy", "reverse", "metrics", "fakedns", "observatory"] {
            assert!(cfg.get(bad).is_none(), "{bad}");
        }
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 1, "no extra inbounds");
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 1);
        assert!(violations(cfg, role).is_none());
        assert_eq!(cfg["log"]["loglevel"], "warning");
        assert_eq!(cfg["log"]["access"], "none");
    }
    // host: pinned destination, sniffing off, nothing but the one rule
    assert_eq!(host["outbounds"][0]["settings"][N.freedom_redirect], "127.0.0.1:7100");
    assert_eq!(host["outbounds"][0]["protocol"], "freedom");
    assert_eq!(host["inbounds"][0]["sniffing"]["enabled"], false);
    assert_eq!(host["routing"]["rules"].as_array().unwrap().len(), 1);
    assert_eq!(host["routing"]["rules"][0], json!({"inboundTag": ["in-reality"], "outboundTag": "to-strait"}));
    assert_eq!(host["inbounds"][0]["settings"]["clients"][0]["flow"], "");
    let r = &host["inbounds"][0]["streamSettings"]["realitySettings"];
    assert_eq!(r[N.reality_target], "127.0.0.1:8443");
    assert!(!r["serverNames"].as_array().unwrap().is_empty());
    // client: loopback UDP inbound, no mux unless XUDP, and then never TCP mux.cool
    assert_eq!(c1["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(c1["inbounds"][0]["settings"][N.tunnel_network], "udp");
    assert!(c1["outbounds"][0].get(N.mux).is_none());
    assert_eq!(c2["outbounds"][0][N.mux][N.mux_concurrency], -1);
    assert_eq!(c1["outbounds"][0]["streamSettings"]["xhttpSettings"][N.xhttp_mode], "packet-up", "packet-up is the default");
    assert_eq!(c1["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"], "firefox");
    // every U-flagged name from the table appears in some generated config, and the table lists them
    let all = format!("{host}{c1}{c2}");
    for n in [N.log_error, N.freedom_redirect, N.freedom_final_rules, N.reality_target, N.xhttp_mode, N.tunnel_proto, N.tunnel_network, N.tunnel_addr, N.tunnel_port, N.mux, N.mux_concurrency, N.mux_xudp, N.mux_udp443, N.vless_encryption] {
        assert!(all.contains(&format!("\"{n}\"")) || n == N.tunnel_proto, "{n}");
    }
    assert!(xray_config::verified().len() >= 8);
    assert_eq!(host["outbounds"][0]["settings"][N.freedom_final_rules], json!([{"action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": "7100"}, {"action": "block"}]));
}

#[test]
fn audit_catches_each_avoid_list_item() {
    let s = secrets();
    let host = host_config(&host_params(), &s).unwrap();
    let client = client_config(&client_params(), &s).unwrap();
    let cases: Vec<(&str, Role, Box<dyn Fn(&mut Value)>)> = vec![
        ("vision", Role::Host, Box::new(|v| v["inbounds"][0]["settings"]["clients"][0]["flow"] = json!("xtls-rprx-vision"))),
        ("vision", Role::Client, Box::new(|v| v["outbounds"][0]["settings"]["flow"] = json!("xtls-rprx-vision"))),
        ("mux", Role::Client, Box::new(|v| v["outbounds"][0][N.mux] = json!({"enabled": true, "concurrency": 8}))),
        ("extra inbound", Role::Host, Box::new(|v| v["inbounds"].as_array_mut().unwrap().push(json!({"protocol": "socks", "port": 1080})))),
        ("extra inbound", Role::Client, Box::new(|v| v["inbounds"].as_array_mut().unwrap().push(json!({"protocol": "http", "port": 8080})))),
        ("open proxy", Role::Host, Box::new(|v| v["outbounds"][0]["settings"][N.freedom_redirect] = json!("8.8.8.8:53"))),
        ("open proxy", Role::Host, Box::new(|v| v["outbounds"][0]["settings"][N.freedom_redirect] = json!("127.0.0.1:7100@evil"))),
        ("open proxy", Role::Host, Box::new(|v| v["outbounds"][0]["settings"].as_object_mut().unwrap().clear())),
        ("rules missing", Role::Host, Box::new(|v| { v["outbounds"][0]["settings"].as_object_mut().unwrap().remove(N.freedom_final_rules); })),
        ("rules wider", Role::Host, Box::new(|v| v["outbounds"][0]["settings"][N.freedom_final_rules][0]["ip"] = json!(["127.0.0.1", "10.0.0.0/8"]))),
        ("rules no catch-all", Role::Host, Box::new(|v| { v["outbounds"][0]["settings"][N.freedom_final_rules].as_array_mut().unwrap().pop(); })),
        ("rules other port", Role::Host, Box::new(|v| v["outbounds"][0]["settings"][N.freedom_final_rules][0]["port"] = json!("1-65535"))),
        ("api", Role::Host, Box::new(|v| v["api"] = json!({"tag": "api", "services": ["StatsService"]}))),
        ("stats", Role::Host, Box::new(|v| v["stats"] = json!({}))),
        ("dns", Role::Client, Box::new(|v| v["dns"] = json!({"servers": ["1.1.1.1"]}))),
        ("routing", Role::Host, Box::new(|v| v["routing"]["rules"][0]["ip"] = json!(["0.0.0.0/0"]))),
        ("routing", Role::Host, Box::new(|v| v["routing"]["rules"][0]["outboundTag"] = json!("direct"))),
        ("sniffing", Role::Host, Box::new(|v| v["inbounds"][0]["sniffing"]["enabled"] = json!(true))),
        ("serverNames", Role::Host, Box::new(|v| v["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] = json!([]))),
        ("target", Role::Host, Box::new(|v| v["inbounds"][0]["streamSettings"]["realitySettings"][N.reality_target] = json!("https://example.org:443"))),
        ("client listen", Role::Client, Box::new(|v| v["inbounds"][0]["listen"] = json!("0.0.0.0"))),
        ("second outbound", Role::Host, Box::new(|v| v["outbounds"].as_array_mut().unwrap().push(json!({"protocol": "freedom"})))),
    ];
    for (name, role, f) in cases {
        let mut v = if role == Role::Host { host.clone() } else { client.clone() };
        f(&mut v);
        assert!(violations(&v, role).is_some(), "audit missed: {name}");
    }
    // generators refuse bad params
    assert!(host_config(&XrayParams { server_name: "".into(), ..host_params() }, &s).is_err());
    assert!(host_config(&XrayParams { target: "https://x.org".into(), ..host_params() }, &s).is_err());
    assert!(client_config(&XrayParams { server_addr: "".into(), ..client_params() }, &s).is_err());
}

#[tokio::test]
async fn reality_target_must_answer_and_be_well_formed() {
    let t = Tmp::new();
    let bin = t.xray(&[]);
    let ep = || Some("0.0.0.0:45994".to_string());
    // a closed local port: explicit, loud failure naming the setting (nothing is started)
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    failed_with(XrayFactory.listen(&spec(&bin, &t, ep(), &[("xray_target", dead.as_str())])).await, "not reachable");
    failed_with(XrayFactory.listen(&spec(&bin, &t, ep(), &[("xray_target", "https://x.example:443")])).await, "invalid REALITY target");
    assert!(t.runs().iter().all(|r| !r.starts_with("run|-c|")), "must not start with a dead target");
}
