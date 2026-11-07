//! ntfy backend against a fake ntfy server (HTTP/1.1 over loopback, plus one TLS test). No real network.
#![cfg(feature = "rv-ntfy")]
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat_tunnel::rendezvous::derive::{seal, seal_at, Derived};
use nat_tunnel::rendezvous::ntfy::{Ntfy, Timing};
use nat_tunnel::rendezvous::{Candidate, ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const KEY: [u8; 16] = [0x5c; 16];
const HOST: &str = "198.51.100.1:4000";
const CLIENT: &str = "198.51.100.2:5000";

fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            o.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    o
}

#[derive(Default)]
struct Inner {
    msgs: HashMap<String, Vec<(u64, u64, String)>>, // topic -> (seq, unix time, body)
    subs: HashMap<String, Vec<mpsc::UnboundedSender<String>>>,
    seq: u64,
    posts: Vec<Instant>,
    gets: usize,
    health: usize,
    post_overrides: VecDeque<(u16, Option<u64>)>,
    all_status: Option<u16>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Inner>>);

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

impl Fake {
    async fn start(&self) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let me = me.clone();
                tokio::spawn(async move { me.handle(s).await });
            }
        });
        a
    }
    fn store(&self, topic: &str, body: &str) {
        let mut g = self.0.lock().unwrap();
        g.seq += 1;
        let (seq, t) = (g.seq, now());
        g.msgs.entry(topic.into()).or_default().push((seq, t, body.into()));
        let line = msg_line(seq, t, topic, body);
        g.subs.entry(topic.into()).or_default().retain(|s| s.send(line.clone()).is_ok());
    }
    /// Drop every open stream (server side closes the sockets).
    fn kick(&self) {
        self.0.lock().unwrap().subs.clear();
    }
    fn posts(&self) -> Vec<Instant> {
        self.0.lock().unwrap().posts.clone()
    }
    async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(&self, s: S) {
        let mut r = BufReader::new(s);
        let mut line = String::new();
        if r.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let mut p = line.split_whitespace();
        let (method, target) = (p.next().unwrap().to_string(), p.next().unwrap().to_string());
        let mut len = 0usize;
        let mut ua = String::new();
        loop {
            line.clear();
            r.read_line(&mut line).await.unwrap_or(0);
            let l = line.trim();
            if l.is_empty() {
                break;
            }
            let l = l.to_ascii_lowercase();
            if let Some(v) = l.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
            if let Some(v) = l.strip_prefix("user-agent:") {
                ua = v.trim().to_string();
            }
        }
        assert_eq!(ua, "mozilla/5.0"); // generic on purpose: nothing names the product
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await.unwrap();
        let body = String::from_utf8(body).unwrap();
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let status_only = |code: u16, ra: Option<u64>| {
            let ra = ra.map(|v| format!("Retry-After: {v}\r\n")).unwrap_or_default();
            format!("HTTP/1.1 {code} X\r\n{ra}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}")
        };
        if path == "/v1/health" {
            let (st, h) = {
                let mut g = self.0.lock().unwrap();
                g.health += 1;
                (g.all_status, ())
            };
            let _ = h;
            let resp = match st {
                Some(c) => status_only(c, None),
                None => {
                    let b = r#"{"healthy":true,"role":"active"}"#;
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                }
            };
            let _ = r.write_all(resp.as_bytes()).await;
            return;
        }
        let topic = path.trim_start_matches('/').trim_end_matches("/json").to_string();
        let forced = self.0.lock().unwrap().all_status;
        if let Some(c) = forced {
            let _ = r.write_all(status_only(c, None).as_bytes()).await;
            return;
        }
        if method == "POST" {
            let ov = {
                let mut g = self.0.lock().unwrap();
                g.posts.push(Instant::now());
                g.post_overrides.pop_front()
            };
            if let Some((c, ra)) = ov {
                let _ = r.write_all(status_only(c, ra).as_bytes()).await;
                return;
            }
            self.store(&topic, &body);
            let _ = r.write_all(status_only(200, None).as_bytes()).await;
            return;
        }
        // GET /<topic>/json?since=..
        let since = query.split('&').find_map(|kv| kv.strip_prefix("since=")).unwrap_or("all").to_string();
        let (mut rx, replay) = {
            let mut g = self.0.lock().unwrap();
            g.gets += 1;
            let (tx, rx) = mpsc::unbounded_channel();
            g.subs.entry(topic.clone()).or_default().push(tx);
            let all = g.msgs.get(&topic).cloned().unwrap_or_default();
            let t = now();
            let replay: Vec<String> = all
                .into_iter()
                .filter(|(seq, tm, _)| {
                    if let Some(m) = since.strip_suffix('m') {
                        *tm + m.parse::<u64>().unwrap_or(0) * 60 >= t
                    } else if let Some(id) = since.strip_prefix('m') {
                        *seq > id.parse::<u64>().unwrap_or(0)
                    } else {
                        true
                    }
                })
                .map(|(seq, tm, b)| msg_line(seq, tm, &topic, &b))
                .collect();
            (rx, replay)
        };
        let chunk = |s: &str| format!("{:x}\r\n{s}\r\n", s.len());
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let _ = r.write_all(head.as_bytes()).await;
        let open = format!("{{\"id\":\"o\",\"time\":{},\"event\":\"open\",\"topic\":\"{topic}\"}}\n", now());
        let _ = r.write_all(chunk(&open).as_bytes()).await;
        for l in replay {
            let _ = r.write_all(chunk(&l).as_bytes()).await;
        }
        while let Some(l) = rx.recv().await {
            if r.write_all(chunk(&l).as_bytes()).await.is_err() {
                return;
            }
        }
        // sender dropped (kick): abrupt close, no terminating chunk
    }
}

fn msg_line(seq: u64, t: u64, topic: &str, body: &str) -> String {
    format!("{{\"id\":\"m{seq}\",\"time\":{t},\"event\":\"message\",\"topic\":\"{topic}\",\"message\":\"{body}\"}}\n")
}

fn topic() -> String {
    Derived::new(&KEY).ntfy_topic()
}
fn ctx(role: Role) -> RvCtx {
    RvCtx::new(KEY, role, vec![if role == Role::Host { HOST } else { CLIENT }.parse().unwrap()])
}
fn quick() -> Timing {
    Timing {
        fast: Duration::from_millis(200),
        slow: Duration::from_millis(400),
        fast_for: Duration::from_secs(5),
        reconnect: Duration::from_millis(100),
        idle: Duration::from_secs(5),
        io: Duration::from_secs(3),
    }
}
fn ntfy(base: &str) -> Arc<Ntfy> {
    Arc::new(Ntfy::new(&RvConfig { ntfy_base: Some(base.into()), ..Default::default() }).with_timing(quick()))
}

struct Running {
    rx: mpsc::Receiver<Candidate>,
    cancel: CancellationToken,
    join: tokio::task::JoinHandle<Result<(), RvError>>,
}
fn spawn(n: Arc<Ntfy>, c: RvCtx) -> Running {
    let (tx, rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let cc = cancel.clone();
    let join = tokio::spawn(async move { n.run(c, tx, cc).await });
    Running { rx, cancel, join }
}
async fn first(r: &mut Running, secs: u64) -> Option<Candidate> {
    timeout(Duration::from_secs(secs), r.rx.recv()).await.ok().flatten()
}
async fn stop(r: Running) {
    r.cancel.cancel();
    assert_eq!(timeout(Duration::from_secs(1), r.join).await.expect("returns within 1 s").unwrap(), Ok(()));
}

#[tokio::test]
async fn host_and_client_find_each_other_and_ignore_own() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    let mut h = spawn(ntfy(&base), ctx(Role::Host));
    let mut c = spawn(ntfy(&base), ctx(Role::Client));
    let hc = first(&mut h, 5).await.expect("host got client");
    let cc = first(&mut c, 5).await.expect("client got host");
    assert_eq!((hc.addr, hc.via), (CLIENT.parse().unwrap(), "ntfy"));
    assert_eq!(cc.addr, HOST.parse::<SocketAddr>().unwrap());
    // keeps publishing; own blobs never come back as candidates
    assert!(first(&mut h, 1).await.is_none() && first(&mut c, 0).await.is_none());
    stop(h).await;
    stop(c).await;
}

#[tokio::test]
async fn late_joiner_gets_cached_message() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    let h = spawn(ntfy(&base), ctx(Role::Host));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut c = spawn(ntfy(&base), ctx(Role::Client));
    assert_eq!(first(&mut c, 5).await.unwrap().addr, HOST.parse::<SocketAddr>().unwrap());
    stop(h).await;
    stop(c).await;
}

#[tokio::test]
async fn tampered_old_and_foreign_blobs_ignored() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    let d = Derived::new(&KEY);
    let host_addr: SocketAddr = HOST.parse().unwrap();
    let good = seal(&d, Role::Host, &[host_addr]).unwrap();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let old = seal_at(&d, Role::Host, &["203.0.113.9:1".parse().unwrap()], now() - 600, [7; 12]).unwrap();
    let foreign = seal(&Derived::new(&[1; 16]), Role::Host, &["203.0.113.8:1".parse().unwrap()]).unwrap();
    for body in [b64(&bad), b64(&old), b64(&foreign), "not base64 !!".into(), String::new()] {
        f.store(&topic(), &body);
    }
    let mut c = spawn(ntfy(&base), ctx(Role::Client));
    assert!(first(&mut c, 1).await.is_none(), "nothing valid yet");
    f.store(&topic(), &b64(&good));
    assert_eq!(first(&mut c, 3).await.unwrap().addr, host_addr);
    assert!(first(&mut c, 1).await.is_none());
    stop(c).await;
}

#[tokio::test]
async fn http_429_backs_off_and_respects_rate() {
    let f = Fake::default();
    f.0.lock().unwrap().post_overrides = VecDeque::from([(429, Some(1))]);
    let base = format!("http://{}", f.start().await);
    let h = spawn(ntfy(&base), ctx(Role::Host));
    tokio::time::sleep(Duration::from_millis(2600)).await;
    stop(h).await;
    let p = f.posts();
    assert!(p.len() >= 3, "{} posts", p.len());
    assert!(p[1] - p[0] >= Duration::from_millis(990), "Retry-After 1 s honoured: {:?}", p[1] - p[0]);
    for w in p.windows(2) {
        assert!(w[1] - w[0] >= Duration::from_millis(190), "publish rate: {:?}", w[1] - w[0]);
    }
}

#[tokio::test]
async fn repeated_429_blocks() {
    let f = Fake::default();
    f.0.lock().unwrap().post_overrides = VecDeque::from([(429, Some(1)); 5]);
    let base = format!("http://{}", f.start().await);
    let h = spawn(ntfy(&base), ctx(Role::Host));
    let r = timeout(Duration::from_secs(6), h.join).await.unwrap().unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");
    assert_eq!(f.posts().len(), 3, "stops publishing after the third 429");
}

#[tokio::test]
async fn http_403_is_blocked_and_500_is_failed() {
    let f = Fake::default();
    f.0.lock().unwrap().all_status = Some(403);
    let base = format!("http://{}", f.start().await);
    let h = spawn(ntfy(&base), ctx(Role::Host));
    let r = timeout(Duration::from_secs(3), h.join).await.unwrap().unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");

    let f = Fake::default();
    f.0.lock().unwrap().all_status = Some(500);
    let base = format!("http://{}", f.start().await);
    let h = spawn(ntfy(&base), ctx(Role::Host));
    let r = timeout(Duration::from_secs(3), h.join).await.unwrap().unwrap();
    assert!(matches!(r, Err(RvError::Failed(_))), "{r:?}");
}

#[tokio::test]
async fn server_down_is_blocked() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    let h = spawn(ntfy(&format!("http://{a}")), ctx(Role::Host));
    let r = timeout(Duration::from_secs(3), h.join).await.unwrap().unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");
    assert!(matches!(ntfy(&format!("http://{a}")).probe(Duration::from_secs(2)).await, ProbeStatus::Blocked(_)));
}

#[tokio::test]
async fn stream_drop_reconnects_and_resumes() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    let mut c = spawn(ntfy(&base), ctx(Role::Client));
    tokio::time::sleep(Duration::from_millis(700)).await; // stream open and survived > 5x reconnect
    let gets = f.0.lock().unwrap().gets;
    f.kick();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(f.0.lock().unwrap().gets > gets, "re-subscribed");
    let good = seal(&Derived::new(&KEY), Role::Host, &[HOST.parse().unwrap()]).unwrap();
    f.store(&topic(), &b64(&good));
    assert_eq!(first(&mut c, 3).await.unwrap().addr, HOST.parse::<SocketAddr>().unwrap());
    stop(c).await;
}

#[tokio::test]
async fn cancel_is_prompt() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    let c = spawn(ntfy(&base), ctx(Role::Client));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t = Instant::now();
    stop(c).await;
    assert!(t.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn probe_publishes_nothing() {
    let f = Fake::default();
    let base = format!("http://{}", f.start().await);
    assert!(matches!(ntfy(&base).probe(Duration::from_secs(2)).await, ProbeStatus::Reachable { .. }));
    {
        let g = f.0.lock().unwrap();
        assert_eq!((g.posts.len(), g.gets, g.health, g.seq), (0, 0, 1, 0));
    }
    f.0.lock().unwrap().all_status = Some(451);
    assert!(matches!(ntfy(&base).probe(Duration::from_secs(2)).await, ProbeStatus::Blocked(_)));
    f.0.lock().unwrap().all_status = Some(500);
    assert!(matches!(ntfy(&base).probe(Duration::from_secs(2)).await, ProbeStatus::Error(_)));
}

#[test]
fn disclosure_is_honest() {
    let d = ntfy("http://x").disclosure();
    assert!(d.shared[0].contains("IP address") && d.shared[0].contains("logs"));
    assert_eq!(d.not_shared.len(), 3);
}

/// TLS path: self-signed cert made with the `openssl` CLI, trusted through the test-only hook.
#[tokio::test]
async fn tls_path_works() {
    let dir = std::env::temp_dir().join(format!("rv_ntfy_tls_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sh = |args: &[&str]| std::process::Command::new("openssl").args(args).current_dir(&dir).output();
    let ok = sh(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE"])
        .map(|o| o.status.success())
        .unwrap_or(false)
        && sh(&["x509", "-in", "c.pem", "-outform", "DER", "-out", "c.der"]).map(|o| o.status.success()).unwrap_or(false)
        && sh(&["pkcs8", "-topk8", "-nocrypt", "-in", "k.pem", "-outform", "DER", "-out", "k.der"]).map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("openssl CLI unavailable: TLS test skipped (UNVERIFIED)");
        return;
    }
    let (cert, key) = (std::fs::read(dir.join("c.der")).unwrap(), std::fs::read(dir.join("k.der")).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let f = Fake::default();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let f2 = f.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let (acc, f) = (acc.clone(), f2.clone());
            tokio::spawn(async move {
                if let Ok(s) = acc.accept(s).await {
                    f.handle(s).await
                }
            });
        }
    });
    let base = format!("https://localhost:{port}");
    let mk = || Arc::new(Ntfy::new(&RvConfig { ntfy_base: Some(base.clone()), ..Default::default() }).with_timing(quick()).with_extra_root(cert.clone()));
    let pr = mk().probe(Duration::from_secs(3)).await;
    assert!(matches!(pr, ProbeStatus::Reachable { .. }), "{pr:?}");
    let mut h = spawn(mk(), ctx(Role::Host));
    let mut c = spawn(mk(), ctx(Role::Client));
    assert_eq!(first(&mut h, 5).await.unwrap().addr, CLIENT.parse::<SocketAddr>().unwrap());
    assert_eq!(first(&mut c, 5).await.unwrap().addr, HOST.parse::<SocketAddr>().unwrap());
    stop(h).await;
    stop(c).await;
    // an untrusted cert must be refused (Blocked)
    let plain = Ntfy::new(&RvConfig { ntfy_base: Some(base.clone()), ..Default::default() }).with_timing(quick());
    assert!(matches!(plain.probe(Duration::from_secs(3)).await, ProbeStatus::Blocked(_)));
}
