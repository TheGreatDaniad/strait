//! `mqtt` rendezvous against an in-test fake MQTT 3.1.1 broker (plain TCP; the TLS path is only
//! exercised by the #[ignore] live test in rv_mqtt_live.rs).
#![cfg(feature = "rv-mqtt")]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nat_tunnel::rendezvous::derive::{seal, seal_at, Derived};
use nat_tunnel::rendezvous::mqtt::{Mqtt, Tuning};
use nat_tunnel::rendezvous::{Candidate, ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError, Status, StatusSink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

// ---------- fake broker ----------

#[derive(Default)]
struct St {
    subs: Mutex<Vec<(String, mpsc::UnboundedSender<Vec<u8>>)>>,
    connects: AtomicUsize,
    subscribes: AtomicUsize,
    publishes: AtomicUsize,
    disconnects: AtomicUsize,
    max_payload: AtomicUsize,
    retained: AtomicBool,
    refuse: AtomicBool,
    topics: Mutex<Vec<String>>,
}

struct Fake {
    addr: SocketAddr,
    st: Arc<St>,
    kick: broadcast::Sender<()>,
}

fn pkt(first: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![first];
    let mut n = body.len();
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        v.push(b);
        if n == 0 {
            break;
        }
    }
    v.extend_from_slice(body);
    v
}

async fn rd(r: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<(u8, Vec<u8>)> {
    let h = r.read_u8().await?;
    let (mut n, mut m) = (0usize, 1usize);
    loop {
        let b = r.read_u8().await?;
        n += (b & 127) as usize * m;
        if b & 128 == 0 {
            break;
        }
        m *= 128;
    }
    let mut body = vec![0; n];
    r.read_exact(&mut body).await?;
    Ok((h, body))
}

impl St {
    fn fanout(&self, topic: &str, payload: &[u8]) {
        let mut b = (topic.len() as u16).to_be_bytes().to_vec();
        b.extend_from_slice(topic.as_bytes());
        b.extend_from_slice(payload);
        let p = pkt(0x30, &b);
        for (t, tx) in self.subs.lock().unwrap().iter() {
            if t == topic {
                let _ = tx.send(p.clone());
            }
        }
    }
}

impl Fake {
    async fn start() -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let st = Arc::new(St::default());
        let (kick, _) = broadcast::channel(4);
        let (st2, kick2) = (st.clone(), kick.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(conn(s, st2.clone(), kick2.subscribe()));
            }
        });
        Fake { addr, st, kick }
    }
    fn url(&self) -> String {
        format!("tcp://{}", self.addr)
    }
    fn drop_conns(&self) {
        let _ = self.kick.send(());
        self.st.subs.lock().unwrap().clear();
    }
    fn inject(&self, topic: &str, payload: &[u8]) {
        self.st.fanout(topic, payload);
    }
}

async fn conn(s: TcpStream, st: Arc<St>, mut kick: broadcast::Receiver<()>) {
    let (mut r, mut w) = s.into_split();
    let (ptx, mut prx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(p) = rd(&mut r).await {
            if ptx.send(p).is_err() {
                break;
            }
        }
    });
    let (otx, mut orx) = mpsc::unbounded_channel::<Vec<u8>>();
    loop {
        tokio::select! {
            _ = kick.recv() => return,
            Some(o) = orx.recv() => { if w.write_all(&o).await.is_err() { return } }
            p = prx.recv() => {
                let Some((h, body)) = p else { return };
                match h >> 4 {
                    1 => {
                        st.connects.fetch_add(1, SeqCst);
                        let code = if st.refuse.load(SeqCst) { 5 } else { 0 };
                        let _ = w.write_all(&[0x20, 2, 0, code]).await;
                    }
                    8 => {
                        st.subscribes.fetch_add(1, SeqCst);
                        let tl = u16::from_be_bytes([body[2], body[3]]) as usize;
                        let topic = String::from_utf8(body[4..4 + tl].to_vec()).unwrap();
                        st.topics.lock().unwrap().push(topic.clone());
                        st.subs.lock().unwrap().push((topic, otx.clone()));
                        let _ = w.write_all(&[0x90, 3, body[0], body[1], 0]).await;
                    }
                    3 => {
                        st.publishes.fetch_add(1, SeqCst);
                        if h & 1 != 0 { st.retained.store(true, SeqCst) }
                        let tl = u16::from_be_bytes([body[0], body[1]]) as usize;
                        let topic = String::from_utf8(body[2..2 + tl].to_vec()).unwrap();
                        let payload = &body[2 + tl..];
                        st.max_payload.fetch_max(payload.len(), SeqCst);
                        st.fanout(&topic, payload);
                    }
                    12 => { let _ = w.write_all(&[0xD0, 0]).await; }
                    14 => { st.disconnects.fetch_add(1, SeqCst); return }
                    _ => {}
                }
            }
        }
    }
}

// ---------- helpers ----------

fn fast() -> Tuning {
    Tuning {
        pub_fast: Duration::from_millis(100),
        fast_window: Duration::from_secs(60),
        pub_slow: Duration::from_millis(100),
        min_gap: Duration::from_millis(20),
        backoff_base: Duration::from_millis(40),
        max_fails: 3,
        connect_timeout: Duration::from_secs(2),
        ..Tuning::default()
    }
}

fn backend(urls: &[String], t: Tuning) -> Arc<Mqtt> {
    Arc::new(Mqtt::with_tuning(&RvConfig { mqtt_broker: Some(urls.join(",")), ..Default::default() }, t))
}

const KEY: [u8; 16] = [7; 16];

fn ctx(role: Role, key: [u8; 16], addr: &str) -> RvCtx {
    RvCtx::new(key, role, vec![addr.parse().unwrap()])
}

fn topic_of(key: [u8; 16]) -> String {
    format!("strait/{}", Derived::new(&key).room_topic())
}

struct Peer {
    rx: mpsc::Receiver<Candidate>,
    cancel: CancellationToken,
    h: tokio::task::JoinHandle<Result<(), RvError>>,
}

fn spawn(b: &Arc<Mqtt>, c: RvCtx) -> Peer {
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (b, cc) = (b.clone(), cancel.clone());
    Peer { rx, cancel, h: tokio::spawn(async move { b.run(c, tx, cc).await }) }
}

impl Peer {
    async fn got(&mut self) -> Candidate {
        timeout(Duration::from_secs(5), self.rx.recv()).await.expect("no candidate in 5 s").unwrap()
    }
    async fn nothing_for(&mut self, ms: u64) {
        assert!(timeout(Duration::from_millis(ms), self.rx.recv()).await.is_err(), "unexpected candidate");
    }
    async fn stop(self) -> Result<(), RvError> {
        self.cancel.cancel();
        timeout(Duration::from_secs(1), self.h).await.expect("run did not stop within 1 s").unwrap()
    }
}

async fn dead_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    format!("tcp://{a}")
}

async fn wait_for(f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not reached");
}

// ---------- tests ----------

#[tokio::test]
async fn find_each_other_through_one_broker() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let s2 = statuses.clone();
    let mut hc = ctx(Role::Host, KEY, "203.0.113.1:4000");
    hc.status = StatusSink::new(move |s| s2.lock().unwrap().push(s));
    let mut h = spawn(&b, hc);
    let mut c = spawn(&b, ctx(Role::Client, KEY, "203.0.113.2:5000"));
    assert_eq!(h.got().await, Candidate { addr: "203.0.113.2:5000".parse().unwrap(), via: "mqtt" });
    assert_eq!(c.got().await.addr, "203.0.113.1:4000".parse().unwrap());
    // no duplicates despite repeated publishes
    h.nothing_for(400).await;
    assert!(statuses.lock().unwrap().contains(&Status::Publishing));
    assert!(f.st.max_payload.load(SeqCst) > 0 && f.st.max_payload.load(SeqCst) < 256);
    assert!(!f.st.retained.load(SeqCst), "must not use retain");
    assert!(h.stop().await.is_ok() && c.stop().await.is_ok());
}

#[tokio::test]
async fn find_each_other_through_two_brokers_one_dead() {
    let (f, dead) = (Fake::start().await, dead_url().await);
    let b = backend(&[dead, f.url()], fast());
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    let mut c = spawn(&b, ctx(Role::Client, KEY, "203.0.113.2:5000"));
    assert_eq!(h.got().await.addr, "203.0.113.2:5000".parse().unwrap());
    assert_eq!(c.got().await.addr, "203.0.113.1:4000".parse().unwrap());
    // the dead broker gave up but the run keeps going on the live one
    sleep(Duration::from_millis(500)).await;
    assert!(h.stop().await.is_ok() && c.stop().await.is_ok());

    // both live: both stay subscribed
    let (f1, f2) = (Fake::start().await, Fake::start().await);
    let b = backend(&[f1.url(), f2.url()], fast());
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    wait_for(|| f1.st.subscribes.load(SeqCst) == 1 && f2.st.subscribes.load(SeqCst) == 1).await;
    let mut c = spawn(&b, ctx(Role::Client, KEY, "203.0.113.2:5000"));
    h.got().await;
    c.got().await;
    h.stop().await.unwrap();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn own_message_ignored() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    wait_for(|| f.st.publishes.load(SeqCst) >= 2).await; // fake echoes them back to us
    h.nothing_for(300).await;
    h.stop().await.unwrap();
}

#[tokio::test]
async fn tampered_and_stale_ignored() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    wait_for(|| f.st.subscribes.load(SeqCst) == 1).await;
    let (d, topic) = (Derived::new(&KEY), topic_of(KEY));
    let peer: SocketAddr = "203.0.113.9:9".parse().unwrap();
    let mut bad = seal(&d, Role::Client, &[peer]).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    f.inject(&topic, &bad);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    f.inject(&topic, &seal_at(&d, Role::Client, &[peer], now - 600, [1; 12]).unwrap());
    f.inject(&topic, b"garbage");
    f.inject(&topic, &seal(&Derived::new(&[9; 16]), Role::Client, &[peer]).unwrap()); // wrong key
    h.nothing_for(300).await;
    let good: SocketAddr = "203.0.113.10:10".parse().unwrap();
    f.inject(&topic, &seal(&d, Role::Client, &[good]).unwrap());
    assert_eq!(h.got().await.addr, good);
    h.stop().await.unwrap();
}

#[tokio::test]
async fn different_room_never_delivers_and_topic_has_no_wildcards() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let key2 = [8u8; 16];
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    let mut c = spawn(&b, ctx(Role::Client, key2, "203.0.113.2:5000"));
    wait_for(|| f.st.publishes.load(SeqCst) >= 4).await;
    h.nothing_for(300).await;
    c.nothing_for(10).await;
    let topics = f.st.topics.lock().unwrap().clone();
    assert!(topics.contains(&topic_of(KEY)) && topics.contains(&topic_of(key2)));
    for t in topics {
        assert!(t.starts_with("strait/strait-") && !t.contains(['#', '+', '$']), "{t}");
    }
    h.stop().await.unwrap();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn reconnects_after_the_broker_drops_the_socket() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let mut h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    wait_for(|| f.st.subscribes.load(SeqCst) == 1).await;
    f.drop_conns();
    wait_for(|| f.st.subscribes.load(SeqCst) == 2).await;
    let mut c = spawn(&b, ctx(Role::Client, KEY, "203.0.113.2:5000"));
    assert_eq!(h.got().await.addr, "203.0.113.2:5000".parse().unwrap());
    assert_eq!(c.got().await.addr, "203.0.113.1:4000".parse().unwrap());
    h.stop().await.unwrap();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn all_dead_is_blocked_and_refusal_is_failed() {
    let b = backend(&[dead_url().await, dead_url().await], fast());
    let (tx, _rx) = mpsc::channel(1);
    let r = timeout(Duration::from_secs(10), b.run(ctx(Role::Host, KEY, "203.0.113.1:4000"), tx, CancellationToken::new())).await.unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");

    let f = Fake::start().await;
    f.st.refuse.store(true, SeqCst);
    let b = backend(&[f.url()], fast());
    let (tx, _rx) = mpsc::channel(1);
    let r = timeout(Duration::from_secs(10), b.run(ctx(Role::Host, KEY, "203.0.113.1:4000"), tx, CancellationToken::new())).await.unwrap();
    assert!(matches!(r, Err(RvError::Failed(_))), "{r:?}");
}

#[tokio::test]
async fn cancel_sends_disconnect() {
    let f = Fake::start().await;
    let b = backend(&[f.url()], fast());
    let h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    wait_for(|| f.st.subscribes.load(SeqCst) == 1).await;
    assert!(h.stop().await.is_ok());
    wait_for(|| f.st.disconnects.load(SeqCst) == 1).await;
}

#[tokio::test]
async fn probe_only_connects() {
    let f = Fake::start().await;
    let b = backend(&[f.url(), dead_url().await], fast());
    let r = b.probe(Duration::from_secs(2)).await;
    assert!(matches!(r, ProbeStatus::Reachable { .. }), "{r:?}");
    wait_for(|| f.st.disconnects.load(SeqCst) == 1).await;
    assert_eq!(f.st.connects.load(SeqCst), 1);
    assert_eq!(f.st.subscribes.load(SeqCst), 0);
    assert_eq!(f.st.publishes.load(SeqCst), 0);
    let b = backend(&[dead_url().await], fast());
    assert!(matches!(b.probe(Duration::from_secs(2)).await, ProbeStatus::Blocked(_)));
}

#[tokio::test]
async fn publish_cap_is_enforced() {
    let f = Fake::start().await;
    let t = Tuning { cap: 3, cap_window: Duration::from_secs(60), ..fast() };
    let b = backend(&[f.url()], t);
    let h = spawn(&b, ctx(Role::Host, KEY, "203.0.113.1:4000"));
    sleep(Duration::from_millis(1200)).await; // would be ~12 publishes uncapped
    assert_eq!(f.st.publishes.load(SeqCst), 3);
    h.stop().await.unwrap();
}

#[tokio::test]
async fn disclosure_flags_test_grade() {
    let d = Mqtt::new(&RvConfig::default()).disclosure();
    assert!(d.operator.contains("testing only") && d.operator.contains("HiveMQ") && d.operator.contains("EMQX"));
    assert_eq!(d.not_shared.len(), 3);
}
