//! `nostr` rendezvous backend against in-test fake relays (plain ws:// on 127.0.0.1, no real network).
//! The fake verifies NIP-01 id + BIP-340 signature, so a pass proves we sign correctly.
#![cfg(feature = "rv-nostr")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use nat_tunnel::rendezvous::derive::{hex, seal, seal_at, Derived};
use nat_tunnel::rendezvous::nostr::Nostr;
use nat_tunnel::rendezvous::{Candidate, ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError, Status, StatusSink};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;

const KEY: [u8; 16] = [0x42; 16];
const HOST: &str = "192.0.2.1:4000";
const CLIENT: &str = "192.0.2.2:4000";

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    /// Delay the WebSocket handshake.
    Slow(Duration),
    /// Answer every EVENT with OK false "rate-limited:".
    Limit,
}

#[derive(Default)]
struct St {
    upgrades: usize,
    reqs: usize,
    bad_sig: usize,
    refused: usize,
    pubs: Vec<Value>,
    rep: HashMap<(String, u64, String), Value>,
}

struct Fake {
    url: String,
    st: Arc<Mutex<St>>,
    bc: broadcast::Sender<Value>,
}

fn dtag(e: &Value) -> String {
    e["tags"].as_array().unwrap().iter().find(|t| t[0] == "d").map(|t| t[1].as_str().unwrap().to_string()).unwrap_or_default()
}

fn verify(e: &Value) -> bool {
    let ser = json!([0, e["pubkey"], e["created_at"], e["kind"], e["tags"], e["content"]]).to_string();
    let id = Sha256::digest(ser.as_bytes());
    if hex(&id) != e["id"].as_str().unwrap_or("") {
        return false;
    }
    let un = |s: &str| -> Option<Vec<u8>> {
        (s.len() % 2 == 0).then(|| (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect())
    };
    let (Some(pk), Some(sig)) = (un(e["pubkey"].as_str().unwrap_or("")), un(e["sig"].as_str().unwrap_or(""))) else { return false };
    let (Ok(pk), Ok(sig)) = (secp256k1::XOnlyPublicKey::from_slice(&pk), secp256k1::schnorr::Signature::from_slice(&sig)) else { return false };
    secp256k1::Secp256k1::verification_only().verify_schnorr(&sig, &secp256k1::Message::from_digest(id.into()), &pk).is_ok()
}

fn matches(f: &Value, e: &Value) -> bool {
    let kind = e["kind"].as_u64().unwrap_or(0);
    f["kinds"].as_array().is_some_and(|k| k.iter().any(|x| x.as_u64() == Some(kind)))
        && e["tags"].as_array().is_some_and(|t| t.iter().any(|t| t[0] == "r" && f["#r"][0] == t[1]))
        && e["created_at"].as_u64().unwrap_or(0) >= f["since"].as_u64().unwrap_or(0)
}

impl Fake {
    async fn start(mode: Mode) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let st = Arc::new(Mutex::new(St::default()));
        let (bc, _) = broadcast::channel(256);
        let (st2, bc2) = (st.clone(), bc.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = l.accept().await else { return };
                tokio::spawn(conn(tcp, st2.clone(), mode, bc2.clone()));
            }
        });
        Fake { url, st, bc }
    }

    /// A URL where nothing listens (connection refused).
    async fn dead() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("ws://{}", l.local_addr().unwrap())
    }

    fn inject(&self, e: Value) {
        if e["kind"].as_u64().unwrap() / 10000 == 3 {
            self.st.lock().unwrap().rep.insert((e["pubkey"].to_string(), 30077, dtag(&e)), e.clone());
        }
        let _ = self.bc.send(e);
    }
    fn pubs(&self) -> usize {
        self.st.lock().unwrap().pubs.len()
    }
    fn kinds(&self) -> Vec<u64> {
        self.st.lock().unwrap().pubs.iter().map(|e| e["kind"].as_u64().unwrap()).collect()
    }
}

async fn conn(tcp: tokio::net::TcpStream, st: Arc<Mutex<St>>, mode: Mode, bc: broadcast::Sender<Value>) {
    if let Mode::Slow(d) = mode {
        tokio::time::sleep(d).await;
    }
    let Ok(ws) = accept_async(tcp).await else { return };
    st.lock().unwrap().upgrades += 1;
    let (mut w, mut r) = ws.split();
    let mut rx = bc.subscribe();
    let mut filt: Option<Value> = None;
    loop {
        tokio::select! {
            m = r.next() => {
                let t = match m {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => continue,
                };
                let v: Value = serde_json::from_str(&t).unwrap();
                match v[0].as_str().unwrap() {
                    "REQ" => {
                        let f = v[2].clone();
                        st.lock().unwrap().reqs += 1;
                        let stored: Vec<Value> = st.lock().unwrap().rep.values().filter(|e| matches(&f, e)).cloned().collect();
                        for e in stored {
                            let _ = w.send(Message::text(json!(["EVENT", v[1], e]).to_string())).await;
                        }
                        let _ = w.send(Message::text(json!(["EOSE", v[1]]).to_string())).await;
                        filt = Some(f);
                    }
                    "EVENT" => {
                        let e = v[1].clone();
                        let id = e["id"].clone();
                        let reply = if !verify(&e) {
                            st.lock().unwrap().bad_sig += 1;
                            json!(["OK", id, false, "invalid: bad id or signature"])
                        } else if matches!(mode, Mode::Limit) {
                            st.lock().unwrap().refused += 1;
                            json!(["OK", id, false, "rate-limited: slow down"])
                        } else {
                            {
                                let mut s = st.lock().unwrap();
                                s.pubs.push(e.clone());
                                if e["kind"].as_u64().unwrap() / 10000 == 3 {
                                    s.rep.insert((e["pubkey"].to_string(), 30077, dtag(&e)), e.clone());
                                }
                            }
                            let _ = bc.send(e);
                            json!(["OK", id, true, ""])
                        };
                        let _ = w.send(Message::text(reply.to_string())).await;
                    }
                    _ => {}
                }
            }
            e = rx.recv() => {
                if let (Ok(e), Some(f)) = (e, &filt) {
                    if matches(f, &e) {
                        let _ = w.send(Message::text(json!(["EVENT", "r", e]).to_string())).await;
                    }
                }
            }
        }
    }
}

struct Side {
    rx: mpsc::Receiver<Candidate>,
    cancel: CancellationToken,
    h: JoinHandle<Result<(), RvError>>,
    status: Arc<Mutex<Vec<String>>>,
}

fn start(role: Role, relays: &[String]) -> Side {
    let local: SocketAddr = if role == Role::Host { HOST } else { CLIENT }.parse().unwrap();
    let status = Arc::new(Mutex::new(Vec::new()));
    let s2 = status.clone();
    let mut ctx = RvCtx::new(KEY, role, vec![local]);
    ctx.status = StatusSink::new(move |s: Status| s2.lock().unwrap().push(format!("{s:?}")));
    let nostr = Nostr::new(&RvConfig { relays: relays.to_vec(), ..Default::default() });
    let (tx, rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let h = tokio::spawn(async move { nostr.run(ctx, tx, c2).await });
    Side { rx, cancel, h, status }
}

impl Side {
    async fn peer(&mut self, secs: u64) -> Candidate {
        timeout(Duration::from_secs(secs), self.rx.recv()).await.expect("no peer candidate in time").unwrap()
    }
    /// Cancel and return how long `run` took to finish.
    async fn stop(self) -> Duration {
        let t = Instant::now();
        self.cancel.cancel();
        assert_eq!(timeout(Duration::from_secs(2), self.h).await.expect("run did not stop").unwrap(), Ok(()));
        t.elapsed()
    }
}

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

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// An (unsigned) event as another publisher would put it on the relay.
fn raw_event(room: &str, kind: u64, blob: &[u8], tag: &str) -> Value {
    json!({"id": "00", "pubkey": "ab", "created_at": now(), "kind": kind, "tags": [["d", "x"], [tag, room]], "content": b64(blob), "sig": "00"})
}

#[tokio::test]
async fn one_relay_both_find_each_other() {
    let f = Fake::start(Mode::Normal).await;
    let mut host = start(Role::Host, &[f.url.clone()]);
    let mut client = start(Role::Client, &[f.url.clone()]);
    let c = client.peer(6).await;
    assert_eq!((c.addr, c.via), (HOST.parse().unwrap(), "nostr"));
    let h = host.peer(6).await;
    assert_eq!((h.addr, h.via), (CLIENT.parse().unwrap(), "nostr"));
    // the fake verified every signature: ours must all be valid, and both kinds were published
    {
        let s = f.st.lock().unwrap();
        assert_eq!(s.bad_sig, 0);
        assert!(s.pubs.iter().all(|e| e["content"].as_str().unwrap().len() < 200));
    }
    assert!(f.kinds().contains(&20077));
    assert!(host.status.lock().unwrap().contains(&"Waiting".to_string()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(host.status.lock().unwrap().contains(&"Publishing".to_string()));
    let (a, b) = (host.stop().await, client.stop().await);
    assert!(a < Duration::from_secs(1) && b < Duration::from_secs(1), "cancel took {a:?} / {b:?}");
}

#[tokio::test]
async fn bad_signature_is_rejected_by_the_fake() {
    // proves the verifier in the fake is not vacuous
    let mut e = json!({"id": "00", "pubkey": "ab", "created_at": 1, "kind": 20077, "tags": [], "content": "", "sig": "00"});
    assert!(!verify(&e));
    e["id"] = json!("zz");
    assert!(!verify(&e));
}

#[tokio::test]
async fn three_relays_with_dead_and_slow_one() {
    let dead = Fake::dead().await;
    let slow = Fake::start(Mode::Slow(Duration::from_secs(3))).await;
    let good = Fake::start(Mode::Normal).await;
    let relays = [dead, slow.url.clone(), good.url.clone()];
    let mut host = start(Role::Host, &relays);
    let mut client = start(Role::Client, &relays);
    assert_eq!(client.peer(6).await.addr, HOST.parse::<SocketAddr>().unwrap());
    assert_eq!(host.peer(6).await.addr, CLIENT.parse::<SocketAddr>().unwrap());
    // the slow relay also works eventually and nobody is told twice
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(slow.pubs() > 0, "slow relay should get events once connected");
    assert!(client.rx.try_recv().is_err(), "duplicate candidate forwarded");
    host.stop().await;
    client.stop().await;
}

#[tokio::test]
async fn rate_limited_relay_gets_one_publish_then_silence() {
    let lim = Fake::start(Mode::Limit).await;
    let good = Fake::start(Mode::Normal).await;
    let relays = [lim.url.clone(), good.url.clone()];
    let mut host = start(Role::Host, &relays);
    let mut client = start(Role::Client, &relays);
    client.peer(6).await;
    host.peer(6).await;
    tokio::time::sleep(Duration::from_secs(7)).await; // > 2 more publish slots
    {
        let s = lim.st.lock().unwrap();
        assert_eq!(s.refused, 2, "one refused event per side, then silence (got {})", s.refused);
        assert_eq!(s.bad_sig, 0);
    }
    assert!(good.pubs() >= 4);
    host.stop().await;
    client.stop().await;
}

#[tokio::test]
async fn late_joiner_gets_the_replaceable_event() {
    let f = Fake::start(Mode::Normal).await;
    let host = start(Role::Host, &[f.url.clone()]);
    // wait until the addressable event is stored (published ~2.5 s in)
    let t = Instant::now();
    while f.st.lock().unwrap().rep.is_empty() {
        assert!(t.elapsed() < Duration::from_secs(8));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let before = f.pubs();
    let mut client = start(Role::Client, &[f.url.clone()]);
    let t = Instant::now();
    let c = client.peer(4).await;
    assert_eq!(c.addr, HOST.parse::<SocketAddr>().unwrap());
    // delivered from the stored event on REQ, not by waiting for the next ephemeral repeat (5 s)
    assert!(t.elapsed() < Duration::from_secs(2), "took {:?} (pubs before {before})", t.elapsed());
    let rep = f.st.lock().unwrap().rep.values().next().unwrap().clone();
    assert_eq!(rep["kind"], 30077);
    assert!(dtag(&rep).ends_with("host"));
    host.stop().await;
    client.stop().await;
}

#[tokio::test]
async fn own_events_are_ignored() {
    let f = Fake::start(Mode::Normal).await;
    let mut host = start(Role::Host, &[f.url.clone()]);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(f.pubs() >= 2);
    assert!(host.rx.try_recv().is_err());
    host.stop().await;
}

#[tokio::test]
async fn tampered_stale_foreign_blobs_are_ignored() {
    let f = Fake::start(Mode::Normal).await;
    let mut client = start(Role::Client, &[f.url.clone()]);
    while f.st.lock().unwrap().reqs == 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let d = Derived::new(&KEY);
    let room = d.room_hex();
    let ok_addr: SocketAddr = "192.0.2.77:7777".parse().unwrap();
    let good = seal(&d, Role::Host, &[ok_addr]).unwrap();
    let mut tampered = good.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let stale = seal_at(&d, Role::Host, &["192.0.2.66:1".parse().unwrap()], now() - 1000, [3; 12]).unwrap();
    let foreign = seal(&Derived::new(&[9; 16]), Role::Host, &["192.0.2.55:1".parse().unwrap()]).unwrap();
    let wrong_role = seal(&d, Role::Client, &["192.0.2.44:1".parse().unwrap()]).unwrap();
    f.inject(raw_event(&room, 20077, &tampered, "r"));
    f.inject(raw_event(&room, 20077, &stale, "r"));
    f.inject(raw_event(&room, 20077, &foreign, "r"));
    f.inject(raw_event(&room, 20077, &wrong_role, "r"));
    f.inject(raw_event(&room, 20077, b"junk", "r"));
    f.inject(raw_event(&room, 20077, &good, "x")); // right blob, not tagged for the room
    f.inject(raw_event(&room, 1, &good, "r")); // wrong kind
    f.inject(raw_event(&room, 20077, &good, "r"));
    let c = client.peer(3).await;
    assert_eq!(c.addr, ok_addr);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(client.rx.try_recv().is_err(), "only the one good blob may come through");
    client.stop().await;
}

#[tokio::test]
async fn all_relays_dead_is_blocked() {
    let relays = [Fake::dead().await, Fake::dead().await];
    let s = start(Role::Host, &relays);
    let r = timeout(Duration::from_secs(20), s.h).await.expect("should give up").unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");
}

#[tokio::test]
async fn probe_publishes_nothing() {
    let good = Fake::start(Mode::Normal).await;
    let n = Nostr::new(&RvConfig { relays: vec![Fake::dead().await, good.url.clone()], ..Default::default() });
    match n.probe(Duration::from_secs(5)).await {
        ProbeStatus::Reachable { rtt_ms } => assert!(rtt_ms < 2000),
        o => panic!("{o:?}"),
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = good.st.lock().unwrap();
    assert_eq!((s.pubs.len(), s.reqs, s.refused, s.bad_sig), (0, 0, 0, 0));
    assert_eq!(s.upgrades, 1);
    drop(s);
    let n = Nostr::new(&RvConfig { relays: vec![Fake::dead().await], ..Default::default() });
    assert!(matches!(n.probe(Duration::from_secs(2)).await, ProbeStatus::Blocked(_)));
}

#[tokio::test]
async fn cancel_while_connecting_is_prompt() {
    let slow = Fake::start(Mode::Slow(Duration::from_secs(30))).await;
    let s = start(Role::Host, &[slow.url.clone()]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(s.stop().await < Duration::from_secs(1));
}

#[test]
fn disclosure_text() {
    let d = Nostr::new(&RvConfig::default()).disclosure();
    assert_eq!(d.shared.len(), 1);
    assert!(d.operator.contains("offchain.pub"));
    assert_eq!(Nostr::new(&RvConfig::default()).id(), "nostr");
}
