//! rv-dht tests against a local mainline Testnet on 127.0.0.1 (no real network).
#![cfg(feature = "rv-dht")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mainline::{Dht as Node, MutableItem, SigningKey, Testnet};
use nat_tunnel::rendezvous::derive::{seal, seal_at, Derived};
use nat_tunnel::rendezvous::dht::{poll_windows, Dht, PutSchedule, Tune};
use nat_tunnel::rendezvous::{Candidate, ProbeStatus, Rendezvous, Role, RvCtx, RvError};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
fn tune() -> Tune {
    Tune {
        poll_steps: vec![Duration::from_millis(200), Duration::from_millis(300)],
        republish: Duration::from_secs(1),
        bootstrap_timeout: Duration::from_secs(5),
        early: vec![],
        min_stored: 0,
        retry: Duration::from_millis(300),
    }
}
fn net() -> Testnet {
    Testnet::builder(6).build().unwrap()
}
fn dht_at(tn: &Testnet, clock: u64) -> Dht {
    Dht::with_network(tn.bootstrap.clone(), Ipv4Addr::LOCALHOST, Arc::new(move || clock), tune())
}
fn dht(tn: &Testnet) -> Dht {
    Dht::with_network(tn.bootstrap.clone(), Ipv4Addr::LOCALHOST, Arc::new(now), tune())
}
fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

type Handle = tokio::task::JoinHandle<Result<(), RvError>>;
fn start(b: Dht, key: [u8; 16], role: Role, local: Vec<SocketAddr>) -> (mpsc::Receiver<Candidate>, CancellationToken, Handle) {
    let (tx, rx) = mpsc::channel(16);
    let c = CancellationToken::new();
    let c2 = c.clone();
    let h = tokio::spawn(async move { b.run(RvCtx::new(key, role, local), tx, c2).await });
    (rx, c, h)
}
async fn recv(rx: &mut mpsc::Receiver<Candidate>, secs: u64) -> Option<Candidate> {
    tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await.ok().flatten()
}
async fn stop(c: CancellationToken, h: Handle) {
    c.cancel();
    assert!(tokio::time::timeout(Duration::from_secs(3), h).await.expect("stops in time").unwrap().is_ok());
}

/// Raw publisher standing in for a peer: put `blob` under `role`'s key at the window of `clock`.
fn raw_put(tn: &Testnet, key: [u8; 16], role: Role, blob: &[u8], seq: i64, cas: Option<i64>, clock: u64) {
    let d = Derived::new(&key);
    let seed = if role == Role::Host { d.dht_host_seed } else { d.dht_client_seed };
    let node = Node::builder().bootstrap(&tn.bootstrap).bind_address(Ipv4Addr::LOCALHOST).build().unwrap();
    assert!(node.bootstrapped());
    let salt = (clock / 600).to_be_bytes();
    node.put_mutable(MutableItem::new(SigningKey::from_bytes(&seed), blob, seq, Some(&salt)), cas).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn host_and_client_find_each_other() {
    let tn = net();
    let key = [7u8; 16];
    let (hc, cc) = (sa("192.0.2.1:1111"), sa("198.51.100.2:2222"));
    let (mut hrx, hcancel, hh) = start(dht(&tn), key, Role::Host, vec![hc]);
    let (mut crx, ccancel, ch) = start(dht(&tn), key, Role::Client, vec![cc]);
    assert_eq!(recv(&mut hrx, 20).await, Some(Candidate { addr: cc, via: "dht" }));
    assert_eq!(recv(&mut crx, 20).await, Some(Candidate { addr: hc, via: "dht" }));
    stop(hcancel, hh).await;
    stop(ccancel, ch).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_key_finds_nothing() {
    let tn = net();
    let (_hrx, hcancel, hh) = start(dht(&tn), [1u8; 16], Role::Host, vec![sa("192.0.2.1:1111")]);
    let (mut crx, ccancel, ch) = start(dht(&tn), [2u8; 16], Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 4).await, None);
    stop(hcancel, hh).await;
    stop(ccancel, ch).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(windows, ignore = "raw_put standalone loopback Node fails with NoClosestNodes/Timeout on Windows; product DHT path passes")]
async fn seq_update_replaces_record() {
    let tn = net();
    let key = [3u8; 16];
    let d = Derived::new(&key);
    let (x, y) = (sa("192.0.2.10:1000"), sa("192.0.2.11:1001"));
    let t = now() as i64;
    raw_put(&tn, key, Role::Host, &seal(&d, Role::Host, &[x]).unwrap(), t, None, now());
    let (mut crx, cc, ch) = start(dht(&tn), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(x));
    raw_put(&tn, key, Role::Host, &seal(&d, Role::Host, &[y]).unwrap(), t + 1, Some(t), now());
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(y));
    stop(cc, ch).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn previous_window_is_read() {
    let tn = net();
    let key = [4u8; 16];
    let w = (now() / 600) * 600;
    let (hc, cc) = (sa("192.0.2.1:1111"), sa("198.51.100.2:2222"));
    // host's clock is the last second of window W, the client's already in W+1
    let (_hrx, hcancel, hh) = start(dht_at(&tn, w + 599), key, Role::Host, vec![hc]);
    let (mut crx, ccancel, ch) = start(dht_at(&tn, w + 600), key, Role::Client, vec![cc]);
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(hc));
    stop(hcancel, hh).await;
    stop(ccancel, ch).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(windows, ignore = "raw_put standalone loopback Node fails with NoClosestNodes/Timeout on Windows; product DHT path passes")]
async fn own_tampered_and_stale_blobs_are_ignored() {
    let tn = net();
    let key = [5u8; 16];
    let d = Derived::new(&key);
    let a = sa("192.0.2.20:2000");
    let t = now() as i64;
    // host-sealed blob sitting under the CLIENT key: a host polling it must ignore it (own role)
    raw_put(&tn, key, Role::Client, &seal(&d, Role::Host, &[a]).unwrap(), t, None, now());
    let (mut hrx, hc, hh) = start(dht(&tn), key, Role::Host, vec![sa("192.0.2.1:1111")]);
    assert_eq!(recv(&mut hrx, 4).await, None);
    stop(hc, hh).await;

    // client polls the host key: garbage, flipped bit, then a stale (1000 s old) blob -> nothing
    let mut bad = seal(&d, Role::Host, &[a]).unwrap();
    let n = bad.len();
    bad[n - 1] ^= 1;
    raw_put(&tn, key, Role::Host, &bad, t, None, now());
    raw_put(&tn, key, Role::Host, b"garbage", t + 1, Some(t), now());
    let old = seal_at(&d, Role::Host, &[a], now() - 1000, [9u8; 12]).unwrap();
    raw_put(&tn, key, Role::Host, &old, t + 2, Some(t + 1), now());
    let (mut crx, cc, ch) = start(dht(&tn), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 5).await, None);
    // a valid record afterwards still works
    raw_put(&tn, key, Role::Host, &seal(&d, Role::Host, &[a]).unwrap(), t + 3, Some(t + 2), now());
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(a));
    stop(cc, ch).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_failure_is_blocked() {
    let mut t = tune();
    t.bootstrap_timeout = Duration::from_secs(4);
    let b = Dht::with_network(vec!["127.0.0.1:9".into()], Ipv4Addr::LOCALHOST, Arc::new(now), t);
    let (tx, _rx) = mpsc::channel(1);
    let r = b.run(RvCtx::new([1; 16], Role::Host, vec![sa("192.0.2.1:1")]), tx, CancellationToken::new()).await;
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_stops_promptly() {
    let tn = net();
    let (_rx, c, h) = start(dht(&tn), [6u8; 16], Role::Host, vec![sa("192.0.2.1:1111")]);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let t0 = std::time::Instant::now();
    stop(c, h).await;
    assert!(t0.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_sends_only_pings() {
    // a fake bootstrap node: answers pings and records every datagram it sees
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let s2 = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            s2.lock().unwrap().push(buf[..n].to_vec());
            let _ = sock.send_to(b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:t2:rv1:y1:re", from).await;
        }
    });
    let b = Dht::with_network(vec![addr.to_string()], Ipv4Addr::LOCALHOST, Arc::new(now), tune());
    assert!(matches!(b.probe(Duration::from_secs(3)).await, ProbeStatus::Reachable { .. }));
    let pk = seen.lock().unwrap().clone();
    assert!(!pk.is_empty());
    assert!(pk.iter().all(|p| p.windows(9).any(|w| w == b"1:q4:ping")), "only ping queries");
    // nothing listening -> Blocked
    let b = Dht::with_network(vec!["127.0.0.1:9".into()], Ipv4Addr::LOCALHOST, Arc::new(now), tune());
    assert!(matches!(b.probe(Duration::from_millis(500)).await, ProbeStatus::Blocked(_)));
}

// ---------------------------------------------------------------- hardening

#[test]
fn poll_windows_adds_next_only_near_the_end() {
    let w = 1000u64;
    assert_eq!(poll_windows(w * 600), vec![w, w - 1]);
    assert_eq!(poll_windows(w * 600 + 509), vec![w, w - 1]);
    assert_eq!(poll_windows(w * 600 + 510), vec![w, w - 1, w + 1]);
    assert_eq!(poll_windows(w * 600 + 599), vec![w, w - 1, w + 1]);
}

#[test]
fn put_schedule_retries_thin_puts_then_early_then_steady() {
    let t = Tune {
        early: vec![Duration::from_secs(12), Duration::from_secs(20)],
        min_stored: 3,
        retry: Duration::from_secs(4),
        republish: Duration::from_secs(270),
        ..tune()
    };
    let mut s = PutSchedule::default();
    let secs = |d: Duration| d.as_secs();
    assert_eq!(secs(s.after_put(&t, 1)), 4); // thin: retry (x3 at most)
    assert_eq!(secs(s.after_put(&t, 0)), 4);
    assert_eq!(secs(s.after_put(&t, 2)), 4);
    assert_eq!(secs(s.after_put(&t, 1)), 12); // retries used up: early schedule
    assert_eq!(secs(s.after_put(&t, 8)), 20);
    assert_eq!(secs(s.after_put(&t, 8)), 270);
}

/// Host's clock is in the next window, the client's still in the last 90 s of the current one:
/// the client must look ahead (it used to see only current and previous).
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(windows, ignore = "raw_put standalone loopback Node fails with NoClosestNodes/Timeout on Windows; product DHT path passes")]
async fn client_behind_reads_next_window() {
    let tn = net();
    let key = [11u8; 16];
    let w = (now() / 600) * 600;
    let hc = sa("192.0.2.1:1111");
    let (_hrx, hcancel, hh) = start(dht_at(&tn, w + 605), key, Role::Host, vec![hc]);
    let (mut crx, ccancel, ch) = start(dht_at(&tn, w + 590), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(hc));
    stop(hcancel, hh).await;
    stop(ccancel, ch).await;
}

/// A peer clock 100 s ahead seals a blob "from the future"; it must still open.
#[tokio::test(flavor = "multi_thread")]
async fn blob_from_a_fast_clock_is_accepted() {
    let tn = net();
    let key = [12u8; 16];
    let d = Derived::new(&key);
    let a = sa("192.0.2.30:3000");
    raw_put(&tn, key, Role::Host, &seal_at(&d, Role::Host, &[a], now() + 100, [3u8; 12]).unwrap(), now() as i64, None, now());
    let (mut crx, cc, ch) = start(dht(&tn), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(a));
    stop(cc, ch).await;
}

/// Junk in the current window must not hide a valid record in the previous one.
#[tokio::test(flavor = "multi_thread")]
async fn junk_in_current_window_does_not_hide_previous() {
    let tn = net();
    let key = [13u8; 16];
    let d = Derived::new(&key);
    let a = sa("192.0.2.31:3100");
    let t = now() as i64;
    raw_put(&tn, key, Role::Host, &seal(&d, Role::Host, &[a]).unwrap(), t, None, now() - 600);
    raw_put(&tn, key, Role::Host, b"junk", t, None, now());
    let (mut crx, cc, ch) = start(dht(&tn), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    assert_eq!(recv(&mut crx, 20).await.map(|c| c.addr), Some(a));
    stop(cc, ch).await;
}

/// A record with a higher seq already sits under the host key (earlier run, fast clock): the host
/// reads it, adopts its seq and overwrites it instead of failing forever.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(windows, ignore = "raw_put standalone loopback Node fails with NoClosestNodes/Timeout on Windows; product DHT path passes")]
async fn host_overwrites_a_higher_seq_record() {
    let tn = net();
    let key = [14u8; 16];
    let d = Derived::new(&key);
    let (old, fresh) = (sa("192.0.2.40:4000"), sa("192.0.2.41:4001"));
    let t = now() as i64;
    raw_put(&tn, key, Role::Host, &seal(&d, Role::Host, &[old]).unwrap(), t + 5000, None, now());
    let (_hrx, hc, hh) = start(dht(&tn), key, Role::Host, vec![fresh]);
    let (mut crx, cc, ch) = start(dht(&tn), key, Role::Client, vec![sa("198.51.100.2:2222")]);
    let mut got = Vec::new();
    while let Some(c) = recv(&mut crx, 25).await {
        got.push(c.addr);
        if c.addr == fresh {
            break;
        }
    }
    assert!(got.contains(&fresh), "host never replaced the stale record: {got:?}");
    stop(hc, hh).await;
    stop(cc, ch).await;
}

/// The host publishes again on the early schedule even though nobody was seen (seq keeps rising).
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(windows, ignore = "raw_put standalone loopback Node fails with NoClosestNodes/Timeout on Windows; product DHT path passes")]
async fn host_repeats_its_put_early() {
    let tn = net();
    let key = [15u8; 16];
    let mut t = tune();
    t.republish = Duration::from_secs(60);
    t.early = vec![Duration::from_millis(300), Duration::from_millis(300)];
    let dd = Dht::with_network(tn.bootstrap.clone(), Ipv4Addr::LOCALHOST, Arc::new(now), t);
    let t0 = now() as i64; // the host's seq starts at its start time and rises by one per PUT
    let (_rx, c, h) = start(dd, key, Role::Host, vec![sa("192.0.2.1:1111")]);
    let pk = SigningKey::from_bytes(&Derived::new(&key).dht_host_seed).verifying_key().to_bytes();
    let salt = (now() / 600).to_be_bytes();
    let reader = Node::builder().bootstrap(&tn.bootstrap).bind_address(Ipv4Addr::LOCALHOST).build().unwrap();
    assert!(reader.bootstrapped());
    let seq_of = |r: &Node| r.get_mutable_most_recent(&pk, Some(&salt)).map(|i| i.seq());
    tokio::time::sleep(Duration::from_secs(4)).await;
    let last = seq_of(&reader).expect("host published");
    assert!(last >= t0 + 3, "expected the first PUT plus two early ones, seq {last} vs start {t0}");
    stop(c, h).await;
}
