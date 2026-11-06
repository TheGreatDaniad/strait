//! `trk` backend against an in-process fake BEP 15 tracker (no real network).
#![cfg(feature = "rv-trk")]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nat_tunnel::rendezvous::trackers::Trackers;
use nat_tunnel::rendezvous::{ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const KEY: [u8; 16] = [7; 16];
const CONN: u64 = 0xdead_beef_1234;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    ErrorOnAnnounce,
}

#[derive(Clone, Debug)]
struct Seen {
    action: u32,
    event: u32,
    port: u16,
    src_port: u16,
    ih: [u8; 20],
}

struct Fake {
    addr: String,
    log: Arc<Mutex<Vec<Seen>>>,
}
impl Fake {
    fn count(&self, f: impl Fn(&Seen) -> bool) -> usize {
        self.log.lock().unwrap().iter().filter(|s| f(s)).count()
    }
}

/// Answers CONNECT and ANNOUNCE; returns every endpoint stored for the info_hash (the caller too,
/// like real trackers do).
fn fake(mode: Mode) -> Fake {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    tokio::spawn(async move {
        let sock = UdpSocket::from_std(sock).unwrap();
        let mut swarm: Vec<([u8; 20], SocketAddr)> = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let b = &buf[..n];
            if n < 16 {
                continue;
            }
            let (action, tid) = (u32::from_be_bytes(b[8..12].try_into().unwrap()), &b[12..16]);
            let mut out = Vec::new();
            if action == 0 && n == 16 {
                l2.lock().unwrap().push(Seen { action, event: 0, port: 0, src_port: from.port(), ih: [0; 20] });
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(tid);
                out.extend_from_slice(&CONN.to_be_bytes());
            } else if action == 1 && n == 98 && u64::from_be_bytes(b[0..8].try_into().unwrap()) == CONN {
                let ih: [u8; 20] = b[16..36].try_into().unwrap();
                let event = u32::from_be_bytes(b[80..84].try_into().unwrap());
                let port = u16::from_be_bytes(b[96..98].try_into().unwrap());
                l2.lock().unwrap().push(Seen { action, event, port, src_port: from.port(), ih });
                if mode == Mode::ErrorOnAnnounce {
                    out.extend_from_slice(&3u32.to_be_bytes());
                    out.extend_from_slice(tid);
                    out.extend_from_slice(b"nope");
                } else {
                    let ep = SocketAddr::new(from.ip(), port);
                    swarm.retain(|(h, e)| !(h == &ih && e == &ep));
                    if event != 3 {
                        swarm.push((ih, ep));
                    }
                    out.extend_from_slice(&1u32.to_be_bytes());
                    out.extend_from_slice(tid);
                    out.extend_from_slice(&[0, 0, 7, 8, 0, 0, 0, 1, 0, 0, 0, 1]);
                    for (_, e) in swarm.iter().filter(|(h, _)| h == &ih) {
                        if let SocketAddr::V4(v) = e {
                            out.extend_from_slice(&v.ip().octets());
                            out.extend_from_slice(&v.port().to_be_bytes());
                        }
                    }
                }
            } else {
                continue;
            }
            let _ = sock.send_to(&out, from).await;
        }
    });
    Fake { addr, log }
}

/// A UDP port that never answers.
fn blackhole() -> (std::net::UdpSocket, String) {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = s.local_addr().unwrap().to_string();
    (s, a)
}

fn backend(trk: &[&str]) -> Trackers {
    Trackers::new(&RvConfig { trackers: trk.iter().map(|s| s.to_string()).collect(), ..Default::default() })
}
fn ctx(role: Role) -> RvCtx {
    let port = if role == Role::Host { 4000 } else { 5000 };
    RvCtx::new(KEY, role, vec![format!("127.0.0.1:{port}").parse().unwrap()])
}

struct Started {
    rx: mpsc::Receiver<nat_tunnel::rendezvous::Candidate>,
    cancel: CancellationToken,
    h: tokio::task::JoinHandle<Result<(), RvError>>,
}
fn start(b: Trackers, c: RvCtx) -> Started {
    let (tx, rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let cc = cancel.clone();
    Started { rx, cancel, h: tokio::spawn(async move { b.run(c, tx, cc).await }) }
}

#[tokio::test]
async fn two_peers_find_each_other_with_mapped_port() {
    let f = fake(Mode::Normal);
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_port = sock.local_addr().unwrap().port();
    let mut host = start(backend(&[&f.addr]), ctx(Role::Host).with_sock(sock));
    let mut client = start(backend(&[&f.addr]), ctx(Role::Client));
    let c = timeout(Duration::from_secs(10), client.rx.recv()).await.unwrap().unwrap();
    let h = timeout(Duration::from_secs(10), host.rx.recv()).await.unwrap().unwrap();
    assert_eq!((c.addr, c.via), ("127.0.0.1:4000".parse().unwrap(), "trk"));
    assert_eq!(h.addr, "127.0.0.1:5000".parse::<SocketAddr>().unwrap());
    // wrong-port safety: announced port = ctx.local port, never the socket's own port.
    let log = f.log.lock().unwrap().clone();
    let ann: Vec<_> = log.iter().filter(|s| s.action == 1).collect();
    assert!(ann.iter().all(|s| s.port == 4000 || s.port == 5000));
    assert!(ann.iter().any(|s| s.port == 4000 && s.src_port == sock_port && s.src_port != 4000), "host used the shared socket");
    assert!(ann.iter().any(|s| s.port == 5000 && s.src_port != 5000));
    assert!(ann.iter().all(|s| s.ih == nat_tunnel::rendezvous::derive::Derived::new(&KEY).room_info_hash()));
    host.cancel.cancel();
    client.cancel.cancel();
}

#[tokio::test]
async fn own_address_is_filtered() {
    let f = fake(Mode::Normal);
    let mut host = start(backend(&[&f.addr]), ctx(Role::Host));
    // the fake returns the host itself in every response; nothing may be emitted
    timeout(Duration::from_secs(1), async { while f.count(|s| s.action == 1) == 0 { tokio::time::sleep(Duration::from_millis(20)).await } })
        .await
        .unwrap();
    assert!(timeout(Duration::from_millis(700), host.rx.recv()).await.is_err());
    host.cancel.cancel();
}

#[tokio::test]
async fn no_ipv4_candidate_fails() {
    let c = RvCtx::new(KEY, Role::Host, vec!["[2001:db8::1]:4000".parse().unwrap()]);
    let r = backend(&["127.0.0.1:9"]).run(c, mpsc::channel(1).0, CancellationToken::new()).await;
    assert_eq!(r, Err(RvError::Failed("no mapped address".into())));
}

#[tokio::test]
async fn error_response_backs_off_and_other_tracker_works() {
    let bad = fake(Mode::ErrorOnAnnounce);
    let good = fake(Mode::Normal);
    let mut host = start(backend(&[&bad.addr, &good.addr]), ctx(Role::Host));
    let mut client = start(backend(&[&bad.addr, &good.addr]), ctx(Role::Client));
    timeout(Duration::from_secs(10), client.rx.recv()).await.unwrap().unwrap();
    timeout(Duration::from_secs(10), host.rx.recv()).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // two clients, each got one error and then 30 s of silence
    assert_eq!(bad.count(|s| s.action == 1), 2);
    assert!(!host.h.is_finished());
    host.cancel.cancel();
    client.cancel.cancel();
}

#[tokio::test]
async fn dead_tracker_does_not_stop_live_one() {
    let (_keep, dead) = blackhole();
    let f = fake(Mode::Normal);
    let mut host = start(backend(&[&dead, &f.addr]), ctx(Role::Host));
    let mut client = start(backend(&[&dead, &f.addr]), ctx(Role::Client));
    timeout(Duration::from_secs(10), client.rx.recv()).await.unwrap().unwrap();
    timeout(Duration::from_secs(10), host.rx.recv()).await.unwrap().unwrap();
    host.cancel.cancel();
    client.cancel.cancel();
}

#[tokio::test]
async fn all_dead_is_blocked() {
    let (_k1, d1) = blackhole();
    let (_k2, d2) = blackhole();
    let s = start(backend(&[&d1, &d2]), ctx(Role::Host));
    let r = timeout(Duration::from_secs(15), s.h).await.unwrap().unwrap();
    assert!(matches!(r, Err(RvError::Blocked(_))), "{r:?}");
}

#[tokio::test]
async fn cancel_sends_stopped() {
    let f = fake(Mode::Normal);
    let s = start(backend(&[&f.addr]), ctx(Role::Host));
    timeout(Duration::from_secs(3), async { while f.count(|x| x.action == 1 && x.event == 2) == 0 { tokio::time::sleep(Duration::from_millis(20)).await } })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await; // let the response land
    s.cancel.cancel();
    assert_eq!(timeout(Duration::from_secs(1), s.h).await.unwrap().unwrap(), Ok(()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.count(|x| x.event == 3), 1);
}

#[tokio::test]
async fn probe_connects_but_never_announces() {
    let f = fake(Mode::Normal);
    let b = backend(&[&f.addr]);
    assert!(matches!(b.probe(Duration::from_secs(3)).await, ProbeStatus::Reachable { .. }));
    assert_eq!(f.count(|s| s.action == 1), 0);
    assert!(f.count(|s| s.action == 0) >= 1);
    let (_k, dead) = blackhole();
    assert!(matches!(backend(&[&dead]).probe(Duration::from_millis(600)).await, ProbeStatus::Blocked(_)));
    assert!(matches!(backend(&["no-such-host.invalid:80"]).probe(Duration::from_secs(1)).await, ProbeStatus::Error(_)));
}

#[test]
fn announce_cadence_phases() {
    use nat_tunnel::rendezvous::trackers::cadence_at;
    let s = |e| cadence_at(e).as_secs();
    assert_eq!((s(0), s(19)), (2, 2));
    assert_eq!((s(20), s(59)), (5, 5));
    assert_eq!((s(60), s(600)), (30, 30));
}
