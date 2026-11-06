//! Rendezvous core: runner semantics (with the mock hub), sig adapter on a loopback signal
//! server, registry, and invite `rv` field.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nat_tunnel::invite::{Endpoint, Invite};
use nat_tunnel::relay::{self, Config};
use nat_tunnel::rendezvous::mock::MockHub;
use nat_tunnel::rendezvous::sig::{self, Sig};
use nat_tunnel::rendezvous::{
    all_disclosures, by_ids, registry, ProbeStatus, Rendezvous, Role, Runner, RvConfig, RvCtx, Status,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const KEY: [u8; 16] = [0xa5; 16];
const HOST: &str = "198.51.100.1:4000";
const CLIENT: &str = "198.51.100.2:5000";

fn ctx(role: Role) -> RvCtx {
    let a: SocketAddr = if role == Role::Host { HOST } else { CLIENT }.parse().unwrap();
    RvCtx::new(KEY, role, vec![a])
}
fn fast(r: Vec<Arc<dyn Rendezvous>>) -> Runner {
    Runner::new(r).with_backoff(Duration::from_millis(10))
}
async fn status_is(h: &nat_tunnel::rendezvous::RunnerHandle, id: &str, want: impl Fn(&Status) -> bool) -> bool {
    let mut w = h.status_watch();
    timeout(Duration::from_secs(3), async {
        loop {
            if w.borrow().iter().any(|(i, s)| *i == id && want(s)) {
                return;
            }
            w.changed().await.unwrap();
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn first_peer_wins_both_directions() {
    let hub = MockHub::new();
    let b = hub.backend("mock");
    let mut host = fast(vec![b.arc()]).start(ctx(Role::Host));
    let mut client = fast(vec![b.arc()]).start(ctx(Role::Client));
    let c = timeout(Duration::from_secs(2), client.next()).await.unwrap().unwrap();
    assert_eq!((c.addr, c.via), (HOST.parse().unwrap(), "mock"));
    let h = timeout(Duration::from_secs(2), host.next()).await.unwrap().unwrap();
    assert_eq!(h.addr, CLIENT.parse::<SocketAddr>().unwrap());
    assert!(status_is(&client, "mock", |s| matches!(s, Status::GotPeer(a) if a.to_string() == HOST)).await);
}

#[tokio::test]
async fn different_key_never_meets() {
    let hub = MockHub::new();
    let b = hub.backend("mock");
    let _host = fast(vec![b.arc()]).start(ctx(Role::Host));
    let mut other = ctx(Role::Client);
    other.key = [1; 16];
    let mut client = fast(vec![b.arc()]).start(other);
    assert!(timeout(Duration::from_millis(300), client.next()).await.is_err());
}

#[tokio::test]
async fn dedup_across_backends() {
    let hub = MockHub::new();
    let (a, b) = (hub.backend("a"), hub.backend("b"));
    let _host = fast(vec![a.arc(), b.arc()]).start(ctx(Role::Host));
    let mut client = fast(vec![a.arc(), b.arc()]).start(ctx(Role::Client));
    assert!(timeout(Duration::from_secs(2), client.next()).await.unwrap().is_some());
    // the same endpoint arrives from the other backend too, but must not be emitted again
    assert!(status_is(&client, "a", |s| matches!(s, Status::GotPeer(_))).await);
    assert!(status_is(&client, "b", |s| matches!(s, Status::GotPeer(_))).await);
    assert!(timeout(Duration::from_millis(300), client.next()).await.is_err(), "duplicate emitted");
}

#[tokio::test]
async fn failing_backend_does_not_stop_others_and_restarts_three_times() {
    let hub = MockHub::new();
    let (bad, good) = (hub.backend("bad").fail_first(usize::MAX), hub.backend("good"));
    let _host = fast(vec![good.arc()]).start(ctx(Role::Host));
    let mut client = fast(vec![bad.arc(), good.arc()]).start(ctx(Role::Client));
    let c = timeout(Duration::from_secs(2), client.next()).await.unwrap().unwrap();
    assert_eq!(c.via, "good");
    assert!(status_is(&client, "bad", |s| matches!(s, Status::Failed(m) if m == "mock failure")).await);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(bad.runs(), 4, "1 run + 3 restarts, then give up");
    assert!(status_is(&client, "good", |s| matches!(s, Status::GotPeer(_))).await);
}

#[tokio::test]
async fn backend_recovers_after_restarts() {
    let hub = MockHub::new();
    let flaky = hub.backend("flaky").fail_first(2);
    let _host = fast(vec![flaky.arc()]).start(ctx(Role::Host));
    // host also fails twice first; both recover and still meet
    let mut client = fast(vec![flaky.arc()]).start(ctx(Role::Client));
    assert!(timeout(Duration::from_secs(3), client.next()).await.unwrap().is_some());
    assert!(flaky.runs() >= 3);
}

#[tokio::test]
async fn backoff_grows_exponentially() {
    let hub = MockHub::new();
    let bad = hub.backend("bad").fail_first(usize::MAX);
    let t0 = Instant::now();
    let h = Runner::new(vec![bad.arc()]).with_backoff(Duration::from_millis(60)).start(ctx(Role::Host));
    // restarts wait 60 + 120 + 240 ms before the 2nd, 3rd, 4th run
    while bad.runs() < 4 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(t0.elapsed() < Duration::from_secs(3));
    }
    assert!(t0.elapsed() >= Duration::from_millis(410), "{:?}", t0.elapsed());
    drop(h);
}

#[tokio::test]
async fn blocked_is_reported_and_not_retried() {
    let hub = MockHub::new();
    let b = hub.backend("blk").blocked();
    let h = fast(vec![b.arc()]).start(ctx(Role::Client));
    assert!(status_is(&h, "blk", |s| matches!(s, Status::Blocked(_))).await);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(b.runs(), 1);
}

#[tokio::test]
async fn cancel_stops_everything_promptly_and_cleans_up() {
    let hub = MockHub::new();
    let (a, b) = (hub.backend("a"), hub.backend("b").latency(Duration::from_secs(30)));
    let h = fast(vec![a.arc(), b.arc()]).start(ctx(Role::Host));
    assert!(status_is(&h, "a", |s| *s == Status::Waiting).await);
    assert_eq!(hub.mailboxes(), 1);
    let t0 = Instant::now();
    h.stop().await;
    assert!(t0.elapsed() < Duration::from_millis(300), "{:?}", t0.elapsed());
    assert_eq!(hub.mailboxes(), 0);
    assert_eq!(a.clean_exits(), 1);
}

#[tokio::test]
async fn drop_cancels() {
    let hub = MockHub::new();
    let a = hub.backend("a");
    let h = fast(vec![a.arc()]).start(ctx(Role::Host));
    assert!(status_is(&h, "a", |s| *s == Status::Waiting).await);
    let tok = h.cancel_token();
    drop(h);
    assert!(tok.is_cancelled());
    timeout(Duration::from_secs(1), async {
        while a.clean_exits() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn slow_backend_does_not_delay_fast_one() {
    let hub = MockHub::new();
    let (slow, fastb) = (hub.backend("slow").latency(Duration::from_secs(5)), hub.backend("fast"));
    let _host = fast(vec![fastb.arc()]).start(ctx(Role::Host));
    let mut client = fast(vec![slow.arc(), fastb.arc()]).start(ctx(Role::Client));
    let c = timeout(Duration::from_secs(1), client.next()).await.unwrap().unwrap();
    assert_eq!(c.via, "fast");
}

#[tokio::test]
async fn probe_all_is_concurrent_and_bounded() {
    let hub = MockHub::new();
    let d = Duration::from_millis(300);
    let r = Runner::new(vec![
        hub.backend("a").probe_delay(d).arc(),
        hub.backend("b").probe_delay(d).arc(),
        hub.backend("c").probe_delay(d).arc(),
        hub.backend("blk").blocked().arc(),
        hub.backend("slow").probe_delay(Duration::from_secs(5)).arc(),
    ]);
    let t0 = Instant::now();
    let res = r.probe_all(Duration::from_millis(500)).await;
    let el = t0.elapsed();
    assert!(el < Duration::from_millis(900), "not concurrent / unbounded: {el:?}");
    assert!(el >= Duration::from_millis(500), "slow one must hit the timeout: {el:?}");
    let ids: Vec<_> = res.iter().map(|(i, _)| *i).collect();
    assert_eq!(ids, ["a", "b", "c", "blk", "slow"]);
    assert!(matches!(res[0].1, ProbeStatus::Reachable { rtt_ms } if (250..600).contains(&rtt_ms)));
    assert!(matches!(res[3].1, ProbeStatus::Blocked(_)));
    assert!(matches!(res[4].1, ProbeStatus::Error(_)));
}

#[test]
fn registry_and_disclosures() {
    let cfg = RvConfig::default();
    let ids: Vec<_> = registry(&cfg).iter().map(|b| b.id()).collect();
    assert!(ids.contains(&"sig"));
    let pick = by_ids(&["nope".into(), "sig".into(), "sig".into(), "".into()], &cfg);
    assert_eq!(pick.len(), 1);
    assert_eq!(pick[0].id(), "sig");
    assert!(by_ids(&["nope".into()], &cfg).is_empty());
    let all = all_disclosures();
    assert_eq!(all.len(), ids.len());
    let (_, d) = all.iter().find(|(i, _)| *i == "sig").unwrap();
    assert!(!d.title.is_empty() && !d.shared.is_empty() && !d.not_shared.is_empty() && !d.why.is_empty() && !d.operator.is_empty());
}

// ---------------------------------------------------------------- sig on a loopback server

async fn server() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    tokio::spawn(relay::serve(s, Config { rate_per_sec: 1e6, burst: 1e6, ..Config::default() }));
    a
}
fn sig_for(a: SocketAddr) -> Arc<dyn Rendezvous> {
    Arc::new(Sig::new(vec![Endpoint::Addr(a)]))
}
async fn sock_ctx(role: Role) -> (RvCtx, SocketAddr) {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a = s.local_addr().unwrap();
    (RvCtx::new(KEY, role, vec![]).with_sock(s), a)
}

#[test]
fn sig_room_matches_legacy_derivation() {
    let hexkey = "a5".repeat(16);
    assert_eq!(sig::room_for(&KEY), relay::room_for_key(&hexkey));
}

#[tokio::test]
async fn sig_exchanges_observed_addresses_both_ways() {
    let srv = server().await;
    let ((hc, ha), (cc, ca)) = (sock_ctx(Role::Host).await, sock_ctx(Role::Client).await);
    let mut host = fast(vec![sig_for(srv)]).start(hc);
    let mut client = fast(vec![sig_for(srv)]).start(cc);
    let c = timeout(Duration::from_secs(3), client.next()).await.unwrap().unwrap();
    assert_eq!((c.addr, c.via), (ha, "sig"));
    let h = timeout(Duration::from_secs(3), host.next()).await.unwrap().unwrap();
    assert_eq!(h.addr, ca);
    assert!(status_is(&client, "sig", |s| matches!(s, Status::GotPeer(_))).await);
}

#[tokio::test]
async fn sig_private_socket_and_wrong_key_isolation() {
    let srv = server().await;
    let mut host = fast(vec![sig_for(srv)]).start(RvCtx::new(KEY, Role::Host, vec![]));
    let mut other = fast(vec![sig_for(srv)]).start(RvCtx::new([3; 16], Role::Client, vec![]));
    assert!(timeout(Duration::from_millis(500), other.next()).await.is_err());
    let mut client = fast(vec![sig_for(srv)]).start(RvCtx::new(KEY, Role::Client, vec![]));
    let c = timeout(Duration::from_secs(3), client.next()).await.unwrap().unwrap();
    assert!(c.addr.ip().is_loopback());
    assert!(timeout(Duration::from_secs(3), host.next()).await.unwrap().is_some());
}

#[tokio::test]
async fn sig_deregisters_on_cancel() {
    let srv = server().await;
    let host = fast(vec![sig_for(srv)]).start(RvCtx::new(KEY, Role::Host, vec![]));
    tokio::time::sleep(Duration::from_millis(200)).await;
    host.stop().await;
    let mut client = fast(vec![sig_for(srv)]).start(RvCtx::new(KEY, Role::Client, vec![]));
    assert!(timeout(Duration::from_millis(600), client.next()).await.is_err(), "stale host still registered");
}

#[tokio::test]
async fn sig_probe() {
    let srv = server().await;
    let r = sig_for(srv).probe(Duration::from_secs(1)).await;
    assert!(matches!(r, ProbeStatus::Reachable { rtt_ms } if rtt_ms < 500), "{r:?}");
    // a closed port: no reply
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    let t0 = Instant::now();
    let r = sig_for(dead_addr).probe(Duration::from_millis(300)).await;
    assert!(matches!(r, ProbeStatus::Blocked(_)), "{r:?}");
    assert!(t0.elapsed() < Duration::from_millis(800));
    assert!(matches!(Sig::new(vec![]).probe(Duration::from_millis(100)).await, ProbeStatus::Error(_)));
    // probe publishes nothing: a client registering afterwards sees no host
    let mut client = fast(vec![sig_for(srv)]).start(RvCtx::new(KEY, Role::Client, vec![]));
    assert!(timeout(Duration::from_millis(400), client.next()).await.is_err());
}

#[tokio::test]
async fn sig_without_servers_fails_visibly() {
    let h = Runner::new(vec![Arc::new(Sig::new(vec![]))]).with_backoff(Duration::from_millis(5)).start(RvCtx::new(KEY, Role::Host, vec![]));
    assert!(status_is(&h, "sig", |s| matches!(s, Status::Failed(m) if m.contains("no signal server"))).await);
}

// ---------------------------------------------------------------- invite rv

#[test]
fn invite_rv_round_trip_and_legacy_unchanged() {
    let sig_addr: SocketAddr = "203.0.113.5:7000".parse().unwrap();
    // without rv: byte-identical to before
    assert_eq!(Invite::new("k").signal(sig_addr).encode(), "STRAIT2|k||203.0.113.5:7000");
    assert_eq!(Invite::new("k").host(sig_addr).room("r").encode(), "STRAIT2|k|203.0.113.5:7000||r");
    let inv = Invite::new("k").signal(sig_addr).rv("sig").rv("trk").rv("futurex").rv("sig");
    assert_eq!(inv.rv, ["sig", "trk", "futurex"]);
    let text = inv.encode();
    assert_eq!(text, "STRAIT2|k||203.0.113.5:7000||sig,trk,futurex");
    assert_eq!(Invite::parse(&text), Some(inv));
    // rv with no host/signal is a valid invite (trk/nostr/dht need neither)
    let only = Invite::new("k").rv("dht");
    assert_eq!(Invite::parse(&only.encode()), Some(only));
    // old parsers read the first four fields only; the room slot stays empty
}

#[test]
fn invite_rv_shape_rules() {
    let p = |s: &str| Invite::parse(s);
    // short form: 4th field is rv when it is a list / known id, a room otherwise
    assert_eq!(p("STRAIT2|k||1.2.3.4:5|sig,trk").unwrap().rv, ["sig", "trk"]);
    assert_eq!(p("STRAIT2|k||1.2.3.4:5|sig").unwrap().room, "");
    assert_eq!(p("STRAIT2|k||1.2.3.4:5|srvtest").unwrap().room, "srvtest");
    assert_eq!(p("STRAIT2|k||1.2.3.4:5|srvtest|dht").unwrap().rv, ["dht"]);
    // a room that looks like an rv id survives a round trip
    let odd = Invite::new("k").signal("1.2.3.4:5".parse::<SocketAddr>().unwrap()).room("sig");
    assert_eq!(Invite::parse(&odd.encode()), Some(odd));
    // validation
    for bad in ["STRAIT2|k||1.2.3.4:5||SIG", "STRAIT2|k||1.2.3.4:5||a-b", "STRAIT2|k||1.2.3.4:5||abcdefghijklm", "STRAIT2|k||1.2.3.4:5||a,b,c,d,e,f,g,h,i", "STRAIT2|k||1.2.3.4:5||é"] {
        assert!(p(bad).is_none(), "{bad}");
    }
    assert_eq!(p("STRAIT2|k||1.2.3.4:5||a,b,c,d,e,f,g,h").unwrap().rv.len(), 8);
    assert_eq!(p("STRAIT2|k||1.2.3.4:5||sig,,trk,").unwrap().rv, ["sig", "trk"]);
    assert!(Invite::new("k").rv("BAD").rv("").rv("toolongidentifier").rv.is_empty());
    assert!(p("STRAIT2|k|||").is_none());
    // key_bytes
    assert!(Invite::new("a5".repeat(16)).key_bytes() == Some(KEY));
    assert!(Invite::new("abc123").key_bytes().is_none());
}
