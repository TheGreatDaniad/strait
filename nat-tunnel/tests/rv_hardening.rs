//! Runner behaviour: status/summary log lines and the host's one-time nudge to the other methods.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nat_tunnel::rendezvous::runner::Runner;
use nat_tunnel::rendezvous::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvCtx, RvError};
use nat_tunnel::transport::usable_family;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
struct Cap;
impl log::Log for Cap {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        LOG.lock().unwrap().push(r.args().to_string());
    }
    fn flush(&self) {}
}
fn capture() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        log::set_logger(&Cap).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
}

/// Optionally reports one candidate; counts how often the runner nudged it (within `listen`).
struct Probe {
    id: &'static str,
    emit: Option<SocketAddr>,
    listen: Duration,
    nudges: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Rendezvous for Probe {
    fn id(&self) -> &'static str {
        self.id
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure { title: "t", shared: &[], not_shared: &[], why: "", operator: "" }
    }
    async fn probe(&self, _: Duration) -> ProbeStatus {
        ProbeStatus::Reachable { rtt_ms: 0 }
    }
    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        if let Some(addr) = self.emit {
            let _ = tx.send(Candidate { addr, via: self.id }).await;
        }
        let end = tokio::time::Instant::now() + self.listen;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep_until(end) => return Ok(()),
                _ = ctx.nudge.notified() => { self.nudges.fetch_add(1, SeqCst); }
            }
        }
    }
}

fn probe(id: &'static str, emit: Option<&str>, nudges: &Arc<AtomicUsize>) -> Arc<dyn Rendezvous> {
    Arc::new(Probe { id, emit: emit.map(|s| s.parse().unwrap()), listen: Duration::from_millis(1500), nudges: nudges.clone() })
}

#[tokio::test]
async fn host_learning_a_client_nudges_the_other_methods_once() {
    let (finder, other) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    // `other` also reports a candidate later: the nudge must not fire a second time for it
    let r = Runner::new(vec![probe("dht", Some("192.0.2.5:5000"), &finder), probe("trk", Some("192.0.2.6:6000"), &other)]);
    let mut h = r.start(RvCtx::new([1; 16], Role::Host, vec!["192.0.2.1:1".parse().unwrap()]));
    h.next().await.expect("first candidate");
    h.next().await.expect("second candidate");
    tokio::time::sleep(Duration::from_millis(1700)).await;
    h.stop().await;
    // two backends found a peer, but only the first one to report nudges, and only the others
    assert_eq!(finder.load(SeqCst) + other.load(SeqCst), 1, "exactly one nudge in total");
}

#[tokio::test]
async fn guest_side_never_nudges() {
    let n = Arc::new(AtomicUsize::new(0));
    let r = Runner::new(vec![probe("dht", Some("192.0.2.5:5000"), &n), probe("trk", None, &n)]);
    let h = r.start(RvCtx::new([1; 16], Role::Client, vec![]));
    tokio::time::sleep(Duration::from_millis(1700)).await;
    h.stop().await;
    assert_eq!(n.load(SeqCst), 0);
}

#[tokio::test]
async fn status_changes_and_summary_are_logged() {
    capture();
    let n = Arc::new(AtomicUsize::new(0));
    let r = Runner::new(vec![probe("zzlog", Some("192.0.2.7:7000"), &n)]);
    let mut h = r.start(RvCtx::new([2; 16], Role::Host, vec![]));
    h.next().await.expect("candidate");
    h.stop().await;
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("rendezvous host: zzlog -> GotPeer(192.0.2.7:7000)"), "{log}");
    assert!(log.contains("rendezvous host: ended after") && log.contains("zzlog=GotPeer"), "{log}");
}

#[test]
fn ipv6_is_usable_only_with_a_route() {
    let (v4, v6, lo): (SocketAddr, SocketAddr, SocketAddr) = ("192.0.2.1:1".parse().unwrap(), "[2001:db8::1]:1".parse().unwrap(), "[::1]:1".parse().unwrap());
    assert!(usable_family(v4, false) && usable_family(v4, true));
    assert!(!usable_family(v6, false) && usable_family(v6, true));
    assert!(usable_family(lo, false), "loopback always works (tests)");
}
