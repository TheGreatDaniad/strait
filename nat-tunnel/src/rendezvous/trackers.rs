//! `trk`: public BitTorrent UDP trackers (BEP 15) as a rendezvous channel. No identity, no crypto:
//! the "swarm" is `room_info_hash()` and a peer's published record is its announced `ip:port`.
//!
//! The announced port MUST be the STUN-mapped port of the punching socket (trackers store the
//! announced port, not the observed one), so it is taken from the first IPv4 entry of `ctx.local`.
//! With `ctx.sock` set, every packet goes through that socket (same 5-tuple as the punch).
//! Politeness: retransmits 1/2/4 s, re-announce every 2 s for the first 20 s, every 5 s until 60 s,
//! then every 30 s (live runs saw 5 s accepted without errors; never below 2 s, so
//! >= 1 s between requests to one tracker apart from CONNECT immediately followed by ANNOUNCE),
//! 30 s back-off after an error response, tracker dropped after 3 of them.
//! shortcut: IPv4 trackers/peers only, resolved once per run; upgrade if v6-only hosts matter.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, RvConfig, RvCtx, RvError, Status};

const DEFAULT_TRACKERS: [&str; 4] = [
    "open.stealth.si:80",
    "tracker.opentrackr.org:1337",
    "open.demonii.com:1337",
    "tracker.torrent.eu.org:451",
];
const PROTOCOL_ID: u64 = 0x41727101980;
const RTO: [Duration; 3] = [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)];
const CONN_TTL: Duration = Duration::from_secs(55);
const ERR_BACKOFF: Duration = Duration::from_secs(30);
const MAX_ERRORS: u32 = 3;

pub struct Trackers {
    cfg: RvConfig,
}

impl Trackers {
    pub fn new(cfg: &RvConfig) -> Self {
        Self { cfg: cfg.clone() }
    }

    /// The configured list, or the defaults only when none was configured. A configured list with
    /// an unusable entry is an error, never a silent fallback to public trackers.
    fn entries(&self) -> Result<Vec<String>, String> {
        if self.cfg.trackers.is_empty() {
            return Ok(DEFAULT_TRACKERS.iter().map(|s| s.to_string()).collect());
        }
        self.cfg.trackers.iter().map(|t| entry(t).ok_or_else(|| format!("tracker '{t}' is not usable (use udp://host:port)"))).collect()
    }
}

/// `host:port` (optionally `udp://host:port[/announce]`); anything else is ignored.
fn entry(s: &str) -> Option<String> {
    let s = s.trim();
    let s = match s.split_once("://") {
        Some(("udp", rest)) => rest,
        Some(_) => return None,
        None => s,
    };
    let s = s.split('/').next()?;
    let (h, p) = s.rsplit_once(':')?;
    (!h.is_empty() && p.parse::<u16>().ok()? != 0).then(|| s.to_string())
}

/// Resolve every run (IPv4 only, like the punch socket), in parallel, deduplicated.
async fn resolve(entries: &[String]) -> Vec<SocketAddr> {
    let jobs = entries.iter().cloned().map(|e| async move {
        let found = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(e)).await.ok()?.ok()?;
        found.into_iter().find(SocketAddr::is_ipv4)
    });
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in futures::future::join_all(jobs).await.into_iter().flatten() {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

fn rnd() -> [u8; 16] {
    uuid::Uuid::new_v4().into_bytes()
}
fn new_tid() -> u32 {
    u32::from_be_bytes(rnd()[..4].try_into().unwrap())
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

fn connect_pkt(tid: u32) -> Vec<u8> {
    let mut p = PROTOCOL_ID.to_be_bytes().to_vec();
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&tid.to_be_bytes());
    p
}

/// event: 0 none, 2 started, 3 stopped.
fn announce_pkt(conn: u64, tid: u32, ih: &[u8; 20], peer_id: &[u8; 20], event: u32, port: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(98);
    p.extend_from_slice(&conn.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&tid.to_be_bytes());
    p.extend_from_slice(ih);
    p.extend_from_slice(peer_id);
    p.extend_from_slice(&0u64.to_be_bytes()); // downloaded
    p.extend_from_slice(&1u64.to_be_bytes()); // left (never "seeding")
    p.extend_from_slice(&0u64.to_be_bytes()); // uploaded
    p.extend_from_slice(&event.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // ip = use source
    p.extend_from_slice(&new_tid().to_be_bytes()); // key
    p.extend_from_slice(&(-1i32).to_be_bytes()); // num_want = default
    p.extend_from_slice(&port.to_be_bytes());
    p
}

/// Compact IPv4 peers (6 bytes each) of an announce response body.
fn parse_peers(body: &[u8]) -> Vec<SocketAddr> {
    body.chunks_exact(6)
        .map(|c| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3])), u16::from_be_bytes([c[4], c[5]])))
        .collect()
}

#[derive(PartialEq)]
enum Dead {
    Timeout,
    Errors,
}

struct Pending {
    tid: u32,
    announce: bool,
    sent: Instant,
    tries: usize,
}

struct T {
    addr: SocketAddr,
    conn: Option<(u64, Instant)>,
    pend: Option<Pending>,
    next: Instant,
    errs: u32,
    answered: bool,
    announced: bool,
    dead: Option<Dead>,
}

struct Run {
    sock: Arc<UdpSocket>,
    ts: Vec<T>,
    ih: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    start: Instant,
}

/// Re-announce interval after `elapsed_secs` of a run: 2 s, then 5 s from 20 s, 30 s from 60 s.
pub fn cadence_at(elapsed_secs: u64) -> Duration {
    Duration::from_secs(if elapsed_secs < 20 { 2 } else if elapsed_secs < 60 { 5 } else { 30 })
}

impl Run {
    fn cadence(&self) -> Duration {
        cadence_at(self.start.elapsed().as_secs())
    }

    /// Announce again now (once): the host just learned a client through another method.
    fn nudge(&mut self) {
        let now = Instant::now();
        for t in self.ts.iter_mut().filter(|t| t.dead.is_none() && t.pend.is_none()) {
            t.next = now;
        }
    }

    fn pkt(&self, t: &T, p: &Pending) -> Vec<u8> {
        match (p.announce, t.conn) {
            (true, Some((c, _))) => announce_pkt(c, p.tid, &self.ih, &self.peer_id, if t.announced { 0 } else { 2 }, self.port),
            _ => connect_pkt(p.tid),
        }
    }

    async fn xmit(&mut self, i: usize, p: Pending) {
        let bytes = self.pkt(&self.ts[i], &p);
        self.ts[i].pend = Some(p);
        if self.sock.send_to(&bytes, self.ts[i].addr).await.is_err() && !self.ts[i].answered {
            self.ts[i].dead = Some(Dead::Timeout); // no route / unreachable network
        }
    }

    /// Timers: retransmit, give up, start the next CONNECT/ANNOUNCE.
    async fn drive(&mut self) {
        let now = Instant::now();
        for i in 0..self.ts.len() {
            if self.ts[i].dead.is_some() {
                continue;
            }
            if let Some(p) = &self.ts[i].pend {
                if now.duration_since(p.sent) < RTO[p.tries - 1] {
                    continue;
                }
                if p.tries < RTO.len() {
                    let np = Pending { tid: p.tid, announce: p.announce, sent: now, tries: p.tries + 1 };
                    self.xmit(i, np).await;
                } else {
                    let t = &mut self.ts[i];
                    t.pend = None;
                    t.conn = None;
                    if t.answered {
                        t.next = now + Duration::from_secs(5);
                    } else {
                        t.dead = Some(Dead::Timeout);
                    }
                }
            } else if now >= self.ts[i].next {
                let live = matches!(self.ts[i].conn, Some((_, at)) if at.elapsed() < CONN_TTL);
                self.xmit(i, Pending { tid: new_tid(), announce: live, sent: now, tries: 1 }).await;
            }
        }
    }

    /// One datagram. `Some(peers)` when it answered an announce.
    async fn handle(&mut self, from: SocketAddr, d: &[u8]) -> Option<Vec<SocketAddr>> {
        let i = self.ts.iter().position(|t| t.addr == from)?;
        let p = self.ts[i].pend.as_ref()?;
        if d.len() < 8 || u32_at(d, 4) != p.tid {
            return None;
        }
        let (announce, now) = (p.announce, Instant::now());
        match (u32_at(d, 0), announce) {
            (0, false) if d.len() >= 16 => {
                let t = &mut self.ts[i];
                t.conn = Some((u64::from_be_bytes(d[8..16].try_into().unwrap()), now));
                t.answered = true;
                self.xmit(i, Pending { tid: new_tid(), announce: true, sent: now, tries: 1 }).await;
            }
            (1, true) if d.len() >= 20 => {
                let cad = self.cadence();
                let t = &mut self.ts[i];
                t.pend = None;
                t.announced = true;
                t.next = now + cad;
                return Some(parse_peers(&d[20..]));
            }
            (3, _) => {
                let t = &mut self.ts[i];
                t.pend = None;
                t.conn = None;
                t.errs += 1;
                t.next = now + ERR_BACKOFF;
                if t.errs >= MAX_ERRORS {
                    t.dead = Some(Dead::Errors);
                }
            }
            _ => {}
        }
        None
    }
}

#[async_trait::async_trait]
impl Rendezvous for Trackers {
    fn id(&self) -> &'static str {
        "trk"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Public BitTorrent trackers",
            shared: &[
                "your public IP address and port, the time, and a random-looking code derived from the invite",
                "tracker operators can see BOTH peers' addresses in plaintext",
            ],
            not_shared: &["your traffic", "the invite key", "anything readable about what you are doing"],
            why: "to tell the other device where you are so both can connect directly",
            operator: "volunteer-run public BitTorrent trackers; no uptime promise",
        }
    }

    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let entries = match self.entries() {
            Ok(e) => e,
            Err(e) => return ProbeStatus::Error(e),
        };
        let addrs = resolve(&entries).await;
        if addrs.is_empty() {
            return ProbeStatus::Error("no resolvable tracker".into());
        }
        let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
            Ok(s) => s,
            Err(e) => return ProbeStatus::Error(format!("bind: {e}")),
        };
        let tids: Vec<u32> = addrs.iter().map(|_| new_tid()).collect();
        let start = Instant::now();
        let at = [Duration::ZERO, Duration::from_secs(1), Duration::from_secs(3)]; // CONNECT only
        let (mut sent, mut buf) = (0, [0u8; 512]);
        loop {
            let el = start.elapsed();
            if el >= timeout {
                return ProbeStatus::Blocked("no tracker answered".into());
            }
            if sent < at.len() && el >= at[sent] {
                for (a, t) in addrs.iter().zip(&tids) {
                    let _ = sock.send_to(&connect_pkt(*t), a).await;
                }
                sent += 1;
            }
            let wake = at.get(sent).copied().unwrap_or(timeout).min(timeout);
            let wait = wake.saturating_sub(el).max(Duration::from_millis(5));
            if let Ok(Ok((n, from))) = tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
                if let Some(i) = addrs.iter().position(|a| *a == from) {
                    if n >= 16 && u32_at(&buf, 0) == 0 && u32_at(&buf, 4) == tids[i] {
                        return ProbeStatus::Reachable { rtt_ms: start.elapsed().as_millis().max(1) as u32 };
                    }
                }
            }
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let Some(port) = ctx.local.iter().find(|a| a.is_ipv4()).map(|a| a.port()) else {
            return Err(RvError::Failed("no mapped address".into()));
        };
        let entries = self.entries().map_err(RvError::Failed)?;
        let addrs = resolve(&entries).await;
        if addrs.is_empty() {
            return Err(RvError::Blocked("no resolvable tracker".into()));
        }
        let sock = match &ctx.sock {
            Some(s) => s.clone(),
            None => Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.map_err(|e| RvError::Failed(format!("bind: {e}")))?),
        };
        let now = Instant::now();
        let mut peer_id = [0u8; 20];
        peer_id[..16].copy_from_slice(&rnd());
        peer_id[16..].copy_from_slice(&rnd()[..4]);
        let mut r = Run {
            sock,
            ts: addrs
                .into_iter()
                .map(|addr| T { addr, conn: None, pend: None, next: now, errs: 0, answered: false, announced: false, dead: None })
                .collect(),
            ih: ctx.derived().room_info_hash(),
            peer_id,
            port,
            start: now,
        };
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        let (mut published, mut have_peer) = (false, false);
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut buf = [0u8; 2048];
        loop {
            let mut peers = vec![];
            tokio::select! {
                _ = cancel.cancelled() => {
                    for t in &r.ts {
                        if let (true, Some((c, _))) = (t.announced, t.conn) {
                            let b = announce_pkt(c, new_tid(), &r.ih, &r.peer_id, 3, r.port);
                            let _ = r.sock.send_to(&b, t.addr).await;
                        }
                    }
                    return Ok(());
                }
                got = r.sock.recv_from(&mut buf) => {
                    if let Ok((n, from)) = got {
                        if let Some(p) = r.handle(from, &buf[..n]).await {
                            peers = p;
                            if !published {
                                published = true;
                                ctx.status.set(Status::Publishing);
                            } else if !have_peer {
                                ctx.status.set(Status::Waiting);
                            }
                        }
                    }
                }
                _ = tick.tick() => r.drive().await,
                _ = ctx.nudge.notified() => r.nudge(),
            }
            for a in peers {
                if a.port() == 0 || ctx.local.contains(&a) || !seen.insert(a) {
                    continue;
                }
                match tx.try_send(Candidate { addr: a, via: "trk" }) {
                    Ok(()) => have_peer = true,
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    Err(_) => {
                        seen.remove(&a); // queue full: seen again at the next announce
                    }
                }
            }
            if r.ts.iter().all(|t| t.dead.is_some()) {
                let blocked = r.ts.iter().all(|t| t.dead == Some(Dead::Timeout));
                let m = format!("all {} trackers failed", r.ts.len());
                return Err(if blocked { RvError::Blocked(m) } else { RvError::Failed(m) });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_list_never_falls_back_to_defaults() {
        let t = |l: &[&str]| Trackers::new(&RvConfig { trackers: l.iter().map(|s| s.to_string()).collect(), ..Default::default() }).entries();
        assert_eq!(t(&[]).unwrap().len(), DEFAULT_TRACKERS.len());
        assert_eq!(t(&["udp://t.example:6969/announce"]).unwrap(), vec!["t.example:6969"]);
        assert!(t(&["https://t.example/announce"]).is_err());
        assert!(t(&["t.example:6969", "http://x"]).is_err());
    }
}
