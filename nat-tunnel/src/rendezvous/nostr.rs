//! `nostr` rendezvous backend: the sealed candidates ride as tiny events on public Nostr relays.
//!
//! Per run a throwaway secp256k1 key signs everything. Each relay gets two kinds of event
//! carrying the same sealed blob (base64 in `content`, hashed room tag as `r` tag):
//! an ephemeral kind 20077 (fast path, repeated) and one addressable kind 30077 (`d` tag = room
//! tag + role, refreshed) so a late joiner still finds it. We subscribe to both kinds by `r`
//! tag and `open()` everything we see; failures (own role, stale, tampered) are ignored.
//! Live behaviour of the four default relays: `docs/research/live-nostr-test.md`.
//!
//! `ws://` URLs are plain TCP (tests / local relays); `wss://` is the default.
//! shortcut: the WebSocket client is hand-rolled (no Sec-WebSocket-Accept check, no
//! compression); the sealed AEAD authenticates the payload anyway. Upgrade if we need more.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use secp256k1::{All, Keypair, Secp256k1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::derive::{hex, open, seal, Derived};
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvConfig, RvCtx, RvError, Status, StatusSink};

const DEFAULT_RELAYS: [&str; 4] =
    ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net", "wss://offchain.pub"];
const KIND_EPH: u64 = 20077;
const KIND_REP: u64 = 30077;
const MIN_GAP: Duration = Duration::from_millis(2500);
const BUDGET_EVENTS: usize = 25;
const BUDGET_WINDOW: Duration = Duration::from_secs(600);
const MAX_CONNECT_FAILS: u32 = 4;
const SINCE_SECS: u64 = 120;

pub struct Nostr {
    cfg: RvConfig,
}

impl Nostr {
    pub fn new(cfg: &RvConfig) -> Self {
        Self { cfg: cfg.clone() }
    }
    fn relays(&self) -> Vec<String> {
        if self.cfg.relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            self.cfg.relays.clone()
        }
    }
}

#[async_trait::async_trait]
impl Rendezvous for Nostr {
    fn id(&self) -> &'static str {
        "nostr"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Nostr relays",
            shared: &["your IP address (to the relays), timing, a random-looking tag, and an unreadable sealed message"],
            not_shared: &["your traffic", "the invite key", "your address in readable form"],
            why: "to tell the other device where you are so both can connect directly",
            operator: "independent public Nostr relays (damus.io, nos.lol, primal.net, offchain.pub); no uptime promise",
        }
    }

    /// TCP + TLS + WebSocket upgrade per relay, then drop the socket. Publishes nothing.
    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let mut set = JoinSet::new();
        for url in self.relays() {
            set.spawn(async move {
                let t = Instant::now();
                ws::connect(&url).await.map(|_| t.elapsed().as_millis() as u32)
            });
        }
        let mut last = String::from("no relay answered");
        let wait = async {
            while let Some(r) = set.join_next().await {
                match r {
                    Ok(Ok(ms)) => return Some(ms),
                    Ok(Err(e)) => last = e.to_string(),
                    Err(_) => {}
                }
            }
            None
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(Some(rtt_ms)) => ProbeStatus::Reachable { rtt_ms },
            Ok(None) => ProbeStatus::Blocked(last),
            Err(_) => ProbeStatus::Blocked("timed out".into()),
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let d = ctx.derived();
        seal(&d, ctx.role, &ctx.local).map_err(|e| RvError::Failed(format!("cannot seal candidates: {e}")))?;
        let secp = Secp256k1::new();
        let mut sk = [0u8; 32];
        let kp = loop {
            OsRng.fill_bytes(&mut sk);
            if let Ok(k) = Keypair::from_seckey_slice(&secp, &sk) {
                break k;
            }
        };
        let sh = Arc::new(Shared {
            room: d.room_hex(),
            d,
            role: ctx.role,
            local: ctx.local.clone(),
            secp,
            kp,
            tx,
            seen: Mutex::new(HashSet::new()),
            published: AtomicBool::new(false),
            status: ctx.status.clone(),
            start: Instant::now(),
        });
        sh.status.set(Status::Waiting);

        let mut set = JoinSet::new();
        for url in self.relays() {
            set.spawn(relay_loop(sh.clone(), url, cancel.clone()));
        }
        let mut errs: Vec<(bool, String)> = Vec::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    // relay tasks see the token too and close their sockets; bound the wait.
                    let _ = tokio::time::timeout(Duration::from_millis(700), async { while set.join_next().await.is_some() {} }).await;
                    set.abort_all();
                    return Ok(());
                }
                r = set.join_next() => match r {
                    Some(Ok(End::Gave(blockish, msg))) => errs.push((blockish, msg)),
                    Some(_) => {}
                    None => break,
                },
            }
        }
        if cancel.is_cancelled() {
            return Ok(());
        }
        let msg = errs.iter().map(|e| e.1.as_str()).collect::<Vec<_>>().join("; ");
        if !errs.is_empty() && errs.iter().all(|e| e.0) {
            Err(RvError::Blocked(msg))
        } else {
            Err(RvError::Failed(msg))
        }
    }
}

struct Shared {
    d: Derived,
    room: String,
    role: Role,
    local: Vec<SocketAddr>,
    secp: Secp256k1<All>,
    kp: Keypair,
    tx: mpsc::Sender<Candidate>,
    seen: Mutex<HashSet<SocketAddr>>,
    published: AtomicBool,
    status: StatusSink,
    start: Instant,
}

enum End {
    Cancelled,
    /// Gave up on this relay: (every error was connect-level, message).
    Gave(bool, String),
}

/// Per-relay publishing state; survives reconnects so politeness limits hold.
struct Pace {
    hist: VecDeque<Instant>,
    last: Option<Instant>,
    stopped: bool,
    next_eph: Instant,
    next_rep: Instant,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn sleep_or_cancel(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! { _ = cancel.cancelled() => true, _ = tokio::time::sleep(d) => false }
}

async fn relay_loop(sh: Arc<Shared>, url: String, cancel: CancellationToken) -> End {
    let now = Instant::now();
    let mut pace = Pace { hist: VecDeque::new(), last: None, stopped: false, next_eph: now, next_rep: now };
    let (mut fails, mut ever) = (0u32, false);
    loop {
        let conn = tokio::select! { _ = cancel.cancelled() => return End::Cancelled, r = ws::connect(&url) => r };
        match conn {
            Err(e) => {
                fails += 1;
                log::debug!("nostr {url}: connect failed ({fails}): {e}");
                if fails >= MAX_CONNECT_FAILS {
                    return End::Gave(!ever, format!("{url}: {e}"));
                }
                if sleep_or_cancel(Duration::from_secs(1 << (fails - 1)), &cancel).await {
                    return End::Cancelled;
                }
            }
            Ok(mut w) => {
                fails = 0;
                ever = true;
                match session(&sh, &mut w, &url, &mut pace, &cancel).await {
                    Ok(()) | Err(SessionEnd::Receiver) => return End::Cancelled,
                    Err(SessionEnd::Io(e)) => {
                        log::debug!("nostr {url}: dropped: {e}");
                        if sleep_or_cancel(Duration::from_secs(1), &cancel).await {
                            return End::Cancelled;
                        }
                    }
                }
            }
        }
    }
}

enum SessionEnd {
    Io(std::io::Error),
    /// The runner stopped listening for candidates.
    Receiver,
}
impl From<std::io::Error> for SessionEnd {
    fn from(e: std::io::Error) -> Self {
        SessionEnd::Io(e)
    }
}

async fn session(sh: &Shared, w: &mut ws::Ws, url: &str, pace: &mut Pace, cancel: &CancellationToken) -> Result<(), SessionEnd> {
    let req = json!(["REQ", "r", {"kinds": [KIND_EPH, KIND_REP], "#r": [&sh.room], "since": now_secs().saturating_sub(SINCE_SECS)}]);
    w.send(1, req.to_string().as_bytes()).await?;
    pace.next_eph = Instant::now();
    pace.next_rep = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                w.close().await;
                return Ok(());
            }
            f = w.recv() => match f? {
                ws::Frame::Ping(p) => w.send(10, &p).await?,
                ws::Frame::Text(t) => {
                    for c in on_message(sh, pace, url, &t) {
                        if sh.tx.send(Candidate { addr: c, via: "nostr" }).await.is_err() {
                            return Err(SessionEnd::Receiver);
                        }
                    }
                }
            },
            _ = tick.tick() => {
                if let Some(msg) = due_event(sh, pace) {
                    w.send(1, msg.as_bytes()).await?;
                }
            }
        }
    }
}

/// The next event to publish if the schedule, the 2.5 s spacing and the per-10-min budget allow.
fn due_event(sh: &Shared, p: &mut Pace) -> Option<String> {
    let now = Instant::now();
    if p.stopped || p.last.is_some_and(|t| now.duration_since(t) < MIN_GAP) {
        return None;
    }
    while p.hist.front().is_some_and(|t| now.duration_since(*t) > BUDGET_WINDOW) {
        p.hist.pop_front();
    }
    if p.hist.len() >= BUDGET_EVENTS {
        return None;
    }
    let (kind, tags) = if now >= p.next_eph {
        let early = sh.start.elapsed() < Duration::from_secs(30);
        // Gentle: the stored (replaceable) event already serves late joiners, and public relays
        // (damus) answer "rate-limited: you are noting too much" to anything chattier.
        p.next_eph = now + Duration::from_secs(if early { 10 } else { 45 });
        (KIND_EPH, json!([["r", sh.room]]))
    } else if now >= p.next_rep {
        p.next_rep = now + Duration::from_secs(120);
        let role = if sh.role == Role::Host { "host" } else { "client" };
        (KIND_REP, json!([["d", format!("{}{role}", sh.room)], ["r", sh.room]]))
    } else {
        return None;
    };
    let content = b64_encode(&seal(&sh.d, sh.role, &sh.local).ok()?);
    let ev = sign_event(&sh.secp, &sh.kp, now_secs(), kind, tags, content);
    p.last = Some(now);
    p.hist.push_back(now);
    Some(json!(["EVENT", ev]).to_string())
}

fn sign_event(secp: &Secp256k1<All>, kp: &Keypair, created_at: u64, kind: u64, tags: Value, content: String) -> Value {
    let pubkey = hex(&kp.x_only_public_key().0.serialize());
    let ser = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    let id = Sha256::digest(ser.as_bytes());
    let sig = secp.sign_schnorr_no_aux_rand(&secp256k1::Message::from_digest(id.into()), kp);
    json!({"id": hex(&id), "pubkey": pubkey, "created_at": created_at, "kind": kind, "tags": tags, "content": content, "sig": hex(sig.as_ref())})
}

/// Handles one relay message; returns newly seen peer addresses.
fn on_message(sh: &Shared, pace: &mut Pace, url: &str, text: &str) -> Vec<SocketAddr> {
    let Ok(v) = serde_json::from_str::<Value>(text) else { return vec![] };
    match v[0].as_str() {
        Some("OK") => {
            if v[2].as_bool() == Some(true) {
                if !sh.published.swap(true, SeqCst) {
                    sh.status.set(Status::Publishing);
                }
            } else {
                let reason = v[3].as_str().unwrap_or("");
                log::debug!("nostr {url}: event refused: {reason}");
                if reason.starts_with("rate-limited:") {
                    // Temporary: a long-running host must not lose a relay for good over a burst.
                    log::info!("nostr {url}: rate-limited ({reason}); pausing publishes there for 5 minutes");
                    let until = Instant::now() + Duration::from_secs(300);
                    pace.next_eph = until;
                    pace.next_rep = until;
                } else if ["blocked:", "restricted:", "auth-required:"].iter().any(|p| reason.starts_with(p)) {
                    log::info!("nostr {url}: relay asked us to stop ({reason}); not publishing there any more");
                    pace.stopped = true;
                }
            }
            vec![]
        }
        Some("EVENT") => {
            let e = &v[2];
            let kind = e["kind"].as_u64().unwrap_or(0);
            let tagged = e["tags"].as_array().is_some_and(|t| t.iter().any(|t| t[0] == "r" && t[1] == sh.room.as_str()));
            if (kind != KIND_EPH && kind != KIND_REP) || !tagged {
                return vec![];
            }
            let Some(blob) = e["content"].as_str().and_then(b64_decode) else { return vec![] };
            let Ok(addrs) = open(&sh.d, sh.role, &blob) else { return vec![] };
            let mut seen = sh.seen.lock().unwrap();
            addrs.into_iter().filter(|a| seen.insert(*a)).collect()
        }
        Some("NOTICE") | Some("CLOSED") => {
            log::debug!("nostr {url}: {text:.200}");
            vec![]
        }
        _ => vec![],
    }
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(s.len() * 3 / 4));
    for ch in s.bytes() {
        acc = acc << 6 | B64.iter().position(|&x| x == ch)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Minimal WebSocket client over TCP or rustls.
mod ws {
    use std::fmt;
    use std::io;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::OsRng;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::b64_encode;

    const MAX_MSG: usize = 1 << 20;
    const UA: &str = "Mozilla/5.0"; // relays 403 default library user agents

    #[derive(Debug)]
    pub enum ConnErr {
        /// TCP / TLS / timeout / garbage.
        Net(String),
        /// The HTTP status of a refused upgrade (403, 503, ...).
        Http(u16),
    }
    impl fmt::Display for ConnErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ConnErr::Net(s) => f.write_str(s),
                ConnErr::Http(c) => write!(f, "HTTP {c}"),
            }
        }
    }

    trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

    pub struct Ws {
        io: Box<dyn Io>,
        buf: Vec<u8>,
        msg: Vec<u8>,
    }

    pub enum Frame {
        Text(String),
        Ping(Vec<u8>),
    }

    fn tls() -> Arc<rustls::ClientConfig> {
        static C: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        C.get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default protocol versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
    }

    /// `(tls, host, port, path)` from `ws://` / `wss://` URLs (hostnames or IPv4 only).
    pub fn parse_url(u: &str) -> Option<(bool, String, u16, String)> {
        let (tls, rest) = if let Some(r) = u.strip_prefix("wss://") {
            (true, r)
        } else {
            (false, u.strip_prefix("ws://")?)
        };
        let (hp, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match hp.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (hp, if tls { 443 } else { 80 }),
        };
        (!host.is_empty()).then(|| (tls, host.to_string(), port, path.to_string()))
    }

    pub async fn connect(url: &str) -> Result<Ws, ConnErr> {
        tokio::time::timeout(Duration::from_secs(10), connect_inner(url))
            .await
            .unwrap_or_else(|_| Err(ConnErr::Net("connect timed out".into())))
    }

    async fn connect_inner(url: &str) -> Result<Ws, ConnErr> {
        let net = |e: io::Error| ConnErr::Net(e.to_string());
        let (use_tls, host, port, path) = parse_url(url).ok_or_else(|| ConnErr::Net(format!("bad relay url {url}")))?;
        let tcp = TcpStream::connect((host.as_str(), port)).await.map_err(net)?;
        let _ = tcp.set_nodelay(true);
        let mut io: Box<dyn Io> = if use_tls {
            let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| ConnErr::Net(e.to_string()))?;
            Box::new(tokio_rustls::TlsConnector::from(tls()).connect(name, tcp).await.map_err(net)?)
        } else {
            Box::new(tcp)
        };
        let mut k = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        let hostport = if port == if use_tls { 443 } else { 80 } { host.clone() } else { format!("{host}:{port}") };
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {UA}\r\n\r\n",
            b64_encode(&k)
        );
        io.write_all(req.as_bytes()).await.map_err(net)?;
        let mut buf = Vec::new();
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if buf.len() > 16 * 1024 {
                return Err(ConnErr::Net("oversized upgrade response".into()));
            }
            let mut tmp = [0u8; 2048];
            let n = io.read(&mut tmp).await.map_err(net)?;
            if n == 0 {
                return Err(ConnErr::Net("closed during upgrade".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        if code != 101 {
            return Err(if code == 0 { ConnErr::Net("not an HTTP response".into()) } else { ConnErr::Http(code) });
        }
        buf.drain(..end);
        Ok(Ws { io, buf, msg: Vec::new() })
    }

    impl Ws {
        pub async fn send(&mut self, op: u8, data: &[u8]) -> io::Result<()> {
            let n = data.len();
            let mut f = vec![0x80 | op];
            if n < 126 {
                f.push(0x80 | n as u8);
            } else if n < 65536 {
                f.push(0x80 | 126);
                f.extend((n as u16).to_be_bytes());
            } else {
                f.push(0x80 | 127);
                f.extend((n as u64).to_be_bytes());
            }
            let mut m = [0u8; 4];
            OsRng.fill_bytes(&mut m);
            f.extend(m);
            f.extend(data.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
            tokio::time::timeout(Duration::from_secs(10), self.io.write_all(&f))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        }

        pub async fn close(&mut self) {
            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                let _ = self.send(8, &[]).await;
                let _ = self.io.shutdown().await;
            })
            .await;
        }

        /// Cancel-safe: partial reads stay in `self.buf`.
        pub async fn recv(&mut self) -> io::Result<Frame> {
            loop {
                if let Some(f) = self.parse()? {
                    return Ok(f);
                }
                let mut tmp = [0u8; 8192];
                let n = self.io.read(&mut tmp).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }

        fn parse(&mut self) -> io::Result<Option<Frame>> {
            let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
            loop {
                let b = &self.buf;
                if b.len() < 2 {
                    return Ok(None);
                }
                let (fin, op, masked) = (b[0] & 0x80 != 0, b[0] & 0xf, b[1] & 0x80 != 0);
                let (mut n, mut o) = ((b[1] & 0x7f) as usize, 2usize);
                if n == 126 || n == 127 {
                    let w = if n == 126 { 2 } else { 8 };
                    if b.len() < 2 + w {
                        return Ok(None);
                    }
                    let v = b[2..2 + w].iter().fold(0u64, |a, x| a << 8 | *x as u64);
                    n = usize::try_from(v).unwrap_or(usize::MAX);
                    o = 2 + w;
                }
                if n > MAX_MSG {
                    return Err(bad("frame too large"));
                }
                let mo = if masked { 4 } else { 0 };
                if b.len() < o + mo + n {
                    return Ok(None);
                }
                let mut pl = b[o + mo..o + mo + n].to_vec();
                if masked {
                    let m = [b[o], b[o + 1], b[o + 2], b[o + 3]];
                    pl.iter_mut().enumerate().for_each(|(i, x)| *x ^= m[i % 4]);
                }
                self.buf.drain(..o + mo + n);
                match op {
                    8 => return Err(io::ErrorKind::UnexpectedEof.into()),
                    9 => return Ok(Some(Frame::Ping(pl))),
                    0 | 1 => {
                        self.msg.extend(pl);
                        if self.msg.len() > MAX_MSG {
                            return Err(bad("message too large"));
                        }
                        if fin {
                            let t = String::from_utf8_lossy(&std::mem::take(&mut self.msg)).into_owned();
                            return Ok(Some(Frame::Text(t)));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_known() {
        for n in 0..40 {
            let v: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&v)).unwrap(), v);
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert!(b64_decode("a$b").is_none());
    }

    fn hex_dec(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn signed_event_verifies_and_tamper_fails() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let e = sign_event(&secp, &kp, 1_700_000_000, KIND_EPH, json!([["r", "x"]]), "abc".into());
        let id = hex_dec(e["id"].as_str().unwrap());
        let sig = secp256k1::schnorr::Signature::from_slice(&hex_dec(e["sig"].as_str().unwrap())).unwrap();
        let (xo, _) = kp.x_only_public_key();
        assert!(secp.verify_schnorr(&sig, &secp256k1::Message::from_digest_slice(&id).unwrap(), &xo).is_ok());
        assert!(secp.verify_schnorr(&sig, &secp256k1::Message::from_digest([0u8; 32]), &xo).is_err());
    }

    #[test]
    fn urls() {
        assert_eq!(ws::parse_url("wss://nos.lol").unwrap(), (true, "nos.lol".into(), 443, "/".into()));
        assert_eq!(ws::parse_url("ws://127.0.0.1:9/x").unwrap(), (false, "127.0.0.1".into(), 9, "/x".into()));
        assert!(ws::parse_url("http://x").is_none());
    }
}
