//! `ntfy` rendezvous backend: ntfy.sh-compatible HTTP(S) pub/sub (a self-hosted server speaks the
//! same API; set `RvConfig::ntfy_base`, `http://` works too).
//!
//! Each side POSTs its sealed candidate blob (base64 text) to `<base>/<topic>` and keeps a
//! streaming `GET <base>/<topic>/json?since=2m` open; every message body is `open()`ed and
//! failures (own role, stale, bad tag) are ignored. The server's 12 h cache lets a late joiner
//! read the blob that was published before it subscribed.
//!
//! Publish frequency (documented limit, ntfy.sh allows a burst of 60 then 1 per 5 s per IP):
//! at start, then every 6 s for the first 30 s, then every 30 s, i.e. never more than 1 per 6 s.
//! HTTP 429 is honoured (`Retry-After`, default 10 s); a third 429 in a row, or 403/451, stops
//! the method for the session (`Blocked`). Stream reconnects wait >= 1 s with exponential backoff.
//! User-Agent is the fixed string `strait-rendezvous`.
//!
//! The HTTP/1.1 client is deliberately tiny (Connection: close, chunked/length/EOF bodies) to
//! avoid pulling in hyper/reqwest; TLS is rustls + webpki roots.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use super::derive::{open, seal};
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, RvConfig, RvCtx, RvError, Status};

const DEFAULT_BASE: &str = "https://ntfy.sh";
const UA: &str = "strait-rendezvous";

/// Intervals; `Default` is the production schedule. Tests scale them down.
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct Timing {
    pub fast: Duration,
    pub slow: Duration,
    pub fast_for: Duration,
    /// Minimum wait before a stream reconnect.
    pub reconnect: Duration,
    /// Stream idle limit (ntfy sends keepalives every 45 s).
    pub idle: Duration,
    /// Connect+TLS and response-head limit.
    pub io: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            fast: Duration::from_secs(6),
            slow: Duration::from_secs(30),
            fast_for: Duration::from_secs(30),
            reconnect: Duration::from_secs(1),
            idle: Duration::from_secs(90),
            io: Duration::from_secs(10),
        }
    }
}

pub struct Ntfy {
    base: String,
    timing: Timing,
    extra_root: Option<Vec<u8>>,
}

impl Ntfy {
    pub fn new(cfg: &RvConfig) -> Self {
        let base = cfg.ntfy_base.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| DEFAULT_BASE.into());
        Self { base, timing: Timing::default(), extra_root: None }
    }
    #[doc(hidden)]
    pub fn with_timing(mut self, t: Timing) -> Self {
        self.timing = t;
        self
    }
    /// Test-only trust hook: also trust this DER root/leaf certificate.
    #[doc(hidden)]
    pub fn with_extra_root(mut self, der: Vec<u8>) -> Self {
        self.extra_root = Some(der);
        self
    }
    fn http(&self) -> Result<Http, RvError> {
        Http::new(&self.base, self.timing, self.extra_root.as_deref())
    }
}

// ---------- tiny HTTP client ----------

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Http {
    tls: Option<tokio_rustls::TlsConnector>,
    host: String,
    port: u16,
    prefix: String,
    t: Timing,
}

fn blocked(e: impl std::fmt::Display) -> RvError {
    RvError::Blocked(e.to_string())
}

impl Http {
    fn new(base: &str, t: Timing, extra_root: Option<&[u8]>) -> Result<Self, RvError> {
        let base = base.trim();
        let (tls_on, rest) = match base.split_once("://") {
            Some(("https", r)) => (true, r),
            Some(("http", r)) => (false, r),
            Some((s, _)) => return Err(RvError::Failed(format!("unsupported ntfy URL scheme {s:?}"))),
            None => (true, base),
        };
        let (auth, prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
            None => (rest, String::new()),
        };
        let default_port = if tls_on { 443 } else { 80 };
        let (host, port) = match auth.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(':') || h.starts_with('[') => {
                (h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse::<u16>().map_err(|_| RvError::Failed("bad port in ntfy URL".into()))?)
            }
            _ => (auth.trim_matches(|c| c == '[' || c == ']').to_string(), default_port),
        };
        if host.is_empty() {
            return Err(RvError::Failed("empty host in ntfy URL".into()));
        }
        let tls = if tls_on {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(der) = extra_root {
                roots.add(rustls::pki_types::CertificateDer::from(der.to_vec())).map_err(|e| RvError::Failed(e.to_string()))?;
            }
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| RvError::Failed(e.to_string()))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Some(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
        } else {
            None
        };
        Ok(Self { tls, host, port, prefix, t })
    }

    async fn connect(&self) -> Result<Box<dyn Io>, RvError> {
        let work = async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port)).await.map_err(|e| blocked(format!("cannot connect to {}: {e}", self.host)))?;
            let _ = tcp.set_nodelay(true);
            match &self.tls {
                None => Ok(Box::new(tcp) as Box<dyn Io>),
                Some(c) => {
                    let name = rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(blocked)?;
                    let s = c.connect(name, tcp).await.map_err(|e| blocked(format!("TLS to {} failed: {e}", self.host)))?;
                    Ok(Box::new(s) as Box<dyn Io>)
                }
            }
        };
        timeout(self.t.io, work).await.unwrap_or_else(|_| Err(blocked(format!("connecting to {} timed out", self.host))))
    }

    async fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Resp, RvError> {
        let mut io = self.connect().await?;
        let hostport = if self.port == if self.tls.is_some() { 443 } else { 80 } { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
        let mut req = format!("{method} {}{path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n", self.prefix);
        if let Some(b) = body {
            req += &format!("Content-Type: text/plain\r\nContent-Length: {}\r\n", b.len());
        }
        req += "\r\n";
        if let Some(b) = body {
            req += b;
        }
        let fail = |e: io::Error| RvError::Failed(format!("ntfy request failed: {e}"));
        io.write_all(req.as_bytes()).await.map_err(fail)?;
        io.flush().await.map_err(fail)?;
        let mut r = BufReader::new(io);
        let head = async {
            let mut line = String::new();
            r.read_line(&mut line).await?;
            let status: u16 = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
            let (mut retry_after, mut chunked, mut len) = (None, false, None);
            for _ in 0..64 {
                line.clear();
                r.read_line(&mut line).await?;
                let l = line.trim();
                if l.is_empty() {
                    return Ok::<_, io::Error>((status, retry_after, chunked, len));
                }
                if let Some((k, v)) = l.split_once(':') {
                    let v = v.trim();
                    match k.to_ascii_lowercase().as_str() {
                        "retry-after" => retry_after = v.parse::<u64>().ok(),
                        "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                        "content-length" => len = v.parse::<usize>().ok(),
                        _ => {}
                    }
                }
            }
            Err(io::Error::new(io::ErrorKind::InvalidData, "too many headers"))
        };
        let (status, retry_after, chunked, len) = timeout(self.t.io, head)
            .await
            .map_err(|_| RvError::Failed("ntfy response timed out".into()))?
            .map_err(fail)?;
        let mode = if chunked { Mode::Chunked } else if let Some(n) = len { Mode::Len(n) } else { Mode::Eof };
        Ok(Resp { status, retry_after, body: Body { r, mode } })
    }
}

struct Resp {
    status: u16,
    retry_after: Option<u64>,
    body: Body,
}

enum Mode {
    Chunked,
    Len(usize),
    Eof,
    Done,
}

struct Body {
    r: BufReader<Box<dyn Io>>,
    mode: Mode,
}

impl Body {
    /// Next piece of body bytes; `None` at the end.
    async fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.mode {
            Mode::Done => Ok(None),
            Mode::Chunked => {
                let mut l = String::new();
                self.r.read_line(&mut l).await?;
                let n = usize::from_str_radix(l.trim().split(';').next().unwrap_or(""), 16)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
                if n == 0 {
                    self.mode = Mode::Done;
                    return Ok(None);
                }
                if n > 1 << 20 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk too large"));
                }
                let mut v = vec![0u8; n];
                self.r.read_exact(&mut v).await?;
                let mut crlf = [0u8; 2];
                self.r.read_exact(&mut crlf).await?;
                Ok(Some(v))
            }
            Mode::Len(0) => {
                self.mode = Mode::Done;
                Ok(None)
            }
            Mode::Len(_) | Mode::Eof => {
                let cap = if let Mode::Len(l) = self.mode { l.min(4096) } else { 4096 };
                let mut v = vec![0u8; cap];
                let n = self.r.read(&mut v).await?;
                if n == 0 {
                    self.mode = Mode::Done;
                    return Ok(None);
                }
                v.truncate(n);
                if let Mode::Len(l) = &mut self.mode {
                    *l -= n;
                }
                Ok(Some(v))
            }
        }
    }

    /// Whole body, capped at 64 KB.
    async fn all(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(c) = self.next().await? {
            out.extend_from_slice(&c);
            if out.len() > 65536 {
                break;
            }
        }
        Ok(out)
    }
}

// ---------- base64 (standard alphabet, padded) ----------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_enc(b: &[u8]) -> String {
    let mut o = String::new();
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

fn b64_dec(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut o) = (0u32, 0u32, Vec::new());
    for ch in s.trim().trim_end_matches('=').bytes() {
        acc = acc << 6 | B64.iter().position(|&x| x == ch)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            o.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(o)
}

// ---------- the two loops ----------

struct Shared {
    got_peer: AtomicBool,
}

fn publish_interval(t: &Timing, since_start: Duration) -> Duration {
    if since_start < t.fast_for {
        t.fast
    } else {
        t.slow
    }
}

fn retry_wait(ra: Option<u64>) -> Duration {
    Duration::from_secs(ra.unwrap_or(10).clamp(1, 300))
}

async fn publisher(h: &Http, ctx: &RvCtx, topic: &str, sh: &Shared) -> Result<(), RvError> {
    let d = ctx.derived();
    let t0 = Instant::now();
    let (mut ok_once, mut n429, mut fails) = (false, 0u32, 0u32);
    loop {
        // A fresh blob (new timestamp and nonce) every time so the peer's 120 s window never lapses.
        let blob = seal(&d, ctx.role, &ctx.local).map_err(|e| RvError::Failed(format!("cannot seal candidates: {e}")))?;
        let mut wait = publish_interval(&h.t, t0.elapsed());
        match h.request("POST", &format!("/{topic}"), Some(&b64_enc(&blob))).await {
            Ok(r) if (200..300).contains(&r.status) => {
                (n429, fails) = (0, 0);
                if !ok_once {
                    ok_once = true;
                    ctx.status.set(Status::Publishing);
                    if !sh.got_peer.load(Ordering::Relaxed) {
                        ctx.status.set(Status::Waiting);
                    }
                }
            }
            Ok(r) if r.status == 403 || r.status == 451 => return Err(blocked(format!("ntfy refused publishing (HTTP {})", r.status))),
            Ok(r) if r.status == 429 => {
                n429 += 1;
                if n429 >= 3 {
                    return Err(blocked("ntfy keeps rate limiting this address (HTTP 429)"));
                }
                wait = wait.max(retry_wait(r.retry_after));
            }
            Ok(r) => {
                fails += 1;
                if !ok_once || fails >= 3 {
                    return Err(RvError::Failed(format!("ntfy answered HTTP {} to a publish", r.status)));
                }
            }
            Err(e @ RvError::Blocked(_)) if !ok_once => return Err(e),
            Err(e) => {
                fails += 1;
                if fails >= 3 {
                    return Err(RvError::Failed(e.to_string()));
                }
            }
        }
        tokio::select! { _ = sleep(wait) => {}, _ = ctx.nudge.notified() => {} }
    }
}

async fn subscriber(h: &Http, ctx: &RvCtx, topic: &str, tx: &mpsc::Sender<Candidate>, sh: &Shared) -> Result<(), RvError> {
    let d = ctx.derived();
    let (mut since, mut ever, mut fails, mut n429) = ("2m".to_string(), false, 0u32, 0u32);
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    loop {
        let mut wait = h.t.reconnect;
        match h.request("GET", &format!("/{topic}/json?since={since}"), None).await {
            Ok(mut r) if r.status == 200 => {
                ever = true;
                n429 = 0;
                let started = Instant::now();
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let chunk = match timeout(h.t.idle, r.body.next()).await {
                        Ok(Ok(Some(c))) => c,
                        _ => break, // end, error or idle: reconnect
                    };
                    buf.extend_from_slice(&chunk);
                    while let Some(i) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=i).collect();
                        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&line) else { continue };
                        if v["event"] == "open" && !sh.got_peer.load(Ordering::Relaxed) {
                            ctx.status.set(Status::Waiting);
                        }
                        if v["event"] != "message" {
                            continue;
                        }
                        if let Some(id) = v["id"].as_str() {
                            since = id.to_string();
                        }
                        let Some(blob) = v["message"].as_str().and_then(b64_dec) else { continue };
                        let Ok(addrs) = open(&d, ctx.role, &blob) else { continue };
                        for addr in addrs {
                            if seen.insert(addr) {
                                sh.got_peer.store(true, Ordering::Relaxed);
                                if tx.send(Candidate { addr, via: "ntfy" }).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    if buf.len() > 1 << 20 {
                        buf.clear();
                    }
                }
                // A stream that dies right after opening counts as a failure (backoff grows).
                if started.elapsed() < h.t.reconnect * 5 {
                    fails += 1;
                } else {
                    fails = 0;
                }
            }
            Ok(r) if r.status == 403 || r.status == 451 => return Err(blocked(format!("ntfy refused the subscription (HTTP {})", r.status))),
            Ok(r) if r.status == 429 => {
                n429 += 1;
                if n429 >= 3 {
                    return Err(blocked("ntfy keeps rate limiting this address (HTTP 429)"));
                }
                wait = wait.max(retry_wait(r.retry_after));
            }
            Ok(r) => {
                fails += 1;
                if !ever || fails >= 5 {
                    return Err(RvError::Failed(format!("ntfy answered HTTP {} to the subscription", r.status)));
                }
            }
            Err(e @ RvError::Blocked(_)) if !ever => return Err(e),
            Err(e) => {
                fails += 1;
                if fails >= 5 {
                    return Err(RvError::Failed(e.to_string()));
                }
            }
        }
        sleep(wait * 2u32.pow(fails.min(5)).min(30)).await;
    }
}

#[async_trait::async_trait]
impl Rendezvous for Ntfy {
    fn id(&self) -> &'static str {
        "ntfy"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "ntfy (HTTPS pub/sub)",
            shared: &["your IP address, timing, a random-looking topic name and an unreadable sealed message (the operator logs topic names and IP addresses for rate limiting)"],
            not_shared: &["your traffic", "the invite key", "your address in readable form"],
            why: "to tell the other device where you are so both can connect directly",
            operator: "ntfy.sh, run by a single company with rate limits and no uptime promise; you can point this at your own ntfy server",
        }
    }

    async fn probe(&self, limit: Duration) -> ProbeStatus {
        let h = match self.http() {
            Ok(h) => h,
            Err(e) => return ProbeStatus::Error(e.to_string()),
        };
        let t0 = Instant::now();
        let work = async {
            let mut r = h.request("GET", "/v1/health", None).await?;
            let body = r.body.all().await.unwrap_or_default();
            Ok::<_, RvError>((r.status, body))
        };
        match timeout(limit, work).await {
            Err(_) => ProbeStatus::Blocked("no answer from ntfy in time".into()),
            Ok(Err(RvError::Blocked(e))) => ProbeStatus::Blocked(e),
            Ok(Err(e)) => ProbeStatus::Error(e.to_string()),
            Ok(Ok((200, body))) if serde_json::from_slice::<serde_json::Value>(&body).map(|v| v["healthy"] == true).unwrap_or(false) => {
                ProbeStatus::Reachable { rtt_ms: t0.elapsed().as_millis() as u32 }
            }
            Ok(Ok((s @ (403 | 451), _))) => ProbeStatus::Blocked(format!("ntfy refused the request (HTTP {s})")),
            Ok(Ok((s, _))) => ProbeStatus::Error(format!("ntfy is not healthy (HTTP {s})")),
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let h = self.http()?;
        let topic = ctx.derived().room_topic();
        let sh = Shared { got_peer: AtomicBool::new(false) };
        // Dropping the futures on cancel closes their sockets at once.
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            r = publisher(&h, &ctx, &topic, &sh) => r,
            r = subscriber(&h, &ctx, &topic, &tx, &sh) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b64_roundtrip() {
        for n in 0..40u8 {
            let v: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64_dec(&b64_enc(&v)).unwrap(), v);
        }
        assert_eq!(b64_enc(b"Man"), "TWFu");
        assert_eq!(b64_enc(b"Ma"), "TWE=");
        assert!(b64_dec("a!b").is_none());
    }
    #[test]
    fn base_parse() {
        let h = Http::new("http://127.0.0.1:8080/pre/", Timing::default(), None).unwrap();
        assert_eq!((h.host.as_str(), h.port, h.prefix.as_str(), h.tls.is_some()), ("127.0.0.1", 8080, "/pre", false));
        let h = Http::new("https://ntfy.sh", Timing::default(), None).unwrap();
        assert_eq!((h.host.as_str(), h.port, h.tls.is_some()), ("ntfy.sh", 443, true));
        let h = Http::new("http://[::1]:9", Timing::default(), None).unwrap();
        assert_eq!((h.host.as_str(), h.port), ("::1", 9));
        assert!(Http::new("ftp://x", Timing::default(), None).is_err());
    }
}
