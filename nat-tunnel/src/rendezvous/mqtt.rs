//! `mqtt` rendezvous backend: sealed endpoint blobs over public MQTT brokers (TLS 8883).
//!
//! Minimal MQTT 3.1.1 client written here (CONNECT, SUBSCRIBE, PUBLISH QoS 0, PINGREQ,
//! DISCONNECT) over tokio-rustls (ring, webpki roots); no rumqttc, so no extra dependencies.
//!
//! Brokers: `RvConfig.mqtt_broker` (comma list of `host:port`, `mqtts://`/`ssl://`/`tls://` or
//! `mqtt://`/`tcp://` URLs; bare `host:port` is TLS only for port 8883) or the built-in
//! HiveMQ + EMQX list, all used in parallel. Topic `strait/<room_topic>`, never retained.
//!
//! Politeness (per broker): one publish at start, then every 5 s for the first 30 s, then every
//! 20 s; at least 2 s between publishes; at most 25 publishes per 10 minutes; payload < 256 B;
//! random client id per run; reconnect with exponential backoff (1 s doubling, max 60 s) and
//! give up on a broker after 4 consecutive failures; DISCONNECT on cancel. `probe` only
//! connects (CONNECT/CONNACK) and disconnects: it subscribes to and publishes nothing.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use super::derive::{open, seal};
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, RvConfig, RvCtx, RvError, Status};

const DEFAULT_BROKERS: &[&str] = &["broker.hivemq.com:8883", "broker.emqx.io:8883"];
const MAX_PAYLOAD: usize = 256;

/// Timing and retry knobs. The defaults are the documented politeness policy; tests shrink them.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct Tuning {
    pub pub_fast: Duration,
    pub fast_window: Duration,
    pub pub_slow: Duration,
    pub min_gap: Duration,
    pub cap: usize,
    pub cap_window: Duration,
    pub backoff_base: Duration,
    pub max_fails: u32,
    pub keepalive: Duration,
    pub connect_timeout: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            pub_fast: Duration::from_secs(5),
            fast_window: Duration::from_secs(30),
            pub_slow: Duration::from_secs(20),
            min_gap: Duration::from_secs(2),
            cap: 25,
            cap_window: Duration::from_secs(600),
            backoff_base: Duration::from_secs(1),
            max_fails: 4,
            keepalive: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

pub struct Mqtt {
    brokers: Vec<Spec>,
    tun: Tuning,
}

impl Mqtt {
    pub fn new(cfg: &RvConfig) -> Self {
        Self::with_tuning(cfg, Tuning::default())
    }
    #[doc(hidden)]
    pub fn with_tuning(cfg: &RvConfig, tun: Tuning) -> Self {
        let mut brokers: Vec<Spec> = match &cfg.mqtt_broker {
            Some(s) => s.split(',').filter_map(|p| parse_spec(p.trim())).collect(),
            None => Vec::new(),
        };
        if brokers.is_empty() {
            brokers = DEFAULT_BROKERS.iter().filter_map(|s| parse_spec(s)).collect();
        }
        Self { brokers, tun }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Spec {
    host: String,
    port: u16,
    tls: bool,
}

impl Spec {
    fn label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn parse_spec(s: &str) -> Option<Spec> {
    let (scheme, rest) = match s.split_once("://") {
        Some((sc, r)) => (Some(sc.to_ascii_lowercase()), r),
        None => (None, s),
    };
    let rest = rest.trim_end_matches('/');
    let tls_scheme = match scheme.as_deref() {
        Some("mqtts" | "ssl" | "tls") => Some(true),
        Some("mqtt" | "tcp") => Some(false),
        Some(_) => return None,
        None => None,
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok()?)),
        None => (rest, None),
    };
    if host.is_empty() {
        return None;
    }
    let tls = tls_scheme.unwrap_or(port == Some(8883));
    let port = port.unwrap_or(if tls { 8883 } else { 1883 });
    Some(Spec { host: host.trim_matches(['[', ']']).to_string(), port, tls })
}

// ---------- wire format ----------

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

fn put_str(v: &mut Vec<u8>, s: &[u8]) {
    v.extend_from_slice(&(s.len() as u16).to_be_bytes());
    v.extend_from_slice(s);
}

fn connect_pkt(client_id: &str, keepalive: Duration) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, b"MQTT");
    b.extend_from_slice(&[4, 0x02]); // level 3.1.1, clean session, no auth/will
    b.extend_from_slice(&(keepalive.as_secs().min(65535) as u16).to_be_bytes());
    put_str(&mut b, client_id.as_bytes());
    pkt(0x10, &b)
}

fn subscribe_pkt(topic: &str) -> Vec<u8> {
    let mut b = vec![0, 1];
    put_str(&mut b, topic.as_bytes());
    b.push(0); // QoS 0
    pkt(0x82, &b)
}

fn publish_pkt(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, topic.as_bytes());
    b.extend_from_slice(payload);
    pkt(0x30, &b) // QoS 0, DUP 0, RETAIN 0
}

const PINGREQ: [u8; 2] = [0xC0, 0];
const DISCONNECT: [u8; 2] = [0xE0, 0];

async fn read_pkt<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let h = r.read_u8().await?;
    let (mut n, mut m) = (0usize, 1usize);
    loop {
        let b = r.read_u8().await?;
        n += (b & 127) as usize * m;
        if b & 128 == 0 {
            break;
        }
        m *= 128;
        if m > 128 * 128 * 128 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad length"));
        }
    }
    if n > 64 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too large"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok((h, body))
}

/// Topic and payload of an incoming PUBLISH.
fn parse_publish(h: u8, body: &[u8]) -> Option<(&[u8], &[u8])> {
    let tl = u16::from_be_bytes([*body.first()?, *body.get(1)?]) as usize;
    let topic = body.get(2..2 + tl)?;
    let skip = if (h >> 1) & 3 > 0 { 2 } else { 0 }; // packet id, only for QoS > 0
    Some((topic, body.get(2 + tl + skip..)?))
}

// ---------- connection ----------

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// connect / TLS / timeout / socket errors: looks like filtering or an outage
    Net,
    /// the broker answered but refused or misbehaved
    Proto,
}

type Fail = (Kind, String);

fn tls_config() -> Arc<ClientConfig> {
    static C: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// TCP (+TLS) + CONNECT/CONNACK, all within `tun.connect_timeout`.
async fn connect(spec: &Spec, tun: &Tuning, client_id: &str) -> Result<Box<dyn Io>, Fail> {
    let net = |e: &dyn std::fmt::Display| (Kind::Net, format!("{}: {e}", spec.label()));
    let go = async {
        let tcp = TcpStream::connect((spec.host.as_str(), spec.port)).await.map_err(|e| net(&e))?;
        let _ = tcp.set_nodelay(true);
        let mut io: Box<dyn Io> = if spec.tls {
            let name = ServerName::try_from(spec.host.clone()).map_err(|e| net(&e))?;
            Box::new(TlsConnector::from(tls_config()).connect(name, tcp).await.map_err(|e| net(&format!("TLS: {e}")))?)
        } else {
            Box::new(tcp)
        };
        io.write_all(&connect_pkt(client_id, tun.keepalive)).await.map_err(|e| net(&e))?;
        let (h, body) = read_pkt(&mut io).await.map_err(|e| net(&e))?;
        match (h, body.as_slice()) {
            (0x20, [_, 0]) => Ok(io),
            (0x20, [_, code]) => Err((Kind::Proto, format!("{}: connection refused (code {code})", spec.label()))),
            _ => Err((Kind::Proto, format!("{}: unexpected reply to CONNECT", spec.label()))),
        }
    };
    tokio::time::timeout(tun.connect_timeout, go).await.unwrap_or_else(|_| Err(net(&"timed out")))
}

async fn send(w: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<(), Fail> {
    match tokio::time::timeout(Duration::from_secs(5), w.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err((Kind::Net, "write failed".into())),
    }
}

// ---------- publish pacing ----------

struct Pace {
    t0: Instant,
    last: Option<Instant>,
    sent: VecDeque<Instant>,
}

impl Pace {
    /// When the next publish may go out (not before `now`).
    fn due(&mut self, t: &Tuning, now: Instant) -> Instant {
        while self.sent.front().is_some_and(|s| now.duration_since(*s) >= t.cap_window) {
            self.sent.pop_front();
        }
        let mut at = match self.last {
            None => now,
            Some(l) => {
                let every = if l.duration_since(self.t0) < t.fast_window { t.pub_fast } else { t.pub_slow };
                (l + every).max(l + t.min_gap)
            }
        };
        if self.sent.len() >= t.cap {
            at = at.max(self.sent[0] + t.cap_window);
        }
        at.max(now)
    }
    fn note(&mut self, now: Instant) {
        self.last = Some(now);
        self.sent.push_back(now);
    }
}

// ---------- one broker ----------

struct Shared {
    ctx: RvCtx,
    topic: String,
    client_id: String,
    tun: Tuning,
    tx: mpsc::Sender<Candidate>,
    seen: Mutex<HashSet<std::net::SocketAddr>>,
    cancel: CancellationToken,
}

/// `Ok(())` = cancelled or the consumer is gone.
async fn session(spec: &Spec, sh: &Shared, pace: &mut Pace, connected: &mut bool) -> Result<(), Fail> {
    // A connect to a dead broker can block for seconds (Windows retries SYNs to a closed port for
    // about 2 s); cancel must not wait for it.
    let io = tokio::select! {
        _ = sh.cancel.cancelled() => return Ok(()),
        r = connect(spec, &sh.tun, &sh.client_id) => r?,
    };
    *connected = true;
    let (mut rd, mut wr) = tokio::io::split(io);
    send(&mut wr, &subscribe_pkt(&sh.topic)).await?;
    let (ptx, mut prx) = mpsc::channel::<io::Result<(u8, Vec<u8>)>>(16);
    let reader = tokio::spawn(async move {
        loop {
            let p = read_pkt(&mut rd).await;
            let stop = p.is_err();
            if ptx.send(p).await.is_err() || stop {
                break;
            }
        }
    });
    let d = sh.ctx.derived();
    let mut next_ping = Instant::now() + sh.tun.keepalive / 2;
    let mut last_rx = Instant::now();
    let mut next_pub = pace.due(&sh.tun, Instant::now());
    let r: Result<(), Fail> = async {
        loop {
            tokio::select! {
                _ = sh.cancel.cancelled() => {
                    let _ = tokio::time::timeout(Duration::from_millis(500), wr.write_all(&DISCONNECT)).await;
                    let _ = tokio::time::timeout(Duration::from_millis(300), wr.flush()).await;
                    return Ok(());
                }
                p = prx.recv() => {
                    let (h, body) = match p {
                        Some(Ok(p)) => p,
                        Some(Err(e)) => return Err((Kind::Net, format!("{}: {e}", spec.label()))),
                        None => return Err((Kind::Net, "reader stopped".into())),
                    };
                    last_rx = Instant::now();
                    match h >> 4 {
                        9 if body.last() == Some(&0x80) => return Err((Kind::Proto, format!("{}: subscribe refused", spec.label()))),
                        3 => if let Some((t, payload)) = parse_publish(h, &body) {
                            if t != sh.topic.as_bytes() { continue }
                            let Ok(addrs) = open(&d, sh.ctx.role, payload) else { continue };
                            for addr in addrs {
                                let new = sh.seen.lock().unwrap().insert(addr);
                                if new && sh.tx.send(Candidate { addr, via: "mqtt" }).await.is_err() {
                                    return Ok(());
                                }
                            }
                        },
                        _ => {}
                    }
                }
                _ = tokio::time::sleep_until(next_pub.into()) => {
                    let blob = seal(&d, sh.ctx.role, &sh.ctx.local).map_err(|e| (Kind::Proto, format!("seal: {e}")))?;
                    if blob.len() < MAX_PAYLOAD {
                        send(&mut wr, &publish_pkt(&sh.topic, &blob)).await?;
                        pace.note(Instant::now());
                        sh.ctx.status.set(Status::Publishing);
                        sh.ctx.status.set(Status::Waiting);
                    }
                    next_pub = pace.due(&sh.tun, Instant::now());
                }
                _ = tokio::time::sleep_until(next_ping.into()) => {
                    if last_rx.elapsed() > sh.tun.keepalive * 3 / 2 {
                        return Err((Kind::Net, format!("{}: no reply from broker", spec.label())));
                    }
                    send(&mut wr, &PINGREQ).await?;
                    next_ping = Instant::now() + sh.tun.keepalive / 2;
                }
            }
        }
    }
    .await;
    reader.abort();
    r
}

/// `None` = stopped normally; `Some(fail)` = this broker gave up.
async fn broker_task(spec: Spec, sh: Arc<Shared>) -> Option<Fail> {
    let mut pace = Pace { t0: Instant::now(), last: None, sent: VecDeque::new() };
    let mut fails = 0u32;
    loop {
        let mut connected = false;
        let err = match session(&spec, &sh, &mut pace, &mut connected).await {
            Ok(()) => return None,
            Err(e) => e,
        };
        log::debug!("mqtt {}: {}", spec.label(), err.1);
        if connected {
            fails = 0;
        }
        fails += 1;
        if fails >= sh.tun.max_fails {
            return Some(err);
        }
        let wait = (sh.tun.backoff_base * 2u32.saturating_pow(fails - 1)).min(Duration::from_secs(60));
        tokio::select! {
            _ = sh.cancel.cancelled() => return None,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

// ---------- trait ----------

#[async_trait::async_trait]
impl Rendezvous for Mqtt {
    fn id(&self) -> &'static str {
        "mqtt"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Public MQTT brokers (test-grade)",
            shared: &["your IP address, timing, a random-looking topic name and an unreadable sealed message"],
            not_shared: &["your traffic", "the invite key", "your address in readable form"],
            why: "to tell the other device where you are so both can connect directly",
            operator: "public MQTT brokers run by HiveMQ and EMQX for testing only: they say so themselves, may reset or change at any time and promise no uptime; use only as an extra option",
        }
    }

    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let client_id = client_id();
        let tun = Tuning { connect_timeout: timeout, ..self.tun.clone() };
        let one = |spec: Spec| {
            let (tun, id) = (tun.clone(), client_id.clone());
            async move {
                let t0 = Instant::now();
                let mut io = connect(&spec, &tun, &id).await?;
                let rtt = t0.elapsed().as_millis() as u32;
                let _ = tokio::time::timeout(Duration::from_millis(500), io.write_all(&DISCONNECT)).await;
                Ok::<u32, Fail>(rtt)
            }
        };
        let all = futures::future::join_all(self.brokers.iter().cloned().map(one));
        let Ok(res) = tokio::time::timeout(timeout + Duration::from_secs(1), all).await else {
            return ProbeStatus::Blocked("no MQTT broker answered in time".into());
        };
        if let Some(rtt_ms) = res.iter().filter_map(|r| r.as_ref().ok()).min() {
            return ProbeStatus::Reachable { rtt_ms: *rtt_ms };
        }
        let why: Vec<String> = res.into_iter().filter_map(|r| r.err().map(|e| e.1)).collect();
        ProbeStatus::Blocked(why.join("; "))
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let d = ctx.derived();
        seal(&d, ctx.role, &ctx.local).map_err(|e| RvError::Failed(format!("cannot seal candidates: {e}")))?;
        let sh = Arc::new(Shared {
            topic: format!("strait/{}", d.room_topic()),
            client_id: client_id(),
            tun: self.tun.clone(),
            seen: Mutex::new(HashSet::new()),
            ctx,
            tx,
            cancel: cancel.clone(),
        });
        let res = futures::future::join_all(self.brokers.iter().cloned().map(|s| broker_task(s, sh.clone()))).await;
        let fails: Vec<Fail> = res.iter().flatten().cloned().collect();
        if cancel.is_cancelled() || fails.len() < res.len() {
            return Ok(());
        }
        let msg = fails.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join("; ");
        Err(if fails.iter().all(|f| f.0 == Kind::Net) { RvError::Blocked(msg) } else { RvError::Failed(msg) })
    }
}

/// Random per run, carries no identity.
fn client_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        let s = |x| parse_spec(x);
        assert_eq!(s("broker.hivemq.com:8883"), Some(Spec { host: "broker.hivemq.com".into(), port: 8883, tls: true }));
        assert_eq!(s("127.0.0.1:1883").map(|x| x.tls), Some(false));
        assert_eq!(s("tcp://127.0.0.1:9").map(|x| x.tls), Some(false));
        assert_eq!(s("mqtts://h").map(|x| (x.port, x.tls)), Some((8883, true)));
        assert_eq!(s("mqtt://h").map(|x| (x.port, x.tls)), Some((1883, false)));
        assert_eq!(s("http://h"), None);
        assert_eq!(s(""), None);
    }

    #[test]
    fn framing() {
        assert_eq!(pkt(0x30, &[0; 200])[..3], [0x30, 0xC8, 0x01]);
        assert_eq!(subscribe_pkt("a/b"), [0x82, 8, 0, 1, 0, 3, b'a', b'/', b'b', 0]);
    }
}
