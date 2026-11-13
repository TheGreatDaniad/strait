//! `ws` carrier: sealed tunnel frames as a byte stream inside WebSocket binary messages, over TLS
//! (`wss`) or plain TCP (`ws`, for tests and for a host behind a TLS-terminating reverse proxy).
//! Our own implementation (tokio-tungstenite framing + rustls); not wire compatible with wstunnel.
//!
//! Layering: [`StreamCarrier`] (length prefix, padding, bounded drop-oldest queues, per-peer
//! connection table) <-> a small pump task per connection <-> `WebSocketStream` <-> TLS <-> TCP.
//! The pump owns ping/pong keepalive, the idle timeout and the typed end-of-connection reason.
//!
//! Spec parameters (`CarrierSpec.params`), both ends unless noted:
//! `key` (required: the invite key text; every secret below is HKDF-SHA256 derived from it with
//! info `strait-ws-v1:<label>`), `tls` = `pin` (default) | `ca` (client: public CA via webpki-roots,
//! for a real certificate or proxy) | `off` (plain ws), `path` and `token` (override the derived
//! values, e.g. to match a proxy rule), `sni`, `host` (HTTP Host header; client; default =
//! sni or endpoint), `max_frame` (default 1472), `buckets` (comma list, padded framing; both ends
//! must agree), `idle_ms` (60000), `ping_ms` (20000), `connect_ms` (10000), `out_queue`, `in_queue`.
//!
//! Auth and decoy: the host answers an upgrade only for `GET <path>` with `Authorization: Bearer
//! <derived token>` and a valid WebSocket handshake. Anything else (wrong path, wrong or missing
//! token, plain browser GET, wrong method, garbage) gets one fixed `404` page, byte-identical for
//! every cause, so a scanner learns nothing. A header that never completes is closed silently
//! after [`HEAD_TIMEOUT`]. Token and path are derivable by any invite holder (same documented
//! limit as handshake v2); the end-to-end AEAD, not this token, protects the tunnel.
//!
//! TLS identity: a self-signed Ed25519 certificate that is a pure function of the invite key (TLS
//! 1.3 only, so the certificate is not visible on the wire). The client accepts exactly that
//! certificate (pin = SHA-256 of its DER, see [`Identity::pin_hex`]) and still verifies the TLS
//! signature, so no CA is involved. A wrong key gives a TLS failure, typed `Blocked`.
//!
//! Peer keys: one WebSocket connection = one peer. Host side: the TCP remote address (IPv4-mapped
//! normalized); behind a reverse proxy that is the proxy's IP with the per-connection source port.
//! If that exact address is still held by a connection being torn down, the port is replaced by a
//! free one from a private counter (still unique). Client side: the host's resolved address, fixed
//! for the life of the carrier. The transport's per-peer maps therefore see distinct stable keys.
//!
//! Without an address (`endpoint` unset) both ends run in punch mode, for a host that has no
//! reachable TCP port: the host announces its TCP mapping next to the UDP one, the client finds
//! it through rendezvous, and both dial each other from their listening port until a connection
//! forms (see [`super::tcp_punch`]). The host is always the TLS / WebSocket server, whichever
//! side's SYN got through.
//!
//! TCP-over-TCP: see [`tcp_over_tcp_warning`]. Caps are honest: `punchable=false`,
//! `reliable_stream=true`. Dial errors: connect / TLS / any non-101 HTTP answer = `Blocked`,
//! everything else `Failed`; reconnect-with-backoff is the transport's job.
//! Back-pressure: the outbound queue is bounded with drop-oldest (counted in
//! `stats().dropped_oldest`), so `send_to` never blocks and a slow peer never stalls the whole
//! tunnel; inbound waits for room and lets TCP push back on the sender.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::AbortHandle;
use tokio_rustls::rustls::{self, pki_types};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::WebSocketStream;

use super::stream::{StreamCarrier, StreamCfg, StreamStats};
use super::udp::norm;
use super::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, Caps, FrameIo, Health};
use crate::rendezvous::{Disclosure, ProbeStatus};

/// A header that has not completed after this long is dropped without an answer.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEAD: usize = 8 * 1024;
const MAX_PENDING_HANDSHAKES: usize = 256;
/// Pending handshakes one source address may hold (a NAT with a few guests still fits).
const MAX_PENDING_PER_IP: u8 = 8;

/// Per-source count of pending handshakes; the guard gives its slot back on drop.
#[derive(Default, Clone)]
struct PendingByIp(Arc<Mutex<std::collections::HashMap<std::net::IpAddr, u8>>>);

struct PendingSlot(PendingByIp, std::net::IpAddr);

impl PendingByIp {
    fn take(&self, ip: std::net::IpAddr) -> Option<PendingSlot> {
        let mut m = self.0.lock().unwrap();
        let n = m.entry(ip).or_insert(0);
        if *n >= MAX_PENDING_PER_IP {
            return None;
        }
        *n += 1;
        Some(PendingSlot(self.clone(), ip))
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut m = (self.0).0.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}
/// TUN MTU the integration should use on this carrier to limit TCP-in-TCP head-of-line cost
/// (`max_frame` 1335 gives `Caps::tun_mtu` 1300).
pub const RECOMMENDED_TUN_MTU: usize = 1300;
pub const DEFAULT_MAX_FRAME: usize = 1472;
const DEFAULT_LOWAT: usize = 0; // off: not shown to help (docs/research/e2e-xray-ws-tuning.md)
const DEFAULT_PIPE: usize = 65536;

/// Cap the kernel's unsent backlog so a stalled path backs up into our drop-oldest queue (where
/// stale frames are discarded) instead of into hundreds of KB of kernel buffer that must all be
/// delivered, late, before a fresh frame can leave. Best effort; no-op where unsupported.
fn limit_unsent(tcp: &TcpStream, bytes: usize) {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    if bytes > 0 {
        use std::os::fd::AsRawFd;
        #[cfg(target_os = "macos")]
        const OPT: libc::c_int = 0x201;
        #[cfg(not(target_os = "macos"))]
        const OPT: libc::c_int = 25;
        let v = bytes.min(i32::MAX as usize) as libc::c_int;
        // SAFETY: valid fd of a live socket, pointer to a c_int of the stated size.
        unsafe {
            libc::setsockopt(tcp.as_raw_fd(), libc::IPPROTO_TCP, OPT, &v as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        }
    }
    let _ = (tcp, bytes);
}

/// The fixed answer to everything that is not an authenticated upgrade.
const DECOY_BODY: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n</body>\r\n</html>\r\n";

pub fn decoy_response() -> Vec<u8> {
    format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        DECOY_BODY.len(),
        DECOY_BODY
    )
    .into_bytes()
}

/// `Some(text)` when the carrier is stream-backed: carrying an inner TCP flow over it nests two
/// retransmission loops. The integration should then use a small MTU and datagram-friendly settings.
pub fn tcp_over_tcp_warning(caps: &Caps) -> Option<&'static str> {
    caps.reliable_stream.then_some(
        "ws carrier is TCP: tunnelled TCP flows nest two congestion loops (TCP-over-TCP); use TUN MTU <= 1300, \
         keep queues short (drop-oldest is on) and prefer a UDP carrier when it works",
    )
}

pub struct WsFactory;

// ---------------------------------------------------------------- config / identity

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TlsMode {
    Pin,
    Ca,
    Off,
}

#[derive(Clone, Debug)]
struct Cfg {
    key: Vec<u8>,
    tls: TlsMode,
    sni: Option<String>,
    host: Option<String>,
    path: Option<String>,
    token: Option<String>,
    max_frame: usize,
    buckets: Vec<usize>,
    idle: Duration,
    ping: Duration,
    connect: Duration,
    out_queue: Option<usize>,
    in_queue: Option<usize>,
    /// TCP_NOTSENT_LOWAT in bytes (0 = off): unsent bytes the kernel may hold per connection.
    lowat: usize,
    /// In-process pipe between the pump and the carrier, bytes.
    pipe: usize,
}

impl Cfg {
    fn from_spec(spec: &CarrierSpec) -> Result<Cfg, CarrierError> {
        let get = |k: &str| spec.params.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let bad = |k: &str| CarrierError::Failed(format!("ws: bad parameter {k}"));
        // Queue tuning knobs may also come from `NAT_TUNNEL_WS_<KEY>` (invite entries cannot carry them).
        let num = |k: &str| -> Result<Option<u64>, CarrierError> {
            let env = std::env::var(format!("NAT_TUNNEL_WS_{}", k.to_uppercase())).ok();
            get(k).map(str::to_string).or(env).map(|v| v.parse::<u64>().map_err(|_| bad(k))).transpose()
        };
        let key = get("key").filter(|k| !k.is_empty()).ok_or_else(|| CarrierError::Failed("ws: missing parameter key".into()))?;
        let tls = match get("tls").unwrap_or("pin") {
            "pin" => TlsMode::Pin,
            "ca" => TlsMode::Ca,
            "off" => TlsMode::Off,
            _ => return Err(bad("tls")),
        };
        let buckets = match get("buckets") {
            Some(s) => s.split(',').map(|b| b.trim().parse::<usize>().map_err(|_| bad("buckets"))).collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        let ms = |k: &str, d: u64| -> Result<Duration, CarrierError> { Ok(Duration::from_millis(num(k)?.unwrap_or(d).max(1))) };
        Ok(Cfg {
            key: key.as_bytes().to_vec(),
            tls,
            sni: get("sni").map(str::to_string),
            host: get("host").map(str::to_string),
            path: get("path").map(str::to_string),
            token: get("token").map(str::to_string),
            max_frame: num("max_frame")?.map(|v| v as usize).unwrap_or(DEFAULT_MAX_FRAME),
            buckets,
            idle: ms("idle_ms", 60_000)?,
            ping: ms("ping_ms", 20_000)?,
            connect: ms("connect_ms", 10_000)?,
            out_queue: num("out_queue")?.map(|v| v as usize),
            in_queue: num("in_queue")?.map(|v| v as usize),
            lowat: num("lowat")?.map(|v| v as usize).unwrap_or(DEFAULT_LOWAT),
            pipe: num("pipe")?.map(|v| v as usize).unwrap_or(DEFAULT_PIPE).max(1024),
        })
    }

    fn stream_cfg(&self, local: SocketAddr) -> StreamCfg {
        let mut c = StreamCfg::new(CarrierId::Ws, self.max_frame);
        c.framing.buckets = self.buckets.clone();
        c.framing.buckets.sort_unstable();
        c.local = local;
        if let Some(q) = self.out_queue {
            c.out_queue = q;
        }
        if let Some(q) = self.in_queue {
            c.in_queue = q;
        }
        c
    }

    fn ws_config(&self) -> WebSocketConfig {
        let mut w = WebSocketConfig::default();
        // One message carries at most a coalesced batch of records; refuse anything much bigger.
        w.max_message_size = Some(256 * 1024);
        w.max_frame_size = Some(256 * 1024);
        w
    }

    fn path_token(&self) -> (String, String) {
        let id = Identity::derive(&self.key);
        (self.path.clone().unwrap_or(id.path), self.token.clone().unwrap_or(id.token))
    }
}

/// Everything derived from the invite key.
#[derive(Clone, Debug)]
pub struct Identity {
    pub path: String,
    pub token: String,
    seed: [u8; 32],
    serial: [u8; 16],
}

impl Identity {
    pub fn derive(key: &[u8]) -> Identity {
        let hk = Hkdf::<Sha256>::new(None, key);
        let out = |label: &str, buf: &mut [u8]| hk.expand(format!("strait-ws-v1:{label}").as_bytes(), buf).expect("hkdf length");
        let (mut p, mut t, mut seed, mut serial) = ([0u8; 8], [0u8; 24], [0u8; 32], [0u8; 16]);
        out("path", &mut p);
        out("token", &mut t);
        out("tls-seed", &mut seed);
        out("tls-serial", &mut serial);
        serial[0] &= 0x7f; // positive DER INTEGER
        Identity { path: format!("/{}", hex(&p)), token: hex(&t), seed, serial }
    }

    /// The deterministic self-signed certificate (DER) and its signing key (PKCS#8 DER).
    pub fn cert(&self) -> Result<(Vec<u8>, Vec<u8>), CarrierError> {
        let err = |e: rcgen::Error| CarrierError::Failed(format!("ws: certificate: {e}"));
        // PKCS#8 v1 wrapper of an Ed25519 seed (fixed 16 byte prefix).
        let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        pkcs8.extend_from_slice(&self.seed);
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pki_types::PrivatePkcs8KeyDer::from(pkcs8.clone()), &rcgen::PKCS_ED25519)
            .map_err(err)?;
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(err)?;
        p.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&self.serial));
        p.not_before = rcgen::date_time_ymd(2024, 1, 1);
        p.not_after = rcgen::date_time_ymd(2124, 1, 1);
        let cert = p.self_signed(&kp).map_err(err)?;
        Ok((cert.der().to_vec(), pkcs8))
    }

    /// SHA-256 of the certificate DER, hex. A function of the key only; this is the client's pin.
    pub fn pin_hex(&self) -> String {
        hex(&Sha256::digest(self.cert().expect("cert").0))
    }
}

pub fn identity_for_key(key: &str) -> Identity {
    Identity::derive(key.as_bytes())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_tls(id: &Identity) -> Result<tokio_rustls::TlsAcceptor, CarrierError> {
    let (cert, key) = id.cert()?;
    let tls = |e: rustls::Error| CarrierError::Failed(format!("ws: tls: {e}"));
    let mut c = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert.into()], pki_types::PrivatePkcs8KeyDer::from(key).into())
        .map_err(tls)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(c)))
}

#[derive(Debug)]
struct PinVerifier {
    want: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _name: &pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.want.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn client_tls(cfg: &Cfg, id: &Identity) -> Result<tokio_rustls::TlsConnector, CarrierError> {
    let p = provider();
    let b = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CarrierError::Failed(format!("ws: tls: {e}")))?;
    let mut c = if cfg.tls == TlsMode::Ca {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        b.with_root_certificates(roots).with_no_client_auth()
    } else {
        let want = id.cert()?.0;
        b.dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier { want, algs: p.signature_verification_algorithms }))
            .with_no_client_auth()
    };
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(c)))
}

// ---------------------------------------------------------------- per-connection pump

trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}
type Conn = Box<dyn Duplex>;

type End = Option<(io::ErrorKind, String)>;
type EndCell = Arc<Mutex<End>>;

/// The end of the in-process pipe handed to `StreamCarrier`: reads EOF with the pump's typed reason.
struct Side {
    io: DuplexStream,
    end: EndCell,
}

impl AsyncRead for Side {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => match self.end.lock().unwrap().clone() {
                Some((k, m)) => Poll::Ready(Err(io::Error::new(k, m))),
                None => Poll::Ready(Ok(())),
            },
            r => r,
        }
    }
}

impl AsyncWrite for Side {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn reset(m: &str) -> End {
    Some((io::ErrorKind::ConnectionReset, m.to_string()))
}

fn map_ws_err(e: tungstenite::Error) -> End {
    use tungstenite::error::ProtocolError as P;
    use tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed | E::Protocol(P::ResetWithoutClosingHandshake) => reset("websocket closed without a closing handshake"),
        E::Io(e) => match e.kind() {
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => {
                reset(&e.to_string())
            }
            _ => Some((io::ErrorKind::Other, e.to_string())),
        },
        e => Some((io::ErrorKind::InvalidData, format!("websocket: {e}"))),
    }
}

/// Start the pump for an upgraded socket; returns the `StreamCarrier` side.
fn spawn_pump(ws: WebSocketStream<Conn>, idle: Duration, ping: Duration, pipe: usize) -> Side {
    let (app, ours) = tokio::io::duplex(pipe);
    let end: EndCell = Arc::new(Mutex::new(None));
    let cell = end.clone();
    tokio::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        let (mut app_rd, mut app_wr) = tokio::io::split(ours);
        let kick = Notify::new();
        let reader = async {
            loop {
                match tokio::time::timeout(idle, stream.next()).await {
                    Err(_) => return Some((io::ErrorKind::TimedOut, "idle timeout".to_string())),
                    Ok(None) => return reset("websocket closed without a closing handshake"),
                    Ok(Some(Err(e))) => return map_ws_err(e),
                    Ok(Some(Ok(Message::Binary(b)))) => {
                        if app_wr.write_all(&b).await.is_err() {
                            return None; // carrier side is gone
                        }
                    }
                    Ok(Some(Ok(Message::Ping(_)))) => kick.notify_one(), // tungstenite queued the pong
                    Ok(Some(Ok(Message::Pong(_)))) => {}
                    Ok(Some(Ok(Message::Close(_)))) => return None,
                    Ok(Some(Ok(_))) => return Some((io::ErrorKind::InvalidData, "unexpected non-binary message".into())),
                }
            }
        };
        let writer = async {
            let mut buf = vec![0u8; 16 * 1024];
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + ping, ping);
            loop {
                let m = tokio::select! {
                    n = app_rd.read(&mut buf) => match n {
                        Ok(0) | Err(_) => return None,
                        Ok(n) => Message::Binary(buf[..n].to_vec()),
                    },
                    _ = tick.tick() => Message::Ping(Vec::new()),
                    _ = kick.notified() => {
                        let _ = tokio::time::timeout(idle, sink.flush()).await;
                        continue;
                    }
                };
                match tokio::time::timeout(idle, sink.send(m)).await {
                    Err(_) => return Some((io::ErrorKind::TimedOut, "write stalled".to_string())),
                    Ok(Err(e)) => return map_ws_err(e),
                    Ok(Ok(())) => {}
                }
            }
        };
        let r = tokio::select! { r = reader => r, r = writer => r };
        if r.is_none() {
            // Orderly end: send / answer the Close frame, bounded.
            let _ = tokio::time::timeout(Duration::from_millis(500), sink.close()).await;
        }
        *cell.lock().unwrap() = r;
        // Dropping the pipe halves now gives the carrier side its EOF, carrying the reason above.
    });
    Side { io: app, end }
}

// ---------------------------------------------------------------- the carrier

/// The `ws` carrier: a [`StreamCarrier`] whose connections are WebSockets.
pub struct WsCarrier {
    inner: Arc<StreamCarrier>,
    overhead: usize,
    tasks: Vec<AbortHandle>,
    punch: Option<Arc<Punch>>,
}

impl Drop for WsCarrier {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Outbound attempts one carrier runs at a time (a host fires at every announced client).
const MAX_PUNCH_INFLIGHT: usize = 32;

/// Punch mode state: every socket of this carrier uses local TCP `port`.
struct Punch {
    port: u16,
    cfg: Cfg,
    sc: std::sync::Weak<StreamCarrier>,
    /// Host: how a connection is answered. `None` on the client.
    serve: Option<Arc<Serve>>,
    inflight: Mutex<std::collections::HashSet<SocketAddr>>,
    /// Host: how `port` looks from outside, refreshed in the background.
    mapped: Mutex<Option<SocketAddr>>,
    /// Client: key of its one connection.
    peer: Mutex<Option<SocketAddr>>,
}

impl Punch {
    /// Dial `to` from the shared port unless that is already running or connected.
    fn kick(self: &Arc<Self>, to: SocketAddr) {
        let to = norm(to);
        let Some(sc) = self.sc.upgrade() else { return };
        if !to.is_ipv4() || sc.peers().contains(&to) {
            return;
        }
        {
            let mut f = self.inflight.lock().unwrap();
            if f.len() >= MAX_PUNCH_INFLIGHT || !f.insert(to) {
                return;
            }
        }
        let p = self.clone();
        tokio::spawn(async move {
            if let Ok(Ok(tcp)) = tokio::time::timeout(super::tcp_punch::ATTEMPT, super::tcp_punch::connect_from(p.port, to)).await {
                log::debug!("ws carrier: tcp punch connected to {to}");
                p.adopt(tcp, to).await;
            }
            p.inflight.lock().unwrap().remove(&to);
        });
    }

    /// A TCP connection exists (dialed or accepted): run this side's part of the upgrade on it.
    async fn adopt(self: &Arc<Self>, tcp: TcpStream, remote: SocketAddr) {
        if let Some(sv) = &self.serve {
            return sv.conn(tcp, remote).await;
        }
        let remote = norm(remote);
        let (ip, ep) = (remote.ip().to_string(), remote.to_string());
        let Ok(Ok(ws)) = tokio::time::timeout(self.cfg.connect, client_upgrade(tcp, &ip, &ep, &self.cfg)).await else { return };
        let Some(sc) = self.sc.upgrade() else { return };
        let mut peer = self.peer.lock().unwrap();
        if peer.is_none() && sc.add_conn(spawn_pump(ws, self.cfg.idle, self.cfg.ping, self.cfg.pipe), remote).is_ok() {
            *peer = Some(remote);
        }
    }
}

/// Host side: everything needed to answer one TCP connection.
struct Serve {
    tls: Option<tokio_rustls::TlsAcceptor>,
    path: String,
    token: String,
    cfg: Cfg,
    sc: std::sync::Weak<StreamCarrier>,
    ctr: AtomicU16,
}

impl Serve {
    async fn conn(&self, tcp: TcpStream, remote: SocketAddr) {
        let _ = tcp.set_nodelay(true);
        limit_unsent(&tcp, self.cfg.lowat);
        let ws = tokio::time::timeout(HEAD_TIMEOUT, async {
            let conn: Conn = match &self.tls {
                Some(a) => Box::new(a.accept(tcp).await.ok()?),
                None => Box::new(tcp),
            };
            server_upgrade(conn, &self.path, &self.token, self.cfg.ws_config()).await
        })
        .await
        .ok()
        .flatten();
        let (Some(ws), Some(sc)) = (ws, self.sc.upgrade()) else { return };
        let side = spawn_pump(ws, self.cfg.idle, self.cfg.ping, self.cfg.pipe);
        let mut peer = norm(remote);
        while sc.peers().contains(&peer) {
            peer.set_port(1024 + self.ctr.fetch_add(1, Ordering::Relaxed) % 60000);
        }
        if let Err(e) = sc.add_conn(side, peer) {
            log::debug!("ws carrier: reject {remote}: {e}");
        }
    }
}

impl WsCarrier {
    pub fn stats(&self) -> StreamStats {
        self.inner.stats()
    }
    /// Connections that ended since the last call, with the typed reason.
    pub fn take_closed(&self) -> Vec<(SocketAddr, CarrierError)> {
        self.inner.take_closed()
    }
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.inner.peers()
    }
}

#[async_trait::async_trait]
impl FrameIo for WsCarrier {
    fn caps(&self) -> Caps {
        let mut c = self.inner.caps();
        c.overhead += self.overhead;
        c.punchable = self.punch.as_ref().is_some_and(|p| p.serve.is_none());
        c
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        let Some(p) = self.punch.as_ref().filter(|p| p.serve.is_none()) else {
            return self.inner.send_to(frame, to).await;
        };
        // A punch client has one connection, whatever address the transport aims at; until it
        // exists a frame is lost like a datagram and the send becomes a dial attempt.
        let peer = *p.peer.lock().unwrap();
        match self.inner.send_to(frame, peer.unwrap_or(to)).await {
            Err(e) if matches!(CarrierError::from_io(&e), Some(CarrierError::UnknownPeer)) => {
                p.kick(to);
                Ok(frame.len())
            }
            r => r,
        }
    }
    async fn send_probe(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        match &self.punch {
            // Port scans and socket fan-outs are UDP tricks; a TCP dial per probe would be a flood.
            Some(p) if p.serve.is_none() => Ok(frame.len()),
            _ => self.send_to(frame, to).await,
        }
    }
    async fn stun_mapped(&self, servers: &[SocketAddr], wait: Duration) -> Vec<SocketAddr> {
        let Some(p) = self.punch.as_ref().filter(|p| p.serve.is_none()) else { return Vec::new() };
        let seen = super::tcp_punch::mapped(p.port, 2).await;
        if !seen.is_empty() {
            return seen;
        }
        // No TCP answer: the public address by UDP, assuming the router keeps the port number.
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else { return Vec::new() };
        let s = crate::tunnel::stun::survey(&sock, servers, wait).await;
        s.first().map(|m| SocketAddr::new(m.mapped.ip(), p.port)).into_iter().collect()
    }
    fn punch(&self, to: SocketAddr) {
        if let Some(p) = self.punch.as_ref().filter(|p| p.serve.is_some()) {
            p.kick(to);
        }
    }
    fn extra_candidates(&self, public_ip: std::net::IpAddr) -> Vec<SocketAddr> {
        let Some(p) = self.punch.as_ref().filter(|p| p.serve.is_some()) else { return Vec::new() };
        // Until a TCP STUN answer says otherwise: the router keeps the port number.
        let m = (*p.mapped.lock().unwrap()).unwrap_or(SocketAddr::new(public_ip, p.port));
        if m.is_ipv4() { vec![m] } else { Vec::new() }
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.try_recv_from(buf)
    }
    async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }
    fn health(&self) -> Health {
        self.inner.health()
    }
    async fn close(&self) {
        for t in &self.tasks {
            t.abort();
        }
        self.inner.close().await
    }
}

/// WebSocket header (<= 8 B with client mask) plus TLS record overhead when TLS is on.
fn overhead(cfg: &Cfg) -> usize {
    8 + if cfg.tls == TlsMode::Off { 0 } else { 22 }
}

fn warn_tcp(c: &WsCarrier) {
    if let Some(w) = tcp_over_tcp_warning(&c.caps()) {
        log::warn!("{w}");
    }
}

/// Host: bind and serve. `endpoint` = listen address; without one the carrier runs in punch mode
/// on `bind_port` (0 = any).
pub async fn listen_ws(spec: &CarrierSpec) -> Result<WsCarrier, CarrierError> {
    let cfg = Cfg::from_spec(spec)?;
    let id = Identity::derive(&cfg.key);
    let tls = if cfg.tls == TlsMode::Off { None } else { Some(server_tls(&id)?) };
    let punch_mode = spec.endpoint.is_none();
    let (l, bind) = match &spec.endpoint {
        Some(bind) => (TcpListener::bind(bind).await, bind.clone()),
        None => (super::tcp_punch::listen(spec.bind_port.unwrap_or(0)), format!("0.0.0.0:{}", spec.bind_port.unwrap_or(0))),
    };
    let l = l.map_err(|e| CarrierError::Failed(format!("ws: bind {bind}: {e}")))?;
    let local = l.local_addr().map_err(|e| CarrierError::Failed(e.to_string()))?;
    let inner = Arc::new(StreamCarrier::new(cfg.stream_cfg(local))?);
    // The tasks hold only a Weak: dropping the carrier must not be kept alive by them.
    let (path, token) = cfg.path_token();
    let serve = Arc::new(Serve { tls, path, token, cfg: cfg.clone(), sc: Arc::downgrade(&inner), ctr: AtomicU16::new(0) });
    let sv = serve.clone();
    let h = tokio::spawn(async move {
        let sem = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
        let by_ip = PendingByIp::default();
        loop {
            let (tcp, remote) = match l.accept().await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await; // EMFILE and friends
                    continue;
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else { continue };
            // A reverse proxy on loopback fronts many guests with one address: no per-IP cap there.
            let ip = norm(remote).ip();
            let slot = if ip.is_loopback() {
                None
            } else {
                match by_ip.take(ip) {
                    Some(sl) => Some(sl),
                    None => continue,
                }
            };
            let sv = sv.clone();
            tokio::spawn(async move {
                let (_permit, _slot) = (permit, slot);
                sv.conn(tcp, remote).await;
            });
        }
    });
    let mut tasks = vec![h.abort_handle()];
    let punch = punch_mode.then(|| {
        Arc::new(Punch {
            port: local.port(),
            cfg: cfg.clone(),
            sc: Arc::downgrade(&inner),
            serve: Some(serve),
            inflight: Mutex::default(),
            mapped: Mutex::new(None),
            peer: Mutex::new(None),
        })
    });
    if let Some(p) = &punch {
        let p = Arc::downgrade(p);
        // Keep the announced mapping current (a router may hand out another port later).
        tasks.push(
            tokio::spawn(async move {
                loop {
                    let Some(pu) = p.upgrade() else { return };
                    if let Some(m) = super::tcp_punch::mapped(pu.port, 1).await.into_iter().next() {
                        *pu.mapped.lock().unwrap() = Some(m);
                    }
                    drop(pu);
                    tokio::time::sleep(Duration::from_secs(120)).await;
                }
            })
            .abort_handle(),
        );
    }
    let c = WsCarrier { inner, overhead: overhead(&cfg), tasks, punch };
    warn_tcp(&c);
    Ok(c)
}

/// Read the request head (a client sends nothing after it until the 101), answer decoy or 101.
async fn server_upgrade(mut s: Conn, path: &str, token: &str, wsc: WebSocketConfig) -> Option<WebSocketStream<Conn>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return decoy(s).await;
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let accept = if buf.len() == end + 4 { check_head(&buf[..end], path, token) } else { None };
    let Some(accept) = accept else { return decoy(s).await };
    let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n");
    s.write_all(resp.as_bytes()).await.ok()?;
    s.flush().await.ok()?;
    Some(WebSocketStream::from_raw_socket(s, Role::Server, Some(wsc)).await)
}

async fn decoy(mut s: Conn) -> Option<WebSocketStream<Conn>> {
    let _ = s.write_all(&decoy_response()).await;
    let _ = s.shutdown().await;
    None
}

/// `Some(Sec-WebSocket-Accept)` only for an authenticated, well-formed upgrade request.
fn check_head(head: &[u8], path: &str, token: &str) -> Option<String> {
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    if rl.next()? != "GET" || rl.next()? != path || rl.next()? != "HTTP/1.1" || rl.next().is_some() {
        return None;
    }
    let (mut upgrade, mut conn, mut ver, mut key, mut auth) = (false, false, false, None, false);
    for l in lines {
        let (n, v) = l.split_once(':')?;
        let v = v.trim();
        match n.to_ascii_lowercase().as_str() {
            "upgrade" => upgrade |= v.eq_ignore_ascii_case("websocket"),
            "connection" => conn |= v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")),
            "sec-websocket-version" => ver = v == "13",
            "sec-websocket-key" => key = Some(v),
            "authorization" => auth |= ct_eq(v.as_bytes(), format!("Bearer {token}").as_bytes()),
            _ => {}
        }
    }
    let key = key.filter(|k| k.len() == 24)?;
    (upgrade && conn && ver && auth).then(|| tungstenite::handshake::derive_accept_key(key.as_bytes()))
}

// ---------------------------------------------------------------- client side

fn split_host(endpoint: &str) -> Result<(String, u16), CarrierError> {
    let bad = || CarrierError::Failed(format!("ws: endpoint {endpoint:?} is not host:port"));
    let (h, p) = endpoint.rsplit_once(':').ok_or_else(bad)?;
    Ok((h.trim_start_matches('[').trim_end_matches(']').to_string(), p.parse().map_err(|_| bad())?))
}

/// TLS + upgrade on a connected socket, as the client. `host` is the name (or IP) for SNI,
/// `endpoint` the default Host header.
async fn client_upgrade(tcp: TcpStream, host: &str, endpoint: &str, cfg: &Cfg) -> Result<WebSocketStream<Conn>, CarrierError> {
    let blocked = |s: &str, e: &dyn std::fmt::Display| CarrierError::Blocked(format!("{s}: {e}"));
    let id = Identity::derive(&cfg.key);
    let (path, token) = cfg.path_token();
    let _ = tcp.set_nodelay(true);
    limit_unsent(&tcp, cfg.lowat);
    let conn: Conn = if cfg.tls == TlsMode::Off {
        Box::new(tcp)
    } else {
        let name = cfg.sni.clone().unwrap_or_else(|| host.to_string());
        let name = pki_types::ServerName::try_from(name.clone()).map_err(|e| CarrierError::Failed(format!("ws: sni {name}: {e}")))?;
        Box::new(client_tls(cfg, &id)?.connect(name, tcp).await.map_err(|e| blocked("tls", &e))?)
    };
    // Host header is configurable independently of the TCP target (domain fronting style / proxy vhost).
    let hosthdr = cfg.host.clone().or_else(|| cfg.sni.clone()).unwrap_or_else(|| endpoint.to_string());
    let req = tungstenite::http::Request::builder()
        .method("GET")
        .uri(format!("ws://{hosthdr}{path}"))
        .header("Host", &hosthdr)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tungstenite::handshake::client::generate_key())
        .header("Authorization", format!("Bearer {token}"))
        .body(())
        .map_err(|e| CarrierError::Failed(format!("ws: request: {e}")))?;
    let (ws, _resp) = tokio_tungstenite::client_async_with_config(req, conn, Some(cfg.ws_config())).await.map_err(|e| match e {
        tungstenite::Error::Http(r) => CarrierError::Blocked(format!("upgrade refused: http {}", r.status().as_u16())),
        e => CarrierError::Failed(format!("ws: upgrade: {e}")),
    })?;
    Ok(ws)
}

/// TCP + TLS + upgrade. Sends no WebSocket frames. Returns (ws, host address, local address).
async fn connect_ws(spec: &CarrierSpec, cfg: &Cfg) -> Result<(WebSocketStream<Conn>, SocketAddr, SocketAddr), CarrierError> {
    let endpoint = spec.endpoint.as_deref().ok_or_else(|| CarrierError::Failed("ws: missing endpoint".into()))?;
    let (host, port) = split_host(endpoint)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| CarrierError::Failed(format!("ws: resolve {host}: {e}")))?
        .collect();
    let blocked = |s: &str, e: &dyn std::fmt::Display| CarrierError::Blocked(format!("{s}: {e}"));
    let work = async {
        let mut last = CarrierError::Failed(format!("ws: {host} has no address"));
        let mut tcp = None;
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = blocked("connect", &e),
            }
        }
        let tcp = tcp.ok_or(last)?;
        let remote = tcp.peer_addr().map_err(|e| blocked("connect", &e))?;
        let local = tcp.local_addr().map_err(|e| blocked("connect", &e))?;
        let ws = client_upgrade(tcp, &host, endpoint, cfg).await?;
        Ok::<_, CarrierError>((ws, remote, local))
    };
    match tokio::time::timeout(cfg.connect, work).await {
        Ok(r) => r,
        Err(_) => Err(CarrierError::Blocked("connect timeout".into())),
    }
}

/// Client: one connection, shown to the transport as the host's resolved address.
pub async fn dial_ws(spec: &CarrierSpec) -> Result<WsCarrier, CarrierError> {
    let cfg = Cfg::from_spec(spec)?;
    if spec.endpoint.is_none() {
        return punch_client(spec, cfg);
    }
    let (ws, remote, local) = connect_ws(spec, &cfg).await?;
    let inner = Arc::new(StreamCarrier::new(cfg.stream_cfg(local))?);
    inner.add_conn(spawn_pump(ws, cfg.idle, cfg.ping, cfg.pipe), norm(remote))?;
    let c = WsCarrier { inner, overhead: overhead(&cfg), tasks: Vec::new(), punch: None };
    warn_tcp(&c);
    Ok(c)
}

/// Client without a host address: nothing is dialed yet. The transport learns the host's
/// endpoints through rendezvous and every frame it aims at one becomes a dial from our port,
/// while the listener takes the host's own dial when that one gets through first.
fn punch_client(spec: &CarrierSpec, cfg: Cfg) -> Result<WsCarrier, CarrierError> {
    let l = super::tcp_punch::listen(spec.bind_port.unwrap_or(0)).map_err(|e| CarrierError::Failed(format!("ws: bind: {e}")))?;
    let local = l.local_addr().map_err(|e| CarrierError::Failed(e.to_string()))?;
    let inner = Arc::new(StreamCarrier::new(cfg.stream_cfg(local))?);
    let punch = Arc::new(Punch {
        port: local.port(),
        cfg: cfg.clone(),
        sc: Arc::downgrade(&inner),
        serve: None,
        inflight: Mutex::default(),
        mapped: Mutex::new(None),
        peer: Mutex::new(None),
    });
    let p = Arc::downgrade(&punch);
    let h = tokio::spawn(async move {
        loop {
            let Ok((tcp, remote)) = l.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Some(p) = p.upgrade() else { return };
            tokio::spawn(async move { p.adopt(tcp, remote).await });
        }
    });
    let c = WsCarrier { inner, overhead: overhead(&cfg), tasks: vec![h.abort_handle()], punch: Some(punch) };
    warn_tcp(&c);
    Ok(c)
}

#[async_trait::async_trait]
impl CarrierFactory for WsFactory {
    fn id(&self) -> CarrierId {
        CarrierId::Ws
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "WebSocket over TLS (own implementation)",
            shared: &[
                "a network observer sees a TLS connection to your host that looks like a website using WebSocket",
                "traffic volume and timing patterns may still be recognisable",
                "without a reachable port on the host: a public STUN server sees each side's address once, to learn its TCP port mapping",
            ],
            not_shared: &["the tunnel payload", "keys"],
            why: "carry the tunnel over the web port when UDP is blocked",
            operator: "none: connects only to the host itself (plus one STUN query when the host has no reachable port)",
        }
    }
    async fn probe(&self, spec: &CarrierSpec, timeout: Duration) -> ProbeStatus {
        let cfg = match Cfg::from_spec(spec) {
            Ok(c) => c,
            Err(e) => return ProbeStatus::Error(e.to_string()),
        };
        if spec.endpoint.is_none() {
            // Punch mode has nothing to dial before rendezvous; like the UDP carriers, say so.
            return ProbeStatus::Reachable { rtt_ms: 0 };
        }
        let t0 = Instant::now();
        match tokio::time::timeout(timeout, connect_ws(spec, &cfg)).await {
            // The socket is dropped right away: no WebSocket frame is ever sent.
            Ok(Ok(_)) => ProbeStatus::Reachable { rtt_ms: t0.elapsed().as_millis() as u32 },
            Ok(Err(CarrierError::Blocked(m))) => ProbeStatus::Blocked(m),
            Ok(Err(e)) => ProbeStatus::Error(e.to_string()),
            Err(_) => ProbeStatus::Blocked("timeout".into()),
        }
    }
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        Ok(Arc::new(listen_ws(spec).await?))
    }
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        Ok(Arc::new(dial_ws(spec).await?))
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;

    #[test]
    fn per_ip_cap_frees_on_drop() {
        let by = PendingByIp::default();
        let (a, b): (std::net::IpAddr, std::net::IpAddr) = ("9.9.9.9".parse().unwrap(), "9.9.9.10".parse().unwrap());
        let held: Vec<_> = (0..MAX_PENDING_PER_IP).map(|_| by.take(a).expect("slot")).collect();
        assert!(by.take(a).is_none(), "ninth from one address is refused");
        assert!(by.take(b).is_some(), "another address is unaffected");
        drop(held);
        assert!(by.take(a).is_some());
        assert!(by.0.lock().unwrap().len() <= 1, "no leaked entries");
    }

    #[test]
    fn serial_is_not_seed_material_and_deterministic() {
        let (a, b) = (Identity::derive(b"k"), Identity::derive(b"k"));
        assert_eq!(a.serial, b.serial);
        assert_ne!(a.serial, a.seed[..16]);
        assert_eq!(a.pin_hex(), b.pin_hex());
    }
}
