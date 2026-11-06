//! Length-prefixed frames over any `AsyncRead + AsyncWrite` (TLS, WebSocket binary stream, an
//! Xray TCP inbound). One connection per peer, so peer keys are unique by construction.
//!
//! Record format (big endian):
//! ```text
//! plain   : [u16 body_len][frame]                      body_len = frame len
//! padded  : [u16 body_len][u16 frame_len][frame][pad]  body_len = bucket size (>= 2 + frame_len)
//! ```
//! A body that carries no frame (plain `body_len == 0`, padded `frame_len == 0`) is a cover record
//! and is ignored by the receiver. Both ends must use the same `buckets` setting.
//!
//! Queues are bounded. Outbound: drop-oldest (counted in [`StreamStats::dropped_oldest`]) so a
//! slow TCP path never turns into seconds of bufferbloat. Inbound: the reader task waits for room,
//! which stops reading the socket and lets TCP back-pressure the sender.
//!
//! Traffic shaping (doc section 6.4): size buckets + random extra padding, coalescing window, and
//! a jitter hook run before each write. None of it is a proven defence.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::{CarrierError, CarrierId, Caps, FrameIo, Health, Rng};

pub const MAX_BODY: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Length prefix (or inner frame length) above the configured maximum.
    Oversize { len: usize, max: usize },
    /// Padded body shorter than its inner header, or inner length beyond the body.
    BadBody,
    /// The stream ended in the middle of a record.
    Truncated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Oversize { len, max } => write!(f, "record of {len} bytes exceeds limit {max}"),
            FrameError::BadBody => f.write_str("malformed padded record"),
            FrameError::Truncated => f.write_str("stream ended inside a record"),
        }
    }
}
impl std::error::Error for FrameError {}

/// Codec parameters; both ends must agree on `buckets.is_empty()`.
#[derive(Debug, Clone)]
pub struct FramingCfg {
    pub max_frame: usize,
    /// Body sizes to pad up to (ascending after `normalized`). Empty = no padding mode.
    pub buckets: Vec<usize>,
    /// Up to this many extra random pad bytes before rounding to a bucket (padded mode only).
    pub random_pad: usize,
}

impl FramingCfg {
    pub fn plain(max_frame: usize) -> Self {
        Self { max_frame, buckets: Vec::new(), random_pad: 0 }
    }
    pub fn padded(&self) -> bool {
        !self.buckets.is_empty()
    }
    fn max_body(&self) -> usize {
        if self.padded() {
            (self.max_frame + 2).max(self.buckets.iter().copied().max().unwrap_or(0)).min(MAX_BODY)
        } else {
            self.max_frame
        }
    }
    fn validate(&self) -> Result<(), CarrierError> {
        if self.max_frame == 0 || self.max_frame + if self.padded() { 2 } else { 0 } > MAX_BODY {
            return Err(CarrierError::Failed(format!("max_frame {} out of range", self.max_frame)));
        }
        if self.buckets.iter().any(|&b| b < 3 || b > MAX_BODY) {
            return Err(CarrierError::Failed("bucket size out of range".into()));
        }
        Ok(())
    }
}

/// Append one record. An empty `frame` in padded mode makes a cover record.
pub fn encode_record(cfg: &FramingCfg, frame: &[u8], rng: &mut Rng, out: &mut Vec<u8>) -> Result<(), CarrierError> {
    if frame.len() > cfg.max_frame {
        return Err(CarrierError::FrameTooLarge { max: cfg.max_frame });
    }
    if !cfg.padded() {
        out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        out.extend_from_slice(frame);
        return Ok(());
    }
    let mut body = 2 + frame.len();
    if cfg.random_pad > 0 {
        body += rng.below(cfg.random_pad as u64 + 1) as usize;
    }
    if let Some(b) = cfg.buckets.iter().copied().filter(|&b| b >= body).min() {
        body = b;
    }
    let body = body.min(MAX_BODY);
    out.extend_from_slice(&(body as u16).to_be_bytes());
    out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    out.extend_from_slice(frame);
    let start = out.len();
    out.resize(start + body - 2 - frame.len(), 0);
    rng.fill(&mut out[start..]);
    Ok(())
}

/// Incremental decoder. Memory is bounded by `max_body + 2` whatever the length prefix claims:
/// nothing is reserved from a prefix, bytes are only buffered as they arrive.
pub struct FrameDecoder {
    cfg: FramingCfg,
    max_body: usize,
    buf: Vec<u8>,
    want: Option<usize>,
}

impl FrameDecoder {
    pub fn new(cfg: &FramingCfg) -> Self {
        Self { cfg: cfg.clone(), max_body: cfg.max_body(), buf: Vec::new(), want: None }
    }

    /// Feed bytes of any split; complete frames are appended to `out`. After an `Err` the stream
    /// is out of sync: close it.
    pub fn feed(&mut self, mut data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), FrameError> {
        while !data.is_empty() {
            let target = self.want.unwrap_or(2);
            let take = (target - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < target {
                continue;
            }
            match self.want {
                None => {
                    let n = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                    if n > self.max_body {
                        return Err(FrameError::Oversize { len: n, max: self.max_body });
                    }
                    self.buf.clear();
                    if n > 0 {
                        self.want = Some(n);
                    }
                }
                Some(n) => {
                    if self.cfg.padded() {
                        if n < 2 {
                            return Err(FrameError::BadBody);
                        }
                        let fl = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                        if 2 + fl > n {
                            return Err(FrameError::BadBody);
                        }
                        if fl > self.cfg.max_frame {
                            return Err(FrameError::Oversize { len: fl, max: self.cfg.max_frame });
                        }
                        if fl > 0 {
                            out.push(self.buf[2..2 + fl].to_vec());
                        }
                    } else {
                        out.push(std::mem::take(&mut self.buf));
                    }
                    self.buf.clear();
                    self.want = None;
                }
            }
        }
        Ok(())
    }

    /// Call at end of stream: partial data buffered means the peer cut a record in half.
    pub fn finish(&self) -> Result<(), FrameError> {
        if self.buf.is_empty() && self.want.is_none() { Ok(()) } else { Err(FrameError::Truncated) }
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Allocated buffer size (tests assert a hostile length prefix reserves nothing).
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

/// Returns how long to wait before each write.
pub type Jitter = Arc<dyn Fn() -> Duration + Send + Sync>;

#[derive(Clone)]
pub struct StreamCfg {
    pub id: CarrierId,
    pub framing: FramingCfg,
    /// Address reported by `local_addr` (a stream carrier has no UDP port).
    pub local: SocketAddr,
    pub out_queue: usize,
    pub in_queue: usize,
    /// Wait this long after the first queued frame for more to share one write. 0 = off.
    pub coalesce: Duration,
    pub coalesce_max_bytes: usize,
    pub jitter: Option<Jitter>,
}

impl StreamCfg {
    pub fn new(id: CarrierId, max_frame: usize) -> Self {
        Self {
            id,
            framing: FramingCfg::plain(max_frame),
            local: SocketAddr::from(([127, 0, 0, 1], 0)),
            out_queue: 256,
            in_queue: 256,
            coalesce: Duration::ZERO,
            coalesce_max_bytes: 16 * 1024,
            jitter: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    pub frames_in: u64,
    pub frames_out: u64,
    pub bytes_out: u64,
    pub dropped_oldest: u64,
    /// Received frames that did not fit the caller's buffer (delivered as `FrameTooLarge`).
    pub oversize_rx: u64,
    pub writes: u64,
}

#[derive(Default)]
struct Counters {
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    bytes_out: AtomicU64,
    dropped_oldest: AtomicU64,
    oversize_rx: AtomicU64,
    writes: AtomicU64,
}

struct Inbox {
    q: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    cap: usize,
    readable: Notify,
    space: Notify,
}

impl Inbox {
    async fn push(&self, f: Vec<u8>, peer: SocketAddr) {
        let mut f = Some(f);
        loop {
            let n = self.space.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            {
                let mut q = self.q.lock().unwrap();
                if q.len() < self.cap {
                    q.push_back((f.take().unwrap(), peer));
                    drop(q);
                    self.readable.notify_one();
                    return;
                }
            }
            n.await;
        }
    }
}

struct OutQ {
    q: Mutex<VecDeque<Vec<u8>>>,
    cap: usize,
    notify: Notify,
}

struct Conn {
    out: Arc<OutQ>,
    tasks: [AbortHandle; 2],
}

struct Shared {
    cfg: StreamCfg,
    inbox: Inbox,
    conns: Mutex<HashMap<SocketAddr, Conn>>,
    closed_events: Mutex<Vec<(SocketAddr, CarrierError)>>,
    /// Set once a connection has existed and none is left (or `close()` ran).
    sticky: Mutex<Option<CarrierError>>,
    ever: AtomicBool,
    n: Counters,
}

impl Shared {
    fn conn_closed(&self, peer: SocketAddr, why: CarrierError) {
        let mut conns = self.conns.lock().unwrap();
        if let Some(c) = conns.remove(&peer) {
            for t in &c.tasks {
                t.abort();
            }
        } else {
            return; // already reported
        }
        let empty = conns.is_empty();
        drop(conns);
        {
            let mut ev = self.closed_events.lock().unwrap();
            if ev.len() >= 64 {
                ev.remove(0);
            }
            ev.push((peer, why.clone()));
        }
        if empty {
            *self.sticky.lock().unwrap() = Some(why);
        }
        self.inbox.readable.notify_one();
    }
}

fn map_io(e: io::Error) -> CarrierError {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof => CarrierError::Reset(e.to_string()),
        _ => CarrierError::Failed(e.to_string()),
    }
}

/// A set of stream connections presented as one [`FrameIo`]. A client adds one connection; a host
/// adds one per accepted client (keyed by its remote address).
pub struct StreamCarrier {
    sh: Arc<Shared>,
}

impl Drop for StreamCarrier {
    fn drop(&mut self) {
        abort_all(&self.sh);
    }
}

fn abort_all(sh: &Shared) {
    for (_, c) in sh.conns.lock().unwrap().drain() {
        for t in &c.tasks {
            t.abort();
        }
    }
}

impl StreamCarrier {
    pub fn new(cfg: StreamCfg) -> Result<Self, CarrierError> {
        cfg.framing.validate()?;
        if cfg.out_queue == 0 || cfg.in_queue == 0 {
            return Err(CarrierError::Failed("queues must hold at least one frame".into()));
        }
        let inbox = Inbox { q: Mutex::new(VecDeque::new()), cap: cfg.in_queue, readable: Notify::new(), space: Notify::new() };
        Ok(Self {
            sh: Arc::new(Shared {
                cfg,
                inbox,
                conns: Mutex::new(HashMap::new()),
                closed_events: Mutex::new(Vec::new()),
                sticky: Mutex::new(None),
                ever: AtomicBool::new(false),
                n: Counters::default(),
            }),
        })
    }

    /// Client convenience: one connection, shown to the transport as `virtual_host`.
    pub fn client<S>(cfg: StreamCfg, io: S, virtual_host: SocketAddr) -> Result<Self, CarrierError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let c = Self::new(cfg)?;
        c.add_conn(io, virtual_host)?;
        Ok(c)
    }

    /// Needs a Tokio runtime. `peer` must be unused.
    pub fn add_conn<S>(&self, io: S, peer: SocketAddr) -> Result<(), CarrierError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let sh = &self.sh;
        let mut conns = sh.conns.lock().unwrap();
        if conns.contains_key(&peer) {
            return Err(CarrierError::Failed(format!("peer {peer} already connected")));
        }
        let (mut rd, mut wr) = tokio::io::split(io);
        let out = Arc::new(OutQ { q: Mutex::new(VecDeque::new()), cap: sh.cfg.out_queue, notify: Notify::new() });

        let s = sh.clone();
        let reader = tokio::spawn(async move {
            let mut dec = FrameDecoder::new(&s.cfg.framing);
            let mut buf = vec![0u8; 16 * 1024];
            let mut frames = Vec::new();
            let why = loop {
                match rd.read(&mut buf).await {
                    Ok(0) => {
                        break match dec.finish() {
                            Ok(()) => CarrierError::Eof,
                            Err(_) => CarrierError::Reset("closed in the middle of a record".into()),
                        }
                    }
                    Ok(n) => {
                        frames.clear();
                        let r = dec.feed(&buf[..n], &mut frames);
                        for f in frames.drain(..) {
                            s.n.frames_in.fetch_add(1, Ordering::Relaxed);
                            s.inbox.push(f, peer).await;
                        }
                        if let Err(e) = r {
                            break CarrierError::Failed(format!("framing: {e}"));
                        }
                    }
                    Err(e) => break map_io(e),
                }
            };
            s.conn_closed(peer, why);
        });

        let s = sh.clone();
        let q = out.clone();
        let writer = tokio::spawn(async move {
            let mut rng = Rng::from_entropy();
            let why = 'outer: loop {
                let mut batch: Vec<u8> = Vec::new();
                let mut frames = 0u64;
                // Wait for the first frame, then (optionally) a coalescing window.
                loop {
                    let n = q.notify.notified();
                    tokio::pin!(n);
                    n.as_mut().enable();
                    let got: Vec<Vec<u8>> = q.q.lock().unwrap().drain(..).collect();
                    if !got.is_empty() {
                        for f in got {
                            if let Err(e) = encode_record(&s.cfg.framing, &f, &mut rng, &mut batch) {
                                break 'outer e;
                            }
                            frames += 1;
                        }
                        break;
                    }
                    n.await;
                }
                if !s.cfg.coalesce.is_zero() {
                    let deadline = tokio::time::Instant::now() + s.cfg.coalesce;
                    while batch.len() < s.cfg.coalesce_max_bytes {
                        let n = q.notify.notified();
                        tokio::pin!(n);
                        n.as_mut().enable();
                        let got: Vec<Vec<u8>> = q.q.lock().unwrap().drain(..).collect();
                        for f in got {
                            if let Err(e) = encode_record(&s.cfg.framing, &f, &mut rng, &mut batch) {
                                break 'outer e;
                            }
                            frames += 1;
                        }
                        if batch.len() >= s.cfg.coalesce_max_bytes {
                            break;
                        }
                        if tokio::time::timeout_at(deadline, n).await.is_err() {
                            break;
                        }
                    }
                }
                if let Some(j) = &s.cfg.jitter {
                    let d = j();
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
                if let Err(e) = wr.write_all(&batch).await {
                    break map_io(e);
                }
                if let Err(e) = wr.flush().await {
                    break map_io(e);
                }
                s.n.frames_out.fetch_add(frames, Ordering::Relaxed);
                s.n.bytes_out.fetch_add(batch.len() as u64, Ordering::Relaxed);
                s.n.writes.fetch_add(1, Ordering::Relaxed);
            };
            s.conn_closed(peer, why);
        });

        conns.insert(peer, Conn { out, tasks: [reader.abort_handle(), writer.abort_handle()] });
        sh.ever.store(true, Ordering::Relaxed);
        *sh.sticky.lock().unwrap() = None;
        Ok(())
    }

    /// Host side: accept TCP connections forever, one peer per remote address.
    pub fn serve_tcp(&self, listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
        let me = StreamCarrier { sh: self.sh.clone() };
        tokio::spawn(async move {
            // `me` shares state only; dropping it at task end must not abort connections.
            let me = std::mem::ManuallyDrop::new(me);
            while let Ok((s, remote)) = listener.accept().await {
                let _ = s.set_nodelay(true);
                if let Err(e) = me.add_conn(s, remote) {
                    log::debug!("stream carrier: reject {remote}: {e}");
                }
            }
        })
    }

    pub fn stats(&self) -> StreamStats {
        let n = &self.sh.n;
        StreamStats {
            frames_in: n.frames_in.load(Ordering::Relaxed),
            frames_out: n.frames_out.load(Ordering::Relaxed),
            bytes_out: n.bytes_out.load(Ordering::Relaxed),
            dropped_oldest: n.dropped_oldest.load(Ordering::Relaxed),
            oversize_rx: n.oversize_rx.load(Ordering::Relaxed),
            writes: n.writes.load(Ordering::Relaxed),
        }
    }

    /// Connections that ended since the last call, with the typed reason (`Eof`, `Reset`, ...).
    pub fn take_closed(&self) -> Vec<(SocketAddr, CarrierError)> {
        std::mem::take(&mut *self.sh.closed_events.lock().unwrap())
    }

    pub fn peers(&self) -> Vec<SocketAddr> {
        self.sh.conns.lock().unwrap().keys().copied().collect()
    }

    pub fn inbox_len(&self) -> usize {
        self.sh.inbox.q.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl FrameIo for StreamCarrier {
    fn caps(&self) -> Caps {
        let c = &self.sh.cfg;
        Caps {
            id: c.id,
            max_frame: c.framing.max_frame,
            punchable: false,
            reliable_stream: true,
            overhead: if c.framing.padded() { 4 } else { 2 },
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.sh.cfg.local)
    }

    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        let max = self.sh.cfg.framing.max_frame;
        if frame.len() > max {
            return Err(CarrierError::FrameTooLarge { max }.into());
        }
        if frame.is_empty() {
            return Err(CarrierError::Failed("empty frame".into()).into());
        }
        let out = {
            let conns = self.sh.conns.lock().unwrap();
            match conns.get(&to) {
                Some(c) => c.out.clone(),
                None => {
                    let e = if conns.is_empty() && self.sh.ever.load(Ordering::Relaxed) {
                        CarrierError::Closed
                    } else {
                        CarrierError::UnknownPeer
                    };
                    return Err(e.into());
                }
            }
        };
        {
            let mut q = out.q.lock().unwrap();
            if q.len() >= out.cap {
                q.pop_front();
                self.sh.n.dropped_oldest.fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(frame.to_vec());
        }
        out.notify.notify_one();
        Ok(frame.len())
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let item = self.sh.inbox.q.lock().unwrap().pop_front();
        match item {
            Some((f, peer)) => {
                self.sh.inbox.space.notify_one();
                if f.len() > buf.len() {
                    self.sh.n.oversize_rx.fetch_add(1, Ordering::Relaxed);
                    return Err(CarrierError::FrameTooLarge { max: buf.len() }.into());
                }
                buf[..f.len()].copy_from_slice(&f);
                Ok((f.len(), peer))
            }
            None => match self.sh.sticky.lock().unwrap().clone() {
                Some(e) => Err(e.into()),
                None => Err(io::ErrorKind::WouldBlock.into()),
            },
        }
    }

    async fn readable(&self) -> io::Result<()> {
        loop {
            let n = self.sh.inbox.readable.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if !self.sh.inbox.q.lock().unwrap().is_empty() || self.sh.sticky.lock().unwrap().is_some() {
                return Ok(());
            }
            n.await;
        }
    }

    fn health(&self) -> Health {
        match &*self.sh.sticky.lock().unwrap() {
            Some(e) => Health::Down(e.to_string()),
            None => Health::Ok,
        }
    }

    async fn close(&self) {
        abort_all(&self.sh);
        *self.sh.sticky.lock().unwrap() = Some(CarrierError::Closed);
        self.sh.inbox.readable.notify_one();
    }
}
