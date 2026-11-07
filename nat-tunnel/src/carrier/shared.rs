//! A datagram port carved out of the host's plain UDP socket, so ss and awg can ride the one
//! socket whose STUN mapping a rendezvous method publishes (trackers announce a single port).
//!
//! The host feeds every datagram the plain protocol did not claim to each [`Port`] (`push`); the
//! carrier on top (awg envelope, ss AEAD) keeps what authenticates and drops the rest silently.
//! Sending goes out of the same socket, so the NAT mapping and the host's hole punch are shared.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::ReadBuf;
use tokio::sync::Notify;

use super::udp::to_wire;
use super::{Caps, FrameIo};

const QUEUE_CAP: usize = 1024;

#[derive(Default)]
struct Q {
    items: VecDeque<(Vec<u8>, SocketAddr)>,
    waker: Option<Waker>,
}

/// Pre-authentication budget per source address: the carrier on top pays for cipher setup on
/// every datagram, so addresses that never authenticated get a small token bucket.
const GATE_BURST: f64 = 32.0;
const GATE_PER_SEC: f64 = 8.0;
const GATE_MAX_SOURCES: usize = 4096;

#[derive(Default)]
struct Gate {
    known: HashSet<SocketAddr>,
    buckets: HashMap<SocketAddr, (f64, Instant)>,
}

impl Gate {
    fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        if self.known.contains(&from) {
            return true;
        }
        if self.buckets.len() >= GATE_MAX_SOURCES && !self.buckets.contains_key(&from) {
            // Idle buckets are full again: forgetting them loses nothing.
            self.buckets.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(5));
            if self.buckets.len() >= GATE_MAX_SOURCES {
                return false;
            }
        }
        let b = self.buckets.entry(from).or_insert((GATE_BURST, now));
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * GATE_PER_SEC).min(GATE_BURST);
        b.1 = now;
        if b.0 < 1.0 {
            return false;
        }
        b.0 -= 1.0;
        true
    }

    fn mark(&mut self, a: SocketAddr) {
        if self.known.len() >= GATE_MAX_SOURCES {
            self.known.clear(); // shortcut: authenticated peers re-mark on their next valid packet
        }
        self.buckets.remove(&a);
        self.known.insert(a);
    }
}

pub struct Port {
    raw: Arc<dyn FrameIo>,
    /// Sends of a `raw` that has no socket to write to directly (a wrapped or emulated carrier).
    pump: Option<tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    gate: Mutex<Option<Gate>>,
    q: Mutex<Q>,
    notify: Notify,
}

impl Port {
    /// `raw` is the plain UDP carrier; with a real socket the port writes to it directly, else
    /// every send goes through `raw.send_to`.
    pub fn new(raw: Arc<dyn FrameIo>) -> io::Result<Arc<Self>> {
        let pump = raw.udp().is_none().then(|| {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
            let r = raw.clone();
            tokio::spawn(async move {
                while let Some((d, to)) = rx.recv().await {
                    let _ = r.send_to(&d, to).await;
                }
            });
            tx
        });
        Ok(Arc::new(Self { raw, pump, gate: Mutex::new(None), q: Mutex::new(Q::default()), notify: Notify::new() }))
    }

    /// Rate-limit datagrams from sources not yet passed to [`Port::mark_known`].
    pub fn limit_unauth(&self) {
        *self.gate.lock().unwrap() = Some(Gate::default());
    }

    /// `from` authenticated: exempt it from the limit.
    pub fn mark_known(&self, from: SocketAddr) {
        if let Some(g) = self.gate.lock().unwrap().as_mut() {
            g.mark(from);
        }
    }

    /// Hand over a datagram the plain protocol did not claim. A full queue drops the newest.
    pub fn push(&self, d: &[u8], from: SocketAddr) {
        if self.gate.lock().unwrap().as_mut().is_some_and(|g| !g.allow(from, Instant::now())) {
            return;
        }
        let mut q = self.q.lock().unwrap();
        if q.items.len() < QUEUE_CAP {
            q.items.push_back((d.to_vec(), from));
            if let Some(w) = q.waker.take() {
                w.wake();
            }
            drop(q);
            self.notify.notify_one();
        }
    }

    pub fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        let mut q = self.q.lock().unwrap();
        match q.items.pop_front() {
            Some((d, from)) => {
                let n = d.len().min(buf.remaining());
                buf.put_slice(&d[..n]);
                Poll::Ready(Ok(from))
            }
            None => {
                q.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut q = self.q.lock().unwrap();
        if q.items.is_empty() {
            q.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    pub fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], to: SocketAddr) -> Poll<io::Result<usize>> {
        let Some(sock) = self.raw.udp() else {
            let _ = self.pump.as_ref().expect("set in new").send((buf.to_vec(), to));
            return Poll::Ready(Ok(buf.len()));
        };
        let dual = sock.local_addr().is_ok_and(|a| a.is_ipv6());
        sock.poll_send_to(cx, buf, to_wire(dual, to))
    }
}

#[async_trait::async_trait]
impl FrameIo for Port {
    fn caps(&self) -> Caps {
        self.raw.caps()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.raw.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.raw.send_to(frame, to).await
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some((d, from)) = self.q.lock().unwrap().items.pop_front() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let n = d.len().min(buf.len());
        buf[..n].copy_from_slice(&d[..n]);
        Ok((n, from))
    }
    async fn readable(&self) -> io::Result<()> {
        loop {
            if !self.q.lock().unwrap().items.is_empty() {
                return Ok(());
            }
            self.notify.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauth_source_is_limited_known_is_not() {
        let mut g = Gate::default();
        let (a, b): (SocketAddr, SocketAddr) = ("1.2.3.4:5".parse().unwrap(), "1.2.3.4:6".parse().unwrap());
        let t = Instant::now();
        let passed = (0..100).filter(|_| g.allow(a, t)).count();
        assert_eq!(passed, GATE_BURST as usize);
        assert!(g.allow(b, t), "another port behind the same NAT is independent");
        g.mark(a);
        assert!((0..100).all(|_| g.allow(a, t)), "an authenticated source is unaffected");
        assert!(g.allow(b, t + Duration::from_secs(10)), "bucket refills");
    }

    #[test]
    fn gate_memory_is_bounded() {
        let mut g = Gate::default();
        let t = Instant::now();
        for i in 0..(GATE_MAX_SOURCES as u32 + 100) {
            g.allow(SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 1)), t);
        }
        assert!(g.buckets.len() <= GATE_MAX_SOURCES);
    }
}
