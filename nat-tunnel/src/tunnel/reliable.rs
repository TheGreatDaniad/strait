//! Reliable delivery over the lossy tunnel datagrams.
//!
//! Sliding window ARQ: up to [`WINDOW`] unacknowledged frames in flight, with
//! cumulative acknowledgements, an out-of-order buffer on the receiver, and
//! timeout-based retransmission. Stop-and-wait capped throughput at one frame
//! per round trip; a window makes bulk transfer practical.
//!
//! Frame layout (inside the AEAD plaintext):
//!
//! ```text
//! DATA:  [0x01][seq u32 BE][payload..]
//! ACK:   [0x02][last in-order seq u32 BE]
//! HELLO: [0x03]
//! BYE:   [0x04]
//! ```

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Largest payload carried by one frame (keeps datagrams well under a 1200-byte MTU).
pub const MAX_PAYLOAD: usize = 1400;
/// Upper bound for the congestion window and the reorder buffer.
pub const WINDOW: usize = 512;
/// Initial congestion window (frames).
const INITIAL_CWND: usize = 16;
/// Never shrink below this, or recovery stalls.
const MIN_CWND: usize = 8;
/// Retransmit timeout for unacknowledged frames.
pub const RETRANSMIT: Duration = Duration::from_millis(250);
/// Give up after this many attempts for a frame.
pub const MAX_ATTEMPTS: u32 = 40;
/// Bound the send queue so a fast local source cannot grow memory without limit.
const MAX_QUEUE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data { seq: u32, payload: Vec<u8> },
    Ack { seq: u32 },
    Hello,
    Bye,
}

pub fn encode(frame: &Frame) -> Vec<u8> {
    match frame {
        Frame::Data { seq, payload } => {
            let mut out = Vec::with_capacity(5 + payload.len());
            out.push(0x01);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        Frame::Ack { seq } => {
            let mut out = Vec::with_capacity(5);
            out.push(0x02);
            out.extend_from_slice(&seq.to_be_bytes());
            out
        }
        Frame::Hello => vec![0x03],
        Frame::Bye => vec![0x04],
    }
}

pub fn decode(bytes: &[u8]) -> Option<Frame> {
    match bytes.first()? {
        0x01 if bytes.len() >= 5 => Some(Frame::Data {
            seq: u32::from_be_bytes(bytes[1..5].try_into().ok()?),
            payload: bytes[5..].to_vec(),
        }),
        0x02 if bytes.len() >= 5 => Some(Frame::Ack {
            seq: u32::from_be_bytes(bytes[1..5].try_into().ok()?),
        }),
        0x03 if bytes.len() == 1 => Some(Frame::Hello),
        0x04 if bytes.len() == 1 => Some(Frame::Bye),
        _ => None,
    }
}

struct Outstanding {
    seq: u32,
    frame: Frame,
    last_sent: Instant,
    attempts: u32,
}

/// One reliable byte stream, one direction per sequence space.
pub struct Reliable {
    queue: VecDeque<Vec<u8>>,
    outstanding: VecDeque<Outstanding>,
    /// Congestion window in frames: grows with ACK progress, halves on loss.
    cwnd: usize,
    /// Slow-start threshold; above it growth is +1 per RTT.
    ssthresh: usize,
    /// Credit for the +1-per-RTT growth.
    ca_credit: usize,
    /// Duplicate ACKs for fast retransmit.
    dup_acks: u32,
    /// When the window last backed off; prevents halving on every poll.
    last_backoff: Option<Instant>,
    next_seq: u32,
    expected_seq: u32,
    received_any: bool,
    reorder: BTreeMap<u32, Vec<u8>>,
    failed: bool,
}

impl Default for Reliable {
    fn default() -> Self {
        Self::new()
    }
}

impl Reliable {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            outstanding: VecDeque::new(),
            cwnd: INITIAL_CWND,
            ssthresh: WINDOW,
            ca_credit: 0,
            dup_acks: 0,
            last_backoff: None,
            next_seq: 1,
            expected_seq: 1,
            received_any: false,
            reorder: BTreeMap::new(),
            failed: false,
        }
    }

    /// Queue bytes for delivery and return the frames that fit the window.
    pub fn send(&mut self, data: &[u8], now: Instant) -> Vec<Frame> {
        for chunk in data.chunks(MAX_PAYLOAD) {
            if self.queue.len() >= MAX_QUEUE {
                // The receiver cannot keep up; drop rather than grow forever.
                break;
            }
            self.queue.push_back(chunk.to_vec());
        }
        self.fill_window(now)
    }

    /// Feed a received frame. Returns payloads delivered in order plus frames
    /// that must be sent back (acknowledgements and newly windowed data).
    pub fn recv(&mut self, frame: Frame, now: Instant) -> (Vec<Vec<u8>>, Vec<Frame>) {
        match frame {
            Frame::Data { seq, payload } => {
                let mut delivered = Vec::new();
                if seq == self.expected_seq {
                    delivered.push(payload);
                    self.expected_seq = self.expected_seq.wrapping_add(1);
                    self.received_any = true;
                    while let Some(next) = self.reorder.remove(&self.expected_seq) {
                        delivered.push(next);
                        self.expected_seq = self.expected_seq.wrapping_add(1);
                    }
                } else if seq > self.expected_seq
                    && seq < self.expected_seq.wrapping_add(WINDOW as u32 * 2)
                {
                    // Out of order but inside the window: keep it for later.
                    self.reorder.entry(seq).or_insert(payload);
                }

                let ack = if self.received_any {
                    self.expected_seq.wrapping_sub(1)
                } else {
                    0
                };
                let mut out = vec![Frame::Ack { seq: ack }];
                out.extend(self.fill_window(now));
                (delivered, out)
            }
            Frame::Ack { seq } => {
                let mut freed = 0;
                while let Some(front) = self.outstanding.front() {
                    if front.seq <= seq {
                        self.outstanding.pop_front();
                        freed += 1;
                    } else {
                        break;
                    }
                }
                if freed > 0 {
                    self.dup_acks = 0;
                    if self.cwnd < self.ssthresh {
                        // Slow start: grow by the number of frames acked.
                        self.cwnd = (self.cwnd + freed).min(WINDOW);
                    } else {
                        // Congestion avoidance: +1 frame per RTT.
                        self.ca_credit += freed;
                        while self.ca_credit >= self.cwnd && self.cwnd < WINDOW {
                            self.ca_credit -= self.cwnd;
                            self.cwnd += 1;
                        }
                        if self.cwnd >= WINDOW {
                            self.ca_credit = 0;
                        }
                    }
                } else if !self.outstanding.is_empty() {
                    // Duplicate ACK: after three, retransmit the oldest frame
                    // instead of waiting for the full timeout.
                    self.dup_acks += 1;
                    if self.dup_acks >= 3 {
                        self.dup_acks = 0;
                        if let Some(front) = self.outstanding.front_mut() {
                            front.last_sent = now.checked_sub(RETRANSMIT).unwrap_or(now);
                        }
                        self.back_off(now);
                    }
                }
                (Vec::new(), self.fill_window(now))
            }
            Frame::Hello => (Vec::new(), vec![Frame::Hello]),
            Frame::Bye => {
                self.failed = true;
                (Vec::new(), Vec::new())
            }
        }
    }

    /// Retransmit frames whose timers expired, then top up the window.
    pub fn poll(&mut self, now: Instant) -> Vec<Frame> {
        if self.failed {
            return Vec::new();
        }
        // Frames are ordered, so the front is the oldest. If it is not due,
        // no other frame is either: skip the 512-entry scan entirely.
        let expired = self
            .outstanding
            .front()
            .is_some_and(|front| now.duration_since(front.last_sent) >= RETRANSMIT);
        if !expired {
            return self.fill_window(now);
        }
        let mut out = Vec::new();
        // Pace repairs: a large window can lose several frames at once, but
        // resending all of them in one burst makes congestion worse.
        let mut budget = 16;
        for pending in self.outstanding.iter_mut() {
            if budget == 0 {
                break;
            }
            if now.duration_since(pending.last_sent) < RETRANSMIT {
                continue;
            }
            pending.attempts += 1;
            if pending.attempts > MAX_ATTEMPTS {
                self.failed = true;
                return vec![Frame::Bye];
            }
            pending.last_sent = now;
            out.push(pending.frame.clone());
            budget -= 1;
        }
        if !out.is_empty() {
            self.back_off(now);
        }
        out.extend(self.fill_window(now));
        out
    }

    /// True while the caller may hand over more bytes without overrunning
    /// the in-flight window or the send queue.
    pub fn can_accept(&self) -> bool {
        self.queue.len() < self.cwnd
    }

    pub fn has_pending(&self) -> bool {
        !self.outstanding.is_empty() || !self.queue.is_empty()
    }

    /// Drop all state, as if the stream had just been opened.
    pub fn reset(&mut self) {
        self.queue.clear();
        self.outstanding.clear();
        self.cwnd = INITIAL_CWND;
        self.ssthresh = WINDOW;
        self.ca_credit = 0;
        self.dup_acks = 0;
        self.last_backoff = None;
        self.next_seq = 1;
        self.expected_seq = 1;
        self.received_any = false;
        self.reorder.clear();
        self.failed = false;
    }

    /// (congestion window, frames in flight, queued payloads)
    pub fn status(&self) -> (usize, usize, usize) {
        (self.cwnd, self.outstanding.len(), self.queue.len())
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    /// One congestion response per RTO, however many frames are being
    /// repaired. Halving on every poll collapsed the window in <1 s.
    fn back_off(&mut self, now: Instant) {
        let due = self
            .last_backoff
            .is_none_or(|last| now.duration_since(last) >= RETRANSMIT);
        if !due {
            return;
        }
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        self.ca_credit = 0;
        self.last_backoff = Some(now);
    }

    fn fill_window(&mut self, now: Instant) -> Vec<Frame> {
        let mut out = Vec::new();
        if self.failed {
            return out;
        }
        while self.outstanding.len() < self.cwnd {
            let Some(payload) = self.queue.pop_front() else {
                break;
            };
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            let frame = Frame::Data { seq, payload };
            self.outstanding.push_back(Outstanding {
                seq,
                frame: frame.clone(),
                last_sent: now,
                attempts: 0,
            });
            out.push(frame);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_codec_roundtrip() {
        for frame in [
            Frame::Data {
                seq: 7,
                payload: b"hello".to_vec(),
            },
            Frame::Ack { seq: 7 },
            Frame::Hello,
            Frame::Bye,
        ] {
            assert_eq!(decode(&encode(&frame)), Some(frame));
        }
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0x01]), None);
    }

    #[test]
    fn delivers_in_order_and_acks() {
        let now = Instant::now();
        let mut tx = Reliable::new();
        let mut rx = Reliable::new();

        let frames = tx.send(b"hello", now);
        assert_eq!(frames.len(), 1);
        let (data, acks) = rx.recv(frames[0].clone(), now);
        assert_eq!(data, vec![b"hello".to_vec()]);
        assert_eq!(acks[0], Frame::Ack { seq: 1 });

        let (_, next) = tx.recv(acks[0].clone(), now);
        assert!(next.is_empty());
        assert!(!tx.has_pending());
    }

    #[test]
    fn window_keeps_many_frames_in_flight() {
        let now = Instant::now();
        let mut tx = Reliable::new();
        let frames = tx.send(&vec![0u8; MAX_PAYLOAD * (WINDOW + 10)], now);
        assert_eq!(frames.len(), INITIAL_CWND);
        assert!(tx.has_pending());
    }

    #[test]
    fn congestion_window_grows_and_halves() {
        let now = Instant::now();
        let mut tx = Reliable::new();
        let frames = tx.send(&vec![0u8; MAX_PAYLOAD * 64], now);
        assert_eq!(frames.len(), INITIAL_CWND);

        // Acknowledge everything in flight: cwnd grows.
        let last = frames.last().unwrap();
        let seq = match last {
            Frame::Data { seq, .. } => *seq,
            _ => unreachable!(),
        };
        let (_, more) = tx.recv(Frame::Ack { seq }, now);
        assert!(!more.is_empty());
        assert!(tx.cwnd > INITIAL_CWND);

        // A timeout halves it.
        let before = tx.cwnd;
        let later = now + RETRANSMIT + Duration::from_millis(1);
        let _ = tx.poll(later);
        assert!(tx.cwnd <= before / 2 + 1);

        // A second poll inside the same RTO must not halve it again.
        let after = tx.cwnd;
        let soon = later + Duration::from_millis(20);
        let _ = tx.poll(soon);
        assert!(tx.cwnd >= after.min(MIN_CWND));
    }

    #[test]
    fn cumulative_ack_releases_the_window() {
        let now = Instant::now();
        let mut tx = Reliable::new();
        let frames = tx.send(&vec![0u8; MAX_PAYLOAD * 10], now);
        assert_eq!(frames.len(), 10);
        let (_, more) = tx.recv(Frame::Ack { seq: 10 }, now);
        assert!(more.is_empty());
        assert!(!tx.has_pending());
    }

    #[test]
    fn out_of_order_is_reordered() {
        let now = Instant::now();
        let mut rx = Reliable::new();
        let second = Frame::Data {
            seq: 2,
            payload: b"second".to_vec(),
        };
        let first = Frame::Data {
            seq: 1,
            payload: b"first".to_vec(),
        };
        let (delivered, _) = rx.recv(second, now);
        assert!(delivered.is_empty());
        let (delivered, _) = rx.recv(first, now);
        assert_eq!(delivered, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn duplicate_is_not_redelivered() {
        let now = Instant::now();
        let mut rx = Reliable::new();
        let frame = Frame::Data {
            seq: 1,
            payload: b"x".to_vec(),
        };
        assert_eq!(rx.recv(frame.clone(), now).0.len(), 1);
        assert!(rx.recv(frame, now).0.is_empty());
    }

    #[test]
    fn retransmits_after_timeout() {
        let now = Instant::now();
        let mut tx = Reliable::new();
        assert_eq!(tx.send(b"hello", now).len(), 1);
        assert!(tx.poll(now).is_empty());
        let later = now + RETRANSMIT + Duration::from_millis(1);
        assert_eq!(tx.poll(later).len(), 1);
    }
}
