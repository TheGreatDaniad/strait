//! Authenticated encryption for tunnel datagrams.
//!
//! Every datagram on the wire is sealed with ChaCha20-Poly1305 under a key from the join
//! handshake (`tunnel::handshake`); nothing is ever keyed from the invite alone.
//!
//! Wire format (clear part + ciphertext):
//!
//! ```text
//! [u64 session id][u64 counter][ciphertext + 16-byte tag]
//! ```
//!
//! The session id is authenticated as AEAD associated data; a new session (a peer that joined
//! again) picks a new id, which tells the other side to reset its stream state.
//!
//! The counter is the nonce (the two directions use disjoint nonce spaces through the direction
//! bit) and the replay guard: a sliding window of [`WINDOW`] counters accepts reordered datagrams
//! once each (RFC 6479 style); anything older or seen before is a replay.
//!
//! Key rotation: the top 24 bits of the counter are an epoch, and epochs follow the clock: every
//! [`REKEY_EVERY`] since the session began, both sides hash their send key and their receive key
//! forward and drop the old ones, whether or not anything was sent. Nothing is negotiated and no
//! packet is added. A key taken from a device later cannot open earlier epochs. Each (key, nonce)
//! pair is used once: a key belongs to one epoch of one direction, and the counter within it only
//! grows.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

/// Datagram starts with an 8-byte session id and an 8-byte counter.
pub const HEADER_LEN: usize = 16;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// How long one key lives.
pub const REKEY_EVERY: Duration = Duration::from_secs(120);
/// Counter bits below the epoch.
const EPOCH_SHIFT: u32 = 40;
/// A receiver derives at most this many epochs ahead for one datagram (a forged counter costs
/// no more than this), and keeps this many epochs of slack behind its clock.
const MAX_EPOCH_JUMP: u64 = 64;
const SLACK_EPOCHS: u64 = 2;
/// Reordered datagrams accepted per direction.
pub const WINDOW: u64 = 2048;

/// The next epoch's key. One-way: the previous key cannot be recovered from it.
fn next_key(k: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"strait-rekey-v3");
    h.update(k);
    zeroize::Zeroizing::new(h.finalize().into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Datagram shorter than header or tag.
    TooShort,
    /// Counter not greater than the last accepted one.
    Replay,
    /// Authentication failed (wrong key or tampered datagram).
    BadTag,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::TooShort => write!(f, "datagram too short"),
            CryptoError::Replay => write!(f, "replayed datagram"),
            CryptoError::BadTag => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        .max(1)
}

/// A session id that orders sessions by time but is not predictable to the millisecond.
fn new_session_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let r = u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let id = ((now_nanos() & !0xF_FFFF) | (r & 0xF_FFFF)).max(1);
    LAST.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some(id.max(l + 1))).map_or(id, |l| id.max(l + 1))
}

/// One direction's key and its epoch.
struct Dir {
    key: zeroize::Zeroizing<[u8; 32]>,
    cipher: ChaCha20Poly1305,
    epoch: u64,
}

impl Dir {
    fn new(k: &[u8; 32]) -> Self {
        Self { key: zeroize::Zeroizing::new(*k), cipher: ChaCha20Poly1305::new(Key::from_slice(k)), epoch: 0 }
    }
    /// This direction's key `n` epochs on (without changing it).
    fn ahead(&self, n: u64) -> Self {
        let mut k = zeroize::Zeroizing::new(*self.key);
        for _ in 0..n {
            k = next_key(&k);
        }
        Self { cipher: ChaCha20Poly1305::new(Key::from_slice(&k[..])), key: k, epoch: self.epoch + n }
    }
}

/// Sliding replay window over the counters of the current receive epoch.
#[derive(Default)]
struct Window {
    /// Highest counter accepted (0 = none yet).
    top: u64,
    bits: [u64; (WINDOW / 64) as usize],
}

impl Window {
    fn bit(&mut self, c: u64) -> (&mut u64, u64) {
        let i = c % WINDOW;
        (&mut self.bits[(i / 64) as usize], 1 << (i % 64))
    }
    /// Would `c` be new?
    fn fresh(&self, c: u64) -> bool {
        if c > self.top {
            return true;
        }
        if self.top - c >= WINDOW || c == 0 {
            return false;
        }
        let i = c % WINDOW;
        self.bits[(i / 64) as usize] & (1 << (i % 64)) == 0
    }
    /// Mark `c` seen (call only after `fresh` and after the tag checked).
    fn mark(&mut self, c: u64) {
        if c > self.top {
            let gap = c - self.top;
            if gap >= WINDOW {
                self.bits = [0; (WINDOW / 64) as usize];
            } else {
                for x in self.top + 1..c {
                    let (w, m) = self.bit(x);
                    *w &= !m;
                }
            }
            self.top = c;
        }
        let (w, m) = self.bit(c);
        *w |= m;
    }
}

pub struct AeadSession {
    send: Dir,
    recv: Dir,
    /// True when this side is the host (controls the nonce direction bit).
    host: bool,
    /// Identifies this session; a new one picks a larger value.
    session: u64,
    /// Largest session id seen from the peer.
    peer_session: u64,
    send_counter: u64,
    window: Window,
    /// When the session began: epochs follow from it.
    born: Instant,
}

impl AeadSession {
    /// A session under the key from the join handshake.
    pub fn from_key(key: &[u8; 32], host: bool) -> Self {
        Self {
            send: Dir::new(key),
            recv: Dir::new(key),
            host,
            session: new_session_id(),
            peer_session: 0,
            send_counter: 0,
            window: Window::default(),
            born: Instant::now(),
        }
    }

    fn clock_epoch(&self) -> u64 {
        (self.born.elapsed().as_secs() / REKEY_EVERY.as_secs()).min((1 << 24) - 1)
    }

    /// Follow the clock: move the send key to the current epoch, and drop receive keys more than
    /// [`SLACK_EPOCHS`] behind it. Called on every seal and open; call it on a timer too, so an
    /// idle direction does not keep an old key.
    pub fn age(&mut self) {
        let now = self.clock_epoch();
        if now > self.send.epoch {
            self.send = self.send.ahead(now - self.send.epoch);
            self.send_counter = now << EPOCH_SHIFT;
        }
        let floor = now.saturating_sub(SLACK_EPOCHS);
        if floor > self.recv.epoch {
            self.recv = self.recv.ahead(floor - self.recv.epoch);
            self.window = Window { top: floor << EPOCH_SHIFT, ..Window::default() };
        }
    }

    /// Move the send side to the next epoch now (the clock does it every [`REKEY_EVERY`]).
    pub fn rekey(&mut self) {
        self.send = self.send.ahead(1);
        self.send_counter = self.send.epoch << EPOCH_SHIFT;
    }

    fn nonce(host_direction: bool, counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[0] = host_direction as u8;
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce)
    }

    /// Encrypt and frame one datagram.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.age();
        if (self.send_counter + 1) >> EPOCH_SHIFT != self.send.epoch {
            self.rekey(); // an epoch's counter space is used up (2^40 datagrams)
        }
        self.send_counter += 1;
        let ciphertext = self
            .send
            .cipher
            .encrypt(&Self::nonce(self.host, self.send_counter), Payload { msg: plaintext, aad: &self.session.to_be_bytes() })
            .expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.send_counter.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Verify and decrypt one datagram. The second value is true when the peer's session id is
    /// new (the caller resets its stream state); the id is authenticated, so it cannot be forged.
    pub fn open(&mut self, datagram: &[u8]) -> Result<(Vec<u8>, bool), CryptoError> {
        if datagram.len() < HEADER_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        self.age();
        let session = u64::from_be_bytes(datagram[..8].try_into().unwrap());
        let counter = u64::from_be_bytes(datagram[8..HEADER_LEN].try_into().unwrap());
        let epoch = counter >> EPOCH_SHIFT;
        // Rejected before the tag is checked: BadTag, never Replay (callers treat a Replay from
        // the peer as proof of a working path, so it must be authenticated).
        if epoch < self.recv.epoch || epoch - self.recv.epoch > MAX_EPOCH_JUMP {
            return Err(CryptoError::BadTag); // that key is gone, or a forged far-future epoch
        }
        // A forged epoch costs at most the slack ahead of this side's clock in key derivations.
        if epoch > self.clock_epoch() + SLACK_EPOCHS {
            return Err(CryptoError::BadTag);
        }
        // A newer epoch: derive its key on the side and keep it only if the datagram is genuine.
        let ahead = (epoch > self.recv.epoch).then(|| self.recv.ahead(epoch - self.recv.epoch));
        let dir = ahead.as_ref().unwrap_or(&self.recv);
        let plaintext = dir
            .cipher
            .decrypt(&Self::nonce(!self.host, counter), Payload { msg: &datagram[HEADER_LEN..], aad: &datagram[..8] })
            .map_err(|_| CryptoError::BadTag)?;
        if session < self.peer_session {
            return Err(CryptoError::Replay);
        }
        if session == self.peer_session && ahead.is_none() && !self.window.fresh(counter) {
            return Err(CryptoError::Replay);
        }
        let restarted = session > self.peer_session;
        if restarted {
            self.peer_session = session;
            self.window = Window::default();
        }
        if let Some(d) = ahead {
            self.recv = d;
            self.window = Window::default();
        }
        self.window.mark(counter);
        Ok((plaintext, restarted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (AeadSession, AeadSession) {
        let k = [3u8; 32];
        (AeadSession::from_key(&k, true), AeadSession::from_key(&k, false))
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut host, mut guest) = pair();
        assert_eq!(guest.open(&host.seal(b"ping")).unwrap().0, b"ping");
        assert_eq!(host.open(&guest.seal(b"pong")).unwrap().0, b"pong");
    }

    #[test]
    fn replay_is_rejected_and_reordering_is_not() {
        let (mut host, mut guest) = pair();
        let (a, b, c) = (host.seal(b"a"), host.seal(b"b"), host.seal(b"c"));
        assert!(guest.open(&c).is_ok());
        assert_eq!(guest.open(&a).unwrap().0, b"a", "late but new");
        assert!(guest.open(&b).is_ok());
        for d in [&a, &b, &c] {
            assert_eq!(guest.open(d), Err(CryptoError::Replay));
        }
        // Beyond the window a late datagram is refused.
        let old = host.seal(b"old");
        for _ in 0..WINDOW {
            assert!(guest.open(&host.seal(b"x")).is_ok());
        }
        assert_eq!(guest.open(&old), Err(CryptoError::Replay));
    }

    #[test]
    fn tampering_and_wrong_key_fail() {
        let (mut host, mut guest) = pair();
        let mut sealed = host.seal(b"data");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(guest.open(&sealed), Err(CryptoError::BadTag));
        assert_eq!(AeadSession::from_key(&[4; 32], false).open(&host.seal(b"x")), Err(CryptoError::BadTag));
        // a forged datagram does not burn its counter: the genuine one still opens
        let good = host.seal(b"good");
        let mut f = good.clone();
        f[20] ^= 1;
        assert!(guest.open(&f).is_err());
        assert!(guest.open(&good).is_ok());
    }

    #[test]
    fn handshake_session_rotates_keys_without_losing_packets() {
        let (mut host, mut guest) = pair();
        for round in 0..5 {
            let before = host.seal(b"before");
            assert_eq!(guest.open(&before).unwrap().0, b"before", "round {round}");
            // One rotation period passes on both clocks, then both rotate.
            host.born -= REKEY_EVERY;
            guest.born -= REKEY_EVERY;
            host.rekey();
            guest.rekey();
            let after = host.seal(b"after");
            let back = guest.seal(b"back");
            assert_eq!(guest.open(&after).unwrap().0, b"after");
            assert_eq!(host.open(&back).unwrap().0, b"back");
            // What was sealed before the rotation no longer opens: its key is gone.
            assert_eq!(guest.open(&before), Err(CryptoError::BadTag));
        }
    }

    #[test]
    fn receiver_follows_several_epochs_at_once_and_forgeries_change_nothing() {
        let (mut host, mut guest) = pair();
        assert!(guest.open(&host.seal(b"0")).is_ok());
        for _ in 0..2 {
            host.rekey();
        }
        let mut forged = host.seal(b"x");
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(guest.open(&forged), Err(CryptoError::BadTag));
        assert_eq!(guest.open(&host.seal(b"7")).unwrap().0, b"7");
        // Further ahead than this side's clock allows: refused before any key is derived.
        host.rekey();
        host.rekey();
        host.rekey();
        assert_eq!(guest.open(&host.seal(b"far")), Err(CryptoError::BadTag));
    }

    /// An idle receiver drops its old key on the clock alone: a key taken from it later does
    /// not open what was recorded before.
    #[test]
    fn idle_direction_ages_its_receive_key() {
        let (mut host, mut guest) = pair();
        let early = host.seal(b"early");
        guest.born -= REKEY_EVERY * (SLACK_EPOCHS as u32 + 3);
        guest.age();
        assert_eq!(guest.recv.epoch, 3);
        assert_eq!(guest.open(&early), Err(CryptoError::BadTag), "the old key is gone");
        // a sender that slept as long jumps by the clock too, and the receiver follows
        host.born -= REKEY_EVERY * (SLACK_EPOCHS as u32 + 3);
        assert_eq!(guest.open(&host.seal(b"later")).unwrap().0, b"later");
    }

    #[test]
    fn an_old_key_cannot_open_later_epochs_and_the_new_one_not_earlier() {
        let k = [3u8; 32];
        let (mut host, _) = pair();
        let early = host.seal(b"early");
        host.rekey();
        let late = host.seal(b"late");
        let later_key = next_key(&k);
        let mut thief = AeadSession::from_key(&later_key, false);
        assert_eq!(thief.open(&early), Err(CryptoError::BadTag));
        assert_ne!(*later_key, k);
        let mut honest = AeadSession::from_key(&k, false);
        assert_eq!(honest.open(&late).unwrap().0, b"late");
    }

    #[test]
    fn a_new_session_resets_the_window() {
        let k = [3u8; 32];
        let mut host = AeadSession::from_key(&k, true);
        let mut first = AeadSession::from_key(&k, false);
        assert!(host.open(&first.seal(b"old")).unwrap().1);
        let mut second = AeadSession::from_key(&k, false);
        let sealed = second.seal(b"new");
        let (plain, restarted) = host.open(&sealed).unwrap();
        assert!(restarted && plain == b"new");
        assert_eq!(host.open(&sealed), Err(CryptoError::Replay));
        assert_eq!(host.open(&first.seal(b"stale session")), Err(CryptoError::Replay));
    }
}
