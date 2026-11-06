//! Authenticated encryption for tunnel datagrams.
//!
//! Every UDP datagram on the wire is sealed with ChaCha20-Poly1305. A pre-shared-key session
//! ([`AeadSession::new`], forward mode) derives one key per sender session id, so a restarted
//! process (counter back at 1) never reuses a (key, nonce) pair; the two sides use disjoint
//! nonce spaces within a key.
//!
//! Wire format (clear part + ciphertext):
//!
//! ```text
//! [u64 session id][u64 counter][ciphertext + 16-byte tag]
//! ```
//!
//! The session id is authenticated as AEAD associated data. A peer that
//! restarts picks a larger id, which tells the other side to reset its replay
//! window and stream state instead of rejecting the new counters as replays.
//!
//! The counter also acts as the nonce and as a replay guard: a datagram whose
//! counter is not strictly greater than the last accepted one is rejected.

use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

/// Datagram starts with an 8-byte session id and an 8-byte counter.
pub const HEADER_LEN: usize = 16;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;

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

/// Key for datagrams sealed under sender session id `session` (pre-shared-key sessions).
fn session_cipher(base: &[u8; 32], session: u64) -> ChaCha20Poly1305 {
    let mut h = Sha256::new();
    h.update(b"strait-fwd-session-v2");
    h.update(base);
    h.update(session.to_be_bytes());
    let k = zeroize::Zeroizing::new(<[u8; 32]>::from(h.finalize()));
    ChaCha20Poly1305::new(Key::from_slice(&k[..]))
}

/// A session id that still orders restarts by time but is not predictable to the millisecond:
/// the low 20 bits are random, so a clock set back does not reproduce an old id.
fn new_session_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let r = u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let id = ((now_nanos() & !0xF_FFFF) | (r & 0xF_FFFF)).max(1);
    // Strictly increasing inside one process, so a session made right after another is "newer".
    LAST.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some(id.max(l + 1))).map_or(id, |l| id.max(l + 1))
}

pub struct AeadSession {
    cipher: ChaCha20Poly1305,
    /// Pre-shared-key sessions: the base the per-session keys come from, and the cipher for the
    /// peer's current session id. `None` when the key came from a handshake (already unique).
    base: Option<zeroize::Zeroizing<[u8; 32]>>,
    peer_cipher: Option<(u64, ChaCha20Poly1305)>,
    /// True when this side is the host (controls the nonce direction bit).
    host: bool,
    /// Identifies this session; a restart picks a larger value.
    session: u64,
    /// Largest session id seen from the peer.
    peer_session: u64,
    send_counter: u64,
    recv_counter: u64,
}

impl AeadSession {
    /// `host` must be true on exactly one of the two peers.
    pub fn new(psk: &str, host: bool) -> Self {
        let base = zeroize::Zeroizing::new(<[u8; 32]>::from(Sha256::digest(psk.as_bytes())));
        let session = new_session_id();
        Self {
            cipher: session_cipher(&base, session),
            base: Some(base),
            peer_cipher: None,
            host,
            session,
            peer_session: 0,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Use a ready 32-byte key (e.g. the per-peer key from the mux handshake).
    pub fn from_key(key: &[u8; 32], host: bool) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            base: None,
            peer_cipher: None,
            host,
            session: now_nanos(),
            peer_session: 0,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    fn nonce(&self, host_direction: bool, counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[0] = host_direction as u8;
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce)
    }

    /// Encrypt and frame one datagram.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.send_counter += 1;
        let nonce = self.nonce(self.host, self.send_counter);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.session.to_be_bytes(),
                },
            )
            .expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.send_counter.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Verify and decrypt one datagram.
    ///
    /// The second value is true when the peer restarted: its session id is
    /// new, so the caller must reset its stream state. The session id is
    /// authenticated, so an attacker cannot force a reset by editing it.
    pub fn open(&mut self, datagram: &[u8]) -> Result<(Vec<u8>, bool), CryptoError> {
        if datagram.len() < HEADER_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        let session = u64::from_be_bytes(datagram[..8].try_into().unwrap());
        let counter = u64::from_be_bytes(datagram[8..HEADER_LEN].try_into().unwrap());
        let nonce = self.nonce(!self.host, counter);
        // Pre-shared-key sessions: the peer sealed under the key of its own session id.
        let fresh = match (&self.base, &self.peer_cipher) {
            (Some(base), pc) if pc.as_ref().is_none_or(|(s, _)| *s != session) => Some(session_cipher(base, session)),
            _ => None,
        };
        let cipher = match (&fresh, &self.peer_cipher, &self.base) {
            (Some(c), _, _) => c,
            (None, Some((_, c)), Some(_)) => c,
            _ => &self.cipher,
        };
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &datagram[HEADER_LEN..],
                    aad: &datagram[..8],
                },
            )
            .map_err(|_| CryptoError::BadTag)?;

        if session < self.peer_session {
            return Err(CryptoError::Replay);
        }
        let restarted = session > self.peer_session;
        if restarted {
            self.peer_session = session;
            self.recv_counter = 0;
            if let Some(c) = fresh {
                self.peer_cipher = Some((session, c)); // cached only once authenticated
            }
        }
        if counter <= self.recv_counter {
            return Err(CryptoError::Replay);
        }
        self.recv_counter = counter;
        Ok((plaintext, restarted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_both_directions() {
        let mut host = AeadSession::new("secret", true);
        let mut guest = AeadSession::new("secret", false);

        let sealed = host.seal(b"ping");
        assert_eq!(guest.open(&sealed).unwrap().0, b"ping");

        let sealed = guest.seal(b"pong");
        assert_eq!(host.open(&sealed).unwrap().0, b"pong");
    }

    #[test]
    fn replay_is_rejected() {
        let mut host = AeadSession::new("secret", true);
        let mut guest = AeadSession::new("secret", false);
        let sealed = host.seal(b"once");
        assert!(guest.open(&sealed).is_ok());
        assert_eq!(guest.open(&sealed), Err(CryptoError::Replay));
    }

    #[test]
    fn tampering_fails() {
        let mut host = AeadSession::new("secret", true);
        let mut guest = AeadSession::new("secret", false);
        let mut sealed = host.seal(b"data");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(guest.open(&sealed), Err(CryptoError::BadTag));
    }

    #[test]
    fn restarting_peer_gets_a_fresh_window() {
        let mut host = AeadSession::new("secret", true);
        let mut first = AeadSession::new("secret", false);
        let sealed = first.seal(b"old");
        assert_eq!(host.open(&sealed).unwrap().0, b"old");

        // A new process has a larger session id and counters from zero.
        let mut second = AeadSession::new("secret", false);
        let sealed = second.seal(b"new");
        let (plain, restarted) = host.open(&sealed).unwrap();
        assert_eq!(plain, b"new");
        assert!(restarted);

        // The old session's datagrams are still rejected.
        assert_eq!(host.open(&sealed), Err(CryptoError::Replay));
    }

    #[test]
    fn restarted_sender_never_reuses_a_key_and_nonce() {
        // Same PSK, same role, both at counter 1: the keystream must differ (a reused
        // (key, nonce) would make the two ciphertexts of equal plaintexts identical).
        let a = AeadSession::new("secret", true).seal(&[0u8; 64]);
        let b = AeadSession::new("secret", true).seal(&[0u8; 64]);
        assert_eq!(a[8..16], b[8..16], "both are counter 1");
        assert_ne!(a[..8], b[..8], "distinct session ids");
        assert_ne!(a[16..], b[16..], "distinct keystream");
    }

    #[test]
    fn wrong_key_fails() {
        let mut host = AeadSession::new("secret", true);
        let mut guest = AeadSession::new("different", false);
        let sealed = host.seal(b"data");
        assert_eq!(guest.open(&sealed), Err(CryptoError::BadTag));
    }
}
