//! Join handshake: Noise `NKpsk0` (X25519, ChaCha20-Poly1305, SHA-256) through the `snow` crate.
//!
//! * The invite key is the pre-shared key: without it neither message can be produced or read.
//! * The host has a long-term Ed25519 key. Its public half is the invite's `hk`; the Noise static
//!   key is the same key in X25519 form (`to_scalar_bytes` / `to_montgomery`), and the host signs
//!   its rendezvous records with it. Using one key pair for both is analysed in Thormarker,
//!   "On using the same key pair for Ed25519 and an X25519 based KEM" (IACR ePrint 2021/509).
//!   The client encrypts to that key, so only its holder can complete the handshake: knowing the
//!   invite is not enough to pose as the host. An invite without `hk` is refused.
//! * Both sides add a fresh ephemeral key, so a recorded session stays unreadable when the
//!   invite or the host key leaks later.
//!
//! Message 1 (client) carries a timestamp and the optional guest token, encrypted to the host.
//! Message 2 (host) carries the slot and the verdict (accepted, full, refused, clock): a refusal
//! is as authenticated as an acceptance. Reading message 2 is the client's proof of the host.

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const PATTERN: &str = "Noise_NKpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"strait-join-v3";
/// Ephemeral key + AEAD tag: what Noise adds to each message's payload.
pub const OVERHEAD: usize = 48;
pub const TOKEN_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed;

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let (mut ik, mut ok) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 {
        ik[i] ^= key[i];
        ok[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(ik);
    for p in parts {
        h.update(p);
    }
    let inner = h.finalize();
    let mut h = Sha256::new();
    h.update(ok);
    h.update(inner);
    h.finalize().into()
}

fn builder<'a>(psk: &'a [u8; 32]) -> Result<snow::Builder<'a>, Failed> {
    let p: snow::params::NoiseParams = PATTERN.parse().map_err(|_| Failed)?;
    snow::Builder::new(p).psk(0, psk).and_then(|b| b.prologue(PROLOGUE)).map_err(|_| Failed)
}

/// One session key from Noise's two directional keys (the tunnel separates directions by nonce).
fn session_key(hs: &mut snow::HandshakeState) -> [u8; 32] {
    let (a, b) = hs.dangerously_get_raw_split();
    hmac(&a, &[b"strait-session-v3", &b])
}

/// A new random host key (the private Ed25519 seed).
pub fn new_host_key() -> [u8; 32] {
    x25519_dalek::StaticSecret::random().to_bytes()
}

/// The public half of a host key: the invite's `hk` (an Ed25519 public key).
pub fn public_of(host_key: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(host_key).verifying_key().to_bytes()
}

/// The host's Noise static private key (X25519 form of the Ed25519 key).
fn noise_private(host_key: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(ed25519_dalek::SigningKey::from_bytes(host_key).to_scalar_bytes())
}

/// The Noise static public key for an invite's `hk`. Fails for bytes that are not a valid key.
fn noise_public(hk: &[u8; 32]) -> Result<[u8; 32], Failed> {
    match ed25519_dalek::VerifyingKey::from_bytes(hk) {
        Ok(v) if !v.is_weak() => Ok(v.to_montgomery().to_bytes()),
        _ => Err(Failed),
    }
}

/// Is `hk` a usable host key (a valid Ed25519 point of full order)?
pub fn valid_public(hk: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(hk).is_ok_and(|v| !v.is_weak())
}

/// Sign `msg` with the host key (rendezvous records).
pub fn sign(host_key: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(host_key).sign(msg).to_bytes()
}

/// Check a signature made by [`sign`] against the invite's `hk` (strict verification).
pub fn verify_sig(hk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(hk)
        .is_ok_and(|v| !v.is_weak() && v.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok())
}

/// A JOIN older or newer than this (seconds) is refused: replays are useless after it, and the
/// host's replay cache only has to cover this span.
pub const JOIN_MAX_SKEW: u32 = 600;

/// Message 1's payload: the client's clock and the optional token.
pub fn join_payload(now: u32, token: Option<&[u8; TOKEN_LEN]>) -> Vec<u8> {
    let mut p = now.to_be_bytes().to_vec();
    if let Some(t) = token {
        p.extend_from_slice(t);
    }
    p
}

/// Split message 1's payload into the client's clock and the token (empty if none).
pub fn parse_join_payload(p: &[u8]) -> Option<(u32, &[u8])> {
    let ts = u32::from_be_bytes(p.get(..4)?.try_into().ok()?);
    let token = &p[4..];
    (token.is_empty() || token.len() == TOKEN_LEN).then_some((ts, token))
}

/// Within [`JOIN_MAX_SKEW`] of `now`?
pub fn fresh(ts: u32, now: u32) -> bool {
    ts.abs_diff(now) <= JOIN_MAX_SKEW
}

/// Client side, between message 1 and message 2.
pub struct ClientHs {
    psk: [u8; 32],
    rs: [u8; 32],
    /// The ephemeral private key: the state is rebuilt from it for each answer, so a forged
    /// message 2 (which spends a Noise state) cannot end a join.
    e: zeroize::Zeroizing<[u8; 32]>,
    payload: Vec<u8>,
    /// Message 1, sent unchanged on every retry.
    pub msg1: Vec<u8>,
}

impl ClientHs {
    /// `hk` is the invite's host key (Ed25519 public).
    pub fn new(psk: &[u8; 32], hk: &[u8; 32], payload: &[u8]) -> Result<Self, Failed> {
        let rs = noise_public(hk)?;
        let e = zeroize::Zeroizing::new(x25519_dalek::StaticSecret::random().to_bytes());
        let mut hs = Self { psk: *psk, rs, e, payload: payload.to_vec(), msg1: Vec::new() };
        let (_, msg1) = hs.state()?;
        hs.msg1 = msg1;
        Ok(hs)
    }

    /// A fresh initiator state that has written message 1 (the same bytes every time).
    fn state(&self) -> Result<(snow::HandshakeState, Vec<u8>), Failed> {
        let mut state = builder(&self.psk)?
            .remote_public_key(&self.rs)
            .and_then(|b| b.fixed_ephemeral_key_for_testing_only(&self.e[..]).build_initiator())
            .map_err(|_| Failed)?;
        let mut msg1 = vec![0u8; self.payload.len() + OVERHEAD];
        let n = state.write_message(&self.payload, &mut msg1).map_err(|_| Failed)?;
        msg1.truncate(n);
        Ok((state, msg1))
    }

    /// Read message 2: its payload and the session key. Fails for a host without the static key
    /// or the invite key, and for a tampered message; this handshake stays usable either way.
    pub fn finish(&mut self, msg2: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Failed> {
        let (mut state, _) = self.state()?;
        let mut payload = vec![0u8; msg2.len()];
        let n = state.read_message(msg2, &mut payload).map_err(|_| Failed)?;
        payload.truncate(n);
        Ok((payload, session_key(&mut state)))
    }
}

/// Host side, after message 1 was read.
pub struct HostHs {
    state: Box<snow::HandshakeState>,
}

impl HostHs {
    /// Read message 1; returns its payload (the guest's clock, then its token if it has one).
    pub fn read(psk: &[u8; 32], host_key: &[u8; 32], msg1: &[u8]) -> Result<(Self, Vec<u8>), Failed> {
        let sk = noise_private(host_key);
        let mut state = builder(psk)?.local_private_key(&sk[..]).and_then(|b| b.build_responder()).map_err(|_| Failed)?;
        let mut payload = vec![0u8; msg1.len()];
        let n = state.read_message(msg1, &mut payload).map_err(|_| Failed)?;
        payload.truncate(n);
        Ok((Self { state: Box::new(state) }, payload))
    }

    /// Write message 2 and return it with the session key.
    pub fn write(mut self, payload: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Failed> {
        let mut msg2 = vec![0u8; payload.len() + OVERHEAD];
        let n = self.state.write_message(payload, &mut msg2).map_err(|_| Failed)?;
        msg2.truncate(n);
        Ok((msg2, session_key(&mut self.state)))
    }
}

// ---- guest tokens -------------------------------------------------------------------------
//
// A host that invites people one by one gives each a token: `id (4) | expires (4, Unix seconds,
// 0 = never) | mac (16)`. The MAC key derives from the host's private key, so tokens need no
// storage to verify and nobody else can mint one. The host keeps a name per id and a revoked list.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub id: u32,
    pub expires: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    Forged,
    Expired,
}

/// Key for personal-invite tokens: bound to the host key and to the invite key, so replacing the
/// invite also cancels every personal invite made from it.
pub fn token_key(host_private: &[u8; 32], invite_key: &str) -> [u8; 32] {
    hmac(host_private, &[b"strait-guest-token-v4", invite_key.as_bytes()])
}

pub fn mint(key: &[u8; 32], t: Token) -> [u8; TOKEN_LEN] {
    let mut out = [0u8; TOKEN_LEN];
    out[..4].copy_from_slice(&t.id.to_be_bytes());
    out[4..8].copy_from_slice(&t.expires.to_be_bytes());
    let mac = hmac(key, &[b"guest", &out[..8]]);
    out[8..].copy_from_slice(&mac[..16]);
    out
}

pub fn now_secs() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

pub fn verify(key: &[u8; 32], token: &[u8], now: u32) -> Result<Token, TokenError> {
    let t: &[u8; TOKEN_LEN] = token.try_into().map_err(|_| TokenError::Malformed)?;
    let mac = hmac(key, &[b"guest", &t[..8]]);
    if mac[..16].iter().zip(&t[8..]).fold(0u8, |d, (a, b)| d | (a ^ b)) != 0 {
        return Err(TokenError::Forged);
    }
    let tok = Token { id: u32::from_be_bytes(t[..4].try_into().unwrap()), expires: u32::from_be_bytes(t[4..8].try_into().unwrap()) };
    if tok.expires != 0 && now >= tok.expires {
        return Err(TokenError::Expired);
    }
    Ok(tok)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; 32] = [7; 32];

    /// A forged message 2 does not spend the guest's handshake: the real answer still completes it.
    #[test]
    fn a_forged_answer_does_not_end_the_join() {
        let host = new_host_key();
        let mut c = ClientHs::new(&PSK, &public_of(&host), b"p").unwrap();
        let first = c.msg1.clone();
        assert!(c.finish(&[0u8; 48]).is_err());
        let (hs, p) = HostHs::read(&PSK, &host, &c.msg1).unwrap();
        assert_eq!((p.as_slice(), c.msg1 == first), (&b"p"[..], true));
        let (m2, k) = hs.write(b"ok").unwrap();
        let (pl, k2) = c.finish(&m2).unwrap();
        assert_eq!((pl.as_slice(), k), (&b"ok"[..], k2));
    }

    #[test]
    fn both_sides_agree_and_payloads_arrive() {
        let host = new_host_key();
        let mut c = ClientHs::new(&PSK, &public_of(&host), b"token").unwrap();
        assert_eq!(c.msg1.len(), 5 + OVERHEAD);
        let (h, p1) = HostHs::read(&PSK, &host, &c.msg1).unwrap();
        assert_eq!(p1, b"token");
        let (msg2, hk) = h.write(b"slot").unwrap();
        let (p2, ck) = c.finish(&msg2).unwrap();
        assert_eq!((p2.as_slice(), ck), (&b"slot"[..], hk));
    }

    /// Knowing the invite key (the psk) is not enough to answer as the host.
    #[test]
    fn a_host_without_the_static_key_is_refused() {
        let (real, fake) = (new_host_key(), new_host_key());
        let mut c = ClientHs::new(&PSK, &public_of(&real), b"").unwrap();
        // The impostor cannot even read message 1...
        assert!(HostHs::read(&PSK, &fake, &c.msg1).is_err());
        // ...and a message 2 from a handshake of its own does not finish the client's.
        let mut other = ClientHs::new(&PSK, &public_of(&fake), b"").unwrap();
        let (h, _) = HostHs::read(&PSK, &fake, &other.msg1).unwrap();
        let (msg2, _) = h.write(b"").unwrap();
        assert!(c.finish(&msg2).is_err());
        assert!(other.finish(&msg2).is_ok());
    }

    #[test]
    fn wrong_invite_key_and_tampering_fail() {
        let host = new_host_key();
        let c = ClientHs::new(&PSK, &public_of(&host), b"x").unwrap();
        assert!(HostHs::read(&[8; 32], &host, &c.msg1).is_err());
        let mut bad = c.msg1.clone();
        bad[40] ^= 1;
        assert!(HostHs::read(&PSK, &host, &bad).is_err());
        // A low-order ephemeral key (all zero) is refused.
        let mut zero = c.msg1.clone();
        zero[..32].fill(0);
        assert!(HostHs::read(&PSK, &host, &zero).is_err());
    }

    /// The Noise key really is the X25519 form of the Ed25519 key in the invite.
    #[test]
    fn host_key_forms_agree_and_signatures_bind_to_hk() {
        let k = new_host_key();
        let hk = public_of(&k);
        let x = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*noise_private(&k))).to_bytes();
        assert_eq!(noise_public(&hk).unwrap(), x);
        assert!(valid_public(&hk));
        let sig = sign(&k, b"record");
        assert!(verify_sig(&hk, b"record", &sig));
        assert!(!verify_sig(&hk, b"recorD", &sig));
        assert!(!verify_sig(&public_of(&new_host_key()), b"record", &sig));
        // The identity point (y = 1) is a valid encoding of a weak key: refused.
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert!(!valid_public(&ident) && ClientHs::new(&PSK, &ident, b"").is_err(), "a low-order hk is refused");
    }

    #[test]
    fn join_payload_carries_clock_and_token() {
        assert_eq!(parse_join_payload(&join_payload(77, None)), Some((77, &[][..])));
        let t = [9u8; TOKEN_LEN];
        assert_eq!(parse_join_payload(&join_payload(5, Some(&t))), Some((5, &t[..])));
        assert_eq!(parse_join_payload(&[1, 2, 3]), None);
        assert_eq!(parse_join_payload(&[0, 0, 0, 1, 7]), None, "a token of the wrong size");
        assert!(fresh(1000, 1000 + JOIN_MAX_SKEW) && !fresh(1000, 1001 + JOIN_MAX_SKEW) && fresh(2000, 2000 - JOIN_MAX_SKEW));
    }

    #[test]
    fn tokens_verify_expire_and_cannot_be_forged() {
        let key = token_key(&new_host_key(), "k");
        let t = mint(&key, Token { id: 7, expires: 1000 });
        assert_eq!(verify(&key, &t, 999), Ok(Token { id: 7, expires: 1000 }));
        assert_eq!(verify(&key, &t, 1000), Err(TokenError::Expired));
        assert_eq!(verify(&key, &mint(&key, Token { id: 7, expires: 0 }), u32::MAX), Ok(Token { id: 7, expires: 0 }));
        let mut forged = t;
        forged[3] = 8; // another guest's id under the same MAC
        assert_eq!(verify(&key, &forged, 0), Err(TokenError::Forged));
        assert_eq!(verify(&token_key(&new_host_key(), "k"), &t, 0), Err(TokenError::Forged));
        assert_eq!(verify(&token_key(&[7; 32], "other invite"), &mint(&token_key(&[7; 32], "k"), Token { id: 1, expires: 0 }), 0), Err(TokenError::Forged), "a new invite key cancels old tokens");
        assert_eq!(verify(&key, &t[..10], 0), Err(TokenError::Malformed));
        assert_eq!(unhex::<24>(&hex(&t)), Some(t));
        assert_eq!(unhex::<24>("zz"), None);
    }
}
