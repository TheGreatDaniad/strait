//! Adversarial tests for the relay wire codec and the sealed-frame AEAD (M7).
use nat_tunnel::relay::*;
use nat_tunnel::tunnel::crypto::{AeadSession, CryptoError, HEADER_LEN, TAG_LEN};
use std::net::SocketAddr;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn decode_never_panics_on_arbitrary_datagrams() {
    let mut r = Rng(42);
    for _ in 0..50_000 {
        let n = (r.next() % 80) as usize;
        let mut b = r.bytes(n);
        if n > 0 && r.next() % 2 == 0 {
            b[0] = [1u8, 3, 4, 5, 6][(r.next() % 5) as usize];
        }
        let _ = decode(&b);
    }
    let _ = decode(&vec![6u8; 70_000]);
    // every length of every type byte
    for t in 0..=255u8 {
        for len in 0..40 {
            let mut b = vec![0xAB; len];
            if len > 0 {
                b[0] = t;
            }
            let _ = decode(&b);
        }
    }
}

#[test]
fn encoders_have_documented_layout() {
    let reg = encode_register(0x01020304, 1);
    assert_eq!(reg, [1, 1, 2, 3, 4, 1]);
    let dereg = encode_deregister(0x01020304, 0);
    assert_eq!(dereg, [4, 1, 2, 3, 4, 0]);
    assert_eq!(encode_ping(0x0A0B0C0D), [5, 0x0A, 0x0B, 0x0C, 0x0D]);
}

#[test]
fn pong_and_peer_round_trip_and_truncation_rejected() {
    let mut r = Rng(7);
    for _ in 0..5000 {
        let nonce = r.next() as u32;
        let mut pong = vec![6u8];
        pong.extend_from_slice(&nonce.to_be_bytes());
        assert_eq!(decode(&pong), Some(Incoming::Pong(nonce)));
        for cut in 0..pong.len() {
            assert_eq!(decode(&pong[..cut]), None);
        }
        pong.push(0);
        assert_eq!(decode(&pong), None, "trailing byte must be rejected");

        let (ip, port, role) = (r.next() as u32, r.next() as u16, r.next() as u8);
        let mut peer = vec![3u8];
        peer.extend_from_slice(&0u32.to_be_bytes());
        peer.push(role);
        peer.extend_from_slice(&ip.to_be_bytes());
        peer.extend_from_slice(&port.to_be_bytes());
        let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
        assert_eq!(decode(&peer), Some(Incoming::Peer { role, addr }));
        for cut in 0..peer.len() {
            assert_eq!(decode(&peer[..cut]), None, "truncated PEER at {cut}");
        }
        peer.push(0);
        assert_eq!(decode(&peer), None);
    }
}

#[test]
fn client_side_decode_ignores_client_to_server_messages() {
    // REGISTER/DEREGISTER/PING are not valid server->peer messages.
    assert_eq!(decode(&encode_register(1, 0)), None);
    assert_eq!(decode(&encode_deregister(1, 0)), None);
    assert_eq!(decode(&encode_ping(1)), None);
}

// ---- AEAD sealed frames ----

fn pair() -> (AeadSession, AeadSession) {
    (AeadSession::new("secret", true), AeadSession::new("secret", false))
}

#[test]
fn open_garbage_and_truncated_rejected() {
    let mut r = Rng(99);
    let (mut host, mut guest) = pair();
    for _ in 0..20_000 {
        let n = (r.next() % 120) as usize;
        assert!(guest.open(&r.bytes(n)).is_err());
    }
    let sealed = host.seal(b"hello world");
    for cut in 0..sealed.len() {
        assert!(guest.open(&sealed[..cut]).is_err(), "cut {cut}");
    }
    assert_eq!(guest.open(&sealed[..HEADER_LEN + TAG_LEN - 1]), Err(CryptoError::TooShort));
    // the intact frame still opens after all that abuse
    assert_eq!(guest.open(&sealed).unwrap().0, b"hello world");
}

#[test]
fn every_bit_flip_rejected() {
    let (mut host, _) = pair();
    let sealed = host.seal(b"payload under attack");
    for bit in 0..sealed.len() * 8 {
        let mut guest = AeadSession::new("secret", false);
        let mut f = sealed.clone();
        f[bit / 8] ^= 1 << (bit % 8);
        assert!(guest.open(&f).is_err(), "bit {bit} flip accepted");
    }
}

#[test]
fn replay_and_reorder_rejected() {
    let (mut host, mut guest) = pair();
    let a = host.seal(b"a");
    let b = host.seal(b"b");
    let c = host.seal(b"c");
    assert!(guest.open(&b).is_ok());
    assert_eq!(guest.open(&b), Err(CryptoError::Replay));
    assert_eq!(guest.open(&a), Err(CryptoError::Replay));
    assert!(guest.open(&c).is_ok());
    assert_eq!(guest.open(&c), Err(CryptoError::Replay));
}

#[test]
fn wrong_key_and_reflection_rejected() {
    let (mut host, _) = pair();
    let sealed = host.seal(b"x");
    assert!(AeadSession::new("other", false).open(&sealed).is_err());
    // reflecting a host frame back to the host must fail (direction bit)
    assert!(AeadSession::new("secret", true).open(&sealed).is_err());
}

#[test]
fn empty_and_large_payload_round_trip() {
    let (mut host, mut guest) = pair();
    for n in [0usize, 1, 1400, 65_000] {
        let p = vec![0x5A; n];
        assert_eq!(guest.open(&host.seal(&p)).unwrap().0, p);
    }
}
