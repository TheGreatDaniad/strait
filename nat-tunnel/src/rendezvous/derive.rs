//! Key derivation and sealed candidate blobs (design section 2).
//!
//! `prk = HKDF-SHA256(salt = "strait-rv-v1", ikm = invite key bytes)`; each purpose is its own
//! `expand(info)`, so a service that sees one derived value learns nothing about the others or
//! the key. Blobs are never logged.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use super::Role;

const SALT: &[u8] = b"strait-rv-v1";
const VER: u8 = 1;
/// A blob older than this is rejected (replay of a captured blob).
pub const WINDOW_PAST_SECS: u64 = 120;
/// Tolerated clock skew into the future.
pub const WINDOW_FUTURE_SECS: u64 = 30;
pub const MAX_CANDIDATES: usize = 8;

/// Values derived from the 16-byte invite key.
#[derive(Clone, PartialEq, Eq)]
pub struct Derived {
    pub seal_key: [u8; 32],
    pub room: [u8; 32],
    pub dht_host_seed: [u8; 32],
    pub dht_client_seed: [u8; 32],
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Derived(..)") // never print key material
    }
}

/// Parse the invite's 32-hex-character key (either case). Anything else is rejected.
pub fn parse_key(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let h = (b[2 * i] as char).to_digit(16)?;
        let l = (b[2 * i + 1] as char).to_digit(16)?;
        *o = (h * 16 + l) as u8;
    }
    Some(out)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn base32_lower(b: &[u8]) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::new());
    for &x in b {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

impl Derived {
    pub fn new(key: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SALT), key);
        let ex = |info: &[u8]| {
            let mut o = [0u8; 32];
            hk.expand(info, &mut o).expect("32 bytes is a valid HKDF length");
            o
        };
        Self {
            seal_key: ex(b"seal"),
            room: ex(b"room"),
            dht_host_seed: ex(b"dht-host"),
            dht_client_seed: ex(b"dht-client"),
        }
    }

    /// From the invite's key string (32 hex chars).
    pub fn from_invite_key(key: &str) -> Option<Self> {
        parse_key(key).map(|k| Self::new(&k))
    }

    /// Tracker info_hash: first 20 bytes of the room tag.
    pub fn room_info_hash(&self) -> [u8; 20] {
        self.room[..20].try_into().unwrap()
    }

    /// ntfy / MQTT topic: `strait-` + lowercase base32 of the first 16 bytes (26 chars).
    pub fn room_topic(&self) -> String {
        format!("strait-{}", base32_lower(&self.room[..16]))
    }

    /// Nostr `r` tag: the full room tag as lowercase hex.
    pub fn room_hex(&self) -> String {
        hex(&self.room)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    /// Too short, bad version, bad family, trailing bytes, or bad port.
    Malformed,
    /// AEAD tag failed: wrong key, wrong sender role, or tampering.
    BadTag,
    WrongRole,
    Stale,
    Future,
    NoCandidates,
    TooMany,
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BlobError {}

fn role_byte(r: Role) -> u8 {
    match r {
        Role::Host => 0,
        Role::Client => 1,
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn aad(sender: Role) -> [u8; 1 + SALT.len()] {
    let mut a = [0u8; 1 + SALT.len()];
    a[0] = role_byte(sender);
    a[1..].copy_from_slice(SALT);
    a
}

/// Seal `cands` as sent by `sender`. Fails on 0 or more than 8 candidates or a zero port.
pub fn seal(d: &Derived, sender: Role, cands: &[SocketAddr]) -> Result<Vec<u8>, BlobError> {
    let nonce: [u8; 12] = ChaCha20Poly1305::generate_nonce(&mut OsRng).into();
    seal_at(d, sender, cands, now_secs(), nonce)
}

/// [`seal`] with an explicit clock and nonce (tests, pinned vectors).
pub fn seal_at(d: &Derived, sender: Role, cands: &[SocketAddr], now: u64, nonce: [u8; 12]) -> Result<Vec<u8>, BlobError> {
    if cands.is_empty() {
        return Err(BlobError::NoCandidates);
    }
    if cands.len() > MAX_CANDIDATES {
        return Err(BlobError::TooMany);
    }
    if cands.iter().any(|c| c.port() == 0) {
        return Err(BlobError::Malformed);
    }
    let mut pt = vec![VER, role_byte(sender)];
    pt.extend_from_slice(&(now as u32).to_be_bytes());
    pt.push(cands.len() as u8);
    for c in cands {
        match c.ip() {
            IpAddr::V4(a) => {
                pt.push(4);
                pt.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                pt.push(6);
                pt.extend_from_slice(&a.octets());
            }
        }
        pt.extend_from_slice(&c.port().to_be_bytes());
    }
    let ct = ChaCha20Poly1305::new((&d.seal_key).into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad(sender) })
        .expect("encrypt");
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

/// Open a blob that must have been sent by the role opposite to `own`.
pub fn open(d: &Derived, own: Role, blob: &[u8]) -> Result<Vec<SocketAddr>, BlobError> {
    open_at(d, own, blob, now_secs())
}

pub fn open_at(d: &Derived, own: Role, blob: &[u8], now: u64) -> Result<Vec<SocketAddr>, BlobError> {
    let sender = match own {
        Role::Host => Role::Client,
        Role::Client => Role::Host,
    };
    if blob.len() < 12 + 16 {
        return Err(BlobError::Malformed);
    }
    let (nonce, ct) = blob.split_at(12);
    let pt = ChaCha20Poly1305::new((&d.seal_key).into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad(sender) })
        .map_err(|_| BlobError::BadTag)?;
    if pt.len() < 7 || pt[0] != VER {
        return Err(BlobError::Malformed);
    }
    if pt[1] != role_byte(sender) {
        return Err(BlobError::WrongRole);
    }
    let ts = u32::from_be_bytes(pt[2..6].try_into().unwrap()) as u64;
    // The u32 timestamp is compared modulo nothing: it is simply unix seconds until 2106.
    let now32 = now & 0xffff_ffff;
    if ts + WINDOW_PAST_SECS < now32 {
        return Err(BlobError::Stale);
    }
    if ts > now32 + WINDOW_FUTURE_SECS {
        return Err(BlobError::Future);
    }
    let n = pt[6] as usize;
    if n == 0 {
        return Err(BlobError::NoCandidates);
    }
    if n > MAX_CANDIDATES {
        return Err(BlobError::TooMany);
    }
    let mut rest = &pt[7..];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (&fam, r) = rest.split_first().ok_or(BlobError::Malformed)?;
        let alen = match fam {
            4 => 4,
            6 => 16,
            _ => return Err(BlobError::Malformed),
        };
        if r.len() < alen + 2 {
            return Err(BlobError::Malformed);
        }
        let ip: IpAddr = if alen == 4 {
            Ipv4Addr::from(<[u8; 4]>::try_from(&r[..4]).unwrap()).into()
        } else {
            Ipv6Addr::from(<[u8; 16]>::try_from(&r[..16]).unwrap()).into()
        };
        let port = u16::from_be_bytes([r[alen], r[alen + 1]]);
        if port == 0 {
            return Err(BlobError::Malformed);
        }
        out.push(SocketAddr::new(ip, port));
        rest = &r[alen + 2..];
    }
    if !rest.is_empty() {
        return Err(BlobError::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const NOW: u64 = 1_800_000_000;

    fn d() -> Derived {
        Derived::new(&K)
    }
    fn a4() -> SocketAddr {
        "203.0.113.7:4242".parse().unwrap()
    }
    fn a6() -> SocketAddr {
        "[2001:db8::1]:51820".parse().unwrap()
    }
    fn sealed(role: Role, c: &[SocketAddr], at: u64) -> Vec<u8> {
        seal_at(&d(), role, c, at, [7; 12]).unwrap()
    }

    /// Encrypt an arbitrary plaintext as `sender` to test the receiver's format checks.
    fn raw(sender: Role, pt: &[u8]) -> Vec<u8> {
        let ct = ChaCha20Poly1305::new((&d().seal_key).into())
            .encrypt(Nonce::from_slice(&[9; 12]), Payload { msg: pt, aad: &aad(sender) })
            .unwrap();
        [&[9u8; 12][..], &ct].concat()
    }
    fn pt(ver: u8, role: u8, ts: u32, n: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![ver, role];
        v.extend(ts.to_be_bytes());
        v.push(n);
        v.extend(body);
        v
    }
    const V4BODY: [u8; 7] = [4, 1, 2, 3, 4, 0x12, 0x34];

    #[test]
    fn roundtrip_both_roles_v4_and_v6() {
        let c = vec![a4(), a6(), "10.0.0.1:1".parse().unwrap()];
        for (s, r) in [(Role::Host, Role::Client), (Role::Client, Role::Host)] {
            let b = seal_at(&d(), s, &c, NOW, [1; 12]).unwrap();
            assert_eq!(open_at(&d(), r, &b, NOW).unwrap(), c);
        }
        // random-nonce path and wall clock
        let b = seal(&d(), Role::Host, &[a6()]).unwrap();
        assert_eq!(open(&d(), Role::Client, &b).unwrap(), vec![a6()]);
        assert_ne!(b, seal(&d(), Role::Host, &[a6()]).unwrap(), "nonce must be random");
    }

    #[test]
    fn eight_ok_nine_rejected_zero_rejected() {
        let eight: Vec<SocketAddr> = (1..=8).map(|i| SocketAddr::from(([1, 1, 1, i], 1000 + i as u16))).collect();
        let b = sealed(Role::Host, &eight, NOW);
        assert_eq!(open_at(&d(), Role::Client, &b, NOW).unwrap(), eight);
        let mut nine = eight.clone();
        nine.push(a4());
        assert_eq!(seal_at(&d(), Role::Host, &nine, NOW, [0; 12]), Err(BlobError::TooMany));
        assert_eq!(seal_at(&d(), Role::Host, &[], NOW, [0; 12]), Err(BlobError::NoCandidates));
        assert_eq!(seal_at(&d(), Role::Host, &["1.1.1.1:0".parse().unwrap()], NOW, [0; 12]), Err(BlobError::Malformed));
        // a hostile peer that seals 9 / 0 candidates with the right key is rejected on receipt
        let body9 = V4BODY.repeat(9);
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 0, NOW as u32, 9, &body9)), NOW), Err(BlobError::TooMany));
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 0, NOW as u32, 0, &[])), NOW), Err(BlobError::NoCandidates));
    }

    #[test]
    fn wrong_key_and_wrong_role() {
        let b = sealed(Role::Host, &[a4()], NOW);
        let other = Derived::new(&[9; 16]);
        assert_eq!(open_at(&other, Role::Client, &b, NOW), Err(BlobError::BadTag));
        // a host must not accept its own blob (nor a reflected one)
        assert_eq!(open_at(&d(), Role::Host, &b, NOW), Err(BlobError::BadTag));
        let c = sealed(Role::Client, &[a4()], NOW);
        assert_eq!(open_at(&d(), Role::Client, &c, NOW), Err(BlobError::BadTag));
        // correct aad but inner role byte lying
        assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &pt(1, 1, NOW as u32, 1, &V4BODY)), NOW), Err(BlobError::WrongRole));
    }

    #[test]
    fn timestamp_window() {
        let at = |t: u64| open_at(&d(), Role::Client, &sealed(Role::Host, &[a4()], t), NOW);
        assert!(at(NOW).is_ok());
        assert!(at(NOW - 120).is_ok());
        assert_eq!(at(NOW - 121), Err(BlobError::Stale));
        assert_eq!(at(NOW - 100_000), Err(BlobError::Stale));
        assert!(at(NOW + 30).is_ok());
        assert_eq!(at(NOW + 31), Err(BlobError::Future));
    }

    #[test]
    fn truncation_and_extension_rejected() {
        let b = sealed(Role::Host, &[a4(), a6()], NOW);
        for n in 0..b.len() {
            assert!(open_at(&d(), Role::Client, &b[..n], NOW).is_err(), "len {n}");
        }
        let mut longer = b.clone();
        longer.push(0);
        assert!(open_at(&d(), Role::Client, &longer, NOW).is_err());
    }

    #[test]
    fn every_bit_flip_rejected() {
        let b = sealed(Role::Host, &[a4(), a6()], NOW);
        for i in 0..b.len() * 8 {
            let mut m = b.clone();
            m[i / 8] ^= 1 << (i % 8);
            assert!(open_at(&d(), Role::Client, &m, NOW).is_err(), "bit {i}");
        }
    }

    #[test]
    fn malformed_plaintext_rejected() {
        let ts = NOW as u32;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("bad version", pt(2, 0, ts, 1, &V4BODY)),
            ("bad family", pt(1, 0, ts, 1, &[5, 1, 2, 3, 4, 0, 80])),
            ("short addr", pt(1, 0, ts, 1, &V4BODY[..5])),
            ("n larger than data", pt(1, 0, ts, 2, &V4BODY)),
            ("trailing bytes", pt(1, 0, ts, 1, &[&V4BODY[..], &[0]].concat())),
            ("port zero", pt(1, 0, ts, 1, &[4, 1, 2, 3, 4, 0, 0])),
            ("too short", vec![1, 0, 0]),
            ("empty", vec![]),
        ];
        for (name, p) in cases {
            assert_eq!(open_at(&d(), Role::Client, &raw(Role::Host, &p), NOW), Err(BlobError::Malformed), "{name}");
        }
    }

    #[test]
    fn domain_separation() {
        let x = d();
        let v = [x.seal_key, x.room, x.dht_host_seed, x.dht_client_seed];
        for i in 0..4 {
            for j in i + 1..4 {
                assert_ne!(v[i], v[j], "{i} vs {j}");
            }
        }
        let y = Derived::new(&[K[0] ^ 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_ne!(x.seal_key, y.seal_key);
        assert_ne!(x.room, y.room);
        assert_eq!(&x.room[..20], &x.room_info_hash());
        // none of the derived values equals the key (or contains it as a prefix)
        assert!(v.iter().all(|s| s[..16] != K));
    }

    #[test]
    fn topic_and_hex_shapes() {
        let x = d();
        let t = x.room_topic();
        assert!(t.starts_with("strait-") && t.len() == 7 + 26, "{t}");
        assert!(t[7..].bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)));
        assert_eq!(x.room_hex().len(), 64);
        // RFC 4648 vectors (lowercase, unpadded)
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"f"), "my");
    }

    #[test]
    fn parse_key_strict() {
        assert_eq!(parse_key("000102030405060708090a0b0c0d0e0f"), Some(K));
        assert_eq!(parse_key("000102030405060708090A0B0C0D0E0F"), Some(K));
        for bad in ["", "abc123", "000102030405060708090a0b0c0d0e0", "000102030405060708090a0b0c0d0e0f0", "000102030405060708090a0b0c0d0e0g", "0001020304050607 8090a0b0c0d0e0f", "ééééééééééééééééééééééééééééééé"] {
            assert!(parse_key(bad).is_none(), "{bad:?}");
        }
        assert_eq!(Derived::from_invite_key("000102030405060708090a0b0c0d0e0f"), Some(d()));
    }

    /// Pinned (cross-checked against an independent Python HKDF/ChaCha20-Poly1305): changing any of these breaks interop with every deployed invite and blob.
    #[test]
    fn pinned_vectors() {
        let x = d();
        assert_eq!(hex(&x.seal_key), "ba4b1c0d17e9877100c95a204557ea405205ec9dc79c8ba98db84db33fd9d127");
        assert_eq!(hex(&x.room), "e4082b688b7958e32ec2ecefb0223f8da54fe8ac3a263dc9589f210b8a8d165e");
        assert_eq!(hex(&x.dht_host_seed), "9a41f82e02a6707024f2577a5d640f4dafcecabbc2bd10f3518466c2c9615f94");
        assert_eq!(hex(&x.dht_client_seed), "10c85213c33234e60ada5bf7f4f05bfba3a2fb2c84f28ab36f818db41e1d0258");
        assert_eq!(x.room_topic(), "strait-4qecw2elpfmoglwc5tx3air7ru");
        assert_eq!(hex(&sealed(Role::Host, &[a4(), a6()], NOW)), "07070707070707070707070717cdddc391b83f73b4606bb236ae79862794eddb4967b453d1c8634716c6d8921678719d8692286c7ee3835796f9d8cb79");
    }
}
