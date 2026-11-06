//! Adversarial tests for the invite parser (M7). Seeded, deterministic.
use nat_tunnel::carrier::{CarrierEntry, CarrierId};
use nat_tunnel::invite::{Endpoint, Invite};
use nat_tunnel::relay::room_for_key;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

fn rand_string(r: &mut Rng, max: usize) -> String {
    const SPECIAL: &[char] = &['|', ',', ':', '[', ']', '@', '\0', '.', '-', ' ', '\t', '\n', 'é', '漢', '🦀', '\u{202e}', '\u{feff}', '%', '/'];
    let n = r.below(max + 1);
    (0..n)
        .map(|_| match r.below(4) {
            0 => *r.pick(SPECIAL),
            1 => char::from_u32(r.next() as u32 % 0x11_0000).unwrap_or('x'),
            2 => (b'0' + r.below(10) as u8) as char,
            _ => (b'a' + r.below(26) as u8) as char,
        })
        .collect()
}

#[test]
fn random_strings_never_panic() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    for _ in 0..20_000 {
        let s = rand_string(&mut r, 200);
        let _ = Invite::parse(&s);
        let _ = Invite::parse(&format!("STRAIT2|{s}"));
        let _ = s.parse::<Endpoint>();
    }
}

#[test]
fn random_bytes_lossy_never_panic() {
    let mut r = Rng(12345);
    for _ in 0..10_000 {
        let n = r.below(300);
        let b: Vec<u8> = (0..n).map(|_| r.next() as u8).collect();
        let _ = Invite::parse(&String::from_utf8_lossy(&b));
    }
}

#[test]
fn pathological_shapes_never_panic() {
    let big = "a".repeat(1_000_000);
    let cases = vec![
        String::new(),
        "|".repeat(100_000),
        format!("STRAIT2{}", "|".repeat(100_000)),
        format!("STRAIT2|k|{}", ",".repeat(200_000)),
        format!("STRAIT2|{big}|1.2.3.4:1"),
        format!("STRAIT2|k|{big}:1"),
        format!("STRAIT2|k|{}", vec!["1.2.3.4:5"; 50_000].join(",")),
        format!("STRAIT2|k|{}", vec!["h.example.com:5"; 50_000].join(",")),
        "STRAIT2|k\0|1.2.3.4:5".into(),
        "STRAIT2|k|1.2.3.4\0:5".into(),
        "STRAIT2|k|[::1".into(),
        "STRAIT2|k|[::1]:".into(),
        "STRAIT2|k|[]:5".into(),
        "STRAIT2|k|:::::".into(),
        "STRAIT2|k|1.2.3.4:99999".into(),
        "STRAIT2|k|1.2.3.4:0".into(),
        "STRAIT2|k|h:65536".into(),
        "STRAIT2|k|.:5".into(),
        "STRAIT2|k|..:5".into(),
        "STRAIT2|k|a..b:5".into(),
        "a:1|b|c|d|e|f".into(),
        "|||".into(),
        "STRAIT2||1.2.3.4:5".into(),
        "STRAIT2|k|1.2.3.4:5|||||||x".into(),
        format!("STRAIT2|k|1.2.3.4:5||r|{}", "a,".repeat(100_000)),
        format!("STRAIT2|k|1.2.3.4:5||r|{}", "a".repeat(1_000_000)),
        "STRAIT2|k||1.2.3.4:5|,,,,".into(),
    ];
    for c in cases {
        let _ = Invite::parse(&c);
    }
}

#[test]
fn rejects_invalid() {
    for s in ["", "   ", "STRAIT2|", "STRAIT2||", "STRAIT2|k", "STRAIT2|k||", "STRAIT2|k|1.2.3.4:70000", "STRAIT2|k|h:0", "STRAIT2|a@b|1.2.3.4:5", "STRAIT2|k|-a.com:5", "STRAIT2|k|a_b.com:5", "STRAIT2|k|1.2.3:5"] {
        assert!(Invite::parse(s).is_none(), "should reject {s:?}");
    }
}

fn rand_label(r: &mut Rng) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let n = 1 + r.below(10);
    let mut s: String = (0..n).map(|_| *r.pick(A) as char).collect();
    if n > 2 && r.below(2) == 0 {
        s.replace_range(1..2, "-");
    }
    s
}

fn rand_endpoint(r: &mut Rng) -> Endpoint {
    let port = 1 + r.below(65535) as u16;
    match r.below(3) {
        0 => Endpoint::Addr(SocketAddr::from((Ipv4Addr::from(r.next() as u32), port))),
        1 => Endpoint::Addr(SocketAddr::from((Ipv6Addr::from(((r.next() as u128) << 64) | r.next() as u128), port))),
        _ => {
            let mut labels: Vec<String> = (0..1 + r.below(4)).map(|_| rand_label(r)).collect();
            labels.push(["com", "net", "example", "x1a"][r.below(4)].to_string());
            Endpoint::Name { host: labels.join("."), port }
        }
    }
}

#[test]
fn encode_parse_round_trip() {
    let mut r = Rng(0xDEADBEEF);
    for i in 0..10_000 {
        let key: String = (0..1 + r.below(64)).map(|_| *r.pick(b"0123456789abcdefXYZ_-=+/") as char).collect();
        let mut inv = Invite::new(key);
        for _ in 0..r.below(6) {
            inv.hosts.push(rand_endpoint(&mut r));
        }
        for _ in 0..r.below(4) {
            inv.signals.push(rand_endpoint(&mut r));
        }
        if inv.hosts.is_empty() && inv.signals.is_empty() {
            continue; // not a valid invite by design
        }
        if r.below(4) == 0 {
            inv.room = rand_label(&mut r);
        }
        for _ in 0..r.below(4) {
            let id: String = (0..1 + r.below(12)).map(|_| *r.pick(b"abcdefghijklmnopqrstuvwxyz0123456789") as char).collect();
            inv = inv.rv(id);
        }
        let text = inv.encode();
        assert_eq!(Invite::parse(&text).as_ref(), Some(&inv), "iter {i}: {text}");
        // surrounding whitespace is tolerated
        assert_eq!(Invite::parse(&format!("  {text}\n")).as_ref(), Some(&inv));
    }
}

#[test]
fn rv_field_fuzz_never_panics_and_never_exceeds_limits() {
    let mut r = Rng(4242);
    for _ in 0..20_000 {
        let rv = rand_string(&mut r, 60);
        let room = rand_string(&mut r, 10);
        for text in [format!("STRAIT2|k|1.2.3.4:5||{room}|{rv}"), format!("STRAIT2|k||1.2.3.4:5|{rv}"), format!("STRAIT2|k|1.2.3.4:5|||{rv}")] {
            if let Some(inv) = Invite::parse(&text) {
                assert!(inv.rv.len() <= 8, "{text:?}");
                assert!(inv.rv.iter().all(|i| (1..=12).contains(&i.len()) && i.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())), "{text:?}");
                // whatever was accepted re-encodes to something that parses to the same value
                assert_eq!(Invite::parse(&inv.encode()).as_ref(), Some(&inv), "{text:?}");
            }
        }
    }
}

#[test]
fn room_for_key_deterministic_and_distinct() {
    let mut r = Rng(777);
    assert_eq!(room_for_key("k"), room_for_key("k"));
    let mut seen = std::collections::HashSet::new();
    for i in 0..5000 {
        let k = format!("{i}-{}", rand_string(&mut r, 20));
        assert_eq!(room_for_key(&k), room_for_key(&k));
        seen.insert(room_for_key(&k));
    }
    // 32-bit space, 5000 keys: birthday collisions expected ~3; demand near-distinct.
    assert!(seen.len() > 4900, "only {} distinct rooms", seen.len());
    assert_ne!(room_for_key("a"), room_for_key("b"));
    assert_ne!(room_for_key(""), room_for_key("\0"));
}

/// BUG (invite.rs Endpoint::from_str): IP-literal endpoints accept port 0
/// (`SocketAddr` parses it), while hostnames reject it. Un-ignore once fixed.
#[test]
fn port_zero_rejected_for_ip_literals() {
    for s in ["STRAIT2|k|1.2.3.4:0", "STRAIT2|k|[::1]:0", "STRAIT2|k||1.2.3.4:0"] {
        assert!(Invite::parse(s).is_none(), "accepted {s:?}");
    }
}

// ---------------------------------------------------------------- carriers (`cr` field)

#[test]
fn old_invites_are_byte_identical() {
    for s in [
        "STRAIT2|abc123|203.0.113.10:7100",
        "STRAIT2|abc123||203.0.113.5:7000",
        "STRAIT2|k|1.2.3.4:5||r",
        "STRAIT2|k|1.2.3.4:5|||sig,trk",
        "STRAIT2|k|1.2.3.4:5|6.7.8.9:1||trk",
        "STRAIT2|k|a-b.example.com:7100,203.0.113.10:1,[2001:db8::1]:7100|signal.example.com:7000",
    ] {
        let inv = Invite::parse(s).unwrap();
        assert!(inv.cr.is_empty() && inv.cr_unknown.is_empty(), "{s}");
        assert_eq!(inv.encode(), s);
    }
    assert_eq!(Invite::parse("203.0.113.10:7000|srvtest|01234567").unwrap().cr.len(), 0);
}

#[test]
fn carrier_entries_round_trip_with_escapes() {
    let inv = Invite::new("k")
        .host("1.2.3.4:7100".parse::<SocketAddr>().unwrap())
        .carrier(CarrierEntry::new(CarrierId::Ss).at("1.2.3.4:8388"))
        .carrier(CarrierEntry::new(CarrierId::Ws).at("h.example:443").with("sni", "h.example").with("path", "/a b,c;d=e|f%g"))
        .carrier(CarrierEntry::new(CarrierId::Xray).at("[2001:db8::1]:443").with("sni", "www.example.org").with("mode", "stream-one"))
        .carrier(CarrierEntry::new(CarrierId::Awg));
    let text = inv.encode();
    assert!(text.starts_with("STRAIT2|k|1.2.3.4:7100||||ss@1.2.3.4:8388,ws@h.example:443;sni=h.example;path=/a%20b%2Cc%3Bd%3De%7Cf%25g,"), "{text}");
    assert_eq!(text.matches('|').count(), 6, "reserved characters are escaped: {text}");
    assert_eq!(Invite::parse(&text).as_ref(), Some(&inv));
}

#[test]
fn secrets_and_unknown_params_never_travel() {
    let inv = Invite::new("k")
        .host("1.2.3.4:7100".parse::<SocketAddr>().unwrap())
        .carrier(CarrierEntry::new(CarrierId::Ws).at("h.example:443").with("sni", "h").with("key", "SECRET").with("token", "SECRET"))
        .carrier(CarrierEntry::new(CarrierId::Ss).at("1.2.3.4:1").with("psk", "SECRET"));
    let text = inv.encode();
    assert!(!text.contains("SECRET") && !text.contains("psk") && !text.contains("token"), "{text}");
    // a hand-written invite with a disallowed parameter is accepted but the parameter is dropped
    let p = Invite::parse("STRAIT2|k|1.2.3.4:7100||||ws@h.example:443;sni=h;key=SECRET;path=/p").unwrap();
    assert_eq!(p.cr[0].params, vec![("sni".to_string(), "h".to_string()), ("path".to_string(), "/p".to_string())]);
}

#[test]
fn unknown_carrier_ids_are_kept_in_place() {
    let text = "STRAIT2|k|1.2.3.4:7100||||ss@1.2.3.4:1,quic@1.2.3.4:2;x=1,ws@h.example:443,zzz";
    let inv = Invite::parse(text).unwrap();
    assert_eq!(inv.cr.iter().map(|c| c.id).collect::<Vec<_>>(), [CarrierId::Ss, CarrierId::Ws]);
    assert_eq!(inv.cr_unknown, [(1, "quic@1.2.3.4:2;x=1".to_string()), (3, "zzz".to_string())]);
    assert_eq!(inv.encode(), text);
}

#[test]
fn carrier_only_invite_is_valid_but_bare_carrier_is_not() {
    assert!(Invite::parse("STRAIT2|k|||||ws@h.example:443").is_some());
    assert!(Invite::parse("STRAIT2|k|||||ws").is_none(), "no endpoint anywhere: cannot connect");
    for bad in ["ws@", "ws@nonsense", "ws@h:0", "WS@h:1", "ws@h:1;sni", "ws@h:1;=v", "ws@h:1;sni=%zz", "ws@h:1;sni=%ff", "ss@b@c:1"] {
        assert!(Invite::parse(&format!("STRAIT2|k|1.2.3.4:5||||{bad}")).is_none(), "{bad}");
    }
    let nine = (0..9).map(|i| format!("ss{i}")).collect::<Vec<_>>().join(",");
    assert!(Invite::parse(&format!("STRAIT2|k|1.2.3.4:5||||{nine}")).is_none(), "more than 8 entries");
    let eight = (0..8).map(|i| format!("ss{i}")).collect::<Vec<_>>().join(",");
    assert!(Invite::parse(&format!("STRAIT2|k|1.2.3.4:5||||{eight}")).is_some());
}

#[test]
fn cr_field_fuzz_never_panics_and_respects_limits() {
    let mut r = Rng(0xC0FFEE);
    for _ in 0..20_000 {
        let cr = rand_string(&mut r, 120);
        for text in [format!("STRAIT2|k|1.2.3.4:5||||{cr}"), format!("STRAIT2|k|1.2.3.4:5||x|trk|{cr}")] {
            if let Some(inv) = Invite::parse(&text) {
                assert!(inv.cr.len() + inv.cr_unknown.len() <= 8, "{text:?}");
                for e in &inv.cr {
                    let ok = CarrierEntry::allowed_params(e.id);
                    assert!(e.params.iter().all(|(k, _)| ok.contains(&k.as_str())), "{text:?}");
                }
                assert_eq!(Invite::parse(&inv.encode()).as_ref(), Some(&inv), "{text:?}");
            }
        }
    }
}

#[test]
fn carriers_encode_parse_round_trip() {
    let mut r = Rng(0xFACADE);
    for i in 0..5_000 {
        let mut inv = Invite::new("k").host(rand_endpoint(&mut r));
        if r.below(3) == 0 {
            inv.room = rand_label(&mut r);
        }
        if r.below(3) == 0 {
            inv = inv.rv("trk");
        }
        for _ in 0..r.below(6) {
            let id = *r.pick(&[CarrierId::Ss, CarrierId::Ws, CarrierId::Awg, CarrierId::Xray, CarrierId::Udp]);
            let mut e = CarrierEntry::new(id);
            if r.below(2) == 0 {
                e = e.at(rand_endpoint(&mut r).to_string());
            }
            for k in CarrierEntry::allowed_params(id) {
                if r.below(2) == 0 {
                    let v: String = (0..r.below(20)).map(|_| char::from_u32(0x20 + r.below(0x500) as u32).unwrap_or('x')).filter(|c| !c.is_control()).collect();
                    e = e.with(*k, v);
                }
            }
            inv = inv.carrier(e);
        }
        let text = inv.encode();
        assert_eq!(Invite::parse(&text).as_ref(), Some(&inv), "iter {i}: {text}");
    }
}
