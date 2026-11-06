//! awg carrier: loopback UDP + the in-memory lossy link. Needs `--features cr-awg`.
#![cfg(feature = "cr-awg")]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nat_tunnel::carrier::awg::{AwgCarrier, AwgFactory, Role, HDR};
use nat_tunnel::carrier::mem::{self, MemCfg, MemIo};
use nat_tunnel::carrier::*;

const KEY: &[u8] = b"invite-key-A-0123456789abcdef013";

async fn recv(io: &dyn FrameIo) -> (Vec<u8>, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = vec![0u8; 4096];
        loop {
            io.readable().await.unwrap();
            match io.try_recv_from(&mut buf) {
                Ok((n, a)) => return (buf[..n].to_vec(), a),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("recv: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for a frame")
}

/// Nothing deliverable arrives within `ms`.
async fn silent(io: &dyn FrameIo, ms: u64) -> bool {
    tokio::time::sleep(Duration::from_millis(ms)).await;
    let mut b = [0u8; 4096];
    matches!(io.try_recv_from(&mut b), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
}

fn spec(key: &str, port: Option<u16>) -> CarrierSpec {
    CarrierSpec { endpoint: None, bind_port: port, params: vec![("key".into(), key.into())] }
}

fn mem_pair(cfg: MemCfg, ka: &[u8], kb: &[u8], seed: Option<u64>) -> (AwgCarrier, AwgCarrier, Arc<MemIo>, Arc<MemIo>) {
    let (a, b) = mem::pair(cfg);
    let (a, b) = (Arc::new(a), Arc::new(b));
    (
        AwgCarrier::wrap_seeded(a.clone(), ka, Role::Client, seed),
        AwgCarrier::wrap_seeded(b.clone(), kb, Role::Host, seed),
        a,
        b,
    )
}

fn b_addr() -> SocketAddr {
    mem::ADDR_B.parse().unwrap()
}
fn a_addr() -> SocketAddr {
    mem::ADDR_A.parse().unwrap()
}

async fn loopback_pair(key: &str) -> (Arc<dyn FrameIo>, Arc<dyn FrameIo>, SocketAddr) {
    let host = AwgFactory.listen(&spec(key, None)).await.unwrap();
    let port = host.local_addr().unwrap().port();
    let client = AwgFactory.dial(&spec(key, None)).await.unwrap();
    (host, client, format!("127.0.0.1:{port}").parse().unwrap())
}

#[tokio::test]
async fn round_trip_both_ways_over_udp() {
    let (host, client, haddr) = loopback_pair("00112233445566778899aabbccddeeff").await;
    client.send_to(b"hello host", haddr).await.unwrap();
    let (f, from) = recv(&*host).await;
    assert_eq!(f, b"hello host");
    host.send_to(&vec![7u8; 1000], from).await.unwrap();
    let (f, _) = recv(&*client).await;
    assert_eq!(f, vec![7u8; 1000]);
    assert!(host.caps().punchable && !host.caps().reliable_stream);
    assert!(host.udp().is_some());
}

#[tokio::test]
async fn two_clients_one_host() {
    let (host, c1, haddr) = loopback_pair("some invite").await;
    let c2 = AwgFactory.dial(&spec("some invite", None)).await.unwrap();
    c1.send_to(b"from one", haddr).await.unwrap();
    c2.send_to(b"from two", haddr).await.unwrap();
    let (fa, aa) = recv(&*host).await;
    let (fb, ab) = recv(&*host).await;
    assert_ne!(aa, ab);
    let (one, two) = if fa == b"from one" { (aa, ab) } else { (ab, aa) };
    assert_eq!(if fa == b"from one" { &fb } else { &fa }, b"from two");
    host.send_to(b"to one", one).await.unwrap();
    host.send_to(b"to two", two).await.unwrap();
    assert_eq!(recv(&*c1).await.0, b"to one");
    assert_eq!(recv(&*c2).await.0, b"to two");
}

#[tokio::test]
async fn wrong_key_dropped_no_reply() {
    let (a, b, _ra, rb) = mem_pair(MemCfg::default(), KEY, b"a different invite key entirely!!", None);
    a.send_to(b"secret", b_addr()).await.unwrap();
    assert!(silent(&b, 50).await);
    // The host never answers: nothing was sent back on the wire.
    assert_eq!(rb.stats().sent, 0);
}

#[tokio::test]
async fn junk_burst_ignored_and_never_answered() {
    let (a, b, ra, rb) = mem_pair(MemCfg::default(), KEY, KEY, Some(5));
    a.send_to(b"real", b_addr()).await.unwrap();
    let jc = a.params().junk_count;
    assert_eq!(ra.stats().sent as usize, jc + 1);
    assert_eq!(recv(&b).await.0, b"real");
    assert!(silent(&b, 20).await);
    assert_eq!(rb.stats().sent, 0, "host answered junk or real frame unprompted");
    // Burst is once per peer, not per frame.
    a.send_to(b"again", b_addr()).await.unwrap();
    assert_eq!(ra.stats().sent as usize, jc + 2);
    assert_eq!(recv(&b).await.0, b"again");
    // The host side never junks.
    b.send_to(b"x", a_addr()).await.unwrap();
    assert_eq!(rb.stats().sent, 1);
}

#[tokio::test]
async fn garbage_tampered_truncated_dropped() {
    let (a, b, ra, _rb) = mem_pair(MemCfg::default(), KEY, KEY, Some(9));
    // Capture a genuine datagram by sending through a second wrapper on a spare link.
    let (c, d, _rc, rd) = mem_pair(MemCfg::default(), KEY, KEY, Some(10));
    c.send_to(&vec![3u8; 300], b_addr()).await.unwrap();
    let mut wire = Vec::new();
    loop {
        let mut buf = vec![0u8; 2048];
        match rd.try_recv_from(&mut buf) {
            Ok((n, _)) => wire.push(buf[..n].to_vec()),
            Err(_) => break,
        }
    }
    let real = wire.pop().unwrap();
    let mut bad: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xAB; HDR - 1], vec![0u8; 1400], real[..real.len() - 1].to_vec(), real[..HDR].to_vec()];
    for i in 0..real.len().min(80) {
        let mut t = real.clone();
        t[i] ^= 0x01;
        bad.push(t);
    }
    let mut rng = Rng::new(77);
    for _ in 0..500 {
        let mut g = vec![0u8; 1 + rng.below(1400) as usize];
        rng.fill(&mut g);
        bad.push(g);
    }
    for g in &bad {
        ra.send_to(g, b_addr()).await.unwrap();
    }
    assert!(silent(&b, 50).await);
    // The untouched datagram still verifies (on the correct receiver).
    ra.send_to(&real, b_addr()).await.unwrap();
    let _ = (a, d);
    let (f, _) = recv(&b).await;
    assert_eq!(f, vec![3u8; 300]);
}

#[tokio::test]
async fn oversize_is_frame_too_large() {
    let (a, _b, _ra, _rb) = mem_pair(MemCfg::default(), KEY, KEY, None);
    let max = a.caps().max_frame;
    assert!(a.send_to(&vec![0u8; max], b_addr()).await.is_ok());
    let e = a.send_to(&vec![0u8; max + 1], b_addr()).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::FrameTooLarge { max }));
}

#[tokio::test]
async fn mtu_accounting() {
    let cfg = MemCfg { mtu: 1000, ..Default::default() };
    for k in 0..40u8 {
        let key = [k; 32];
        let (a, b, ra, rb) = mem_pair(cfg.clone(), &key, &key, Some(k as u64));
        let c = a.caps();
        assert_eq!(c.id, CarrierId::Awg);
        assert_eq!(c.max_frame + c.overhead, 1000);
        // A max-size frame never exceeds the inner MTU on the wire, for any padding draw.
        for s in [c.max_frame, c.max_frame - 1, 40, 41, 100, 130] {
            a.send_to(&vec![1u8; s], b_addr()).await.unwrap();
            assert_eq!(recv(&b).await.0.len(), s);
        }
        let _ = (ra, rb);
    }
}

#[tokio::test]
async fn padding_exactness_fuzz() {
    let (a, b, _ra, _rb) = mem_pair(MemCfg::default(), KEY, KEY, Some(1234));
    let max = a.caps().max_frame;
    let mut rng = Rng::new(4321);
    for _ in 0..3000 {
        let n = rng.below(max as u64 + 1) as usize;
        let mut f = vec![0u8; n];
        rng.fill(&mut f);
        a.send_to(&f, b_addr()).await.unwrap();
        assert_eq!(recv(&b).await.0, f);
        b.send_to(&f, a_addr()).await.unwrap();
        assert_eq!(recv(&a).await.0, f);
    }
}

#[tokio::test]
async fn lossy_reordered_duplicated_link_keeps_framing() {
    let cfg = MemCfg { seed: 3, loss: 0.1, dup: 0.15, reorder: 0.3, reorder_extra: Duration::from_millis(5), ..Default::default() };
    let (a, b, _ra, _rb) = mem_pair(cfg, KEY, KEY, Some(8));
    let mut sent = std::collections::HashSet::new();
    for i in 0..400u32 {
        let mut f = vec![(i % 251) as u8; 40 + (i as usize * 7) % 1000];
        f[..4].copy_from_slice(&i.to_le_bytes());
        sent.insert(f.clone());
        a.send_to(&f, b_addr()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut got = 0;
    let mut buf = vec![0u8; 4096];
    loop {
        match b.try_recv_from(&mut buf) {
            Ok((n, _)) => {
                assert!(sent.contains(&buf[..n]), "delivered a frame that was never sent");
                got += 1;
            }
            Err(_) => break,
        }
    }
    assert!(got > 250, "only {got} delivered");
}

/// All datagrams `a` put on the wire for `n` frames, read raw from the peer end.
async fn capture(key: &[u8], seed: u64, n: usize, len: impl Fn(usize) -> usize) -> Vec<(usize, Vec<u8>)> {
    let (a, _b, _ra, rb) = mem_pair(MemCfg { mtu: 2000, ..Default::default() }, key, key, Some(seed));
    let mut out = Vec::new();
    for i in 0..n {
        let l = len(i);
        a.send_to(&vec![0u8; l], b_addr()).await.unwrap(); // constant plaintext on purpose
        loop {
            let mut buf = vec![0u8; 2100];
            match rb.try_recv_from(&mut buf) {
                Ok((k, _)) => out.push((l, buf[..k].to_vec())),
                Err(_) => break,
            }
        }
    }
    out
}

#[tokio::test]
async fn no_fixed_header_and_flat_bytes() {
    let mut rng = Rng::new(99);
    let lens: Vec<usize> = (0..10_000).map(|_| 60 + rng.below(1000) as usize).collect();
    let pk = capture(KEY, 21, 10_000, |i| lens[i]).await;
    assert!(pk.len() >= 10_000);
    let min = pk.iter().map(|p| p.1.len()).min().unwrap();
    assert!(min >= 32);
    for off in 0..32 {
        let mut hist = [0u32; 256];
        for (_, d) in &pk {
            hist[d[off] as usize] += 1;
        }
        let e = pk.len() as f64 / 256.0;
        let chi: f64 = hist.iter().map(|&c| (c as f64 - e).powi(2) / e).sum();
        // df = 255: mean 255, sd ~22.6; 6 sigma bound.
        assert!(chi < 255.0 + 6.0 * 22.6, "offset {off} not flat: chi2 {chi}");
        assert!(hist.iter().filter(|&&c| c > 0).count() > 240, "offset {off} misses byte values");
    }
}

#[tokio::test]
async fn length_distribution_within_derived_range() {
    let (a, ..) = mem_pair(MemCfg::default(), KEY, KEY, None);
    let pr = a.params().clone();
    let pk = capture(KEY, 31, 4000, |i| if i % 2 == 0 { 600 } else { 30 }).await;
    let mut big = std::collections::HashSet::new();
    let mut small = std::collections::HashSet::new();
    for (l, d) in &pk {
        let extra = d.len() as isize - (*l + HDR) as isize;
        if *l == 600 && extra >= 0 && (extra as usize) <= pr.pad_max {
            assert!(extra as usize >= pr.pad_min);
            big.insert(extra);
        } else if *l == 30 && extra >= 0 && (extra as usize) <= pr.bucket - 1 + pr.small_extra {
            small.insert(extra);
        }
    }
    // Every data/ctl datagram falls in its range (junk is the only exception, 3..8 of 4000).
    let counted = pk.iter().filter(|(l, d)| (*l == 600 || *l == 30) && d.len() >= HDR + *l).count();
    assert!(counted >= 4000, "{counted}");
    let span = pr.pad_max - pr.pad_min + 1;
    assert!(big.len() * 10 >= span * 9, "big pad covers {}/{}", big.len(), span);
    assert!(small.len() >= 2);
}

#[tokio::test]
async fn every_invite_has_a_different_fingerprint() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut types = HashSet::new();
    for k in 0..200u32 {
        let (a, ..) = mem_pair(MemCfg::default(), &k.to_le_bytes(), &k.to_le_bytes(), None);
        let p = a.params().clone();
        assert!(p.pad_min <= p.pad_max && p.junk_min <= p.junk_max && p.junk_count >= 3);
        types.insert(p.data_type.0);
        seen.insert(format!("{p:?}"));
    }
    assert!(seen.len() >= 199, "{}", seen.len());
    assert!(types.len() >= 195);
    // Same key, same parameters on both ends.
    let (a, b, ..) = mem_pair(MemCfg::default(), KEY, KEY, None);
    assert_eq!(a.params(), b.params());
}

#[tokio::test]
async fn factory_needs_key_and_disclosure_is_honest() {
    assert!(matches!(AwgFactory.listen(&CarrierSpec::default()).await, Err(CarrierError::Failed(_))));
    assert!(matches!(AwgFactory.probe(&CarrierSpec::default(), Duration::from_secs(1)).await, nat_tunnel::rendezvous::ProbeStatus::Reachable { .. }));
    let d = AwgFactory.disclosure();
    assert!(d.operator.starts_with("none") && !d.shared.is_empty() && !d.not_shared.is_empty());
    assert!(by_ids(&["awg".to_string()]).len() == 1);
}
