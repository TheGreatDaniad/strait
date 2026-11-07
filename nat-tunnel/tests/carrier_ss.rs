//! `ss` carrier (Shadowsocks-2022 over UDP), loopback only.
#![cfg(feature = "cr-ss")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nat_tunnel::carrier::ss::{b64, derive_psk, PLACEHOLDER, SS_MAX_FRAME};
use nat_tunnel::carrier::*;
use nat_tunnel::rendezvous::derive::{parse_key, Derived};
use nat_tunnel::rendezvous::ProbeStatus;
use tokio::net::UdpSocket;

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const KEY2: &str = "ffeeddccbbaa99887766554433221100";

fn spec(ep: &str, key: &str) -> CarrierSpec {
    CarrierSpec { endpoint: Some(ep.into()), bind_port: None, params: vec![("key".into(), key.into())] }
}

async fn pair() -> (Arc<dyn FrameIo>, Arc<dyn FrameIo>, SocketAddr) {
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let addr = host.local_addr().unwrap();
    let cli = f.dial(&spec(&addr.to_string(), KEY)).await.unwrap();
    (host, cli, addr)
}

async fn recv(io: &dyn FrameIo) -> (Vec<u8>, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = vec![0u8; 4096];
        loop {
            io.readable().await.unwrap();
            if let Ok((n, a)) = io.try_recv_from(&mut buf) {
                return (buf[..n].to_vec(), a);
            }
        }
    })
    .await
    .expect("frame expected")
}

async fn none(io: &dyn FrameIo, ms: u64) {
    let mut buf = vec![0u8; 4096];
    let r = tokio::time::timeout(Duration::from_millis(ms), io.readable()).await;
    if r.is_ok() {
        assert!(io.try_recv_from(&mut buf).is_err(), "no frame expected");
    }
}

#[tokio::test]
async fn frames_both_ways() {
    let (host, cli, haddr) = pair().await;
    assert_eq!(cli.caps().id, CarrierId::Ss);
    assert!(cli.caps().punchable);
    cli.send_to(b"hello", haddr).await.unwrap();
    let (f, peer) = recv(&*host).await;
    assert_eq!(f, b"hello");
    host.send_to(&[7u8; SS_MAX_FRAME], peer).await.unwrap();
    let (f, from) = recv(&*cli).await;
    assert_eq!((f.len(), from), (SS_MAX_FRAME, haddr));
    // an unknown peer / wrong host address is an explicit error
    let bogus: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let e = host.send_to(b"x", bogus).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::UnknownPeer));
    let e = cli.send_to(b"x", bogus).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::UnknownPeer));
}

#[tokio::test]
async fn two_clients_distinct_peers() {
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let ha = host.local_addr().unwrap();
    let a = f.dial(&spec(&ha.to_string(), KEY)).await.unwrap();
    let b = f.dial(&spec(&ha.to_string(), KEY)).await.unwrap();
    a.send_to(b"from-a", ha).await.unwrap();
    let (fa, pa) = recv(&*host).await;
    b.send_to(b"from-b", ha).await.unwrap();
    let (fb, pb) = recv(&*host).await;
    assert_eq!((fa.as_slice(), fb.as_slice()), (&b"from-a"[..], &b"from-b"[..]));
    assert_ne!(pa, pb);
    host.send_to(b"to-b", pb).await.unwrap();
    host.send_to(b"to-a", pa).await.unwrap();
    assert_eq!(recv(&*a).await.0, b"to-a");
    assert_eq!(recv(&*b).await.0, b"to-b");
}

#[tokio::test]
async fn wrong_key_delivers_nothing() {
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let ha = host.local_addr().unwrap();
    let bad = f.dial(&spec(&ha.to_string(), KEY2)).await.unwrap();
    for _ in 0..5 {
        bad.send_to(b"intruder", ha).await.unwrap();
    }
    none(&*host, 400).await;
    // the host still serves a good client
    let good = f.dial(&spec(&ha.to_string(), KEY)).await.unwrap();
    good.send_to(b"ok", ha).await.unwrap();
    assert_eq!(recv(&*host).await.0, b"ok");
}

#[tokio::test]
async fn foreign_target_is_not_proxied() {
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use shadowsocks::relay::udprelay::{options::UdpSocketControlData, ProxySocket};
    use shadowsocks::relay::Address;
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let ha = host.local_addr().unwrap();
    let k = parse_key(KEY).unwrap();
    let cfg = ServerConfig::new(ha, b64(&derive_psk(&k)), CipherKind::AEAD2022_BLAKE3_AES_128_GCM).unwrap();
    let s = ProxySocket::connect(Context::new_shared(ServerType::Local), &cfg).await.unwrap();
    let mut c = UdpSocketControlData::default();
    c.client_session_id = 77;
    s.send_with_ctrl(&Address::SocketAddress("8.8.8.8:53".parse().unwrap()), &c, b"relay me").await.unwrap();
    none(&*host, 300).await;
    // control: the placeholder target from the same raw client is accepted
    c.packet_id = 1;
    s.send_with_ctrl(&Address::SocketAddress(PLACEHOLDER), &c, b"mine").await.unwrap();
    assert_eq!(recv(&*host).await.0, b"mine");
}

#[tokio::test]
async fn oversize_is_an_error() {
    let (host, cli, ha) = pair().await;
    let e = cli.send_to(&vec![0u8; SS_MAX_FRAME + 1], ha).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::FrameTooLarge { max: SS_MAX_FRAME }));
    cli.send_to(b"x", ha).await.unwrap();
    let (_, peer) = recv(&*host).await;
    let e = host.send_to(&vec![0u8; SS_MAX_FRAME + 1], peer).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::FrameTooLarge { max: SS_MAX_FRAME }));
    assert!(cli.caps().max_frame + cli.caps().overhead <= 1472);
}

#[tokio::test]
async fn garbage_and_truncated_are_ignored() {
    let (host, cli, ha) = pair().await;
    cli.send_to(b"first", ha).await.unwrap();
    let (_, peer) = recv(&*host).await;
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for n in [0usize, 1, 15, 16, 17, 31, 32, 33, 60, 200, 1472] {
        raw.send_to(&vec![0xA5u8; n], ha).await.unwrap();
        raw.send_to(&(0..n).map(|i| (i * 31 + 7) as u8).collect::<Vec<_>>(), ha).await.unwrap();
    }
    none(&*host, 300).await;
    cli.send_to(b"still works", ha).await.unwrap();
    assert_eq!(recv(&*host).await.0, b"still works");
    host.send_to(b"back", peer).await.unwrap();
    assert_eq!(recv(&*cli).await.0, b"back");
    assert_eq!(host.health(), Health::Ok);
}

/// Loopback UDP middlebox between one client and the host. `plan(i)` decides per client datagram:
/// number of copies to forward (0 = drop) and extra delay in ms.
async fn middle(host: SocketAddr, plan: impl Fn(u64) -> (usize, u64) + Send + Sync + 'static) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fa = front.local_addr().unwrap();
    let client = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
    let (f2, b2, c2) = (front.clone(), back.clone(), client.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut i = 0u64;
        loop {
            let (n, from) = f2.recv_from(&mut buf).await.unwrap();
            *c2.lock().unwrap() = Some(from);
            let (copies, delay) = plan(i);
            i += 1;
            let d = buf[..n].to_vec();
            let b = b2.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                for _ in 0..copies {
                    let _ = b.send_to(&d, host).await;
                }
            });
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, _) = back.recv_from(&mut buf).await.unwrap();
            let c = *client.lock().unwrap();
            if let Some(c) = c {
                let _ = front.send_to(&buf[..n], c).await;
            }
        }
    });
    fa
}

#[tokio::test]
async fn replayed_datagram_is_dropped() {
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let ha = host.local_addr().unwrap();
    // every datagram reaches the host three times
    let mid = middle(ha, |_| (3, 0)).await;
    let cli = f.dial(&spec(&mid.to_string(), KEY)).await.unwrap();
    for i in 0..10u8 {
        cli.send_to(&[i; 40], mid).await.unwrap();
    }
    let mut got = Vec::new();
    while got.len() < 10 {
        got.push(recv(&*host).await.0[0]);
    }
    none(&*host, 400).await;
    got.sort();
    assert_eq!(got, (0..10).collect::<Vec<u8>>());
}

#[tokio::test]
async fn lossy_reordering_link() {
    let f = ss::SsFactory;
    let host = f.listen(&spec("127.0.0.1:0", KEY)).await.unwrap();
    let ha = host.local_addr().unwrap();
    // seeded: drop ~25%, duplicate ~15%, delay ~20% by 15 ms (reorder)
    let mid = middle(ha, |i| {
        let mut r = Rng::new(i + 1);
        let x = r.f64();
        let delay = if r.f64() < 0.2 { 15 } else { 0 };
        (if x < 0.25 { 0 } else if x < 0.40 { 2 } else { 1 }, delay)
    })
    .await;
    let cli = f.dial(&spec(&mid.to_string(), KEY)).await.unwrap();
    let n = 300u32;
    for i in 0..n {
        cli.send_to(&i.to_be_bytes(), mid).await.unwrap();
        if i % 50 == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut seen = std::collections::HashSet::new();
    let mut buf = [0u8; 64];
    while let Ok((len, _)) = host.try_recv_from(&mut buf) {
        assert_eq!(len, 4);
        let v = u32::from_be_bytes(buf[..4].try_into().unwrap());
        assert!(v < n);
        assert!(seen.insert(v), "duplicate frame {v} delivered");
    }
    assert!(seen.len() > 150 && seen.len() < 290, "delivered {}", seen.len());
}

#[test]
fn key_is_distinct_and_pinned() {
    let k = parse_key(KEY).unwrap();
    let p = derive_psk(&k);
    assert_eq!(p, derive_psk(&k));
    assert_ne!(p, derive_psk(&parse_key(KEY2).unwrap()));
    let d = Derived::new(&k);
    for other in [&d.seal_key, &d.room_trk, &d.room_mqtt, &d.room_ntfy, &d.room_nostr, &d.dht_host_seed, &d.dht_client_seed] {
        assert_ne!(&p[..], &other[..16]);
    }
    assert_eq!(nat_tunnel::rendezvous::derive::hex(&p), "fedfdaed5ba45ab84f96bb0c7cfcb98b");
}

#[tokio::test]
async fn probe_and_disclosure() {
    let f = ss::SsFactory;
    assert!(matches!(f.probe(&spec("127.0.0.1:9", KEY), Duration::from_secs(2)).await, ProbeStatus::Reachable { .. }));
    assert!(matches!(f.probe(&spec("127.0.0.1:9", "zz"), Duration::from_secs(2)).await, ProbeStatus::Error(_)));
    assert!(matches!(f.probe(&CarrierSpec::default(), Duration::from_secs(2)).await, ProbeStatus::Error(_)));
    let d = f.disclosure();
    assert_eq!(d.operator, "none: peer to peer, no third party");
    assert!(d.shared.iter().any(|s| s.contains("random bytes")));
    assert!(f.listen(&CarrierSpec { endpoint: Some("127.0.0.1:0".into()), ..Default::default() }).await.is_err());
}
