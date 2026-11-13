//! Carrier layer (Phase A1): trait + ids, UDP control, stream framing (fuzz-style), loopback
//! demux, supervisor against a fake sidecar (this test binary re-executed), in-memory link, ladder.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use nat_tunnel::carrier::ladder::{entry_id, plan, Ladder, LadderError, LadderInput, Reason};
use nat_tunnel::carrier::loopback::{Demux, Guard, LoopbackCfg, LoopbackUdp};
use nat_tunnel::carrier::mem::{self, MemCfg};
use nat_tunnel::carrier::stream::{encode_record, FrameDecoder, FrameError, FramingCfg, StreamCarrier, StreamCfg};
use nat_tunnel::carrier::supervisor::*;
use nat_tunnel::carrier::udp::UdpCarrier;
use nat_tunnel::carrier::*;
use nat_tunnel::rendezvous::ProbeStatus;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

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

async fn recv_err(io: &dyn FrameIo) -> io::Error {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = vec![0u8; 4096];
        loop {
            io.readable().await.unwrap();
            match io.try_recv_from(&mut buf) {
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return e,
            }
        }
    })
    .await
    .expect("timed out waiting for an error")
}

fn would_block(io: &dyn FrameIo) -> bool {
    let mut b = [0u8; 64];
    matches!(io.try_recv_from(&mut b), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
}

/// Behaviour every carrier must share: ping/pong with stable peer keys, typed oversize error,
/// WouldBlock when empty.
async fn conformance(a: &dyn FrameIo, a_sees_b: SocketAddr, b: &dyn FrameIo) {
    assert!(would_block(a) && would_block(b));
    a.send_to(b"ping", a_sees_b).await.unwrap();
    let (got, pa) = recv(b).await;
    assert_eq!(got, b"ping");
    b.send_to(b"pong", pa).await.unwrap();
    let (got, from) = recv(a).await;
    assert_eq!(got, b"pong");
    assert_eq!(from, a_sees_b, "client sees the host under one stable key");
    let max = a.caps().max_frame;
    let err = a.send_to(&vec![7u8; max + 1], a_sees_b).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&err), Some(&CarrierError::FrameTooLarge { max }));
    // exactly max is fine
    a.send_to(&vec![7u8; max], a_sees_b).await.unwrap();
    assert_eq!(recv(b).await.0.len(), max);
}

// ---------------------------------------------------------------- ids, caps, errors, registry

#[test]
fn ids_roundtrip_and_registry() {
    for id in CarrierId::ALL {
        assert_eq!(CarrierId::parse(id.as_str()), Some(id));
    }
    assert_eq!(CarrierId::parse("nope"), None);
    assert!(CarrierId::Udp.default_punchable() && !CarrierId::Xray.default_punchable());
    // The registry depends on the compiled-in `cr-*` features, in registry order.
    let mut expect = vec![CarrierId::Udp];
    for (on, id) in [
        (cfg!(feature = "cr-ss"), CarrierId::Ss),
        (cfg!(feature = "cr-ws"), CarrierId::Ws),
        (cfg!(feature = "cr-awg"), CarrierId::Awg),
        (cfg!(feature = "cr-xray"), CarrierId::Xray),
    ] {
        if on {
            expect.push(id);
        }
    }
    assert_eq!(built_ids(), expect);
    let ids: Vec<String> = ["xray", "udp", "udp", "bogus"].iter().map(|s| s.to_string()).collect();
    let got: Vec<CarrierId> = by_ids(&ids).iter().map(|f| f.id()).collect();
    // Unknown and not-compiled-in ids are skipped, duplicates collapse, order follows the request.
    let mut want = Vec::new();
    if cfg!(feature = "cr-xray") {
        want.push(CarrierId::Xray);
    }
    want.push(CarrierId::Udp);
    assert_eq!(got, want);
    assert_eq!(all_disclosures().len(), expect.len());
}

#[test]
fn caps_tun_mtu_and_error_mapping() {
    let c = Caps { id: CarrierId::Udp, max_frame: 1472, punchable: true, reliable_stream: false, overhead: 0 };
    assert_eq!(c.tun_mtu(), 1400);
    assert_eq!(Caps { max_frame: 1300, ..c }.tun_mtu(), 1265);
    assert_eq!(Caps { max_frame: 10, ..c }.tun_mtu(), 0);
    for e in [
        CarrierError::Unsupported,
        CarrierError::Blocked("x".into()),
        CarrierError::Failed("y".into()),
        CarrierError::FrameTooLarge { max: 5 },
        CarrierError::Eof,
        CarrierError::Reset("r".into()),
        CarrierError::Closed,
        CarrierError::UnknownPeer,
    ] {
        let io: io::Error = e.clone().into();
        assert_eq!(CarrierError::from_io(&io), Some(&e));
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------- UDP control

#[tokio::test]
async fn udp_carrier_conformance() {
    let a = UdpCarrier::bind(None).await.unwrap();
    let b = UdpCarrier::bind(None).await.unwrap();
    let pb = b.local_addr().unwrap().port();
    assert!(a.caps().punchable && a.udp().is_some());
    assert_eq!(a.caps().id, CarrierId::Udp);
    conformance(&a, sa(&format!("127.0.0.1:{pb}")), &b).await;
}

#[tokio::test]
async fn udp_port_in_use_is_an_error() {
    let a = UdpCarrier::bind(None).await.unwrap();
    let p = a.local_addr().unwrap().port();
    assert!(UdpCarrier::bind(Some(p)).await.is_err());
}

#[tokio::test]
async fn udp_factory_listen_dial() {
    let f = registry().into_iter().next().unwrap();
    let h = f.listen(&CarrierSpec::default()).await.unwrap();
    let c = f.dial(&CarrierSpec::default()).await.unwrap();
    let port = h.local_addr().unwrap().port();
    c.send_to(b"hi", sa(&format!("127.0.0.1:{port}"))).await.unwrap();
    assert_eq!(recv(&*h).await.0, b"hi");
    assert!(matches!(f.probe(&CarrierSpec::default(), Duration::from_secs(1)).await, ProbeStatus::Reachable { .. }));
}

// ---------------------------------------------------------------- stream framing

fn rand_frame(rng: &mut Rng, max: usize) -> Vec<u8> {
    let mut f = vec![0u8; 1 + rng.below(max as u64) as usize];
    rng.fill(&mut f);
    f
}

fn cfgs() -> Vec<FramingCfg> {
    vec![
        FramingCfg::plain(1500),
        FramingCfg { max_frame: 1500, buckets: vec![128, 512, 1600], random_pad: 40 },
    ]
}

#[test]
fn codec_roundtrip_random_splits() {
    for cfg in cfgs() {
        let mut rng = Rng::new(7);
        for _ in 0..300 {
            let frames: Vec<Vec<u8>> = (0..1 + rng.below(20)).map(|_| rand_frame(&mut rng, 1500)).collect();
            let mut wire = Vec::new();
            for f in &frames {
                encode_record(&cfg, f, &mut rng, &mut wire).unwrap();
                if cfg.padded() && rng.below(4) == 0 {
                    encode_record(&cfg, &[], &mut rng, &mut wire).unwrap(); // cover record
                }
            }
            let mut dec = FrameDecoder::new(&cfg);
            let mut out = Vec::new();
            let mut rest = &wire[..];
            while !rest.is_empty() {
                let n = (1 + rng.below(300) as usize).min(rest.len());
                dec.feed(&rest[..n], &mut out).unwrap();
                rest = &rest[n..];
            }
            assert_eq!(out, frames);
            dec.finish().unwrap();
            assert_eq!(dec.buffered(), 0);
        }
    }
}

#[test]
fn codec_truncated_at_every_cut() {
    for cfg in cfgs() {
        let mut rng = Rng::new(11);
        let mut wire = Vec::new();
        let mut bounds = vec![0usize];
        for _ in 0..6 {
            encode_record(&cfg, &rand_frame(&mut rng, 700), &mut rng, &mut wire).unwrap();
            bounds.push(wire.len());
        }
        for cut in 0..=wire.len() {
            let mut dec = FrameDecoder::new(&cfg);
            let mut out = Vec::new();
            dec.feed(&wire[..cut], &mut out).unwrap();
            let complete = bounds.iter().filter(|&&b| b != 0 && b <= cut).count();
            assert_eq!(out.len(), complete, "cut {cut}");
            assert_eq!(dec.finish().is_ok(), bounds.contains(&cut), "cut {cut}");
            if !bounds.contains(&cut) {
                assert_eq!(dec.finish(), Err(FrameError::Truncated));
            }
        }
    }
}

#[test]
fn codec_oversize_prefix_rejected_without_allocating() {
    let cfg = FramingCfg::plain(1500);
    let mut dec = FrameDecoder::new(&cfg);
    let mut out = Vec::new();
    assert_eq!(dec.feed(&[0xFF, 0xFF], &mut out), Err(FrameError::Oversize { len: 65535, max: 1500 }));
    assert!(dec.capacity() < 64, "capacity {}", dec.capacity());
    // a legal-but-large claim followed by a flood still never buffers more than one record
    let mut dec = FrameDecoder::new(&cfg);
    let mut flood = vec![0x05, 0xDC]; // 1500
    flood.extend(std::iter::repeat(1u8).take(3_000_000));
    dec.feed(&flood, &mut out).unwrap();
    assert!(dec.capacity() <= 2 * 1502, "capacity {}", dec.capacity());
    assert!(!out.is_empty());
}

#[test]
fn codec_garbage_never_panics_or_grows() {
    for cfg in cfgs() {
        let mut rng = Rng::new(99);
        for _ in 0..2000 {
            let mut junk = vec![0u8; rng.below(3000) as usize];
            rng.fill(&mut junk);
            let mut dec = FrameDecoder::new(&cfg);
            let mut out = Vec::new();
            let _ = dec.feed(&junk, &mut out);
            assert!(dec.buffered() <= 65535);
            assert!(out.iter().all(|f| f.len() <= 1500));
        }
    }
}

#[test]
fn codec_padded_malformed_and_cover() {
    let cfg = FramingCfg { max_frame: 10, buckets: vec![64], random_pad: 0 };
    let mut out = Vec::new();
    assert_eq!(FrameDecoder::new(&cfg).feed(&[0, 1, 0], &mut out), Err(FrameError::BadBody));
    assert_eq!(FrameDecoder::new(&cfg).feed(&[0, 5, 0, 9, 1, 2, 3], &mut out), Err(FrameError::BadBody));
    let mut m = vec![0, 64, 0, 20];
    m.extend(vec![0u8; 62]);
    assert_eq!(FrameDecoder::new(&cfg).feed(&m, &mut out), Err(FrameError::Oversize { len: 20, max: 10 }));
    // plain zero-length record is a cover record too
    let mut d = FrameDecoder::new(&FramingCfg::plain(10));
    d.feed(&[0, 0, 0, 2, 9, 9], &mut out).unwrap();
    assert_eq!(out, vec![vec![9, 9]]);
    // encoder never accepts an oversize frame
    let mut w = Vec::new();
    let e = encode_record(&FramingCfg::plain(10), &[0; 11], &mut Rng::new(1), &mut w).unwrap_err();
    assert_eq!(e, CarrierError::FrameTooLarge { max: 10 });
    assert!(w.is_empty());
}

#[test]
fn codec_bucket_sizes_on_the_wire() {
    let cfg = FramingCfg { max_frame: 1500, buckets: vec![64, 256, 1024], random_pad: 0 };
    let mut rng = Rng::new(3);
    for (len, body) in [(1, 64), (62, 64), (63, 256), (254, 256), (255, 1024), (1022, 1024), (1023, 1025)] {
        let mut w = Vec::new();
        encode_record(&cfg, &vec![1u8; len], &mut rng, &mut w).unwrap();
        assert_eq!(w.len(), 2 + body, "frame {len}");
    }
}

// ---------------------------------------------------------------- stream carrier

fn scfg() -> StreamCfg {
    StreamCfg::new(CarrierId::Ws, 1500)
}

const V: &str = "10.9.9.9:7100";

#[tokio::test]
async fn stream_conformance_over_duplex() {
    let (c, h) = tokio::io::duplex(64 * 1024);
    let client = StreamCarrier::client(scfg(), c, sa(V)).unwrap();
    let host = StreamCarrier::new(scfg()).unwrap();
    host.add_conn(h, sa("192.0.2.1:5000")).unwrap();
    let caps = client.caps();
    assert!(!caps.punchable && caps.reliable_stream && client.udp().is_none());
    assert!(host.add_conn(tokio::io::duplex(8).0, sa("192.0.2.1:5000")).is_err(), "duplicate peer key");
    conformance(&client, sa(V), &host).await;
    // unknown peer and empty frame are typed
    let e = client.send_to(b"x", sa("1.2.3.4:5")).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::UnknownPeer));
    let e = client.send_to(b"", sa(V)).await.unwrap_err();
    assert!(matches!(CarrierError::from_io(&e), Some(CarrierError::Failed(_))));
}

#[tokio::test]
async fn stream_clean_eof_is_typed() {
    let (c, mut raw) = tokio::io::duplex(4096);
    let client = StreamCarrier::client(scfg(), c, sa(V)).unwrap();
    let mut w = Vec::new();
    encode_record(&FramingCfg::plain(1500), b"last words", &mut Rng::new(1), &mut w).unwrap();
    raw.write_all(&w).await.unwrap();
    drop(raw);
    assert_eq!(recv(&client).await.0, b"last words", "data before EOF is still delivered");
    let e = recv_err(&client).await;
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::Eof));
    assert!(matches!(client.health(), Health::Down(_)));
    let e = client.send_to(b"x", sa(V)).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::Closed));
    assert_eq!(client.take_closed(), vec![(sa(V), CarrierError::Eof)]);
}

#[tokio::test]
async fn stream_eof_mid_record_is_a_reset() {
    let (c, mut raw) = tokio::io::duplex(4096);
    let client = StreamCarrier::client(scfg(), c, sa(V)).unwrap();
    raw.write_all(&[0, 10, 1, 2, 3]).await.unwrap();
    drop(raw);
    let e = recv_err(&client).await;
    assert!(matches!(CarrierError::from_io(&e), Some(CarrierError::Reset(_))), "{e}");
}

struct ResetIo;
impl AsyncRead for ResetIo {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}
impl AsyncWrite for ResetIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stream_rst_is_typed() {
    let client = StreamCarrier::client(scfg(), ResetIo, sa(V)).unwrap();
    let e = recv_err(&client).await;
    assert!(matches!(CarrierError::from_io(&e), Some(CarrierError::Reset(_))), "{e}");
}

#[tokio::test]
async fn stream_bad_framing_from_peer_closes_with_failed() {
    let (c, mut raw) = tokio::io::duplex(4096);
    let client = StreamCarrier::client(StreamCfg::new(CarrierId::Ws, 100), c, sa(V)).unwrap();
    raw.write_all(&[0xFF, 0xFF]).await.unwrap(); // claims 65535 > 100
    let e = recv_err(&client).await;
    assert!(matches!(CarrierError::from_io(&e), Some(CarrierError::Failed(m)) if m.contains("exceeds")), "{e}");
}

#[tokio::test]
async fn stream_outbound_queue_drops_oldest_and_counts() {
    let (c, mut raw) = tokio::io::duplex(64); // tiny pipe nobody reads yet
    let mut cfg = scfg();
    cfg.out_queue = 4;
    let client = StreamCarrier::client(cfg, c, sa(V)).unwrap();
    for i in 0u32..200 {
        let mut f = i.to_be_bytes().to_vec();
        f.extend([0u8; 16]);
        client.send_to(&f, sa(V)).await.unwrap();
        if i % 20 == 0 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(client.stats().dropped_oldest > 100, "{:?}", client.stats());
    // now read everything: order preserved, the newest frame survived
    let mut dec = FrameDecoder::new(&FramingCfg::plain(1500));
    let mut frames = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), raw.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n], &mut frames).unwrap();
    }
    let ids: Vec<u32> = frames.iter().map(|f| u32::from_be_bytes(f[..4].try_into().unwrap())).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "order kept: {ids:?}");
    assert_eq!(*ids.last().unwrap(), 199, "newest kept");
    assert_eq!(ids.len() as u64 + client.stats().dropped_oldest, 200, "every frame is either sent or counted");
}

#[tokio::test]
async fn stream_inbound_back_pressure_stops_reading_but_loses_nothing() {
    let (c, mut raw) = tokio::io::duplex(256);
    let mut cfg = scfg();
    cfg.in_queue = 8;
    let client = StreamCarrier::client(cfg, c, sa(V)).unwrap();
    let feeder = tokio::spawn(async move {
        let mut w = Vec::new();
        let f = FramingCfg::plain(1500);
        let mut rng = Rng::new(1);
        for i in 0u32..1000 {
            encode_record(&f, &i.to_be_bytes(), &mut rng, &mut w).unwrap();
        }
        raw.write_all(&w).await.unwrap();
        raw
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(client.inbox_len() <= 8, "inbox {}", client.inbox_len());
    assert!(!feeder.is_finished(), "sender must be held back by TCP-style back-pressure");
    for i in 0u32..1000 {
        let (f, _) = recv(&client).await;
        assert_eq!(f, i.to_be_bytes());
    }
    let _raw = feeder.await.unwrap();
}

#[tokio::test]
async fn stream_coalescing_merges_writes() {
    async fn run(coalesce: Duration) -> u64 {
        let (c, mut raw) = tokio::io::duplex(64 * 1024);
        let mut cfg = scfg();
        cfg.coalesce = coalesce;
        let client = StreamCarrier::client(cfg, c, sa(V)).unwrap();
        for i in 0..10u8 {
            client.send_to(&[i; 20], sa(V)).await.unwrap();
            if i == 4 {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
        let mut dec = FrameDecoder::new(&FramingCfg::plain(1500));
        let mut frames = Vec::new();
        let mut buf = [0u8; 1024];
        while frames.len() < 10 {
            let n = tokio::time::timeout(Duration::from_secs(3), raw.read(&mut buf)).await.unwrap().unwrap();
            dec.feed(&buf[..n], &mut frames).unwrap();
        }
        client.stats().writes
    }
    assert_eq!(run(Duration::ZERO).await, 2, "two bursts, two writes");
    assert_eq!(run(Duration::from_millis(80)).await, 1, "one coalesced write");
}

#[tokio::test]
async fn stream_padding_and_jitter_on_the_wire() {
    let (c, mut raw) = tokio::io::duplex(64 * 1024);
    let calls = Arc::new(AtomicU32::new(0));
    let k = calls.clone();
    let mut cfg = scfg();
    cfg.framing = FramingCfg { max_frame: 1500, buckets: vec![64, 256], random_pad: 0 };
    cfg.jitter = Some(Arc::new(move || {
        k.fetch_add(1, Ordering::Relaxed);
        Duration::from_millis(2)
    }));
    let client = StreamCarrier::client(cfg, c, sa(V)).unwrap();
    assert_eq!(client.caps().overhead, 4);
    for (len, wire) in [(10usize, 66usize), (100, 258), (300, 304)] {
        client.send_to(&vec![5u8; len], sa(V)).await.unwrap();
        let mut rec = vec![0u8; wire];
        tokio::time::timeout(Duration::from_secs(3), raw.read_exact(&mut rec)).await.unwrap().unwrap();
        assert_eq!(u16::from_be_bytes([rec[2], rec[3]]) as usize, len);
    }
    assert_eq!(calls.load(Ordering::Relaxed) as u64, client.stats().writes, "one jitter call per write");
    assert_eq!(client.stats().writes, 3);
}

#[tokio::test]
async fn stream_tcp_host_gets_one_peer_per_connection() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let host = StreamCarrier::new(scfg()).unwrap();
    let _srv = host.serve_tcp(l);
    let mut clients = Vec::new();
    for i in 0..3u8 {
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let local = s.local_addr().unwrap();
        let c = StreamCarrier::client(scfg(), s, addr).unwrap();
        c.send_to(&[i; 8], addr).await.unwrap();
        clients.push((c, local));
    }
    let mut seen = Vec::new();
    for _ in 0..3 {
        let (f, peer) = recv(&host).await;
        seen.push((f[0], peer));
    }
    for (i, local) in clients.iter().enumerate().map(|(i, (_, l))| (i as u8, l)) {
        assert!(seen.contains(&(i, *local)), "client {i} keyed by its own address");
    }
    host.send_to(b"to-1", clients[1].1).await.unwrap();
    assert_eq!(recv(&clients[1].0).await.0, b"to-1");
    assert!(would_block(&clients[0].0) && would_block(&clients[2].0));
    // a client going away is reported with its peer key, the others stay up
    let (c0, l0) = clients.remove(0);
    c0.close().await;
    drop(c0);
    for _ in 0..50 {
        if !host.take_closed().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!host.peers().contains(&l0));
    assert_eq!(host.peers().len(), 2);
    assert_eq!(host.health(), Health::Ok);
}

// ---------------------------------------------------------------- loopback + demux

/// A sidecar that funnels every client through ONE outbound source port (the XUDP worst case) and
/// broadcasts every reply to every client flow, because it cannot tell them apart either.
async fn shared_source_sidecar(host: SocketAddr) -> (SocketAddr, SocketAddr) {
    let inbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (in_addr, out_addr) = (inbound.local_addr().unwrap(), outbound.local_addr().unwrap());
    tokio::spawn(async move {
        let mut flows: Vec<SocketAddr> = Vec::new();
        let (mut a, mut b) = ([0u8; 2048], [0u8; 2048]);
        loop {
            tokio::select! {
                Ok((n, c)) = inbound.recv_from(&mut a) => {
                    if !flows.contains(&c) { flows.push(c); }
                    let _ = outbound.send_to(&a[..n], host).await;
                }
                Ok((n, _)) = outbound.recv_from(&mut b) => {
                    for f in &flows { let _ = inbound.send_to(&b[..n], f).await; }
                }
            }
        }
    });
    (in_addr, out_addr)
}

fn lcfg(demux: Demux) -> LoopbackCfg {
    let mut c = LoopbackCfg::new(CarrierId::Xray);
    c.demux = demux;
    c
}

#[tokio::test]
async fn loopback_conformance_both_demux_modes() {
    for demux in [Demux::None, Demux::Header] {
        let host = LoopbackUdp::host(lcfg(demux), sa("127.0.0.1:0")).await.unwrap();
        let client = LoopbackUdp::client(lcfg(demux), host.local_addr().unwrap(), sa(V)).await.unwrap();
        assert!(!client.caps().punchable && client.udp().is_none());
        assert_eq!(client.caps().overhead, if demux == Demux::Header { 4 } else { 0 });
        conformance(&client, sa(V), &host).await;
        // the client refuses to talk to any "host" but the virtual one
        let e = client.send_to(b"x", sa("1.1.1.1:1")).await.unwrap_err();
        assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::UnknownPeer));
    }
}

#[tokio::test]
async fn loopback_shared_source_port_collides_without_demux() {
    let host = LoopbackUdp::host(lcfg(Demux::None), sa("127.0.0.1:0")).await.unwrap();
    let (inb, out) = shared_source_sidecar(host.local_addr().unwrap()).await;
    let mut cs = Vec::new();
    for i in 0..3u8 {
        let c = LoopbackUdp::client(lcfg(Demux::None), inb, sa(V)).await.unwrap();
        c.send_to(&[i], sa(V)).await.unwrap();
        cs.push(c);
    }
    let mut peers = Vec::new();
    for _ in 0..3 {
        peers.push(recv(&host).await.1);
    }
    assert!(peers.iter().all(|p| *p == out), "the documented problem: three clients, one peer key {peers:?}");
}

#[tokio::test]
async fn loopback_header_demux_restores_one_peer_per_address() {
    let host = LoopbackUdp::host(lcfg(Demux::Header), sa("127.0.0.1:0")).await.unwrap();
    let (inb, _out) = shared_source_sidecar(host.local_addr().unwrap()).await;
    let mut cs = Vec::new();
    for i in 0..3u8 {
        let c = LoopbackUdp::client(lcfg(Demux::Header), inb, sa(V)).await.unwrap();
        c.send_to(&[i], sa(V)).await.unwrap();
        cs.push(c);
    }
    let mut by_payload = std::collections::HashMap::new();
    for _ in 0..3 {
        let (f, peer) = recv(&host).await;
        assert!(peer.to_string().starts_with("240."), "synthetic key {peer}");
        by_payload.insert(f[0], peer);
    }
    assert_eq!(by_payload.len(), 3);
    assert_eq!(by_payload.values().collect::<std::collections::HashSet<_>>().len(), 3, "distinct peer keys");
    assert_eq!(host.client_count(), 3);
    // each reply reaches exactly its client although the sidecar broadcasts it to all of them
    for i in 0..3u8 {
        host.send_to(&[100 + i], by_payload[&i]).await.unwrap();
    }
    for (i, c) in cs.iter().enumerate() {
        let (f, from) = recv(c).await;
        assert_eq!(f, vec![100 + i as u8]);
        assert_eq!(from, sa(V));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for c in &cs {
        assert!(would_block(c));
        assert_eq!(c.stats().foreign, 2, "the other two clients' replies were seen and rejected");
    }
    // eviction frees the mapping; an unknown key is a typed error
    host.forget(by_payload[&0]);
    assert_eq!(host.client_count(), 2);
    let e = host.send_to(b"x", by_payload[&0]).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::UnknownPeer));
}

#[tokio::test]
async fn loopback_limits_and_foreign_sources() {
    let mut cfg = lcfg(Demux::Header);
    cfg.max_clients = 2;
    let host = LoopbackUdp::host(cfg, sa("127.0.0.1:0")).await.unwrap();
    for i in 0..3u8 {
        let c = LoopbackUdp::client(lcfg(Demux::Header), host.local_addr().unwrap(), sa(V)).await.unwrap();
        c.send_to(&[i], sa(V)).await.unwrap();
    }
    recv(&host).await;
    recv(&host).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut b = [0u8; 8];
    assert!(host.try_recv_from(&mut b).is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(host.stats().refused_clients, 1);
    assert_eq!(host.client_count(), 2);

    // a local app that is not the sidecar cannot inject into a client
    let sidecar = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c = LoopbackUdp::client(lcfg(Demux::None), sidecar.local_addr().unwrap(), sa(V)).await.unwrap();
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder.send_to(b"evil", c.local_addr().unwrap()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(would_block(&c));
    assert_eq!(c.stats().foreign, 1);
    // guard health flows through
    struct Down;
    impl Guard for Down {
        fn health(&self) -> Health {
            Health::Down("gone".into())
        }
    }
    assert_eq!(c.with_guard(Down).health(), Health::Down("gone".into()));
}

// ---------------------------------------------------------------- in-memory link

async fn drain(io: &dyn FrameIo, wait: Duration) -> Vec<u32> {
    tokio::time::sleep(wait).await;
    let mut out = Vec::new();
    let mut b = [0u8; 64];
    while let Ok((n, _)) = io.try_recv_from(&mut b) {
        assert_eq!(n, 4);
        out.push(u32::from_be_bytes(b[..4].try_into().unwrap()));
    }
    out
}

#[tokio::test]
async fn mem_conformance_and_punchable_flag() {
    let (a, b) = mem::pair(MemCfg { mtu: 1300, punchable: false, ..Default::default() });
    assert!(!a.caps().punchable && a.caps().max_frame == 1300 && a.caps().tun_mtu() == 1265);
    conformance(&a, b.local_addr().unwrap(), &b).await;
    assert!(a.udp().is_none());
}

#[tokio::test]
async fn mem_loss_dup_reorder_are_deterministic() {
    async fn run(seed: u64) -> (Vec<u32>, mem::MemStats) {
        let (a, b) = mem::pair(MemCfg { seed, loss: 0.2, dup: 0.2, reorder: 0.3, ..Default::default() });
        for i in 0..300u32 {
            a.send_to(&i.to_be_bytes(), a.peer_addr()).await.unwrap();
        }
        (drain(&b, Duration::from_millis(100)).await, a.stats())
    }
    let (r1, s1) = run(42).await;
    let (r2, s2) = run(42).await;
    assert_eq!(r1, r2, "same seed, same outcome");
    assert_eq!(s1, s2);
    assert!(s1.lost > 20 && s1.lost < 120, "{s1:?}");
    assert!(s1.duplicated > 10 && s1.reordered > 20, "{s1:?}");
    assert!(!r1.windows(2).all(|w| w[0] <= w[1]), "reordering visible");
    assert_eq!(r1.len() as u64, 300 - s1.lost + s1.duplicated, "accounting {s1:?}");
    let (r3, _) = run(43).await;
    assert_ne!(r1, r3, "different seed, different outcome");
}

#[tokio::test]
async fn mem_latency_and_kill() {
    let (a, b) = mem::pair(MemCfg { latency: Duration::from_millis(60), ..Default::default() });
    let t = Instant::now();
    a.send_to(b"late", a.peer_addr()).await.unwrap();
    assert!(would_block(&b));
    b.readable().await.unwrap();
    assert!(t.elapsed() >= Duration::from_millis(55), "{:?}", t.elapsed());
    assert_eq!(recv(&b).await.0, b"late");
    assert_eq!(a.health(), Health::Ok);
    a.kill();
    assert!(matches!(b.health(), Health::Down(_)));
    let e = a.send_to(b"x", a.peer_addr()).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::Closed));
    let e = recv_err(&b).await;
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::Closed));
}

// ---------------------------------------------------------------- ladder

fn v(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn ladder_order_filters_and_stagger() {
    let invite = v(&["xray@h.example:443;m=so", "ws@h.example:443", "udp", "ss@1.2.3.4:8388", "udp", "future9"]);
    let built = [CarrierId::Udp, CarrierId::Ws, CarrierId::Ss];
    let mut inp = LadderInput::new(&invite, &built);
    let disabled = v(&["ss"]);
    inp.disabled = &disabled;
    inp.host_reachable = true;
    let p = plan(&inp);
    let ids: Vec<_> = p.attempts.iter().map(|a| a.id).collect();
    assert_eq!(ids, vec![CarrierId::Ws, CarrierId::Udp]);
    assert_eq!(p.attempts[0].entry, "ws@h.example:443");
    assert_eq!(p.attempts[0].delay, Duration::ZERO);
    assert_eq!(p.attempts[1].delay, Duration::from_millis(300));
    assert_eq!(
        p.skipped,
        vec![
            ("xray".to_string(), Reason::NotBuilt),
            ("ss".to_string(), Reason::DisabledLocally),
            ("future9".to_string(), Reason::UnknownId),
        ]
    );
    assert_eq!(entry_id("ws@h:1;p=/x"), "ws");
}

#[test]
fn ladder_old_invite_means_udp_only() {
    let built = [CarrierId::Udp];
    let p = plan(&LadderInput::new(&[], &built));
    assert_eq!(p.attempts.len(), 1);
    assert_eq!(p.attempts[0].id, CarrierId::Udp);
}

#[test]
fn ladder_explicit_failure_summary() {
    let invite = v(&["udp", "ws", "xray"]);
    let built = [CarrierId::Udp, CarrierId::Ws];
    let probes = [(CarrierId::Ws, ProbeStatus::Blocked(String::new()))];
    let mut inp = LadderInput::new(&invite, &built);
    inp.host_reachable = true;
    inp.probes = &probes;
    let mut l = Ladder::new(plan(&inp));
    assert_eq!(l.pending().len(), 1);
    assert!(l.error().is_none() && l.summary().is_empty());
    l.fail(CarrierId::Udp, Reason::NoPunch);
    assert_eq!(l.summary(), "udp: no punch; ws: blocked; xray: not supported by this build");
    let err = l.error().unwrap();
    let io: io::Error = err.clone().into();
    assert_eq!(LadderError::from_io(&io), Some(&err));
}

#[test]
fn ladder_needs_reachable_host_and_no_punch() {
    let invite = v(&["udp", "xray", "awg", "ws"]);
    let built = [CarrierId::Udp, CarrierId::Xray, CarrierId::Awg, CarrierId::Ws];
    let mut inp = LadderInput::new(&invite, &built);
    // host behind NAT, punching works: xray cannot be used, ws without an address punches over TCP
    let p = plan(&inp);
    assert_eq!(p.attempts.iter().map(|a| a.id).collect::<Vec<_>>(), vec![CarrierId::Udp, CarrierId::Awg, CarrierId::Ws]);
    assert_eq!(p.skipped, vec![("xray".to_string(), Reason::NeedsReachableHost)]);
    // a ws entry with an address that nothing else makes reachable is still a plain dial target
    let with_addr = v(&["ws@198.51.100.7:8443"]);
    let mut dial = LadderInput::new(&with_addr, &built);
    dial.host_reachable = true;
    assert_eq!(plan(&dial).attempts.len(), 1);
    // ...and punching is known impossible: nothing is left, and the message says why
    inp.punch_ok = false;
    let l = Ladder::new(plan(&inp));
    assert_eq!(l.summary(), "udp: no punch; xray: needs a reachable host; awg: no punch; ws: no punch");
}

#[test]
fn ladder_keeps_ss_awg_without_an_address_when_only_rendezvous_finds_the_host() {
    // They ride the host's plain UDP socket (the one rendezvous publishes), so they are attempted;
    // an older host just stays silent and the attempt times out like any other.
    let invite = v(&["udp", "awg", "ss@203.0.113.9:8388"]);
    let built = [CarrierId::Udp, CarrierId::Awg, CarrierId::Ss];
    let mut inp = LadderInput::new(&invite, &built);
    inp.rendezvous_only = true;
    let p = plan(&inp);
    assert_eq!(p.attempts.iter().map(|a| a.id).collect::<Vec<_>>(), vec![CarrierId::Udp, CarrierId::Awg, CarrierId::Ss]);
    assert!(p.skipped.is_empty());
}

#[test]
fn ladder_probe_errors_demoted_last_working_first_winner_stops() {
    let invite = v(&["udp", "ss", "ws"]);
    let built = [CarrierId::Udp, CarrierId::Ss, CarrierId::Ws];
    let probes = [(CarrierId::Udp, ProbeStatus::Error("dns".into())), (CarrierId::Ws, ProbeStatus::Reachable { rtt_ms: 5 })];
    let mut inp = LadderInput::new(&invite, &built);
    inp.host_reachable = true;
    inp.probes = &probes;
    let order = |inp: &LadderInput| plan(inp).attempts.iter().map(|a| a.id).collect::<Vec<_>>();
    assert_eq!(order(&inp), vec![CarrierId::Ss, CarrierId::Ws, CarrierId::Udp]);
    inp.last_working = Some(CarrierId::Udp);
    assert_eq!(order(&inp), vec![CarrierId::Udp, CarrierId::Ss, CarrierId::Ws]);
    let mut l = Ladder::new(plan(&inp));
    l.fail(CarrierId::Udp, Reason::Timeout);
    l.succeed(CarrierId::Ss);
    assert!(l.pending().is_empty() && l.error().is_none());
    assert_eq!(l.winner(), Some(CarrierId::Ss));
}

// ---------------------------------------------------------------- supervisor vs fake sidecar

/// When the test binary is re-executed with STRAIT_FAKE_SIDECAR set, this "test" is the sidecar.
#[test]
fn fake_sidecar_entry() {
    let Ok(mode) = std::env::var("STRAIT_FAKE_SIDECAR") else { return };
    let num = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let ms = |k: &str, d: u64| Duration::from_millis(num(k, d));
    println!(); // libtest has already printed "test <name> ... " without a newline
    let say = |s: &str| {
        use std::io::Write;
        println!("{s}");
        let _ = io::stdout().flush();
    };
    let sleep_forever = || loop {
        std::thread::sleep(Duration::from_secs(1));
    };
    let echo = |hang_after: Option<Duration>| {
        let s = std::net::UdpSocket::bind(format!("127.0.0.1:{}", num("FAKE_PORT", 0))).unwrap();
        say(&format!("READY port={}", s.local_addr().unwrap().port()));
        let t0 = Instant::now();
        let mut b = [0u8; 2048];
        loop {
            let (n, from) = s.recv_from(&mut b).unwrap();
            if hang_after.is_some_and(|h| t0.elapsed() > h) {
                sleep_forever();
            }
            let _ = s.send_to(&b[..n], from);
        }
    };
    match mode.as_str() {
        "echo" => echo(None),
        "slow" => {
            std::thread::sleep(ms("FAKE_DELAY_MS", 500));
            echo(None)
        }
        "never_ready" => sleep_forever(),
        "hang" => echo(Some(ms("FAKE_HANG_AFTER_MS", 400))),
        "always_crash" => {
            say("CRASHING secret=abc123");
            std::thread::sleep(ms("FAKE_DELAY_MS", 0));
            std::process::exit(9)
        }
        "crash_runs" => {
            let path = std::env::var("FAKE_STATE").unwrap();
            let runs = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0) + 1;
            std::fs::write(&path, runs.to_string()).unwrap();
            if runs <= num("FAKE_CRASH_RUNS", 2) {
                say(&format!("crashing on run {runs}"));
                std::process::exit(7);
            }
            echo(None)
        }
        "ignore_term" => {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            echo(None)
        }
        "args" => {
            for a in std::env::args() {
                say(&format!("ARG:{a}"));
            }
            say("READY");
            sleep_forever()
        }
        "env" => {
            for (k, _) in std::env::vars() {
                say(&format!("ENV:{k}"));
            }
            say("READY");
            sleep_forever()
        }
        "spam" => {
            for i in 0..1000 {
                say(&format!("line {i} secret=abc123"));
            }
            say("READY");
            sleep_forever()
        }
        other => panic!("unknown fake mode {other}"),
    }
    std::process::exit(0);
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn fake(mode: &str, env: &[(&str, &str)]) -> SidecarConfig {
    let exe: PathBuf = std::env::current_exe().unwrap();
    let mut c = SidecarConfig::new(exe);
    c.args = ["--exact", "fake_sidecar_entry", "--nocapture", "--test-threads=1"].iter().map(Into::into).collect();
    c.env = vec![("STRAIT_FAKE_SIDECAR".into(), mode.into())];
    c.env.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    c.restart = RestartPolicy {
        max_restarts: 3,
        backoff_initial: Duration::from_millis(30),
        backoff_max: Duration::from_millis(200),
        reset_after: Duration::from_secs(60),
    };
    c.stop_grace = Duration::from_secs(3);
    c.start_timeout = Duration::from_secs(10);
    c
}

fn udp_health(port: u16) -> HealthCheck {
    HealthCheck::Udp { addr: sa(&format!("127.0.0.1:{port}")), probe: b"ping".to_vec(), expect: b"ping".to_vec() }
}

async fn echo_ok(port: u16) -> bool {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(b"echo?", format!("127.0.0.1:{port}")).await.unwrap();
    let mut b = [0u8; 16];
    matches!(tokio::time::timeout(Duration::from_secs(2), s.recv_from(&mut b)).await, Ok(Ok((5, _))) if &b[..5] == b"echo?")
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_refuses_relative_and_missing_programs() {
    let e = Supervisor::start(SidecarConfig::new("xray")).await.err().unwrap();
    assert_eq!(e, SidecarError::RelativeProgram("xray".into()));
    let e = Supervisor::start(SidecarConfig::new("./bin/xray")).await.err().unwrap();
    assert!(matches!(e, SidecarError::RelativeProgram(_)));
    let e = Supervisor::start(SidecarConfig::new("/definitely/not/here")).await.err().unwrap();
    assert_eq!(e, SidecarError::Missing("/definitely/not/here".into()));
    assert_eq!(e.to_reason(), Reason::SidecarMissing);
    let mut c = SidecarConfig::new("no-such-binary-xyz");
    c.allow_relative = true;
    assert!(matches!(Supervisor::start(c).await.err().unwrap(), SidecarError::Missing(_)), "bare name: NotFound at spawn");
    // a directory is not a program
    let e = Supervisor::start(SidecarConfig::new(std::env::temp_dir())).await.err().unwrap();
    assert!(matches!(e, SidecarError::Missing(_)));
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_starts_serves_and_stops_gracefully() {
    let port = free_udp_port();
    let mut c = fake("echo", &[("FAKE_PORT", &port.to_string())]);
    c.health = udp_health(port);
    let sup = Supervisor::start(c).await.unwrap();
    assert!(matches!(sup.state(), SidecarState::Ready { restarts: 0, .. }));
    assert_eq!(sup.spawns(), 1);
    assert!(echo_ok(port).await);
    assert_eq!(sup.health(), Health::Ok);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(sup.logs().iter().any(|l| l.starts_with("out: READY port=")), "{:?}", sup.logs());
    let mut w = sup.watch();
    assert!(sup.stop().await, "exited on SIGTERM within the grace");
    assert_eq!(*w.borrow_and_update(), SidecarState::Stopped);
    assert!(!echo_ok(port).await, "process is gone");
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_slow_start_and_start_timeout() {
    let port = free_udp_port();
    let mut c = fake("slow", &[("FAKE_PORT", &port.to_string()), ("FAKE_DELAY_MS", "800")]);
    c.health = udp_health(port);
    let t = Instant::now();
    let sup = Supervisor::start(c).await.unwrap();
    assert!(t.elapsed() >= Duration::from_millis(700), "{:?}", t.elapsed());
    sup.stop().await;

    let port = free_udp_port();
    let mut c = fake("slow", &[("FAKE_PORT", &port.to_string()), ("FAKE_DELAY_MS", "5000")]);
    c.health = udp_health(port);
    c.start_timeout = Duration::from_millis(300);
    c.restart.max_restarts = 1;
    let e = Supervisor::start(c).await.err().unwrap();
    let SidecarError::GaveUp(exit) = &e else { panic!("{e:?}") };
    assert_eq!(exit.cause, ExitCause::StartTimeout);
    assert_eq!(e.to_reason(), Reason::Timeout);
}

#[tokio::test]
async fn sup_never_ready_on_stdout_gives_up() {
    let mut c = fake("never_ready", &[]);
    c.health = HealthCheck::StdoutLine("READY".into());
    c.start_timeout = Duration::from_millis(300);
    c.restart.max_restarts = 0;
    let e = Supervisor::start(c).await.err().unwrap();
    assert!(matches!(e, SidecarError::GaveUp(Exit { cause: ExitCause::StartTimeout, .. })));
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_restarts_after_crashes_then_serves() {
    let port = free_udp_port();
    let state = std::env::temp_dir().join(format!("strait-fake-{}-{port}", std::process::id()));
    let _ = std::fs::remove_file(&state);
    let mut c = fake(
        "crash_runs",
        &[("FAKE_PORT", &port.to_string()), ("FAKE_STATE", state.to_str().unwrap()), ("FAKE_CRASH_RUNS", "2")],
    );
    c.health = udp_health(port);
    let sup = Supervisor::start(c).await.unwrap();
    assert_eq!(sup.spawns(), 3, "two crashes, third run healthy");
    assert!(matches!(sup.state(), SidecarState::Ready { restarts: 2, .. }), "{:?}", sup.state());
    assert!(echo_ok(port).await);
    assert!(sup.logs().iter().any(|l| l.contains("crashing on run 2")));
    sup.stop().await;
    let _ = std::fs::remove_file(&state);
}

#[tokio::test]
async fn sup_gives_up_after_max_restarts_with_exit_code() {
    let mut c = fake("always_crash", &[]);
    c.health = HealthCheck::StdoutLine("READY".into());
    c.restart.max_restarts = 2;
    let t = Instant::now();
    let e = Supervisor::start(c).await.err().unwrap();
    let SidecarError::GaveUp(exit) = &e else { panic!("{e:?}") };
    assert_eq!((exit.code, exit.cause), (Some(9), ExitCause::Exited));
    assert_eq!(e.to_reason(), Reason::SidecarExited(Some(9)));
    // backoff 30 ms then 60 ms happened between the three runs
    assert!(t.elapsed() >= Duration::from_millis(90), "{:?}", t.elapsed());
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_detects_a_hang_and_restarts() {
    let port = free_udp_port();
    let mut c = fake("hang", &[("FAKE_PORT", &port.to_string()), ("FAKE_HANG_AFTER_MS", "1500")]);
    c.health = udp_health(port);
    c.monitor_interval = Some(Duration::from_millis(100));
    c.monitor_failures = 2;
    let sup = Supervisor::start(c).await.unwrap();
    let mut w = sup.watch();
    let saw_hung = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let SidecarState::Backoff { last, .. } = w.borrow_and_update().clone() {
                return last;
            }
            w.changed().await.unwrap();
        }
    })
    .await
    .expect("hang must be detected");
    assert_eq!(saw_hung.cause, ExitCause::Hung);
    // and it comes back
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if matches!(*w.borrow_and_update(), SidecarState::Ready { restarts: 1, .. }) {
                return;
            }
            w.changed().await.unwrap();
        }
    })
    .await
    .expect("restarted after hang");
    assert!(sup.spawns() >= 2);
    sup.stop().await;
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_stop_escalates_to_kill_when_sigterm_is_ignored() {
    let port = free_udp_port();
    let mut c = fake("ignore_term", &[("FAKE_PORT", &port.to_string())]);
    c.health = udp_health(port);
    c.stop_grace = Duration::from_millis(400);
    let sup = Supervisor::start(c).await.unwrap();
    let t = Instant::now();
    assert!(!sup.stop().await, "had to be killed");
    assert!(t.elapsed() >= Duration::from_millis(400), "{:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(!echo_ok(port).await);
}

#[tokio::test]
async fn sup_args_are_literal_and_env_is_not_inherited() {
    let nasty = "$(echo pwned);`touch /tmp/strait-pwned` && x | y > z 'q' \"r\"";
    let mut c = fake("args", &[]);
    c.args.push(nasty.into());
    c.health = HealthCheck::StdoutLine("READY".into());
    let sup = Supervisor::start(c).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(sup.logs().iter().any(|l| l == &format!("out: ARG:{nasty}")), "{:?}", sup.logs());
    assert!(!std::path::Path::new("/tmp/strait-pwned").exists());
    sup.stop().await;

    std::env::set_var("STRAIT_TEST_SECRET", "hunter2");
    let mut c = fake("env", &[("LISTED_VAR", "1")]);
    c.health = HealthCheck::StdoutLine("READY".into());
    let sup = Supervisor::start(c).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let logs = sup.logs();
    assert!(logs.iter().any(|l| l == "out: ENV:LISTED_VAR"));
    for k in ["STRAIT_TEST_SECRET", "HOME", "PATH", "USER"] {
        assert!(!logs.iter().any(|l| l == &format!("out: ENV:{k}")), "{k} leaked into the sidecar");
    }
    sup.stop().await;
}

#[tokio::test]
async fn sup_log_ring_is_bounded_and_redacts() {
    let mut c = fake("spam", &[]);
    c.health = HealthCheck::StdoutLine("READY".into());
    c.log_lines = 50;
    c.redact = vec!["abc123".into()];
    let sup = Supervisor::start(c).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let logs = sup.logs();
    assert_eq!(logs.len(), 50);
    assert!(logs.iter().all(|l| !l.contains("abc123")));
    assert!(logs.iter().any(|l| l.contains("line 999 secret=***")), "{:?}", &logs[logs.len() - 3..]);
    sup.stop().await;
}

// libc::kill(pid, 0) existence probe: unix only.
#[cfg(unix)]
#[tokio::test]
async fn sup_drop_kills_the_child() {
    let port = free_udp_port();
    let mut c = fake("echo", &[("FAKE_PORT", &port.to_string())]);
    c.health = udp_health(port);
    let sup = Supervisor::start(c).await.unwrap();
    let SidecarState::Ready { pid, .. } = sup.state() else { panic!() };
    drop(sup);
    let gone = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // SAFETY: signal 0 only probes for existence.
            if unsafe { libc::kill(pid as i32, 0) } != 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "child {pid} still alive after the supervisor was dropped");
}

#[cfg(unix)] // sidecar supervisor fakes use POSIX paths/signals; exit 101 on Windows (carriers are experimental)
#[tokio::test]
async fn sup_as_guard_for_loopback() {
    let port = free_udp_port();
    let mut c = fake("echo", &[("FAKE_PORT", &port.to_string())]);
    c.health = udp_health(port);
    let sup = Supervisor::start(c).await.unwrap();
    // the fake sidecar IS a UDP echo: a LoopbackUdp client pointed at it round-trips frames
    let lb = LoopbackUdp::client(LoopbackCfg::new(CarrierId::Xray), sa(&format!("127.0.0.1:{port}")), sa(V))
        .await
        .unwrap()
        .with_guard(sup);
    lb.send_to(b"through the sidecar", sa(V)).await.unwrap();
    assert_eq!(recv(&lb).await, (b"through the sidecar".to_vec(), sa(V)));
    assert_eq!(lb.health(), Health::Ok);
}

#[test]
fn keyless_verdicts_are_honest() {
    use nat_tunnel::carrier::{keyless_verdict, Verdict};
    use nat_tunnel::rendezvous::ProbeStatus as P;
    let u = |id| keyless_verdict(id, &P::Reachable { rtt_ms: 0 });
    for id in [CarrierId::Udp, CarrierId::Ss, CarrierId::Awg] {
        assert!(matches!(u(id), Verdict::Unverifiable(_)), "{id}");
    }
    assert_eq!(keyless_verdict(CarrierId::Xray, &P::Reachable { rtt_ms: 7 }), Verdict::Reachable { rtt_ms: 7 });
    let cert = P::Blocked("tls: invalid peer certificate: ApplicationVerificationFailure".into());
    assert!(matches!(keyless_verdict(CarrierId::Ws, &cert), Verdict::Unverifiable(_)));
    assert!(matches!(keyless_verdict(CarrierId::Ws, &P::Blocked("connect: Connection refused".into())), Verdict::Blocked(_)));
    assert!(matches!(keyless_verdict(CarrierId::Ss, &P::Error("ss: no endpoint".into())), Verdict::Unverifiable(_)));
    assert!(keyless_verdict(CarrierId::Awg, &P::Reachable { rtt_ms: 0 }).to_string().starts_with("unverifiable: "));
}
