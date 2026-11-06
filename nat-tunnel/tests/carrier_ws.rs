//! `ws` carrier tests: real loopback sockets only (ws:// and wss:// with the key-derived pinned cert).
#![cfg(feature = "cr-ws")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nat_tunnel::carrier::ws::*;
use nat_tunnel::carrier::*;
use nat_tunnel::rendezvous::ProbeStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const KEY: &str = "test-invite-key-1";

fn spec(endpoint: Option<String>, tls: bool, extra: &[(&str, &str)]) -> CarrierSpec {
    let mut params = vec![("key".to_string(), KEY.to_string()), ("tls".to_string(), if tls { "pin" } else { "off" }.to_string())];
    params.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    CarrierSpec { endpoint, bind_port: None, params }
}

async fn host(tls: bool, extra: &[(&str, &str)]) -> (WsCarrier, SocketAddr) {
    let h = listen_ws(&spec(Some("127.0.0.1:0".into()), tls, extra)).await.expect("listen");
    let a = h.local_addr().unwrap();
    (h, a)
}

async fn client(addr: SocketAddr, tls: bool, extra: &[(&str, &str)]) -> Result<WsCarrier, CarrierError> {
    dial_ws(&spec(Some(addr.to_string()), tls, extra)).await
}

async fn recv(io: &dyn FrameIo) -> std::io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 4096];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            io.readable().await?;
            match io.try_recv_from(&mut buf) {
                Ok((n, a)) => return Ok((buf[..n].to_vec(), a)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .expect("recv timed out")
}

async fn wait_for<F: Fn() -> bool>(f: F) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5), "condition not reached");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---- raw WebSocket helpers (client side, zero mask key so payload bytes are unchanged)

fn wsframe(fin: bool, op: u8, p: &[u8]) -> Vec<u8> {
    let mut f = vec![((fin as u8) << 7) | op];
    match p.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(p);
    f
}

fn upgrade_req(path: &str, token: Option<&str>) -> String {
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{auth}\r\n")
}

async fn raw_exchange(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
    out
}

/// Upgrade by hand; returns the stream after the 101 head.
async fn raw_ws(addr: SocketAddr) -> TcpStream {
    let id = identity_for_key(KEY);
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(upgrade_req(&id.path, Some(&id.token)).as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).await.unwrap(), 1);
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    s
}

fn rec(frame: &[u8]) -> Vec<u8> {
    let mut v = (frame.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(frame);
    v
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn frames_both_ways_ws_and_wss() {
    for tls in [false, true] {
        let (h, addr) = host(tls, &[]).await;
        let c = client(addr, tls, &[]).await.expect("dial");
        let hostkey: SocketAddr = addr;
        assert_eq!(c.send_to(b"hello host", hostkey).await.unwrap(), 10);
        c.send_to(&vec![7u8; 1400], hostkey).await.unwrap();
        let (f, peer) = recv(&h).await.unwrap();
        assert_eq!(f, b"hello host");
        assert_eq!(recv(&h).await.unwrap().0, vec![7u8; 1400]);
        assert_eq!(peer, c.local_addr().unwrap(), "host peer key = client TCP address");
        h.send_to(b"hello client", peer).await.unwrap();
        let (f, from) = recv(&c).await.unwrap();
        assert_eq!((f.as_slice(), from), (&b"hello client"[..], hostkey));
        assert_eq!(c.send_to(b"x", "127.0.0.1:1".parse().unwrap()).await.unwrap_err().kind(), std::io::ErrorKind::NotConnected);
    }
}

#[tokio::test]
async fn padded_framing_over_ws() {
    let ex = [("buckets", "256,512,1024,1500")];
    let (h, addr) = host(false, &ex).await;
    let c = client(addr, false, &ex).await.unwrap();
    for n in [1usize, 100, 300, 1400] {
        c.send_to(&vec![n as u8; n], addr).await.unwrap();
        assert_eq!(recv(&h).await.unwrap().0.len(), n);
    }
}

#[tokio::test]
async fn caps_warning_and_disclosure() {
    let (h, addr) = host(true, &[("max_frame", "1335")]).await;
    let c = client(addr, true, &[("max_frame", "1335")]).await.unwrap();
    for caps in [h.caps(), c.caps()] {
        assert_eq!(caps.id, CarrierId::Ws);
        assert!(!caps.punchable && caps.reliable_stream);
        assert!(caps.overhead > 2, "ws + tls overhead is counted: {}", caps.overhead);
        assert_eq!(caps.tun_mtu(), RECOMMENDED_TUN_MTU);
        assert!(tcp_over_tcp_warning(&caps).unwrap().contains("TCP-over-TCP"));
    }
    let f = by_ids(&["ws".to_string()]);
    assert_eq!(f.len(), 1);
    let d = f[0].disclosure();
    assert!(d.shared[0].contains("looks like a website using WebSocket"));
    assert_eq!(d.not_shared, &["the tunnel payload", "keys"]);
    assert_eq!(d.why, "carry the tunnel over the web port when UDP is blocked");
    assert!(d.operator.starts_with("none: connects only to the host itself"));
}

#[tokio::test]
async fn identity_is_a_pure_function_of_the_key() {
    let (a, b, c) = (identity_for_key(KEY), identity_for_key(KEY), identity_for_key("other"));
    assert_eq!(a.cert().unwrap().0, b.cert().unwrap().0);
    assert_eq!((a.path.clone(), a.token.clone(), a.pin_hex()), (b.path.clone(), b.token.clone(), b.pin_hex()));
    assert_ne!(a.pin_hex(), c.pin_hex());
    assert_ne!(a.token, c.token);
    assert_eq!(a.pin_hex().len(), 64);
}

#[tokio::test]
async fn wrong_key_wrong_pin_is_blocked_and_delivers_nothing() {
    let (h, addr) = host(true, &[]).await;
    let bad = CarrierSpec { endpoint: Some(addr.to_string()), bind_port: None, params: vec![("key".into(), "not-the-key".into())] };
    match dial_ws(&bad).await {
        Err(CarrierError::Blocked(m)) => assert!(m.starts_with("tls"), "{m}"),
        r => panic!("expected Blocked(tls), got {:?}", r.err()),
    }
    // CA mode against our self-signed cert must fail too (no CA dependency, no silent trust).
    match client(addr, true, &[("tls", "ca")]).await {
        Err(CarrierError::Blocked(_)) => {}
        r => panic!("expected Blocked, got {:?}", r.err()),
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h.peers().is_empty());
    assert_eq!(h.stats().frames_in, 0);
}

#[tokio::test]
async fn wrong_token_or_path_gets_decoy_and_no_frames() {
    for tls in [false, true] {
        let (h, addr) = host(tls, &[]).await;
        for ex in [[("token", "deadbeef")], [("path", "/nope")]] {
            match client(addr, tls, &ex).await {
                Err(CarrierError::Blocked(m)) => assert!(m.contains("404"), "{m}"),
                r => panic!("expected Blocked 404, got {:?}", r.err()),
            }
        }
        assert!(h.peers().is_empty());
        assert_eq!(h.stats().frames_in, 0);
    }
}

#[tokio::test]
async fn decoy_is_a_plain_identical_404_for_every_failure() {
    let (h, addr) = host(false, &[]).await;
    let id = identity_for_key(KEY);
    let reqs: Vec<Vec<u8>> = vec![
        b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n".to_vec(),
        upgrade_req(&id.path, None).into_bytes(),
        upgrade_req(&id.path, Some("wrong")).into_bytes(),
        upgrade_req("/other", Some(&id.token)).into_bytes(),
        upgrade_req(&id.path, Some(&id.token)).replace("GET", "POST").into_bytes(),
        upgrade_req(&id.path, Some(&id.token)).replace("Upgrade: websocket\r\n", "").into_bytes(),
        upgrade_req(&id.path, Some(&id.token)).replace("Version: 13", "Version: 8").into_bytes(),
        b"\x16\x03\x01garbage\r\n\r\n".to_vec(),
        format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(9000)).into_bytes(),
    ];
    let want = decoy_response();
    for r in &reqs {
        assert_eq!(raw_exchange(addr, r).await, want, "request {:?}", String::from_utf8_lossy(&r[..r.len().min(40)]));
    }
    let text = String::from_utf8(want).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 404 Not Found"));
    let mut names: Vec<String> = head.lines().skip(1).map(|l| l.split(':').next().unwrap().to_ascii_lowercase()).collect();
    names.sort();
    assert_eq!(names, ["connection", "content-length", "content-type"], "no Server/Date/Set-Cookie to fingerprint");
    assert!(body.contains("404 Not Found") && !body.to_lowercase().contains("strait") && !body.to_lowercase().contains("websocket"));
    assert!(h.peers().is_empty());
    assert_eq!(h.stats().frames_in, 0);
}

#[tokio::test]
async fn two_clients_get_distinct_peers_and_replies_are_routed() {
    let (h, addr) = host(true, &[]).await;
    let (c1, c2) = (client(addr, true, &[]).await.unwrap(), client(addr, true, &[]).await.unwrap());
    c1.send_to(b"from-1", addr).await.unwrap();
    c2.send_to(b"from-2", addr).await.unwrap();
    let (mut got, mut peers) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        let (f, p) = recv(&h).await.unwrap();
        got.push(f);
        peers.push(p);
    }
    assert_ne!(peers[0], peers[1]);
    for (f, p) in got.iter().zip(&peers) {
        h.send_to(&[b"to-", &f[5..]].concat(), *p).await.unwrap();
    }
    assert_eq!(recv(&c1).await.unwrap().0, b"to-1");
    assert_eq!(recv(&c2).await.unwrap().0, b"to-2");
    assert_eq!(h.peers().len(), 2);
}

#[tokio::test]
async fn oversize_frame_is_frame_too_large() {
    let (h, addr) = host(false, &[("max_frame", "1000")]).await;
    let c = client(addr, false, &[("max_frame", "1000")]).await.unwrap();
    let e = c.send_to(&vec![0u8; 1001], addr).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::FrameTooLarge { max: 1000 }));
    c.send_to(&vec![1u8; 1000], addr).await.unwrap();
    assert_eq!(recv(&h).await.unwrap().0.len(), 1000);
    // And a peer that sends a longer record than allowed is cut off, not delivered.
    let mut r = raw_ws(addr).await;
    r.write_all(&wsframe(true, 2, &rec(&vec![2u8; 1001]))).await.unwrap();
    wait_for(|| h.peers().len() == 1).await; // raw peer gone again, only `c` left
}

#[tokio::test]
async fn fragmented_websocket_messages_reassemble() {
    let (h, addr) = host(false, &[]).await;
    let mut s = raw_ws(addr).await;
    let r1 = rec(b"first frame");
    let r2 = rec(&vec![9u8; 700]);
    // r1 split in three WS fragments with a ping in between (legal per RFC 6455).
    s.write_all(&wsframe(false, 2, &r1[..3])).await.unwrap();
    s.write_all(&wsframe(true, 9, b"p")).await.unwrap();
    s.write_all(&wsframe(false, 0, &r1[3..8])).await.unwrap();
    s.write_all(&wsframe(true, 0, &r1[8..])).await.unwrap();
    // r2 as one-byte messages for the first bytes (record header split across messages), then the rest.
    for b in &r2[..5] {
        s.write_all(&wsframe(true, 2, &[*b])).await.unwrap();
    }
    s.write_all(&wsframe(true, 2, &r2[5..])).await.unwrap();
    // Two records in one message.
    s.write_all(&wsframe(true, 2, &[rec(b"a"), rec(b"bb")].concat())).await.unwrap();
    assert_eq!(recv(&h).await.unwrap().0, b"first frame");
    assert_eq!(recv(&h).await.unwrap().0, vec![9u8; 700]);
    assert_eq!(recv(&h).await.unwrap().0, b"a");
    assert_eq!(recv(&h).await.unwrap().0, b"bb");
    // The server answered the ping with a pong (flushed on our kick).
    let mut b = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut b)).await.expect("pong").unwrap();
    assert_eq!(b, [0x8a, 1]);
}

#[tokio::test]
async fn idle_timeout_closes_a_silent_peer_with_a_typed_reason() {
    let (h, addr) = host(false, &[("idle_ms", "300"), ("ping_ms", "100000")]).await;
    let _s = raw_ws(addr).await; // connects, then says nothing
    wait_for(|| h.peers().len() == 1).await;
    wait_for(|| h.peers().is_empty()).await;
    let closed = h.take_closed();
    assert_eq!(closed.len(), 1);
    assert!(matches!(&closed[0].1, CarrierError::Failed(m) if m.contains("idle timeout")), "{:?}", closed[0].1);
}

#[tokio::test]
async fn keepalive_pings_hold_an_idle_connection_open() {
    let ex = [("idle_ms", "700"), ("ping_ms", "150")];
    let (h, addr) = host(true, &ex).await;
    let c = client(addr, true, &ex).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1800)).await; // > 2 idle periods with no data
    assert_eq!(c.health(), Health::Ok);
    assert_eq!(h.peers().len(), 1);
    c.send_to(b"still here", addr).await.unwrap();
    assert_eq!(recv(&h).await.unwrap().0, b"still here");
}

#[tokio::test]
async fn server_restart_gives_typed_error_and_a_new_dial_works() {
    let (h, addr) = host(true, &[]).await;
    let c = client(addr, true, &[]).await.unwrap();
    c.send_to(b"hi", addr).await.unwrap();
    recv(&h).await.unwrap();
    h.close().await;
    drop(h);
    let e = recv(&c).await.unwrap_err();
    assert!(
        matches!(CarrierError::from_io(&e), Some(CarrierError::Reset(_)) | Some(CarrierError::Eof)),
        "typed reset/eof expected, got {e}"
    );
    assert!(matches!(c.health(), Health::Down(_)));
    let e = c.send_to(b"x", addr).await.unwrap_err();
    assert_eq!(CarrierError::from_io(&e), Some(&CarrierError::Closed));
    // "Restart": bind the same port again; the transport redials.
    let t = Instant::now();
    let h2 = loop {
        match listen_ws(&spec(Some(addr.to_string()), true, &[])).await {
            Ok(h) => break h,
            Err(e) => {
                assert!(t.elapsed() < Duration::from_secs(5), "rebind: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let c2 = client(addr, true, &[]).await.unwrap();
    c2.send_to(b"back", addr).await.unwrap();
    assert_eq!(recv(&h2).await.unwrap().0, b"back");
    // Nothing listening any more: connect errors are Blocked.
    h2.close().await;
    drop(h2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(client(addr, true, &[]).await, Err(CarrierError::Blocked(_))));
}

#[tokio::test]
async fn slow_reader_never_blocks_the_sender_and_recovers() {
    let (h, addr) = host(false, &[("in_queue", "2")]).await;
    let c = client(addr, false, &[("out_queue", "8")]).await.unwrap();
    let t = Instant::now();
    let payload = vec![5u8; 1200];
    for i in 0..30_000u32 {
        c.send_to(&payload, addr).await.unwrap();
        if i % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }
    assert!(t.elapsed() < Duration::from_secs(10), "send_to must not block: {:?}", t.elapsed());
    wait_for(|| c.stats().dropped_oldest > 0).await;
    assert_eq!(c.health(), Health::Ok, "a slow peer is not a dead peer");
    // The reader wakes up: it gets some frames, then a fresh one gets through.
    let mut got = 0;
    let mut buf = vec![0u8; 4096];
    while tokio::time::timeout(Duration::from_millis(300), h.readable()).await.is_ok() {
        match h.try_recv_from(&mut buf) {
            Ok(_) => got += 1,
            Err(_) => break,
        }
    }
    assert!(got > 0 && got < 30_000, "got {got}");
    c.send_to(b"fresh", addr).await.unwrap();
    loop {
        if recv(&h).await.unwrap().0 == b"fresh" {
            break;
        }
    }
}

#[tokio::test]
async fn fuzz_through_the_websocket_layer() {
    let (h, addr) = host(false, &[]).await;
    let mut rng = Rng::new(0xC0FFEE);
    for round in 0..150u32 {
        let mut s = if round % 3 == 0 {
            // garbage straight after the upgrade: random bytes as WebSocket frames
            raw_ws(addr).await
        } else {
            raw_ws(addr).await
        };
        let mut junk = vec![0u8; 1 + rng.below(3000) as usize];
        rng.fill(&mut junk);
        match round % 3 {
            0 => {
                let _ = s.write_all(&junk).await;
            }
            1 => {
                // valid WS framing, garbage record stream split at random message boundaries
                let mut rest = &junk[..];
                while !rest.is_empty() {
                    let n = (1 + rng.below(200) as usize).min(rest.len());
                    let _ = s.write_all(&wsframe(true, 2, &rest[..n])).await;
                    rest = &rest[n..];
                }
            }
            _ => {
                // valid records, random message splits, then a text frame (not allowed)
                let r = rec(&junk[..junk.len().min(1000)]);
                let cut = rng.below(r.len() as u64) as usize;
                let _ = s.write_all(&wsframe(false, 2, &r[..cut])).await;
                let _ = s.write_all(&wsframe(true, 0, &r[cut..])).await;
                let _ = s.write_all(&wsframe(true, 1, b"text")).await;
            }
        }
        drop(s);
    }
    // Everything the garbage managed to deliver respects the frame limit, and the host is alive.
    let mut buf = vec![0u8; 4096];
    while let Ok((n, _)) = h.try_recv_from(&mut buf) {
        assert!(n <= DEFAULT_MAX_FRAME);
    }
    wait_for(|| h.peers().is_empty()).await;
    let c = client(addr, false, &[]).await.unwrap();
    c.send_to(b"alive", addr).await.unwrap();
    loop {
        if recv(&h).await.unwrap().0 == b"alive" {
            break;
        }
    }
}

/// Fake host: replies 101 to a request on `path`, records the request head and every byte after it.
async fn fake_host(l: TcpListener) -> tokio::task::JoinHandle<(String, usize)> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().to_string();
        let acc = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut n = 0;
        let mut buf = [0u8; 256];
        while let Ok(Ok(k)) = tokio::time::timeout(Duration::from_millis(400), s.read(&mut buf)).await {
            if k == 0 {
                break;
            }
            n += k;
        }
        (head, n)
    })
}

#[tokio::test]
async fn probe_sends_no_frames_and_reports_typed_status() {
    let f = by_ids(&["ws".to_string()]).remove(0);
    // Against a real host: Reachable, and the host saw no frame.
    let (h, addr) = host(true, &[]).await;
    let sp = spec(Some(addr.to_string()), true, &[]);
    assert!(matches!(f.probe(&sp, Duration::from_secs(5)).await, ProbeStatus::Reachable { .. }));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.stats().frames_in, 0);
    assert!(h.peers().is_empty());
    // Wrong key (TLS pin) and wrong token (decoy) are Blocked; bad spec is Error.
    let bad = CarrierSpec { endpoint: Some(addr.to_string()), bind_port: None, params: vec![("key".into(), "zzz".into())] };
    assert!(matches!(f.probe(&bad, Duration::from_secs(5)).await, ProbeStatus::Blocked(_)));
    let sp2 = spec(Some(addr.to_string()), true, &[("token", "nope")]);
    assert!(matches!(f.probe(&sp2, Duration::from_secs(5)).await, ProbeStatus::Blocked(m) if m.contains("404")));
    assert!(matches!(f.probe(&CarrierSpec::default(), Duration::from_secs(1)).await, ProbeStatus::Error(_)));
    // Nothing listening.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    assert!(matches!(f.probe(&spec(Some(dead.to_string()), false, &[]), Duration::from_secs(2)).await, ProbeStatus::Blocked(_)));
    // Byte-level: a fake plain host sees the upgrade request (with our Host header) and zero bytes after it.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let j = fake_host(l).await;
    let sp3 = spec(Some(a.to_string()), false, &[("host", "front.example.org")]);
    assert!(matches!(f.probe(&sp3, Duration::from_secs(5)).await, ProbeStatus::Reachable { .. }));
    let (head, after) = j.await.unwrap();
    assert_eq!(after, 0, "probe wrote bytes after the upgrade");
    assert!(head.starts_with(&format!("GET {} HTTP/1.1\r\n", identity_for_key(KEY).path)), "{head}");
    assert!(head.contains("Host: front.example.org\r\n") && head.to_ascii_lowercase().contains("authorization: bearer "), "{head}");
}

#[tokio::test]
async fn dial_errors_are_typed() {
    // Missing key / endpoint are Failed, not Blocked.
    let e = dial_ws(&CarrierSpec { endpoint: Some("127.0.0.1:1".into()), ..Default::default() }).await.err().unwrap();
    assert!(matches!(e, CarrierError::Failed(_)), "{e}");
    let e = dial_ws(&spec(None, false, &[])).await.err().unwrap();
    assert!(matches!(e, CarrierError::Failed(_)), "{e}");
    // A peer that accepts and never answers the upgrade: Blocked("connect timeout").
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let _keep = tokio::spawn(async move {
        let _s = l.accept().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let e = client(a, false, &[("connect_ms", "300")]).await.err().unwrap();
    assert!(matches!(e, CarrierError::Blocked(ref m) if m.contains("timeout")), "{e}");
    // A server that is not WebSocket at all but answers HTTP 403: Blocked.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 2048];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
    });
    assert!(matches!(client(a, false, &[]).await.err().unwrap(), CarrierError::Blocked(ref m) if m.contains("403")));
}

#[tokio::test]
async fn a_healthy_host_probed_without_its_key_is_unverifiable_not_blocked() {
    let f = by_ids(&["ws".to_string()]).remove(0);
    let (_h, addr) = host(true, &[]).await;
    let keyless = CarrierSpec { endpoint: Some(addr.to_string()), bind_port: None, params: vec![("key".into(), "00112233445566778899aabbccddeeff".into())] };
    let st = f.probe(&keyless, Duration::from_secs(5)).await;
    assert!(matches!(keyless_verdict(CarrierId::Ws, &st), Verdict::Unverifiable(_)), "{st:?}");
}
