//! STRAIT_EXIT_PROXY preamble: sender side (fail-closed, end-to-end through the
//! real exit) and the reference reader (valid / malformed / oversized / slow).
//! Env-dependent test lives alone in this binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::poll_fn;
use nat_tunnel::userspace::{exit_target_from, read_exit_preamble, serve_tcp_with, ExitConfig, MAX_PREAMBLE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn sender_formats_and_fails_closed() {
    let remote = sa("93.184.216.34:443");
    assert_eq!(exit_target_from(None, remote).unwrap(), (remote, None));
    let (addr, pre) = exit_target_from(Some("127.0.0.1:9000"), remote).unwrap();
    assert_eq!(addr, sa("127.0.0.1:9000"));
    assert_eq!(pre.unwrap(), b"93.184.216.34:443\n");
    let (_, pre) = exit_target_from(Some("127.0.0.1:9000"), sa("[2001:db8::1]:80")).unwrap();
    let pre = pre.unwrap();
    assert!(pre.len() <= MAX_PREAMBLE);
    for bad in ["", "nonsense", "localhost:80", "127.0.0.1", "127.0.0.1:99999"] {
        assert!(exit_target_from(Some(bad), remote).is_err(), "{bad:?}");
    }
}

async fn read_with(bytes: &[u8], t: Duration) -> std::io::Result<SocketAddr> {
    let mut b = bytes;
    read_exit_preamble(&mut b, t).await
}

#[tokio::test]
async fn reader_valid_malformed_oversized() {
    let t = Duration::from_secs(1);
    assert_eq!(read_with(b"1.2.3.4:80\nGET /", t).await.unwrap(), sa("1.2.3.4:80"));
    let (_, pre) = exit_target_from(Some("127.0.0.1:9000"), sa("[2001:db8::1]:80")).unwrap();
    assert_eq!(read_with(&pre.unwrap(), t).await.unwrap(), sa("[2001:db8::1]:80"));
    for bad in [&b"\n"[..], b"junk\n", b"1.2.3.4\n", b"1.2.3.4:80", b"\xff\xfe:1\n", b""] {
        assert!(read_with(bad, t).await.is_err(), "{bad:?}");
    }
    // Oversized: rejected without needing a newline, and before buffering more.
    let long = vec![b'1'; 10_000];
    let e = read_with(&long, t).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    // Exactly at the limit is rejected, one under is parsed-or-malformed (not "too long").
    let mut at = vec![b'1'; MAX_PREAMBLE];
    at.push(b'\n');
    assert_eq!(read_with(&at, t).await.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn reader_slow_preamble_times_out() {
    let (mut a, mut b) = tokio::io::duplex(64);
    let r = tokio::spawn(async move { read_exit_preamble(&mut b, Duration::from_millis(300)).await });
    a.write_all(b"1.2.3.4:").await.unwrap(); // drip, never finish
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(r.await.unwrap().unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}

/// Through the real exit: a lab proxy built on the reference reader receives the
/// destination, then bytes flow; a malformed env var refuses the flow.
#[tokio::test]
async fn exit_uses_proxy_preamble_then_fails_closed() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paddr = proxy.local_addr().unwrap();
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = proxy.accept().await.unwrap();
            let seen = seen_tx.clone();
            tokio::spawn(async move {
                if let Ok(dest) = read_exit_preamble(&mut s, Duration::from_secs(2)).await {
                    let _ = seen.send(dest);
                    let _ = s.write_all(b"via-proxy").await;
                }
            });
        }
    });

    let sem = Arc::new(Semaphore::new(4));
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(serve_tcp_with(Box::pin(poll_fn(move |cx| rx.poll_recv(cx))), ExitConfig::default(), Some(sem.clone())));
    let open = |remote: SocketAddr| {
        let (client, inner) = tokio::io::duplex(4096);
        tx.send((inner, sa("10.0.0.2:1"), remote)).unwrap();
        client
    };

    std::env::set_var("STRAIT_EXIT_PROXY", paddr.to_string());
    let target = sa("203.0.113.7:8443");
    let mut c = open(target);
    let mut buf = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"via-proxy");
    assert_eq!(seen_rx.recv().await.unwrap(), target);

    // Malformed value: never dials the destination directly; flow is closed.
    std::env::set_var("STRAIT_EXIT_PROXY", "not-an-address");
    let mut c = open(sa("127.0.0.1:1"));
    let mut b = [0u8; 1];
    assert_eq!(tokio::time::timeout(Duration::from_secs(3), c.read(&mut b)).await.unwrap().unwrap(), 0);
    std::env::remove_var("STRAIT_EXIT_PROXY");
}
