//! M1: IPv6-first ladder over loopback. Skips when the machine lacks v6 loopback
//! or a dual-stack socket. Real v6 internet paths cannot be exercised here.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::transport::{dual_stack_available, ConnectError, ConnectOpts, Event, Tunnel};

fn v6_loopback_port() -> Option<u16> {
    let s = std::net::UdpSocket::bind("[::1]:0").ok()?;
    dual_stack_available().then(|| s.local_addr().unwrap().port())
}

fn opts<'a>(host: bool, port: Option<u16>) -> ConnectOpts<'a> {
    ConnectOpts { signal: None, peer: None, room: "", key: "k6", host, bind_port: port, hosts: vec![], mux: false }
}

async fn next_data(t: &mut Tunnel) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            t.tick().await.unwrap();
            if let Some(Event::Data(d)) = t.try_recv().await.unwrap() {
                return d;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("data before timeout")
}

/// Host on a dual-stack socket; guest dials `hosts` through the ladder.
async fn pair(port: u16, hosts: Vec<SocketAddr>) {
    let host = tokio::spawn(async move {
        let mut t = Tunnel::connect(opts(true, Some(port))).await.expect("host ready");
        t.send(b"hi-guest").await.unwrap();
        assert_eq!(next_data(&mut t).await, b"hi-host");
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut t = Tunnel::connect_ladder(opts(false, None), &hosts, false, false)
        .await
        .expect("guest connects");
    assert!(t.is_direct());
    t.send(b"hi-host").await.unwrap();
    assert_eq!(next_data(&mut t).await, b"hi-guest");
    host.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_only_loopback_invite() {
    let Some(port) = v6_loopback_port() else { return eprintln!("skip: no v6 loopback/dual stack") };
    pair(port, vec![format!("[::1]:{port}").parse().unwrap()]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_only_invite_on_dual_host() {
    let Some(port) = v6_loopback_port() else { return eprintln!("skip: no v6 loopback/dual stack") };
    pair(port, vec![format!("127.0.0.1:{port}").parse().unwrap()]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_v6_falls_back_to_v4_fast() {
    let Some(port) = v6_loopback_port() else { return eprintln!("skip: no v6 loopback/dual stack") };
    // v6 endpoint on a port nobody serves; v4 is the live one (listed first on purpose).
    let dead = std::net::UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap();
    let hosts = vec![format!("127.0.0.1:{port}").parse().unwrap(), dead];
    let started = std::time::Instant::now();
    pair(port, hosts).await;
    assert!(started.elapsed() < Duration::from_secs(4), "must not wait the full punch window");
}

#[tokio::test]
async fn v6_only_invite_without_route_is_explicit_error() {
    let hosts: Vec<SocketAddr> = vec!["[2001:db8::1]:7100".parse().unwrap()];
    let err = Tunnel::connect_ladder(opts(false, None), &hosts, false, false)
        .await
        .err()
        .expect("must fail");
    assert!(matches!(err, ConnectError::NoIpv6Route), "{err:?}");
    assert_eq!(err.to_string(), "No IPv6 on this network; the host is IPv6-only.");
    // Survives the io::Error conversion used by Tunnel::connect.
    let io: std::io::Error = err.into();
    assert!(matches!(ConnectError::from_io(&io), Some(ConnectError::NoIpv6Route)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_host_is_host_unreachable() {
    // Bound but never answering UDP socket.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let hosts = vec![silent.local_addr().unwrap()];
    let err = Tunnel::connect_ladder(opts(false, None), &hosts, false, false)
        .await
        .err()
        .expect("must fail");
    assert!(matches!(err, ConnectError::HostUnreachable), "{err:?}");
}
