//! check_host against a local signaling server on loopback.

use std::net::SocketAddr;

use nat_tunnel::{preflight, relay};
use tokio::net::UdpSocket;

#[tokio::test]
async fn signal_latency_and_invite() {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv: SocketAddr = s.local_addr().unwrap();
    tokio::spawn(relay::serve(s, relay::Config::default()));

    // Port 0 is not allowed by the host; any free high port works for the probe.
    let free = std::net::UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port();
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let v = preflight::check_host(free, Some("k".repeat(32)), vec![dead, srv], vec![]).await.unwrap();
    preflight::release_kept_mapping().await;

    assert_eq!(v.signal.as_deref(), Some(srv.to_string().as_str()));
    assert!(v.signal_latency_ms.unwrap() < 1000);
    assert!(v.hostable);
    assert_eq!(v.port, free);
    assert!(v.invite.starts_with("STRAIT2|") && v.invite.contains(&srv.to_string()));
    assert_eq!(v.endpoint.as_ref(), v.endpoints.first());

    // JSON field set matches handoff section 7 exactly.
    let json = serde_json::to_value(&v).unwrap();
    let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        "client_note client_requirements endpoint endpoints hostable invite method nat note port signal signal_latency_ms"
            .split(' ')
            .collect::<Vec<_>>(),
        "no `rendezvous` key unless methods were chosen"
    );
}
