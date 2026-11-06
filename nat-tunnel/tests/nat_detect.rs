//! NAT classification against fake STUN servers on local addresses.
//! A "NAT" is a closure mapping (server addr) -> mapped addr.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use nat_tunnel::tunnel::stun::{message, NatType};
use nat_tunnel::tunnel::NatTraversalModule;
use tokio::net::UdpSocket;

type Nat = Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>;

/// Fake STUN server on `ip`; answers Binding with XOR-MAPPED-ADDRESS = nat(self).
async fn fake(ip: Ipv4Addr, nat: Nat) -> SocketAddr {
    let sock = UdpSocket::bind((ip, 0)).await.unwrap();
    let me = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                // Windows: ICMP port-unreachable from an earlier reply shows up as ConnectionReset.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(_) => break,
            };
            if n < 20 {
                continue;
            }
            let id: [u8; 12] = buf[8..20].try_into().unwrap();
            let m = nat(me);
            let SocketAddr::V4(m) = m else { continue };
            let mut v = vec![0, 1];
            v.extend((m.port() ^ 0x2112).to_be_bytes());
            let ip = u32::from(*m.ip()) ^ 0x2112_A442;
            v.extend(ip.to_be_bytes());
            let mut attr = vec![0x00, 0x20, 0, 8];
            attr.extend(v);
            let _ = sock.send_to(&message(0x0101, &attr, &id), from).await;
        }
    });
    me
}

async fn run(servers: &[SocketAddr]) -> (NatType, String) {
    let cfg = nat_tunnel::config::Config::load_from_env().unwrap();
    let nat = NatTraversalModule::from_config(&cfg.nat_traversal);
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let r = nat.classify_servers(&sock, servers).await;
    (r.kind, r.detail)
}

/// Two distinct local IPv4s (loopback + LAN); None when the host has no LAN IP.
fn second_ip() -> Option<Ipv4Addr> {
    NatTraversalModule::local_egress_ip().filter(|ip| !ip.is_loopback())
}

fn pubaddr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), port))
}

#[tokio::test]
async fn cone_address_port_dependent_and_dead() {
    let Some(lan) = second_ip() else {
        eprintln!("skip: no second local IPv4");
        return;
    };
    let lo = Ipv4Addr::LOCALHOST;

    // Cone: same mapping for everyone.
    let cone: Nat = Arc::new(|_| pubaddr(40000));
    let s = [fake(lo, cone.clone()).await, fake(lo, cone.clone()).await, fake(lan, cone).await];
    let (k, d) = run(&s).await;
    assert_eq!(k, NatType::RestrictedCone, "{d}");

    // Address-dependent: port keyed on destination IP only.
    let adm: Nat = Arc::new(|srv| pubaddr(if srv.ip().is_loopback() { 40001 } else { 40002 }));
    let s = [fake(lo, adm.clone()).await, fake(lo, adm.clone()).await, fake(lan, adm).await];
    let (k, d) = run(&s).await;
    assert_eq!(k, NatType::Symmetric, "{d}");
    assert!(d.contains("address-dependent"), "{d}");

    // Port-dependent: same across IPs for equal... differs between two ports of one IP.
    let pdm: Nat = Arc::new(|srv| pubaddr(40100 + (srv.port() % 2) * 7));
    let a = fake(lo, pdm.clone()).await;
    let mut b = fake(lo, pdm.clone()).await;
    while b.port() % 2 == a.port() % 2 {
        b = fake(lo, pdm.clone()).await;
    }
    let mut c = fake(lan, pdm.clone()).await;
    while c.port() % 2 != a.port() % 2 {
        c = fake(lan, pdm.clone()).await;
    }
    let (k, d) = run(&[a, b, c]).await;
    assert_eq!(k, NatType::Symmetric, "{d}");
    assert!(d.contains("port-dependent"), "{d}");

    // One server dead: still two distinct IPs -> classified.
    let cone: Nat = Arc::new(|_| pubaddr(40000));
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let (k, d) = run(&[dead, fake(lo, cone.clone()).await, fake(lan, cone.clone()).await]).await;
    assert_eq!(k, NatType::RestrictedCone, "{d}");

    // Only one distinct IP alive -> Unknown, not Symmetric.
    let (k, d) = run(&[dead, fake(lo, cone).await]).await;
    assert_eq!(k, NatType::Unknown, "{d}");

    // All dead -> Block.
    let (k, _) = run(&[dead]).await;
    assert_eq!(k, NatType::Block);
}
