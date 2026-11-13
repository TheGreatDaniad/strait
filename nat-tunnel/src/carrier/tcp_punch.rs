//! TCP hole punching for stream carriers: every socket of one side shares one local port
//! (address reuse), so the listener, the outbound attempts and the STUN query all show the same
//! NAT mapping. Two peers that dial each other's mapped address at about the same time meet in a
//! TCP simultaneous open (or one side's SYN simply reaches the other's listener).
//! IPv4 only. shortcut: no IPv6 punch, add a `[::]` socket set when a v6-only pair needs it.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::tunnel::stun;

/// One outbound attempt: long enough for two SYN retransmissions, short enough to restart often.
pub const ATTEMPT: Duration = Duration::from_secs(3);

/// Public STUN servers that also answer over TCP (checked 2026-11). `STUN_TCP_SERVERS`
/// (comma separated `host:port`) replaces the list.
pub const DEFAULT_TCP_STUN: &[&str] =
    &["stun.nextcloud.com:443", "stun.voipgate.com:3478", "stun.freeswitch.org:3478", "stun.hot-chilli.net:3478"];

fn socket(port: u16) -> std::io::Result<TcpSocket> {
    let s = TcpSocket::new_v4()?;
    s.set_reuseaddr(true)?;
    #[cfg(unix)]
    s.set_reuseport(true)?;
    s.bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))?;
    Ok(s)
}

/// A listener on `port` (0 = any) whose port outbound attempts can share.
pub fn listen(port: u16) -> std::io::Result<TcpListener> {
    socket(port)?.listen(64)
}

/// Dial `to` from local `port`.
pub async fn connect_from(port: u16, to: SocketAddr) -> std::io::Result<TcpStream> {
    socket(port)?.connect(to).await
}

async fn servers() -> Vec<SocketAddr> {
    let entries: Vec<String> = match std::env::var("STUN_TCP_SERVERS") {
        Ok(v) => v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Err(_) => DEFAULT_TCP_STUN.iter().map(|s| s.to_string()).collect(),
    };
    stun::resolve_servers(&entries).await
}

async fn ask(port: u16, server: SocketAddr) -> Option<SocketAddr> {
    let mut s = connect_from(port, server).await.map_err(|e| log::debug!("TCP STUN {server} from port {port}: {e}")).ok()?;
    let id = stun::new_transaction_id();
    s.write_all(&stun::message(0x0001, &[], &id)).await.ok()?;
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 256];
    loop {
        let n = s.read(&mut chunk).await.ok().filter(|n| *n > 0)?;
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= 20 && buf.len() >= 20 + u16::from_be_bytes([buf[2], buf[3]]) as usize {
            return stun::mapped_for(&buf, &id);
        }
        if buf.len() > 1024 {
            return None;
        }
    }
}

/// How local TCP `port` looks from outside: one address per answering server, at most `want`
/// (two different answers = the NAT picks a port per destination, punching cannot work).
pub async fn mapped(port: u16, want: usize) -> Vec<SocketAddr> {
    mapped_with(port, &servers().await, want).await
}

/// [`mapped`] against the given servers.
pub async fn mapped_with(port: u16, servers: &[SocketAddr], want: usize) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for &s in servers {
        if out.len() >= want {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(2), ask(port, s)).await {
            Ok(Some(m)) => {
                log::debug!("TCP port {port} is {m} from outside (STUN {s})");
                out.push(m);
            }
            r => log::debug!("TCP STUN {s}: no usable answer{}", if r.is_err() { " (timeout)" } else { "" }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Listener and dialer share a port; a dial from that port to another listener keeps it.
    #[tokio::test]
    async fn sockets_share_one_port() {
        let a = listen(0).unwrap();
        let port = a.local_addr().unwrap().port();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = connect_from(port, b.local_addr().unwrap()).await.unwrap();
        assert_eq!(s.local_addr().unwrap().port(), port);
        let (_, from) = b.accept().await.unwrap();
        assert_eq!(from.port(), port);
    }

    /// Live: the default public servers answer over TCP (needs internet).
    #[tokio::test]
    #[ignore]
    async fn live_default_servers_answer() {
        let l = listen(0).unwrap();
        let m = mapped(l.local_addr().unwrap().port(), 2).await;
        assert_eq!(m.len(), 2, "{m:?}");
    }

    /// A TCP STUN server's answer is read as the mapping of the shared port.
    #[tokio::test]
    async fn mapping_comes_from_a_tcp_stun_answer() {
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = srv.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut c, from) = srv.accept().await.unwrap();
                let mut req = [0u8; 20];
                c.read_exact(&mut req).await.unwrap();
                let SocketAddr::V4(v4) = from else { panic!("v4") };
                let mut attr = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01];
                attr.extend_from_slice(&(v4.port() ^ 0x2112).to_be_bytes());
                attr.extend_from_slice(&(u32::from(*v4.ip()) ^ 0x2112_A442).to_be_bytes());
                let id: [u8; 12] = req[8..20].try_into().unwrap();
                c.write_all(&stun::message(0x0101, &attr, &id)).await.unwrap();
            }
        });
        let l = listen(0).unwrap();
        let port = l.local_addr().unwrap().port();
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let m = mapped_with(port, &[dead, at, at], 2).await;
        assert_eq!(m, vec![SocketAddr::new([127, 0, 0, 1].into(), port); 2]);
    }
}
