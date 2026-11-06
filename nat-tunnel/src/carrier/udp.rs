//! Raw UDP carrier: today's behaviour behind [`FrameIo`] (default, and the control for every
//! other test). IPv4 peers are addressed through their v4-mapped form on a dual-stack socket and
//! received addresses are normalized back to plain IPv4, exactly like `Tunnel::wire` / `norm`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, Caps, FrameIo};
use crate::rendezvous::{Disclosure, ProbeStatus};

/// Largest datagram payload on a 1500 B Ethernet path (IPv4 + UDP headers). Today's biggest sealed
/// frame is 1435 B.
pub const UDP_MAX_FRAME: usize = 1472;

/// IPv4 peers go out as v4-mapped IPv6 on a dual-stack socket.
pub fn to_wire(dual: bool, addr: SocketAddr) -> SocketAddr {
    match (dual, addr.ip()) {
        (true, IpAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), addr.port()),
        _ => addr,
    }
}

/// Received address back to plain IPv4 for logging, signaling and comparisons.
pub fn norm(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        _ => addr,
    }
}

pub struct UdpCarrier {
    sock: UdpSocket,
    dual: bool,
    max_frame: usize,
}

impl UdpCarrier {
    /// Wrap a socket the caller bound (e.g. the transport's `bind_marked` result).
    pub fn from_socket(sock: UdpSocket, dual: bool) -> Self {
        Self { sock, dual, max_frame: UDP_MAX_FRAME }
    }

    /// Dual-stack bind on `port` (0 = any), v4-only fallback. No `SO_MARK` / interface pinning:
    /// the transport keeps `bind_marked` for that and hands the socket to [`Self::from_socket`].
    pub async fn bind(port: Option<u16>) -> io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let port = port.unwrap_or(0);
        let mk = |d: Domain, a: SocketAddr, v6only: bool| -> io::Result<Socket> {
            let s = Socket::new(d, Type::DGRAM, Some(Protocol::UDP))?;
            if v6only {
                s.set_only_v6(false)?;
            }
            s.bind(&a.into())?;
            let _ = s.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = s.set_send_buffer_size(4 * 1024 * 1024);
            s.set_nonblocking(true)?;
            Ok(s)
        };
        let (s, dual) = match mk(Domain::IPV6, SocketAddr::from(([0u16; 8], port)), true) {
            Ok(s) => (s, true),
            // A taken port must fail, not fall back to v4 and shadow the owner.
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Err(e),
            Err(_) => (mk(Domain::IPV4, SocketAddr::from(([0, 0, 0, 0], port)), false)?, false),
        };
        Ok(Self::from_socket(UdpSocket::from_std(s.into())?, dual))
    }

    pub fn with_max_frame(mut self, max: usize) -> Self {
        self.max_frame = max;
        self
    }

    pub fn is_dual(&self) -> bool {
        self.dual
    }
}

#[async_trait::async_trait]
impl FrameIo for UdpCarrier {
    fn caps(&self) -> Caps {
        Caps { id: CarrierId::Udp, max_frame: self.max_frame, punchable: true, reliable_stream: false, overhead: 0 }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        if frame.len() > self.max_frame {
            return Err(CarrierError::FrameTooLarge { max: self.max_frame }.into());
        }
        self.sock.send_to(frame, to_wire(self.dual, to)).await
    }
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, from) = self.sock.try_recv_from(buf)?;
        Ok((n, norm(from)))
    }
    async fn readable(&self) -> io::Result<()> {
        self.sock.readable().await
    }
    fn udp(&self) -> Option<&UdpSocket> {
        Some(&self.sock)
    }
}

pub struct UdpFactory;

#[async_trait::async_trait]
impl CarrierFactory for UdpFactory {
    fn id(&self) -> CarrierId {
        CarrierId::Udp
    }
    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Direct UDP",
            shared: &["Encrypted UDP datagrams between you and the other device"],
            not_shared: &["No third party carries the data"],
            why: "Fastest path; also the only one that can hole-punch through NATs.",
            operator: "none",
        }
    }
    async fn probe(&self, _spec: &CarrierSpec, _t: Duration) -> ProbeStatus {
        // A bare UDP probe proves nothing without the peer; the punch itself is the probe.
        match UdpCarrier::bind(None).await {
            Ok(_) => ProbeStatus::Reachable { rtt_ms: 0 },
            Err(e) => ProbeStatus::Error(e.to_string()),
        }
    }
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let c = UdpCarrier::bind(spec.bind_port).await.map_err(|e| CarrierError::Failed(e.to_string()))?;
        Ok(Arc::new(c))
    }
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        self.listen(spec).await
    }
}
