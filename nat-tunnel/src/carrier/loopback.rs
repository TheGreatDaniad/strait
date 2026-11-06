//! A carrier whose remote is a local UDP port: a sidecar (Xray, wstunnel, ...) or an in-process
//! forwarder terminates the real carrier and speaks plain UDP on 127.0.0.1.
//!
//! # The shared-source-port problem
//! Behind a sidecar, every client reaches the host's loopback socket from the sidecar's outbound
//! UDP socket. If two clients share one source port (XUDP may do this; see doc section 6.6), the
//! host sees one `SocketAddr` for several peers: `Peer.addr` collides, pre-handshake frames cannot
//! be told apart, and replies go to the wrong flow. Two options, selected by [`Demux`]:
//!
//! * [`Demux::None`]: the peer key is the real loopback source. Correct only if the sidecar gives
//!   each client its own source port (verify in the lab).
//! * [`Demux::Header`]: the client prepends a 4-byte random client id to every datagram; the host
//!   strips it and maps `(source, id)` to a synthetic peer address in 240.0.0.0/8 (reserved, never
//!   a real peer), so the one-peer-per-`SocketAddr` invariant holds whatever the source port does.
//!   Replies carry the id back; a client ignores datagrams with another client's id (counted in
//!   [`LoopbackStats::foreign`]). Costs 4 bytes per frame; both ends must use it.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::net::UdpSocket;

use super::{CarrierError, CarrierId, Caps, FrameIo, Health};

pub const DEMUX_HEADER: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demux {
    None,
    Header,
}

#[derive(Debug, Clone)]
pub struct LoopbackCfg {
    /// Which carrier terminates behind the loopback (shown in `caps`).
    pub id: CarrierId,
    pub max_frame: usize,
    /// True when the outer path is a stream (XHTTP, WebSocket): bound queues matter upstream.
    pub reliable_stream: bool,
    pub demux: Demux,
    /// Host side, `Demux::Header`: cap on distinct client mappings (new ones are refused, counted).
    pub max_clients: usize,
}

impl LoopbackCfg {
    pub fn new(id: CarrierId) -> Self {
        Self { id, max_frame: 1500, reliable_stream: true, demux: Demux::None, max_clients: 1024 }
    }
}

/// Keeps a sidecar (or forwarder task) alive for as long as the carrier lives.
pub trait Guard: Send + Sync + 'static {
    fn health(&self) -> Health {
        Health::Ok
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopbackStats {
    /// Datagrams from an unexpected source / client id, or too short for the header.
    pub foreign: u64,
    /// New client mappings refused because `max_clients` was reached.
    pub refused_clients: u64,
}

#[derive(Default)]
struct HostMap {
    by_key: HashMap<(SocketAddr, u32), SocketAddr>,
    by_peer: HashMap<SocketAddr, (SocketAddr, u32)>,
    next: u32,
}

enum Role {
    Client { remote: SocketAddr, virtual_host: SocketAddr, cid: u32 },
    Host { map: Mutex<HostMap> },
}

pub struct LoopbackUdp {
    sock: UdpSocket,
    cfg: LoopbackCfg,
    role: Role,
    guard: Option<Box<dyn Guard>>,
    scratch: Mutex<Vec<u8>>,
    foreign: AtomicU64,
    refused: AtomicU64,
}

fn synthetic(n: u32) -> SocketAddr {
    // 240.0.0.0/8 holds 2^24 addresses; max_clients is far below that.
    SocketAddr::from((Ipv4Addr::new(240, (n >> 16) as u8, (n >> 8) as u8, n as u8), 1))
}

impl LoopbackUdp {
    /// Client side. `remote` = the sidecar's local inbound; `virtual_host` = the address the
    /// transport believes the host has (frames from `remote` are reported as coming from it).
    pub async fn client(cfg: LoopbackCfg, remote: SocketAddr, virtual_host: SocketAddr) -> io::Result<Self> {
        let bind = if remote.is_ipv6() { "[::1]:0" } else { "127.0.0.1:0" };
        let sock = UdpSocket::bind(bind).await?;
        let b = *uuid::Uuid::new_v4().as_bytes();
        let cid = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        Ok(Self::make(sock, cfg, Role::Client { remote, virtual_host, cid }))
    }

    /// Host side: the socket the sidecar's outbound is redirected to (`bind` on loopback).
    pub async fn host(cfg: LoopbackCfg, bind: SocketAddr) -> io::Result<Self> {
        let sock = UdpSocket::bind(bind).await?;
        Ok(Self::make(sock, cfg, Role::Host { map: Mutex::new(HostMap::default()) }))
    }

    fn make(sock: UdpSocket, cfg: LoopbackCfg, role: Role) -> Self {
        Self {
            sock,
            cfg,
            role,
            guard: None,
            scratch: Mutex::new(vec![0u8; 65536]),
            foreign: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }

    pub fn with_guard(mut self, g: impl Guard) -> Self {
        self.guard = Some(Box::new(g));
        self
    }

    pub fn stats(&self) -> LoopbackStats {
        LoopbackStats { foreign: self.foreign.load(Ordering::Relaxed), refused_clients: self.refused.load(Ordering::Relaxed) }
    }

    /// Host side: drop the mapping of an evicted peer.
    pub fn forget(&self, peer: SocketAddr) {
        if let Role::Host { map } = &self.role {
            let mut m = map.lock().unwrap();
            if let Some(k) = m.by_peer.remove(&peer) {
                m.by_key.remove(&k);
            }
        }
    }

    pub fn client_count(&self) -> usize {
        match &self.role {
            Role::Host { map } => map.lock().unwrap().by_peer.len(),
            Role::Client { .. } => 1,
        }
    }

    fn hdr(&self) -> usize {
        if self.cfg.demux == Demux::Header { DEMUX_HEADER } else { 0 }
    }
}

#[async_trait::async_trait]
impl FrameIo for LoopbackUdp {
    fn caps(&self) -> Caps {
        Caps {
            id: self.cfg.id,
            max_frame: self.cfg.max_frame,
            punchable: false,
            reliable_stream: self.cfg.reliable_stream,
            overhead: self.hdr(),
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize> {
        if frame.len() > self.cfg.max_frame {
            return Err(CarrierError::FrameTooLarge { max: self.cfg.max_frame }.into());
        }
        let (dst, cid) = match &self.role {
            Role::Client { remote, virtual_host, cid } => {
                if to != *virtual_host {
                    return Err(CarrierError::UnknownPeer.into());
                }
                (*remote, *cid)
            }
            Role::Host { map } => match self.cfg.demux {
                Demux::None => (to, 0),
                Demux::Header => match map.lock().unwrap().by_peer.get(&to) {
                    Some(&(src, cid)) => (src, cid),
                    None => return Err(CarrierError::UnknownPeer.into()),
                },
            },
        };
        if self.cfg.demux == Demux::Header {
            let mut d = Vec::with_capacity(DEMUX_HEADER + frame.len());
            d.extend_from_slice(&cid.to_be_bytes());
            d.extend_from_slice(frame);
            self.sock.send_to(&d, dst).await?;
        } else {
            self.sock.send_to(frame, dst).await?;
        }
        Ok(frame.len())
    }

    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut sc = self.scratch.lock().unwrap();
        loop {
            let (n, src) = self.sock.try_recv_from(&mut sc)?;
            let (payload, peer) = match &self.role {
                Role::Client { remote, virtual_host, cid } => {
                    if src != *remote {
                        self.foreign.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if self.cfg.demux == Demux::Header {
                        if n < DEMUX_HEADER || u32::from_be_bytes(sc[..4].try_into().unwrap()) != *cid {
                            self.foreign.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        (&sc[DEMUX_HEADER..n], *virtual_host)
                    } else {
                        (&sc[..n], *virtual_host)
                    }
                }
                Role::Host { map } => match self.cfg.demux {
                    Demux::None => (&sc[..n], src),
                    Demux::Header => {
                        if n < DEMUX_HEADER {
                            self.foreign.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let cid = u32::from_be_bytes(sc[..4].try_into().unwrap());
                        let mut m = map.lock().unwrap();
                        let peer = match m.by_key.get(&(src, cid)) {
                            Some(p) => *p,
                            None => {
                                if m.by_peer.len() >= self.cfg.max_clients {
                                    self.refused.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                m.next += 1;
                                let p = synthetic(m.next);
                                m.by_key.insert((src, cid), p);
                                m.by_peer.insert(p, (src, cid));
                                p
                            }
                        };
                        (&sc[DEMUX_HEADER..n], peer)
                    }
                },
            };
            if payload.len() > buf.len() || payload.len() > self.cfg.max_frame {
                return Err(CarrierError::FrameTooLarge { max: buf.len().min(self.cfg.max_frame) }.into());
            }
            buf[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), peer));
        }
    }

    async fn readable(&self) -> io::Result<()> {
        self.sock.readable().await
    }

    fn health(&self) -> Health {
        self.guard.as_ref().map(|g| g.health()).unwrap_or(Health::Ok)
    }
}
