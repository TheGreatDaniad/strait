//! `sig`: the existing UDP signal protocol (`relay.rs`) as a rendezvous method. IPv4 only.
//!
//! The signal server reports the address it *observed* for each registrant, so unlike the other
//! methods `ctx.local` is not published. For that observed address to be the one the punch will
//! use, pass the punch socket in `RvCtx::sock` (the adapter then sends and receives on it for
//! the lifetime of `run`); otherwise it uses a private socket (fine for tests, wrong port behind
//! a NAT). The room is `relay::room_for_key(lowercase hex of the 16-byte key)`, the same value
//! the legacy transport derives from the invite's key string.
//!
//! Publish frequency: REGISTER to each server every 2 s for the first 10 s, then every 15 s.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::derive::hex;
use super::{Candidate, Disclosure, ProbeStatus, Rendezvous, Role, RvCtx, RvError, Status};
use crate::invite::{resolve_signals, Endpoint};
use crate::relay::{self, Incoming};

pub struct Sig {
    servers: Vec<Endpoint>,
}

impl Sig {
    pub fn new(servers: Vec<Endpoint>) -> Self {
        Self { servers }
    }
}

fn role_u8(r: Role) -> u8 {
    match r {
        Role::Host => 0,
        Role::Client => 1,
    }
}

/// Room the legacy transport uses for this key.
pub fn room_for(key: &[u8; 16]) -> u32 {
    relay::room_for_key(&hex(key))
}

async fn resolve(servers: &[Endpoint]) -> Result<Vec<SocketAddr>, String> {
    if servers.is_empty() {
        return Err("no signal server configured".into());
    }
    resolve_signals(servers).await
}

#[async_trait::async_trait]
impl Rendezvous for Sig {
    fn id(&self) -> &'static str {
        "sig"
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Signal server (UDP)",
            shared: &[
                "your public IP address and port, as seen by the signal server",
                "a room number derived from the invite key (the key itself is not sent)",
                "the time of each check-in",
            ],
            not_shared: &["your traffic", "the invite key", "anything readable about what you tunnel"],
            why: "the server tells each device the other's public address so they can connect directly",
            operator: "the signal server named in the invite (whoever runs it; no uptime promise)",
        }
    }

    async fn probe(&self, timeout: Duration) -> ProbeStatus {
        let servers = match resolve(&self.servers).await {
            Ok(s) => s,
            Err(e) => return ProbeStatus::Error(e),
        };
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
            return ProbeStatus::Error("cannot open a UDP socket".into());
        };
        let nonce = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7) ^ std::process::id()) | 1;
        let t0 = Instant::now();
        for s in &servers {
            let _ = sock.send_to(&relay::encode_ping(nonce), s).await;
        }
        let mut buf = [0u8; 64];
        let wait = async {
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return None };
                if servers.contains(&from) && relay::decode(&buf[..n]) == Some(Incoming::Pong(nonce)) {
                    return Some(t0.elapsed());
                }
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(Some(rtt)) => ProbeStatus::Reachable { rtt_ms: rtt.as_millis() as u32 },
            _ => ProbeStatus::Blocked("no reply from the signal server (UDP may be filtered)".into()),
        }
    }

    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError> {
        let servers = resolve(&self.servers).await.map_err(RvError::Failed)?;
        let sock: Arc<UdpSocket> = match &ctx.sock {
            Some(s) => s.clone(),
            None => Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| RvError::Failed(e.to_string()))?),
        };
        let (room, me) = (room_for(&ctx.key), role_u8(ctx.role));
        let reg = relay::encode_register(room, me);
        let t0 = Instant::now();
        let mut next_reg = Instant::now();
        let mut buf = [0u8; 64];
        loop {
            if Instant::now() >= next_reg {
                for s in &servers {
                    let _ = sock.send_to(&reg, s).await;
                }
                ctx.status.set(Status::Publishing);
                let every = if t0.elapsed() < Duration::from_secs(10) { 2 } else { 15 };
                next_reg = Instant::now() + Duration::from_secs(every);
                ctx.status.set(Status::Waiting);
            }
            tokio::select! {
                _ = cancel.cancelled() => {
                    for s in &servers {
                        let _ = sock.send_to(&relay::encode_deregister(room, me), s).await;
                    }
                    return Ok(());
                }
                _ = tokio::time::sleep_until(next_reg.into()) => {}
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { continue };
                    if !servers.contains(&from) { continue }
                    if let Some(Incoming::Peer { role, addr }) = relay::decode(&buf[..n]) {
                        if role != me && tx.send(Candidate { addr, via: "sig" }).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
