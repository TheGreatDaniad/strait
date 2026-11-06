//! TUN backed by an existing datagram fd (iOS NetworkExtension utun; macOS only for the FFI harness).
//!
//! The owner (PacketTunnelProvider) configured the address, routes and DNS. Like the Android
//! module, this one only moves whole IP packets, but a utun fd carries a 4-byte address-family
//! header (`AF_INET` = 2, `AF_INET6` = 30 on Darwin) before every packet: stripped on read,
//! prepended on write. The fd is never closed here (the extension owns it).
//!
//! The fd arrives either in `TunConfig.fd`, or, when that is `None`/negative, from the provider
//! registered with [`set_fd_provider`]: the guest calls it once the host has assigned an address,
//! and the FFI layer answers it after Swift ran `setTunnelNetworkSettings` (connect first, learn
//! the address, configure, hand over the fd).
//!
//! MTU: the carrier that won decides it (`transport::tun_mtu()`, 1400 or less, e.g. 1300 for xray).
//! The interface itself belongs to the owner, so the provider must apply that value
//! (`NEPacketTunnelNetworkSettings.mtu`): `transport::set_tun_mtu` runs before the provider is
//! called, so reading `nat_tunnel::transport::tun_mtu()` inside it is enough. A packet that still
//! exceeds it is dropped here with one warning instead of being refused by the carrier per packet.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use tokio::io::unix::AsyncFd;

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub name: Option<String>,
    pub default_via: Option<Ipv4Addr>,
    pub bypass: Vec<String>,
    pub fd: Option<i32>,
    pub fd_socket: Option<String>,
}

impl TunConfig {
    pub fn parse_addr(value: &str) -> Result<(Ipv4Addr, u8), String> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("expected ADDR/PREFIX, got {value}"))?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| format!("bad address {addr}"))?;
        let prefix: u8 = prefix.parse().map_err(|_| format!("bad prefix {prefix}"))?;
        if prefix == 0 || prefix > 32 {
            return Err(format!("prefix must be 1..=32, got {prefix}"));
        }
        Ok((addr, prefix))
    }
}

/// Called with the host-assigned address; must return the utun fd (may block until Swift is done).
pub type FdProvider = Arc<dyn Fn(Ipv4Addr, u8) -> io::Result<RawFd> + Send + Sync>;

static PROVIDER: Mutex<Option<FdProvider>> = Mutex::new(None);

pub fn set_fd_provider(p: Option<FdProvider>) {
    *PROVIDER.lock().unwrap() = p;
}

const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;

pub struct TunDevice {
    fd: AsyncFd<RawFd>,
    scratch: Vec<u8>,
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_pkt(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let mut tmp = [0u8; 4 + 2048];
    let n = unsafe { libc::read(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n <= 4 {
        return Ok(0);
    }
    let len = (n - 4).min(buf.len());
    let mtu = crate::transport::tun_mtu();
    if len > mtu {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| log::warn!("TUN fd delivered a {len}-byte packet but the carrier's MTU is {mtu}: dropping (set the interface MTU to {mtu})"));
        return Ok(0);
    }
    buf[..len].copy_from_slice(&tmp[4..4 + len]);
    Ok(len)
}

impl TunDevice {
    pub fn start_reader(&mut self) {}

    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_pkt(self.fd.as_raw_fd(), buf)
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| read_pkt(inner.get_ref().as_raw_fd(), buf)) {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }

    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.scratch.clear();
        self.scratch.extend_from_slice(&[0, 0, 0, if buf[0] >> 4 == 6 { AF_INET6 } else { AF_INET }]);
        self.scratch.extend_from_slice(buf);
        loop {
            let mut guard = self.fd.writable().await?;
            let scratch = &self.scratch;
            match guard.try_io(|inner| {
                let n = unsafe { libc::write(inner.get_ref().as_raw_fd(), scratch.as_ptr().cast(), scratch.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r.map(|n| n.saturating_sub(4)),
                Err(_) => continue,
            }
        }
    }
}

pub fn open(cfg: &TunConfig) -> io::Result<TunDevice> {
    let fd = match cfg.fd.filter(|f| *f >= 0) {
        Some(fd) => fd,
        None => {
            let provider = PROVIDER.lock().unwrap().clone();
            let provider = provider.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "iOS needs a TUN fd (tun_fd or an fd provider)")
            })?;
            provider(cfg.addr, cfg.prefix)?
        }
    };
    set_nonblocking(fd)?;
    #[allow(deprecated)] // `register` needs an owned fd; the extension owns this one
    let fd = AsyncFd::new(fd)?;
    log::info!("utun fd up: {}/{} mtu {}", cfg.addr, cfg.prefix, crate::transport::tun_mtu());
    Ok(TunDevice { fd, scratch: Vec::with_capacity(1604) })
}

pub fn ensure_host_firewall() {}

/// `recover` has nothing to undo here (the extension owns the interface).
pub fn recover_cli() -> i32 {
    0
}

/// macOS socket pinning (see `transport::bind_marked`): the harness has no tunnel route to dodge.
#[cfg(target_os = "macos")]
pub fn physical_ifindex() -> Option<u32> {
    None
}

pub const TUNNEL_MARK: u32 = 1;
