//! Android TUN support.
//!
//! Android's VpnService owns the TUN interface, its address, routes and DNS.
//! The app only needs to read/write whole IP packets on an existing fd, so the
//! desktop tunmode (which creates interfaces and rewrites routes) is not used.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};

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

pub struct TunDevice {
    fd: AsyncFd<RawFd>,
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl TunDevice {
    pub fn start_reader(&mut self) {}

    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet"));
            }
            return Err(err);
        }
        Ok(n as usize)
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
    }

    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
    }
}


#[path = "android_fd_proto.rs"]
pub mod proto;

/// Connect to Kotlin's fd socket, announce the assigned address, receive the TUN fd.
fn recv_fd(name: &str, ip: Ipv4Addr, prefix: u8, gw: Ipv4Addr) -> io::Result<i32> {
    use std::mem::{size_of, zeroed};
    use std::os::unix::ffi::OsStrExt;

    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = name.as_bytes();
    let len = if let Some(rest) = path.strip_prefix(b"@") {
        // Linux abstract namespace.
        addr.sun_path[0] = 0;
        let n = rest.len().min(addr.sun_path.len() - 1);
        for (i, b) in rest[..n].iter().enumerate() {
            addr.sun_path[i + 1] = *b as libc::c_char;
        }
        size_of::<libc::sa_family_t>() + 1 + n
    } else {
        let n = path.len().min(addr.sun_path.len() - 1);
        for (i, b) in path[..n].iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        size_of::<libc::sa_family_t>() + n + 1
    };

    let mut last_err = None;
    let mut connected = false;
    for _ in 0..50 {
        let rc = unsafe {
            libc::connect(
                sock,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        };
        if rc == 0 {
            connected = true;
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            last_err = Some(err);
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }
        last_err = Some(err);
        break;
    }
    if !connected {
        unsafe { libc::close(sock) };
        return Err(last_err.unwrap_or_else(|| io::Error::other("fd socket connect failed")));
    }

    let r = proto::request_fd(sock, ip, prefix, gw);
    unsafe { libc::close(sock) };
    r
}

pub fn open(cfg: &TunConfig) -> io::Result<TunDevice> {
    let fd = if let Some(name) = &cfg.fd_socket {
        recv_fd(name, cfg.addr, cfg.prefix, Ipv4Addr::new(10, 7, 0, 1))?
    } else {
        cfg.fd.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Android requires --tun-fd or --tun-fd-socket")
        })?
    };
    set_nonblocking(fd)?;
    // VpnService TUNs may advertise checksum offload. Linux then forwards
    // packets with partial checksums; the exit kernel drops TCP/UDP. Turn
    // offload off so the kernel computes checksums before the app sees them.
    const TUNSETOFFLOAD: libc::c_int = 0x4004_54d0;
    let offload: u32 = 0;
    let rc = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, &offload) };
    if rc != 0 {
        log::debug!("TUNSETOFFLOAD failed: {}", io::Error::last_os_error());
    }
    let fd = AsyncFd::new(fd)?;
    log::info!("android tun fd up: {}/{} mtu 1400", cfg.addr, cfg.prefix);
    Ok(TunDevice { fd })
}

pub fn ensure_host_firewall() {}

/// `recover` has nothing to undo on Android (the VpnService owns the interface).
pub fn recover_cli() -> i32 {
    0
}
