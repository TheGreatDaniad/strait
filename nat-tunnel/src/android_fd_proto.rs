//! Wire protocol between the Rust guest and the Kotlin VpnService fd socket.
//!
//! The guest connects to Kotlin's abstract unix socket, sends one text line
//! `STRAIT-ADDR <ip>/<prefix> <gateway>\n` with the address the host assigned,
//! and Kotlin builds the VPN interface with exactly that address, then answers
//! with one byte carrying the TUN fd (SCM_RIGHTS). A Kotlin peer that predates
//! the line simply ignores it; mirrored by FdProtocol.kt.
//! Included by `#[path]` from tunmode_android.rs and tests/android_fd_protocol.rs
//! so it stays testable off-device.

use std::io;
use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

pub const ADDR_TAG: &str = "STRAIT-ADDR";

pub fn encode_addr(ip: Ipv4Addr, prefix: u8, gw: Ipv4Addr) -> String {
    format!("{ADDR_TAG} {ip}/{prefix} {gw}\n")
}

pub fn decode_addr(line: &str) -> Option<(Ipv4Addr, u8, Ipv4Addr)> {
    let mut it = line.trim().split(' ');
    if it.next()? != ADDR_TAG {
        return None;
    }
    let (ip, prefix) = it.next()?.split_once('/')?;
    let gw = it.next()?.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if it.next().is_some() || prefix == 0 || prefix > 32 {
        return None;
    }
    Some((ip.parse().ok()?, prefix, gw))
}

/// On a connected unix stream socket: announce the address, then receive the TUN fd.
pub fn request_fd(sock: RawFd, ip: Ipv4Addr, prefix: u8, gw: Ipv4Addr) -> io::Result<RawFd> {
    let line = encode_addr(ip, prefix, gw);
    let mut sent = 0;
    while sent < line.len() {
        let n = unsafe {
            libc::write(sock, line.as_ptr().add(sent) as *const libc::c_void, line.len() - sent)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        sent += n as usize;
    }
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut control = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;
    if unsafe { libc::recvmsg(sock, &mut msg, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        if unsafe { (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS } {
            return Ok(unsafe { *(libc::CMSG_DATA(cmsg) as *const i32) });
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "no file descriptor received"))
}
