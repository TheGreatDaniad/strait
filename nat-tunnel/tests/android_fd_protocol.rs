//! Rust half of the Android fd-socket protocol, against a fake Kotlin peer.
#![cfg(unix)]
#[path = "../src/android_fd_proto.rs"]
mod proto;

use std::net::Ipv4Addr;

const GW: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);

#[test]
fn addr_roundtrip_and_rejects() {
    let line = proto::encode_addr(Ipv4Addr::new(10, 7, 0, 3), 16, GW);
    assert_eq!(line, "STRAIT-ADDR 10.7.0.3/16 10.7.0.1\n");
    assert_eq!(proto::decode_addr(&line), Some((Ipv4Addr::new(10, 7, 0, 3), 16, GW)));
    for bad in [
        "",
        "HELLO 10.7.0.3/16 10.7.0.1",
        "STRAIT-ADDR 10.7.0.3 10.7.0.1",
        "STRAIT-ADDR 10.7.0.3/0 10.7.0.1",
        "STRAIT-ADDR 10.7.0.3/33 10.7.0.1",
        "STRAIT-ADDR x/16 10.7.0.1",
        "STRAIT-ADDR 10.7.0.3/16 10.7.0.1 extra",
    ] {
        assert_eq!(proto::decode_addr(bad), None, "{bad}");
    }
}

#[test]
fn fake_kotlin_receives_address_then_sends_fd() {
    let mut sv = [0i32; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
    let (guest, kotlin) = (sv[0], sv[1]);
    // The fd Kotlin hands over: the write end of a pipe.
    let mut p = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
    let (pr, pw) = (p[0], p[1]);

    let peer = std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        let mut got = Vec::new();
        while !got.ends_with(b"\n") {
            let n = unsafe { libc::read(kotlin, buf.as_mut_ptr() as *mut _, buf.len()) };
            assert!(n > 0);
            got.extend_from_slice(&buf[..n as usize]);
        }
        let addr = proto::decode_addr(std::str::from_utf8(&got).unwrap());
        // Same shape as LocalSocket.setFileDescriptorsForSend + write(1).
        let mut byte = [1u8];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut _;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            *(libc::CMSG_DATA(c) as *mut i32) = pw;
            assert_eq!(libc::sendmsg(kotlin, &msg, 0), 1);
            libc::close(kotlin);
        }
        addr
    });

    let fd = proto::request_fd(guest, Ipv4Addr::new(10, 7, 0, 3), 16, GW).unwrap();
    assert_eq!(peer.join().unwrap(), Some((Ipv4Addr::new(10, 7, 0, 3), 16, GW)));
    assert_eq!(unsafe { libc::write(fd, b"x".as_ptr() as *const _, 1) }, 1);
    let mut b = [0u8; 1];
    assert_eq!(unsafe { libc::read(pr, b.as_mut_ptr() as *mut _, 1) }, 1);
    assert_eq!(b[0], b'x');
}
