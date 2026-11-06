//! Drives the C ABI exactly as Swift will: C strings, a status callback, a datagram fd with the
//! 4-byte AF header standing in for the utun. Run:
//!   cargo test --no-default-features --features ffi --test ffi_harness -- --test-threads=1
//! The live test (real VPS, needs the internet) is `#[ignore]`: add `-- --ignored`.
#![cfg(all(feature = "ffi", target_os = "macos"))]

use std::ffi::{c_char, c_void, CStr, CString};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nat_tunnel::ffi::*;

static EVENTS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());

extern "C" fn on_status(json: *const c_char, _user: *mut c_void) {
    let s = unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned();
    EVENTS.lock().unwrap().push(serde_json::from_str(&s).expect("status is JSON"));
}

fn wait_event(f: impl Fn(&serde_json::Value) -> bool, secs: u64) -> serde_json::Value {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(e) = EVENTS.lock().unwrap().iter().find(|e| f(e)) {
            return e.clone();
        }
        assert!(Instant::now() < end, "timeout; events: {:?}", EVENTS.lock().unwrap());
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = b.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(src: [u8; 4], dst: [u8; 4], seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x54, 0x55, (seq >> 8) as u8, seq as u8, b't', b'u', b't', b'u', b'n'];
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&icmp);
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p
}

/// UDP DNS query for example.com A -> `dst`:53 (the userspace exit proxies UDP, not ICMP).
fn dns_query(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in ["example", "com"] {
        dns.push(l.len() as u8);
        dns.extend_from_slice(l.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut udp = vec![0xc3, 0x50, 0, 53, 0, 0, 0, 0];
    udp.extend_from_slice(&dns);
    let n = udp.len() as u16;
    udp[4..6].copy_from_slice(&n.to_be_bytes());
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&udp);
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p
}

/// The "kernel" side of a fake utun: a datagram socketpair. Returns (rust_end, test_end).
fn fake_utun() -> (i32, i32) {
    let mut sv = [0i32; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) }, 0);
    (sv[0], sv[1])
}

fn ping_through(kernel: i32, my_ip: [u8; 4], dst: [u8; 4]) -> bool {
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe { libc::setsockopt(kernel, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&tv as *const libc::timeval).cast(), 16) };
    for seq in 1..=8u16 {
        let mut frame = vec![0, 0, 0, 2];
        // Odd tries ICMP echo (kernel-TUN hosts), even tries DNS over UDP (userspace-exit hosts).
        frame.extend(if seq % 2 == 1 { echo_request(my_ip, dst, seq) } else { dns_query(my_ip, [1, 1, 1, 1]) });
        assert!(unsafe { libc::write(kernel, frame.as_ptr().cast(), frame.len()) } > 0);
        let mut buf = [0u8; 2048];
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            let n = unsafe { libc::read(kernel, buf.as_mut_ptr().cast(), buf.len()) };
            if n >= 4 + 28 && buf[3] == 2 {
                let icmp_reply = buf[4 + 9] == 1 && buf[4 + 20] == 0 && buf[4 + 12..4 + 16] == dst;
                let dns_reply = buf[4 + 9] == 17 && buf[4 + 20..4 + 22] == [0, 53] && buf[4 + 28..4 + 30] == [0x12, 0x34];
                if icmp_reply || dns_reply {
                    return true;
                }
            }
        }
    }
    false
}

/// Shared scenario: start -> needTun/connecting -> (fd) -> connected -> ping -> stop.
fn scenario(invite: &str, early_fd: bool, ping_dst: [u8; 4]) -> (i32, serde_json::Value) {
    EVENTS.lock().unwrap().clear();
    let (rust_end, kernel) = fake_utun();
    let h = unsafe {
        strait_client_start(cs(invite).as_ptr(), if early_fd { rust_end } else { -1 }, std::ptr::null(), Some(on_status), std::ptr::null_mut())
    };
    assert!(!h.is_null());
    let assigned = wait_event(|e| e["ip"].as_str().is_some_and(|ip| ip.starts_with("10.7.0.")), 30);
    assert_eq!(assigned["state"], "connecting");
    if !early_fd {
        wait_event(|e| e["needTun"] == true, 30); // "ask for the fd" event, after the address is known
        assert_eq!(unsafe { strait_client_set_fd(h, rust_end) }, 0);
    }
    let connected = wait_event(|e| e["state"] == "connected", 30);
    let ip: Vec<u8> = connected["ip"].as_str().unwrap().split('.').map(|x| x.parse().unwrap()).collect();
    assert!(ping_through(kernel, [ip[0], ip[1], ip[2], ip[3]], ping_dst), "no ICMP echo reply via the tunnel");
    let t = Instant::now();
    assert_eq!(unsafe { strait_client_stop(h) }, 0, "stop did not finish in 2 s");
    assert!(t.elapsed() < Duration::from_secs(2));
    let states: Vec<String> = EVENTS.lock().unwrap().iter().map(|e| e["state"].as_str().unwrap().to_string()).collect();
    let first_conn = states.iter().position(|s| s == "connecting").expect("connecting seen");
    let first_ok = states.iter().position(|s| s == "connected").unwrap();
    assert!(first_conn < first_ok, "order: {states:?}");
    assert_eq!(states.last().unwrap(), "idle", "{states:?}");
    unsafe { libc::close(kernel) };
    (0, connected)
}

#[test]
fn utility_calls() {
    let v = unsafe { CStr::from_ptr(strait_version()) }.to_str().unwrap();
    assert!(!v.is_empty());
    let mut k = [0 as c_char; 33];
    assert_eq!(unsafe { strait_generate_key(k.as_mut_ptr()) }, 0);
    let key = unsafe { CStr::from_ptr(k.as_ptr()) }.to_str().unwrap();
    assert!(key.len() == 32 && key.bytes().all(|b| b.is_ascii_hexdigit()));
    // Null / tiny buffers must not crash.
    assert_eq!(unsafe { strait_generate_key(std::ptr::null_mut()) }, -1);
    let mut small = [0 as c_char; 4];
    assert_eq!(unsafe { strait_probe(cs("sig").as_ptr(), small.as_mut_ptr(), small.len()) }, -2);
    let mut out = vec![0 as c_char; 8192];
    let n = unsafe { strait_probe(cs("sig").as_ptr(), out.as_mut_ptr(), out.len()) };
    assert!(n > 0);
    let rows: serde_json::Value = serde_json::from_str(unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap()).unwrap();
    assert_eq!(rows[0]["id"], "sig");
    // Bad invite / no callback -> NULL, no panic.
    assert!(unsafe { strait_client_start(cs("garbage").as_ptr(), -1, std::ptr::null(), Some(on_status), std::ptr::null_mut()) }.is_null());
    assert!(unsafe { strait_client_start(cs("STRAIT2|00112233445566778899aabbccddeeff|127.0.0.1:1").as_ptr(), -1, std::ptr::null(), None, std::ptr::null_mut()) }.is_null());
}

struct Local(Child);
impl Drop for Local {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn local_host_both_fd_paths() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let invite = format!("STRAIT2|00112233445566778899aabbccddeeff|127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nat-tunnel"))
        .args(["host", "--invite", &invite, "--tun", "10.7.0.1/16", "--userspace", "--max-clients", "2"])
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let err = BufReader::new(child.stderr.take().unwrap());
    let log = std::sync::Arc::new(Mutex::new(String::new()));
    for r in [Box::new(out) as Box<dyn BufRead + Send>, Box::new(err)] {
        let log = log.clone();
        std::thread::spawn(move || r.lines().map_while(Result::ok).for_each(|l| log.lock().unwrap().push_str(&(l + "\n"))));
    }
    let _host = Local(child);
    std::thread::sleep(Duration::from_secs(1));
    // DNS to 1.1.1.1 through the host's userspace exit (needs the Mac's internet).
    scenario(&invite, true, [1, 1, 1, 1]);
    scenario(&invite, false, [1, 1, 1, 1]);
    let end = Instant::now() + Duration::from_secs(5);
    while !log.lock().unwrap().contains("left:") && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let l = log.lock().unwrap().clone();
    assert!(l.contains("left:"), "host never saw the client leave:\n{l}");
}

#[test]
#[ignore = "live: real VPS 203.0.113.10:7100, needs the internet"]
fn live_vps() {
    let invite = "STRAIT2|0123456789abcdef0123456789abcdef|203.0.113.10:7100";
    let (_, connected) = scenario(invite, false, [1, 1, 1, 1]);
    eprintln!("live connected: {connected}");
    assert_eq!(connected["path"], "direct");
    // Operator check (read-only): journalctl on the VPS must show `left: client left`.
}
