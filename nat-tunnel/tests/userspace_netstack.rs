//! Drives the real smoltcp netstack headlessly: the stack is a Sink/Stream of
//! raw IPv4 packets, so a hand-built TCP client can talk to `serve_tcp_with`
//! exactly as the mux host does, without a TUN device.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nat_tunnel::userspace::{build, serve_tcp_with, ExitConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// The exit policy is process-global; tests that touch it run one at a time.
static POLICY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn csum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut odd: Option<u8> = None;
    for p in parts {
        for &b in p.iter() {
            match odd.take() {
                Some(hi) => sum += u16::from_be_bytes([hi, b]) as u32,
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u16::from_be_bytes([hi, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn v4(a: SocketAddr) -> (Ipv4Addr, u16) {
    match a {
        SocketAddr::V4(a) => (*a.ip(), a.port()),
        _ => unreachable!(),
    }
}

fn tcp_packet(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_packet_opts(src, dst, seq, ack, flags, payload, &[])
}

/// `opts` must be a multiple of 4 bytes.
fn tcp_packet_opts(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8, payload: &[u8], opts: &[u8]) -> Vec<u8> {
    let ((sip, sp), (dip, dp)) = (v4(src), v4(dst));
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sp.to_be_bytes());
    tcp.extend_from_slice(&dp.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[(5 + opts.len() as u8 / 4) << 4, flags]);
    tcp.extend_from_slice(&8192u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);
    tcp.extend_from_slice(opts);
    tcp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&sip.octets());
    pseudo.extend_from_slice(&dip.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    let c = csum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&sip.octets());
    ip.extend_from_slice(&dip.octets());
    let c = csum(&[&ip]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&tcp);
    ip
}

#[derive(Debug)]
struct Seg {
    /// The client port this segment is addressed to.
    port: u16,
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn parse(p: &[u8]) -> Option<Seg> {
    if p.len() < 40 || p[0] >> 4 != 4 || p[9] != 6 {
        return None;
    }
    let ihl = ((p[0] & 15) * 4) as usize;
    let t = &p[ihl..];
    let off = ((t[12] >> 4) * 4) as usize;
    Some(Seg {
        port: u16::from_be_bytes([t[2], t[3]]),
        seq: u32::from_be_bytes(t[4..8].try_into().unwrap()),
        flags: t[13],
        payload: t[off..].to_vec(),
    })
}

async fn echo() -> SocketAddr {
    nat_tunnel::userspace::set_exit_policy(false, true); // lab: echo server on 127.0.0.1
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn netstack_enforces_flow_cap_and_returns_permits() {
    let _g = POLICY_LOCK.lock().await;
    let echo = echo().await;
    let host = build(1400).unwrap();
    let sem = Arc::new(Semaphore::new(2));
    let cfg = ExitConfig { max_tcp: 2, ..Default::default() };
    tokio::spawn(serve_tcp_with(host.tcp, cfg, Some(sem.clone())));
    let (mut sink, mut stream) = host.stack.split();

    let client = |i: u16| SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 40000 + i));
    let isn = 1000u32;
    // Per flow: next client seq and server seq (learned from SYN-ACK).
    let mut next: HashMap<u16, (u32, u32)> = HashMap::new();
    let mut echoed: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut reset: Vec<u16> = Vec::new();

    for i in 0..3u16 {
        sink.send(tcp_packet(client(i), echo, isn, 0, SYN, &[])).await.unwrap();
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(pkt))) = tokio::time::timeout(Duration::from_millis(300), stream.next()).await else {
            if echoed.len() == 2 && reset.len() == 1 {
                break;
            }
            continue;
        };
        let Some(seg) = parse(&pkt) else { continue };
        let i = seg.port - 40000;
        if seg.flags & RST != 0 {
            reset.push(i);
        } else if seg.flags & (SYN | ACK) == (SYN | ACK) {
            let sseq = seg.seq.wrapping_add(1);
            next.insert(i, (isn + 1, sseq));
            sink.send(tcp_packet(client(i), echo, isn + 1, sseq, ACK, &[])).await.unwrap();
            sink.send(tcp_packet(client(i), echo, isn + 1, sseq, PSH | ACK, b"hi")).await.unwrap();
        } else if !seg.payload.is_empty() {
            echoed.entry(i).or_insert(seg.payload); // later copies are retransmits (we do not ACK data)
        } else if seg.flags & FIN != 0 && !echoed.contains_key(&i) && !reset.contains(&i) {
            reset.push(i); // refused flows may close with FIN instead of RST
        }
    }
    assert_eq!(echoed.len(), 2, "served {echoed:?} reset {reset:?}");
    assert!(echoed.values().all(|v| v == b"hi"));
    assert_eq!(reset.len(), 1, "exactly one flow beyond the cap is refused");
    assert!(!echoed.contains_key(&reset[0]));
    assert_eq!(sem.available_permits(), 0);

    // Client FINs on the served flows: permits come back.
    for (&i, &(cseq, sseq)) in &next {
        if echoed.contains_key(&i) {
            sink.send(tcp_packet(client(i), echo, cseq + 2, sseq + 2, FIN | ACK, &[])).await.unwrap();
        }
    }
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while sem.available_permits() != 2 && tokio::time::Instant::now() < end {
        // ACK the stack's FIN on served flows so it can finish closing.
        if let Ok(Some(Ok(p))) = tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
            if let Some(g) = parse(&p).filter(|g| g.flags & FIN != 0) {
                let i = g.port - 40000;
                if let (true, Some(&(cseq, _))) = (echoed.contains_key(&i), next.get(&i)) {
                    sink.send(tcp_packet(client(i), echo, cseq + 3, g.seq.wrapping_add(1), ACK, &[])).await.unwrap();
                }
            }
        }
    }
    assert_eq!(sem.available_permits(), 2);
}

/// The stack must advertise a window big enough for a long path: a SYN offering window scaling gets
/// a SYN-ACK whose shift covers `TCP_BUF` (64 KiB gave shift 1 and ~7.5 Mbit/s at 66 ms).
#[tokio::test]
async fn syn_ack_advertises_a_window_for_long_paths() {
    let _g = POLICY_LOCK.lock().await;
    let echo = echo().await;
    let host = build(1400).unwrap();
    tokio::spawn(serve_tcp_with(host.tcp, ExitConfig::default(), None));
    let (mut sink, mut stream) = host.stack.split();
    let c = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 41000));
    // MSS 1360, NOP, window scale 7, NOP, NOP (padding)
    let opts = [2, 4, 0x05, 0x50, 1, 3, 3, 7];
    sink.send(tcp_packet_opts(c, echo, 1000, 0, SYN, &[], &opts)).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let p = stream.next().await.unwrap().unwrap();
            if parse(&p).is_some_and(|s| s.flags & (SYN | ACK) == (SYN | ACK)) {
                return p;
            }
        }
    })
    .await
    .expect("no SYN-ACK");
    let t = &pkt[((pkt[0] & 15) * 4) as usize..];
    let (off, win) = (((t[12] >> 4) * 4) as usize, u16::from_be_bytes([t[14], t[15]]) as u64);
    let mut o = &t[20..off];
    let mut shift = None;
    while let Some(&k) = o.first() {
        match k {
            0 => break,
            1 => o = &o[1..],
            _ => {
                if k == 3 {
                    shift = Some(o[2]);
                }
                o = &o[o[1] as usize..];
            }
        }
    }
    let shift = shift.expect("SYN-ACK must carry a window-scale option");
    let max_window = 65535u64 << shift;
    assert!(max_window >= nat_tunnel::userspace::TCP_BUF as u64, "shift {shift} (window field {win}) cannot cover the buffer");
}

/// A guest flow to a host loopback listener is dropped by the stack filter by default (no SYN-ACK,
/// nothing reaches the listener) and works once the loopback opt-in is set.
#[tokio::test]
async fn guest_flow_to_host_loopback_is_refused_unless_opted_in() {
    let _g = POLICY_LOCK.lock().await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = l.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n = accepted.clone();
    tokio::spawn(async move {
        while l.accept().await.is_ok() {
            n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let host = build(1400).unwrap();
    tokio::spawn(serve_tcp_with(host.tcp, ExitConfig::default(), None));
    let (mut sink, mut stream) = host.stack.split();
    let c = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 42000));
    let synack = |p: Vec<u8>| parse(&p).is_some_and(|s| s.flags & (SYN | ACK) == (SYN | ACK));

    nat_tunnel::userspace::set_exit_policy(false, false);
    sink.send(tcp_packet(c, target, 1000, 0, SYN, &[])).await.unwrap();
    let got = tokio::time::timeout(Duration::from_millis(700), async {
        while let Some(Ok(p)) = stream.next().await {
            if synack(p) {
                return true;
            }
        }
        false
    })
    .await;
    assert!(got.is_err(), "default policy must not answer a SYN to loopback");
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);

    nat_tunnel::userspace::set_exit_policy(false, true);
    let c2 = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 42001));
    sink.send(tcp_packet(c2, target, 1000, 0, SYN, &[])).await.unwrap();
    let ok = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(p)) = stream.next().await {
            if synack(p) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(ok, Ok(true), "opt-in must restore the flow");
    nat_tunnel::userspace::set_exit_policy(false, false);
}
