//! Real-internet test of the mux client against a live `nat-tunnel host --userspace`.
//! Userspace guest: hand-built IPv4 packets, no TUN, no sudo.
//!
//!   STRAIT_VPS_INVITE='STRAIT2|<key>|<ip>:7100' [STRAIT_VPS_V6='[v6]:7100'] \
//!   [STRAIT_VPS_BULK='host/path'] cargo test --test vps_client -- --ignored --nocapture --test-threads=1

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use nat_tunnel::invite::{Endpoint, Invite};
use nat_tunnel::transport::{has_v6_route, ConnectError, ConnectOpts, Event, Tunnel};

fn invite() -> (String, Vec<SocketAddr>) {
    let inv = Invite::parse(&std::env::var("STRAIT_VPS_INVITE").expect("STRAIT_VPS_INVITE")).expect("invite");
    let hosts = inv
        .hosts
        .iter()
        .map(|e| match e {
            Endpoint::Addr(a) => *a,
            other => other.to_string().to_socket_addrs().unwrap().next().unwrap(),
        })
        .collect();
    (inv.key, hosts)
}

async fn join_with(key: &str, hosts: &[SocketAddr], v6: bool) -> Result<Tunnel, ConnectError> {
    let o = ConnectOpts { signal: None, peer: None, room: "", key, host: false, bind_port: None, hosts: vec![], mux: true };
    let mut t = Tunnel::connect_ladder(o, hosts, v6, false).await?;
    t.enable_packet_mode();
    Ok(t)
}

struct Cli {
    t: Tunnel,
    ip: Ipv4Addr,
    id: u16,
}

impl Cli {
    async fn join(key: &str, hosts: &[SocketAddr]) -> (Self, Duration) {
        let s = Instant::now();
        let t = join_with(key, hosts, has_v6_route()).await.expect("join");
        let d = s.elapsed();
        let (ip, prefix, gw) = t.assigned().expect("ASSIGN");
        println!("joined in {d:?}: {ip}/{prefix} gw {gw} via {:?}", t.peer());
        assert_eq!(ip.octets()[..2], [10, 7]);
        (Self { t, ip, id: 1 }, d)
    }
    async fn send(&mut self, p: &[u8]) {
        self.t.send_packet(p).await.unwrap();
    }
    /// Next inbound IP packet within `d`; keeps keepalives ticking.
    async fn recv(&mut self, d: Duration) -> Option<Vec<u8>> {
        let end = Instant::now() + d;
        loop {
            self.t.tick().await.unwrap();
            match self.t.try_recv().await.unwrap() {
                Some(Event::Data(p)) => return Some(p),
                Some(Event::Closed) => panic!("host closed the session"),
                None => {
                    let left = end.checked_duration_since(Instant::now())?;
                    let _ = tokio::time::timeout(left.min(Duration::from_millis(50)), self.t.readable()).await;
                }
            }
        }
    }
    fn next_id(&mut self) -> u16 {
        self.id = self.id.wrapping_add(1);
        self.id
    }
}

fn csum(parts: &[&[u8]]) -> u16 {
    let mut s = 0u32;
    let mut odd: Option<u8> = None;
    for p in parts {
        for &b in *p {
            match odd.take() {
                Some(h) => s += u16::from_be_bytes([h, b]) as u32,
                None => odd = Some(b),
            }
        }
    }
    if let Some(h) = odd {
        s += (h as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, (id >> 8) as u8, id as u8, 0x40, 0, 64, proto, 0, 0];
    p.extend(src.octets());
    p.extend(dst.octets());
    p[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    let c = csum(&[&p]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend(body);
    p
}

fn pseudo(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> Vec<u8> {
    let mut v = src.octets().to_vec();
    v.extend(dst.octets());
    v.extend([0, proto]);
    v.extend((len as u16).to_be_bytes());
    v
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, id_ip: u16) -> Vec<u8> {
    let mut b = vec![8, 0, 0, 0, (id >> 8) as u8, id as u8, (seq >> 8) as u8, seq as u8];
    b.extend((0..32u8).map(|i| i ^ (id as u8)));
    let c = csum(&[&b]);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 1, id_ip, &b)
}

fn udp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, data: &[u8], id: u16) -> Vec<u8> {
    let len = 8 + data.len();
    let mut b = [sp.to_be_bytes(), dp.to_be_bytes(), (len as u16).to_be_bytes(), [0, 0]].concat();
    b.extend(data);
    let c = csum(&[&pseudo(src, dst, 17, len), &b]);
    b[6..8].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 17, id, &b)
}

/// (proto, src, dst, payload) of a well-formed IPv4 packet.
fn parse(p: &[u8]) -> Option<(u8, Ipv4Addr, Ipv4Addr, &[u8])> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 15) as usize * 4;
    let tot = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || tot > p.len() || tot < ihl {
        return None;
    }
    Some((p[9], Ipv4Addr::new(p[12], p[13], p[14], p[15]), Ipv4Addr::new(p[16], p[17], p[18], p[19]), &p[ihl..tot]))
}

fn dns_query(name: &str, qid: u16) -> Vec<u8> {
    let mut q = vec![(qid >> 8) as u8, qid as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend(l.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    q
}

/// A-record addresses of a DNS response (names compressed or not).
fn dns_answers(r: &[u8], qid: u16) -> Vec<Ipv4Addr> {
    assert!(r.len() > 12 && u16::from_be_bytes([r[0], r[1]]) == qid, "bad dns header");
    assert_eq!(r[3] & 15, 0, "rcode");
    let skip = |mut i: usize| {
        loop {
            match r[i] {
                0 => return i + 1,
                l if l & 0xc0 == 0xc0 => return i + 2,
                l => i += 1 + l as usize,
            }
        }
    };
    let mut i = skip(12) + 4;
    let mut out = vec![];
    for _ in 0..u16::from_be_bytes([r[6], r[7]]) {
        i = skip(i);
        let (ty, rdl) = (u16::from_be_bytes([r[i], r[i + 1]]), u16::from_be_bytes([r[i + 8], r[i + 9]]) as usize);
        if ty == 1 && rdl == 4 {
            out.push(Ipv4Addr::new(r[i + 10], r[i + 11], r[i + 12], r[i + 13]));
        }
        i += 10 + rdl;
    }
    out
}

async fn ping(c: &mut Cli, dst: Ipv4Addr, n: u16) -> Vec<Duration> {
    let mut rtts = vec![];
    let id = 0x7000 + c.ip.octets()[3] as u16;
    for seq in 0..n {
        let ipid = c.next_id();
        let p = icmp_echo(c.ip, dst, id, seq, ipid);
        let s = Instant::now();
        c.send(&p).await;
        while let Some(r) = c.recv(Duration::from_millis(1000).saturating_sub(s.elapsed())).await {
            if let Some((1, from, to, b)) = parse(&r) {
                if b[0] == 0 && from == dst && to == c.ip && u16::from_be_bytes([b[4], b[5]]) == id && u16::from_be_bytes([b[6], b[7]]) == seq {
                    rtts.push(s.elapsed());
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    rtts
}

fn rtt_report(what: &str, n: u16, r: &[Duration]) {
    let ms: Vec<f64> = r.iter().map(|d| d.as_secs_f64() * 1e3).collect();
    let (mn, mx) = ms.iter().fold((f64::MAX, 0f64), |a, &x| (a.0.min(x), a.1.max(x)));
    println!(
        "{what}: {}/{n} replies, loss {:.0}%, rtt min/avg/max = {mn:.1}/{:.1}/{mx:.1} ms",
        ms.len(),
        100.0 * (n as usize - ms.len()) as f64 / n as f64,
        ms.iter().sum::<f64>() / ms.len().max(1) as f64
    );
}

async fn dns(c: &mut Cli, server: Ipv4Addr, name: &str) -> Vec<Ipv4Addr> {
    let qid = 0x4242;
    let ipid = c.next_id();
    c.send(&udp(c.ip, server, 40000, 53, &dns_query(name, qid), ipid)).await;
    while let Some(r) = c.recv(Duration::from_secs(5)).await {
        if let Some((17, from, _, b)) = parse(&r) {
            if from == server && b.len() > 8 && u16::from_be_bytes([b[2], b[3]]) == 40000 {
                return dns_answers(&b[8..], qid);
            }
        }
    }
    panic!("no DNS answer from {server}");
}

// ---- minimal TCP client -------------------------------------------------

struct Tcp {
    dst: Ipv4Addr,
    sp: u16,
    dp: u16,
    seq: u32,
    ack: u32,
}

const SYN: u8 = 2;
const FIN: u8 = 1;
const RST: u8 = 4;
const PSH: u8 = 8;
const ACK: u8 = 16;

impl Tcp {
    fn seg(&self, c: &mut Cli, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut h = [self.sp.to_be_bytes(), self.dp.to_be_bytes()].concat();
        h.extend(self.seq.to_be_bytes());
        h.extend(if flags & ACK != 0 { self.ack } else { 0 }.to_be_bytes());
        let mss: &[u8] = if flags & SYN != 0 { &[2, 4, 0x05, 0x40] } else { &[] };
        h.extend([((20 + mss.len()) as u8 / 4) << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
        h.extend(mss);
        h.extend(data);
        let c2 = csum(&[&pseudo(c.ip, self.dst, 6, h.len()), &h]);
        h[16..18].copy_from_slice(&c2.to_be_bytes());
        let id = c.next_id();
        ipv4(c.ip, self.dst, 6, id, &h)
    }

    async fn recv_seg(&self, c: &mut Cli, d: Duration) -> Option<(u8, u32, u32, Vec<u8>)> {
        let end = Instant::now() + d;
        while let Some(r) = c.recv(end.checked_duration_since(Instant::now())?).await {
            if let Some((6, from, to, b)) = parse(&r) {
                if from == self.dst && to == c.ip && b.len() >= 20 && u16::from_be_bytes([b[0], b[1]]) == self.dp && u16::from_be_bytes([b[2], b[3]]) == self.sp {
                    let off = (b[12] >> 4) as usize * 4;
                    return Some((b[13], u32::from_be_bytes(b[4..8].try_into().unwrap()), u32::from_be_bytes(b[8..12].try_into().unwrap()), b[off..].to_vec()));
                }
            }
        }
        None
    }

    async fn connect(c: &mut Cli, dst: Ipv4Addr, dp: u16, sp: u16) -> (Self, Duration) {
        let mut t = Tcp { dst, sp, dp, seq: 0x1000_0000 + sp as u32, ack: 0 };
        let s = Instant::now();
        for _ in 0..3 {
            let syn = t.seg(c, SYN, &[]);
            c.send(&syn).await;
            while let Some((f, seq, ack, _)) = t.recv_seg(c, Duration::from_secs(3)).await {
                if f & (SYN | ACK) == (SYN | ACK) && ack == t.seq + 1 {
                    t.seq += 1;
                    t.ack = seq + 1;
                    let a = t.seg(c, ACK, &[]);
                    c.send(&a).await;
                    return (t, s.elapsed());
                }
                if f & RST != 0 {
                    panic!("RST to SYN for {dst}:{dp}");
                }
            }
        }
        panic!("no SYN-ACK from {dst}:{dp}");
    }

    /// Send `req`, read until FIN, idle 5 s, or `max` bytes. Returns (bytes, first_byte_latency, total).
    async fn exchange(&mut self, c: &mut Cli, req: &[u8], max: usize) -> (Vec<u8>, Duration, Duration) {
        let s = Instant::now();
        let p = self.seg(c, PSH | ACK, req);
        c.send(&p).await;
        let sent = self.seq.wrapping_add(req.len() as u32);
        self.seq = sent;
        let (mut body, mut first, mut resent) = (vec![], None, false);
        let mut last_rx = Instant::now();
        while body.len() < max {
            let Some((f, seq, _, data)) = self.recv_seg(c, Duration::from_secs(1)).await else {
                if last_rx.elapsed() > Duration::from_secs(5) {
                    break;
                }
                if body.is_empty() && !resent && last_rx.elapsed() > Duration::from_secs(2) {
                    self.seq = sent.wrapping_sub(req.len() as u32); // one retransmit of the request
                    let p = self.seg(c, PSH | ACK, req);
                    c.send(&p).await;
                    self.seq = sent;
                    resent = true;
                }
                continue;
            };
            last_rx = Instant::now();
            if f & RST != 0 {
                break;
            }
            if seq == self.ack && !data.is_empty() {
                first.get_or_insert(s.elapsed());
                self.ack = self.ack.wrapping_add(data.len() as u32);
                body.extend(&data);
            }
            let fin = f & FIN != 0 && seq.wrapping_add(data.len() as u32) == self.ack;
            if fin {
                self.ack = self.ack.wrapping_add(1);
            }
            if !data.is_empty() || f & FIN != 0 {
                let a = self.seg(c, ACK, &[]);
                c.send(&a).await;
            }
            if fin {
                let f = self.seg(c, FIN | ACK, &[]);
                c.send(&f).await;
                break;
            }
        }
        (body, first.unwrap_or_default(), s.elapsed())
    }

    async fn rst(&self, c: &mut Cli) {
        let r = self.seg(c, RST | ACK, &[]);
        c.send(&r).await;
    }
}

fn get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: strait-vps-test\r\nConnection: close\r\n\r\n").into_bytes()
}

// ---- tests ----------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn internet_v4() {
    let (key, hosts) = invite();
    let v4: Vec<_> = hosts.iter().copied().filter(|a| a.is_ipv4()).collect();
    let (mut c, _) = Cli::join(&key, &v4).await;

    let r = ping(&mut c, Ipv4Addr::new(1, 1, 1, 1), 20).await;
    rtt_report("ICMP 1.1.1.1", 20, &r);
    assert!(r.len() >= 18, "icmp loss too high");

    for s in [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)] {
        let a = dns(&mut c, s, "example.com").await;
        println!("DNS example.com via {s}: {a:?}");
        assert!(!a.is_empty());
    }

    let (mut t, hs) = Tcp::connect(&mut c, Ipv4Addr::new(1, 1, 1, 1), 80, 50001).await;
    let (body, ttfb, tot) = t.exchange(&mut c, &get("1.1.1.1", "/"), 1 << 20).await;
    let text = String::from_utf8_lossy(&body);
    println!("TCP 1.1.1.1:80 handshake {hs:?}, ttfb {ttfb:?}, total {tot:?}, {} bytes: {:?}", body.len(), text.lines().next());
    assert!(text.starts_with("HTTP/1.1 "), "no HTTP response");
    c.t.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn bulk_throughput() {
    let (key, hosts) = invite();
    let v4: Vec<_> = hosts.iter().copied().filter(|a| a.is_ipv4()).collect();
    let (mut c, _) = Cli::join(&key, &v4).await;
    let target = std::env::var("STRAIT_VPS_BULK").unwrap_or("ipv4.download.thinkbroadband.com/10MB.zip".into());
    let (host, path) = target.split_once('/').unwrap();
    let Some(SocketAddr::V4(sa)) = (host, 80).to_socket_addrs().ok().and_then(|mut i| i.find(|a| a.is_ipv4())) else {
        return println!("skip: cannot resolve {host}");
    };
    let (mut t, hs) = Tcp::connect(&mut c, *sa.ip(), 80, 50002).await;
    let (body, ttfb, tot) = t.exchange(&mut c, &get(host, &format!("/{path}")), 5 << 20).await;
    t.rst(&mut c).await;
    let head = String::from_utf8_lossy(&body[..body.len().min(40)]).lines().next().unwrap_or("").to_string();
    println!("bulk {host} ({}) hs {hs:?} ttfb {ttfb:?}: {} bytes in {tot:?} = {:.2} Mbit/s [{head}]", sa.ip(), body.len(), body.len() as f64 * 8.0 / 1e6 / (tot - ttfb).as_secs_f64().max(1e-3));
    c.t.close().await.unwrap(); // close first: a panic would leak the slot for 60 s
    assert!(body.len() > 100_000, "too little data");
}

#[tokio::test]
#[ignore]
async fn keepalive_survives_idle_40s() {
    let (key, hosts) = invite();
    let (mut c, _) = Cli::join(&key, &hosts).await;
    let end = Instant::now() + Duration::from_secs(40);
    while Instant::now() < end {
        let _ = c.recv(Duration::from_millis(500)).await;
    }
    let r = ping(&mut c, Ipv4Addr::new(1, 1, 1, 1), 3).await;
    println!("after 40 s idle: {}/3 echo replies", r.len());
    assert!(r.len() >= 2);
    c.t.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn two_clients_isolated() {
    let (key, hosts) = invite();
    let (mut a, _) = Cli::join(&key, &hosts).await;
    let (mut b, _) = Cli::join(&key, &hosts).await;
    assert_ne!(a.ip, b.ip);
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let (ra, rb) = (ping(&mut a, dst, 5).await, ping(&mut b, dst, 5).await);
    println!("A {} ({} replies), B {} ({} replies)", a.ip, ra.len(), b.ip, rb.len());
    assert!(ra.len() >= 4 && rb.len() >= 4);
    // nothing addressed to B may reach A and vice versa
    while let Some(p) = a.recv(Duration::from_millis(300)).await {
        assert_eq!(parse(&p).map(|x| x.2), Some(a.ip), "A got a foreign packet");
    }
    // A spoofs B's source address: the host must drop it, so no reply for anyone
    let ipid = a.next_id();
    a.send(&icmp_echo(b.ip, dst, 0x5555, 1, ipid)).await;
    assert!(a.recv(Duration::from_secs(2)).await.is_none(), "spoofed packet got a reply at A");
    assert!(b.recv(Duration::from_secs(1)).await.is_none(), "spoofed packet got a reply at B");
    a.t.close().await.unwrap();
    b.t.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn wrong_key_cannot_join() {
    let (key, hosts) = invite();
    let mut bad = key.clone().into_bytes();
    bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
    let s = Instant::now();
    let err = join_with(std::str::from_utf8(&bad).unwrap(), &hosts, has_v6_route()).await.err().expect("must fail");
    println!("wrong key: {err:?} after {:?}", s.elapsed());
    assert!(matches!(err, ConnectError::HostUnreachable), "{err:?}");
}

/// Fill all slots, see HostFull, then a graceful close frees one.
#[tokio::test]
#[ignore]
async fn slots_fill_and_free() {
    let (key, hosts) = invite();
    let max: usize = std::env::var("STRAIT_VPS_MAX").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let mut cs = vec![];
    for _ in 0..max {
        cs.push(Cli::join(&key, &hosts).await.0);
    }
    let err = join_with(&key, &hosts, has_v6_route()).await.err().expect("host should be full");
    println!("join #{}: {err:?}", max + 1);
    assert!(matches!(err, ConnectError::HostFull), "{err:?}");
    let freed = cs.pop().unwrap();
    let ip = freed.ip;
    let mut f = freed;
    f.t.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (again, _) = Cli::join(&key, &hosts).await;
    println!("after BYE the slot was reused: {} (freed {ip})", again.ip);
    assert_eq!(again.ip, ip);
    for mut c in cs {
        c.t.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore]
async fn over_ipv6() {
    let (key, _) = invite();
    let Ok(v6) = std::env::var("STRAIT_VPS_V6") else { return println!("skip: STRAIT_VPS_V6 unset") };
    let hosts: Vec<SocketAddr> = vec![v6.parse().unwrap()];
    if !has_v6_route() {
        let err = join_with(&key, &hosts, false).await.err().expect("must fail");
        println!("no global IPv6 route here: {err:?} / {err}");
        assert!(matches!(err, ConnectError::NoIpv6Route));
        return;
    }
    let (mut c, _) = Cli::join(&key, &hosts).await;
    assert!(c.t.peer().unwrap().is_ipv6());
    let r = ping(&mut c, Ipv4Addr::new(1, 1, 1, 1), 10).await;
    rtt_report("ICMP 1.1.1.1 over v6 transport", 10, &r);
    assert!(r.len() >= 8);
    c.t.close().await.unwrap();
}
