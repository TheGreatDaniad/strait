//! Interop with the REAL shadowsocks-rust `ssserver` / `sslocal` processes. Run with
//! `SSSERVER_BIN=.. SSLOCAL_BIN=.. cargo test --features cr-ss --test carrier_ss_real -- --ignored --nocapture`
#![cfg(feature = "cr-ss")]

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nat_tunnel::carrier::ss::{b64, derive_psk, PLACEHOLDER, SS_MAX_FRAME};
use nat_tunnel::carrier::*;
use nat_tunnel::rendezvous::derive::parse_key;
use tokio::net::UdpSocket;

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const KEY2: &str = "ffeeddccbbaa99887766554433221100";
const METHOD: &str = "2022-blake3-aes-128-gcm";

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bin(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| panic!("{var} not set"))
}
fn psk(key: &str) -> String {
    b64(&derive_psk(&parse_key(key).unwrap()))
}
fn spec(ep: &str, key: &str, target: Option<SocketAddr>) -> CarrierSpec {
    let mut params = vec![("key".to_string(), key.to_string())];
    if let Some(t) = target {
        params.push(("target".into(), t.to_string()));
    }
    CarrierSpec { endpoint: Some(ep.into()), bind_port: None, params }
}
async fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}
fn spawn(bin: &str, args: &[&str]) -> Proc {
    let log = std::fs::File::create(std::env::temp_dir().join(format!("ssreal-{}.log", std::process::id()))).unwrap();
    Proc(Command::new(bin).args(args).stdout(Stdio::null()).stderr(log).spawn().unwrap())
}

/// UDP echo that counts datagrams.
async fn echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        while let Ok((l, f)) = s.recv_from(&mut b).await {
            n2.fetch_add(1, Ordering::Relaxed);
            let _ = s.send_to(&b[..l], f).await;
        }
    });
    (a, n)
}

async fn recv(io: &dyn FrameIo, ms: u64) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_millis(ms), async {
        let mut buf = vec![0u8; 4096];
        loop {
            io.readable().await.unwrap();
            if let Ok((n, _)) = io.try_recv_from(&mut buf) {
                return buf[..n].to_vec();
            }
        }
    })
    .await
    .ok()
}

async fn real_server(port: u16) -> Proc {
    let p = spawn(&bin("SSSERVER_BIN"), &["-s", &format!("127.0.0.1:{port}"), "-m", METHOD, "-k", &psk(KEY), "-U"]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    p
}

#[tokio::test]
#[ignore]
async fn our_dial_through_real_ssserver() {
    let (echo_addr, echo_n) = echo().await;
    let port = free_port().await;
    let _srv = real_server(port).await;
    let ep = format!("127.0.0.1:{port}");
    let host: SocketAddr = ep.parse().unwrap();
    let cli = ss::SsFactory.dial(&spec(&ep, KEY, Some(echo_addr))).await.unwrap();

    // sizes 1..=max_frame: every frame comes back exactly
    let sizes = [1usize, 2, 15, 16, 17, 100, 500, 1000, 1200, 1300, SS_MAX_FRAME - 1, SS_MAX_FRAME];
    for &sz in &sizes {
        let f: Vec<u8> = (0..sz).map(|i| (i * 7 + sz) as u8).collect();
        cli.send_to(&f, host).await.unwrap();
        assert_eq!(recv(&*cli, 3000).await.as_deref(), Some(&f[..]), "size {sz}");
    }
    // burst, in order enough: 500 frames all back
    for i in 0..500u32 {
        cli.send_to(&i.to_be_bytes(), host).await.unwrap();
    }
    let mut got = 0;
    while recv(&*cli, 500).await.is_some() {
        got += 1;
    }
    assert!(got >= 495, "burst echoes {got}/500");

    // wrong key: nothing ever comes back
    let bad = ss::SsFactory.dial(&spec(&ep, KEY2, Some(echo_addr))).await.unwrap();
    let before = echo_n.load(Ordering::Relaxed);
    bad.send_to(b"nope", host).await.unwrap();
    assert!(recv(&*bad, 800).await.is_none());
    assert_eq!(echo_n.load(Ordering::Relaxed), before, "wrong key must not reach the target");
}

#[tokio::test]
#[ignore]
async fn replayed_datagrams_through_real_ssserver() {
    let (echo_addr, echo_n) = echo().await;
    let port = free_port().await;
    let _srv = real_server(port).await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // duplicating middle box: every client datagram reaches the real server twice
    let mid = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mid_addr = mid.local_addr().unwrap();
    tokio::spawn(async move {
        let up = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (mut b, mut c) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut cli: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                Ok((n, f)) = mid.recv_from(&mut b) => { cli = Some(f); let _ = up.send_to(&b[..n], server).await; let _ = up.send_to(&b[..n], server).await; }
                Ok((n, _)) = up.recv_from(&mut c) => { if let Some(f) = cli { let _ = mid.send_to(&c[..n], f).await; } }
            }
        }
    });
    let cli = ss::SsFactory.dial(&spec(&mid_addr.to_string(), KEY, Some(echo_addr))).await.unwrap();
    for i in 0..20u32 {
        cli.send_to(&i.to_be_bytes(), mid_addr).await.unwrap();
    }
    let mut got = 0;
    while recv(&*cli, 700).await.is_some() {
        got += 1;
    }
    println!("replay: client sent 20, target saw {}, client got {got}", echo_n.load(Ordering::Relaxed));
    assert_eq!(got, 20, "duplicates must not reach the app");
}

#[tokio::test]
#[ignore]
async fn real_sslocal_tunnel_to_our_host() {
    let host = ss::SsFactory.listen(&spec("127.0.0.1:0", KEY, None)).await.unwrap();
    let ha = host.local_addr().unwrap();
    let lp = free_port().await;
    let _loc = spawn(
        &bin("SSLOCAL_BIN"),
        &["--protocol", "tunnel", "-U", "-b", &format!("127.0.0.1:{lp}"), "-s", &ha.to_string(), "-m", METHOD, "-k", &psk(KEY), "-f", &PLACEHOLDER.to_string()],
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let lpa = format!("127.0.0.1:{lp}");
    let mut peer = None;
    for sz in [1usize, 64, 1000, SS_MAX_FRAME] {
        let f: Vec<u8> = (0..sz).map(|i| (i * 3 + 1) as u8).collect();
        app.send_to(&f, &lpa).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let got = loop {
            host.readable().await.unwrap();
            if let Ok((n, a)) = host.try_recv_from(&mut buf) {
                peer = Some(a);
                break buf[..n].to_vec();
            }
        };
        assert_eq!(got, f, "size {sz}");
        // reply reaches sslocal's local socket
        host.send_to(&f, peer.unwrap()).await.unwrap();
        let mut rb = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), app.recv_from(&mut rb)).await.expect("reply").unwrap();
        assert_eq!(&rb[..n], &f[..], "reply size {sz}");
    }
    // 200 frames steady: the real client's packet ids all pass our replay window
    for i in 0..200u32 {
        app.send_to(&i.to_be_bytes(), &lpa).await.unwrap();
    }
    let mut n = 0;
    let mut buf = vec![0u8; 4096];
    while recv_host(&*host, &mut buf).await {
        n += 1;
    }
    assert!(n >= 195, "host received {n}/200");
}

async fn recv_host(h: &dyn FrameIo, buf: &mut [u8]) -> bool {
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            h.readable().await.unwrap();
            if h.try_recv_from(buf).is_ok() {
                return;
            }
        }
    })
    .await
    .is_ok()
}

// ---------------------------------------------------------------------------------------------
// Relay with capture and roaming: client <-> relay <-> server. `rebind` makes the relay continue
// from a new upstream source port (a NAT rebinding / roaming client).

type Cap = Arc<std::sync::Mutex<Vec<(bool, Vec<u8>)>>>; // (true = client to server, datagram)

async fn relay(server: SocketAddr, cap: Option<Cap>) -> (SocketAddr, Arc<tokio::sync::Notify>) {
    let down = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = down.local_addr().unwrap();
    let rebind = Arc::new(tokio::sync::Notify::new());
    let rb = rebind.clone();
    tokio::spawn(async move {
        let mut up = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut cli: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                Ok((n, f)) = down.recv_from(&mut a) => {
                    cli = Some(f);
                    if let Some(c) = &cap { c.lock().unwrap().push((true, a[..n].to_vec())); }
                    let _ = up.send_to(&a[..n], server).await;
                }
                Ok((n, _)) = up.recv_from(&mut b) => {
                    if let Some(c) = &cap { c.lock().unwrap().push((false, b[..n].to_vec())); }
                    if let Some(f) = cli { let _ = down.send_to(&b[..n], f).await; }
                }
                _ = rb.notified() => { up = UdpSocket::bind("0.0.0.0:0").await.unwrap(); }
            }
        }
    });
    (addr, rebind)
}

#[tokio::test]
async fn our_host_follows_a_roaming_client() {
    let host = ss::SsFactory.listen(&spec("127.0.0.1:0", KEY, None)).await.unwrap();
    let (mid, rebind) = relay(host.local_addr().unwrap(), None).await;
    let cli = ss::SsFactory.dial(&spec(&mid.to_string(), KEY, None)).await.unwrap();
    cli.send_to(b"one", mid).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let peer = loop {
        host.readable().await.unwrap();
        if let Ok((_, a)) = host.try_recv_from(&mut buf) {
            break a;
        }
    };
    rebind.notify_one();
    tokio::time::sleep(Duration::from_millis(100)).await;
    cli.send_to(b"two", mid).await.unwrap();
    let (n, p2) = loop {
        host.readable().await.unwrap();
        if let Ok(r) = host.try_recv_from(&mut buf) {
            break r;
        }
    };
    assert_eq!((&buf[..n], p2), (&b"two"[..], peer), "peer key must survive the source-port change");
    host.send_to(b"back", peer).await.unwrap();
    assert_eq!(recv(&*cli, 2000).await.as_deref(), Some(&b"back"[..]), "reply must follow the new source port");
}

fn entropy_report(label: &str, pk: &[Vec<u8>]) {
    let all: Vec<u8> = pk.iter().flatten().copied().collect();
    let chi = |d: &[u8]| {
        let mut c = [0f64; 256];
        d.iter().for_each(|&b| c[b as usize] += 1.0);
        let e = d.len() as f64 / 256.0;
        c.iter().map(|x| (x - e) * (x - e) / e).sum::<f64>()
    };
    let first: Vec<u8> = pk.iter().filter_map(|p| p.first().copied()).collect();
    let pop = |p: &Vec<u8>| p.iter().map(|b| b.count_ones() as f64).sum::<f64>() / p.len() as f64;
    let printable = |b: &u8| (0x20..=0x7e).contains(b);
    let ex1 = pk.iter().filter(|p| !(3.4..4.6).contains(&pop(p))).count();
    let ex2 = pk.iter().filter(|p| p.len() >= 6 && p[..6].iter().all(printable)).count();
    let ex3 = pk.iter().filter(|p| p.iter().filter(|b| printable(b)).count() * 2 > p.len()).count();
    let ex4 = pk.iter().filter(|p| p.split(|b| !printable(b)).any(|r| r.len() > 20)).count();
    let mut lens: Vec<usize> = pk.iter().map(|p| p.len()).collect();
    lens.sort();
    println!(
        "{label}: n={} bytes={} chi2(all)={:.1} (df255 mean 255 sd 22.6) chi2(first byte, n={})={:.1} | GFW-style exemptions hit: popcount-outside-3.4..4.6 {}, first6-printable {}, >50%-printable {}, run>20-printable {} | len min/med/max {}/{}/{}",
        pk.len(), all.len(), chi(&all), first.len(), chi(&first), ex1, ex2, ex3, ex4, lens[0], lens[lens.len() / 2], lens[lens.len() - 1]
    );
}

/// Real ssserver, packets recorded on the wire between our client and the server.
#[tokio::test]
#[ignore]
async fn wire_capture_and_overhead() {
    let (echo_addr, _) = echo().await;
    let port = free_port().await;
    let _srv = real_server(port).await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cap: Cap = Default::default();
    let (mid, _) = relay(server, Some(cap.clone())).await;
    let cli = ss::SsFactory.dial(&spec(&mid.to_string(), KEY, Some(echo_addr))).await.unwrap();
    let mut rng = 0x9e3779b97f4a7c15u64;
    let mut sizes = vec![];
    for i in 0..3000usize {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let sz = if i < 200 { 1 + i * 7 % SS_MAX_FRAME } else { 40 + (rng >> 33) as usize % 1300 };
        sizes.push(sz);
        let f: Vec<u8> = (0..sz).map(|j| (rng >> (j % 56)) as u8 ^ j as u8).collect();
        cli.send_to(&f, mid).await.unwrap();
        assert_eq!(recv(&*cli, 3000).await.as_deref(), Some(&f[..]), "frame {i} size {sz}");
    }
    let c = cap.lock().unwrap();
    let (up, down): (Vec<_>, Vec<_>) = c.iter().cloned().partition(|(d, _)| *d);
    let up: Vec<Vec<u8>> = up.into_iter().map(|x| x.1).collect();
    let down: Vec<Vec<u8>> = down.into_iter().map(|x| x.1).collect();
    let ov_up: Vec<usize> = up.iter().zip(&sizes).map(|(p, s)| p.len() - s).collect();
    let ov_dn: Vec<usize> = down.iter().zip(&sizes).map(|(p, s)| p.len() - s).collect();
    println!("overhead client->server: min {} max {} ; server->client: min {} max {}", ov_up.iter().min().unwrap(), ov_up.iter().max().unwrap(), ov_dn.iter().min().unwrap(), ov_dn.iter().max().unwrap());
    println!("max wire datagram: up {} down {}", up.iter().map(|p| p.len()).max().unwrap(), down.iter().map(|p| p.len()).max().unwrap());
    entropy_report("client->server", &up);
    entropy_report("server->client", &down);
    if let Ok(d) = std::env::var("SS_CAPTURE_OUT") {
        let hex = |p: &Vec<u8>| p.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let s: String = c.iter().map(|(d, p)| format!("{} {} {}\n", if *d { "c2s" } else { "s2c" }, p.len(), hex(p))).collect();
        std::fs::write(d, s).unwrap();
    }
    assert!(ov_up.iter().chain(&ov_dn).all(|&o| o <= ss::SS_OVERHEAD), "SS_OVERHEAD is too small");
}

fn pct(v: &[f64], p: f64) -> f64 {
    v[((v.len() as f64 - 1.0) * p) as usize]
}

/// Internet leg. SS_MODE=rtt: SS_REMOTE (ssserver addr), SS_TARGET (echo behind it), SS_SECS, SS_PPS,
/// SS_CLIENTS. SS_MODE=bridge: SS_BIND local UDP addr relayed through the tunnel until killed.
#[tokio::test]
#[ignore]
async fn internet() {
    let remote = std::env::var("SS_REMOTE").expect("SS_REMOTE");
    let target: SocketAddr = std::env::var("SS_TARGET").expect("SS_TARGET").parse().unwrap();
    let host: SocketAddr = remote.parse().unwrap();
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    if std::env::var("SS_MODE").as_deref() == Ok("bridge") {
        let l = Arc::new(UdpSocket::bind(std::env::var("SS_BIND").unwrap()).await.unwrap());
        let cli = ss::SsFactory.dial(&spec(&remote, KEY, Some(target))).await.unwrap();
        let (l2, c2) = (l.clone(), cli.clone());
        let back = tokio::spawn(async move {
            let mut last: Option<SocketAddr> = None;
            let mut b = vec![0u8; 4096];
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    Ok((n, f)) = l2.recv_from(&mut buf) => { last = Some(f); let _ = c2.send_to(&buf[..n.min(SS_MAX_FRAME)], host).await; }
                    r = c2.readable() => { r.unwrap(); while let Ok((n, _)) = c2.try_recv_from(&mut b) { if let Some(f) = last { let _ = l2.send_to(&b[..n], f).await; } } }
                }
            }
        });
        back.await.unwrap();
        return;
    }
    let (secs, pps, n_cli) = (env("SS_SECS", 20), env("SS_PPS", 10), env("SS_CLIENTS", 1));
    let mut hs = vec![];
    for c in 0..n_cli {
        let cli = ss::SsFactory.dial(&spec(&remote, KEY, Some(target))).await.unwrap();
        hs.push(tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            let total = secs * pps;
            let c2 = cli.clone();
            let tx = tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_micros(1_000_000 / pps));
                for seq in 0..total as u32 {
                    tick.tick().await;
                    let mut f = vec![0xA5u8; 100];
                    f[..4].copy_from_slice(&seq.to_be_bytes());
                    f[4..12].copy_from_slice(&(t0.elapsed().as_nanos() as u64).to_be_bytes());
                    let _ = c2.send_to(&f, host).await;
                }
            });
            let (mut rtts, mut seen, mut maxseq, mut reorder, mut dup) = (vec![], std::collections::HashSet::new(), -1i64, 0, 0);
            let end = tokio::time::Instant::now() + Duration::from_secs(secs) + Duration::from_secs(3);
            let mut buf = vec![0u8; 4096];
            while tokio::time::timeout_at(end, cli.readable()).await.is_ok() {
                while let Ok((n, _)) = cli.try_recv_from(&mut buf) {
                    let seq = u32::from_be_bytes(buf[..4].try_into().unwrap());
                    let ts = u64::from_be_bytes(buf[4..12].try_into().unwrap());
                    let _ = n;
                    if !seen.insert(seq) {
                        dup += 1;
                        continue;
                    }
                    if (seq as i64) < maxseq {
                        reorder += 1;
                    }
                    maxseq = maxseq.max(seq as i64);
                    rtts.push((t0.elapsed().as_nanos() as u64 - ts) as f64 / 1e6);
                }
            }
            tx.await.unwrap();
            let (mut gaps, mut s) = (vec![], 0u32);
            while s < total as u32 {
                if seen.contains(&s) {
                    s += 1;
                    continue;
                }
                let a = s;
                while s < total as u32 && !seen.contains(&s) {
                    s += 1;
                }
                gaps.push(format!("{a}..{}", s - 1));
            }
            println!("client {c}: missing seq ranges (at {pps} pps): {}", gaps.join(" "));
            if rtts.is_empty() {
                println!("client {c}: sent {total} recv 0 (100% loss)");
                return;
            }
            rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!(
                "client {c}: sent {total} recv {} loss {:.2}% reorder {reorder} dup {dup} rtt ms min {:.1} med {:.1} p95 {:.1} p99 {:.1} max {:.1}",
                seen.len(), 100.0 * (total as f64 - seen.len() as f64) / total as f64, rtts[0], pct(&rtts, 0.5), pct(&rtts, 0.95), pct(&rtts, 0.99), rtts[rtts.len() - 1]
            );
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
}

/// Roaming against the real ssserver: the client's UDP source port changes mid-session (relay
/// rebinds). With SS_REMOTE/SS_TARGET set it goes to the internet server instead of loopback.
#[tokio::test]
#[ignore]
async fn roaming_through_real_ssserver() {
    let (server, target, _keep) = match std::env::var("SS_REMOTE") {
        Ok(r) => (r.parse::<SocketAddr>().unwrap(), std::env::var("SS_TARGET").unwrap().parse().unwrap(), None),
        Err(_) => {
            let (e, _) = echo().await;
            let port = free_port().await;
            let p = real_server(port).await;
            (format!("127.0.0.1:{port}").parse().unwrap(), e, Some(p))
        }
    };
    let (mid, rebind) = relay(server, None).await;
    let cli = ss::SsFactory.dial(&spec(&mid.to_string(), KEY, Some(target))).await.unwrap();
    let mut ok = [0, 0];
    for phase in 0..2 {
        for i in 0..20u32 {
            cli.send_to(&i.to_be_bytes(), mid).await.unwrap();
            if recv(&*cli, 2000).await.is_some() {
                ok[phase] += 1;
            }
        }
        rebind.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("roaming: echoes before source-port change {}/20, after {}/20", ok[0], ok[1]);
    assert_eq!(ok, [20, 20]);
}
