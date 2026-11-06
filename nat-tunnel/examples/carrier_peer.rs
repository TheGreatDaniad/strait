//! Real-network carrier peer. `carrier_peer host|client --carrier ws|awg|udp --key <hex> --endpoint host:port
//! [--param k=v]... [--mode echo|send] [--size N --pps N --secs N --redial --label X]`.
//! host: listen and echo every frame back to its sender. client: dial, send paced frames
//! (magic|seq|t_us|pad), count loss/dup/reorder, print RTT stats and one JSON line.
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nat_tunnel::carrier::udp::norm;
use nat_tunnel::carrier::*;
use nat_tunnel::tunnel::crypto::AeadSession;

const MAGIC: &[u8; 4] = b"CPR1";

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned()
}

fn spec(a: &[String], listen: bool) -> (CarrierSpec, SocketAddr) {
    let ep = arg(a, "--endpoint").expect("--endpoint");
    let addr = norm(ep.to_socket_addrs().expect("endpoint").next().expect("resolve"));
    let mut params = vec![("key".to_string(), arg(a, "--key").expect("--key"))];
    for (i, x) in a.iter().enumerate() {
        if x == "--param" {
            let (k, v) = a[i + 1].split_once('=').expect("k=v");
            params.push((k.into(), v.into()));
        }
    }
    let s = CarrierSpec { endpoint: Some(ep), bind_port: listen.then(|| addr.port()), params };
    (s, addr)
}

fn factory(a: &[String]) -> Arc<dyn CarrierFactory> {
    let id = arg(a, "--carrier").expect("--carrier");
    by_ids(&[id.clone()]).into_iter().next().unwrap_or_else(|| panic!("carrier {id} not built"))
}

async fn host(a: &[String]) {
    let (s, _) = spec(a, true);
    let io = factory(a).listen(&s).await.expect("listen");
    eprintln!("host up on {:?} caps={:?}", io.local_addr(), io.caps());
    let mut buf = vec![0u8; 4096];
    let mut n = 0u64;
    // --seal: open and re-seal with the real Strait AEAD (wire = sid|counter|ct), one session per peer
    let seal = a.iter().any(|x| x == "--seal");
    let psk = arg(a, "--key").unwrap();
    let mut sess: HashMap<SocketAddr, AeadSession> = HashMap::new();
    loop {
        if io.readable().await.is_err() {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        }
        loop {
            match io.try_recv_from(&mut buf) {
                Ok((len, from)) => {
                    n += 1;
                    let out = if seal {
                        let ss = sess.entry(from).or_insert_with(|| AeadSession::new(&psk, true));
                        match ss.open(&buf[..len]) { Ok((p, _)) => ss.seal(&p), Err(_) => continue }
                    } else { buf[..len].to_vec() };
                    if let Err(e) = io.send_to(&out, from).await {
                        eprintln!("echo to {from}: {e}");
                    }
                    if n % 100000 == 0 {
                        eprintln!("echoed {n}");
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("recv: {e}");
                    break;
                }
            }
        }
    }
}

/// JSON has no NaN: no samples -> null.
fn jn(x: f64) -> String {
    if x.is_finite() { format!("{x:.2}") } else { "null".into() }
}

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

async fn client(a: &[String]) {
    let size: usize = arg(a, "--size").map_or(500, |v| v.parse().unwrap());
    let pps: f64 = arg(a, "--pps").map_or(10.0, |v| v.parse().unwrap());
    let secs: f64 = arg(a, "--secs").map_or(10.0, |v| v.parse().unwrap());
    let redial = a.iter().any(|x| x == "--redial");
    let label = arg(a, "--label").unwrap_or_default();
    let seal = a.iter().any(|x| x == "--seal");
    let mut ses = AeadSession::new(&arg(a, "--key").unwrap(), false);
    let size = if seal { size - 32 } else { size }; // wire size stays as asked
    assert!(size >= 16);
    let (s, peer) = spec(a, false);
    let f = factory(a);
    let t0 = Instant::now();
    let io = match f.dial(&s).await {
        Ok(io) => io,
        Err(e) => {
            println!("{{\"label\":\"{label}\",\"dial_error\":{:?}}}", format!("{e:?}"));
            return;
        }
    };
    let mut io: Arc<dyn FrameIo> = io;
    eprintln!("dialed in {:?} caps={:?}", t0.elapsed(), io.caps());
    let base = Instant::now();
    let total = (pps * secs) as u32;
    let mut seen: Vec<bool> = vec![false; total as usize + 1];
    let (mut sent, mut recv, mut dup, mut reorder, mut max_seq, mut bytes_rx) = (0u32, 0u32, 0u32, 0u32, -1i64, 0u64);
    let (mut send_err, mut redials) = (0u32, 0u32);
    let mut events: Vec<String> = Vec::new();
    let mut rtts: Vec<f64> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / pps));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut buf = vec![0u8; 4096];
    let mut pkt = vec![0u8; size];
    pkt[..4].copy_from_slice(MAGIC);
    let mut down_at: Option<Instant> = None;
    let mut redial_at = Instant::now();
    let mut end: Option<Instant> = None;
    let mut by_sec: HashMap<u64, u32> = HashMap::new();
    loop {
        if let Some(e) = end {
            if Instant::now() > e {
                break;
            }
        }
        if down_at.is_some() && redial && Instant::now() >= redial_at {
            match f.dial(&s).await {
                Ok(n) => {
                    io = n;
                    redials += 1;
                    events.push(format!("redial_ok after {} ms down", down_at.unwrap().elapsed().as_millis()));
                    down_at = None;
                }
                Err(e) => {
                    if redials == 0 || events.len() < 40 {
                        events.push(format!("redial_fail {e:?}"));
                    }
                    redial_at = Instant::now() + Duration::from_millis(500);
                }
            }
            continue;
        }
        let sending = sent < total && down_at.is_none();
        tokio::select! {
            _ = tick.tick(), if sending => {
                pkt[4..8].copy_from_slice(&sent.to_be_bytes());
                pkt[8..16].copy_from_slice(&(base.elapsed().as_micros() as u64).to_be_bytes());
                let w = if seal { ses.seal(&pkt) } else { pkt.clone() };
                match io.send_to(&w, peer).await {
                    Ok(_) => {}
                    Err(e) => {
                        send_err += 1;
                        let t = CarrierError::from_io(&e).map(|c| format!("{c:?}")).unwrap_or_else(|| format!("{e:?}"));
                        if send_err <= 3 { events.push(format!("send_err seq={sent} {t}")); }
                    }
                }
                sent += 1;
                if sent == total { end = Some(Instant::now() + Duration::from_secs(3)); }
                // a dead stream: keep going; health()/readable() flips below
                if let Health::Down(m) = io.health() {
                    if down_at.is_none() { down_at = Some(Instant::now()); events.push(format!("health_down {m}")); redial_at = Instant::now(); }
                }
            }
            r = io.readable() => {
                match r {
                    Err(e) => {
                        let t = CarrierError::from_io(&e).map(|c| format!("{c:?}")).unwrap_or_else(|| format!("{e:?}"));
                        if down_at.is_none() { down_at = Some(Instant::now()); events.push(format!("readable_err {t}")); redial_at = Instant::now(); }
                        if !redial { tokio::time::sleep(Duration::from_millis(50)).await; }
                        if end.is_none() && sent >= total { end = Some(Instant::now()); }
                        if !redial && down_at.is_some() && end.is_none() { end = Some(Instant::now() + Duration::from_secs(1)); }
                    }
                    Ok(()) => loop {
                        match io.try_recv_from(&mut buf) {
                            Ok((n0, _)) => {
                                let pl = if seal { match ses.open(&buf[..n0]) { Ok((p, _)) => p, Err(_) => continue } } else { buf[..n0].to_vec() };
                                let (n, buf) = (pl.len(), &pl);
                                if n >= 16 && &buf[..4] == MAGIC {
                                    let seq = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
                                    let ts = u64::from_be_bytes(buf[8..16].try_into().unwrap());
                                    let rtt = base.elapsed().as_micros() as f64 - ts as f64;
                                    if seq >= seen.len() { continue; }
                                    if seen[seq] { dup += 1; continue; }
                                    seen[seq] = true;
                                    recv += 1; bytes_rx += n as u64;
                                    if (seq as i64) < max_seq { reorder += 1 } else { max_seq = seq as i64 }
                                    rtts.push(rtt / 1000.0);
                                    *by_sec.entry(base.elapsed().as_secs()).or_default() += 1;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    },
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }
    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let dur = base.elapsed().as_secs_f64() - 3.0;
    let loss = if sent > 0 { 100.0 * (sent - recv.min(sent)) as f64 / sent as f64 } else { 0.0 };
    // longest run of consecutive lost seqs
    let (mut run, mut maxrun) = (0, 0);
    for i in 0..sent as usize {
        if seen[i] { run = 0 } else { run += 1; maxrun = maxrun.max(run) }
    }
    let ev = events.iter().map(|e| format!("{e:?}")).collect::<Vec<_>>().join(",");
    println!(
        "{{\"label\":\"{label}\",\"carrier\":\"{}\",\"size\":{size},\"pps\":{pps},\"secs\":{secs},\"sent\":{sent},\"recv\":{recv},\"loss_pct\":{loss:.3},\"max_loss_run\":{maxrun},\"dup\":{dup},\"reorder\":{reorder},\"send_err\":{send_err},\"redials\":{redials},\"rtt_ms\":{{\"min\":{},\"median\":{},\"p95\":{},\"max\":{}}},\"goodput_mbps\":{:.3},\"events\":[{ev}]}}",
        arg(a, "--carrier").unwrap(),
        jn(pct(&rtts, 0.0)), jn(pct(&rtts, 0.5)), jn(pct(&rtts, 0.95)), jn(pct(&rtts, 1.0)),
        bytes_rx as f64 * 8.0 / dur.max(0.001) / 1e6,
    );
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("host") => host(&a).await,
        Some("client") => client(&a).await,
        #[cfg(feature = "cr-awg")]
        Some("awg-params") => {
            // print the key-derived envelope parameters (junk burst, padding) to compare with a capture
            let k = arg(&a, "--key").unwrap();
            let key: Vec<u8> = (0..k.len()).step_by(2).map(|i| u8::from_str_radix(&k[i..i + 2], 16).unwrap()).collect();
            let u = nat_tunnel::carrier::udp::UdpCarrier::bind(None).await.unwrap();
            let c = nat_tunnel::carrier::awg::AwgCarrier::wrap(Arc::new(u), &key, nat_tunnel::carrier::awg::Role::Client);
            println!("{:?}", c.params());
        }
        _ => eprintln!("usage: carrier_peer host|client --carrier ws|awg|udp --key K --endpoint H:P [--param k=v] [--size --pps --secs --redial --label]"),
    }
}
