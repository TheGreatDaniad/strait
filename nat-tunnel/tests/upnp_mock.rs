//! Mock IGD (HTTP/SOAP) and NAT-PMP responders on loopback; SSDP is skipped by
//! injecting the gateway endpoints.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat_tunnel::upnp::{add_udp_mapping_at, explain, probe_targets, Outcome, Targets};

const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
const SVC: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

#[derive(Default)]
struct Igd {
    maps: Mutex<HashMap<u16, String>>,
    taken: Mutex<HashSet<u16>>, // externals that answer 718
    adds: AtomicUsize,
    deletes: AtomicUsize,
}

#[derive(Clone, Copy)]
enum Quirk {
    None,
    Silent,        // accept, never answer
    Garbage,       // non-HTTP bytes
    BadDesc,       // description lacks services
    Oversize,      // endless body
    Refuse606,     // AddPortMapping -> SOAP fault 606
}

fn http_reply(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

fn spawn_igd(quirk: Quirk, igd: Arc<Igd>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let (igd, mut s) = (igd.clone(), s.unwrap());
            std::thread::spawn(move || {
                match quirk {
                    Quirk::Silent => return std::thread::sleep(Duration::from_secs(30)),
                    Quirk::Garbage => return drop(s.write_all(b"\x00\x01not http at all")),
                    Quirk::Oversize => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                        let junk = [b'a'; 8192];
                        while s.write_all(&junk).is_ok() {}
                        return;
                    }
                    _ => {}
                }
                let mut req = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    let n = s.read(&mut b).unwrap_or(0);
                    req.extend_from_slice(&b[..n]);
                    let t = String::from_utf8_lossy(&req).to_string();
                    if let Some(h) = t.find("\r\n\r\n") {
                        let cl = t.to_lowercase().find("content-length:").map(|i| {
                            t[i + 15..].lines().next().unwrap().trim().parse::<usize>().unwrap()
                        });
                        if req.len() >= h + 4 + cl.unwrap_or(0) { break; }
                    }
                    if n == 0 { return; }
                }
                let t = String::from_utf8_lossy(&req).to_string();
                if t.starts_with("GET /desc.xml") {
                    let body = if matches!(quirk, Quirk::BadDesc) {
                        "<root><serviceList><service><serviceType>".to_string()
                    } else {
                        format!("<root><serviceList><service><serviceType>{SVC}</serviceType><controlURL>/ctl</controlURL></service></serviceList></root>")
                    };
                    return http_reply(&mut s, "200 OK", &body);
                }
                let port: u16 = t.split("<NewExternalPort>").nth(1)
                    .and_then(|x| x.split('<').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
                let proto = t.split("<NewProtocol>").nth(1).and_then(|x| x.split('<').next()).unwrap_or("").to_string();
                if t.contains("#AddPortMapping") {
                    igd.adds.fetch_add(1, SeqCst);
                    if matches!(quirk, Quirk::Refuse606) {
                        return http_reply(&mut s, "500 Internal Server Error",
                            "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>606</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>");
                    }
                    if igd.taken.lock().unwrap().contains(&port) {
                        return http_reply(&mut s, "500 Internal Server Error",
                            "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>");
                    }
                    igd.maps.lock().unwrap().insert(port, proto);
                    http_reply(&mut s, "200 OK", "<u:AddPortMappingResponse/>")
                } else if t.contains("#DeletePortMapping") {
                    igd.deletes.fetch_add(1, SeqCst);
                    let mut maps = igd.maps.lock().unwrap();
                    if maps.get(&port) == Some(&proto) { maps.remove(&port); }
                    drop(maps);
                    http_reply(&mut s, "200 OK", "<u:DeletePortMappingResponse/>")
                } else if t.contains("#GetExternalIPAddress") {
                    http_reply(&mut s, "200 OK", "<u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse>")
                } else {
                    http_reply(&mut s, "404 Not Found", "");
                }
            });
        }
    });
    format!("http://{addr}/desc.xml")
}

#[derive(Default)]
struct Pmp {
    maps: Mutex<HashMap<u16, u16>>,
    maps_req: AtomicUsize,
    last_op: AtomicUsize,
    deletes: AtomicUsize,
}

#[derive(Clone, Copy)]
enum PmpMode { Normal, Silent, Short, Refuse }

fn spawn_pmp(mode: PmpMode, st: Arc<Pmp>) -> SocketAddr {
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = u.local_addr().unwrap();
    std::thread::spawn(move || loop {
        let mut b = [0u8; 64];
        let Ok((n, from)) = u.recv_from(&mut b) else { return };
        match mode {
            PmpMode::Silent => continue,
            PmpMode::Short => { let _ = u.send_to(&[0, 0x81, 0], from); continue; }
            _ => {}
        }
        if n == 2 {
            let mut r = vec![0, 0x80, 0, 0, 0, 0, 0, 1];
            r.extend_from_slice(&[203, 0, 113, 9]);
            let _ = u.send_to(&r, from);
        } else if n == 12 {
            let internal = u16::from_be_bytes([b[4], b[5]]);
            let mut ext = u16::from_be_bytes([b[6], b[7]]);
            let life = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
            let result: u16 = if matches!(mode, PmpMode::Refuse) { 2 } else { 0 };
            st.last_op.store(b[1] as usize, SeqCst);
            if life == 0 { st.deletes.fetch_add(1, SeqCst); st.maps.lock().unwrap().remove(&internal); }
            else {
                st.maps_req.fetch_add(1, SeqCst);
                if ext == 0 { ext = internal }
                st.maps.lock().unwrap().insert(internal, ext);
            }
            let mut r = vec![0, 0x80 | b[1]];
            r.extend_from_slice(&result.to_be_bytes());
            r.extend_from_slice(&[0, 0, 0, 1]);
            r.extend_from_slice(&internal.to_be_bytes());
            r.extend_from_slice(&ext.to_be_bytes());
            r.extend_from_slice(&life.to_be_bytes());
            let _ = u.send_to(&r, from);
        }
    });
    addr
}

#[tokio::test]
async fn upnp_add_release_and_drop_delete() {
    let igd = Arc::new(Igd::default());
    let loc = spawn_igd(Quirk::None, igd.clone());
    let g = add_udp_mapping_at(Some(&loc), None, LOCAL, 7100, 0).await.expect("mapping");
    assert_eq!((g.external_port, g.external_ip, g.method), (7100, Some("203.0.113.7".parse().unwrap()), "upnp"));
    assert!(igd.maps.lock().unwrap().contains_key(&7100));
    g.release().await.unwrap();
    assert!(igd.maps.lock().unwrap().is_empty());
    assert_eq!(igd.deletes.load(SeqCst), 1);

    let g = add_udp_mapping_at(Some(&loc), None, LOCAL, 7101, 0).await.unwrap();
    assert!(igd.maps.lock().unwrap().contains_key(&7101));
    drop(g);
    assert!(igd.maps.lock().unwrap().is_empty(), "Drop must delete");
    assert_eq!(igd.deletes.load(SeqCst), 2);
}

#[tokio::test]
async fn upnp_lease_is_renewed_until_released() {
    let igd = Arc::new(Igd::default());
    let loc = spawn_igd(Quirk::None, igd.clone());
    let g = add_udp_mapping_at(Some(&loc), None, LOCAL, 7200, 2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let n = igd.adds.load(SeqCst);
    assert!(n >= 3, "initial add + >=2 renewals, got {n}");
    g.release().await.unwrap();
    let after = igd.adds.load(SeqCst);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(igd.adds.load(SeqCst), after, "no renewal after release");
}

#[tokio::test]
async fn upnp_conflict_718_moves_to_next_port_or_fails_cleanly() {
    let igd = Arc::new(Igd::default());
    igd.taken.lock().unwrap().extend([7300, 7301]);
    let loc = spawn_igd(Quirk::None, igd.clone());
    let g = add_udp_mapping_at(Some(&loc), None, LOCAL, 7300, 0).await.unwrap();
    assert_eq!(g.external_port, 7302);
    assert_eq!(g.internal.port(), 7300);
    drop(g);

    igd.taken.lock().unwrap().extend(7300..7310);
    assert!(add_udp_mapping_at(Some(&loc), None, LOCAL, 7300, 0).await.is_none());
}

#[tokio::test]
async fn upnp_hostile_gateways_never_hang_or_panic() {
    for q in [Quirk::Silent, Quirk::Garbage, Quirk::BadDesc, Quirk::Oversize] {
        let loc = spawn_igd(q, Arc::new(Igd::default()));
        let t = Instant::now();
        assert!(add_udp_mapping_at(Some(&loc), None, LOCAL, 7400, 0).await.is_none());
        assert!(t.elapsed() < Duration::from_secs(8), "took {:?}", t.elapsed());
    }
    // Unreachable gateway, and a non-LAN URL is refused outright.
    assert!(add_udp_mapping_at(Some("http://127.0.0.1:1/desc.xml"), None, LOCAL, 7400, 0).await.is_none());
    assert!(add_udp_mapping_at(Some("http://8.8.8.8/desc.xml"), None, LOCAL, 7400, 0).await.is_none());
}

#[tokio::test]
async fn natpmp_add_release_drop_and_renew() {
    let st = Arc::new(Pmp::default());
    let srv = spawn_pmp(PmpMode::Normal, st.clone());
    let g = add_udp_mapping_at(None, Some(srv), LOCAL, 7500, 0).await.unwrap();
    assert_eq!((g.method, g.external_port, g.external_ip), ("natpmp", 7500, Some("203.0.113.9".parse().unwrap())));
    assert!(st.maps.lock().unwrap().contains_key(&7500));
    g.release().await.unwrap();
    assert!(st.maps.lock().unwrap().is_empty());

    let g = add_udp_mapping_at(None, Some(srv), LOCAL, 7501, 0).await.unwrap();
    drop(g);
    assert!(st.maps.lock().unwrap().is_empty());
    assert_eq!(st.deletes.load(SeqCst), 2);

    let before = st.maps_req.load(SeqCst);
    let g = add_udp_mapping_at(None, Some(srv), LOCAL, 7502, 2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2600)).await;
    assert!(st.maps_req.load(SeqCst) - before >= 3, "renewals expected");
    g.release().await.unwrap();
}

#[tokio::test]
async fn natpmp_bad_gateways_fail_cleanly() {
    for m in [PmpMode::Silent, PmpMode::Short, PmpMode::Refuse] {
        let srv = spawn_pmp(m, Arc::new(Pmp::default()));
        let t = Instant::now();
        assert!(add_udp_mapping_at(None, Some(srv), LOCAL, 7600, 0).await.is_none());
        assert!(t.elapsed() < Duration::from_secs(6));
    }
}

fn targets(locs: &[String], probes: &[String]) -> Targets {
    Targets {
        local: Some(LOCAL),
        upnp_locations: locs.to_vec(),
        upnp_probes: probes.to_vec(),
        ..Targets::default()
    }
}

#[tokio::test]
async fn upnp_found_by_unicast_probe_skips_dead_candidates() {
    let igd = Arc::new(Igd::default());
    let loc = spawn_igd(Quirk::None, igd.clone());
    // First candidate: closed port; second: a gateway with a broken description.
    let bad = spawn_igd(Quirk::BadDesc, Arc::new(Igd::default()));
    let t = targets(&[], &["http://127.0.0.1:1/rootDesc.xml".into(), bad, loc]);
    let r = probe_targets(t, 7700, 0).await;
    assert!(matches!(r.upnp, Outcome::Mapped { external_port: 7700, .. }), "{:?}", r.upnp);
    assert_eq!(r.guard.as_ref().unwrap().method, "upnp");
    assert!(explain(&r).contains("opened port 7700"));
    r.guard.unwrap().release().await.unwrap();
    assert!(igd.maps.lock().unwrap().is_empty());
}

#[tokio::test]
async fn upnp_fault_606_is_reported_as_refused() {
    let loc = spawn_igd(Quirk::Refuse606, Arc::new(Igd::default()));
    let r = probe_targets(targets(&[loc], &[]), 7800, 0).await;
    assert!(r.guard.is_none());
    assert_eq!(r.upnp, Outcome::Refused { code: 606, reason: "action not authorized".into() });
    assert_eq!(
        explain(&r),
        "The router answered UPnP but refused the mapping (error 606): enable UPnP in the router settings."
    );
}

#[tokio::test]
async fn tcp_mapping_names_tcp_on_add_and_delete() {
    let igd = Arc::new(Igd::default());
    let loc = spawn_igd(Quirk::None, igd.clone());
    let t = Targets { local: Some(LOCAL), upnp_locations: vec![loc], tcp: true, ..Targets::default() };
    let g = probe_targets(t, 7700, 0).await.guard.expect("upnp tcp");
    assert!(g.tcp);
    assert_eq!(igd.maps.lock().unwrap().get(&7700).map(String::as_str), Some("TCP"));
    g.release().await.unwrap();
    assert!(igd.maps.lock().unwrap().is_empty(), "the delete must name TCP too");

    // NAT-PMP: opcode 2, and the reply must echo it.
    let st = Arc::new(Pmp::default());
    let srv = spawn_pmp(PmpMode::Normal, st.clone());
    let t = Targets { local: Some(LOCAL), natpmp: Some(srv), tcp: true, ..Targets::default() };
    let g = probe_targets(t, 7701, 0).await.guard.expect("natpmp tcp");
    assert_eq!((g.tcp, st.last_op.load(SeqCst)), (true, 2));
    g.release().await.unwrap();
    assert_eq!(st.last_op.load(SeqCst), 2, "the delete uses the TCP opcode");
}

#[tokio::test]
async fn carrier_port_follows_the_router_and_is_kept_for_the_host() {
    use nat_tunnel::preflight::{map_carrier_port_with, take_kept_tcp};
    // 7800 is taken on the router (718), so it grants 7801: the carrier must listen on and
    // publish 7801, with the mapping redone as 7801 -> 7801.
    let igd = Arc::new(Igd::default());
    igd.taken.lock().unwrap().insert(7800);
    let loc = spawn_igd(Quirk::None, igd.clone());
    let add = |p: u16| {
        let t = Targets { local: Some(LOCAL), upnp_locations: vec![loc.clone()], tcp: true, ..Targets::default() };
        async move { probe_targets(t, p, 0).await.guard }
    };
    assert_eq!(map_carrier_port_with(7800, &add).await, Ok(7801));
    assert_eq!(igd.maps.lock().unwrap().keys().copied().collect::<Vec<_>>(), vec![7801]);
    // Asking again reuses the kept mapping instead of adding another.
    let adds = igd.adds.load(SeqCst);
    assert_eq!(map_carrier_port_with(7801, &add).await, Ok(7801));
    assert_eq!(igd.adds.load(SeqCst), adds);
    // The host adopts it by its listen port; nothing is kept twice.
    let g = take_kept_tcp(7801).expect("kept for the host");
    assert_eq!((g.internal.port(), g.external_port, g.tcp), (7801, 7801, true));
    assert!(take_kept_tcp(7801).is_none());
    g.release().await.unwrap();
    assert!(igd.maps.lock().unwrap().is_empty());

    // A router that says no is an error with the port in it, and nothing is kept.
    let refuse = spawn_igd(Quirk::Refuse606, Arc::new(Igd::default()));
    let add = |p: u16| {
        let t = Targets { local: Some(LOCAL), upnp_locations: vec![refuse.clone()], tcp: true, ..Targets::default() };
        async move { probe_targets(t, p, 0).await.guard }
    };
    assert!(map_carrier_port_with(7810, &add).await.unwrap_err().contains("7810"));
    assert!(take_kept_tcp(7810).is_none());
}
