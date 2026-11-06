//! Mock PCP (RFC 6887) and NAT-PMP gateways on loopback; no real router.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat_tunnel::upnp::{explain, probe_targets, MapperReport, Outcome, Targets};

const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    Result(u8),   // PCP error result code (full 60-byte reply)
    UnsuppV2,     // version 2, result 1, header only
    UnsuppV0,     // NAT-PMP style: version 0, result 1
    Short,        // 5 bytes
    WrongNonce,
    WrongVersion, // version 3
    WrongOpcode,
    Silent,
}

#[derive(Default)]
struct Pcp {
    maps: Mutex<HashMap<u16, u16>>, // internal -> external
    requests: AtomicUsize,
    deletes: AtomicUsize,
    adds: AtomicUsize,
    nonces: Mutex<Vec<[u8; 12]>>,
}

fn spawn_pcp(mode: Mode, st: Arc<Pcp>) -> SocketAddr {
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = u.local_addr().unwrap();
    std::thread::spawn(move || loop {
        let mut b = [0u8; 128];
        let Ok((n, from)) = u.recv_from(&mut b) else { return };
        st.requests.fetch_add(1, SeqCst);
        if mode == Mode::Silent || n != 60 || b[0] != 2 || b[1] != 1 {
            continue;
        }
        let lifetime = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let internal = u16::from_be_bytes([b[40], b[41]]);
        let mut ext = u16::from_be_bytes([b[42], b[43]]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[24..36]);
        // Client address must be the IPv4-mapped form of our fake LAN address.
        assert_eq!(&b[8..24], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 50]);
        assert_eq!(b[36], 17);
        let mut r = [0u8; 60];
        r[..].copy_from_slice(&b[..60]);
        r[1] = 0x81;
        r[2] = 0;
        r[3] = 0;
        r[8..24].fill(0); // epoch + reserved
        r[44..60].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 5]);
        match mode {
            Mode::Short => { let _ = u.send_to(&r[..5], from); continue; }
            Mode::UnsuppV2 => { let _ = u.send_to(&[2, 0x81, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], from); continue; }
            Mode::UnsuppV0 => { let _ = u.send_to(&[0, 0x81, 0, 1, 0, 0, 0, 0], from); continue; }
            Mode::Result(c) => { r[3] = c; let _ = u.send_to(&r, from); continue; }
            Mode::WrongNonce => r[24] ^= 0xff,
            Mode::WrongVersion => r[0] = 3,
            Mode::WrongOpcode => r[1] = 0x82,
            _ => {}
        }
        if mode == Mode::Normal {
            if lifetime == 0 {
                // Deletion must use the nonce of the creation.
                assert!(st.nonces.lock().unwrap().contains(&nonce), "delete with unknown nonce");
                st.deletes.fetch_add(1, SeqCst);
                st.maps.lock().unwrap().remove(&internal);
            } else {
                st.adds.fetch_add(1, SeqCst);
                st.nonces.lock().unwrap().push(nonce);
                if ext == 0 { ext = internal }
                st.maps.lock().unwrap().insert(internal, ext);
            }
            r[42..44].copy_from_slice(&ext.to_be_bytes());
        }
        let _ = u.send_to(&r, from);
    });
    addr
}

// --- tiny NAT-PMP mock (same wire as tests/upnp_mock.rs) ---
#[derive(Default)]
struct Pmp {
    maps: Mutex<HashMap<u16, u16>>,
    deletes: AtomicUsize,
}

fn spawn_pmp(refuse: Option<u16>, st: Arc<Pmp>) -> SocketAddr {
    spawn_pmp_shift(refuse, 0, st)
}

fn spawn_pmp_shift(refuse: Option<u16>, shift: u16, st: Arc<Pmp>) -> SocketAddr {
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = u.local_addr().unwrap();
    std::thread::spawn(move || loop {
        let mut b = [0u8; 64];
        let Ok((n, from)) = u.recv_from(&mut b) else { return };
        if n == 2 {
            let mut r = vec![0, 0x80, 0, 0, 0, 0, 0, 1];
            r.extend_from_slice(&[203, 0, 113, 9]);
            let _ = u.send_to(&r, from);
        } else if n == 12 {
            let internal = u16::from_be_bytes([b[4], b[5]]);
            let mut ext = u16::from_be_bytes([b[6], b[7]]);
            let life = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
            if life == 0 { st.deletes.fetch_add(1, SeqCst); st.maps.lock().unwrap().remove(&internal); }
            else {
                if ext == 0 { ext = internal }
                ext += shift;
                st.maps.lock().unwrap().insert(internal, ext);
            }
            let mut r = vec![0, 0x81];
            r.extend_from_slice(&refuse.unwrap_or(0).to_be_bytes());
            r.extend_from_slice(&[0, 0, 0, 1]);
            r.extend_from_slice(&internal.to_be_bytes());
            r.extend_from_slice(&ext.to_be_bytes());
            r.extend_from_slice(&life.to_be_bytes());
            let _ = u.send_to(&r, from);
        }
    });
    addr
}

fn t(pcp: Option<SocketAddr>, natpmp: Option<SocketAddr>) -> Targets {
    Targets { local: Some(LOCAL), pcp, natpmp, ..Targets::default() }
}

async fn settle(cond: impl Fn() -> bool) {
    for _ in 0..40 {
        if cond() { return }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn pcp_success_release_drop_and_renew() {
    let st = Arc::new(Pcp::default());
    let srv = spawn_pcp(Mode::Normal, st.clone());
    let r = probe_targets(t(Some(srv), None), 7900, 0).await;
    assert_eq!(r.pcp, Outcome::Mapped { external_port: 7900, external_ip: Some("203.0.113.5".parse().unwrap()) });
    let g = r.guard.unwrap();
    assert_eq!((g.method, g.external_port), ("pcp", 7900));
    assert!(st.maps.lock().unwrap().contains_key(&7900));
    g.release().await.unwrap();
    assert!(st.maps.lock().unwrap().is_empty());
    assert_eq!(st.deletes.load(SeqCst), 1);

    let g = probe_targets(t(Some(srv), None), 7901, 0).await.guard.unwrap();
    drop(g);
    assert!(st.maps.lock().unwrap().is_empty(), "Drop must delete");
    assert_eq!(st.deletes.load(SeqCst), 2);

    let before = st.adds.load(SeqCst);
    let g = probe_targets(t(Some(srv), None), 7902, 2).await.guard.unwrap();
    tokio::time::sleep(Duration::from_millis(2600)).await;
    assert!(st.adds.load(SeqCst) - before >= 3, "initial + >=2 renewals");
    // Renewals reuse the creation nonce (the mock asserts it on delete).
    g.release().await.unwrap();
    let after = st.adds.load(SeqCst);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(st.adds.load(SeqCst), after, "no renewal after release");
}

#[tokio::test]
async fn pcp_result_codes_map_to_refused_with_names() {
    for (code, name) in [
        (2u8, "NOT_AUTHORIZED"), (3, "MALFORMED_REQUEST"), (5, "UNSUPP_OPTION"), (6, "MALFORMED_OPTION"),
        (7, "NETWORK_FAILURE"), (8, "NO_RESOURCES"), (9, "UNSUPP_PROTOCOL"), (10, "USER_EX_QUOTA"),
        (11, "CANNOT_PROVIDE_EXTERNAL"), (12, "ADDRESS_MISMATCH"), (13, "EXCESSIVE_REMOTE_PEERS"),
    ] {
        let srv = spawn_pcp(Mode::Result(code), Arc::new(Pcp::default()));
        let r = probe_targets(t(Some(srv), None), 8000, 0).await;
        assert_eq!(r.pcp, Outcome::Refused { code: code as u32, reason: name.into() });
        assert!(r.guard.is_none());
    }
    for m in [Mode::Result(4), Mode::UnsuppV2, Mode::UnsuppV0] {
        let srv = spawn_pcp(m, Arc::new(Pcp::default()));
        assert_eq!(probe_targets(t(Some(srv), None), 8000, 0).await.pcp, Outcome::Unsupported);
    }
}

#[tokio::test]
async fn pcp_invalid_replies_are_ignored_not_trusted() {
    for m in [Mode::Short, Mode::WrongNonce, Mode::WrongVersion, Mode::WrongOpcode] {
        let st = Arc::new(Pcp::default());
        let srv = spawn_pcp(m, st.clone());
        let start = Instant::now();
        let r = probe_targets(t(Some(srv), None), 8100, 0).await;
        assert!(r.guard.is_none());
        assert!(matches!(r.pcp, Outcome::Error(ref e) if e.contains("invalid reply")), "{:?}", r.pcp);
        assert!(start.elapsed() < Duration::from_secs(4));
    }
}

#[tokio::test]
async fn natpmp_fallback_after_pcp_unsupported() {
    for m in [Mode::UnsuppV2, Mode::UnsuppV0] {
        let pmp = Arc::new(Pmp::default());
        let r = probe_targets(
            t(Some(spawn_pcp(m, Arc::new(Pcp::default()))), Some(spawn_pmp(None, pmp.clone()))),
            8200,
            0,
        )
        .await;
        assert_eq!(r.pcp, Outcome::Unsupported);
        assert!(matches!(r.natpmp, Outcome::Mapped { external_port: 8200, .. }));
        let g = r.guard.unwrap();
        assert_eq!(g.method, "natpmp");
        g.release().await.unwrap();
        assert!(pmp.maps.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn pcp_wins_and_a_losing_natpmp_mapping_is_deleted() {
    let (pcp, pmp) = (Arc::new(Pcp::default()), Arc::new(Pmp::default()));
    // NAT-PMP hands out port+1, so it is a distinct entry that must not leak.
    let pmp_addr = spawn_pmp_shift(None, 1, pmp.clone());
    let r = probe_targets(t(Some(spawn_pcp(Mode::Normal, pcp)), Some(pmp_addr)), 8300, 0).await;
    let g = r.guard.unwrap();
    assert_eq!((g.method, g.external_port), ("pcp", 8300));
    settle(|| pmp.deletes.load(SeqCst) == 1).await;
    assert_eq!(pmp.deletes.load(SeqCst), 1, "loser deleted");
    assert!(pmp.maps.lock().unwrap().is_empty());
    g.release().await.unwrap();
}

#[tokio::test]
async fn all_silent_is_no_answer_within_budget() {
    let pcp = spawn_pcp(Mode::Silent, Arc::new(Pcp::default()));
    let pmp = {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let a = u.local_addr().unwrap();
        std::mem::forget(u); // bound, never answers
        a
    };
    // A TCP port that never answers HTTP for UPnP.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let probe = format!("http://{}/rootDesc.xml", l.local_addr().unwrap());
    let mut targets = t(Some(pcp), Some(pmp));
    targets.upnp_probes = vec![probe];
    let start = Instant::now();
    let r = probe_targets(targets, 8400, 0).await;
    let took = start.elapsed();
    assert!(took < Duration::from_millis(4600), "took {took:?}");
    assert_eq!((r.pcp.clone(), r.natpmp.clone(), r.upnp.clone()), (Outcome::NoAnswer, Outcome::NoAnswer, Outcome::NoAnswer));
    assert_eq!(
        explain(&r),
        "The router did not answer UPnP, NAT-PMP or PCP requests; these are probably turned off in its settings."
    );
}

fn rep(pcp: Outcome, natpmp: Outcome, upnp: Outcome) -> MapperReport {
    MapperReport { pcp, natpmp, upnp, guard: None }
}

#[test]
fn explain_table() {
    let no = || Outcome::NoAnswer;
    let refused = |c: u32| Outcome::Refused { code: c, reason: "x".into() };
    let silent = "The router did not answer UPnP, NAT-PMP or PCP requests; these are probably turned off in its settings.";
    let cases: Vec<(MapperReport, String)> = vec![
        (rep(no(), no(), no()), silent.into()),
        (rep(Outcome::Unsupported, Outcome::Unsupported, no()), silent.into()),
        (rep(no(), no(), refused(606)),
         "The router answered UPnP but refused the mapping (error 606): enable UPnP in the router settings.".into()),
        (rep(no(), refused(2), no()),
         "The router answered NAT-PMP but refused the mapping (error 2): enable NAT-PMP in the router settings.".into()),
        (rep(refused(2), no(), no()),
         "The router answered PCP but refused the mapping (error 2): enable PCP in the router settings.".into()),
        (rep(refused(2), refused(2), refused(501)),
         "The router answered PCP and NAT-PMP and UPnP but refused the mapping (PCP error 2, NAT-PMP error 2, UPnP error 501): enable PCP/NAT-PMP/UPnP in the router settings.".into()),
        (rep(no(), no(), Outcome::Error("HTTP timeout".into())), "Port mapping failed (UPnP: HTTP timeout).".into()),
        (rep(Outcome::Error("a".into()), no(), Outcome::Error("b".into())), "Port mapping failed (PCP: a; UPnP: b).".into()),
        // Refusal outranks transport errors.
        (rep(no(), Outcome::Error("e".into()), refused(606)),
         "The router answered UPnP but refused the mapping (error 606): enable UPnP in the router settings.".into()),
    ];
    for (r, want) in cases {
        assert_eq!(explain(&r), want);
    }
}

/// Real router: `cargo test --release --no-default-features --test pcp_mock -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn real_router_probe() {
    let r = nat_tunnel::upnp::probe_mappers(7123, 120).await;
    println!("PCP:    {:?}\nNAT-PMP:{:?}\nUPnP:   {:?}\nexplain: {}", r.pcp, r.natpmp, r.upnp, explain(&r));
    if let Some(g) = r.guard {
        println!("released: {:?}", g.release().await);
    }
}
