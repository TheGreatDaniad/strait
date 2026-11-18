//! Join handshake security (v3: Noise NKpsk0, host key, personal invites, clock, refusals).
//! Loopback only.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::transport::*;
use nat_tunnel::tunnel::crypto::AeadSession;
use nat_tunnel::tunnel::handshake::{self, ClientHs, Token};
use tokio::net::UdpSocket;

const KEY: &str = "handshake-security-key";
const ACCEPT_LEN: usize = 100;

async fn host_with(cfg: MuxConfig) -> (MuxHost, SocketAddr) {
    let host_key = cfg.host_key.or(Some(TEST_HOST_KEY));
    let h = MuxHost::bind(KEY, MuxConfig { bind_port: Some(0), host_key, ..cfg }).await.unwrap();
    let a: SocketAddr = format!("127.0.0.1:{}", h.local_port().unwrap()).parse().unwrap();
    (h, a)
}

async fn host() -> (MuxHost, SocketAddr) {
    host_with(MuxConfig::default()).await
}

async fn sock() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

/// Send `d` to the host, let it process, return the first reply datagram.
async fn exchange(h: &mut MuxHost, s: &UdpSocket, to: SocketAddr, d: &[u8]) -> Option<Vec<u8>> {
    s.send_to(d, to).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    while h.try_recv().await.unwrap().is_some() {}
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(150), s.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Like `exchange`, for cases where a reply IS expected: UDP on a loaded machine can be slower than
/// one 150 ms window, so resend the same datagram (a same-address retransmit repeats the ACCEPT).
/// Negative checks keep using `exchange` so they stay fast.
async fn exchange_some(h: &mut MuxHost, s: &UdpSocket, to: SocketAddr, d: &[u8]) -> Option<Vec<u8>> {
    for _ in 0..10 {
        if let Some(r) = exchange(h, s, to, d).await {
            return Some(r);
        }
    }
    None
}

struct Joined {
    cn: [u8; 16],
    join: Vec<u8>,
    accept: Vec<u8>,
    slot: u16,
    session: AeadSession,
}

async fn do_join_as(h: &mut MuxHost, s: &UdpSocket, to: SocketAddr, key: &str, auth: JoinAuth) -> Option<Joined> {
    let cn = *uuid::Uuid::new_v4().as_bytes();
    let (mut hs, join) = hs_join(key, &cn, auth);
    let accept = exchange_some(h, s, to, &join).await?;
    assert_eq!((accept[0], accept.len()), (0xF9, ACCEPT_LEN));
    let (slot, session) = hs_finish(key, &mut hs, &cn, &accept)?; // None for a refusal
    Some(Joined { cn, join, accept, slot, session })
}

async fn do_join(h: &mut MuxHost, s: &UdpSocket, to: SocketAddr, key: &str) -> Option<Joined> {
    do_join_as(h, s, to, key, JoinAuth::test()).await
}

fn named(key: &[u8; 32], token: Option<[u8; 24]>) -> JoinAuth {
    JoinAuth { host_key: Some(handshake::public_of(key)), token, ..Default::default() }
}

fn opts<'a>(addr: SocketAddr, key: &'a str, auth: JoinAuth) -> ConnectOpts<'a> {
    ConnectOpts { signal: None, peer: Some(addr), room: "", key, host: false, bind_port: None, hosts: vec![], mux: true, auth }
}

/// Drive the host while `f` runs.
async fn with_host<T>(h: &mut MuxHost, f: impl std::future::Future<Output = T>) -> T {
    let pump = async {
        loop {
            let _ = h.try_recv().await;
            let _ = h.tick().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        r = f => r,
        _ = pump => unreachable!(),
    }
}

#[tokio::test]
async fn invite_holder_who_captured_a_handshake_cannot_read_that_peer() {
    let (mut h, addr) = host().await;
    let (sa, sb, mallory) = (sock().await, sock().await, sock().await);
    let mut a = do_join(&mut h, &sa, addr, KEY).await.expect("A joins");
    let _b = do_join(&mut h, &sb, addr, KEY).await.expect("B joins");
    assert_eq!(h.peer_count(), 2);
    let sealed = a.session.seal(b"A's private payload");

    // Mallory: valid invite, captured A's whole JOIN and ACCEPT, but not the host key. She cannot
    // read A's JOIN, and a client handshake of her own does not open A's ACCEPT.
    assert!(hs_accept(KEY, handshake::new_host_key(), a.slot, &a.join).is_none());
    let (mut hs2, _) = hs_join(KEY, &a.cn, JoinAuth::test());
    assert!(hs_finish(KEY, &mut hs2, &a.cn, &a.accept).is_none(), "A's ACCEPT finishes only A's handshake");

    // Admission is unchanged: Mallory can still join as her own peer.
    assert!(do_join(&mut h, &mallory, addr, KEY).await.is_some());
    assert_eq!(h.peer_count(), 3);
    let _ = sealed;
}

#[tokio::test]
async fn tampered_join_is_ignored() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    let cn = [7u8; 16];
    let (_hs, good) = hs_join(KEY, &cn, JoinAuth::test());
    // Flip one bit in every byte position: nonce, handshake message, mac (type byte -> not a JOIN).
    for i in 1..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        assert!(exchange(&mut h, &s, addr, &bad).await.is_none(), "byte {i} accepted");
    }
    // Truncated / extended.
    assert!(exchange(&mut h, &s, addr, &good[..good.len() - 1]).await.is_none());
    let mut long = good.clone();
    long.push(0);
    assert!(exchange(&mut h, &s, addr, &long).await.is_none());
    assert_eq!(h.peer_count(), 0, "no slot burned");
    // The untampered JOIN still works afterwards (cn was not consumed).
    assert!(exchange_some(&mut h, &s, addr, &good).await.is_some());
    assert_eq!(h.peer_count(), 1);
}

#[tokio::test]
async fn low_order_client_key_is_refused() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    // An all-zero ephemeral key under a valid outer MAC: an invite holder can build this.
    let cn = [9u8; 16];
    let base = hs_base(KEY);
    let mut msg1 = vec![0u8; 52];
    msg1[32..].fill(0xAA);
    let d = hs_join_raw(&base, &cn, &msg1);
    assert!(exchange(&mut h, &s, addr, &d).await.is_none());
    assert_eq!(h.peer_count(), 0);
}

#[tokio::test]
async fn replayed_join_does_not_burn_slots_or_rebind() {
    let (mut h, addr) = host().await;
    let (sa, attacker) = (sock().await, sock().await);
    let a = do_join(&mut h, &sa, addr, KEY).await.unwrap();
    // Replay from another address: ignored.
    assert!(exchange(&mut h, &attacker, addr, &a.join).await.is_none());
    assert_eq!(h.peer_count(), 1);
    // From A's own address a retransmit just repeats the same ACCEPT.
    let mut junk = [0u8; 2048]; // the ASSIGN that followed the first ACCEPT
    let _ = tokio::time::timeout(Duration::from_millis(100), sa.recv_from(&mut junk)).await;
    let again = exchange_some(&mut h, &sa, addr, &a.join).await.expect("retransmit answered");
    assert_eq!(again, a.accept);
    assert_eq!(h.peer_count(), 1);
}

#[tokio::test]
async fn wrong_invite_key_cannot_join() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    assert!(do_join(&mut h, &s, addr, "some-other-invite").await.is_none());
    assert_eq!(h.peer_count(), 0);
    // A real client with the wrong key fails to connect, too.
    let r = with_host(&mut h, Tunnel::connect(opts(addr, "some-other-invite", JoinAuth::test()))).await;
    assert!(r.is_err(), "wrong key must not join");
}

#[tokio::test]
async fn old_version_handshake_fails_cleanly() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    // A v2 JOIN (0xF5, 65 bytes) is not a v3 JOIN: ignored, no slot.
    let mut v2 = vec![0xF5u8; 65];
    v2[1..17].fill(3);
    assert!(exchange(&mut h, &s, addr, &v2).await.is_none());
    assert_eq!(h.peer_count(), 0);
    // And a host that answers in the old format makes a new client time out cleanly.
    let old_host = sock().await;
    let old_addr = old_host.local_addr().unwrap();
    let c = tokio::spawn(async move { Tunnel::connect(opts(old_addr, KEY, JoinAuth::test())).await });
    let mut buf = [0u8; 256];
    let (n, from) = old_host.recv_from(&mut buf).await.unwrap();
    assert_eq!((buf[0], n), (0xF8, 85), "new client sends a v3 JOIN");
    let mut v2_accept = vec![0xF6u8; 83];
    v2_accept[3..19].copy_from_slice(&buf[1..17]);
    old_host.send_to(&v2_accept, from).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), c).await.unwrap().unwrap();
    let e = r.err().expect("must not connect");
    assert!(matches!(ConnectError::from_io(&e), Some(ConnectError::HostUnreachable)), "got {e}");
}

/// A hand-made host: honest, tampering, or one that holds the invite but not the host key.
#[tokio::test]
async fn client_accepts_only_the_host_the_invite_names() {
    let real = handshake::new_host_key();
    let auth = named(&real, None);
    for case in ["honest", "tampered", "impostor"] {
        let fake = sock().await;
        let addr = fake.local_addr().unwrap();
        let auth = auth.clone();
        let c = tokio::spawn(async move { Tunnel::connect(opts(addr, KEY, auth.clone())).await });
        let mut buf = [0u8; 256];
        let (n, from) = fake.recv_from(&mut buf).await.unwrap();
        let join = &buf[..n];
        // The impostor has the invite and a key of its own. It cannot read the client's JOIN, so
        // the best it can send is an ACCEPT from a handshake it ran against itself.
        let reply = match case {
            "impostor" => {
                let mine = handshake::new_host_key();
                assert!(hs_accept(KEY, mine, 0, join).is_none(), "the invite alone cannot answer");
                let cn: [u8; 16] = join[1..17].try_into().unwrap();
                let (_, j) = hs_join(KEY, &cn, named(&mine, None));
                hs_accept(KEY, mine, 0, &j)
            }
            _ => hs_accept(KEY, real, 0, join),
        };
        let (mut accept, mut sess) = reply.expect("accept built");
        if case == "tampered" {
            accept[40] ^= 1;
        }
        // An honest host follows with a sealed ASSIGN (10.7.0.2/16 via 10.7.0.1).
        let mut data = vec![0xF4, 0, 0];
        data.extend(sess.seal(&[0xC0, 10, 7, 0, 2, 16, 10, 7, 0, 1]));
        fake.send_to(&accept, from).await.unwrap();
        fake.send_to(&data, from).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(12), c).await.unwrap().unwrap();
        match case {
            "honest" => assert!(r.expect("honest host is joined").assigned().is_some()),
            _ => assert!(r.is_err(), "{case} host must not be joined"),
        }
    }
}

/// End to end with real ends: a host with its own key serves the invite that names it, and
/// refuses nobody else's handshake state.
#[tokio::test]
async fn host_key_end_to_end() {
    let key = handshake::new_host_key();
    let (mut h, addr) = host_with(MuxConfig { host_key: Some(key), ..Default::default() }).await;
    let good = named(&key, None);
    let t = with_host(&mut h, Tunnel::connect(opts(addr, KEY, good))).await.expect("joins");
    assert!(t.assigned().is_some());
    // An invite without the host key (or with another one) expects a different host: no join.
    let r = with_host(&mut h, tokio::time::timeout(Duration::from_secs(6), Tunnel::connect(opts(addr, KEY, named(&handshake::new_host_key(), None))))).await;
    assert!(!matches!(r, Ok(Ok(_))), "a client expecting another host key must not join");
    // An invite without a host key is refused before anything is sent.
    let e = Tunnel::connect(opts(addr, KEY, JoinAuth::default())).await.err().expect("refused");
    assert!(e.to_string().contains("no host key"), "{e}");
}

#[tokio::test]
async fn personal_invites_admit_expire_and_can_be_withdrawn() {
    let key = handshake::new_host_key();
    let tk = handshake::token_key(&key, KEY);
    let policy = GuestPolicy::default();
    let (mut h, addr) = host_with(MuxConfig { host_key: Some(key), guests: policy.clone(), ..Default::default() }).await;
    let hk = Some(handshake::public_of(&key));
    let with = |t: Token| JoinAuth { host_key: hk, token: Some(handshake::mint(&tk, t)), ..Default::default() };
    let now = handshake::now_secs();

    // A valid personal invite joins and the host learns which one it was.
    let s = sock().await;
    assert!(do_join_as(&mut h, &s, addr, KEY, with(Token { id: 7, expires: now + 3600 })).await.is_some());
    // An expired one, one minted by someone else, and a withdrawn one are refused with an answer.
    let refused = |r: Result<Tunnel, std::io::Error>| matches!(r.as_ref().err().and_then(ConnectError::from_io), Some(ConnectError::Refused));
    let r = with_host(&mut h, Tunnel::connect(opts(addr, KEY, with(Token { id: 8, expires: now - 1 })))).await;
    assert!(refused(r), "expired");
    let foreign = handshake::mint(&handshake::token_key(&handshake::new_host_key(), KEY), Token { id: 9, expires: 0 });
    let r = with_host(&mut h, Tunnel::connect(opts(addr, KEY, JoinAuth { host_key: hk, token: Some(foreign), ..Default::default() }))).await;
    assert!(refused(r), "not this host's token");
    policy.revoked.lock().unwrap().insert(7);
    let r = with_host(&mut h, Tunnel::connect(opts(addr, KEY, with(Token { id: 7, expires: 0 })))).await;
    assert!(refused(r), "withdrawn");
    // Withdrawing also ends the live session (the host re-checks admission every tick).
    assert_eq!(h.peer_count(), 0);
    // Without a token the shared invite still works, unless the host takes personal invites only.
    let t = with_host(&mut h, Tunnel::connect(opts(addr, KEY, named(&key, None)))).await;
    assert!(t.is_ok());
    let (mut strict, saddr) =
        host_with(MuxConfig { host_key: Some(key), guests: GuestPolicy { require_token: std::sync::Arc::new(true.into()), ..Default::default() }, ..Default::default() }).await;
    let r = with_host(&mut strict, Tunnel::connect(opts(saddr, KEY, named(&key, None)))).await;
    assert!(refused(r), "personal invites only");
    let t = with_host(&mut strict, Tunnel::connect(opts(saddr, KEY, with(Token { id: 1, expires: 0 })))).await;
    assert!(t.is_ok());
}

/// A copied personal invite cannot be used next to its owner: while one device's session is live,
/// another device with the same personal invite is told the host is full. Other invites still work.
#[tokio::test]
async fn a_personal_invite_works_on_one_device_at_a_time() {
    let key = handshake::new_host_key();
    let tk = handshake::token_key(&key, KEY);
    let (mut h, addr) = host_with(MuxConfig { host_key: Some(key), max_clients: 4, ..Default::default() }).await;
    let hk = Some(handshake::public_of(&key));
    let with = |id: u32| JoinAuth { host_key: hk, token: Some(handshake::mint(&tk, Token { id, expires: 0 })), ..Default::default() };
    let owner = sock().await;
    let mut a = do_join_as(&mut h, &owner, addr, KEY, with(3)).await.expect("owner joins");
    let mut d = vec![0xF4];
    d.extend_from_slice(&a.slot.to_be_bytes());
    d.extend_from_slice(&a.session.seal(&[0xC1]));
    owner.send_to(&d, addr).await.unwrap();
    for _ in 0..20 {
        while h.try_recv().await.unwrap().is_some() {}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let r = with_host(&mut h, Tunnel::connect(opts(addr, KEY, with(3)))).await;
    assert!(matches!(r.as_ref().err().and_then(ConnectError::from_io), Some(ConnectError::HostFull)), "second device refused");
    assert!(with_host(&mut h, Tunnel::connect(opts(addr, KEY, with(4)))).await.is_ok(), "another person's invite works");
    assert!(with_host(&mut h, Tunnel::connect(opts(addr, KEY, named(&key, None)))).await.is_ok(), "the shared invite works");
}

#[tokio::test]
async fn host_bind_on_taken_port_fails_with_port_in_use() {
    let (first, _) = host().await;
    let port = first.local_port().unwrap();
    let e = match MuxHost::bind(KEY, MuxConfig { bind_port: Some(port), ..Default::default() }).await {
        Ok(_) => panic!("second host must not bind the same UDP port"),
        Err(e) => e,
    };
    assert!(matches!(ConnectError::from_io(&e), Some(ConnectError::PortInUse(p)) if *p == port), "{e}");
}

/// After a host restart the `seen` set is empty, so a captured JOIN is accepted again. It must not
/// hold a slot: only a packet under the new session key (which a replayer cannot make) confirms
/// one, unconfirmed joins give way to real clients and expire.
#[tokio::test]
async fn replayed_join_after_host_restart_cannot_hold_a_slot() {
    let (mut h, addr) = host_with(MuxConfig { max_clients: 2, ..Default::default() }).await;
    let (replayer, legit) = (sock().await, sock().await);
    // Two captured JOINs (valid, replayed from a fresh host's point of view) fill the host.
    for n in 0..2u8 {
        let (_hs, j): (ClientHs, _) = hs_join(KEY, &[n + 1; 16], JoinAuth::test());
        assert!(exchange_some(&mut h, &replayer, addr, &j).await.is_some());
    }
    assert_eq!(h.peer_count(), 2);
    // A real client still gets in (once the replayed joins are past their short grace time), and
    // proves itself with a packet under its session key.
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut a = loop {
        if let Some(a) = do_join(&mut h, &legit, addr, KEY).await {
            break a;
        }
        assert!(std::time::Instant::now() < deadline, "legitimate client joins a 'full' host");
    };
    assert_eq!(h.peer_count(), 2);
    let mut d = vec![0xF4];
    d.extend_from_slice(&a.slot.to_be_bytes());
    d.extend_from_slice(&a.session.seal(&[0xC1]));
    legit.send_to(&d, addr).await.unwrap();
    // The surviving replayed join never confirms and expires; the real one stays.
    let end = std::time::Instant::now() + Duration::from_millis(20600);
    while std::time::Instant::now() < end {
        while h.try_recv().await.unwrap().is_some() {}
        h.tick().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(h.peer_count(), 1, "replayed join expired, confirmed client kept");
}

/// A JOIN whose clock is far off is answered with an authenticated "clock" refusal; one inside
/// the window is accepted.
#[tokio::test]
async fn stale_join_is_refused_with_a_clock_verdict() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    let now = handshake::now_secs();
    let (mut hs, old) = hs_join_at(KEY, &[1; 16], JoinAuth::test(), Some(now - handshake::JOIN_MAX_SKEW - 5));
    let reply = exchange_some(&mut h, &s, addr, &old).await.expect("answered");
    assert!(hs_finish(KEY, &mut hs, &[1; 16], &reply).is_none(), "not an acceptance");
    assert_eq!(h.peer_count(), 0);
    let (_hs, ok) = hs_join_at(KEY, &[2; 16], JoinAuth::test(), Some(now - 60));
    assert!(exchange_some(&mut h, &s, addr, &ok).await.is_some());
    assert_eq!(h.peer_count(), 1);
}

/// Someone with the invite but not the host key cannot make a client give up: a refusal
/// built without the host key does not open, and the client keeps trying.
#[tokio::test]
async fn forged_refusal_is_ignored() {
    let fake = sock().await;
    let addr = fake.local_addr().unwrap();
    let c = tokio::spawn(async move { Tunnel::connect(opts(addr, KEY, JoinAuth::test())).await });
    let mut buf = [0u8; 256];
    let (n, from) = fake.recv_from(&mut buf).await.unwrap();
    let cn: [u8; 16] = buf[1..17].try_into().unwrap();
    let mine = handshake::new_host_key();
    let (_, j) = hs_join(KEY, &cn, named(&mine, None));
    let (forged, _) = hs_accept(KEY, mine, 0, &j).unwrap();
    fake.send_to(&forged, from).await.unwrap();
    let _ = n;
    // Still joining: a second JOIN arrives (from a fresh handshake) instead of a "refused" error.
    let (n2, _) = tokio::time::timeout(Duration::from_secs(3), fake.recv_from(&mut buf)).await.expect("keeps trying").unwrap();
    assert_eq!((buf[0], n2), (0xF8, 85));
    c.abort();
}

/// Forward mode (one guest, TCP bridge) runs the same handshake: the host key decides.
#[tokio::test]
async fn forward_mode_uses_the_handshake() {
    let host_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = host_sock.local_addr().unwrap().port();
    drop(host_sock);
    let host = tokio::spawn(async move {
        Tunnel::connect(ConnectOpts { signal: None, peer: None, room: "", key: KEY, host: true, bind_port: Some(port), hosts: vec![], mux: false, auth: JoinAuth::test() }).await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut guest = Tunnel::connect(ConnectOpts { mux: false, ..opts(addr, KEY, JoinAuth::test()) }).await.expect("guest joins");
    let mut host = tokio::time::timeout(Duration::from_secs(10), host).await.unwrap().unwrap().expect("host session");
    guest.send(b"over the handshake key").await.unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(5);
    let mut got = None;
    while got.is_none() && std::time::Instant::now() < end {
        host.tick().await.unwrap();
        guest.tick().await.unwrap();
        if let Some(Event::Data(d)) = host.try_recv().await.unwrap() {
            got = Some(d);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(got.as_deref(), Some(&b"over the handshake key"[..]));
    // A guest expecting another host key never gets a session.
    let r = tokio::time::timeout(Duration::from_secs(4), Tunnel::connect(ConnectOpts { mux: false, ..opts(addr, KEY, named(&handshake::new_host_key(), None)) })).await;
    assert!(!matches!(r, Ok(Ok(_))));
}
