//! Handshake v2 security: ephemeral X25519 inside JOIN/ACCEPT. Loopback only.

use std::net::SocketAddr;
use std::time::Duration;

use nat_tunnel::transport::*;
use nat_tunnel::tunnel::crypto::CryptoError;
use tokio::net::UdpSocket;
use x25519_dalek::PublicKey;

const KEY: &str = "handshake-security-key";

async fn host() -> (MuxHost, SocketAddr) {
    let h = MuxHost::bind(KEY, MuxConfig { bind_port: Some(0), ..Default::default() })
        .await
        .unwrap();
    let a: SocketAddr = format!("127.0.0.1:{}", h.local_port().unwrap()).parse().unwrap();
    (h, a)
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
    cpub: [u8; 32],
    hn: [u8; 16],
    hpub: [u8; 32],
    dh: [u8; 32],
    join: Vec<u8>,
    accept: Vec<u8>,
}

async fn do_join(h: &mut MuxHost, s: &UdpSocket, to: SocketAddr, key: &str) -> Option<Joined> {
    let cn = *uuid::Uuid::new_v4().as_bytes();
    let (secret, cpub) = hs_keypair();
    let join = hs_join(key, &cn, &cpub);
    let accept = exchange_some(h, s, to, &join).await?;
    assert_eq!((accept[0], accept.len()), (0xF6, 83));
    let hn = accept[19..35].try_into().unwrap();
    let hpub: [u8; 32] = accept[35..67].try_into().unwrap();
    let dh = *secret.diffie_hellman(&PublicKey::from(hpub)).as_bytes();
    Some(Joined { cn, cpub, hn, hpub, dh, join, accept })
}

#[tokio::test]
async fn invite_holder_who_captured_a_handshake_cannot_read_that_peer() {
    let (mut h, addr) = host().await;
    let (sa, sb, mallory) = (sock().await, sock().await, sock().await);
    let a = do_join(&mut h, &sa, addr, KEY).await.expect("A joins");
    let _b = do_join(&mut h, &sb, addr, KEY).await.expect("B joins");
    assert_eq!(h.peer_count(), 2);

    // A seals a frame with its real session.
    let mut a_client = hs_session(KEY, &a.dh, &a.cn, &a.hn, &a.cpub, &a.hpub, false);
    let sealed = a_client.seal(b"A's private payload");

    // Mallory: valid invite, captured A's whole JOIN and ACCEPT (a.join, a.accept),
    // so she knows cn, hn, cpub, hpub and the invite key. Every derivation she can
    // build from those must fail; the DH secret is the only missing input.
    let (m_secret, m_pub) = hs_keypair();
    let guesses: Vec<[u8; 32]> = vec![
        [0u8; 32],
        a.cpub,
        a.hpub,
        a.cn.iter().chain(&a.hn).cloned().cycle().take(32).collect::<Vec<_>>().try_into().unwrap(),
        *m_secret.diffie_hellman(&PublicKey::from(a.hpub)).as_bytes(),
        *hs_keypair().0.diffie_hellman(&PublicKey::from(a.cpub)).as_bytes(),
        m_pub,
    ];
    for dh in &guesses {
        for host_dir in [true, false] {
            let mut m = hs_session(KEY, dh, &a.cn, &a.hn, &a.cpub, &a.hpub, host_dir);
            assert_eq!(m.open(&sealed), Err(CryptoError::BadTag));
        }
    }
    assert!(a.join.len() == 65 && a.accept.len() == 83);

    // The real host-side session still opens it (the derivation itself is sound).
    let mut a_host = hs_session(KEY, &a.dh, &a.cn, &a.hn, &a.cpub, &a.hpub, true);
    assert_eq!(a_host.open(&sealed).unwrap().0, b"A's private payload");

    // Admission is unchanged: Mallory can still join as her own peer.
    assert!(do_join(&mut h, &mallory, addr, KEY).await.is_some());
    assert_eq!(h.peer_count(), 3);
}

#[tokio::test]
async fn tampered_join_is_ignored() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    let cn = [7u8; 16];
    let (_sec, cpub) = hs_keypair();
    let good = hs_join(KEY, &cn, &cpub);
    // Flip one bit in every byte position: nonce, pubkey, mac (tag byte -> not a JOIN).
    for i in 1..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        assert!(exchange(&mut h, &s, addr, &bad).await.is_none(), "byte {i} accepted");
    }
    // Truncated / extended.
    assert!(exchange(&mut h, &s, addr, &good[..64]).await.is_none());
    let mut long = good.clone();
    long.push(0);
    assert!(exchange(&mut h, &s, addr, &long).await.is_none());
    assert_eq!(h.peer_count(), 0, "no slot burned");
    // The untampered JOIN still works afterwards (cn was not consumed).
    assert!(exchange_some(&mut h, &s, addr, &good).await.is_some());
    assert_eq!(h.peer_count(), 1);
}

#[tokio::test]
async fn low_order_client_pubkey_is_refused() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    // All-zero point gives an all-zero DH output; even with a valid MAC it must be refused.
    let d = hs_join(KEY, &[9u8; 16], &[0u8; 32]);
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
    let r = Tunnel::connect(ConnectOpts {
        signal: None,
        peer: Some(addr),
        room: "",
        key: "some-other-invite",
        host: false,
        bind_port: None,
        hosts: vec![],
        mux: true,
    });
    let pump = async {
        loop {
            let _ = h.try_recv().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        r = r => assert!(r.is_err(), "wrong key must not join"),
        _ = pump => unreachable!(),
    }
}

#[tokio::test]
async fn old_version_handshake_fails_cleanly() {
    let (mut h, addr) = host().await;
    let s = sock().await;
    let v1 = hs_join_v1(KEY, &[3u8; 16]);
    assert_eq!(v1.len(), 33);
    assert!(exchange(&mut h, &s, addr, &v1).await.is_none());
    assert_eq!(h.peer_count(), 0);
    // And a v1-style host (silent to v2 JOINs) makes a new client time out cleanly.
    let old_host = sock().await;
    let old_addr = old_host.local_addr().unwrap();
    let c = tokio::spawn(async move {
        Tunnel::connect(ConnectOpts {
            signal: None,
            peer: Some(old_addr),
            room: "",
            key: KEY,
            host: false,
            bind_port: None,
            hosts: vec![],
            mux: true,
        })
        .await
    });
    let mut buf = [0u8; 256];
    let (n, from) = old_host.recv_from(&mut buf).await.unwrap();
    assert_eq!((buf[0], n), (0xF5, 65), "new client sends v2 JOIN, not v1");
    // Reply with a v1-shaped ACCEPT (0xF2, 51 bytes): must be dropped, not misparsed.
    let mut v1_accept = vec![0xF2u8; 51];
    v1_accept[3..19].copy_from_slice(&buf[1..17]);
    old_host.send_to(&v1_accept, from).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), c).await.unwrap().unwrap();
    let e = r.err().expect("must not connect");
    assert!(
        matches!(ConnectError::from_io(&e), Some(ConnectError::HostUnreachable)),
        "got {e}"
    );
}

#[tokio::test]
async fn client_rejects_tampered_accept_and_accepts_honest_one() {
    for tamper in [true, false] {
        let fake = sock().await;
        let addr = fake.local_addr().unwrap();
        let c = tokio::spawn(async move {
            Tunnel::connect(ConnectOpts {
                signal: None,
                peer: Some(addr),
                room: "",
                key: KEY,
                host: false,
                bind_port: None,
                hosts: vec![],
                mux: true,
            })
            .await
        });
        let mut buf = [0u8; 256];
        let (n, from) = fake.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 65);
        let cn: [u8; 16] = buf[1..17].try_into().unwrap();
        let cpub: [u8; 32] = buf[17..49].try_into().unwrap();
        let (hsec, hpub) = hs_keypair();
        let hn = [5u8; 16];
        let mut accept = hs_accept(KEY, 0, (&cn, &hn), (&cpub, &hpub));
        if tamper {
            accept[40] ^= 1; // hpub byte; MAC no longer matches
        }
        let dh = *hsec.diffie_hellman(&PublicKey::from(cpub)).as_bytes();
        // Honest host also follows with a sealed ASSIGN (10.7.0.2/16 via 10.7.0.1).
        let mut sess = hs_session(KEY, &dh, &cn, &hn, &cpub, &hpub, true);
        let mut data = vec![0xF4, 0, 0];
        data.extend(sess.seal(&[0xC0, 10, 7, 0, 2, 16, 10, 7, 0, 1]));
        fake.send_to(&accept, from).await.unwrap();
        fake.send_to(&data, from).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(10), c).await.unwrap().unwrap();
        if tamper {
            assert!(r.is_err(), "tampered ACCEPT must not join");
        } else {
            let t = r.expect("honest ACCEPT joins");
            assert!(t.assigned().is_some());
        }
    }
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
