# Tunnel carriers: making the packet path pluggable

Status: research and design, revised 2026-11-06 after the user chose the carriers. No source changes were made. Nothing third-party was downloaded, run or built; all findings come from reading web pages and crates.io/GitHub metadata, which are treated as untrusted data.

Evidence tags:
- (V) read on the cited page on 2026-11-06.
- (L) read from this repository.
- (U) UNVERIFIED: from memory, from one secondary source, or my own inference.
- "anecdotal" = user reports in issue trackers/blogs without controlled measurement.

Chosen carriers, in implementation order:
1. shadowsocks-rust (embedded crate)
2. wstunnel (WebSocket / HTTP-2 / TLS)
3. AmneziaWG (obfuscated WireGuard)
4. Xray-core / sing-box: VLESS + REALITY, XTLS-Vision, XHTTP (supervised sidecar)
Later: dnstt, slipstream, iodine (short section 9). QUIC/MASQUE was not selected (appendix only).

Invariants every carrier must keep: payload only between the two peers; no third-party relay (a carrier is a transport between the peers or to the host itself, e.g. our own VPS); the end-to-end AEAD of handshake v2 stays inside every carrier, so every carrier is untrusted; failure is explicit.

---

## 0. Summary

- The abstraction is small: about 32 `send_to`/`recv_from` sites, all in `src/transport.rs` (L). Introduce one trait `FrameIo` (section 2). Embedded Rust carriers (1, 2, parts of 3) and the supervised sidecar (4) implement the same trait; a sidecar is just a `FrameIo` over a loopback socket plus a supervisor.
- Honest ranking of what each carrier buys (details in sections 3 to 6):

| # | Carrier | Rides the hole punch? | Needs reachable host? | What it really adds | Main caveat |
|---|---|---|---|---|---|
| 1 | Shadowsocks-2022 | UDP mode yes (in principle) | TCP mode yes | Standard AEAD wrapper, replay and probing resistance on TCP, plugin hook | Looks like "fully encrypted traffic", which the GFW has blocked since 2021 (V). Adds little over our own AEAD on UDP |
| 2 | wstunnel | no | yes | TLS/WebSocket/HTTP-2 on 443 with a real certificate and domain | Stream semantics (TCP-in-TCP); `wstunnel` library crate is not on crates.io (V, 404) |
| 3 | AmneziaWG | yes (UDP) | no | DPI-resistant UDP handshake shape (junk packets, header ranges, padding) | WireGuard identity model clashes with 1-to-many invites; Rust implementation is young |
| 4 | Xray VLESS + REALITY / XHTTP | no | yes | Strongest TCP/443 camouflage in the list | Fast-moving, Go, large; active blocking events in Russia and Iran (V, anecdotal) |

- Two findings that shape the work:
  1. A TLS-in-TLS fingerprint still applies to Strait: the user's own HTTPS handshakes appear as packet-size patterns inside any stream carrier. XTLS-Vision cannot help because our payload is already AEAD-sealed (Vision pads only inner TLS it can see). The mitigation must be in our carrier layer: frame padding and coalescing, plus XHTTP's multiplexing (section 6.4).
  2. For the sidecar path, a Strait host behind Xray sees every client as a loopback source address. That works only if each client gets its own loopback source port (to verify in the lab), or if we use a TCP stream carrier (one connection per client). Decide with a lab test, not by assumption (section 6.6).
- Not recommended: pluggable crypto/handshake (section 2.5); OpenVPN (appendix).
- Decisions needed from the user are in section 10.

---

## 1. Where the current transport touches the network (L)

| Component | Socket | Send sites | Receive sites | Peer key |
|---|---|---|---|---|
| `Tunnel` `src/transport.rs:376` (client, and legacy 1:1 host) | `socket: UdpSocket`, `dual: bool` | wrapper `send_to` (l.741): punch/hello, `send_packet` (l.764), `tick` keepalive (l.1101), `close` (l.1132), signal register (l.1162), connect ladder (l.1186-1395) | wrappers `recv_from` (l.745), `try_recv_from` (l.750); `try_recv` (l.953) | `peer: Option<SocketAddr>` |
| `MuxHost` `src/transport.rs:1753` | `socket: UdpSocket`, `dual` | `raw_send` (l.1934), `register` (l.1926), `send_sealed`, `T_PUNCH`, STUN pokes | `try_recv` (l.2112), `readable()` (l.1919) | `Peer.addr: SocketAddr` and `slot u16` in `T_DATA` |
| Socket creation | `bind_marked` (l.2221): dual-stack, 4 MiB buffers, `SO_MARK` (Linux) / `IP_BOUND_IF` (macOS) / interface pin (Windows) so tunnel datagrams skip the TUN default route | | | |

Facts that matter:
- Wire frames: `T_JOIN F5`, `T_ACCEPT F6`, `T_REJECT F7`, `T_DATA F4 [slot u16][sealed]`, `T_PUNCH F0`. AEAD overhead is 16 B header + 16 B tag (`tunnel/crypto.rs`) plus 3 B, so wire size = IP packet + 35 B. With `MAX_PAYLOAD = 1400` (`tunnel/reliable.rs:21`) the largest frame is 1435 B. TUN MTU is hard-coded 1400 (`tunmode.rs:722`) and `send_packet` / `send_to_peer` silently drop larger packets (l.765, l.1954).
- The same UDP socket also carries hole-punch frames, STUN pokes (the mapped port must come from this socket) and signaling registration. Those exist only on a punchable UDP carrier.
- Packet mode has no ARQ ("the inner TCP handles loss"). Replay window and counters tolerate reorder and loss.
- Android already runs the Rust core as a child process: `StraitVpnService.kt` uses `ProcessBuilder` and the binary ships as `libstrait.so` under `jniLibs` (L). The transport socket is not VPN-protected; capture is avoided by leaving the server's /8 off the VPN routes (L, ~l.207-211).
- Sizes today (L): desktop `nat-tunnel` 19 MB (with GUI); Android arm64 `nat-tunnel` 4.2 MB; `libstrait.so` 8.5 MB in jniLibs.
- Toolchain on this machine: rustc 1.96.0, Go 1.25.6.

---

## 2. Carrier abstraction

### 2.1 Principle
A carrier moves opaque, already-sealed frames between two endpoints and reports what it can do. It never sees keys. Frame tags and handshake are byte-identical on every carrier, so one host can serve UDP and non-UDP clients at once.

### 2.2 Trait

```rust
// src/carrier/mod.rs
#[derive(Clone, Copy, Debug)]
pub struct CarrierCaps {
    pub id: &'static str,          // "udp" | "ss" | "ws" | "awg" | "xray"
    pub max_frame: usize,          // largest sealed frame it can move (wire bytes)
    pub punchable: bool,           // only raw/obfuscated UDP on the shared socket
    pub needs_reachable_host: bool,
    pub ordered_reliable: bool,    // stream-backed: bound queues, expect HOL blocking
}
impl CarrierCaps {
    /// Largest IP packet the TUN may carry (35 B = AEAD 32 + mux 3).
    pub fn tun_mtu(&self) -> usize { self.max_frame.saturating_sub(35).min(1400) }
}

#[async_trait::async_trait]
pub trait FrameIo: Send + Sync + 'static {
    fn caps(&self) -> CarrierCaps;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// Best effort, datagram semantics. `to` is a peer key previously returned by recv.
    async fn send_to(&self, frame: &[u8], to: SocketAddr) -> io::Result<usize>;
    /// Same contract as UdpSocket::try_recv_from (Err(WouldBlock) when empty).
    fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn readable(&self) -> io::Result<()>;
    /// Only the raw UDP carrier returns Some: STUN, signal registration and punching use it.
    fn udp(&self) -> Option<&tokio::net::UdpSocket> { None }
    fn health(&self) -> Health { Health::Ok }       // sidecar exited, tls reset, ...
    async fn close(&self) {}
}

pub trait CarrierFactory: Send + Sync {
    fn id(&self) -> &'static str;
    fn disclosure(&self) -> Disclosure;                        // same struct as rendezvous
    async fn probe(&self, spec: &CarrierSpec, t: Duration) -> ProbeStatus;   // publishes nothing
    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError>;   // host
    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError>;     // client
}
```

Design choices:
- Same poll style as `app.rs` already uses (`readable()` then drain `try_recv_from`), so the pump loops do not change. Stream carriers implement it over an `mpsc` plus `Notify`.
- Peer key stays `SocketAddr`: embedded carriers return the remote's real address; a sidecar returns the loopback source address of the flow; a client-side carrier returns a fixed virtual host address. `Peer`, `MuxEvent`, rate buckets and eviction stay as they are. The one structural change: `MuxHost` owns `Vec<Arc<dyn FrameIo>>` and each `Peer` gets `via: u8` so replies leave on the right carrier.
- Dispatch: `enum Io { Udp(UdpCarrier), Dyn(Arc<dyn FrameIo>) }` keeps the UDP hot path free of boxed futures (`async-trait` is already a dependency, L).
- Stream carriers: 2-byte length prefix, bounded queue with drop-oldest, never unbounded (unbounded queues turn TCP-in-TCP into seconds of bufferbloat). Optional frame padding to size buckets.
- Embedded vs sidecar is an implementation detail behind the trait:

```rust
pub struct LoopbackUdp {                    // used by sidecars AND by in-process wstunnel
    sock: UdpSocket,                        // 127.0.0.1:random
    remote: Option<SocketAddr>,             // client: the sidecar's local inbound
    virtual_host: SocketAddr,               // client: address shown to Tunnel as "the host"
    guard: Box<dyn Guard>,                  // Supervisor{child} | JoinHandle (in-process) | ()
}
```

### 2.3 What changes

| File | Change | Effort |
|---|---|---|
| new `src/carrier/{mod,udp,stream,loopback}.rs` | trait, caps, `UdpCarrier` (move `bind_marked`, `wire`/`norm`/`to_wire` here), length-prefixed stream carrier, `LoopbackUdp` | 2 d |
| `transport.rs` `Tunnel` | `socket: UdpSocket` becomes `io: Io`; three wrappers forward; gate `register_with_signal`, `close` deregister, STUN poke, punch ladder on `caps().punchable` | 1 d (32 sites, mechanical) |
| `transport.rs` `MuxHost` | `ios: Vec<Arc<dyn FrameIo>>`, `Peer.via`, `readable()` = select over ios; `raw_send`, `try_recv`, `register`, `poke_stun`, `T_PUNCH` go through `via` or `ios[0]` if punchable | 1.5 d |
| `transport.rs` / `reliable.rs` | `MAX_PAYLOAD` checks use `caps().tun_mtu()`; counted drops, no silent drop | 0.5 d |
| `tunmode.rs:722`, `StraitVpnService.kt` `setMtu` | MTU from carrier id (static table; both ends know the id; Android needs it before `establish()`) | 0.5 d |
| `invite.rs` | optional `cr` field (section 7.1) | 0.5 d |
| `app.rs` | build carriers from options, ladder driver (section 7.3); pump loops unchanged | 1 d |
| `preflight.rs` | `check-host` probes carriers, prints disclosures | 0.5 d |
| tests | in-memory `FrameIo` pair with loss/reorder/dup; existing e2e suite parametrized over carrier | 1.5 d |

Phase A total (trait, UDP carrier, stream carrier, loopback carrier, MTU, ladder; no third-party code): about 9 days. Behavior of the existing UDP path is unchanged and verifiable by the existing unit and e2e tests.

### 2.4 Hole punch and rendezvous stay untouched
`RvState`, `Runner`, `send_punch`, STUN, signaling talk to the UDP socket via `io.udp()`; they exist only for `punchable` carriers. They are gated, not edited. Rendezvous still outputs candidate `SocketAddr`s. UDP-based carriers (raw UDP, SS-UDP, AmneziaWG) ride the same punched 5-tuple. TCP/TLS/WebSocket/REALITY/XHTTP cannot be hole punched (TCP simultaneous open is theoretically possible but fails through most NATs; U), so they appear in the invite as extra *host endpoints* usable only when the host is reachable (VPS, forwarded port, UPnP TCP mapping). Preflight must say: "this carrier needs a reachable server".

### 2.5 Pluggable crypto/handshake (WireGuard, Noise): not worth it
- Handshake v2 (L) already gives per-join X25519, invite-keyed MACs, per-peer ChaCha20-Poly1305, counters and replay windows, slot and address assignment.
- WireGuard needs a static key pair per peer and an allowed-IPs table; the invite model is "the invite is the whole capability, no identity". A shared client key cannot distinguish peers (same key means one peer slot), and per-client registration needs an identity server, which the project forbids. The same reasoning limits AmneziaWG as a carrier (section 5).
- Noise could fix a real weakness (an invite holder can impersonate the host to another client, documented in `transport.rs` module docs) by giving the host a static key outside the invite. That is an invite-format change independent of carriers: schedule as "handshake v3" (new tags F8..), separately.

---

## 3. Carrier 1: shadowsocks-rust (embedded)

### 3.1 Facts
- Releases: shadowsocks-rust v1.25.0 (2026-08-26); breaking: MSRV 1.91 (needs smoltcp 0.13), outbound code reworked into `net::outbound`, `create_inbound_udp_socket` signature changed, inbound UDP fragmentation option, several security advisories fixed (V, GitHub release). Previous crate releases 1.24.0 (2025-12-11), 1.23.2 (2025-07-04) (V, crates.io). Active.
- crates.io `shadowsocks` 1.25.0, license MIT, 1.06 M downloads total (V). docs.rs lists `ProxySocket` (UDP), `ProxyClientStream`, `ProxyListener`, `ServerConfig`, `context`, `plugin` (SIP003), crypto via `shadowsocks_crypto` (V). Exact UDP send/recv method names and feature flags (`aead-cipher-2022`) were not visible; confirm at implementation (U). The docs.rs page and crates.io disagree on the 1.25.0 publish date (2026-10-19 vs 2026-08-26): trivia, but pin by hash.
- SS-2022 (SIP022, V): pre-shared random key (base64, 16 or 32 bytes; no passwords), ciphers `2022-blake3-aes-128-gcm` / `-aes-256-gcm` required, ChaCha20-Poly1305 variants optional; BLAKE3 subkeys. TCP: salt, request header with timestamp (30 s window), random padding 0 to 900 B, salts stored 60 s to reject replays, anti-probing guidance (no early close, no RST fingerprints). UDP: 16-byte separate header (session id 8 B + packet id u64) encrypted with AES under the PSK, body AEAD with a per-session subkey, 30 s timestamp, server routes by **session id, not source address**, and updates the return address after validation (roaming friendly), sliding-window duplicate filter. Multi-user identity headers are SIP023 (not read; U).

### 3.2 How our sealed datagrams ride it
- A Shadowsocks UDP packet is "payload + target address". We never need a real target: client and host both embed shadowsocks, so the "target" is a constant placeholder (127.0.0.1:7100) and the host does not forward anywhere; it takes the payload and hands it to `MuxHost` as `(frame, peer_addr)`. There is no `ssserver` process and no open-proxy risk (the host code simply ignores the target).
- Client carrier = `ProxySocket` client mode bound to the shared UDP socket if the API allows (needed to ride the punch; U), else its own socket.
- Host carrier = `ProxySocket` server mode: gets the real client address (distinct per client), so `Peer.addr` is naturally unique.
- Overhead: SS-2022 UDP adds about 16 (separate header) + about 30 (main header with IPv4 address) + 16 (tag) + optional padding, roughly 60 to 100 B. Together with our 35 B the wire frame can reach about 1500+ B for a 1400 B packet. Set the TUN MTU to about 1300 (U) for this carrier.
- TCP mode (for UDP-hostile networks): `ProxyClientStream` / `ProxyListener` carrying our length-prefixed frames. Stream semantics, so TCP-in-TCP caveats.
- Both layers encrypt (SS-2022 outer, Strait AEAD inner). Derive the SS PSK from the invite with HKDF (`"strait-cr-ss"`), never from the AEAD key directly.

### 3.3 Obfuscation and plugin status (evidence)
- GFW "fully encrypted traffic" detector live since November 2021: passively detects and blocks high-entropy flows with a few exemptions (e.g. first 6 bytes printable ASCII) (V, GFW Report / OTF summary). SS and our own raw AEAD datagrams are exactly this class, so SS buys no stealth against it. No source measuring SS-2022 specifically in 2025 to 2026 was found (V, absent evidence).
- Russia (anecdotal): in the November 2025 net4people thread SS-2022 was reported to work where VLESS+Vision failed, "but considered unreliable because it could be blocked as unknown encrypted traffic" (V, issue #546).
- Plugins: official v2ray-plugin is stale and "not currently affected because it has not been updated for a long time"; simple-obfs deprecated (V, Exclave wiki); ShadowTLS last release v0.2.25 on 2023-12-13 (V). The embedded crate has a SIP003 `plugin` module that launches an external plugin binary (V) which we should not rely on. Conclusion: do not promise camouflage; offer SS as a cheap, well-reviewed AEAD UDP/TCP carrier and a base layer under wstunnel or XHTTP if ever needed.

### 3.4 Plan
| Step | Files | Tests (no third-party binaries) | Effort |
|---|---|---|---|
| 1a `ss` carrier, UDP mode, client and host in one process | `src/carrier/ss.rs`, feature `carrier-ss`, Cargo dep `shadowsocks = "=1.25.0"` (default-features off, `aead-cipher-2022` on) | in-process client and host over loopback: full handshake v2 + 1000 packets; wrong PSK is rejected with `HandshakeRejected`; replay of a captured frame is dropped | 3 d |
| 1b TCP mode via `stream.rs` | same file | drop-oldest queue test; kill connection mid-flight gives explicit `Reset` | 2 d |
| 1c SS over punched socket | share the UDP socket if API allows | two loopback NATs are not available in unit tests: reuse the existing hole-punch fake if one exists in `tests/`, else lab test | 1 d |

---

## 4. Carrier 2: wstunnel

### 4.1 Facts
- wstunnel v11.1.0 (2026-10-19), Rust, BSD-3-Clause per README (the `wstunnel/Cargo.toml` has no license field; check the repo `LICENSE` file) (V). Recent notes: unauthenticated HTTP CONNECT now answers 407, reverse-tunnel fixes, BSD fixes; assets for Linux, macOS, Windows, FreeBSD, Android with a checksums file (V).
- Transports: WebSocket (default, "more performant"), HTTP/2, WebTransport (HTTP/3, UDP end to end). UDP forwarding: `-L 'udp://51820:localhost:51820?timeout_sec=0'` (default UDP idle timeout 30 s, `0` disables). Server restrictions: `--restrict-to HOST:PORT`, `--restrict-http-upgrade-path-prefix <secret>`, `--restrict-config`. Real certificates via `--tls-certificate`/`--tls-private-key`; client verification is **off by default** (`--tls-verify-certificate` must be turned on); `--tls-sni-override`, optional ECH (needs aws-lc-rs). No uTLS/browser fingerprint mimicry mentioned (V README). Own disclaimer: "Do not rely on wstunnel to protect your privacy." The FAQ suggests MTU about 1300 for WireGuard over it (V).
- Library: the repo is a workspace with `wstunnel` (library) and `wstunnel-cli`. `lib.rs` exposes `run_client`, `create_client(args, executor)` (for embedding), `run_server`, `ClientConfig`, `TlsClientConfig`, `LocalProtocol` (V). Caveats from the code: needs a Tokio runtime and an executor you supply; several setup failures **panic** (bad certificate/key, resolver config, malformed `restrict-to`), so wrap calls; `Stdio` listener calls `process::exit` (never use it embedded); TProxy is Linux-only (V).
- **`wstunnel` is not published on crates.io** (API returned 404, V). Embedding therefore means a pinned git dependency (`git = ..., tag = "v11.1.0"`), which needs network access at build time, or vendoring the tag. Dependencies: tokio-rustls 0.26, rcgen, hickory-resolver, hyper 1.x, fastwebsockets 0.10, web-transport-quinn; crypto backend `aws-lc-rs` by default or `ring` by feature; edition 2024 (V). The project already uses rustls with `ring` (L Cargo.toml), so build with `default-features = false, features = ["ring"]` (U: confirm it compiles and that Android/Windows cross builds do not need cmake).
- Alternative: our own `ws` carrier on `tokio-tungstenite` 0.30.0 (MIT, 2026-07-11, V), already a dev-dependency, plus `rustls` already used by rendezvous. About 400 lines, no wire compatibility with wstunnel, and no git dependency.

### 4.2 Evidence on effectiveness
- wstunnel presents ordinary TLS + WebSocket/HTTP-2 to a real domain. It has no REALITY-style "borrowed handshake", so against a censor that scores IP/AS and SNI (section 6.3) it is weaker than REALITY and falls under the same Russian IP-range and 15 to 20 KB per-connection findings.
- Android: README documents Termux only; iOS not mentioned (V). In-process embedding is the Android/iOS path.

### 4.3 How our frames ride it
Two modes, same carrier id `ws`:
1. **UDP forward mode (preferred first, least code):** run wstunnel with a local UDP listener `udp://127.0.0.1:Lp:127.0.0.1:7100?timeout_sec=0`; Strait talks to `127.0.0.1:Lp` through `LoopbackUdp`. On the host, `wstunnel server --restrict-to 127.0.0.1:7100`, `--restrict-http-upgrade-path-prefix <derived secret>`; each client's WS connection gets its own outbound UDP socket, so `MuxHost` sees a distinct loopback source port per client (U: verify in the lab; if two clients ever share a port, fall back to mode 2).
2. **Own stream carrier over WS:** the `ws` StreamCarrier frames datagrams itself (length prefix, optional padding) over a WebSocket binary stream; no wstunnel UDP semantics involved. One connection per client, so peer keys are unique by construction.
- The path prefix acts as a shared secret (V); derive it from the invite (`"strait-cr-ws-path"`). Do not rely on it for security (the e2e AEAD does that); it only reduces unauthenticated upgrades.
- Embedded vs sidecar: embedded via the git dependency (client only needs `create_client`; host side `run_server`) is the preferred route; the prebuilt binary or a `cargo build` of the tag is the sidecar route and doubles as the lab reference.
- MTU: TCP-based, so no IP fragmentation, but keep TUN MTU 1280 to 1300 to limit head-of-line cost (U).

### 4.4 Plan
| Step | Files | Tests | Effort |
|---|---|---|---|
| 2a own `ws` carrier on tokio-tungstenite + rustls, self-signed cert pinned by a hash derived from the invite for the zero-domain case, real cert when the host has a domain | `src/carrier/ws.rs`, feature `carrier-ws` | in-process server and client; handshake v2 over WS; kill server gives `Reset`; cert-hash mismatch gives `CertMismatch`; bounded-queue drop test | 4 d |
| 2b `LoopbackUdp` + in-process wstunnel (git dep) | `src/carrier/wstunnel.rs`, feature `carrier-wstunnel` | in-process wstunnel server and client on loopback, no external binary; panic wrapped into `Err` (inject a bad cert file) | 3 d |
| 2c Supervisor reuse for the prebuilt wstunnel binary (same profile, process instead of in-process) | `src/carrier/sidecar.rs` (shared with Xray, section 6.7) | fake-sidecar tests (section 8) | 1 d on top of 6.7 |

---

## 5. Carrier 3: AmneziaWG

### 5.1 Facts
- Protocol line (V, Amnezia docs, 2026): 1.5 (mimic QUIC/DNS, randomized handshake sizes, header changes); 2.0 (ranged headers H1-H4, random bytes added to special packets, I1-I5 "CPS" signature packets sent before the handshake); 3.x (3.0 changes the overall connection profile; 3.1 varies packet sizes, sequences, timing and cookie behavior, "written in response to blocking in Russia in June and July 2026"). Cryptographic core is plain WireGuard (Noise_IK, Curve25519, ChaCha20-Poly1305); with all masking parameters zero/off it is byte-compatible with WireGuard.
- Parameters (V): `Jc/Jmin/Jmax` (junk packets after the I chain), `S1-S4` (random prefix on Init/Response/Cookie/Data), `H1-H4` (non-overlapping ranges of message type ids), `I1-I5` (custom signature packets built from static, timestamp and random tags), `HeaderProtectionKey` (32 B, ChaCha20-based header protection, requires S1-S4 at least 12), `ContentPaddingAddition`, timer ranges, `RandomTrailers`, `DisableCookies`.
- Implementations: `amneziawg-go` (Go, MIT, fork of wireguard-go; latest tag v3.1.20260828, date taken from the tag name; 1,088 commits; runs as a userspace daemon with a TUN; library-style use only through the Windows module) (V). `awgtun` (Rust, BSD-3-Clause, boringtun fork implementing AmneziaWG 2.0, 3.0 and 3.1; `Tunn::new_with_amnezia`/`new_with_amnezia3`; the crate does no I/O, the caller drains `poll_outgoing_packet` and sends; **4 stars, 2 forks, no releases, not on crates.io, no version number**; README badge suggests Rust 1.97+, newer than this machine's 1.96.0 (U); self-reported interop with amneziawg-go, tools and kernel module) (V). Kernel module and tools are GPL-2.0 (V via awgtun README). Mullvad's GotaTun (Rust, boringtun fork) is at 0.10.2 (2026-10-20), MPL-2.0 for 0.10.x, no AmneziaWG (V). boringtun 0.7.1 (2026-05-01, BSD-3) is the upstream (V).
- Evidence on real-world value (thin): TechRadar-type coverage says Roskomnadzor blocked a large share of Amnezia's own servers in a June window and that 3.0 targets signature-based detection; vendor blogs call it effective but sell VPNs; one forum comment notes randomized headers raise the bar for rules but statistical analysis may still find it (V search summary, mixed quality). No independent measurement was found. Treat AmneziaWG as "defeats fixed-signature WireGuard filters", not "undetectable".

### 5.2 Two ways to use it, and why one is preferred
- **A. As a data plane (alternative to handshake v2):** rejected (section 2.5). Per-peer static keys vs invite-only capability; 1-to-many needs one WG peer per client and a registration channel.
- **B. As a UDP carrier for our sealed frames (recommended form):** the AWG tunnel is only a pipe. `FrameIo::send_to(frame)` wraps the sealed frame in a minimal IPv4+UDP header (28 B) addressed to a fixed inner address, calls `Tunn::encapsulate`, drains `poll_outgoing_packet`, and sends the result on the (punched) UDP socket. Receive is the reverse. Static WG keys are derived from the invite via HKDF (host key pair and a shared client key pair). Consequence: **one AWG peer slot per invite key**, so this carrier supports `max_clients = 1`, or one derived client key per pre-allocated slot (up to a small K) which the client picks by trial. Document the limit honestly; for 1-to-many hosts, use carriers 1, 2, 4.
- **C. Take the ideas, not the code (cheapest, covers most of the benefit):** a first-party `udp-obfs` carrier in Rust that imitates AWG's *shape* on our own frames: I-packet-style pre-handshake decoys, H-style randomized tag bytes, S-style random prefixes, content padding, junk packets, all keyed from the invite. No WireGuard semantics, no identity problem, works for N clients, rides the punch. About 4 days. This is my recommendation for the first AWG-flavored deliverable; B follows only if the user wants literal AmneziaWG interoperability.
- Overhead for B: WG data message 16 B header + 16 B tag + padding to 16 B, plus S4 prefix, plus 28 B inner IP/UDP, plus our 35 B. TUN MTU about 1280 to 1300 (U).

### 5.3 Plan
| Step | Files | Tests | Effort |
|---|---|---|---|
| 3a `udp-obfs` (AWG-style shape, in tree) | `src/carrier/udp_obfs.rs`, feature `carrier-obfs` | unit: reordering and junk tolerated; statistics test that first-byte and length distributions are flat; e2e over `UdpCarrier` fake | 4 d |
| 3b `awg` carrier on `awgtun` (git dependency, 1:1 only) | `src/carrier/awg.rs`, feature `carrier-awg` | loopback pair of `Tunn`; wrong derived key gives `HandshakeRejected`; interop check against `amneziawg-go` is a lab test needing that binary | 4 d, risk medium (young crate, MSRV) |
| 3c optional: `amneziawg-go` sidecar in userspace/netstack mode | uses supervisor | needs the Go binary | 3 d, not recommended |

---

## 6. Carrier 4: Xray-core / sing-box (supervised sidecar)

### 6.1 Versions and status (V unless noted)
| | Pin | Date | Notes |
|---|---|---|---|
| Xray-core | **v26.10.31** or newer | 2026-10-31 | Emergency security release: disables MPTCP by default (notes cite a Linux kernel IPv4 MPTCP listening remote-root risk; Go 1.24+ enables MPTCP by default; Android SOCKS/HTTP inbounds with LAN access also affected). Previous release v26.10.21 (2026-10-21): removes three weak intermediate root CAs, built with Go 1.27.3. Releases v26.10.10, v26.10.17 and v26.10.29 were **pulled**. Earlier tags v26.9.30, v26.9.9, v26.7.28, v26.7.11 are pre-releases. Never pin a pulled or pre-release tag; rebuild with the Go version named in the notes. |
| sing-box | v1.14.4 | 2026-10-24 | Builds for Android (SFA), iOS (SFI), Linux, macOS, Windows. Reported to lack XHTTP (one Habr article, U); REALITY and Vision supported (U). |
- Licences (U, check LICENSE at the tag): Xray MPL-2.0; sing-box GPL-3.0 with an additional naming restriction. Go build, static, no cgo.
- Xray naming changes to watch (V, docs): the inbound formerly called `dokodemo-door` is now `tunnel` with `allowedNetwork`, `rewriteAddress`, `rewritePort`; the VLESS outbound now uses flat `address/port/id/encryption/flow` fields; `encryption` must be set (`"none"` to disable VLESS Encryption). Xray now also lists Hysteria and MASQUE transports and a `finalmask` stage with `fragment`, `header-custom`, `noise`, `salamander`, `mkcp-legacy`, `xdns` (DNS tunnel over KCP), `xicmp`, `udphop`, `realm` masks (V docs, introduced versions not stated). Churn is high: pin and generate config from a typed profile, never hand-edit strings.

### 6.2 What each piece does for our case
- **VLESS + REALITY (TCP/443):** the server answers unauthenticated clients by relaying to a real target site, so active probes see that site. Needs no certificate of our own. Stream semantics.
- **XTLS-Vision:** padding that removes the TLS-in-TLS signature **of inner TLS that Xray can see**. Our payload is AEAD-sealed Strait frames, so Vision sees no inner TLS and has nothing to pad; it also intercepts UDP/443 (V docs; `xtls-rprx-vision-udp443` to keep it). Recommendation: **no Vision** for this carrier (the signature, if any, comes from our carrier's packet-size pattern, see 6.4). Corroborating field note: Vision-flow REALITY on port 443 was the failing configuration in the November 2025 Russian reports (V, anecdotal, section 6.3).
- **XHTTP (formerly SplitHTTP, from mid-2024):** HTTP-shaped transport with modes `packet-up` (sequenced POSTs plus one download stream; works through almost any server/CDN; default for h3), `stream-up` (single streaming POST disguised as gRPC; works through Cloudflare over h2 with gRPC enabled), `stream-one` (one bidirectional POST; default under REALITY); `auto` = stream-up for TLS h2, stream-one for REALITY, else packet-up. Random padding in Referer/response headers, SSE-style response headers, XMUX with randomized concurrency and connection lifetimes, no `http/1.1` ALPN signature, upload and download can be split over different paths/IPs (`downloadSettings`). Do not enable `mux.cool` with XHTTP (server accepts only plain XUDP now). Running h3 directly on the server is discouraged; QUIC/h3 is blocked in some regions (V, XHTTP: Beyond REALITY, discussion #4113). CDN fronting would make a third party terminate TLS and forward: excluded by default (section 10, D1).
- **VLESS Encryption (post-quantum):** `encryption = mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>.<padding blocks>.<server auth>`, generated with `xray vlessenc`; with it `security: none` is allowed and XTLS is unrestricted on any transport (V docs). `xorpub` masks the handshake public key; padding blocks randomize sizes and delays. Optional hardening layer, not a replacement for REALITY: the maintainer suggested wrapping 1-RTT VLESS Encryption **inside** REALITY with custom padding to change the traffic profile (V, issue #5332, speculative). Our payload is already AEAD-encrypted, so the value is traffic shaping only.

### 6.3 Field evidence, 2025 to 2026 (what works, what does not, how sure)
| Date | Region | Report | Source | Reliability |
|---|---|---|---|---|
| 2023-12 to 2025-04 | Iran | IPs carrying sustained REALITY traffic get blocked within hours to days (Irancell about day two at roughly 100 to 120 GB; heavy-traffic VPS blocked after about 2 h; low-traffic VPS survived a week); handshakes to blocked IPs on 443 never complete while port 80 works. In January 2025 one tester saw XHTTP split modes unblocked while single-stream REALITY was blocked in about four days; "self-steal" (a real site on the VPS with the same domain as SNI) and domestic-domain SNI behind a CDN each carried about 454 GB. | Xray-core discussion #3269 | Anecdotal, small samples, confounded variables; the thread says so itself |
| 2025-06 onward | Russia | Foreign data-center IPs (e.g. Hetzner, DigitalOcean) on affected mobile operators: a TLS connection freezes after roughly 15 to 20 KB (about 25 packets each direction) regardless of protocol, TLS 1.2/1.3, TCP and UDP; no RST; splitting across many connections works but is slow; later an SNI/Host whitelist and a CIDR whitelist. SSH/SFTP reportedly survive. Reports continue to October 2026. | net4people/bbs #490 | Self-reported by the original poster; thresholds approximate |
| 2025-11 | Russia | "TLS connection-based policing" on some home ISPs (MTS/MGTS, JustLan, LanInterCom, RTK): REALITY + Vision on 443 stops working once real data flows; port other than 443 works; removing Vision and enabling mux on 443 reported to work; XHTTP or h2/h3 with mux reported to work, later "does not help much for all users"; SS-2022 works but unreliable; trigger described as number of concurrent active TLS connections, not bytes (title changed from "PPS-based" to "connection-based"). | net4people/bbs #546 | Anecdotal; no root cause confirmed |
| 2025-11 to 2026-05 | Russia | REALITY TCP + Vision with `www.google.com` SNI and `chrome` fingerprint suddenly fails on some ISPs ("failed to read client hello" on the server); changing SNI, fingerprint, fragmentation, IP, even country does not help; a Russian-hosted Xray server over the same ISP works; Yandex/VK Cloud ranges work. Maintainers suspect HTTP/2-like characteristics of early packets are checked; suggested XHTTP (with Browser Dialer) and a coming "Seed" feature; no confirmed fix. | Xray-core #5332 | Anecdotal, closed without resolution |
| 2026-05 | Russia | One operator's account of three failure modes: (1) active probing of a stray non-REALITY inbound scored it "obviously VPN" and the IP was then dropped; (2) behavioral scoring of ClientHello by subnet/AS/SNI/fingerprint and a freeze of about 120 s (600 s if the fingerprint rotates) after three or more concurrent TLS connections to one host within about 20 to 50 ms; Firefox/Android/OkHttp/Edge fingerprints reportedly pass where Chrome/Safari from suspicious ranges are held; (3) the 15 to 20 KB cutoff. Mitigations offered: real nginx fallback and real certificate on any other port, multiplexed transport (gRPC, XHTTP), `mux.cool` off on h2. | avsisp.com blog | Single-vendor opinion plus links; thresholds from community threads |
| 2026-06 | general | Troubleshooting guide: if DPI drops silently after handshake try a port above 40000, a high-traffic SNI target, `firefox`/`qq` fingerprint, XHTTP; config errors that silently break REALITY (`dest` with `https://` prefix, empty `serverNames`, client core without `mlkem768x25519plus`). | semenov.work | Blog; consistent with others but no measurements |
| 2024 (academic) | ISP measurement | Encapsulated TLS handshakes (TLS-in-TLS) in obfuscated proxies are fingerprintable with true-positive rates above 70% under standard configurations; random padding helps only slightly; stream multiplexing is the most promising countermeasure but not sufficient alone; layering shadowsocks inside websocket inside TLS helps little. | Xue, Kallitsis, Houmansadr, Ensafi, USENIX Security 2024 | Peer-reviewed; measured on a mid-size ISP |
| 2021 to ongoing | China | Fully-encrypted-traffic detector (passive, entropy-based, blocks dynamically); October 2022 simultaneous blocking of TLS-based servers (Trojan, Xray, V2Ray TLS+WS, VLESS, gRPC) reported by 100+ users. | GFW Report / OTF summary | Research reports; older |

What this adds up to (my reading, U where marked):
1. There is **no config that is reported to work everywhere**. Russia, Iran and China each defeat different things; the best-supported commonalities are: use a **fresh, low-traffic IP**, a **real site on the same IP (self-steal)** or a domestic SNI, **multiplexed XHTTP rather than raw Vision**, **short-lived connections**, and offer **more than one port**.
2. The per-connection 15 to 20 KB cutoff on foreign data-center IPs (Russian mobile) defeats any single long-lived TCP/TLS flow; the only mitigations reported are an IP the censor does not treat as foreign data center (domestic or whitelisted ASN/SNI) or many short connections (XHTTP `packet-up` and XMUX connection rotation are the closest built-in fit; effectiveness against this specific rule is not reported, U).
3. Sing-box lacks XHTTP (U), which is the transport with the most positive anecdotes. Primary sidecar = Xray; sing-box is optional and for REALITY-only profiles.

### 6.4 Strait-side hardening that the sidecar cannot provide
Our stream carriers and the Xray sidecar both expose the *sizes and timing of the inner user traffic*. Mitigations we control:
- Frame-size bucketing (pad every sealed frame up to the next of a few sizes) and optional small random padding; paid for in bandwidth (configurable, off by default).
- Coalescing several small packets into one stream write; delay budget under 5 ms.
- Per-client keepalive jitter so the 15 s keepalive does not appear as a fixed beat.
These are carrier-level options in `stream.rs`, usable by wstunnel/ws and Xray stream mode. Padding alone is not a proven defence (V, Xue et al.).

### 6.5 Recommended config template (validate before use; names follow current docs, V where marked)
Host (VPS). Strait host listens only on loopback `127.0.0.1:7100/udp`. `<...>` values are derived from the invite key by HKDF in the profile generator, never typed by hand.

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "tag": "in-reality",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "<uuid-from-invite>", "flow": "" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "xhttpSettings": { "path": "/<derived-path>", "mode": "auto" },
      "realitySettings": {
        "target": "127.0.0.1:8443",
        "serverNames": ["<own-domain>"],
        "privateKey": "<x25519-private-from-invite>",
        "shortIds": ["<8-byte-hex-from-invite>"]
      }
    }
  }],
  "outbounds": [
    { "tag": "to-strait", "protocol": "freedom", "settings": { "redirect": "127.0.0.1:7100",
        "finalRules": [ { "action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": "7100" },
                        { "action": "block" } ] } }
  ],
  "routing": { "rules": [
    { "inboundTag": ["in-reality"], "outboundTag": "to-strait" }
  ] }
}
```
Notes: all field names were verified against the v26.10.31 source and the real binary (docs/research/e2e-xray-real.md); `target` is the current REALITY field (`dest` is an alias). `freedom.redirect` rewrites address and port of every UDP packet, so an invite holder cannot use the VPS as an open proxy. **`finalRules` is mandatory** (found in the real run): Xray 26.x freedom blackholes loopback/private destinations for vless inbounds by default, and that also swallows our own `127.0.0.1` redirect, so without an explicit allow nothing flows. The first matching user rule wins, so `allow udp 127.0.0.1:<port>` then `block` (catch-all) gives a second, independent pin. Self-steal means a real nginx on `127.0.0.1:8443` serving the real site and a Let's Encrypt certificate for `<own-domain>`; a stranger who hits the server sees that site. No other Xray port may listen publicly (the stray-port finding, V avsisp). Strait's `MuxHost` listens on loopback only.

Client (sidecar next to the Strait guest):

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "tag": "in-strait", "listen": "127.0.0.1", "port": "<Lp>",
    "protocol": "tunnel",
    "settings": { "allowedNetwork": "udp", "rewriteAddress": "127.0.0.1", "rewritePort": 7100 }
  }],
  "outbounds": [{
    "tag": "out", "protocol": "vless",
    "settings": { "address": "<host-ip>", "port": 443, "id": "<uuid-from-invite>", "encryption": "none", "flow": "" },
    "streamSettings": {
      "network": "xhttp", "security": "reality",
      "xhttpSettings": { "path": "/<derived-path>", "mode": "auto" },
      "realitySettings": { "serverName": "<own-domain>", "fingerprint": "firefox",
                           "publicKey": "<x25519-public>", "shortId": "<8-byte-hex>" }
    }
  }]
}
```
`mode: auto` selects `stream-one` under REALITY (V). Make `mode` a profile switch (`stream-one` default; `packet-up` fallback when stream-one is throttled; `stream-up` + `downloadSettings` only if the user accepts the complexity). `fingerprint` is a profile switch too (`firefox`, `chrome`, `qq`, `android`...): the evidence conflicts (6.3), so ship a short ordered list the ladder can walk. Optional hardening profile B: `encryption` = a generated `mlkem768x25519plus.xorpub.0rtt...` string on both ends (needs the same Xray build).

What to avoid:
- `flow: xtls-rprx-vision` with this carrier (nothing to pad; the failing config in the Russian reports; intercepts UDP/443).
- `mux.cool` together with XHTTP (V); relying on one long TCP flow in Russia (section 6.3).
- Small, single-purpose SNI targets or a target whose IP is unrelated to your IP: both are reported as easy to spot (Iran thread, hypothesis). Do not pick the same famous site for every host. Prefer self-steal; otherwise a popular domestic-looking target near the server's ASN (U).
- Any extra public listener on the VPS (SSH on 22, stray Xray ports, admin panels) and a self-signed or short-lived certificate on the fallback site (V avsisp: one reported cause of being scored as a VPN).
- CDN-fronted XHTTP (a third party forwards; REALITY also cannot run behind a CDN, V).
- `dest` with an `https://` prefix, empty `serverNames` (V semenov: silent breakage).
- An unpinned or pulled release; mixing client and server builds that disagree on VLESS Encryption.
- Hand-typed secrets: derive everything from the invite so one invite equals one capability.

### 6.6 Wiring into Strait (UDP/XUDP mode, with the open question)
```
guest Strait --UDP--> 127.0.0.1:Lp [xray tunnel inbound] ==VLESS/XHTTP/REALITY(tcp 443)==> [xray inbound on VPS] --freedom redirect, UDP--> 127.0.0.1:7100 host Strait
```
- XUDP carries the datagrams over the stream; the server's `freedom` outbound opens a UDP socket to `127.0.0.1:7100`. **Open question for the lab:** does each connected client appear to `MuxHost` as a distinct loopback source address? If two clients share one source port, `Peer.addr` collides (the AEAD would still reject mismatched frames, but the host could not tell the peers apart before the handshake and replies could go to the wrong flow). Plausible but unverified (U).
- Fallback that removes the question: **TCP stream mode**: `tunnel` inbound `allowedNetwork: tcp`, `freedom` redirect to a Strait `StreamListener` on `127.0.0.1:7101`; one TCP connection per client, a unique loopback source port by construction; length-prefixed frames from `stream.rs`; padding options from 6.4 apply. Cost: TCP-in-TCP on both the loopback hop (negligible) and the outer hop (the real cost).
- MTU: for XHTTP stream modes the outer path is TCP, so MTU is not constrained by fragmentation; use 1280 to 1300 (U).
- Routing loop: the sidecar's outbound socket must bypass Strait's TUN default route. Xray has socket mark / bind-interface options (U, check names); on Android the existing approach (leave the server /8 off VPN routes) works since the sidecar shares the UID; `addDisallowedApplication` for the whole app is the stronger alternative (U).

### 6.7 Supervisor and platform notes
- Layout: typed profile to generated config (0600, app-private directory); sidecar listens on `127.0.0.1:<random>` (unix socket if supported); health = process alive plus an end-to-end sealed keepalive RTT through the carrier; restart with exponential backoff, max 3, then explicit `SidecarExited(code)`; kill on parent death (Linux `PR_SET_PDEATHSIG`, Windows Job Object, macOS watchdog; U); logs captured and redacted; version and SHA-256 pinned in the build; never auto-download. Loopback ports are reachable by any local app: random port plus invite-keyed AEAD admission makes this a nuisance risk only (U).
- Android: executing binaries from app data is blocked for apps targeting API 29+ (W^X; V Android behavior-changes page and write-ups). Ship as `lib<name>.so` in `jniLibs/<abi>/` with `extractNativeLibs`/legacy packaging, as `libstrait.so` already does (L). Newer Android / Play policy limits were not checked (U). Alternative: gomobile AAR loaded in-process (sing-box `libbox` pattern).
- iOS: no exec; packet tunnel memory is capped (reported 50 MiB, conflicting 15 MiB reports; unofficial, V forum threads); Go proxy cores are a poor fit. iOS gets embedded Rust carriers only (carriers 1, 2, 3).
- Desktop: plain child; sign bundled binaries; antivirus flags on proxy cores are common (U).
- Size (U, measure): Xray arm64 about 20 to 30 MB, sing-box larger.

### 6.8 Plan
| Step | Files | Tests without third-party binaries | Effort |
|---|---|---|---|
| 4a Supervisor, `LoopbackUdp`, profile types, key derivation (UUID, x25519, shortId, path), config generators with golden-file tests | `src/carrier/sidecar.rs`, `src/carrier/xray/{profile,gen}.rs`, feature `carrier-xray` | golden JSON for host and client; derivation vectors; supervisor against a **fake sidecar** = the test binary re-executed with an env var (`current_exe()`), simulating UDP forward, crash, hang, bad exit codes, slow start; backoff and give-up tests | 5 d |
| 4b Host side: loopback listener, `via` routing, multi-client collision test | `transport.rs` (from phase A), `carrier/loopback.rs` | in-process UDP "sidecar" forwarder task giving per-client source ports, and one giving a shared source port (must be detected and reported as `PeerCollision`) | 2 d |
| 4c TCP stream mode and padding/bucketing | `carrier/stream.rs` | padding distribution tests; drop-oldest | 3 d |
| 4d Lab with real Xray (needs artifacts in section 8) | `scripts/lab-xray.sh`, docs | iperf3 through TUN, tc netem, capture to compare the outer signature, kill tests | 3 d |
| 4e Android packaging of the sidecar | gradle `jniLibs`, `StraitVpnService.kt` | emulator run | 3 d |
| 4f ladder integration and disclosures | `app.rs`, `gui.rs`, mobile UI | existing e2e plus ladder tests with fake carriers | 2 d |

---

## 7. Invite, ladder, UX (apply to all four)

### 7.1 Invite
Same forward-compatibility rules as `rv` in `RENDEZVOUS_DESIGN.md` section 4. New optional field:
```
STRAIT2|<key>|<hosts>|<signals>|<rv>|<cr>
cr = id[@host:port][;k=v]... comma separated, host's preference order
e.g. cr=ss@203.0.113.10:8388,ws@host.example:443;p=/x,xray@host.example:443;m=so;fp=firefox
```
Secrets (SS PSK, WS path, VLESS UUID, REALITY keys, short id) are HKDF-derived from the invite key with per-carrier labels, so the invite stays short and "invite = whole capability" still holds. Public parameters that cannot be derived (host, port, SNI or domain, fingerprint, XHTTP mode) travel in `cr`. Consequence: any invite holder can also derive the carrier's server-side keys, so carriers do not authenticate the host against another invite holder; this is the same documented limit as in handshake v2.

### 7.2 Disclosures (same `Disclosure` struct as rendezvous; nothing preselected)
Per carrier: what the network observer sees; which third parties are involved (none); what is required (reachable server, domain, certificate); honest caveat. Examples: SS-UDP "looks like random UDP; some networks block that"; ws "looks like HTTPS/WebSocket to your domain"; xray-reality "looks like a visit to <domain> over HTTPS; blocked IPs and some mobile networks in Russia/Iran still defeat it"; awg-style "WireGuard-like UDP with random headers".

### 7.3 Client ladder with explicit reasons
Order from the invite, staggered 300 ms (Happy-Eyeballs style); the first carrier whose **sealed ACCEPT** arrives wins; the rest are cancelled. Default order for a typical host: UDP direct/punch, UDP-obfs/AWG, SS-UDP, then TCP 443 carriers (xray-reality, ws). Reason set per carrier: `NotInInvite`, `DisabledLocally`, `NeedsReachableHost`, `SidecarMissing`, `SidecarExited(code)`, `Timeout`, `ConnectionRefused`, `Reset` (typical DPI sign), `TlsFailed`/`CertMismatch`, `HandshakeRejected` (wrong invite or non-Strait peer), `PeerCollision`, `MtuTooSmall`, `ThrottledSuspected` (throughput collapse after N KB, to name the 15 to 20 KB pattern). Remember the last working carrier locally. Never fall back to a relay.

---

## 8. Artifacts a real test needs (nothing was downloaded; ask the user first)

Preferred acquisition: **source from crates.io or a pinned git tag, built in an isolated directory, reviewed, no prebuilt binaries run.** Prebuilt release binaries only if the user prefers, verified against the published checksum, executed only in the lab sandbox.

| # | Artifact | Source | Version | Licence | Build and size | Checksum / integrity | Used for |
|---|---|---|---|---|---|---|---|
| 1 | `shadowsocks` crate | crates.io | `=1.25.0` (2026-08-26) | MIT (V) | `cargo fetch` then `cargo build` (pure Rust; MSRV 1.91, local rustc 1.96.0 ok); pulls `shadowsocks-crypto` 0.8.0 (V) and many transitive crates; size delta unknown, measure | crates.io SHA-256 in `Cargo.lock`; review with `cargo tree` and `cargo deny` | carrier 1, no external process |
| 1b | `shadowsocks-rust` CLI (optional interop) | `cargo install shadowsocks-rust --version 1.25.0 --locked` | 1.25.0 | MIT | builds from crates.io | lockfile | interop with a stock `ssserver` |
| 2 | `wstunnel` library | `https://github.com/erebe/wstunnel` tag `v11.1.0` (not on crates.io, V) | v11.1.0 (2026-10-19) | BSD-3-Clause (README); Cargo.toml has no field, check `LICENSE` | git dependency or vendored; features `ring` instead of default `aws-lc-rs` (U); size unknown | commit hash of the tag | carrier 2b |
| 2b | `wstunnel` binary (lab reference) | same tag, `cargo build --release --package wstunnel-cli`, or release asset | v11.1.0 | BSD-3-Clause | est. 5 to 8 MB (U) | release checksums file (V) | lab comparison |
| 2c | `tokio-tungstenite` | crates.io | 0.30.0 (2026-07-11), MIT (V) | MIT | already a dev-dependency | lockfile | own `ws` carrier |
| 3 | `awgtun` | `https://github.com/AYastrebov/awgtun` (no releases, not on crates.io) | pin a commit hash after review | BSD-3-Clause (V) | `cargo build`; README badge suggests Rust 1.97+, local rustc is 1.96.0 (U: may need a toolchain update) | commit hash | carrier 3b |
| 3b | `amneziawg-go` (optional) | `https://github.com/amnezia-vpn/amneziawg-go` | tag v3.1.20260828 (date from tag) | MIT (V) | `make` with latest Go (local Go 1.25.6, U may be too old) | commit hash | interop checks only |
| 4 | `Xray-core` | `https://github.com/XTLS/Xray-core` | tag **v26.10.31** (2026-10-31); verify not pulled | MPL-2.0 (U) | `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="` with the Go version named in the release notes (the notes say Go 1.27.3 for v26.10.21; local Go 1.25.6, so a toolchain download is probably required: needs permission); size est. 20 to 30 MB per arch (U) | release assets include digest files (U); otherwise pin commit and `go.sum` | carrier 4 lab and later bundling |
| 4b | `sing-box` (optional) | `https://github.com/SagerNet/sing-box` | v1.14.4 (2026-10-24) | GPL-3.0 with extra clause (U) | `go build -tags ...` (U) | commit hash | REALITY-only alternative |
| 4c | `XTLS/REALITY` library | transitive via Xray | n/a | MPL-2.0 (U) | n/a | n/a | n/a |
| 5 | Lab host | the VPS from `.env` (secrets stay in `.env`), a domain with a real certificate, optional nginx for self-steal | n/a | n/a | n/a | n/a | section 6.8 step 4d |
| 6 | Tools | `iperf3`, `tc`/`netem`, `tcpdump` | system packages | various | n/a | distro signatures | measurements |

All Xray/wstunnel/ss tests in sections 3 to 6 marked "without third-party binaries" run with fakes and need only the crates in rows 1 and 2c (plus the git dependency in row 2 for 2b and awgtun for 3b, which are the only items beyond crates.io).

---

## 9. Later (after the four are implemented)
- **dnstt:** CC0, Go, Noise_NK_25519_ChaChaPoly_BLAKE2s over KCP + smux over DoH/DoT/UDP DNS, forwards one local TCP port to one remote TCP port (no TUN), default payload MTU 1232; needs a domain with an NS record delegated to a server on UDP/53 (V, README on a mirror; upstream bamsoftware.com returned 403 and no tagged release was readable). Bandwidth: only self-reported comparison numbers exist (V secondary): a 10 MiB upload took about 16 s, roughly 5 Mbit/s on a clean testbed; real resolvers will be worse (U). Fits our stream carrier plus supervisor in about 3 days after phase 4a. Decision D1 (third-party resolvers forward the data) applies.
- **slipstream:** the Rust port was archived on 2026-08-28; its maintainer now argues QUIC-over-DNS is the wrong architecture and points to MasterDnsVPN (not evaluated) (V). Do not depend on it.
- **iodine:** not researched (old, plain UDP DNS only; U).
- Xray's own `finalmask` includes an `xdns` mask (DNS tunnel over mKCP, needs NS delegation and port 53; V docs). If Xray is already bundled, that may replace a separate dnstt sidecar; evaluate then.

---

## 10. Decisions for the user
- **D1: third parties that forward data.** DNS tunnelling traverses recursive resolvers; CDN-fronted XHTTP/WS goes through a CDN that terminates TLS. Both strain "no third-party relay". Proposal: exclude CDN fronting; allow DNS only later, off by default, with the disclosure "your DNS provider carries the encrypted data".
- **D2: bundling Go binaries** (supply chain, size, licences). Proposal: Xray as an optional "carrier pack", built from a pinned tag in our CI, off by default.
- **D3: the AmneziaWG form:** 3a (in-tree AWG-style shape, N clients) first, 3b (literal AmneziaWG, 1 client) only if interoperability is wanted.
- **D4: Russia/Iran expectations.** The evidence says no carrier is reliable there; the product text must not promise it.

---

## 11. Risks
| Risk | Mitigation |
|---|---|
| Supply chain of Go binaries and git dependencies | build from pinned tags in CI, publish SHA-256, verify at launch, no auto-update, sidecars hold no Strait key and see only AEAD ciphertext |
| Binary size | feature-gate each carrier; measure; optional download pack for Go sidecars |
| Protocol churn (REALITY, XHTTP, VLESS Encryption, FinalMask, field renames, pulled releases) | profile generator is the only code that knows Xray's schema; golden tests per pinned version; two-release upgrade policy |
| TCP-in-TCP meltdown and bufferbloat | bounded drop-oldest queues, small MTU, padding optional, prefer UDP carriers |
| Routing loop / leak of the sidecar socket | per-platform exemption plus a test "sidecar socket never appears on the TUN device" |
| Kill switch interplay | allow-list each carrier endpoint (`tunmode.rs` firewall rules currently know the UDP endpoint only, L) |
| MTU mistakes | static per-carrier table, lab MTU probe, counted drops |
| Detection arms race | carriers selectable by id; never claim undetectability |
| Legal | circumvention tools are restricted in some jurisdictions and stores may reject them; neutral wording; consult counsel for target markets (U) |
| Panic in embedded wstunnel | wrap calls in `catch_unwind` or run in a dedicated task and map to `CarrierError` (V, library panics on bad TLS config) |
| Young crates (awgtun) | pin commit, 1:1 only, review |

---

## Appendix A: other candidates already looked at (not selected)
| Candidate | Version (date) | Note |
|---|---|---|
| Hysteria 2 | app/v2.13.0 (2026-10-05), Go, quic-go 0.63.0, Chrome-154 QUIC fingerprint parroting | UDP as QUIC datagrams, HTTP/3 auth with web-server masquerade, Salamander/Gecko obfuscation; needs UDP; best fit for a datagram model (V protocol doc) |
| QUIC datagram carrier on quinn | quinn 0.11.12 (2026-09-14), MIT/Apache | `send_datagram` may drop oldest queued; `max_datagram_size()` only guaranteed slightly above 1 KB (V). MASQUE (RFC 9298/9484): thin Rust support (`ant-quic` module, `masquerade-proxy` prototype, no CONNECT-IP crate found). Not selected |
| OpenVPN | 2.7.9 (2026-11-05) | Whole VPN with its own TUN and routing (single `VpnService` on Android); heavily fingerprinted; OpenVPN 3 core AGPL (U). Not a carrier |
| boringtun / WireGuard | 0.7.1 (2026-05-01) | Crypto-layer alternative, rejected (section 2.5) |
| TUIC / ShadowTLS | 2023-06 / 2023-12 last releases | unmaintained |
| NaiveProxy / Mieru / Cloak | v154.0.8037.49-5 (2026-10-22) / v3.39.0 (2026-10-23) / v2.12.0 (2025-07-23) | TCP-centric Go/C++ sidecars; skipped |
| phantun | 0.8.1 (2025-08-23), Apache/MIT | fake TCP over UDP; needs TUN/raw sockets, not mobile friendly |
| SSH (russh) | 0.65.1 (2026-11-03), Apache-2.0 | stream; low priority |
| iroh | 1.4.1 (2026-10-21) | QUIC by public key but includes relay servers: excluded by invariant |
| Snowflake, meek | | excluded: volunteers / CDNs forward the data |
| Nebula, ZeroTier, IPsec NAT-T, kcptun, udp2raw, obfs4, Juicity | not researched in depth | placeholders |

## Appendix B: sources (read 2026-11-06; untrusted data)
- Xray-core releases: https://github.com/XTLS/Xray-core/releases , API https://api.github.com/repos/XTLS/Xray-core/releases/latest (v26.10.31)
- sing-box: https://api.github.com/repos/SagerNet/sing-box/releases/latest (v1.14.4)
- Xray docs: https://xtls.github.io/en/config/outbounds/vless.html , https://xtls.github.io/en/config/inbounds/tunnel.html , https://xtls.github.io/en/config/transports/finalmask.html
- XHTTP: Beyond REALITY: https://github.com/XTLS/Xray-core/discussions/4113
- Iran REALITY blocking: https://github.com/XTLS/Xray-core/discussions/3269
- Russia: https://github.com/net4people/bbs/issues/546 , https://github.com/net4people/bbs/issues/490 , https://github.com/XTLS/Xray-core/issues/5332 , https://www.avsisp.com/blog/our-takes/three-ways-russia-breaks-xray/ , https://semenov.work/posts/vless-reality-troubleshooting/
- TLS-in-TLS: https://www.usenix.org/conference/usenixsecurity24/presentation/xue (Xue, Kallitsis, Houmansadr, Ensafi)
- GFW fully-encrypted-traffic blocking: https://www.opentech.fund/news/exposing-the-great-firewalls-dynamic-blocking-of-fully-encrypted-traffic/
- Shadowsocks: https://shadowsocks.org/doc/sip022.html , https://crates.io/api/v1/crates/shadowsocks , https://docs.rs/shadowsocks/latest/shadowsocks/ , https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest , https://github.com/ExclaveNetwork/Exclave/wiki/Configuration , https://api.github.com/repos/ihciah/shadow-tls/releases/latest
- wstunnel: https://github.com/erebe/wstunnel , https://raw.githubusercontent.com/erebe/wstunnel/main/wstunnel/src/lib.rs , https://raw.githubusercontent.com/erebe/wstunnel/main/wstunnel/Cargo.toml , https://api.github.com/repos/erebe/wstunnel/releases/latest , https://crates.io/api/v1/crates/tokio-tungstenite
- AmneziaWG: https://docs.amnezia.org/documentation/amnezia-wg , https://github.com/amnezia-vpn/amneziawg-go , https://api.github.com/repos/amnezia-vpn/amneziawg-go/tags , https://github.com/AYastrebov/awgtun , https://crates.io/api/v1/crates/gotatun , https://crates.io/api/v1/crates/boringtun , https://www.techradar.com/vpn/vpn-privacy-security/amnezia-vpn-improves-anti-censorship-protocol-as-russia-escalates-anti-vpn-regime
- DNS: https://github.com/Mygod/dnstt , https://github.com/Mygod/slipstream-rust/discussions/111
- Hysteria 2: https://v2.hysteria.network/docs/developers/Protocol/ ; quinn: https://docs.rs/quinn/latest/quinn/struct.Connection.html
- Android W^X: https://developer.android.com/about/versions/10/behavior-changes-10 ; iOS NE memory: https://developer.apple.com/forums/thread/106377
- OpenVPN: https://api.github.com/repos/OpenVPN/openvpn/releases/latest
- This repository: `src/transport.rs`, `src/tunnel/crypto.rs`, `src/tunnel/reliable.rs`, `src/tunmode.rs`, `src/app.rs`, `docs/RENDEZVOUS_DESIGN.md`, `STRAIT_HANDOFF.md`, `strait-mobile/android/.../StraitVpnService.kt`

## awg carrier as built (`src/carrier/awg.rs`, feature `cr-awg`)

Option 3a of section 5: our own envelope in the shape of AmneziaWG's ideas, no third-party code, N clients, rides the UDP punch. NOT wire-compatible with AmneziaWG, and a design for resisting fixed-signature fingerprinting, not a verified bypass (no real DPI testing).

- Datagram = `nonce(12) || ChaCha20-mask(type(4) | padlen(2) | tag(4) | sealed frame | zero pad)`. The keystream comes from a per-invite key and the per-packet random nonce, so no byte of the datagram is constant, including the type word and the pad length.
- All parameters come from `HKDF-SHA256(invite key, info "strait-awg-v1")`: mask key, tag key, type-word ranges (2^16 wide, one for data, one for small/control frames), padding range (min 0..8, width 16..64), small-frame bucket (16/24/32 B) plus 0..16 extra, junk burst (3..7 datagrams of 24..~660 B). Every invite therefore has a different fingerprint, and both sides agree without negotiation.
- Client sends the junk burst once before its first real frame to each peer; the host never sends junk and never answers anything that fails the check.
- `tag` is a keyed 32-bit check over the whole plaintext: garbage, truncation, tampering and wrong-key datagrams are dropped silently (no reply, no log). The sealed frame inside stays authenticated end to end; this layer adds obfuscation only.
- `Caps.overhead` = 22 + max(pad_max, bucket-1+extra) (worst case, at most ~94 B); `max_frame` = inner max minus that.
- Key input: `CarrierSpec.params` entry `key` (hex or raw text). `udp()` is delegated to the inner socket so punch/STUN keep working; those raw packets are dropped by the envelope check on receive.
- Disclosure: shared = a network observer sees UDP datagrams to your host with no fixed header, varying sizes and a junk burst at connection start; not shared = payload, keys; not a guarantee: hides the Strait wire format, not that you send UDP to an IP; operator = none, peer to peer.

---

## Phase A1 as built (src/carrier/, tests/carrier_core.rs)

Self-contained carrier layer; `transport.rs` does not use it yet.
- `mod.rs`: `CarrierId` (`udp ss ws awg xray dns`), `Caps { id, max_frame, punchable, reliable_stream, overhead }` (`tun_mtu()`), `CarrierError` (`Unsupported, Blocked, Failed, FrameTooLarge{max}, Eof, Reset, Closed, UnknownPeer`; wrapped in `io::Error`, recover with `CarrierError::from_io`), `FrameIo` (poll style, peer key `SocketAddr`), `CarrierFactory`, `registry()/by_ids()/built_ids()`, seeded `Rng`.
- `udp.rs` `UdpCarrier` (dual-stack, v4-mapped addressing identical to `Tunnel::wire/norm`; `from_socket` takes the transport's `bind_marked` socket). Differences from the sketch: `Caps` has no `needs_reachable_host` (derive from `punchable`), `reliable_stream` replaces `ordered_reliable`, ids are an enum, `max_frame` of UDP is 1472.
- `stream.rs`: record format, buckets, random padding, coalescing window, jitter hook, drop-oldest outbound queue, back-pressured inbound queue, typed EOF/RST, `serve_tcp` (one peer per connection). `FrameDecoder` never reserves memory from a length prefix.
- `loopback.rs`: `LoopbackUdp` client/host, `Demux::{None, Header}`. The doc proposed detecting a shared source port (`PeerCollision`); built in addition: a 4-byte client-id header with synthetic peer keys in 240.0.0.0/8, which removes the collision.
- `supervisor.rs`, `mem.rs`, `ladder.rs`: as described in their module docs. The supervisor does not yet set kill-on-parent-death.

## Xray real-binary validation (2026-11-06)
Done against Xray v26.10.31 (darwin client, linux/amd64 host on a VPS across the internet): see `docs/research/e2e-xray-real.md`. Consequences already in code: host `finalRules` (required, audited by `violations()`), all `N` names verified, REALITY rejection on the client surfaces as `Health::Down` (parsed from the sidecar log). Open for integration: Android, sidecar socket bypass of the TUN, log redaction in the sidecar's own log file.

## Post-P5 fixes (xray target, awg and rendezvous, probes)

- **xray REALITY target**: `--carrier 'xray@0.0.0.0:443;sni=www.cloudflare.com;target=www.cloudflare.com:443'` (also `NAT_TUNNEL_XRAY_TARGET`, or `xray_target` in `CarrierCfg.extra`). `target` is host side; it travels in the invite so `--carriers-from-invite` reuses it, clients ignore it. `sni` and `target` are validated strictly (bare hostname / `host:port`, no scheme); the CLI rejects a bad value, an invite drops it. At start the host needs the target to answer on TCP: the explicit one, else `127.0.0.1:8443` (self-steal), else `<sni>:443`; otherwise it refuses to start with that message.
- **xray binary trust** (audit Group 1, item 8): the binary is read once, checked against `xray_sha256` if set, copied to a private 0500 file in the 0700 run dir, and only that copy is executed (version, `-test`, run, every supervisor restart). As root (unix), an unpinned binary is accepted only if it and every parent directory are root-owned and not group/world-writable; otherwise the carrier refuses (`Blocked`) and says to set the pin or install root-owned. If the run dir is noexec: pinned or root = error naming `NAT_TUNNEL_XRAY_RUNDIR` / `STRAIT_XRAY_RUNDIR` / `xray_run_dir`; otherwise a warning and the original path is run unprotected. Not covered: Windows (no ownership check), macOS code signing of the copy, a hostile run dir location.
- **Ladder reasons**: a timeout becomes `timed out (<why>)` when the carrier's own health knows (xray: `REALITY authentication failed ...`). Plain UDP and ss/awg still cannot tell a wrong key from a drop.
- **awg/ss and rendezvous** (fixed afterwards, see `docs/research/e2e-rendezvous-carriers.md`): an ss / awg entry **without `@host:port`** rides the host's plain UDP socket, the one whose STUN mapping every rendezvous method publishes (trackers announce a single port, so one socket is the only thing all methods can carry). The host serves it on a port carved out of that socket (`MuxConfig::shared`, `carrier/shared.rs`; `--carrier ss` / `--carrier awg` without an address); datagrams the plain protocol does not authenticate are offered to the ss / awg decoders, which keep what authenticates. The guest uses the carrier's own socket: awg as before, ss unconnected (`SsFactory::dial` without endpoint) with STUN read through a tap on that socket. An entry **with** `@host:port` is unchanged (own socket, direct). Not covered: `sig` (the legacy relay registers the plain socket only), IPv6 candidates for ss, a host that predates this change (the guest times out with the usual rendezvous failure text).
- **Probes**: `carrier-test` / `check-host --carriers` print `unverifiable: ...` where a keyless probe cannot know (UDP carriers, ws certificate pin); `check-host --carriers` runs local start checks and prints even when the host check fails.
- **Userspace exit**: per-flow smoltcp buffers are 256 KiB each way (`userspace::TCP_BUF`), about 31 Mbit/s per flow at 66 ms instead of 7.5.
- **Host slot after a killed client**: `NAT_TUNNEL_PEER_TIMEOUT_SECS` (default 60, min 30).
