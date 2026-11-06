# Rendezvous methods — design (authoritative for all implementers)

Status: design, 2026-11-05. Research: `docs/research/*.md`. Live results: `docs/research/live-*.md`.

## 1. Purpose and invariants

Two peers must exchange *where they can be reached* (public IP:port, learned via STUN) before a UDP
hole punch. Behind a port-restricted cone NAT the host must also learn the **client's** endpoint and
both sides must send first, at about the same time. A *rendezvous method* is any channel that carries
those few bytes. Several methods can run at once; the first that delivers a peer wins.

Invariants (unchanged, a violation is a design change):
1. **Payload never touches a rendezvous service.** Only sealed endpoint blobs / tracker peer entries.
2. **No relay, ever.** If no direct path forms, fail with the reason.
3. **The host chooses the methods; nothing is silently on.** There is no built-in default list that
   runs without the host having selected it (the UI preselects nothing; CLI requires `--rendezvous`).
4. **The invite carries the chosen methods**, so the client tries every listed method it can reach.
   The client may disable methods locally (region blocks, privacy) and can test reachability.
5. **Every method shows an honest disclosure** (what is shared, why, what is not) before it is chosen.
6. The key never leaves the peers. Services see only values derived from it (one-way).

## 2. Derivation and sealed blobs (domain separated; `src/rendezvous/derive.rs`)

`prk = HKDF-SHA256(salt = "strait-rv-v1", ikm = invite_key_bytes(16))`. Per purpose `expand(info)`:

| info | use |
|---|---|
| `"seal"` (32 B) | ChaCha20-Poly1305 key for sealed blobs |
| `"room"` (32 B) | room tag; backends truncate/encode: tracker info_hash = first 20 B; Nostr `r` tag = hex; ntfy/MQTT topic = `strait-` + base32(first 16 B) |
| `"dht-host"`, `"dht-client"` (32 B) | ed25519 seeds for BEP 44 records (host record, client record) |
| `"nostr-sk"` (32 B) | NOT used: Nostr events are signed with a throwaway key per run |

Sealed blob (`seal`): `nonce(12) || ChaCha20-Poly1305(plaintext, aad = role_byte || "strait-rv-v1")`,
plaintext = `ver(1)=1 || role(1: 0 host, 1 client) || unix_secs(u32 BE) || n(1) || n × (family(1) 4|6, addr, port u16 BE)`
(<= 8 candidates). Receivers reject: bad tag, wrong role (own role), timestamp older than 120 s or
more than 30 s in the future, n = 0. Nonce: random 12 B. Blobs are never logged.

## 3. Trait (`src/rendezvous/mod.rs`)

```rust
pub enum Role { Host, Client }
pub struct Candidate { pub addr: SocketAddr, pub via: &'static str }   // via = method id

pub struct RvCtx {                  // built by the transport layer
    pub key: [u8; 16],              // invite key
    pub role: Role,
    pub local: Vec<SocketAddr>,     // my reachable candidates (STUN-mapped v4, global v6)
}

pub struct Disclosure {             // shown verbatim in CLI/GUI/app
    pub title: &'static str,
    pub shared: &'static [&'static str],      // what the service can see / store
    pub not_shared: &'static [&'static str],  // what never goes through it
    pub why: &'static str,
    pub operator: &'static str,               // who runs it (no uptime promise unless stated)
}

pub enum ProbeStatus { Reachable { rtt_ms: u32 }, Blocked(String), Error(String) }

#[async_trait::async_trait]            // or boxed futures; no new dep required if you prefer
pub trait Rendezvous: Send + Sync {
    fn id(&self) -> &'static str;      // "sig" | "trk" | "nostr" | "dht" | "ntfy" | "mqtt"
    fn disclosure(&self) -> Disclosure;
    /// Reachability only: handshake-level, publishes NOTHING. Must finish within `timeout`.
    async fn probe(&self, timeout: Duration) -> ProbeStatus;
    /// Publish my sealed candidates, keep them fresh and poll for the OTHER role's. Send every
    /// newly seen peer candidate on `tx` (dedup is done by the runner). Runs until `cancel` fires.
    async fn run(&self, ctx: RvCtx, tx: mpsc::Sender<Candidate>, cancel: CancellationToken) -> Result<(), RvError>;
}
```

`Runner` (`src/rendezvous/runner.rs`): `Runner::new(Vec<Arc<dyn Rendezvous>>)`; `start(ctx) -> RunnerHandle` runs all
backends concurrently, merges + dedups `Candidate`s into one stream, exposes live per-method
`Status { Starting, Publishing, Waiting, GotPeer(addr), Failed(String), Blocked(String) }` through a
watch channel (the UI shows it), restarts a failed backend with backoff (max 3), and stops everything
when dropped/cancelled. `probe_all(timeout)` probes every method concurrently (the "Test services"
button and `check-host`).

## 4. Invite

`STRAIT2|<key>|<hosts>|<signals>|<rv>` — new optional 5th field `rv`: comma list of method ids
(`sig`, `trk`, `nostr`, `dht`, `ntfy`, `mqtt`); empty/absent = none (old invites parse unchanged;
the legacy 4th-field `room` form must keep working: disambiguate by shape, tests required).
`sig` means "use the servers in the `signals` field". Unknown ids are kept and ignored at runtime
(forward compatibility) but never dropped when re-encoding. Max 8 methods.

## 5. Integration points (separate task, after backends exist)

Host mux loop and guest connect take `Vec<Arc<dyn Rendezvous>>` in place of the single `signal`
address (keep the old signal behaviour as the `sig` method). A candidate from any method feeds the
existing punch logic (`send_punch`, per-peer punch windows, simultaneous fire with RTT/2 timing for
the client side). Both roles publish; both poll. STUN-mapped port must come from the SAME socket
used for punching (already how `probe_host` works).

## 6. Methods (each in its own file, own tests with a local fake server, no real network in unit tests)

| id | file | transport | notes |
|---|---|---|---|
| `sig` | `sig.rs` | UDP (existing `relay.rs` protocol) | adapter over current code |
| `trk` | `trackers.rs` | UDP BEP 15, HTTPS fallback | info_hash from `room`; announce with `port = STUN-mapped port`; race 3-4 trackers; list refreshable/overridable; `event=stopped` on exit |
| `nostr` | `nostr.rs` | WSS | ephemeral kind first, replaceable/addressable fallback for late arrivals; throwaway key per run; 3-5 relays raced |
| `dht` | `dht.rs` | UDP (Mainline, BEP 44) | via the `mainline` crate, version pinned; client mode; two derived records |
| `ntfy` | `ntfy.rs` | HTTPS | topic from `room`; configurable base URL (self-hosted = same API) |
| `mqtt` | `mqtt.rs` | TLS 8883 | public brokers are test-grade: opt-in, flagged as such |
| manual | (UI/CLI) | none | copy/paste of the other side's endpoint; no service |

TLS everywhere uses rustls with webpki roots (no OpenSSL; Android arm64 and Windows must build).
Each backend is behind a cargo feature (`rv-trk`, `rv-nostr`, `rv-dht`, `rv-ntfy`, `rv-mqtt`),
all on by default; `cargo build --no-default-features` must still produce the headless CLI with
whichever features are named.

## 7. Politeness rules for public services (enforced in code, tested)

Minimum 1 s between requests to one service; exponential backoff on errors; stop using a service for
the session on rate-limit/ban signals; announce with `stopped` / cancel on exit; max publish
frequency per method documented in its file header; no retries storms; user-agent / client id carries
no identity.

## 8. Disclosure copy (drafts, final text lives in each backend's `disclosure()`)

- trk: shared = your public IP and port, the time, a code that looks random; operators can see both peers' addresses in plaintext. Not shared = key, payload, anything readable.
- nostr: shared = your IP (to the relays), timing, a random-looking tag, an unreadable sealed blob. Not shared = payload, key, addresses in plaintext.
- dht: shared = your IP to nodes that store the record, an unreadable sealed blob under a derived key. Not shared = payload, key.
- ntfy / mqtt: shared = your IP, a hashed topic name, an unreadable sealed blob; operator is a single company; MQTT brokers are for testing and may reset.
- sig: shared = your public IP and port to the signal server you chose. Not shared = payload.
Always: "Your traffic itself goes only between you and the other device."
