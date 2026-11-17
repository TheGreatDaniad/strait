# Join handshake, host key, personal invites, session keys, exit policy

How a guest joins a host, and what each side can and cannot do. Code: `src/tunnel/handshake.rs`
(Noise, host key, tokens), `src/transport.rs` (datagrams, host and client state),
`src/tunnel/crypto.rs` (session encryption, replay window, rotation), `src/rendezvous/derive.rs`
(rendezvous records), `src/userspace.rs` (exit policy). Tests: `tests/handshake_security.rs` and
unit tests next to the code.

## Host key

Every host has a long-term Ed25519 key, made on first use and kept in the settings directory
(owner-only file) or given as `STRAIT_HOST_KEY`. Its public half is in every invite as `hk=`. An
invite without `hk` is refused, and a host refuses to run an invite that names another key.

The Noise static key is the same key in X25519 form (`to_scalar_bytes` / `to_montgomery`), and the
host signs its rendezvous records with it. Using one key pair for both purposes is analysed in
Thormarker, "On using the same key pair for Ed25519 and an X25519 based KEM" (IACR ePrint 2021/509).

## Handshake

Noise `NKpsk0` with X25519, ChaCha20-Poly1305 and SHA-256, through the `snow` crate. Prologue
`strait-join-v3`. Full-tunnel mode and forward mode (one guest, TCP bridge) use it alike. A
forward-mode host applies the same personal-invite rules, refuses a JOIN from another address as
full while the current guest was heard from in the last 30 s (an idle guest sends a keepalive every
10 s), and opens a new connection to the forwarded service for every new session.

| Input | Value |
|---|---|
| psk | `SHA-256("strait-mux-v3" ‖ invite key)` |
| host static key | X25519 form of the host key; the guest takes it from `hk` |
| guest | one fresh ephemeral key per join attempt |

```text
JOIN    0xF8 | cn (16) | Noise message 1 (e, es; payload: clock (4) | optional token (24)) | tag (16)
ACCEPT  0xF9 | cn (16) | Noise message 2 (e, ee; payload: slot (2) | cn (16) | verdict (1))  | tag (16)
```

`tag` is `HMAC(psk, label ‖ fields)[..16]`: a cheap check, so only an invite holder makes the
host run a key exchange. The verdict is 0 accepted, 1 full, 2 refused (withdrawn, expired or
foreign personal invite; personal invites only), 3 clock. A refusal is message 2 like an
acceptance, so only the host can send one. The session key is
`HMAC(k1, "strait-session-v3" ‖ k2)` over Noise's two transport keys.

What this gives:

- Without the invite key nobody can produce or read either message.
- Only the holder of the host key can read message 1 or produce a readable message 2: holding an
  invite is not enough to pose as the host, or to make a guest give up.
- Both sides contribute a fresh key, so a recording stays unreadable if the invite or the host key
  leaks later, and no peer can read another peer's traffic.
- Message 1 carries the guest's clock: the host refuses a JOIN more than 10 minutes off. It
  remembers every nonce (`cn`) it opened before deciding anything, so a recorded JOIN, fresh or
  stale, costs it one key exchange; a retry of a refused JOIN gets the same refusal from memory.
- An accepted join takes an unconfirmed slot at once, for up to 20 s, and keeps it only once a
  packet under its session key arrives, so a replayed JOIN cannot keep a slot.
- One network (an IPv4 address, an IPv6 /64) may start 20 new handshakes per 10 s, hold three
  quarters of the slots, and hold four unconfirmed joins per invite. A full host frees an
  unconfirmed slot of the same source, or one older than 3 s; a join younger than that is never
  pushed out by someone else's. Joins through a local sidecar (xray) have no known network: they
  share one larger handshake budget and are not held to the per-network slot share.
- A guest's pending handshake survives a forged answer: it rebuilds its Noise state from the same
  ephemeral key for each answer it tries.

## Personal invites

A token is `id (4) | expires (4, Unix seconds, 0 = none) | HMAC(token key, "guest" ‖ id ‖ expires)[..16]`,
with `token key = HMAC(host key, "strait-guest-token-v4" ‖ invite key)`: a token works only with the
invite it was made from. It travels in the invite as `gt=` and on
the wire only inside Noise message 1, encrypted to the host.

- The host verifies it without stored state, knows which invite joined, and can withdraw one id.
- Withdrawing a personal invite switches the host to personal invites only (otherwise the person
  could come back with the shared invite), in the window and from `STRAIT_REVOKED` alike. The
  window keeps its personal invites, withdrawn ones included, in its settings: ids are never
  reused, a withdrawal survives a restart, and the switch stays on while a withdrawn invite has
  not expired.
- A personal invite works on one device at a time: while its session was heard from in the last
  40 s, a join with the same token from another address is refused as full; a silent session is
  replaced once the new one confirms. A copy can still be used while the owner is offline.
- "Change every invite" in the window stops sharing and starts again with a new invite key. Every
  old invite stops working, personal ones too (their tokens are bound to the old invite key), so
  a removed person no longer has the keys to the rendezvous records either.

Command line: `host-key`, `personal-invite --id N [--days D]`, `host --personal-only`,
`STRAIT_REVOKED=3,9`. The invite and a raw `--key` never go on the command line, where every user
of the computer can read them: they come from `STRAIT_INVITE`, or `--invite -` / `--key -` read
them from standard input.

## Session keys

- Datagram: `session id (8) | counter (8) | ChaCha20-Poly1305 ciphertext`. The counter is the
  nonce; the two directions differ by a direction bit.
- Replay: a sliding window of 2048 counters accepts reordered datagrams once each.
- Rotation: the top 24 bits of the counter are an epoch, and epochs follow the clock from the start
  of the session. Every 120 s both sides hash their send key and their receive key forward
  (`k' = SHA-256("strait-rekey-v3" ‖ k)`) and drop the old ones, whether or not anything was sent
  (a receiver keeps two epochs of slack). A key read from a device later does not open earlier
  epochs. Each (key, nonce) pair is used once: a key belongs to one epoch of one direction, and the
  counter within it only grows.

## Rendezvous records

- Sealed with ChaCha20-Poly1305 under a key from the invite key; host records also carry an
  Ed25519 signature by the host key. A guest accepts a host record only with a valid signature.
- The identifiers each service sees (topics, the DHT keys, the info-hash) change every UTC day.
- Trackers (`trk`) cannot carry a signature and announce in cleartext: they are never offered in
  the app, come with a warning on the command line, and a guest never port-scans or fans out at an
  address that only an unsigned source reported. A guest keeps at most 8 such addresses at once;
  a host sprays only sealed client records, at no more than 16 new addresses an hour.
- The address a host signs comes from STUN only when two servers agree on it (or only one is
  configured).
- A host record carries its signing time inside the signature and is refused 2 minutes later.
- The birthday scan a symmetric-NAT host needs sends to ports 1024 and up of at most 2 addresses
  from signed records, for at most 3 minutes, and a guest scans one address at most 3 times an hour.
- The signal-server room changes every UTC day, like the other identifiers; the server does not
  let another address replace a host registration that is still live.

## What a guest can reach through the host

One rule set for the userspace exit and the kernel TUN path: the public internet over IPv4 only.
Never the host itself (its interface addresses and its public address, which is its router's
WAN side), the tunnel network (other guests), private, loopback, link-local or multicast ranges,
IPv6 destinations, or TCP port 25, nor cloud metadata and platform addresses (169.254.0.0/16,
168.63.129.16, 100.100.100.200) or 192.0.0.0/24 and 198.18.0.0/15. `--allow-lan` opens the private
ranges, 192.0.0.0/24 and 198.18.0.0/15, never the cloud addresses; `STRAIT_EXIT_ALLOW_SMTP=1` opens port 25;
`STRAIT_EXIT_ALLOW_HOST=1` (labs) lets guests reach services on the host's tunnel address. Each
guest may keep 64 TCP flows open through the userspace exit.

A guest, in turn, only takes packets from the host that are addressed to its own tunnel address
and answer something it sent: a TCP segment that opens a connection (SYN without ACK) is dropped,
and UDP only reaches a local port that sent through the tunnel in the last 3 minutes. The host can
ping the guest's tunnel address, but not connect to services on the guest's device.

## WebSocket carrier identity

The `ws` carrier's TLS certificate is made with the host key. A guest ignores the certificate's
contents and checks the TLS 1.3 handshake signature against `hk`, so only the host can complete
TLS; holding the invite is not enough. A prober without the invite still completes TLS and sees a
self-signed certificate: where active probing matters, the Xray (REALITY) carrier, or `tls=ca`
behind a real certificate, is the choice.

## Privileges

Sharing needs no administrator rights on macOS and Linux (the userspace exit). A full-tunnel guest
asks for the password once per connection, and only the tunnel runs as root: the window stays an
ordinary process. Root installs a verified copy of the program into
`/Library/PrivilegedHelperTools/strait` (macOS) or `/usr/local/libexec/strait` (Linux), and writes
its log only into `/var/run/strait/<uid>`, a folder it creates itself. It receives the rendezvous
and carrier choices only, never a path to another program. Windows still runs the whole window as
administrator.

## Formal model

`docs/proverif/strait_nkpsk0.pv` is a symbolic ProVerif model of the join against an attacker who
holds the invite. ProVerif 2.05 proves that the guest's token and its traffic stay secret, that a
guest that finishes a join has talked to the holder of the host key (injective agreement on both
ephemeral keys and the session key), and that a host that sees the guest's token got it from that
guest (results in `docs/proverif/README.md`). It leaves out the clock check,
the replay cache, rotation and the rendezvous and carrier layers. Nonce uniqueness is argued under
Session keys above.

## Not covered

- An invite holder can replay a signed host record within its 2 minutes.
- A malicious host can point its guests' birthday scan at an address of its choice, within the
  limits above (high ports, 3 minutes, 3 times an hour).
- A copy of a personal invite works while its owner is not connected.
- No kill switch: if Strait stops, traffic uses the normal connection again.
- Nothing here has been reviewed by an outside party.
- The host owner sees where a guest's traffic goes and its unencrypted content, as any VPN exit does.
