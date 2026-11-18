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

The Noise static key is the same key in X25519 form (`to_scalar_bytes` / `to_montgomery`). Key exchange
(X25519) is the host key's only direct use; every signature and MAC has a key of its own:

| Use | Key |
|---|---|
| Noise static key (join handshake), and opening guests' rendezvous records (X25519 with a fresh key, see Rendezvous records) | the host key, X25519 form |
| Rendezvous record signatures | per-invite subkey, purpose `record` |
| The host's DHT items (BEP 44) | per-invite, per-day subkey, purpose `dht` |
| WebSocket carrier TLS handshake | per-invite subkey, purpose `tls` |
| Personal-invite token MAC | `HMAC(host key, "strait-guest-token-v4" ‖ invite key)` |

A subkey is made by key blinding, as Tor v3 onion services do: `subkey = b · host key` with
`b = SHA-512("strait-subkey-v1" ‖ purpose ‖ hk ‖ invite key) mod ℓ`, and its own nonce prefix
`SHA-512("strait-subkey-prefix-v1" ‖ prefix ‖ b)[..32]`. A guest computes the public half, `b · hk`,
from the invite. Without the invite key a subkey cannot be linked to `hk` or to the same host's
subkeys under other invites, so knowing `hk` (a guest removed by "Change every invite", or anyone
who probed a WebSocket host) does not let anyone recognise the host's records or certificates.
The blinded signing keys and the X25519 use of the host key are related keys; no published proof
covers that exact combination (Thormarker, IACR ePrint 2021/509, covers one key pair used for
Ed25519 and an X25519 KEM).

## Handshake

Noise `NKpsk0` with X25519, ChaCha20-Poly1305 and SHA-256, through the `snow` crate. Prologue
`strait-join-v3`. Full-tunnel mode and forward mode (one guest, TCP bridge) use it alike. A
forward-mode host applies the same personal-invite rules, refuses a JOIN from another address (IP
and port) as full while the current guest was heard from in the last 30 s (an idle guest sends a
keepalive every 10 s), and opens a new connection to the forwarded service for every new session.

| Input | Value |
|---|---|
| psk | `SHA-256("strait-mux-v3" ‖ invite key)` |
| host static key | X25519 form of the host key; the guest takes it from `hk` |
| guest | one fresh ephemeral key per join attempt |
| prologue | `"strait-join-v4" ‖ cn`: message 1 is bound to the nonce it travels with |

```text
JOIN    0xF8 | cn (16) | Noise message 1 (e, es; payload: clock (4) | optional token (24)) | tag (16)
ACCEPT  0xF9 | cn (16) | Noise message 2 (e, ee; payload: slot (2) | cn (16) | verdict (1))  | tag (16)
```

`tag` is `HMAC(tag key, label ‖ fields)[..16]` with `tag key = HMAC(psk, "strait-outer-tag-v1")`
(never the psk itself): a cheap check, so only an invite holder makes the host run a key exchange.
`cn` is also in the Noise prologue, so a captured message 1 cannot be re-wrapped under another
`cn`: it would not decrypt. The verdict is 0 accepted, 1 full, 2 refused (withdrawn, expired or
foreign personal invite; personal invites only), 3 clock. A refusal is message 2 like an
acceptance, so only the host can send one. The session key is
`HMAC(k1, "strait-session-v3" ‖ k2)` over Noise's two transport keys.

What this gives:

- Without the invite key nobody can produce or read either message.
- Only the holder of the host key can read message 1 or produce a readable message 2: holding an
  invite is not enough to pose as the host, or to make a guest give up.
- Both sides contribute a fresh key, so a recording stays unreadable if the invite or the host key
  leaks later, and no peer can read another peer's traffic.
- Message 1 carries the guest's clock: the host refuses a JOIN more than 2 minutes off, or made
  before the host started (with 60 s of slack): its memory starts empty, so a recording from before
  a restart is stale too. The refusal (message 2, so only the host can send it) carries the host's
  clock, and the guest joins again on that clock (up to three times), so a wrong clock on either
  side costs one round trip, not the connection. A waiting guest renews its JOIN every 30 s, so a
  host that starts or restarts while it waits still finds it fresh.
- The host remembers the ephemeral key of every fresh message 1 it opened, before deciding
  anything, for 5 minutes (longer than a JOIN stays fresh): a recorded JOIN costs it one key
  exchange. A stale JOIN is refused every time and not remembered, so a flood of them cannot push
  fresh ones out. The memory holds 262,144 JOINs, more than the global join budget (5000 per 10 s)
  lets in over 5 minutes, so it never fills and no JOIN is forgotten early, whatever clocks a flood
  carries; were it ever full, a new JOIN would be dropped, never an old one forgotten. An entry
  leaves only once the wall clock also calls its JOIN stale, so a host clock that steps back does
  not reopen a replay. A JOIN deferred while every free slot is busy stays remembered; only its own retry
  (same `cn`, same address) is read again. A retry of a refused JOIN gets the same refusal from
  memory, and a repeated accepted JOIN gets its answer again at most once a second, only at its own
  address. A guest that the host refused stops, rather than retrying.
- An accepted join takes an unconfirmed slot at once, for up to 20 s, and keeps it only once a
  packet under its session key arrives, so a replayed JOIN cannot keep a slot.
- One network (an IPv4 address, an IPv6 /48) may start 20 new handshakes per 10 s and its wider
  network (IPv4 /24, IPv6 /32) 80, hold three quarters of the slots, and hold four unconfirmed
  joins per invite. The host tracks 4096 networks at once and then forgets the older half, and
  reads at most 5000 handshakes per 10 s in all (about 25 ms of CPU a second): many senders slow
  each other down and cannot exhaust the host; a flood from hundreds of networks can hold off new
  joins while it lasts, never sessions already up. One
  personal invite may start 20 new sessions per 10 s wherever it joins from. A full host frees an
  unconfirmed slot of the same source, or one older than 3 s; a join younger than that is never
  pushed out by someone else's. Joins through a local sidecar (xray) have no known network: they
  share one larger handshake budget and are not held to the per-network slot share.
- Holders of the shared invite on two networks can fill a host (three quarters each). The People
  list shows them; withdraw or change the invite. A host that takes personal invites only is
  filled one slot per personal invite.
- A guest's pending handshake survives a forged answer: it rebuilds its Noise state from the same
  ephemeral key for each answer it tries.
- Which older session a new join replaces (the same device restarting, the same personal invite)
  is decided on the address the JOIN came from, before a data packet can move the session.
  Afterwards the session follows its authenticated packets to a new address, as WireGuard does.
- Admission is re-checked every tick, not only at the join: a session ends when its personal
  invite expires or is withdrawn, and shared-invite sessions end once the host takes personal
  invites only (removing someone turns that on). Nothing else ends a live session: key rotation,
  JOIN renewal and the daily changes of records and certificates never interrupt one.
- Forward mode: a new JOIN, even from the current guest's own address, replaces the live session
  only once its first packet under the new key arrives. A JOIN alone (perhaps spoofed) cannot end
  it.
- Signal server: once an authenticated packet has come in, only such packets move a guest's
  idea of where the host is; the server's PEER messages no longer can. Addresses the server names
  are punched within the same budget as sealed records (see Rendezvous records).

## Personal invites

A token is `id (4) | expires (4, Unix seconds, 0 = none) | HMAC(token key, "guest" ‖ id ‖ expires)[..16]`,
with `token key = HMAC(host key, "strait-guest-token-v4" ‖ invite key)`: a token works only with the
invite it was made from. It travels in the invite as `gt=` and on
the wire only inside Noise message 1, encrypted to the host.

- The host verifies it without stored state, knows which invite joined, and can withdraw one id.
- Withdrawing a personal invite switches the host to personal invites only (otherwise the person
  could come back with the shared invite), in the window and from `STRAIT_REVOKED` alike. The
  window keeps its personal invites, withdrawn ones included, in its settings: ids are never
  reused, a withdrawal survives a restart, and the switch stays on until "Change every invite":
  a removed person's personal invite holds the invite key, which does not expire with the token.
- While the shared invite is allowed, anyone holding a personal invite also holds the shared one
  (drop the token and it is the shared invite), so the one-device rule and removal bind only on a
  host that takes personal invites only. Removing someone turns that on.
- A session ends when its personal invite expires or is withdrawn, not only at the next join.
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

- A guest's record (its public address) is for the host only: sealed with ChaCha20-Poly1305 under
  `HKDF(salt = record key, X25519(fresh key, host Noise key) ‖ fresh public key)`, the fresh public
  key in front, and a 16-byte HMAC under the record key at the end, checked before the key
  exchange, so only an invite holder makes the host do one. Other invite holders cannot read it.
  It is sealed to the host key itself, so it is not forward secret: someone who archives records
  and later gets the host key learns where guests connected from.
- Host records are sealed with ChaCha20-Poly1305 under a key from the invite key, and carry an
  Ed25519 signature over `"strait-record-v1" ‖ nonce ‖ ciphertext` by the host's record subkey for
  this invite. A guest accepts a host record only with a valid signature. Without the invite key
  the signature cannot be checked, so `hk` alone does not link one host's records.
- The identifiers each service sees (topics, the DHT keys, the info-hash) change every UTC day. The
  host's DHT key is its subkey (purpose `dht`) for the invite and the day, so only the host can
  publish there; the guests' DHT key comes from the invite key and is shared by every guest.
- Trackers (`trk`) cannot carry a signature and announce in cleartext: they are never offered in
  the app, come with a warning on the command line, and a guest never port-scans or fans out at an
  address that only an unsigned source reported. A guest keeps at most 8 such addresses at once;
  a host punches only addresses from sealed client records or the signal server: at most 64 new
  addresses an hour and 8 ports of each, never a port below 1024 (UDP, and TCP for the WebSocket
  carrier), and port-sprays at most 16 new addresses an hour. The budget is one per host, so an
  invite holder can use it up, which then stops a host behind NAT from reaching new guests until
  the hour ends or it shares again.
- On the command line, trackers (`trk`) announce guests' addresses in cleartext under the invite's
  info-hash, so any invite holder can list them; the app never uses trackers.
- Any invite holder can block the guests' shared DHT slot for a 10-minute window with a maximal
  sequence number; guests then find the host through the other services.
- The address a host signs comes from STUN only when two servers agree on it (or only one is
  configured); after that the server that agreed keeps it current on its own.
- A host record carries its signing time inside the signature and is refused 2 minutes later; on
  the DHT, which a host republishes every few minutes, up to 7 minutes later.
- The birthday scan a symmetric-NAT host needs sends to ports 1024 and up of at most 2 addresses
  from signed records, for at most 3 minutes, and a guest scans one address at most 3 times an hour.
- The signal-server room changes every UTC day, like the other identifiers; the server does not
  let another address replace a host registration that is still live. Registrations are not
  authenticated, so an invite holder (or anyone who sees the room on the wire) can register as the
  host first and keep the real host from being found there; guests then find it through the other
  services.

## What a guest can reach through the host

One rule set for the userspace exit and the kernel TUN path: the public internet over IPv4 only.
Never the host itself (its interface addresses and its public address, which is its router's
WAN side), the networks it sits on (every on-link IPv4 subnet of /16 or narrower, public ones
too: an office or university LAN), networks it reaches through another interface than its default
route (a VPN or tailnet it is connected to), the tunnel network (other guests), private, loopback, link-local or multicast ranges,
IPv6 destinations, or TCP port 25, nor cloud metadata and platform addresses (169.254.0.0/16,
168.63.129.16, 100.100.100.200) or 192.0.0.0/24 and 198.18.0.0/15. `--allow-lan` opens the private
ranges, 192.0.0.0/24 and 198.18.0.0/15, never the cloud addresses; `STRAIT_EXIT_ALLOW_SMTP=1` opens port 25;
`STRAIT_EXIT_ALLOW_HOST=1` (labs) lets guests reach services on the host's tunnel address. Each
guest may keep 64 TCP flows open through the userspace exit. "Another interface" means a source
address the host does not use toward the internet (judged by the sources toward eight unrouted
test addresses, so multi-WAN hosts keep all their uplinks). A VPN that carries all of the host's
traffic, networks reached through another router on the host's own LAN, and services that trust
the host's address are not told apart from the internet; the other way round, when the host's VPN
carries everything but sends a few ranges around it (split exclusions), guests are refused those
ranges.

A guest, in turn, only takes packets from the host that are addressed to its own tunnel address
and answer something it sent: a TCP segment that opens a connection (SYN without ACK) is dropped,
UDP passes only from an address and port that a local port sent to through the tunnel in the last
3 minutes, and of ICMP only
echo replies and errors pass. Every other protocol (GRE, IP-in-IP, IPv6-in-IPv4, SCTP, ...) and
every fragment is dropped (overlapping fragments could rewrite the TCP flags, RFC 1858). The host
cannot ping the guest or connect to services on the guest's device. A reply that arrives
fragmented is lost; DNS keeps answers under 1232 bytes, and TCP and QUIC avoid fragmentation.

## WebSocket carrier identity

The `ws` carrier's TLS certificate is made with the host's TLS subkey for the current invite and
UTC day, not the host key. A guest ignores the certificate's contents and checks the TLS 1.3
handshake signature against the subkeys it derives from `hk`, the invite key and yesterday, today
and tomorrow, so only the host can complete TLS; holding the invite is not enough. A connection
already up keeps its TLS session across midnight. A prober without the invite still completes TLS
and sees a self-signed certificate, which tells it nothing about `hk` or the host's records, and
changes every day and with the invite: the same host can be recognised by its certificate for one
day at most. The host accepts at most 8 pending TLS handshakes per IPv4 /24 or IPv6 /64, 256 in
all. Where active probing matters, where active probing matters, the Xray (REALITY) carrier, or `tls=ca` behind a real
certificate, is the choice.

## Privileges

Sharing needs no administrator rights on macOS and Linux (the userspace exit). A full-tunnel guest
asks for the password once per connection, and only the tunnel runs as root: the window stays an
ordinary process. Root installs its own copy of the program into
`/Library/PrivilegedHelperTools/strait` (macOS) or `/usr/local/libexec/strait` (Linux) and checks
that the copy has the SHA-256 the window computed when it staged the program. That stops the file
being swapped between staging and use; it does not prove the program is genuine (the app is not
code-signed yet): what approves it is the password prompt. Root writes
its log only into `/var/run/strait/<uid>`, a folder it creates itself. It receives the rendezvous
and carrier choices only, never a path to another program. Windows still runs the whole window as
administrator. The tunnel's log files are 0600 and belong to the user, so other users of the
computer cannot read them. Crash-recovery state (DNS, IPv6, routes) is written before anything
changes, so a kill at any moment can be undone; on macOS it includes the IPv4 default route. On
Linux the system's default route is never changed: two /1 routes through the tunnel take over and
go away with the tunnel device.

A full tunnel sends DNS to 1.1.1.1 and 8.8.8.8 through the tunnel: macOS and Windows set those
resolvers, Linux sets them on the tunnel link for every name through systemd-resolved (without
it, Linux points /etc/resolv.conf at them, keeping its search and options lines, and puts the
original back afterwards; the original is saved first in a root-only folder that survives a reboot,
so after a crash or a power loss the next session, or `nat-tunnel recover`, puts it back; if a DHCP
client rewrites the file meanwhile, its version is kept). With systemd-resolved, names under a routing domain of the physical link (such as
a company's internal domain) still go to that link's resolver. Android routes all public addresses through the VPN and leaves only the app
itself (the tunnel's own packets) out.

The Xray carrier forwards visitors without the key to its REALITY target: an explicit
`target=`, else `<sni>:443`, never a local address on its own.

## Formal model

`docs/proverif/strait_nkpsk0.pv` is a symbolic ProVerif model of the join against an attacker who
holds the invite, who can have the host open guest records of its making (an X25519 oracle on the
host key), and who gets the host key once every session is over. ProVerif 2.05 proves that
the guest's token stays secret while the host key does; that traffic in both directions stays
secret, also after the host key leaks; that a guest that finishes a join has talked to the holder
of the host key (injective agreement on both ephemeral keys and the session key); that every
session the host accepts under the guest's token has a key the attacker never learns; and that a
message 1 carrying the token was made by that guest. It also confirms the limit that the token is
not forward secret. Results are in `docs/proverif/README.md`. The model's header lists its
abstractions: the AEAD's associated data is the ephemeral key rather than the transcript hash; one
host and one `hk`; no signing oracle on the host key (the subkeys and the token MAC are not
modelled); `cn`, the outer tag, the clock check and the replay memory are not modelled; nor are
rotation and the rendezvous and carrier layers. Nonce uniqueness is argued under Session keys
above.

## Not covered

- An invite holder can replay a signed host record within its 2 minutes (7 on the DHT).
- A malicious host can point its guests' birthday scan at an address of its choice, within the
  limits above (high ports, 3 minutes, 3 times an hour).
- A copy of a personal invite works while its owner is not connected.
- No kill switch: if Strait stops, traffic uses the normal connection again.
- A personal token is not forward secret: someone who records a join and later gets the host key
  learns which token was used (not the traffic).
- The record and TLS subkeys are related to the host key's X25519 use (see Host key).
- Root checks that its copy of the tunnel program matches what the window staged, not that it is
  genuine: the app is not code-signed yet.
- Holders of the shared invite on two networks can fill a host (see Handshake), and any invite
  holder can use up the host's hourly punch budget (see Rendezvous records).
- Guest rendezvous records are not forward secret (see Rendezvous records).
- Signal-server registrations are not authenticated (see Rendezvous records).
- A session follows its authenticated packets to a new address at once (NAT rebinding); an
  attacker on the path who races one copied packet can move it until the guest's next packet.
- When the tunnel device is rebuilt (a new address or MTU), traffic leaves outside the tunnel for
  a moment, as it does when Strait stops.
- Android logs the tunnel's messages (with addresses) to logcat, which adb and bug reports can
  read.
- A WebSocket host behind a reverse proxy sees every guest at the proxy's address: the per-address
  cap of 16 connections does not apply there, only the total of 256.
- Nothing here has been audited by an outside party.
- The host owner sees where a guest's traffic goes and its unencrypted content, as any VPN exit does.
