# Mobile Implementation Plan (Android + iOS)

This document records the architecture decisions from the design discussion and
turns them into milestones. It covers client and host roles on both mobile
platforms, with an explicit feasibility call for each.

## Decisions

1. **Layers are independent plugins.** The tunnel protocol, the transport under
   it, and the way packets are turned into streams are separate choices. The
   wire only exposes the tunnel + transport.

   ```
   app
     -> OS network stack + TUN          (VpnService / NEPacketTunnelProvider / utun / tun)
     -> payload adapter (only if needed) (userspace stack, tun2socks-style; never on the wire)
     -> tunnel plugin                    (WireGuard, our native stream tunnel, OpenVPN, ...)
     -> transport plugin                 (UDP direct, UDP relay, TLS/WebSocket relay, ...)
   ```

2. **Mobile clients use the OS VPN API.** Android `VpnService` and iOS
   `NEPacketTunnelProvider` give a TUN/packet flow. For an IP-mode tunnel
   (WireGuard) the client forwards raw IP packets; **no tun2socks** is involved.
   The tunnel socket must be protected (`VpnService.protect()` on Android,
   `NEPacketTunnelProvider` scoping on iOS) so it does not loop into the VPN.

3. **tun2socks is client-internal and does not limit the tunnel technology.**
   It is only an adapter that turns IP packets into flows for a *stream* exit.
   It never appears on the wire. What the network sees is the transport and the
   tunnel protocol.

4. **Phone as exit = userspace stack + native stream protocol.**
   Phones cannot NAT other clients' private addresses without root, so a phone
   exit terminates flows itself:
   - client: OS TUN -> userspace TCP/IP stack -> native stream frames
   - exit: native stream server -> real TCP/UDP sockets -> internet
   The stream protocol is ours (`OPEN/DATA/CLOSE` with a stream id and
   destination), not SOCKS5, so SOCKS-specific DPI is irrelevant. SOCKS5 stays
   as an optional interoperability plugin.

5. **WireGuard stays WireGuard where it is used.** If WireGuard is the tunnel
   plugin, it runs end-to-end inside whatever transport is selected. For a
   stream exit over WireGuard, the stream layer rides inside WG's IP tunnel;
   that is a layering choice, not a change to WG's cryptography.

6. **DPI resistance lives in the transport plugin.** UDP direct -> UDP relay ->
   TLS/WebSocket on 443. WireGuard fingerprinting or UDP blocking is handled
   there (optionally AmneziaWG), not by changing the tunnel semantics.

7. **Desktop/server remains the preferred host.** Kernel TUN + NAT on
   Linux/macOS/Windows is faster, transparent and lower battery. Mobile hosts
   are a stream-exit fallback with documented quality limits.

8. **iOS host is foreground-only and experimental.** iOS has no background
   server, no inbound reachability and no NAT. A stream exit can run only while
   the app is active, and App Store review may reject a general-purpose exit.
   It must be scoped and documented, not sold as an always-on server.

9. **Android host is feasible but constrained.** Foreground service + wake lock,
   userspace stack, battery/thermal cost, carrier NAT for reachability. It is a
   temporary exit node, not a line-rate server.

10. **Shared behaviour stays shared.** Connection strings, connection history
    (last + 5 recent), max clients, per-client bandwidth limits, route/DNS/IPv6
    restore, and the fail-safe probe apply to the mobile roles where the
    platform allows them.

11. **The app is React Native.** React Native owns the UI and shared state
    (connect/host/settings/history). The VPN, packet I/O, and stream-exit
    pieces stay native — a Kotlin `VpnService` module on Android, a Swift
    `NEPacketTunnelProvider` on iOS — and call into the Rust core. JavaScript
    never touches packets. The Windows desktop work lands before the RN app,
    so the mobile app consumes a tested core and a tested host.

## Feasibility matrix

| Platform | Client | Host / exit | Notes |
| --- | --- | --- | --- |
| Linux / macOS / Windows | yes | yes (kernel TUN + NAT) | best quality |
| Android | yes | yes, userspace stream exit | foreground service, no root, battery cost |
| iOS | yes | experimental, foreground only | no background/NAT; review risk |

## Milestones

The ordering matches [`ROADMAP.md`](ROADMAP.md): Windows parity first, then the
React Native app. M-numbers here are the mobile track; R-numbers in the
roadmap are the same work grouped with the app shell.

### M0 - Pluggable core + stable mobile API (Rust, no platform work)
- Introduce traits: `TunnelPlugin` (encapsulate/decapsulate IP or streams),
  `Transport` (datagrams/streams), `HostBackend` (kernel TUN vs userspace
  stack), `StreamExit` (native stream server, optional SOCKS5).
- Move the current custom tunnel behind these traits without changing behaviour.
- Expose a stable C ABI / `uniffi` surface: connect, stop, host start/stop,
  status, stats, history, settings, max clients, bandwidth.
- Keep the relay/hole-punch as the rendezvous + fallback transport.
- Acceptance: existing tests pass; no behaviour change on desktop; the ABI is
  callable from a C/Kotlin/Swift smoke test.

### M1 - WireGuard IP path
- Integrate `boringtun` as the first `TunnelPlugin`; WireGuard keys in the
  connection string/config.
- Desktop host: WG -> kernel TUN + forwarding/NAT; restore guard as today.
- Relay/hole-punch carries WG datagrams (direct or opaque relay).
- Acceptance: Linux/macOS/Windows client + host transfer data with WG
  end-to-end; relay fallback works; keys rotate; no plaintext leaks.

### M2 - Native stream layer + stream exit
- `OPEN/DATA/CLOSE` framing inside the encrypted tunnel; multiple streams;
  per-stream flow control.
- Exit side: terminate TCP/UDP in a userspace stack (`smoltcp` or equivalent),
  open real sockets, forward bytes. No NAT, no root.
- Optional SOCKS5 plugin for interoperability.
- Desktop stream-exit first; benchmark throughput/latency/concurrency.
- Acceptance: browser and multiple TCP streams through a phone-style stream
  exit; checksum-verified bulk transfer; SOCKS and native framing both work.

### M3 - React Native app shell
- Bare React Native (Expo prebuild is not enough for a VPN extension), TypeScript.
- Screens: Connect, Host, Settings, History (last + 5), Logs.
- Persisted settings: default relay, permanent host password, theme,
  connection history.
- Call the Rust core through the native modules; no packet code in JS.
- Acceptance: app builds for Android and iOS; history/settings survive restart;
  the UI can start/stop a mock session.

### M4 - Android client
- Kotlin native module: `VpnService`, TUN fd, `Builder.addRoute`/`addDnsServer`,
  `protect()` the tunnel socket, foreground notification, restore on stop.
- Rust core via JNI (`cargo-ndk`, `arm64-v8a` + `x86_64` for the emulator).
- IP-mode tunnel (custom now, WireGuard plugin later); **no tun2socks**.
- Acceptance: device/emulator reaches the internet through a desktop host;
  route/DNS restore; no VPN loop; battery baseline recorded.

### M5 - Android host (stream exit)
- Foreground service + wake lock; userspace stack; native stream server.
- Reachability via the relay (carrier NAT); max clients + bandwidth limit.
- Battery/thermal and background-kill tests; explicit UI warning.
- Acceptance: two clients concurrently through the phone exit with bandwidth
  caps; survives screen off via foreground service; documented limits.

### M6 - iOS client
- Swift `NEPacketTunnelProvider`; Rust staticlib (`aarch64-apple-ios`).
- Packet flow read/write, routes/DNS via `NEPacketTunnelNetworkSettings`.
- App Group for settings/history; Network Extension entitlement and
  TestFlight provisioning.
- Acceptance: device reaches the internet through a desktop host; clean
  start/stop; App Store-compatible privacy strings.

### M7 - iOS host (experimental, foreground only)
- Stream exit inside the app process while active; native stream protocol.
- No background execution; suspend/resume kills sessions; App Review risk.
- Deliverable: a clearly labelled experimental mode, or omit from App Store
  builds. Acceptance: works while foregrounded against one client; documented
  as non-always-on.

### M8 - Transport / DPI plugins
- TLS/WebSocket transport on 443; relay supports TCP/TLS; fallback order:
  direct UDP -> relay UDP -> TLS/WS relay.
- Optional AmneziaWG/obfuscation for WG fingerprint blocking.
- DPI testbed: SNI/protocol filters, UDP block, loss/latency; assert failover.
- Acceptance: with UDP blocked, the same session survives over TLS/WS 443;
  the tunnel protocol stays unchanged.

### M9 - Hardening and packaging
- Signing, provisioning, Windows Wintun DLL, mobile permissions/privacy.
- Connection history and persistence, max clients, per-client bandwidth,
  restore-on-crash, logging redaction.
- Security: destination ACLs for stream exits, auth, abuse prevention.
- Acceptance: repeatable builds for all targets; documented quality/limits.

## Cross-cutting requirements

- **Keys:** WireGuard keypairs for IP mode; PSK/session keys for the native
  stream mode. The relay never sees plaintext.
- **Restore:** every role that changes routes/DNS/IPv6 must restore on stop,
  crash (where the OS allows) and failed probe.
- **Probe:** production clients verify traffic through the tunnel; the Docker
  lab sets `NAT_TUNNEL_NO_PROBE=1` because it has no internet uplink.
- **Limits:** max clients (lanes) and per-client bandwidth apply to mobile
  hosts; the UI must show them.
- **History:** last connection + 5 recent, persisted per platform.

## Risks and honest limits

- **iOS host is not an always-on exit.** No background servers; App Review may
  reject it. Treat as experimental or omit.
- **Android host quality** is below a desktop: userspace stack, battery/heat,
  OS background limits, carrier NAT.
- **Userspace stream exits** carry TCP/UDP only; no ICMP/raw IP/multicast;
  TCP is terminated and re-originated.
- **TCP-over-reliable** (stream layer over ARQ/TLS) brings head-of-line and
  double-retransmission effects; prefer raw IP + kernel NAT where possible.
- **DPI** is an arms race; no transport is universally unblockable.
- **WireGuard fingerprinting** is real; the transport plugin, not the tunnel,
  is the mitigation.
