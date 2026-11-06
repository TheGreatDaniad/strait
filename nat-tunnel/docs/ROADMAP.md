# Roadmap

This is the implementation order after the 0.3.0 desktop milestone. It puts
**Windows first**, then the **React Native** app for Android and iOS. The
plugin boundaries from [`MOBILE_PLAN.md`](MOBILE_PLAN.md) stay in force: the
tunnel protocol, the transport under it, and the IP-to-stream adapter are
separate choices.

## Current state

- Linux and macOS TUN work end to end (full tunnel, relay fallback, restore).
- Desktop GUI 0.3.0: connect/host/settings, connection history, max clients,
  per-client bandwidth, route/DNS/IPv6 restore, fail-safe probe.
- TCP forwarding and raw-IP TUN over the custom ChaCha20-Poly1305 tunnel.
- Windows client (Wintun full tunnel) and Windows host (userspace TCP/UDP
  exit) are implemented and runtime-tested on Windows 11 ARM64. Kernel
  forwarding from Wintun is not usable; see `docs/WINDOWS_TEST.md`.
- WireGuard is a config renderer only; it is not the data path yet.

## Phase 1 — Windows (client and host)

The goal is a Windows 11 ARM64 build that behaves like the macOS build: full
tunnel as client, exit node as host, same connection string, same restore
guarantees.

### W1. Wintun backend and interface setup (implemented, needs runtime test)

- `tun` crate + `wintun.dll`; adapter address `10.7.x.y/24`, MTU 1400.
- Interface metric 1 so Windows prefers the tunnel over Wi-Fi/Ethernet.
- Tunnel default route through the peer with route metric 1.
- Bypass routes (`New-NetRoute`) on the physical interface for the relay and
  RFC1918 LAN ranges.
- Route restore removes only the tunnel default (`Remove-NetRoute`) and
  re-creates the physical default if needed.
- Wintun DLL lookup: next to `nat-tunnel.exe`, then the working directory.
- Admin check before creating the adapter (`IsUserAnAdmin`).

### W2. DNS, IPv6 and socket pinning (implemented, needs runtime test)

- Capture physical DNS via `Get-DnsClientServerAddress`, apply
  `1.1.1.1/8.8.8.8` on the physical and Wintun interfaces, restore with
  `-ResetServerAddresses` or the captured list, flush with `Clear-DnsClientCache`.
- Disable `ms_tcpip6` on the physical adapter with `Disable-NetAdapterBinding`,
  restore with `Enable-NetAdapterBinding`.
- Pin the tunnel's UDP socket with `IP_UNICAST_IF` (interface index in network
  byte order) so encrypted datagrams keep using the physical path.
- Detect the physical default route with `Get-NetIPConfiguration` /
  `Get-NetRoute`, skipping Wintun and the current adapter index.

### W3. Packaging (script added)

- `scripts/windows-build.ps1` builds `x86_64-pc-windows-msvc` or
  `aarch64-pc-windows-msvc`, downloads Wintun 0.14.1, and copies
  `wintun.dll` beside the executable.
- GUI build is the default; `-Headless` produces the CLI/TUI binary without
  `eframe` for servers and the VM.

### W4. Windows runtime validation (blocked on the VMware Fusion Win11 ARM VM)

The concrete lab layout, prerequisites and acceptance commands are in
[`WINDOWS_TEST.md`](WINDOWS_TEST.md). Summary, in order:

1. `nat-tunnel.exe gui` starts elevated and creates the Wintun adapter.
2. Client to a macOS/Linux host: `curl` through the tunnel; remote site sees
   the tunnel address; `nslookup` resolves via `1.1.1.1` inside the tunnel.
3. Host on Windows to a macOS/Linux client: forwarding/NAT works after
   `New-NetNat` or ICS is configured.
4. Stop/close restores the default route, DNS and IPv6 binding; repeat twice.
5. Kill the process and confirm the routes do not persist (Wintun adapter
   removal); re-run the stale-route recovery.
6. Bandwidth limit and max-clients lanes behave as on macOS.
7. ARM64-specific check: no x64-only dependency in the release folder.

### W5. Windows polish

- Tray icon / single-instance guard and an explicit "Run as administrator"
  elevation prompt in the installer.
- Installer/MSIX or a portable zip with `wintun.dll`.
- Code-signing and SmartScreen notes.
- Optional: Windows service mode for an always-on host.

## Phase 2 — React Native shell (Android + iOS)

React Native owns the UI and shared state; the VPN and stream-exit pieces stay
native and call into the Rust core. The JS layer must not own packet I/O.

### R1. Shared Rust core API

- Stable C ABI (or `uniffi`) for: connect/stop, host start/stop, status,
  stats, connection history, settings, max clients, bandwidth.
- One connection-string parser for `relay:port|room|key[|gateway]`.
- Keep the tunnel/transport plugins behind the existing traits so the app does
  not depend on the current ChaCha20-Poly1305 implementation.

### R2. React Native app skeleton

- Expo prebuild or bare RN (bare is required for VPN extensions), TypeScript.
- Screens: Connect, Host, Settings, History (last + 5), Logs.
- Persisted storage: connection history, default relay, permanent host
  password, theme.
- Shared design tokens with the desktop Catppuccin themes.

### R3. Android client

- Kotlin native module: `VpnService`, TUN fd, `Builder.addRoute`/`addDnsServer`,
  `protect()` on the tunnel socket, foreground notification, restore on stop.
- Rust core via JNI (`cargo-ndk`, `arm64-v8a` + `x86_64`).
- IP-mode tunnel (custom now, WireGuard plugin later); **no tun2socks**.
- Acceptance: device reaches the internet through a desktop host; DNS works;
  route restore; no VPN loop; battery baseline recorded.

### R4. Android host (stream exit)

- Foreground service + wake lock; userspace stream exit and native
  `OPEN/DATA/CLOSE` framing (SOCKS5 optional, never required).
- Reachability through the relay (carrier NAT); max clients and per-client
  bandwidth enforced in the core.
- Acceptance: two clients concurrently through the phone exit with caps;
  survives screen-off via the foreground service; documented battery/thermal
  limits.

### R5. iOS client

- Swift `NEPacketTunnelProvider` extension; Rust staticlib
  (`aarch64-apple-ios`); `NEPacketTunnelNetworkSettings` for routes/DNS.
- App Group for settings/history; Network Extension entitlement and
  provisioning profile.
- Acceptance: device reaches the internet through a desktop host; clean
  start/stop; TestFlight build.

### R6. iOS host (experimental, foreground only)

- Stream exit inside the app while active; no background server, no NAT, no
  inbound reachability.
- Label as experimental and keep it out of App Store builds if review is a
  risk. Acceptance: works while foregrounded against one client.

## Phase 3 — Protocol and transport plugins

### P1. WireGuard data path

- `boringtun` as the first `TunnelPlugin`; replace the custom crypto/ARQ on the
  packet path without changing the OS TUN plumbing.
- Keys in the connection string/config; keepalive; replay window.
- Relay carries opaque WG datagrams; desktop hosts keep kernel TUN + NAT.

### P2. Transport plugins / DPI resistance

- Direct UDP -> UDP relay -> TLS/WebSocket relay on 443.
- Optional AmneziaWG/obfuscation for WireGuard fingerprint blocking.
- Failover order and a DPI testbed (UDP block, SNI/protocol filters, loss).

### P3. Stream protocol hardening

- Native stream framing as the product path; SOCKS5 only for interop.
- Destination ACLs, authentication, abuse prevention for stream exits.

## Phase 4 — Hardening

- Crash-safe restore (watchdog / startup reconciliation) on all platforms.
- Installer/packaging for Windows, macOS, Android, iOS.
- Security review: key handling, relay metadata, logging redaction.
- Performance baselines per platform (throughput, latency, battery).

## Dependencies and risks

- Windows runtime testing needs the VMware Fusion Windows 11 ARM VM with SSH.
- iOS host cannot be an always-on server; treat it as experimental.
- A phone exit is a userspace stream exit; quality is below a kernel-TUN
  desktop host (CPU, battery, TCP-over-reliable effects).
- WireGuard migration is a data-path replacement, not a GUI toggle; schedule
  it after Windows parity and before DPI work.
- DPI resistance is an arms race; the transport layer must remain pluggable.
