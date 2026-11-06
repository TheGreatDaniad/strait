# NAT Tunnel - Architecture

## Overview

A 1:1 NAT-traversal tunnel: two peers behind separate NATs meet through a
rendezvous relay, punch a direct UDP path when the NATs allow it, and fall back
to the relay. The same tunnel can carry one TCP service or whole IP packets.

## Layers

```
application
  -> OS network stack + TUN          (Linux tun, macOS utun, Windows Wintun,
                                      Android VpnService, iOS NEPacketTunnelProvider)
  -> payload adapter (only if needed) (userspace TCP/IP stack; never on the wire)
  -> tunnel plugin                    (current ChaCha20-Poly1305; WireGuard/OpenVPN later)
  -> transport plugin                 (UDP direct, UDP relay, TLS/WebSocket relay later)
```

The network only sees the tunnel and transport. The payload adapter is
client-internal. `tun2socks` is not part of an IP-mode tunnel; it only appears
if the exit is a stream proxy.

## Implemented pieces

### NAT traversal and transport
- STUN mapping discovery, minimal TURN allocate/refresh.
- Rendezvous relay: rooms, 1:1 pairing, opaque ciphertext forwarding.
- Simultaneous UDP hole punching with relay fallback.
- ChaCha20-Poly1305 per datagram, key = SHA-256(PSK), replay guard.
- Raw IP datagrams for TUN mode; reliable ARQ (AIMD, 512-frame window) for
  TCP-forward mode.
- Path preference: replies follow the peer's working path; every frame is also
  sent through the relay, and the ARQ deduplicates copies.

### Host / exit
- Linux and macOS: kernel TUN + forwarding/NAT.
- Windows: Wintun, routes/DNS/IPv6 capture and restore, `IP_UNICAST_IF`
  socket pinning, Administrator check.
- Mobile exits (planned): userspace stream exit with native `OPEN/DATA/CLOSE`
  framing; no NAT, no root, SOCKS5 optional.

### Client
- Linux: kernel TUN + fwmark policy routing.
- macOS: `utun` + `IP_BOUND_IF` pinning + IPv6 reject.
- Windows: Wintun + `IP_UNICAST_IF` + route/DNS/IPv6 restore.
- Mobile (planned): `VpnService` / `NEPacketTunnelProvider`, raw IP, no
  tun2socks for IP-mode tunnels.

### UI
- CLI (`host`, `guest`, `relay`), TUI, and the desktop GUI.
- GUI: connect/host/settings, Catppuccin themes, connection history (last + 5),
  max clients (lanes), per-client bandwidth, persisted settings.
- Mobile (planned): React Native UI with native VPN modules and the Rust core.

## Tech stack

- Rust, Tokio, `tun` (Wintun on Windows), `socket2`, `chacha20poly1305`,
  `clap`, `serde`, `eframe`/`egui`.
- Docker lab (three NAT scenarios + multi-client lanes) and macOS remote test.
- React Native planned for Android/iOS; Kotlin/Swift native modules.

## Development phases

1. Architecture design
2. NAT traversal module
3. Tunnel data path (custom ChaCha20-Poly1305; WireGuard plugin later)
4. Remote access / host lanes
5. Network simulation tests
6. Integration and Docker lab
7. Terminal UI
8. Desktop UI
9. Windows parity (current)
10. React Native Android/iOS app
11. WireGuard and transport/DPI plugins

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the detailed milestones.
