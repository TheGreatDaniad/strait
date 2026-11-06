# Strait

Peer-to-peer internet sharing through NAT, with no relay. One device (the host) shares its connection; another (the client)
uses it. The two find each other, punch through their NATs, and talk directly over UDP.

A strait is a narrow passage between two shores: the shores are the two peers, the passage is the tunnel.

## Principles

- **Payload only travels between the two peers.** There is no relay or TURN fallback, ever.
- **The invite string is the capability.** Whoever holds it can connect; nothing else is trusted.
- **Failure is explicit**, with a reason (no usable rendezvous, symmetric NAT on both sides, host full, ...).
- **Servers only help peers find each other.** They see a sealed address blob, never your traffic or the key.

## What is here

| Path | What it is |
|---|---|
| `nat-tunnel/` | Rust core: CLI (`host`, `guest`, `check-host`, `rv-test`, `recover`), desktop GUI (egui), rendezvous layer, carriers, deploy scripts, docs. The crate and binary are called `nat-tunnel`. |
| `strait-mobile/` | React Native app (Android, iOS) over the same Rust library. |
| `nat-tunnel/docs/` | Design (`RENDEZVOUS_DESIGN.md`, `TUNNEL_CARRIERS.md`), plans and roadmap. |
| `nat-tunnel/docs/design/` | The visual design handoff (palette, mark, screens). |

## How peers find each other

The host chooses which rendezvous methods to use; nothing is on by default. Each shows what it can see before you pick it:
UDP signal server (`sig`), BitTorrent trackers (`trk`), Nostr relays, Mainline DHT, ntfy, public MQTT. All derive their room from
the invite key with HKDF and publish only ChaCha20-Poly1305 sealed endpoints. See `nat-tunnel/docs/RENDEZVOUS_DESIGN.md`.

## Build and test

```bash
cd nat-tunnel
cargo build --release                      # CLI + GUI
cargo test --no-default-features           # headless suite (some live-network tests are #[ignore])
cargo run --release -- gui                 # desktop GUI; the full tunnel needs root
cargo run --release -- check-host          # what kind of NAT are you behind, who can reach you
```

Mobile: `cd strait-mobile && npm install && npx jest`. Device builds are described in `strait-mobile/ios/README_DEVICE_TESTING.md`.
A packet-tunnel VPN on iOS needs a paid Apple Developer team.

## Status

Alpha. Verified on macOS, Windows 11 ARM and Android (emulator) against a real internet host, over every rendezvous method.
iOS runs in the simulator; the system VPN is untested on a device. Hole punching cannot succeed when the host is port-restricted
and the client is symmetric (needs birthday probing, not implemented): the app says so instead of falling back.

## Notes

- Example addresses use documentation ranges (`203.0.113.0/24`) and the example key `0123456789abcdef0123456789abcdef`.
  Generate your own key; never reuse an example.
- No license has been chosen yet.
