# Strait

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="nat-tunnel/assets/logo/strait-logo-dark.png">
  <img src="nat-tunnel/assets/logo/strait-logo-light.png" alt="Strait logo" width="170" align="left">
</picture>

<br><br><br>

**Use another person's home internet connection, directly, from your own device.**

<br clear="left">

## What is Strait?

Strait is software that two people run on their home computers or phones. One of them (the **host**) shares their internet
connection, and the other (the **client**) uses it, through a tunnel between the two devices. The server end of the tunnel is
simply a home device.

That is the problem it solves: getting online through someone you trust, with their connection and their IP address, without
renting a server and without setting one up.

## Easy to use

- One click to run, no configuration. The host starts sharing and gets an invite code; the client pastes it and connects.
- The app checks your network for you and tells you plainly what will and will not work.

## Flexible tunnels

The two peers can choose how they connect. Besides the built-in encrypted UDP tunnel, Strait supports other transports,
for networks that block or inspect traffic:

- Shadowsocks-2022
- Obfuscated UDP in the style of AmneziaWG (our own envelope, not compatible with WireGuard or AmneziaWG clients)
- WebSocket over TLS (TCP). When the host has no reachable TCP port, both sides open the connection to each other through their routers, the same way the UDP tunnel is hole-punched
- Xray (VLESS + REALITY)

## No server of your own

Two devices behind home routers cannot normally find each other. When a signaling step is needed, Strait uses public services
(BitTorrent trackers, Nostr relays, the BitTorrent DHT, ntfy, MQTT brokers), so you do not have to run a signaling server.
The host decides which ones to use, and they only ever see an encrypted blob. They are used just for the first meeting: once the tunnel is connected, your traffic does not pass through them at all, it goes straight between the two devices.

## In the end

Strait connects device A to device B **peer to peer, with no server in the middle**. Traffic goes only between the two devices,
and A reaches the internet with B's IP address. If a direct connection is not possible, Strait says so with the reason instead of
quietly routing through a third party.

---

## Download

Get the latest build from the [Releases page](https://github.com/TheGreatDaniad/strait/releases/latest).

| System | File | Install |
|---|---|---|
| Ubuntu / Debian (Intel/AMD) | `strait_<version>_amd64.deb` | `sudo apt install ./strait_<version>_amd64.deb`, then open **Strait** from the menu |
| Ubuntu / Debian (ARM) | `strait_<version>_arm64.deb` | same, with the arm64 file |
| macOS (Apple silicon and Intel) | `strait-<version>-macos-universal.dmg` | open it, drag **Strait** to Applications, then right-click it and choose **Open** the first time (the app is not notarized) |
| Windows 10/11 (64-bit) | `strait-<version>-windows-x64.zip` | unzip, keep `Strait.exe` and `wintun.dll` together, double-click `Strait.exe` and accept the administrator prompt (choose **More info > Run anyway** if SmartScreen warns; the app is not code-signed) |
| Linux, other | `strait-<version>-linux-<arch>.tar.gz` | run `sudo ./nat-tunnel gui` |

`SHA256SUMS` lists every file's checksum. Sharing or using the full tunnel needs administrator rights; the app asks for them.
If the window cannot open (no usable graphics), Strait retries with OpenGL and then shows the reason instead of closing silently.

## Quick start

```bash
cd nat-tunnel
cargo run --release -- gui     # desktop app; the full tunnel needs admin/root
```

1. **Host:** open the Host tab, check connectivity, choose how to be found, press **Start sharing**, copy the invite.
2. **Client:** paste the invite on the Connect tab and press **Connect**.

## Principles

- Payload only travels between the two peers. There is no relay or TURN fallback, ever.
- The invite string is the capability: whoever holds it can connect.
- Failure is explicit, with a reason.
- Servers only help peers find each other. They see a sealed address blob, never your traffic or the key.

## What is here

| Path | What it is |
|---|---|
| `nat-tunnel/` | Rust core: CLI (`host`, `guest`, `check-host`, `rv-test`, `recover`), desktop GUI, rendezvous layer, transports, deploy scripts, docs. |
| `strait-mobile/` | React Native app (Android, iOS) over the same Rust library. |
| `nat-tunnel/docs/` | Design (`RENDEZVOUS_DESIGN.md`, `TUNNEL_CARRIERS.md`), plans and roadmap, and the visual design handoff. |

## How peers find each other

The host chooses the methods; nothing is on by default, and each one shows what it can see before you pick it: a UDP signal
server (`sig`), BitTorrent trackers (`trk`), Nostr relays, the Mainline DHT, ntfy, and public MQTT. Rooms are derived from the
invite key with HKDF, and only ChaCha20-Poly1305 sealed endpoints are published. See `nat-tunnel/docs/RENDEZVOUS_DESIGN.md`.

## Build and test

```bash
cd nat-tunnel
cargo build --release                      # CLI + GUI
cargo test --no-default-features --features cr-ss,cr-ws,cr-awg   # headless suite (some live-network tests are #[ignore])
cargo run --release -- check-host          # what NAT you are behind and who can reach you
```

The Shadowsocks, AmneziaWG-style and WebSocket transports are built in by default (`cr-ss`, `cr-awg`, `cr-ws`). Xray is an opt-in
build feature (`cr-xray`) because it needs the Xray program installed next to Strait.
Mobile: `cd strait-mobile && npm install && npx jest`. Device builds are in `strait-mobile/ios/README_DEVICE_TESTING.md`.
A packet-tunnel VPN on iOS needs a paid Apple Developer team.

## Test results (AWS NAT lab)

Measured on AWS, not an emulator: 16 "houses" in 3 regions (Linux arm64 and Windows Server 2022), each behind its own NAT and
controlled over SSM. Peers used public rendezvous only (trackers, Nostr, DHT, ntfy, MQTT), with no server of ours and no relay.
Tested build: the code released as v0.4.0.

NAT types in the lab:

| House | NAT | House | NAT |
|---|---|---|---|
| a | port-restricted (Linux masquerade) | e | address-restricted |
| b | AWS NAT Gateway (symmetric) | f | carrier-grade (two NATs, outer random) |
| c | symmetric (`random` masquerade) | g | UDP blocked (only 53/123) |
| d | full cone | h | public, no NAT |

Linux to Linux, UDP over trackers, ✅ = connects and moves data, ❌ = cannot connect (row = host, column = client):

| host \ client | a | b | c | d | e | f | g | h |
|---|---|---|---|---|---|---|---|---|
| a port-restricted | - | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| b symmetric | ✅ | - | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| c symmetric | ✅ | ❌ | - | ✅ | ✅ | ❌ | ❌ | ✅ |
| d full cone | ✅ | ✅ | ✅ | - | ✅ | ✅ | ❌ | ✅ |
| e address-restricted | ✅ | ✅ | ✅ | ✅ | - | ✅ | ❌ | ✅ |
| f carrier-grade | ✅ | ❌ | ❌ | ✅ | ✅ | - | ❌ | ✅ |
| h public | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ws only | - |

- Every pair that is possible without a relay passes, and nothing passes that should not. The only failures are both sides
  symmetric (b, c, f among themselves) and the UDP-blocked house g, which can only use `ws`, and only to a host with inbound TCP.
- Windows to Windows and Windows to Linux behave the same way (91 cross-OS pairs, 60 of 60 repeats for non-symmetric pairs).
- A port-restricted client reaching a symmetric host has to scan ports, which takes 5-59 s. The scan is rate-limited in stages
  (400, then 1500, then up to 4000 packets/s) so it cannot exhaust a small home router's NAT table.
- Throughput, same region: 360-447 Mbit/s; cross-region: 29-130 Mbit/s; 0 % UDP loss in every passing run.
- Transports `udp`, `ss`, `ws`, `awg` and `xray` work on Linux and Windows wherever the network allows them.
- Rendezvous join time: trackers, Nostr, ntfy 0.5-3 s; MQTT 1-5 s; DHT 8-14 s.
- Host on a real home connection (a Mac behind a consumer router, userspace exit): all 7 NAT types connected and moved data.

| Client NAT | First ping | Up / down (Mbit/s) |
|---|---|---|
| port-restricted | 1.0 s | 129 / 137 |
| full cone | 10.1 s | 97 / 128 |
| address-restricted | 4.1 s | 41 / 53 |
| public | 21.3 s | 48 / 52 |
| symmetric (gateway) | 3.2 s | 43 / 58 |
| symmetric (random) | 5.3 s | 32 / 37 |
| carrier-grade | 11.3 s | 24 / 37 |

**WebSocket without a reachable port** (version 0.4.1, two Linux peers behind port-restricted NATs in Frankfurt and Virginia,
the host's TCP port closed to outside connections):

| Case | Result |
|---|---|
| WebSocket only, both directions | ✅ 6 of 6, connected in 1.1 to 1.6 s, 0% loss, 47 to 77 Mbit/s |
| Client with all UDP blocked | ✅ 4 of 4, WebSocket picked automatically when every transport is allowed |
| Idle for 150 s, then traffic | ✅ same session, 0% loss |
| Symmetric NAT on either side | ❌ as expected: the router picks a new port per destination |

Not covered yet: Mac and Android as clients, IPv6, real mobile networks, real consumer routers under the port scan, and the
Windows userspace-exit crash seen in 5 of about 380 early jobs (it is contained, its trigger was never reproduced).

## Notes

- Example addresses use documentation ranges (`203.0.113.0/24`) and the example key `0123456789abcdef0123456789abcdef`.
  Generate your own key; never reuse an example.

## License

Licensed under the [Apache License 2.0](LICENSE). You may use, modify, fork and redistribute Strait, commercially or not.
Please keep the [NOTICE](NOTICE) file and the license text with any copy or fork: that is how credit is preserved.

## Disclaimer

Strait is experimental software. It is early work, has not been security-audited, and may contain bugs, flaws and security issues. It is provided **as is**, without warranty of any kind, as stated in the [license](LICENSE). **Use it at your own risk.** The authors are not liable for any damage, data loss, or other consequences of using it.

- **Hosting shares your IP.** When you host, the client's traffic reaches the internet from your connection and appears to come from your IP address. Only share with people you trust, and you stay responsible for what is done through it.
- **Follow the rules that apply to you.** Check your local laws and your internet provider's terms before sharing or using a connection.
- **It is not an anonymity tool.** Strait connects two devices directly, so the two peers see each other's IP addresses.
- **Don't rely on it for anything critical** while it is in this state.
