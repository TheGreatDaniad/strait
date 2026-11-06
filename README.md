<img src="nat-tunnel/assets/logo/strait-logo-tile.png" alt="Strait logo" width="88" align="left">

# Strait

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
- AmneziaWG (obfuscated WireGuard)
- WebSocket over TLS
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
cargo test --no-default-features           # headless suite (some live-network tests are #[ignore])
cargo run --release -- check-host          # what NAT you are behind and who can reach you
```

The Shadowsocks, AmneziaWG, WebSocket and Xray transports are opt-in build features (`cr-ss`, `cr-awg`, `cr-ws`, `cr-xray`).
Mobile: `cd strait-mobile && npm install && npx jest`. Device builds are in `strait-mobile/ios/README_DEVICE_TESTING.md`.
A packet-tunnel VPN on iOS needs a paid Apple Developer team.

## Status

Alpha. Verified on macOS, Windows 11 ARM and Android (emulator) against a real internet host, over every rendezvous method.
iOS runs in the simulator; the system VPN is untested on a device. Some network combinations (for example both peers behind
symmetric NAT) cannot connect directly, and the app says so instead of falling back to a relay.

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
