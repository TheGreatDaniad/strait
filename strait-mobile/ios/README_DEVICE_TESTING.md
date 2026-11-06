# Testing Strait on a physical iPhone

Simulator builds cannot run a Network Extension packet tunnel, so the VPN path is only provable on a device.
This lists what must be ready and a 5 minute test.

## Must have ready

| Item | Detail | How to check |
| --- | --- | --- |
| Apple Developer Program membership (paid, USD 99/yr) | **A free personal team cannot use the Network Extension "Packet Tunnel" entitlement or create the needed provisioning profile.** An organization or individual paid membership works. | developer.apple.com/account > Membership details shows "Apple Developer Program". In Xcode > Settings > Accounts the team must not be labelled "Personal Team". |
| Team ID | 10 characters, e.g. `ABCDE12345` | Membership details page, or Xcode > Settings > Accounts > team |
| Bundle id base | A reverse-DNS prefix you own, e.g. `com.yourname.strait`. App = `<base>`, extension = `<base>.PacketTunnel`, app group = `group.<base>` | You choose it; one variable, `STRAIT_BUNDLE_BASE` |
| iPhone | iOS 15+, **Developer Mode on** (Settings > Privacy & Security > Developer Mode, restart), cable connected, unlocked, "Trust This Computer" accepted | `xcrun devicectl list devices` shows it connected |
| Mac | Xcode with the iOS platform, CocoaPods, Rust with the iOS targets, >= 8 GB free disk | `df -h /System/Volumes/Data` |

## One-time setup (minimal edits)

Edit only `ios/Signing.xcconfig`:

```
DEVELOPMENT_TEAM = ABCDE12345
STRAIT_BUNDLE_BASE = com.yourname.strait
```

Bundle ids, both entitlement files' app group and the Swift constants all derive from `STRAIT_BUNDLE_BASE`
(through an Info.plist key); nothing else is hardcoded.

```sh
cd strait-mobile && npm install && npx react-native-asset
ios/build-rust.sh                  # libstrait_ios.a -> Strait.xcframework (use CARGO_TARGET_DIR to relocate)
cd ios && pod install
```

## Xcode steps (GUI path)

1. `open ios/StraitMobile.xcworkspace`.
2. Select target **StraitMobile** > Signing & Capabilities: Team = your team (Automatic signing).
   Confirm capabilities **Network Extensions (Packet Tunnel)** and **App Groups** (`group.<base>`) are present.
3. Same for target **StraitPacketTunnel** (same two capabilities, same group).
4. Choose your iPhone as the run destination, press Run. On the phone, trust the developer profile if asked
   (Settings > General > VPN & Device Management).
5. On first Connect iOS shows "Add VPN Configurations": allow it (passcode).

Or from the terminal: `DEVELOPMENT_TEAM=ABCDE12345 ios/device-test.sh` (builds, installs with `xcrun devicectl`,
launches with console, mirrors `idevicesyslog` into `ios/build/device-syslog.txt` if installed).

## 5 minute test script

1. Open the app > Connect, paste `STRAIT2|0123456789abcdef0123456789abcdef|203.0.113.10:7100`, tap Connect.
   Expect: Connecting, then Connected, VPN key icon in the status bar.
2. Egress: if the app shows the public IP seen through the tunnel, expect `203.0.113.10`.
   Cross-check in Safari: `http://1.1.1.1/cdn-cgi/trace` shows `ip=203.0.113.10`.
3. Ping: from the Mac `ping` is not possible to the phone; instead load a page, and check the app's byte counters rise.
4. Disconnect. On the VPS: `journalctl -u <strait service> -n 20` shows `left: client left`; the slot is free
   (reconnect once to confirm it is accepted again).
5. Rendezvous-only invite: run `nat-tunnel check-host --rendezvous trk --json` on the VPS or a host, remove the
   host field (third `|` field, leave it empty) and paste that invite; it must connect via the listed method.
6. If anything fails: Settings app log, `ios/build/device-syslog.txt`, and Console.app (select the iPhone, filter
   `process:PacketTunnel`).

## What this does not prove / known gaps



## What the automated tests already cover (so the device test can be short)

Verified on the Mac (no iPhone):

- `cargo test --no-default-features --features ffi --test ffi_harness -- --test-threads=1`: drives the C ABI exactly as Swift does,
  with a datagram socketpair carrying the 4-byte AF header standing in for the utun. Against a local `nat-tunnel host --userspace`:
  connecting then connected, assigned `10.7.0.x`, a packet round trip through the tunnel, both fd paths (fd passed to start, and
  fd delivered after the address is known via `needTun` + `strait_client_set_fd`), `strait_client_stop` within 2 s, host logs `left:`.
- Same test with `-- --ignored live_vps`: connects to the real VPS invite (direct path), and the VPS journal shows
  `joined as 10.7.0.2` then `left: client left`.
- `ios/build-rust.sh` builds all five rendezvous methods for device and simulator; a C program linked against the XCFramework
  runs on the iOS Simulator (`strait_version`, `strait_generate_key`). The app and the StraitPacketTunnel extension compile for the Simulator.

Only a device can prove: the NetworkExtension entitlement and provisioning, `setTunnelNetworkSettings`, finding the real utun fd,
real routing/DNS (egress IP), and the Connect / Disconnect UX.

## Notes the first device run depends on

- **Free Apple ID cannot do this.** The packet-tunnel entitlement is only granted to a paid Apple Developer Program team.
- **App Group + entitlements**: both targets carry `com.apple.developer.networking.networkextension = packet-tunnel-provider` and the
  app group `group.<STRAIT_BUNDLE_BASE>`; the extension's bundle id must be `<base>.PacketTunnel`.
- **The invite reaches the extension** through `startVPNTunnel(options:)` (not persisted), with `providerConfiguration` and the app
  group as fallbacks.
- **utun fd lookup is not public API.** `PacketTunnelProvider.utunFd()` scans our own fds with
  `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)` (as WireGuard-apple does) and falls back to KVC `packetFlow.socket.fileDescriptor`.
  If both fail ("Could not find the utun file descriptor" in the app, `process:PacketTunnel` in Console.app), the fallback is:
  create `socketpair(AF_UNIX, SOCK_DGRAM)`, give one end to `strait_client_set_fd`, and in Swift pump
  `packetFlow.readPackets` -> write `[0,0,0,AF] + packet` to the other end, and read the other end -> `packetFlow.writePackets`
  (AF = 2 for IPv4). The Rust side already expects exactly that framing, so no Rust change is needed.
- **includeAllNetworks** is set from the app's kill-switch option (default on) with `excludeLocalNetworks`. If the tunnel connects but
  nothing loads, retry once with it off (the killSwitch start option) to rule it out.
- Host mode is rejected on iOS ("host mode is not supported on iOS yet"): client only.
- Metro: the Debug build loads JS from `http://localhost:8081` on the Simulator; on a real iPhone use a Release build or point it at your Mac.
