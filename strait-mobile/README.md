# Strait Mobile

React Native client/host for Strait, using the same design tokens and screens as
the desktop app.

## What is here

- `App.tsx`, `src/` — the Strait UI: header/status chip, Connect/Host/Settings
  tabs, route graphic, all idle/connecting/connected/failed/sharing states,
  connection history (last invite + 5 past), relay, kill-switch, IPv6, max
  clients and per-client bandwidth settings. State is persisted with
  AsyncStorage.
- `android/app/src/main/java/com/straitmobile/StraitVpnService.kt` — Android
  foreground service. Client mode establishes a `VpnService` TUN and passes its
  fd to the Rust tunnel. Host mode runs the userspace exit, so the phone does
  not need root or kernel NAT.
- `StraitModule.kt` — React Native bridge (`Strait.start/stop/getStatus`) plus the
  VPN permission activity flow.
- `android/app/src/main/jniLibs/arm64-v8a/libstrait.so` — the `nat-tunnel` Rust
  binary built for `aarch64-linux-android`. It is an executable packaged as a
  native library so Android extracts it with the right permissions.

## Build

```sh
cd strait-mobile
npm install
npx react-native-asset          # links the bundled Inter/Fraunces/JetBrains Mono fonts
cd android && ./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

The release build uses the debug keystore in this template; replace it before
shipping.

## Android tunnel details

Client command started by the service:

```
libstrait.so guest --relay HOST:PORT --room ROOM --key KEY \
  --tun 10.8.0.2/32 --tun-fd-socket @strait-<package>
```

`ProcessBuilder` does not reliably inherit arbitrary descriptors on Android,
so the service sends the VpnService fd over a Unix socket using SCM_RIGHTS.
The Rust side receives it with `recvmsg` and uses it as the TUN device.

Host command:

```
libstrait.so host --relay HOST:PORT --room ROOM --key KEY \
  --tun 10.8.0.1/24 --userspace [--max-clients N] [--rate-kbps K]
```

The VpnService routes public IPv4 space; RFC1918, loopback, link-local and
multicast stay local. DNS `1.1.1.1`/`8.8.8.8` goes through the tunnel.

## Status

- UI verified on a `Medium_Phone_API_36.1` emulator: all tabs and the idle/host
  screens render at phone size with the handoff fonts and colours.
- Android host mode starts the Rust userspace exit in a foreground service and
  pairs with a Windows client (`host userspace exit ready` in logcat).
- Windows client full tunnel was verified independently: HTTP 200 (31,719
  bytes), DNS, firewall on, route/DNS/IPv6 restore.
- Android client mode is verified end to end: VpnService fd passed over an
  abstract Unix socket (`@strait-<package>`) with `SCM_RIGHTS`, Rust logs
  `android tun fd up: 10.8.0.2/32`, the session reaches `guest tun session
  ready`, the UI shows Connected with live byte counters, and ICMP/traffic
  passes through the tunnel.
- iOS is not started. It needs a NetworkExtension provider and the Rust tunnel
  linked as a static framework (iOS cannot spawn a helper process like
  Android).

## Lab notes

- `STRAIT_EXIT_PROXY` is an env-gated host test hook: when set, outer TCP
  connections dial the proxy and send `target:port\n`. It exists to test a host
  and a client on the same machine without the client's VPN route capturing the
  host's own outbound socket. Production does not set it.
- If a host must log traffic for debugging, do not log invite keys; the host
  invite is intentionally masked in the UI and copied on demand.
