# NAT Tunnel

A cross-platform 1:1 NAT traversal tunnel with Anydesk-like remote access:
two peers behind separate NATs reach each other directly by hole punching, fall
back to a rendezvous relay when the NATs refuse, and can carry either one TCP
service or a full IP tunnel.

## What is actually implemented

| Piece | State |
| --- | --- |
| STUN client (public mapping discovery) | working, unit-tested |
| TURN `Allocate` / `Refresh` (minimal) | working but **no `MESSAGE-INTEGRITY`**, so authenticated servers answer 401 |
| Rendezvous + relay UDP server | working, ciphertext only |
| UDP hole punching with simultaneous send | working (`direct`) |
| Relay fallback for symmetric NAT / blocked paths | working (`relayed`) |
| Per-datagram authenticated encryption | ChaCha20-Poly1305, key = SHA-256(PSK), replay guard |
| Reliable stream over UDP | stop-and-wait ARQ, 1 KiB payload, retransmit on timeout |
| TCP forwarding (`host` / `guest`) | working, one connection per session |
| **TUN full tunnel** | verified on Linux (default route + leak checks) and on macOS (`utun` against a Linux peer, scoped route); Windows (Wintun) is implemented and cross-checks for ARM64/x86_64, runtime test pending |
| WireGuard config rendering / validation | working, **config only**, no kernel TUN and no WG crypto |
| NAT classification, network simulation, TUI | library code, unit-tested, not on the runtime path |

## Two forwarding modes

**TCP mode** — expose one local service:

```sh
# host side (exit node)
nat-tunnel host --relay 203.0.113.5:7000 --room demo --key s3cret \
                --forward 127.0.0.1:8000

# guest side
nat-tunnel guest --relay 203.0.113.5:7000 --room demo --key s3cret \
                 --listen 127.0.0.1:8080
```

**Full tunnel (TUN)** — carry IP packets and move the default route:

```sh
# exit node (needs root; enable ip_forward + NAT if traffic should reach the internet)
sudo nat-tunnel host --relay 203.0.113.5:7000 --room demo --key s3cret \
                     --tun 10.7.0.1/24 --max-clients 4

# client: default route now points at the peer
sudo nat-tunnel guest --relay 203.0.113.5:7000 --room demo --key s3cret \
                      --tun 10.7.0.2/24 \
                      --tun-default-route 10.7.0.1 \
                      --tun-bypass 203.0.113.0/24
```

The tunnel's own UDP socket carries `fwmark 1`; the client puts marked traffic
in a separate table that still points at the physical gateway. Without that,
encrypted packets would follow the new default route into the TUN and loop.
`--tun-bypass` covers the endpoints the tunnel itself must reach (use `/32`s).

Leak behaviour in full-tunnel mode:

* the default route and every non-bypassed destination resolve to the TUN;
* the tunnel's own encrypted UDP is the only traffic allowed on the physical
  interface; application TCP/UDP/ICMP is not;
* **IPv6 fails closed**: a `default unreachable` route is installed, because the
  tunnel is IPv4-only and a working IPv6 default would silently bypass it;
* bypass entries are per-endpoint (`/32`), not whole networks.

## Terminal UI (architecture phase 7)

```sh
# one dashboard per side; each starts its session automatically
nat-tunnel ui --role host  --relay 203.0.113.5:7000 --room demo --key s3cret \
              --forward 127.0.0.1:8000

nat-tunnel ui --role guest --relay 203.0.113.5:7000 --room demo --key s3cret \
              --listen 127.0.0.1:8080
```

It shows role, relay, room, path (direct/relayed), peer, sent/received bytes,
uptime, the peer list, and a log of session events. Keys: `s` start,
`x` stop, `q` quit. TUN mode works the same way (`--tun ADDR/PREFIX`,
`--tun-default-route`, `--tun-bypass`).

### Desktop UI (architecture phase 8)

```sh
sudo nat-tunnel gui     # TUN needs administrator access
```

Compact window with three tabs:

**Connect** — paste `relay:port|room|key` and press Connect, or tick
*Enter details manually* to fill relay / room / key. Everything else is
automatic: TUN `10.7.0.2/24`, default route via `10.7.0.1`, the relay kept on
the physical path, IPv6 blocked. All IPv4 traffic leaves through the host.

**Host** — relay, room and password fields; leaving room/password blank
generates them on start. **Max clients** (1–8) is enforced physically: each
client gets its own tunnel lane, room and `10.7.<n>.0/24`, so no more than that
number can connect. *Start hosting* brings up the exit node and shows one
ready-to-paste connection string per client, plus the shared password, each
with a Copy button. The password is random per session unless a permanent one
is set in Settings. Internet egress from clients also needs IP forwarding and
NAT on the host.

The connection string is `relay:port|room|key` for the first lane and
`relay:port|room|key|gateway` for the others (the gateway is what the client
must use, e.g. `10.7.1.1`).

**Settings** — default relay, permanent host password (saved with `0600` in
`~/Library/Application Support/nat-tunnel/gui.json` on macOS), theme, and the
tunnel profile list. **WireGuard is currently the only profile listed**; the
data path still uses the built-in ChaCha20-Poly1305 tunnel, while the WireGuard
module only renders configuration.

## Mobile (planned, React Native)

The app is **React Native** for both Android and iOS. The UI and shared state
(connect, host, settings, history) are TypeScript; the VPN and packet paths
stay native (Kotlin `VpnService`, Swift `NEPacketTunnelProvider`) and call the
Rust core. Clients use the OS VPN API with a raw-IP tunnel; **tun2socks is not
needed** for IP-mode tunnels. Phone-as-exit uses a userspace stream exit with
our own native stream framing (SOCKS5 optional), because mobile OSes cannot
NAT. See [`docs/MOBILE_PLAN.md`](docs/MOBILE_PLAN.md) and
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the decisions, milestones and the
honest platform limits (iOS host is foreground-only/experimental).

## Windows

Windows support uses the `tun` crate's Wintun backend. The code compiles for
`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`; it has not yet run on
a Windows machine. On Windows the client:

* creates a Wintun adapter with MTU 1400 and interface metric 1;
* installs the tunnel default route with route metric 1 and bypass routes for
  the relay/LAN on the physical interface;
* pins the tunnel UDP socket with `IP_UNICAST_IF` so it keeps using the
  physical path;
* captures DNS with `Get-DnsClientServerAddress` and restores it on stop;
* disables the physical adapter's `ms_tcpip6` binding and restores it.

Build (on Windows, elevated PowerShell):

```powershell
# ARM64 GUI build + wintun.dll beside the executable
.\scripts\windows-build.ps1 -Target aarch64-pc-windows-msvc

# Headless CLI/TUI build for a server or the VM
.\scripts\windows-build.ps1 -Target aarch64-pc-windows-msvc -Headless
```

Run `nat-tunnel.exe gui` as Administrator. `wintun.dll` must be next to the
executable (the script copies it) or in the working directory. The validation
steps and the VM lab layout are in
[`docs/WINDOWS_TEST.md`](docs/WINDOWS_TEST.md).

## Data path

```
peer A ── UDP ──┐                        ┌── UDP ── peer B
                ├── relay (rendezvous) ──┤
                └── direct (punched) ────┘
```

1. Both peers register in a room on the relay.
2. The relay tells each peer the other's public address.
3. Both send at the same time to open their NAT bindings.
4. If a direct datagram authenticates, the peers use it; every frame is also
   sent through the relay so a blocked or lossy direct path still delivers.
   The ARQ layer deduplicates the copies.
5. The relay only forwards opaque ciphertext. It never sees the room key.

The source address of a direct datagram is not trusted: the AEAD tag is what
authenticates the peer, and the working return address is learned from the
packets that actually arrive. This also covers NATs that rewrite the source
address in one direction.

Every datagram carries a session id covered by the AEAD tag. When a peer
restarts, its larger id tells the other side to reset its replay window and ARQ
state, so a fresh session is not mistaken for replayed datagrams.

## Tests

```sh
cargo build
cargo test                 # 28 unit + 2 loopback E2E + 6 integration
./scripts/e2e_docker.sh    # two-NAT Docker lab, 4 scenarios
```

The Docker lab (`docker/README.md`) runs two independent port-preserving
(NETMAP) NAT routers behind a separate L3 transit hop and checks real bytes —
a small HTTP body plus a 64 KiB download verified with `sha256sum`:

1. `direct` — hole punch must be used
2. `full-tunnel` — TUN mode: `1.1.1.1` and `8.8.8.8` both route via the tunnel,
   the origin sees the client as `10.7.0.2`, a peer-LAN-only service is fetched
   through the tunnel, IPv6 has no routable default, and a packet capture shows
   no TCP/DNS/QUIC/ICMP-echo on the physical interface during a transfer
3. `relay-fallback` — direct forwarding dropped, relay carries the traffic
4. `lossy` — 40 ms delay and 5% loss on the WAN

The max-clients limit has its own test: `scripts/e2e_multi_client.sh` starts a
host with two lanes and three clients. Clients 1 and 2 must fetch the host's
private service; client 3 must be rejected (no lane to join). That test forces
the relay path, because the lab's extra-host NETMAP can mis-learn a direct peer;
direct forwarding is covered by `scripts/e2e_docker.sh`.

## Tunnel carriers (how the sealed frames travel)

Plain UDP is the default and behaves exactly as before. A host can additionally serve other
carriers on their own ports, and the invite lists them so the guest can fall back when UDP is
blocked. Carriers move opaque, already-sealed frames: the end-to-end encryption is unchanged and
every secret a carrier needs derives from the invite key (nothing secret is ever in the invite).

```
nat-tunnel host --tun 10.7.0.1/16 --carrier ss@0.0.0.0:7201 --carrier ws@0.0.0.0:8443 ...
nat-tunnel host --invite 'STRAIT2|...' --carriers-from-invite     # listen on the invite's carrier ports
nat-tunnel host ... --no-udp                                     # serve the carriers only
nat-tunnel guest --invite '...' --carrier-disable ss,ws          # never use these (or NAT_TUNNEL_CARRIER_DISABLE)
nat-tunnel check-host --carriers ss,xray                         # also probe carriers
nat-tunnel carrier-test [--carriers ids] [--explain] [--endpoint host:port]
```

* Invite field: `STRAIT2|key|hosts|signals|room|rv|cr`, `cr` = comma list of `id[@host:port][;k=v]`
  with `%XX` escapes, at most 8, ids `udp ss ws awg xray`. Allowed parameters: ws `path`,`sni`;
  xray `sni`,`mode`,`port`; ss and awg none. Unknown ids are kept and ignored. `udp` is implicit.
* Environment: `NAT_TUNNEL_CARRIERS` (host list), `NAT_TUNNEL_CARRIER_DISABLE`,
  `NAT_TUNNEL_XRAY_BIN`, `NAT_TUNNEL_XRAY_SHA256` (local only, never in an invite).
* The guest tries the carriers in the host's order, staggered by 300 ms, the first sealed ACCEPT
  wins, and the winner is remembered in `last_carrier` next to the GUI settings (an id, no secret).
  If all fail: `Could not connect with any of the ways listed in the invite: udp: no punch; ws: blocked.`
* The TUN MTU follows the smallest carrier (1400 for UDP, 1379 for ss, lower for awg and xray).
  Frames a carrier refuses are counted and logged, never dropped silently.
* Only the full-tunnel (`--tun`) mode uses non-UDP carriers. STUN, signal servers and rendezvous
  stay on the plain UDP carrier.

## Rendezvous methods (how a NATed host is found)

A host behind a cone NAT cannot publish an address by itself. It chooses which services carry the
few bytes two peers need to exchange (their endpoints); nothing is used unless named. The invite
lists the choice and the client tries every listed method it can reach. Payload never touches
these services.

```sh
# what each method shares, and whether this network reaches it (publishes nothing)
nat-tunnel rv-test --explain
nat-tunnel rv-test --methods trk,nostr
nat-tunnel rv-test --methods trk,nostr --json    # [{id,status,rtt_ms?,detail?}] (used by the phone app)

# probe the chosen methods as part of the host check; the invite then lists them
nat-tunnel check-host --rendezvous trk,nostr,dht --json   # adds a `rendezvous` array

# host: choose methods (sig needs --signal or an invite that lists a signal server);
# without --rendezvous, the methods listed in --invite are used
nat-tunnel host --rendezvous trk,nostr --tun 10.7.0.1/24 ...

# guest: never use these methods, even if the invite lists them
nat-tunnel guest --invite 'STRAIT2|...' --rv-disable mqtt,ntfy
```

Ids: `sig` (your signal server), `trk` (BitTorrent trackers), `nostr`, `dht` (Mainline DHT),
`ntfy`, `mqtt` (public brokers, test-grade). `check-host` reports method `rendezvous` when no
public or mapped endpoint exists but a chosen method is reachable. The desktop app shows the same
choice on the Host tab, with each method's disclosure.

## Limits (honest)

- TUN mode is verified on **Linux** end to end: default route, IPv6
  fail-closed, and packet-capture leak checks.
- On **macOS**, `scripts/mac_tun_e2e.sh` has been run successfully: a real
  `utun` interface carried traffic to a Linux peer and back, with the default
  route untouched. It uses a scoped `/32` route, so it proves the macOS TUN
  data path, not the macOS all-traffic default-route mode (which is implemented
  with `IP_BOUND_IF` + an IPv6 blackhole but is not exercised by that script).
- **Windows** builds and cross-checks for ARM64/x86_64, but runtime validation
  is still pending the Windows 11 ARM VM. Wintun requires Administrator.
- TUN mode needs root/admin to create the interface and change routes.
- TURN lacks `MESSAGE-INTEGRITY`; WireGuard is config-render-only.
- TCP-forward mode uses a reliable ARQ with a congestion window; TUN mode
  sends raw sealed datagrams (WireGuard-style) and lets the inner TCP handle
  loss. TUN throughput is therefore bounded by what TCP achieves on the path;
  hiding loss from it again (ARQ) caused double retransmissions and head-of-line
  blocking.
- Measured on a real ~50 Mbps path: TCP-forward ~6.1 MB/s, TUN ~2.4 MB/s
  (the path's own TCP baseline was 2.27 MB/s).
- TUN MTU is 1400; packets larger than the frame payload are fragmented and
  reassembled in order.
- The relay can observe traffic volume and endpoints, but only ciphertext
  content.

## License

MIT
