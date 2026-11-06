# Self-hosting Strait: host and (optional) signal server

Invariant: **there is no relay and no default server.** Strait payload always
goes peer to peer. A signal server only helps two peers find each other's
public UDP endpoint; if a direct path is impossible, the session fails with a
reason. Nobody ships a server for you, and the app has none built in.

You only need one if the host is behind NAT without a mapped port. A host with
a public or mapped endpoint needs no server at all.

## The host (what deploy.sh installs)

`deploy/deploy.sh` (run as root on the VPS) installs `strait-host.service`: the
multiplexed host, one UDP port (7100), many clients, started from the invite in
`/etc/strait/host.env` (0600). Default args:

```
nat-tunnel host --invite $STRAIT_INVITE --tun 10.7.0.1/16 --userspace --max-clients 8
```

`--userspace` terminates client TCP/UDP inside the process and re-dials it from
the VPS: no TUN device, no capabilities, no NAT rules. `--tun` only selects the
multiplexed mode (the address is forced to 10.7.0.1/16). Change the args with
`deploy.sh --host-args "..."` or by editing `STRAIT_HOST_ARGS` in host.env.
Because the exit dials arbitrary destinations, the host unit must not set
`IPAddressDeny`.

### TUN exit (opt-in)

Kernel routing instead of the userspace exit. In host.env:
`STRAIT_HOST_ARGS=--tun 10.7.0.1/16 --max-clients 8`. In the unit: uncomment
`CapabilityBoundingSet=CAP_NET_ADMIN`, `AmbientCapabilities=CAP_NET_ADMIN`,
`DeviceAllow=/dev/net/tun rw`, `DevicePolicy=closed`, the 3-family
`RestrictAddressFamilies` line (adds AF_NETLINK, used by `ip`) and set
`PrivateDevices=no`; the `ip` tool must be installed. The binary does not
enable forwarding or NAT:

```
sysctl -w net.ipv4.ip_forward=1        # persist in /etc/sysctl.d/99-strait.conf
nft add table ip strait
nft 'add chain ip strait post { type nat hook postrouting priority 100; }'
nft add rule ip strait post ip saddr 10.7.0.0/16 oifname "eth0" masquerade
```

(`eth0` = your uplink.) Untested on a real host.

### What guests can reach

The userspace exit (default) only dials public internet addresses. It refuses loopback, unspecified,
RFC1918, CGNAT 100.64/10, link-local (incl. 169.254.169.254), multicast, broadcast, 240/4 and the IPv6
equivalents (::1, fe80::/10, fc00::/7, ff00::/8, plus IPv4-mapped/compatible forms). `--allow-lan`
(or `STRAIT_ALLOW_LAN=1` / `NAT_TUNNEL_ALLOW_LAN=1` in host.env) opens the private/CGNAT/ULA ranges only;
loopback needs `STRAIT_EXIT_ALLOW_LOOPBACK=1` (labs, tests); link-local and multicast never open.
Not covered: the host's own public interface addresses.

The TUN exit has no such filter (packets go to the kernel). Add one yourself, before the masquerade rule:

```
nft add table inet strait_fw
nft 'add chain inet strait_fw fwd { type filter hook forward priority -10; policy accept; }'
nft add rule inet strait_fw fwd ip saddr 10.7.0.0/16 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
nft 'add chain inet strait_fw in { type filter hook input priority -10; policy accept; }'
nft add rule inet strait_fw in ip saddr 10.7.0.0/16 iifname != "lo" ip daddr != 10.7.0.1 drop   # host services
```

Adjust the `input` rule if guests should reach something on 10.7.0.1. Untested on a real host.

## The lab key

`0123456789abcdef0123456789abcdef` is a throwaway key used in lab runs (it is
in the project's `.env`). **Never use it for a real deployment**: deploy.sh
refuses a host.env containing it. `.env` must never be committed or shipped;
keep it in `.gitignore`.

## Rotating the key

`deploy.sh --rotate` generates a fresh 128-bit key, rewrites host.env, restarts
the host and prints the new invite. Every existing invite stops working;
redistribute the new one. A plain re-run keeps the current key.

## Verifying a deployment

Run `deploy/verify.sh` on the VPS (service active, UDP 7100 listening, host.env
0600, lab key absent, no `--relay`). Then connect a client with the printed
invite and check `journalctl -u strait-host` shows `client ... is 10.7.0.x`.
Before deploying, `deploy/selftest.sh` checks deploy.sh offline in a temp dir;
`deploy.sh --print-units` shows the exact units that would be installed.

## Signal server: what it is

One binary (`nat-tunnel`), no database, no accounts, state in memory only
(rooms expire after 45 s; restart loses only rendezvous).

```
nat-tunnel relay --port 7000      # subcommand is currently `relay`; a `signal` alias may be added
```

(The subcommand name is historical; the server has no DATA message and cannot
forward a datagram.)

## Run it

1. Build `nat-tunnel` for your server (`cargo build --release`).
2. Use `deploy/strait-signal.service` (hardened, DynamicUser, no capabilities):
   copy it to `/etc/systemd/system/`, then `systemctl enable --now strait-signal`.
   Or run `deploy/deploy.sh --with-signal` (installs it, does not enable it).
3. Open **UDP 7000** only: `ufw allow 7000/udp`.

## Rate limits

The server caps rooms and clients per room (1024), expires idle rooms and has
a per-IP limiter. Tune it with environment variables (`Environment=` lines in
the unit, commented examples are there): `STRAIT_SIGNAL_RATE` (PING msgs/s per
IP), `STRAIT_SIGNAL_BURST` (PING burst; REGISTER burst is 3x) and
`STRAIT_SIGNAL_EXPIRY` (seconds). Invalid values make the server refuse to
start. Defaults live in `src/relay.rs`. A firewall limiter in front is still
good defence in depth:

```
iptables -A INPUT -p udp --dport 7000 -m hashlimit --hashlimit-name strait \
  --hashlimit-above 20/second --hashlimit-mode srcip -j DROP
```

## What the server can and cannot see

- Sees: peer public IP:port, a room id (derived from the key), role, timing.
- Cannot: read, decrypt, or forward payload (AEAD end-to-end; no DATA message),
  or recover the key from the room id.
- Does not log peer identities. Keep it that way: do not add request logging.

## Use it

Put its `host:port` into the invite (the optional signal field,
`STRAIT2|<key>|<hosts>|<signals>`), or in the app under Settings, then
share the invite. A user can list several servers as fallbacks. The client
treats your server as just another endpoint, so it is replaceable at any time.
