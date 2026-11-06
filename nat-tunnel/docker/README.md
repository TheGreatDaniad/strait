# Docker end-to-end harness

This directory contains the container images and entrypoints used by
`scripts/e2e_docker.sh` to exercise the `relay` / `host` / `guest` CLI on a
simulated NAT topology.

## Topology

```
   net_a 172.28.1.0/24            net_b 172.28.2.0/24
     peer-a .2                        peer-b .2
        |                                |
  router-a .254                    router-b .254
        | wan 172.29.0.2                  | wan 172.30.0.2
        |                                  |
        +-------- internet (L3) -----------+
           172.29.0.254 | 172.30.0.254
                         |
                    public 172.31.0.0/24
                    relay 172.31.0.2
```

* `internet` is a plain L3 forwarder with three links and no NAT. It exists so
  WAN packets must make a real routing hop: Docker's own bridges can otherwise
  short-circuit traffic between two WAN interfaces.
* `router-a` and `router-b` are two independent NAT boxes. Each translates its
  LAN 1:1 onto the WAN with `NETMAP` (host part preserved, source port also
  preserved), so both peers get distinct public addresses and a direct hole
  punch is actually possible. Plain Linux `MASQUERADE` is endpoint-dependent
  (symmetric) and would always force the relay path.
* `relay` runs `nat-tunnel relay --port 7000` on the public network.
* `peer-a` runs a local Python HTTP server and `nat-tunnel host`.
* `peer-b` runs `nat-tunnel guest` (TCP listener on `127.0.0.1:8080`, or a TUN
  interface when `TUN=1`).

The relay is a rendezvous/forwarding server. It only ever handles encrypted
datagrams: the room key (`--key`) stays with the peers, so the relay sees
**ciphertext only**.

## Run everything

```sh
./scripts/e2e_docker.sh
```

The script builds `nat-tunnel:dev`, runs the four scenarios below, prints a
PASS/FAIL line per scenario, and tears the stack down. Each scenario checks the
small HTTP body (`nat-tunnel-e2e-ok`) and a 64 KiB `/big.bin` download verified
with `sha256sum`, which forces many ARQ frames and retransmissions.

## Run a scenario manually

Build once:

```sh
docker build -f docker/Dockerfile -t nat-tunnel:dev .
```

### 1. Direct path (TCP mode)

```sh
docker compose up -d internet router-a router-b relay peer-a peer-b

# Wait until the guest listener is up.
until docker compose exec -T peer-b sh -c "ss -ltn | grep -q ':8080 '"; do sleep 1; done

docker compose exec -T peer-b curl -sS --max-time 15 http://127.0.0.1:8080/
# -> nat-tunnel-e2e-ok
docker compose exec -T peer-b sh -c 'curl -sS http://127.0.0.1:8080/big.bin | sha256sum'

docker compose logs --no-color peer-a   # should show "session ready (direct)"
docker compose down -v --remove-orphans
```

### 2. Full tunnel (TUN + default route)

`TUN=1` makes peer-a an exit node with a TUN interface and peer-b a TUN client
whose default route points at it. `172.28.1.2` (peer-a's private LAN address)
has no route from peer-b without the tunnel, so a successful fetch proves the
default path really moved.

```sh
TUN=1 docker compose up -d internet router-a router-b relay peer-a peer-b

# The guest retries until the tunnel session is up.
docker compose exec -T peer-b ip route get 1.1.1.1
# -> 1.1.1.1 via 10.7.0.1 dev nat0 src 10.7.0.2

docker compose exec -T peer-b curl -sS --max-time 30 http://172.28.1.2:8000/
# -> nat-tunnel-e2e-ok
docker compose exec -T peer-b sh -c 'curl -sS --max-time 60 http://172.28.1.2:8000/big.bin | sha256sum'

docker compose logs --no-color peer-a   # "host tun session ready (...)"
docker compose down -v --remove-orphans
```

The tunnel socket is marked `fwmark 1`; the client routes marked traffic with
table 100 through the physical gateway, otherwise the encrypted UDP packets
would be routed back into the TUN and loop.

The scenario also asserts there are no leaks:

* `1.1.1.1` and `8.8.8.8` both resolve to `dev nat0`;
* the origin's HTTP log shows the client as `10.7.0.2`, not the guest's LAN
  address;
* `ip -6 route show default` has no routable default (IPv6 is made
  `unreachable`, since the tunnel is IPv4-only);
* while transferring 64 KiB, a capture on `eth0` contains no TCP, DNS, QUIC or
  ICMP echo. ICMP unreachable/redirect about the tunnel's own UDP socket is
  kernel signalling and is excluded.

### 3. Relay fallback

Drop direct traffic between the two peer public addresses so only the relay can
carry packets:

```sh
BLOCK_DIRECT=1 docker compose up -d internet router-a router-b relay peer-a peer-b

until docker compose exec -T peer-b sh -c "ss -ltn | grep -q ':8080 '"; do sleep 1; done

docker compose exec -T peer-b curl -sS --max-time 15 http://127.0.0.1:8080/
docker compose logs --no-color peer-a   # should show "session ready (relayed)"

docker compose down -v --remove-orphans
```

### 4. Lossy WAN

Add 40 ms of latency and 5% packet loss on `router-a`'s WAN interface, then
allow a longer timeout for retransmissions:

```sh
DELAY_MS=40 LOSS_PCT=5 docker compose up -d internet router-a router-b relay peer-a peer-b

until docker compose exec -T peer-b sh -c "ss -ltn | grep -q ':8080 '"; do sleep 1; done

docker compose exec -T peer-b curl -sS --max-time 30 http://127.0.0.1:8080/
docker compose exec -T peer-b sh -c 'curl -sS --max-time 30 http://127.0.0.1:8080/big.bin | sha256sum'

docker compose down -v --remove-orphans
```

## Inspecting

```sh
docker compose logs --no-color
docker compose exec -T router-a iptables -t nat -S
docker compose exec -T internet ip route
docker compose exec -T router-a iptables -S FORWARD
docker compose exec -T router-a tc qdisc show
docker compose exec -T peer-b ip rule
docker compose exec -T peer-b ip route show table 100
docker compose exec -T relay env
```

With `RUST_LOG=info` (already set for `relay`, `peer-a`, `peer-b`) the peer logs
report whether the data path is direct/hole-punched or relayed. The direct and
fallback scenarios assert this log line as well as the transferred bytes.

## Notes

* Every container gets a static address and a default route through its router.
  The peers are privileged because TUN mode creates an interface and rewrites
  routes; the routers need forwarding and NAT.
* `guest` in TCP mode handles one connection at a time, and each connection is
  a fresh tunnel session (hole punch + possible 4 s fallback window). The
  readiness check looks at the listening socket with `ss` so it does not
  consume a session.
* Only the two tunnel endpoints (`172.29.0.2/32`, `172.31.0.2/32`) are kept on
  the physical path; everything else follows the tunnel. The direct path in
  this Docker-Desktop lab can be forwarded by the host bridge, which is why the
  peer logs sometimes show ICMP redirects; that is lab plumbing, not a leak.
* `DELAY_MS`, `LOSS_PCT`, `BLOCK_DIRECT` and `TUN` are read from the
  environment by `docker compose` and passed to the entrypoints. Impairment is
  applied on `router-a` only.
* All scenarios are safe to rerun; the script always runs
  `docker compose down -v --remove-orphans` on exit.
