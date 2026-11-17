# Architecture

Strait connects two devices directly. Third-party services are used only to introduce the two
devices to each other (rendezvous); tunnel traffic never goes through anyone else.

```text
app (GUI / CLI / mobile)
  -> invite                 key, host key (hk), endpoints, rendezvous methods, carriers
  -> rendezvous             sealed records, host records signed with the host key
  -> hole punch             UDP (and TCP for the WebSocket carrier), port prediction
  -> join handshake         Noise NKpsk0: invite key as psk, host key authenticates the host
  -> session crypto         ChaCha20-Poly1305, replay window, keys rotated every 120 s
  -> carrier                plain UDP, Shadowsocks-2022, obfuscated UDP, WebSocket/TLS, Xray
  -> exit (host)            userspace TCP/UDP exit or kernel TUN, one policy for both
```

- Host: one port, many guests, each with its own session, address (10.7.0.0/16) and rate limit.
- Guest: a TUN device with the tunnel as default route while connected, or a TCP forward.
- Exit policy: a guest reaches the internet only; never the host itself, its LAN, its router,
  other guests, IPv6 destinations or TCP port 25.

Details: [docs/HANDSHAKE.md](docs/HANDSHAKE.md), [docs/RENDEZVOUS_DESIGN.md](docs/RENDEZVOUS_DESIGN.md),
[docs/TUNNEL_CARRIERS.md](docs/TUNNEL_CARRIERS.md).
