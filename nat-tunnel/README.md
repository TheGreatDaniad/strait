# nat-tunnel (Strait core)

The Rust core of Strait: a direct peer-to-peer tunnel between two devices behind NAT. There is no
relay of any kind: tunnel traffic only ever travels between the two peers, and a session that
cannot get a direct path fails instead of falling back to a third party.

See the [project README](../README.md) for what Strait does, downloads and test results.

| Part | Where |
|---|---|
| Join handshake (Noise `NKpsk0`, host key, personal invites, key rotation) | `src/tunnel/handshake.rs`, `src/tunnel/crypto.rs`, [docs/HANDSHAKE.md](docs/HANDSHAKE.md) |
| Transport, hole punching, multi-guest host | `src/transport.rs`, `src/birthday.rs` |
| Rendezvous (signed, sealed records; daily identifiers) | `src/rendezvous/`, [docs/RENDEZVOUS_DESIGN.md](docs/RENDEZVOUS_DESIGN.md) |
| Carriers (Shadowsocks, obfuscated UDP, WebSocket, Xray) | `src/carrier/`, [docs/TUNNEL_CARRIERS.md](docs/TUNNEL_CARRIERS.md) |
| Exit policy (what a guest may reach through the host) | `src/userspace.rs` |
| Invite format | `src/invite.rs` |
| Optional self-hosted signal server (`nat-tunnel signal`) | `src/relay.rs`: it introduces two devices by address and never carries traffic |
| Desktop app, CLI | `src/gui.rs`, `src/main.rs` |

```sh
cargo build --release
cargo test
nat-tunnel check-host          # what this network allows, and an invite for this device
nat-tunnel host --invite '<invite>' --tun 10.7.0.1/16 --userspace
nat-tunnel guest --invite '<invite>' --tun 10.7.0.2/24
```

Every invite names the host's key (`hk=`); `check-host` makes invites with this device's key.
