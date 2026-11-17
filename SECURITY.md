# Security policy

Strait has not been audited. Reports about its security are very welcome, and the protocol and
cryptography matter most.

## Reporting a problem

Please report privately, not in a public issue:

1. Open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private
   vulnerability reporting).
2. Say what an attacker needs (nothing, the invite, a personal invite, a position on the network
   path, a process on the same computer, the host itself) and what they gain.
3. Add the version (`nat-tunnel --version`) or commit, and steps or a proof of concept if you have
   one.

You will get an answer in the advisory thread. Once a fix is released, the report is credited
unless you prefer otherwise.

## What is in scope

- The join handshake, host keys, personal invites and session encryption
  ([`nat-tunnel/docs/HANDSHAKE.md`](nat-tunnel/docs/HANDSHAKE.md),
  [`src/tunnel/`](nat-tunnel/src/tunnel), [`src/transport.rs`](nat-tunnel/src/transport.rs)).
  A symbolic model is in [`nat-tunnel/docs/proverif/`](nat-tunnel/docs/proverif).
- Rendezvous records: sealing, signatures, what each public service can see
  ([`src/rendezvous/`](nat-tunnel/src/rendezvous)).
- What a guest can reach through a host (the exit policy, [`src/userspace.rs`](nat-tunnel/src/userspace.rs)).
- The transports (Shadowsocks, obfuscated UDP, WebSocket/TLS, Xray) and their parsers
  ([`src/carrier/`](nat-tunnel/src/carrier)).
- Anything that runs as root or administrator: the privileged helper, routes, DNS, firewall and
  crash recovery ([`src/privileged.rs`](nat-tunnel/src/privileged.rs), [`src/tunmode.rs`](nat-tunnel/src/tunmode.rs)).
- The mobile apps ([`strait-mobile/`](strait-mobile)).

## Known limits

These are documented and not considered new findings: the list under "Not covered" in
[`HANDSHAKE.md`](nat-tunnel/docs/HANDSHAKE.md) (for example, no kill switch, and a host owner sees
its guests' traffic the way any VPN exit does).

Only the latest release gets security fixes.
