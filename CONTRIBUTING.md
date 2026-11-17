# Contributing to Strait

Thanks for helping. Bug reports, test results from real networks, and code are all welcome.

## Before you start

- Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Issues labelled **good first issue** are small and self-contained.

## The rules the design keeps

- Tunnel traffic only ever travels between the two peers. No relay, no TURN fallback.
- Public services only help two devices find each other, and only see sealed records.
- When something cannot work, Strait says why instead of silently falling back.

A change that breaks one of these will not be merged, however useful it is otherwise.

## Building and testing

The core is Rust (stable toolchain):

```bash
cd nat-tunnel
cargo build --release                 # CLI and desktop app
cargo test                            # unit and integration tests
cargo clippy --all-targets
```

Some tests need the live internet or root and are marked `#[ignore]`. The mobile app:

```bash
cd strait-mobile
npm install
npx jest
```

## Pull requests

- Keep each pull request to one change, with a test for new logic.
- Run `cargo test` before you push, and say in the description what you tested by hand (which OS,
  host or guest, which NAT if you know it).
- Write commit messages in the imperative ("Fix the retry after a refused join").
- Code comments explain why, not what.
- By contributing you agree that your work is licensed under the [Apache License 2.0](LICENSE).

## Reporting a bug

Use the bug report form. The most useful details are your OS, the Strait version, whether you
were the host or the guest, and the output of `nat-tunnel check-host` (it shows your NAT type).
Remove invites and keys from logs before posting them.
