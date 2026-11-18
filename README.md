<p align="center">
  <img src="docs/assets/banner.svg" alt="mousse-net: the open networking engine for Mousse" width="100%">
</p>

# mousse-net

**The open networking engine for [Mousse](https://github.com/mousse-agent/mousse).**

[![CI](https://github.com/mousse-agent/mousse-net/actions/workflows/ci.yml/badge.svg)](https://github.com/mousse-agent/mousse-net/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Mousse is an app for working with AI agents across your computers and phones. `mousse-net` is the Rust engine that connects those devices: it owns device identity, pairing, host grants, the encrypted session, multiplexing and path choice.

Devices pair in person with a QR code, or with a send link and a 6-digit code (CPace). Sessions are TLS 1.3, with post-quantum hybrid key exchange on native targets, on short-lived session certificates signed by each device's identity key. Connections run over the local network, your own routes (Tailscale, SSH, a port forward, a tunnel) or a relay anyone can run.

## Status

Early. Phase 0 is in progress: the engine core, the simulator and the owner test kit. The engine is not yet used by the app, and wire formats may still change.

## What's here

| Path | What it is |
|---|---|
| [`crates/mousse-net-core`](crates/mousse-net-core) | State machines for identity, pairing, grants, session and mux. No I/O; builds for wasm32. |
| [`crates/mousse-net-io`](crates/mousse-net-io) | tokio adapters: TLS sessions, pipes, the session driver, keystores and discovery. |
| [`crates/mousse-sim`](crates/mousse-sim) | Seeded, deterministic simulator. Every drill replays from a seed. |
| [`crates/mousse-helper`](crates/mousse-helper) | Desktop helper and CLI: pairing, grants and terminal channels. |
| [`crates/mousse-check`](crates/mousse-check) | Owner test kit. Every check ships with a broken build that must fail. |
| [`spec/`](spec/) | The wire spec, test vectors, threat model and privacy notes. |
| [`checks/`](checks/) | Check manifests and signed results from devices. |
| [`interop/`](interop/) | A second implementation written from the spec alone. |
| [`docs/`](docs/) | The design and the phase plan. |

## Build and test

Needs Rust 1.96 and the `wasm32-unknown-unknown` target.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo check -p mousse-net-core --target wasm32-unknown-unknown
```

The core's tests also run on wasm32 under Node, with `wasm-bindgen-test-runner`
0.2.130 (from `wasm-bindgen-cli`, the same version as wasm-bindgen) on `PATH`:

```sh
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p mousse-net-core --target wasm32-unknown-unknown
```

Run the Phase 0 checks and their must-fail controls:

```sh
cargo run -p mousse-check -- phase0
```

## Read more

- [Design and phases](docs/PLAN.md)
- [Specification](spec/README.md): wire format, CPace, vectors, threat model, privacy
- [Owner checks](checks/README.md)
- [Contributing notes](AGENTS.md)

## License

[MIT](LICENSE)
