# Contributing notes

- Design and phases: `docs/PLAN.md`. Wire spec and test vectors: `spec/`. The spec is normative; code follows it.
- `crates/mousse-net-core` does no I/O. Randomness and time are passed in, so `mousse-sim` can replay any run from a seed. It must build for `wasm32-unknown-unknown`.
- Crypto dependencies are pinned with `=`. Parsing of untrusted input returns typed errors; no `unwrap()` on it. Secrets are zeroized and never logged.
- Every security check in `mousse-check` ships with a must-fail control. A test must be able to fail.
- Search with `rg`.
- Before a PR: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and `cargo check -p mousse-net-core --target wasm32-unknown-unknown`.
- PRs and issues: say what changed and the result, in plain words, for a reader who hasn't seen the discussion. Tracking issue: mousse-agent/mousse#1510.
