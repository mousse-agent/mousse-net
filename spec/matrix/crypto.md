# Crypto provider choice for the session

Phase 0 spike 1 (crypto matrix). Decides which rustls crypto provider each target uses before the session design freezes. Cells, commands and the result format are in [targets.md](targets.md). Code: `native/net/spikes/tls-matrix`. Results: `results/` (build `7fca58b75+release`).

## Recommendation

1. **Native targets (Windows, macOS, Linux, iOS, Android): aws-lc-rs**, rustls `aws_lc_rs` + `prefer-post-quantum`. Two native peers negotiate **X25519MLKEM768** with TLS13_AES_256_GCM_SHA384. Proven on Windows x64 (msvc and gnu) and Linux x64; the other native cells are not run yet.
2. **Browser (wasm32 in a Worker): ring**, built with a pinned LLVM clang. aws-lc-rs does not build for wasm32-unknown-unknown.
   - With ring alone, **browser sessions are classical (X25519)**. A native peer falls back to X25519 in one round trip, with no HelloRetryRequest.
   - The spike also shows a way out: a pure-Rust X25519MLKEM768 group (about 150 lines over RustCrypto `ml-kem` 0.3.4 and `x25519-dalek` 3.0.0, feature `pq-pure`) interoperates with aws-lc-rs in both directions and runs in wasm32. Adopting it is a design-review decision (see Risks). Until then, record browser sessions as classical only, as the plan's "Risks and cuts" already says.
3. **Not a single provider everywhere, for now.** `rustls-rustcrypto` passed every case on Windows, Linux and wasm32, and needs no C compiler. But it is a 0.1.0 pre-release (published 2026-11-09), its README says not to use it in production, and it has no post-quantum group. Revisit it when it is stable. If one code path everywhere becomes important, "ring + the pure-Rust hybrid group" is the better candidate: it passed natively and in wasm32 and negotiates the hybrid with aws-lc-rs.
4. **Windows builds use the msvc toolchain.** The gnu toolchain works only with a MinGW C compiler and `dlltool`, which this PC does not have by default.

### Session policy the results support

- TLS 1.3 only. A client offering only TLS 1.2 is refused (`PeerIncompatible`).
- Mandatory client certificates; a missing one is refused (`NoCertificatesPresented`).
- Verifiers check only the pinned key (SubjectPublicKeyInfo) and the TLS 1.3 CertificateVerify signature, with `ECDSA_NISTP256_SHA256` as the only scheme. A wrong pin is refused on either side with `InvalidCertificate(ApplicationVerificationFailure)`.
- Exporter values (RFC 8446 §7.5) match on both sides for every provider pair, including wasm32 and mixed providers. The session can bind later steps (pairing confirmation, ticket proof) to the exporter.
- Offer only X25519MLKEM768 and X25519. Dropping secp256r1 and secp384r1 from the key-exchange list is a suggested trim; every result here negotiated one of the two.
- After the handshake, a native-to-native session should check that it negotiated X25519MLKEM768 and close otherwise. TLS 1.3 already protects the group choice in the transcript; this catches a build that lost the post-quantum setting.

### What to pin

| Crate | Version | Notes |
| --- | --- | --- |
| rustls | `=0.23.46` | `default-features = false`, features `std`, `tls12` (only so the TLS 1.2 refusal can be tested), `logging`; plus `aws_lc_rs` + `prefer-post-quantum` on native, `ring` on wasm32. 0.24 is in development releases; its API will differ. |
| aws-lc-rs | `=1.19.0` | resolves aws-lc-sys 0.47.0. Native only. |
| ring | `=0.17.14` | feature `wasm32_unknown_unknown_js` on wasm32 (pulls getrandom 0.2 with `js`). No release since March 2025. |
| rustls-pki-types | `=1.16.0` | feature `web` on wasm32. Without it, rustls with `std` does not compile for wasm32-unknown-unknown (`UnixTime::now` is missing). |
| getrandom | `=0.4.3` | feature `wasm_js` on wasm32 (`crypto.getRandomValues`). |
| rcgen | `=0.14.10` | `default-features = false`; signs through the `SigningKey` trait, so certificates can be made without any rustls provider. Needs an explicit serial number in that mode. |
| p256 | `=0.14.0` | certificate keys and signatures in this spike. |
| ml-kem, x25519-dalek | `=0.3.4`, `=3.0.0` | only if the pure-Rust hybrid group is adopted. |
| wasm-bindgen | `=0.2.130` | the CLI and test runner must be the same version. |
| LLVM clang (wasm32 builds) | 23.1.6 | Builds ring for wasm32. Pin it in CI. |

## Evidence

All results: `results/*.json`, 91 files, all PASS. Each covers 5 cases × the target's transports (pipe and TCP natively, pipe on wasm32).

| Target | Pairs | Hybrid where both ends offer it | Notes |
| --- | --- | --- | --- |
| x86_64-pc-windows-msvc | 25 | yes | rustc 1.99.1 (the msvc toolchain installed on the PC) |
| x86_64-pc-windows-gnu | 25 | yes | rustc 1.96.0; C code built with portable llvm-mingw 20261104 |
| x86_64-unknown-linux-gnu | 25 | yes | rustc 1.96.0, Ubuntu 24.04.5 (WSL 2), gcc 13.3 |
| wasm32-unknown-unknown@node | 16 | yes (`+pq` providers) | Node 24.20.0; ring built with LLVM clang 23.1.6 |

Negotiated suites: aws-lc-rs and ring prefer TLS13_AES_256_GCM_SHA384; rustcrypto prefers TLS13_AES_128_GCM_SHA256. The server follows the client's order.

Tests (`cargo test -p tls-matrix`, 13 native, 2 wasm under Node) also cover: hybrid group with aws-lc-rs on both ends, hybrid fallback with no retry, exporter equality and uniqueness, the must-fail control, a judge that fails when a refusal case connects, and the pure-Rust hybrid group (same secret on both halves; a tampered ciphertext gives a different secret; wrong share lengths and an all-zero X25519 key are refused). Swapping the order of the two secrets in the pure-Rust group makes the interop test fail with `DecryptError` on both sides, so the test does check the wire format against aws-lc-rs.

wasm32 sizes (release, LTO; this whole spike, not just TLS; gzip -9 in brackets):

| Providers | .wasm |
| --- | --- |
| rustcrypto | 1.60 MB (530 KB) |
| rustcrypto + pure-Rust hybrid | 1.64 MB (544 KB) |
| ring | 1.17 MB (405 KB) |
| ring + pure-Rust hybrid | 1.23 MB (428 KB) |

The hybrid group adds about 20 KB gzipped. The whole Node run of the 16 wasm32 pairs (80 handshakes, each with three fresh P-256 keys) takes about half a second.

### Worker time, entropy and storage

- **Time:** rustls asks a `TimeProvider` for the time. On wasm32 the spike injects the host's `Date.now()` through a fixed clock (`builder_with_details`), which also fits the rule that core code gets time injected. The pki-types `web` feature is still needed for rustls to compile.
- **Entropy:** `getrandom` 0.4 (`wasm_js`) and, for ring, `getrandom` 0.2 (`js`) both use `crypto.getRandomValues`, which Workers have. Two getrandom versions end up in a browser build that uses ring.
- **Storage:** not part of this spike. Key persistence across a Worker restart is spike 2.

## Risks

- **Browser sessions are classical** with ring alone. A recorded traffic capture of a browser session could be decrypted by a future quantum computer. The pure-Rust hybrid closes this, but it is our own glue code (key-share layout, secret order, X25519 checks) over `ml-kem`, which needs the same design review as CPace. Its wire format matches aws-lc-rs in every cross test here.
- **Building ring for wasm32 needs clang** with the WebAssembly backend. Apple's clang has none. CI must pin an LLVM build.
- **rustls 0.24** is coming. The provider and verifier APIs used here (`builder_with_details`, `danger` verifiers, `SupportedKxGroup`) may change; pinning `=0.23.46` holds until a planned upgrade.
- **Windows gnu toolchain:** `getrandom` 0.4 needs `dlltool` and C crates need a MinGW compiler. With this spike as a workspace member, `cargo check --workspace` on the PC's default gnu toolchain fails in `getrandom` unless a MinGW toolchain is set up. Use msvc on Windows, or build single crates with `-p`.
- **Windows TCP refusal:** when the server refuses a missing client certificate over TCP, the Windows client sometimes sees a connection reset (os error 10054) instead of the alert. The server's verdict is correct; the app should not depend on the client seeing the exact alert.
- **rustls-rustcrypto maturity:** pre-release, warns against production use, no post-quantum group.
- **Not yet run:** Windows arm64, macOS, Linux arm64, iOS, Android, and every browser. aws-lc-sys builds for those targets are expected to work but each needs its own toolchain (Xcode, the NDK, MSVC arm64). Nothing here proves them.
- **Pinning checks only the key.** The spike ignores certificate dates and the identity-signature extension on purpose. The real verifier must add the session-certificate checks from PLAN §1 (identity signature over the SPKI, validity window with ±10 min skew).
