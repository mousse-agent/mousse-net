# Crypto matrix: target groups

Phase 0 spike 1. Each cell runs the `tls-matrix` spike (`native/net/spikes/tls-matrix`) and writes one JSON result per provider pair into `results/`. A cell passes only when every case passes on every transport the target has. The recommendation is in [crypto.md](crypto.md).

## What one run checks

For each ordered pair of providers (client, server), with fresh self-signed P-256 certificates and verifiers that accept only the pinned peer key (SubjectPublicKeyInfo; chains are ignored):

| Case | Must |
| --- | --- |
| `mutual` | succeed with TLS 1.3. Both sides agree on group and suite. Both sides export the same 32 bytes (label `EXPORTER-mousse-net-matrix-v1`, context `phase0.crypto-matrix`). The group is X25519MLKEM768 exactly when both ends offer it. |
| `wrong-server-pin` | be refused by the client (`InvalidCertificate(ApplicationVerificationFailure)`), and the server must fail too. |
| `wrong-client-pin` | be refused by the server (same error), and the client must fail too. |
| `missing-client-cert` | be refused by the server (`NoCertificatesPresented`). |
| `tls12-only` | be refused by the server (`PeerIncompatible`) when the client offers only TLS 1.2. |

Transports: an in-memory pipe everywhere, and TCP on 127.0.0.1 on native targets. Exporter values are compared, never printed. Separate sessions must export different values.

Must-fail control: `MOUSSE_MATRIX_BREAK=1` makes the client pin the wrong server key in the `mutual` case. Every pair must then print FAIL and the process exits 1. The wasm tests check the same control in-process (`broken_mode_fails`, `broken_mode_fails_in_a_worker`).

Providers (labels in results; `a>b` means client `a`, server `b`):

| Label | What it is |
| --- | --- |
| `aws-lc-rs` | rustls `aws_lc_rs` provider with `prefer-post-quantum`. Offers X25519MLKEM768, X25519, secp256r1, secp384r1. Native only. |
| `ring` | rustls `ring` provider. Offers X25519, secp256r1, secp384r1. |
| `rustcrypto` | `rustls-rustcrypto` 0.1.0-pre.0, pure Rust. Same groups as ring. |
| `ring+pq`, `rustcrypto+pq` | the same providers with the experimental pure-Rust X25519MLKEM768 group (`ml-kem` + `x25519-dalek`) put first. Feature `pq-pure`. |

Result files: `results/<target>__<client>__<server>.json`, with the fields `check`, `target`, `provider`, `outcome`, `kx_group`, `suite`, `build`, `details`. `kx_group` and `suite` come from the first successful `mutual` case. `build` is the git short sha of the spike's code plus the profile.

## The nine target groups

Status: PASS (run here, every pair passed), FAIL, INCOMPLETE (not run yet). "PQ hybrid" is what the recommended provider negotiates with a native peer.

| # | Group | Cells (Rust target) | Recommended provider | PQ hybrid | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Windows x64 | `x86_64-pc-windows-msvc` | aws-lc-rs | yes | PASS | `results/x86_64-pc-windows-msvc__*.json` (25 pairs) |
| | | `x86_64-pc-windows-gnu` (other toolchain) | aws-lc-rs | yes | PASS, with a portable MinGW C toolchain | `results/x86_64-pc-windows-gnu__*.json` (25 pairs) |
| 2 | Windows arm64 | `aarch64-pc-windows-msvc` | aws-lc-rs | expected | INCOMPLETE | needs a Windows on Arm machine |
| 3 | macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` | aws-lc-rs | expected | INCOMPLETE | run on the Mac |
| 4 | Linux x64 | `x86_64-unknown-linux-gnu` | aws-lc-rs | yes | PASS | `results/x86_64-unknown-linux-gnu__*.json` (25 pairs; Ubuntu 24.04.5 on WSL 2) |
| 5 | Linux arm64 | `aarch64-unknown-linux-gnu` | aws-lc-rs | expected | INCOMPLETE | run in an arm64 Linux container on the Mac |
| 6 | iOS (15+) | `aarch64-apple-ios` on a physical phone | aws-lc-rs | expected | INCOMPLETE | needs the phone |
| 7 | Android | `aarch64-linux-android`, `x86_64-linux-android`; minimum API set by spike 4 | aws-lc-rs | expected | INCOMPLETE | needs a phone (arm64) and an emulator (x86_64) |
| 8 | Desktop browser, dedicated Worker | `wasm32-unknown-unknown` in Chromium, Firefox, Safari (macOS) | ring (classical); ring+pq if adopted | no (yes with `pq-pure`) | INCOMPLETE | The wasm32 build itself passes under Node 24: `results/wasm32-unknown-unknown@node__*.json` (16 pairs). That is not a browser cell. |
| 9 | Mobile browser, dedicated Worker | `wasm32-unknown-unknown` in Safari (iOS 15+), Chrome (Android) | as group 8 | as group 8 | INCOMPLETE | needs the phones |

### Cell summary (same-provider pairs; every cross pair also passed)

| Target | aws-lc-rs | ring | rustcrypto | ring+pq | rustcrypto+pq |
| --- | --- | --- | --- | --- | --- |
| x86_64-pc-windows-msvc | PASS, X25519MLKEM768, AES_256_GCM | PASS, X25519, AES_256_GCM | PASS, X25519, AES_128_GCM | PASS, X25519MLKEM768 | PASS, X25519MLKEM768 |
| x86_64-pc-windows-gnu | PASS, X25519MLKEM768 | PASS, X25519 | PASS, X25519 | PASS, X25519MLKEM768 | PASS, X25519MLKEM768 |
| x86_64-unknown-linux-gnu | PASS, X25519MLKEM768 | PASS, X25519 | PASS, X25519 | PASS, X25519MLKEM768 | PASS, X25519MLKEM768 |
| wasm32-unknown-unknown@node | not available | PASS, X25519 | PASS, X25519 | PASS, X25519MLKEM768 | PASS, X25519MLKEM768 |

Cross pairs that matter for the design:

- `aws-lc-rs>ring` and `ring>aws-lc-rs` (a native peer and a classical browser): X25519, one round trip (no HelloRetryRequest), because the hybrid ClientHello also carries an X25519 share.
- `aws-lc-rs>ring+pq`, `ring+pq>aws-lc-rs`, and the same with `rustcrypto+pq`: X25519MLKEM768 both ways. The pure-Rust hybrid matches aws-lc-rs on the wire.

## Commands

All commands run from `native/net`. Set `CARGO_TARGET_DIR` to a build folder of your choice. Every native run takes `--out spec/matrix/results`; every run also has a must-fail control with `MOUSSE_MATRIX_BREAK=1` that must end in `FAIL phase0.crypto-matrix` and exit 1.

### Windows x64 (done on the PC)

    cargo +stable-x86_64-pc-windows-msvc run --release -p tls-matrix -- --out spec/matrix/results
    cargo +stable-x86_64-pc-windows-msvc test -p tls-matrix

The gnu toolchain needs a MinGW C compiler and `dlltool` (for `getrandom` 0.4). The PC has neither, so a portable llvm-mingw (`J:\ryspa\mousse\tools\llvm-mingw-20261104-ucrt-x86_64`) was used, with the toolchain's own linker:

    LM=/j/ryspa/mousse/tools/llvm-mingw-20261104-ucrt-x86_64/bin
    SC=$(rustc +stable-x86_64-pc-windows-gnu --print sysroot)/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained
    PATH="$PATH:$LM" \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$SC/x86_64-w64-mingw32-gcc.exe" \
    CC_x86_64_pc_windows_gnu="$LM/x86_64-w64-mingw32-clang.exe" \
    AR_x86_64_pc_windows_gnu="$LM/llvm-ar.exe" \
    cargo +stable-x86_64-pc-windows-gnu run --release -p tls-matrix -- --out spec/matrix/results

### Linux x64 (done in WSL)

Rust was installed for one user into a private folder (no system packages); gcc was already there.

    export RUSTUP_HOME=~/net-p0-crypto/rustup CARGO_HOME=~/net-p0-crypto/cargo
    sh rustup-init.sh -y --no-modify-path --profile minimal --default-toolchain 1.96.0
    MOUSSE_BUILD_ID=<sha>+release cargo run --release -p tls-matrix -- --out spec/matrix/results

`MOUSSE_BUILD_ID` was set because git inside WSL can't read this Windows worktree.

### wasm32 under Node (done on the PC)

ring needs clang with the wasm32 backend. A portable LLVM 23.1.6 (only `clang.exe`, `llvm-ar.exe` and the clang headers, 144 MB) was unpacked to `J:\ryspa\mousse\tools\llvm-23.1.6`. wasm-bindgen 0.2.130 (prebuilt, checksum checked) is in `J:\ryspa\mousse\tools\wasm-bindgen-0.2.130`. Nothing was installed system-wide.

    export CC_wasm32_unknown_unknown=J:/ryspa/mousse/tools/llvm-23.1.6/bin/clang.exe
    export AR_wasm32_unknown_unknown=J:/ryspa/mousse/tools/llvm-23.1.6/bin/llvm-ar.exe
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=J:/ryspa/mousse/tools/wasm-bindgen-0.2.130/wasm-bindgen-test-runner.exe
    cargo test -p tls-matrix --target wasm32-unknown-unknown --no-default-features --features ring,rustcrypto,pq-pure,wasm

    # result files
    cargo rustc -p tls-matrix --lib --release --target wasm32-unknown-unknown \
      --no-default-features --features ring,rustcrypto,pq-pure,wasm --crate-type cdylib
    wasm-bindgen --target nodejs --out-dir $CARGO_TARGET_DIR/wasm-pkg $CARGO_TARGET_DIR/wasm32-unknown-unknown/release/tls_matrix.wasm
    node spikes/tls-matrix/scripts/matrix-results.mjs --pkg $CARGO_TARGET_DIR/wasm-pkg --build <sha>+release --out spec/matrix/results

Without clang, `--features rustcrypto,pq-pure,wasm` builds and passes; anything with `ring` fails in `ring`'s build script (`failed to find tool "clang"`).

### macOS arm64 and x64 (group 3)

    cargo run --release -p tls-matrix -- --out spec/matrix/results
    rustup target add x86_64-apple-darwin
    cargo run --release --target x86_64-apple-darwin -p tls-matrix -- --out spec/matrix/results   # runs under Rosetta 2
    cargo test -p tls-matrix
    MOUSSE_MATRIX_BREAK=1 cargo run --release -p tls-matrix -- --same-only   # must print FAIL

### Linux arm64 (group 5)

On the Mac, in an arm64 Linux container (or any arm64 Linux host):

    docker run --rm -v "$PWD/../..":/src -w /src/native/net -e MOUSSE_BUILD_ID=<sha>+release rust:1.96 \
      cargo run --release -p tls-matrix -- --out spec/matrix/results

### Windows arm64 (group 2)

On a Windows on Arm machine with the MSVC arm64 build tools (aws-lc-sys may also need clang-cl; to verify):

    cargo +stable-aarch64-pc-windows-msvc run --release -p tls-matrix -- --out spec/matrix/results

### iOS 15+ (group 6), physical phone

`cargo-dinghy` builds, signs and runs the binary on a connected phone. It needs a signing identity and a provisioning profile on the Mac.

    rustup target add aarch64-apple-ios
    cargo install cargo-dinghy --locked
    export IPHONEOS_DEPLOYMENT_TARGET=15.0 MOUSSE_BUILD_ID=$(git rev-parse --short HEAD)+release
    cargo dinghy -d <phone> run --release -p tls-matrix -- --print-results \
      | node spikes/tls-matrix/scripts/matrix-results.mjs --stdin --out spec/matrix/results
    cargo dinghy -d <phone> test --release -p tls-matrix

`--print-results` prints one `MATRIX_RESULT` line per pair; the script writes the files. If dinghy can't pass `MOUSSE_MATRIX_BREAK`, the in-process control is `cargo dinghy -d <phone> test --release -p tls-matrix broken_mode_fails`. A simulator run (`aarch64-apple-ios-sim`) is supporting evidence only, not the cell.

### Android (group 7)

    rustup target add aarch64-linux-android x86_64-linux-android
    cargo install cargo-ndk --locked
    export ANDROID_NDK_HOME=<ndk> MOUSSE_BUILD_ID=$(git rev-parse --short HEAD)+release
    cargo ndk -t arm64-v8a --platform <min API from spike 4> build --release -p tls-matrix --bin tls-matrix
    adb push $CARGO_TARGET_DIR/aarch64-linux-android/release/tls-matrix /data/local/tmp/tls-matrix
    adb shell /data/local/tmp/tls-matrix --print-results \
      | node spikes/tls-matrix/scripts/matrix-results.mjs --stdin --out spec/matrix/results
    adb shell MOUSSE_MATRIX_BREAK=1 /data/local/tmp/tls-matrix --same-only   # must print FAIL

Repeat with `-t x86_64` and `x86_64-linux-android` on an x86_64 emulator.

### Desktop browsers in a dedicated Worker (group 8)

Apple's clang has no wasm32 backend, so use LLVM's clang (Homebrew `llvm`, or the release tarball in a user folder). The `wasm_worker` test runs every pair inside a dedicated Worker, using the Worker's `Date.now()` and `crypto.getRandomValues`, and checks the must-fail control.

    cargo install wasm-bindgen-cli --version 0.2.130 --locked
    export CC_wasm32_unknown_unknown=<llvm>/bin/clang AR_wasm32_unknown_unknown=<llvm>/bin/llvm-ar
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export MOUSSE_BUILD_ID=$(git rev-parse --short HEAD)+debug
    F="--no-default-features --features ring,rustcrypto,pq-pure,browser-worker --test wasm_worker"
    CHROMEDRIVER=$(which chromedriver) cargo test -p tls-matrix --target wasm32-unknown-unknown $F -- --nocapture \
      | node spikes/tls-matrix/scripts/matrix-results.mjs --stdin --out spec/matrix/results
    GECKODRIVER=$(which geckodriver) cargo test ...same...
    SAFARIDRIVER=/usr/bin/safaridriver cargo test ...same...   # once: safaridriver --enable; Safari opens a window

The target label in the files is `wasm32-unknown-unknown@worker-<chromium|firefox|safari>`, taken from the Worker's user agent.

### Mobile browsers (group 9)

Serve the Worker test page and open it on the phone:

    NO_HEADLESS=1 WASM_BINDGEN_TEST_ADDRESS=0.0.0.0:8000 cargo test -p tls-matrix --target wasm32-unknown-unknown $F

iPhone: open `http://<mac LAN address>:8000` in Safari. Android: `adb reverse tcp:8000 tcp:8000`, then `http://localhost:8000` in Chrome. The page shows the test outcome; the `MATRIX_RESULT` lines have to be copied off the page, so these cells are ATTESTED, not PASS, until the browser spike's page can post results back. (`WASM_BINDGEN_TEST_ADDRESS` is to verify on the Mac.)
