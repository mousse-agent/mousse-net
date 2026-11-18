# Spike 2: a browser Worker signs a session certificate

Check `phase0.browser-worker-cert` (`checks/phase0.toml`), PLAN §1 required
vector "a certificate made in a browser Worker and checked by a native
verifier", and "Browser key loss".

## What it does

1. **Worker** (`web/worker.js` + `src/wasm.rs`, wasm32 via wasm-bindgen). A
   dedicated module Worker loads the identity `CryptoKeyPair` from IndexedDB,
   or makes one with `crypto.subtle.generateKey` (ECDSA P-256,
   `extractable: false`) and stores it. The wasm build of `mousse-net-core`
   makes the session key (entropy from `crypto.getRandomValues`) and
   `PendingCertificate::record()`. WebCrypto signs the record; its ECDSA
   output is already raw `r ‖ s` (64 bytes). `PendingCertificate::finish`
   assembles the certificate.
2. **Native verifier** (`src/bin/verify_worker_cert.rs`) checks every
   certificate with `mousse_net_core::session_cert::verify`, pinned to the
   identity public key the Worker exported.
3. **Runner** (`run.mjs`) serves `web/` from a localhost static server it
   starts and stops, drives Chromium, WebKit and Firefox headless with
   Playwright, and hands the transcript to the verifier.

Steps per browser, in one persistent profile:

| Step | Expected |
| --- | --- |
| Page calls `navigator.storage.persist()` (Window-only API) | answer recorded |
| Worker 1: new key, certificate | verifier accepts it with the pin |
| Worker 1 also: the private key's `extractable` flag, a `pkcs8` export attempt | `false`, refused |
| Worker 1 also: `finish` with the DER form of the signature | refused (`not_raw`) |
| Negative: one bit of the certificate flipped | refused (`self_signature_invalid`) |
| Negative: identity signature over another session key's record (re-self-signed) | `identity_signature_invalid` |
| Negative: identity signature in DER (re-self-signed) | `identity_signature_not_raw` |
| Negative: pin set to another identity | `pin_mismatch` |
| Worker terminated; Worker 2 loads the key, new certificate | same pin accepts it |
| Browser closed and reopened on the same profile; Worker 3 | same pin accepts it |
| `Clear-Site-Data: "storage"` from the server; Worker 4 | no stored key; the old pin refuses the new identity (`pin_mismatch`): the app asks to re-pair |

`src/splice.rs` rebuilds a certificate with a different identity-signature
field and signs it again with the session key. Only the negative cases and
controls use it, so the verifier refuses them for the intended reason rather
than for a broken self-signature.

## Must-fail controls

| `--break` | Control name in the result | What is broken | Caught by |
| --- | --- | --- | --- |
| `tampered-cert` | `tampered-cert` | the Worker's certificate carries an identity signature over another SPKI | `identity_signature_invalid` |
| `fresh-key` | `fresh-key-after-restart` | every Worker after the first ignores the stored key | `pin_mismatch` after the restart |
| `der-signature` | `der-signature` | the Worker's certificate carries the DER signature | `identity_signature_not_raw` |
| `skip-pin` | `skip-pin` | the native verifier never passes the pin | the wrong-pin case is accepted |

The first two are the controls `checks/phase0.toml` names; the other two are
extra. `MOUSSE_BROWSER_SPIKE_BREAK=<mode>` works like `--break`.

## Commands

Everything stays inside this folder except the Cargo target folder.

```sh
cd spikes/browser-worker
export CARGO_TARGET_DIR=/some/disk/browser-worker-target   # outside the checkout

# once: wasm target, wasm-bindgen matching the crate's pinned version, Playwright
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version '=0.2.130' --locked --root "$PWD/.tools"
export WASM_BINDGEN="$PWD/.tools/bin/wasm-bindgen"
npm ci
export PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers"
npx playwright install chromium webkit firefox

# unit tests for the splice helper
cargo test

# normal run, every browser; results go to results/
node run.mjs
# one control (must end with FAIL and exit 1)
node run.mjs --break der-signature
# normal run and every control, every browser; exit 0 when the runs PASS and the controls FAIL
node run.mjs --all
# one browser
node run.mjs --browser webkit
```

The runner builds first (`--no-build` skips it): `cargo build --lib --release
--target wasm32-unknown-unknown`, `wasm-bindgen --target web` into `web/pkg`,
and `cargo build --release --bin verify-worker-cert`. It prints one line per
check and ends with `PASS phase0.browser-worker-cert` or
`FAIL phase0.browser-worker-cert`.

The build id is taken once, before anything is written, the same way
`mousse-check` computes it (last commit outside `checks/`, `-dirty` for
other uncommitted changes) plus the profile `release`.

## Results

`results/worker-<browser>.json` (normal run) and
`results/worker-<browser>.control-<name>.json` hold the unsigned payload
`mousse-check sign` reads: `check`, `target`, `control`, `outcome`, `build`,
`platform`, `details` (a one-line summary), `time`, and `extra` (browser
version, `persist()` answers, every check line, the identity key). Sign them
on the Mac with its device key:

```sh
mousse-check sign --device-key ~/.mousse/device.key results/worker-chromium.json
mousse-check sign --device-key ~/.mousse/device.key results/worker-chromium.control-tampered-cert.json
```

Targets are the cells in `checks/phase0.toml`:
`wasm32-unknown-unknown@worker-chromium`, `...@worker-firefox`, and
`...@worker-safari`, which Playwright's WebKit build stands in for here.

`results/worker-cert-vector.json` is one certificate the Chromium Worker made,
with its identity key and window. Verified at `now` with `expected_identity`
it must give `ok`; it is the candidate for the `browser_worker_certificate`
entry listed under `pending` in `spec/vectors/session-cert.json`.

## Phones (INCOMPLETE)

No phones yet; these cells stay INCOMPLETE.

- **iOS Safari** (minimum iOS 15): serve `web/` over HTTPS on the LAN (WebCrypto
  and Clear-Site-Data need a secure context; `localhost` is not reachable
  from the phone), open it in Safari and in a Home Screen install, and drive
  `window.spike` from Web Inspector on the Mac. Module Workers need iOS 15+.
  Record the `persist()` answer in both (Safari grants it to installed web
  apps), and whether the key survives Safari's 7-day storage cap for sites
  that are not installed. Then feed the transcript to `verify-worker-cert` on
  the Mac and sign the result with the Mac's device key, platform
  `iOS <version> Safari`.
- **Android Chrome**: the same page over HTTPS (or `adb reverse tcp:<port>`
  so `127.0.0.1` works), driven through `chrome://inspect`. Record `persist()`
  with and without installing the page, and that the key survives an app
  restart and is gone after "Clear storage".

For both, collect the transcript by hand (the `runs` array of Worker replies
plus `persist`, the shape `run.mjs` writes to `.runs/`), then:

```sh
"$CARGO_TARGET_DIR/release/verify-worker-cert" --transcript phone.json \
  --build <build id> --out results/worker-ios-safari.json
```
