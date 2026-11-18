# Browser Worker spike (Phase 0, spike 2)

Check `phase0.browser-worker-cert`: a browser Worker signs a P-256 session
certificate that the native verifier accepts, and its key survives a Worker
restart.

This directory is its own Cargo workspace, kept apart from the main workspace.

## How it works

- **Identity key:** a non-extractable WebCrypto ECDSA P-256 key, made in the
  Worker and stored in IndexedDB as a `CryptoKey` (PLAN §1: browsers use a
  non-extractable WebCrypto key). The Worker checks that exporting it as
  `pkcs8` or `jwk` is refused.
- **Certificate:** `mousse-net-core` compiled to `wasm32-unknown-unknown`
  builds the session record and assembles the certificate. WebCrypto signs the
  record and returns raw `r ‖ s`, which goes into the certificate as is. The
  core draws no randomness; the Worker passes in the session key's 32 secret
  bytes from `crypto.getRandomValues`.
- **Native check:** `browser-worker-runner` serves the page on `127.0.0.1`
  (random port, Host checked, fixed file list) and checks each certificate
  with `mousse_net_core::session_cert::verify` at its own wall time.
  1. A new Worker makes a certificate with a newly made key. It must verify,
     pinned to the identity key the Worker reports.
  2. That Worker is terminated and a new one loads the key from IndexedDB and
     makes another certificate. It must verify pinned to step 1's key.
- **Controls** (`MOUSSE_BROWSER_SPIKE_BREAK`):
  - `tampered-cert`: the Worker signs a record for another session key and
    puts that signature in its certificate (the core refuses to assemble it,
    so the spike re-signs the certificate itself). The native verifier must
    refuse it: `identity_signature_invalid`.
  - `fresh-key`: the second Worker makes a new key instead of loading the
    stored one. Step 2 must fail: `pin_mismatch`.

## Layout

| Path | What |
| --- | --- |
| `wasm/` | `mousse-browser-worker`: the wasm-bindgen wrapper around the core. |
| `runner/` | `browser-worker-runner`: the loopback server and native verifier. Writes one result JSON per run. |
| `web/` | The page (`index.html`, `page.js`) and the Worker (`worker.js`). `web/pkg/` is built. |
| `scripts/run.mjs` | Starts the runner, opens the page headless (Playwright for Chromium and Firefox, `safaridriver` for Safari), closes both, writes `<check>__<cell>[__<control>].json` and `.log`. |

## Run

```
npm ci
npm run build          # wasm-pack (wasm-bindgen 0.2.130) and the runner, release
node scripts/run.mjs --browser chromium --channel msedge --out <dir>
node scripts/run.mjs --browser firefox --control tampered-cert --out <dir>
node scripts/run.mjs --browser safari --control fresh-key-after-restart --out <dir>
```

Playwright needs its Firefox build (`npx playwright install firefox`); for
Chromium, `--channel msedge` or `--channel chrome` uses the installed browser.
Safari needs "Allow Remote Automation" (Safari's Develop menu) and
`safaridriver --enable`, both done once by the owner. `run.mjs` exits 0 when
the outcome is the expected one (PASS, or FAIL for a control) and 3 when
Safari refuses automation.

`navigator.storage.persist()` is asked for and its answer recorded. Firefox
asks the user, so headless it gets no answer; the run waits 2 s and goes on.
