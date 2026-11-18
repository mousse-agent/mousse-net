# Test vectors

JSON files that pin the wire format in [`../wire.md`](../wire.md). A
conforming implementation passes every case, including every rejection.

## Conventions

- Byte strings are lowercase hex with no separators.
- Times are Unix seconds. The base time is `1790000000`
  (2026-09-21T14:13:20Z).
- Keys are fixed, so every signature is reproducible: identity A has the
  secret scalar `11` repeated 32 times, identity B `22`…, session key 1
  `33`…, session key 2 `44`…. Signatures are deterministic (RFC 6979), but a
  verifier must not depend on that; it only needs to verify them.
- `result` / `error` values are the rejection names used in `wire.md`, or
  `"ok"`.

## Files

| File | wire.md | What it checks |
|---|---|---|
| `session-cert.json` | 5 | `valid`: every intermediate value of one certificate (keys, SPKI, serial, session record, identity signature, extension value, certificate) and a `CertificateVerify`-style signature with a wrong-key counterpart. `cases`: verify `certificate` at `now` with `expected_identity` (null = no pin) and compare the result. Covers the skew edges, an expired certificate, a pin mismatch on reconnect, an identity signature over another TLS key, a DER identity signature, window errors, a bad self-signature, an unsupported version, an off-curve identity key and malformed DER. `pending` lists vectors that will be added later. |
| `session-lifecycle.json` | 6 | A live path: renewal time, the effective deadline, and the tick at which it closes with `cert_expired`; a new connection after the deadline fails step 1. |
| `authz.json` | 7, 8 | Step 2 and the host's traffic table. Includes a valid identity with no grant attempting RPC (closed with `not_authorized`), the 10 s proof deadline, join-only limits, grant expiry edges and a local denial. |
| `ticket.json` | 10.2 | Two valid tickets with fields, binary, fragment and hash; rejections in binary and fragment form; joiner-side expiry edge. |
| `join-proof.json` | 10.3, 10.5 | Join-proof key, input record and MAC; the binding transcript. Exporters are fixed stand-in values. |
| `pairing-attempts.json` | 10.7, 10.8 | Behavioural sequences: three wrong codes, a right code after a wrong one, resends, the same attempt on another session, attempts shared across routes, a dropped attempt, and two joiners racing for one in-person invitation. Each step lists the state that must hold after it. |
| `cbor.json` | 3 | Canonical CBOR that must decode and re-encode unchanged, and inputs that must be rejected with the given error. |
| `der-raw.json` | 4.2, 4.3 | DER to raw conversion and its rejections; inputs where only raw is accepted. |
| `mux.json` | 9.1 | Frames that decode and re-encode unchanged; inputs that need more bytes or are rejected, with the reason. |
| `control.json` | 11 | Control messages that decode and re-encode unchanged; messages that must be rejected. |

Code-exchange (CPace) vectors live in `cpace*.json` files, documented in
[`../cpace.md`](../cpace.md).

## Pending

- **Browser Worker certificate:** a session certificate issued in a browser
  Worker with a WebCrypto identity key, checked by a native verifier. Added
  with the browser spike; listed under `pending` in `session-cert.json`.

## How they are made

`crates/mousse-net-core/src/vectors.rs` generates every file here (except the
code-exchange ones) from the fixed keys above. Its test fails if a file
differs from what it generates. To regenerate after a deliberate change:

```
MOUSSE_NET_WRITE_VECTORS=1 cargo test -p mousse-net-core vector_files_are_current
```

Then review the diff. `crates/mousse-net-core/tests/vectors.rs` checks the
files independently, through the public API only. `pairing-attempts.json` is
replayed by the `pairing_attempt_sequences_hold` test, against the real host
and joiner state machines with a stand-in code exchange.
