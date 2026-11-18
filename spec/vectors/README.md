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
- The authorizing owner (a profile id) is `51` repeated 16 times.
- Pairing uses the real code exchange (CPace profile 1, [`../cpace.md`](../cpace.md)).
  Where random values matter, the file lists them in the order they are
  drawn.
- `result` / `error` values are the rejection names used in `wire.md`, or
  `"ok"`.

## Files

| File | wire.md | What it checks |
|---|---|---|
| `session-cert.json` | 5 | `valid`: every intermediate value of one certificate (keys, SPKI, serial, session record, identity signature, extension value, certificate) and a `CertificateVerify`-style signature with a wrong-key counterpart. `cases`: verify `certificate` at `now` with `expected_identity` (null = no pin) and compare the result. Covers the skew edges, an expired certificate, a pin mismatch on reconnect, another endpoint answering on the expected LAN address (`pin_mismatch`; no data is sent and the caller tries the next candidate), an identity signature over another TLS key, a DER identity signature, window errors, a bad self-signature, an unsupported version, an off-curve identity key and malformed DER. Error precedence: a self-signature that is not strict DER (`malformed`) against well-formed out-of-range scalars (`self_signature_invalid`), extension field lengths judged by checks 3 and 5, and `precedence_*` certificates that break two checks at once. `pending` lists vectors that will be added later. |
| `session-lifecycle.json` | 6 | A live path: renewal time, renewal retries on their backoff while no new path with a later renewal time is current, the effective deadline, and the tick at which it closes with `cert_expired`; a switch to a new path that carries the same certificates keeps the retry schedule; a new connection after the deadline fails step 1. |
| `authz.json` | 7, 8 | `cases`: step 2 and the host's traffic table (8.1). Includes a valid identity with no grant attempting RPC (closed with `not_authorized`), the 10 s proof deadline, join-only limits, grant expiry edges and a local denial. `caller_cases`: the caller's gate (8.2), including a host that opens a stream before `AUTHORIZED`, `PAIRED` out of place and a second `AUTHORIZED`. |
| `hello.json` | 2, 11 | This build's versions and `HELLO` bytes; negotiation cases with the agreed minor version or `close:unsupported_version`; `repeated`: several `HELLO`s on one connection, where only the first counts. |
| `ticket.json` | 10.2 | Two valid tickets with fields, binary, fragment and hash; rejections in binary and fragment form; joiner-side expiry edge. `route_hints`: hints that read as tcp or mdns routes, and hints skipped as `reserved`, `unknown_scheme` or `malformed` (10.2.1). IPv6 hosts are given as their 16 bytes, so every text form of one address gives the same value; DNS names lowercased. Fragment rejections include a length of 1 mod 4 and set unused bits. |
| `join-proof.json` | 10.3, 10.5 | Join-proof key, input record and MAC; the binding transcript (initiator first); an attempt's session id with its input record. Exporters are fixed stand-in values. |
| `pairing-attempts.json` | 10.6, 10.7, 10.8 | Sequences with the real code exchange: three wrong codes, a right code after a wrong one, a stale code after a new one was shown, resends (also after the joiner aborted), a different payload on a running attempt, bad first messages that still use the next code and the scalar, an attempt replayed on another connection (refused before any debit), attempts shared across routes, a dropped attempt, and two joiners racing for one in-person invitation. Each sequence lists its ticket and every party's random draws in order; each step lists every message after the two HELLOs and every shown code byte for byte (`out`) and the state that must hold after it. |
| `pairing-e2e.json` | 8, 10, 11 | Whole pairings between a host and joiners, replayable byte for byte from the scripted random draws (`rng`): in person, "Send link" (including a redrawn code), three wrong codes ending the invitation, the joiner's own 3-attempt limit against a fake host, tampered tickets (secret and invitation id), a proof made on another TLS session, and a lost `PAIRED` learned on the next connection (the host sends `AUTHORIZED {live}` and ignores the join proof). Every step lists what each side does: messages as control bytes and mux frames, closes, shown codes, attempt ids with their `CI` and `sid`, and the final state. |
| `cbor.json` | 3 | Canonical CBOR that must decode and re-encode unchanged, and inputs that must be rejected with the given error, including indefinite lengths (`non_canonical`) and inputs that break several rules (the first in wire.md's order wins). |
| `der-raw.json` | 4.2, 4.3 | DER to raw conversion and its rejections; inputs where only raw is accepted. |
| `mux.json` | 9.1 | Frames that decode and re-encode unchanged; inputs that need more bytes or are rejected, with the reason. |
| `control.json` | 11 | Control messages that decode and re-encode unchanged; messages that must be rejected. |

Code-exchange (CPace) vectors live in `cpace*.json` files, documented in
[`../cpace.md`](../cpace.md).

## Must-fail controls

To show that these tests can fail, `mousse-net-core` can be built with one
planted bug, chosen by a compile-time cfg:

```
RUSTFLAGS='--cfg mousse_control="break-authz"' cargo test -p mousse-net-core
```

| Control | Planted bug | Fails |
|---|---|---|
| `break-session-cert` | Step 1 skips the identity-signature check. | `session_certificates` (`delegation_over_wrong_tls_key`) |
| `break-authz` | A connection with no grant may open streams. | `authorization` (`valid_identity_without_grant_attempting_rpc`) |
| `break-raw-signature` | DER is quietly converted where a raw signature is required. | `der_to_raw`, `session_certificates` (`identity_signature_der`) |
| `break-cpace` | The CPace confirmation compare always passes. | `pairing_e2e_vectors`, `pairing_attempt_sequences_hold`, the CPace rejection vectors |

Each control runs the same tests as a normal build; at least one must fail.
The cfg names are declared in the workspace lints. A release build with any
control set does not compile.

## Pending

- **Browser Worker certificate:** a session certificate issued in a browser
  Worker with a WebCrypto identity key, checked by a native verifier. Added
  with the browser spike; listed under `pending` in `session-cert.json`.

## How they are made

`crates/mousse-net-core/src/vectors/mod.rs` generates every file here
(except the code-exchange ones and `pairing-e2e.json`) from the fixed keys
above. `crates/mousse-net-core/tests/pairing_e2e.rs` generates
`pairing-e2e.json`. Each test fails if a file differs from what it
generates. To regenerate after a deliberate change:

```
MOUSSE_NET_WRITE_VECTORS=1 cargo test -p mousse-net-core
```

Then review the diff. `crates/mousse-net-core/tests/vectors.rs` checks the
files independently, through the public API only. `pairing-attempts.json` is
replayed by the `pairing_attempt_sequences_hold` test and `pairing-e2e.json`
by `pairing_e2e_vectors`, against the real host and joiner state machines
and the real code exchange.
