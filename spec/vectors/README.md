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
| `session-cert.json` | 5 | `valid`: every intermediate value of one certificate (keys, SPKI, serial, session record, identity signature, extension value, certificate) and a `CertificateVerify`-style signature with a wrong-key counterpart. `cases`: verify `certificate` at `now` with `expected_identity` (null = no pin) and compare the result. Covers the skew edges, an expired certificate, a pin mismatch on reconnect, another endpoint answering on the expected LAN address (`pin_mismatch`; no data is sent and the caller tries the next candidate), an identity signature over another TLS key, a DER identity signature, window errors, a bad self-signature, an unsupported version, an off-curve identity key and malformed DER. The pin is checked before the window, so a certificate that breaks both is `pin_mismatch` (`precedence_pin_before_window`), and an expired certificate with no pin is `outside_window`. Error precedence: a self-signature that is not strict DER (`malformed`) against well-formed out-of-range scalars (`self_signature_invalid`), extension field lengths judged by checks 3 and 5, and `precedence_*` certificates that break two checks at once. `browser_worker`: certificates made in real browser Workers (Chromium and Firefox) by `spikes/browser-worker`, with a non-extractable WebCrypto identity key; each has an `ok` case of the same name in `cases`. Their bytes are recorded, not generated. |
| `session-lifecycle.json` | 6 | A live path: renewal time, renewal retries on their backoff while no new path with a later renewal time is current, the effective deadline, and the tick at which it closes with `cert_expired`; a switch to a new path that carries the same certificates keeps the retry schedule; a new connection after the deadline fails step 1. `clock_rollback`: the wall clock is set back after authentication, and the path still closes when the monotonic cap is reached (6). |
| `authz.json` | 7, 8 | `cases`: step 2 and the host's traffic table (8.1). Includes a valid identity with no grant attempting RPC (closed with `not_authorized`), the 10 s proof deadline, join-only limits, one `JOIN_PROOF` on a live connection (before any stream) that can make it join-only, grant expiry edges and a local denial. `caller_cases`: the caller's gate (8.2), including a host that opens a stream before `AUTHORIZED`, `PAIRED` out of place, a second `AUTHORIZED`, a caller that sent a proof waiting for the host's answer after step 2's live notice, `PAIRED` as that answer (`proof_answered_with_paired`), and what a host-opened stream may do, read from the caller's own grants (`host_stream` steps with `local_grants`, `host_opened_stream_needs_the_callers_grant`). `JOIN_DIRECT` on the host follows the `JOIN_PROOF` rows (traffic `join_direct`); caller cases with `start` `pairing_only` cover the pairing-only state of an unpinned Pair with IP connection (8.2), which only `promote_direct` after `PAIRED` makes live; `no_grant_two_proofs_before_admission` and `no_grant_join_direct_after_join_proof` hold a connection to one proof of either kind before admission. |
| `hello.json` | 2, 11 | This build's versions and `HELLO` bytes; negotiation cases with the agreed minor version or `close:unsupported_version`; `repeated`: several `HELLO`s on one connection, where only the first counts. |
| `ticket.json` | 10.2 | Two valid tickets with fields, binary, fragment and hash; rejections in binary and fragment form; joiner-side expiry edge. `route_hints`: hints that read as tcp or mdns routes, and hints skipped as `reserved`, `unknown_scheme` or `malformed` (10.2.1). IPv6 hosts are given as their 16 bytes, so every text form of one address gives the same value; DNS names lowercased. Fragment rejections include a length of 1 mod 4 and set unused bits. |
| `join-proof.json` | 10.3, 10.5 | Join-proof key, input record and MAC; the binding transcript (initiator first); an attempt's session id with its input record. Exporters are fixed stand-in values. |
| `pairing-attempts.json` | 10.6, 10.7, 10.8 | Sequences with the real code exchange: three wrong codes, a right code after a wrong one, a stale code after a new one was shown, a repeated message (it fails the attempt), messages after the joiner aborted, a different payload on a running attempt, bad first messages that still use the next code and the scalar, an attempt replayed on another connection (a new, debited attempt there), a join proof made with the host's own identity, attempts shared across routes, a dropped attempt, and two joiners racing for one in-person invitation. Each sequence lists its ticket and every party's random draws in the reference order (a harness convention, wire.md 10.6); each step lists every message after the two HELLOs and every shown code byte for byte (`out`) and the state that must hold after it. Joiners' in-person proofs name `<letter> (Work)` (10.3). |
| `pairing-e2e.json` | 7, 8, 10, 11 | Whole pairings between a host and joiners, replayable byte for byte from the scripted random draws (`rng`): in person, "Send link" (including a redrawn code), three wrong codes ending the invitation, the joiner's own 3-attempt limit against a fake host, tampered tickets (secret and invitation id), a proof made on another TLS session, a lost `PAIRED` learned on the next connection (the host sends `AUTHORIZED {live}`, then answers the join proof with `PAIRED` from the grant's enrollment receipt), a role change that never committed ending "already paired" with the old grant (`role_change_not_committed`), a crash right after the outcome-pending mark is stored (`crash_after_pending_mark`), a proof timeout while learning a lost `PAIRED` ending the flow until the ticket is opened again (`lost_paired_then_proof_timeout`), a "Send link" joiner that refuses `AUTHORIZED {live}` from a host it never pinned (`send_link_live_needs_a_pin`), a joiner with no pin pairing again while the host still grants it (`re_pair_while_granted`), an in-person ticket opened as a link (`swapped_in_person_link`), a device's own ticket (`own_ticket`) and the joiner's attempt count kept across reopening the link (`joiner_cap_survives_reopening`), and an in-person approval that chooses a role other than the invitation's, followed by a lost `PAIRED` and a role edit in place, so the receipt's `PAIRED` carries the grant's role as it is now (`approved_role_then_edited`). Every step lists what each side does: messages as control bytes and mux frames, closes, shown codes, attempt ids with their `CI` and `sid`, the joiner's flow-record writes (`persist`, with the record it expects and the one it writes, 10.7), and the final state. The joiner is computer `Phone` with profile label `Work` (10.3). |
| `cbor.json` | 3 | Canonical CBOR that must decode and re-encode unchanged, and inputs that must be rejected with the given error, including indefinite lengths (`non_canonical`) and inputs that break several rules (the first in wire.md's order wins). |
| `der-raw.json` | 4.2, 4.3 | DER to raw conversion and its rejections; inputs where only raw is accepted. |
| `direct-code.json` | 10.9 | The direct code. `draws`: 12 drawn bytes to the code, its display form, the lookup and the secret (hex of its 8 ASCII bytes); every character of the alphabet appears, and high bits of a byte are ignored. `accepted`: typed text read as a code (case, spaces, dashes, `O`, `I` and `L`). `rejected`: text that is not a code, `bad_character` (`U`, punctuation, tab, newline, non-ASCII letters and digits, look-alike letters) or `wrong_length`, and a bad character reported before a wrong length. |
| `direct-host.json` | 10.9 | The host side of Pair with IP with the real code exchange, replayed byte for byte from the listed draws against scripted joiners: success with Allow, a wrong secret (debited, the code stays), a wrong lookup (held, not debited, the same for a device with a grant), decline (kept for that device's recovery until its Allow window ends), five failures ending the invitation, a waiting request keeping an invitation with no attempts left, Allow while the device is away and its recovery, a recovery while the request waits, the same identity passing again, the joiner's cancel connected, away and after an Allow while away, a cancel crossing Allow (on the connection and by recovery), a lost `PAIRED` answered from the grant's receipt, two identities passing, a code passed in the last second, no attempt at expiry, an Allow window that ends, `not_received`, one attempt per connection, the host's own identity and the owner's cancel. Each step lists every message and what the host told its I/O layer and UI (`out`) and the state after it. `before_msg_a`: two invitations with the same id and lookup and different secrets send the same bytes up to and including `AUTHORIZED {join_only, I}`, and different `msg_a`. |
| `mux.json` | 9.1, 9.2 | Frames that decode and re-encode unchanged; inputs that need more bytes or are rejected, with the reason; stream rules on a receiving mux (`streams`): ids opened in order with no gaps, frames on never-opened ids, frames on gone streams, `DATA` after `FIN`. |
| `control.json` | 2, 11 | Control messages that decode and re-encode unchanged; messages that must be rejected. Cases with `minor` 4 hold `JOIN_DIRECT` and `AUTHORIZED` keys 2 and 3, decoded as on a connection that agreed minor 4, with the first rule broken named in `error`; `before_minor_4` holds valid ones that a connection at minor 3 rejects. |
| `relay-admission.json` | [relay.md](../relay.md) | `derivations`: relay id, the relay certificate (and another relay's, which the pin must refuse), handles, every proof record with a signature that verifies, the invitation tag and its hash, the enrollment code hash, enrollment links and rejected ones. `messages`: every self-mode message that decodes and re-encodes unchanged, and malformed ones (non-canonical, DER proofs, bad keys, out-of-range values, duplicates, over-long lists, over 16 384 bytes). `scenarios`: scripted runs of one self-hosted relay, replayed with the listed draws, every output byte for byte (relay.md 14). They cover each attack of `docs/phase34-design.md` C.2 that names a vector, the constant refusal deadline (`unlisted_equals_offline`), the pre-accept budget and promotion, accept legs, circuits outliving registrations, `SUCCESSOR`, enrollment, revocation, keepalive and idle waits, protocol errors and connection limits. Hosted mode (leases, admission tokens) is not here. |

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
| `break-cpace-confirm` | The CPace confirmation compare always passes. | `pairing_e2e_vectors`, `pairing_attempt_sequences_hold`, the CPace rejection vectors |
| `break-cpace-sid` | The CPace generator leaves the session id out. | `generator_matches_draft_b3_1`, `session_id_changes_the_generator`, the Mousse CPace vectors |
| `relay-skip-allow-set` | The relay admits any caller of a handle with an allow-set. | `relay_admission`, `relay_admission_scenarios_hold` (`unlisted_equals_offline`) |
| `relay-refuse-early` | A refused call is answered at once instead of at the refusal deadline. | `relay_admission`, `relay_admission_scenarios_hold` (`unlisted_equals_offline`) |
| `relay-successor-unchecked` | `SUCCESSOR` does not check the current key's proof. | `relay_admission`, `relay_admission_scenarios_hold` (`successor_without_current_key`) |
| `relay-no-preaccept-budget` | Join circuits have no byte budget and no per-target cap. | `relay_admission`, `relay_admission_scenarios_hold` (`preaccept_over_budget`) |
| `no-pin-relay` | The relay pin check passes any relay key. | `relay_admission`, `the_certificate_carries_the_identity_and_only_its_pin_passes` |
| `direct-skip-allow` | Pair with IP enrolls as soon as the code passes, with no Allow. | `direct_host_sequences_hold` and the direct host tests |
| `direct-enroll-without-connection` | Allow while the device is away makes the grant at once, with no connection of that device. | `direct_host_sequences_hold` (`allow_while_away_then_recovery`) |
| `direct-allow-beats-cancel` | A joiner's cancel crossing an Allow leaves the grant. | `direct_host_sequences_hold` (`cancel_crossing_allow`), `a_cancelled_close_undoes_only_an_enrollment_that_carried_no_stream` |
| `direct-attempt-not-debited` | A Pair with IP attempt is not debited. | `direct_host_sequences_hold` |

Each control runs the same tests as a normal build; at least one must fail.
The cfg names are declared in the workspace lints. A build with any control
set fails when debug assertions are off. `mousse-net-core`, `mousse-net-io`
and `mousse-helper` also refuse the release profile (and any profile that
inherits it) even with debug assertions on: each build script passes the
profile to its crate, which checks it at compile time, so flags given to one
crate alone (`cargo rustc -- --cfg ...`) are caught too.

## How they are made

`crates/mousse-net-core/src/vectors/mod.rs` generates every file here
(except the code-exchange ones and `pairing-e2e.json`) from the fixed keys
above. The browser Worker certificates in `session-cert.json` are recorded
from `spikes/browser-worker` runs; the generator only checks them.
`crates/mousse-net-core/tests/pairing_e2e.rs` generates `pairing-e2e.json`. Each test fails if a file differs from what it
generates. To regenerate after a deliberate change:

```
MOUSSE_NET_WRITE_VECTORS=1 cargo test -p mousse-net-core
```

Then review the diff. `crates/mousse-net-core/tests/vectors.rs` checks the
files independently, through the public API only. `pairing-attempts.json` is
replayed by the `pairing_attempt_sequences_hold` test and `pairing-e2e.json`
by `pairing_e2e_vectors`, against the real host and joiner state machines
and the real code exchange.
