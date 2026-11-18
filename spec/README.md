# mousse-net specification

The open specification of Mousse networking: how two Mousse devices prove who
they are, decide what each may do, pair, and carry channels over one
encrypted connection.

The design and the phase plan are in [`docs/PLAN.md`](../docs/PLAN.md). This folder is
the part another implementation needs.

| Document | What it covers |
|---|---|
| [`wire.md`](wire.md) | **Normative.** Identity keys, session certificates, step 1 and step 2, grants, pairing tickets and flows, attempt limits, the mux, control messages, error codes, versions. |
| [`cpace.md`](cpace.md) | **Normative.** The code exchange (CPace) used by "Send link" pairing. |
| [`vectors/`](vectors/README.md) | Test vectors for everything in `wire.md`, including rejection vectors. |
| [`threat-model.md`](threat-model.md) | What Phase 0 defends against, and what it does not. |
| [`privacy.md`](privacy.md) | What the relay, Plus and the web client can see. |

## Status

Phase 0 draft. Wire version 1, minor 0. Formats may still change until the
design review of the session certificate and the pairing binding; after that a
change needs a version bump.

## Reference implementation

`crates/mousse-net-core` implements `wire.md` with no I/O of its
own. Its tests check every vector file through the public API
(`tests/vectors.rs`).

## Resolved spec gaps

An independent implementation written from this folder alone found these
gaps. Each is now a normative rule with vectors.

| Gap | Rule | Vector |
|---|---|---|
| When the join proof is sent | [`wire.md`](wire.md) 8, 10.3: the joiner sends `JOIN_PROOF` on every connection right after its own `HELLO`; the host runs step 2 at once, says nothing while it awaits a proof, and ignores the proof under a live grant. | `pairing-e2e.json` `connect` steps, `outcome_after_lost_paired` |
| Messages after an attempt ends | [`wire.md`](wire.md) 10.7, "Resends and messages after an attempt ends": the gate first; two kept values per (TLS session, attempt); identical resend, ended attempt and running attempt rules; `CODE_ABORT` keeps both values. | `pairing-attempts.json` `resend_after_the_joiner_aborted`, `different_payload_on_a_running_attempt_is_the_next_message`, `resend_is_not_a_new_attempt` |
| Responder draw order on a bad first message | [`wire.md`](wire.md) 10.6, "Random draws"; [`cpace.md`](cpace.md) 5.3: the host draws the next code and `yb` before reading `msg_a`. | `pairing-attempts.json` `bad_first_message_still_uses_the_draws` |
| Repeated `HELLO` | [`wire.md`](wire.md) 2, "Only the first `HELLO` counts". | `hello.json` `repeated` |
| Certificate error precedence | [`wire.md`](wire.md) 5.3 (extension lengths, signature value), 5.4 checks 5 and 7: bad DER in the self-signature is `malformed`; out-of-range scalars are `self_signature_invalid`. | `session-cert.json` `self_signature_*`, `identity_key_compressed`, `identity_signature_*`, `precedence_*` |
| Replay inputs for attempt sequences | [`wire.md`](wire.md) 10.6, "Random draws". | `pairing-attempts.json` `draws`, `ticket`, `conventions`, each step's `out` |
| Parser edge cases | [`wire.md`](wire.md) 3, "Which error" (indefinite lengths are `non_canonical`); 10.2 link form (length 1 mod 4, unused bits); 10.2.1 (IPv6 as its address, DNS lowercased). | `cbor.json` `invalid`; `ticket.json` `fragment_length_1_mod_4`, `fragment_unused_bits_set`, `route_hints` |
| Draft-only CPace outputs | [`cpace.md`](cpace.md) 2 and 7: `o_cat`, `transcript_oc` and the sid output are not used and their vectors are informative. | `cpace-ristretto255-sha512.json` (informative entries) |
| Renewal retry timing | [`wire.md`](wire.md) 6, "Renewal": each wait starts when its retry actually runs; a retry skipped while a candidate is coming up still counts and is not made up. | `session-lifecycle.json` `retry_while_candidate` |
| Which messages attempt logs list | [`wire.md`](wire.md) 8 step 1: logs leave out both `HELLO`s and start at `JOIN_PROOF`; replies to `submit_first`, `redeliver` and `inject` are recorded but not delivered. | `pairing-attempts.json` `description` |
| First renewal tick with a candidate pending | [`wire.md`](wire.md) 6, "Renewal": the first request is skipped but counts, and the 30 s wait starts at that tick. | `session-lifecycle.json` `candidate_at_first_renewal` |
| Transport close on a failed flow | [`wire.md`](wire.md) 10.6 rule 9: the joiner sends the step's messages, then `GOAWAY(C)`, unless the connection is already closed; the vectors' `failed` output stands for that `GOAWAY`. | `pairing-e2e.json` `send_link_live_needs_a_pin`, `conventions.outputs`; `pairing-attempts.json` `description` |
