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
| [`relay.md`](relay.md) | **Normative.** The relay protocol, version 1: the outer connection, relay messages, proofs, admission, splicing, self-hosted authorization. |
| [`vectors/`](vectors/README.md) | Test vectors for everything in `wire.md` and `relay.md`, including rejection vectors. |
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
| When the join proof is sent | [`wire.md`](wire.md) 8, 10.3: the joiner sends `JOIN_PROOF` on every connection right after its own `HELLO`; the host runs step 2 at once, says nothing while it awaits a proof, and answers the proof under a live grant with a second `AUTHORIZED`, or with `PAIRED` when the grant's enrollment receipt names its invitation. | `pairing-e2e.json` `connect` steps, `outcome_after_lost_paired` |
| Messages after an attempt ends | [`wire.md`](wire.md) 10.7, "No resends": the gate first; an ended attempt gets `CODE_ABORT` with no work; on a running attempt every payload is the next message, so a repeat fails the attempt. | `pairing-attempts.json` `messages_after_the_joiner_aborted`, `different_payload_on_a_running_attempt_is_the_next_message`, `a_repeated_message_fails_the_attempt` |
| Responder draw order on a bad first message | [`wire.md`](wire.md) 10.6, "Random draws in the vectors"; [`cpace.md`](cpace.md) 5.3: a convention of the vector harness, not a requirement. | `pairing-attempts.json` `bad_first_message_still_uses_the_draws` |
| Repeated `HELLO` | [`wire.md`](wire.md) 2, "Only the first `HELLO` counts". | `hello.json` `repeated` |
| Certificate error precedence | [`wire.md`](wire.md) 5.3 (extension lengths, signature value), 5.4 checks 5 and 7: bad DER in the self-signature is `malformed`; out-of-range scalars are `self_signature_invalid`. | `session-cert.json` `self_signature_*`, `identity_key_compressed`, `identity_signature_*`, `precedence_*` |
| Replay inputs for attempt sequences | [`wire.md`](wire.md) 10.6, "Random draws". | `pairing-attempts.json` `draws`, `ticket`, `conventions`, each step's `out` |
| Parser edge cases | [`wire.md`](wire.md) 3, "Which error" (indefinite lengths are `non_canonical`); 10.2 link form (length 1 mod 4, unused bits); 10.2.1 (IPv6 as its address, DNS lowercased). | `cbor.json` `invalid`; `ticket.json` `fragment_length_1_mod_4`, `fragment_unused_bits_set`, `route_hints` |
| Draft-only CPace outputs | [`cpace.md`](cpace.md) 2 and 7: `o_cat`, `transcript_oc` and the sid output are not used and their vectors are informative. | `cpace-ristretto255-sha512.json` (informative entries) |
| Renewal retry timing | [`wire.md`](wire.md) 6, "Renewal": each wait starts when its retry actually runs; a retry skipped while a candidate is coming up still counts and is not made up. | `session-lifecycle.json` `retry_while_candidate` |
| Which messages attempt logs list | [`wire.md`](wire.md) 8 step 1: logs leave out both `HELLO`s and start at `JOIN_PROOF`; replies to `submit_first`, `redeliver` and `inject` are recorded but not delivered. | `pairing-attempts.json` `description` |
| First renewal tick with a candidate pending | [`wire.md`](wire.md) 6, "Renewal": the first request is skipped but counts, and the 30 s wait starts at that tick. | `session-lifecycle.json` `candidate_at_first_renewal` |
| Transport close on a failed flow | [`wire.md`](wire.md) 10.6 rule 9: the joiner sends the step's messages, then `GOAWAY(C)`, unless the connection is already closed; the vectors' `failed` output stands for that `GOAWAY`. | `pairing-e2e.json` `send_link_live_needs_a_pin`, `conventions.outputs`; `pairing-attempts.json` `description` |
| In-person name and profile label | [`wire.md`](wire.md) 10.3: in person sends `<computer> (<profile>)`, send link `<computer>`; the vectors give both parts. | `pairing-e2e.json` `conventions.joiner`; `pairing-attempts.json` `conventions.joiners` |
| Proof timeout while learning a lost `PAIRED` | [`wire.md`](wire.md) 10.6 rule 7, "A proof that gets no answer ends the flow": terminal, no automatic reconnect; the pending mark stays, so reopening the ticket asks again. | `pairing-e2e.json` `lost_paired_then_proof_timeout` |

## Design review of the session certificate and pairing binding

| Finding | Rule | Vector |
|---|---|---|
| A swapped link could claim "in person" and skip the code | [`wire.md`](wire.md) 10.1: the app passes how the ticket arrived; kind 1 only from an in-app scan, otherwise `PAIRING_FAILED` before dialing. | `pairing-e2e.json` `swapped_in_person_link` |
| A joiner with no pin could not pair again while the host still held its grant | [`wire.md`](wire.md) 8 step 3, 8.1, 8.2, 10.6 rule 8, 10.8: a live connection may carry one proof; a valid one starts a pairing that replaces the grant; the caller waits for the answer. | `pairing-e2e.json` `re_pair_while_granted`; `authz.json` `live_grant_*`, `proof_*` |
| Outcome and attempt count lost when the app is killed or the link reopened | [`wire.md`](wire.md) 10.7: the joiner's flow record, keyed by ticket hash. | `pairing-e2e.json` `joiner_cap_survives_reopening` |
| TLS policy left to the implementation | [`wire.md`](wire.md) 5.4, "TLS policy"; 2, "Security requirements never weaken". | none (checked by the I/O layer) |
| Wrong address read as a clock problem | [`wire.md`](wire.md) 5.4: the pin is checked before the window. | `session-cert.json` `precedence_pin_before_window`, `expired_with_no_pin` |
| Guessing bound and the message after a failed code | [`threat-model.md`](threat-model.md); [`wire.md`](wire.md) 10.6 rule 6. | `pairing-e2e.json` `joiner_cap_survives_reopening` |
| What the identity key signs | [`wire.md`](wire.md) 4.1, "What the identity key signs". | `session-cert.json` |
| Version coupling | [`wire.md`](wire.md) 2: ALPN major, certificate extension version and record version agree; ticket version 1 fixes CPace profile 1. | `session-cert.json`, `ticket.json` |
| Pairing with itself | [`wire.md`](wire.md) 10.1, 10.3. | `pairing-e2e.json` `own_ticket`; `pairing-attempts.json` `join_proof_from_own_identity` |
| Resend cache and cross-session replay rule | Removed ([`wire.md`](wire.md) 10.7): debit first stays; a replayed attempt id on another session is a new, debited attempt that cannot succeed. | `pairing-attempts.json` `attempt_replayed_on_another_connection_is_debited` |
| Setting the wall clock back | [`wire.md`](wire.md) 6: a connection is also capped by monotonic time. | `session-lifecycle.json` `clock_rollback` |

## Final design review before freeze

| Finding | Rule | Vector |
|---|---|---|
| Recovery could report a role change that never committed | [`wire.md`](wire.md) 7 (`enrolled_by`), 8 step 3, 10.6 rule 7, 10.8: the grant keeps an enrollment receipt; the host answers a proof for that invitation with `PAIRED` and its role, and any other live answer is "already paired" with no role change. | `pairing-e2e.json` `outcome_after_lost_paired`, `role_change_not_committed`; `authz.json` `proof_answered_with_paired` |
| Durable writes could trail what they protect | [`wire.md`](wire.md) 10.7: compare-and-swap writes; the debit before `msg_a`, the pending mark before `msg_c`, cleared only once the result and pin are stored. | `pairing-e2e.json` `persist` outputs, `crash_after_pending_mark` |
| A host's grant read as authority over the caller | [`wire.md`](wire.md) 8 steps 4 and 5, 8.2: grants point one way; the caller authorizes host-opened streams against its own grants. | `authz.json` `host_opened_stream_needs_the_callers_grant` |
| Discovery, ticket fragment and code entry disclosures | [`privacy.md`](privacy.md) (mDNS fields, fragment readable by page scripts); [`wire.md`](wire.md) 10.6 step 2 (codes typed only in the app or a trusted origin). | none |
