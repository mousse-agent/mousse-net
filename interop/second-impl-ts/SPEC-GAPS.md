# Spec gaps

## Resolved

| Original gap | Spec section and rule |
| --- | --- |
| Join proof timing | `wire.md` §8 and §10.3. Send `JOIN_PROOF` immediately after the joiner's `HELLO`. The host runs step 2 at connection start and ignores the proof if it found a live grant. |
| Messages after an attempt ends | `wire.md` §8.1 and §10.7. Apply the gate first. An identical exchange payload gets the cached reply. `CODE_ABORT` ends the attempt and preserves the cached payload and reply. |
| Responder draws on a bad first message | `wire.md` §10.6 and `cpace.md` §5.3. Debit the attempt and draw the next code (if needed) and responder scalar before parsing the first message. |
| Repeated `HELLO` | `wire.md` §2. The first `HELLO` fixes the version. Ignore any later `HELLO`. |
| Certificate error precedence | `wire.md` §§5.3–5.4. The verifier checks extension lengths at the identity key and raw-signature steps. Malformed self-signature DER fails the profile check. Well-formed out-of-range scalars fail the self-signature check. |
| Inputs for attempt replays | `wire.md` §10.6 and `pairing-attempts.json` conventions. The fixture supplies the ticket, draws, exporter derivation and expected wire bytes. |
| CBOR, link and route parsing | `wire.md` §§3, 10.2 and 10.2.1. The spec defines CBOR error precedence, canonical unpadded base64url and IPv6 address equality. The route fixture gives the 16 IPv6 bytes in hex. |
| Draft-only CPace outputs | `cpace.md` §§2 and 7. Ordered concatenation, its derived values and the CPace sid output are informative. Mousse pairing uses the initiator-responder transcript and the supplied sid. The vector runner also verifies the informative draft values. |
| Renewal retry timing | `wire.md` §6 and `session-lifecycle.json` (`retry_while_candidate`). Each wait starts when its retry actually runs. A retry that falls due while a candidate is coming up is skipped but counts as run: the next wait starts then and doubles, and the skipped retry is not made up when the candidate fails. |
| Attempt replay logging | `wire.md` §8 step 1 and the `pairing-attempts.json` description. `out` leaves out both HELLOs; a replay over real connections exchanges them and compares from `JOIN_PROOF`. For `submit_first`, `redeliver` and `inject`, the host's reply is recorded but not delivered. Each side keeps its own send order; on connect the joiner's sends are listed before the host's. |

## Open

None.

The browser Worker certificate is pending in `session-cert.json` and
has no certificate bytes.
