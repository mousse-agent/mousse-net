# Spec gaps

## Resolved

| Original gap | Spec section and rule |
| --- | --- |
| Join proof timing | `wire.md` §8 and §10.3. Send `JOIN_PROOF` immediately after the joiner's `HELLO`. A live host gives its step 2 notice and then answers the proof separately. |
| Messages after an attempt ends | `wire.md` §8.1 and §10.7. Apply the gate first. On the same TLS session, a repeat during an attempt fails the attempt and a message for an ended attempt gets `CODE_ABORT` without another debit. On a different TLS session, that ID represents a new attempt and spends a debit. |
| Responder draws on a bad first message | `wire.md` §10.6 and `cpace.md` §5.3. The replay follows the harness convention and draws the next code (if needed) and responder scalar before parsing the first message. |
| Repeated `HELLO` | `wire.md` §2. The first `HELLO` fixes the version. Ignore any later `HELLO`. |
| Certificate error precedence | `wire.md` §§5.3–5.4. The verifier checks extension lengths at the identity key and raw-signature steps. Malformed self-signature DER fails the profile check. Well-formed out-of-range scalars fail the self-signature check. |
| Inputs for attempt replays | `wire.md` §10.6 and `pairing-attempts.json` conventions. The fixture supplies the ticket, draws, exporter derivation and expected wire bytes. |
| CBOR, link and route parsing | `wire.md` §§3, 10.2 and 10.2.1. The spec defines CBOR error precedence, canonical unpadded base64url and IPv6 address equality. The route fixture gives the 16 IPv6 bytes in hex. |
| Draft-only CPace outputs | `cpace.md` §§2 and 7. Ordered concatenation, its derived values and the CPace sid output are informative. Mousse pairing uses the initiator-responder transcript and the supplied sid. The vector runner also verifies the informative draft values. |
| Renewal retry timing | `wire.md` §6 and `session-lifecycle.json` (`retry_while_candidate`). Each wait starts when its retry actually runs. A retry that falls due while a candidate is coming up is skipped but counts as run: the next wait starts then and doubles, and the skipped retry is not made up when the candidate fails. |
| Attempt replay logging | `wire.md` §8 step 1 and the `pairing-attempts.json` description. `out` leaves out both HELLOs; a replay over real connections exchanges them and compares from `JOIN_PROOF`. For `submit_first`, `redeliver` and `inject`, the host's reply is recorded but not delivered. Each side keeps its own send order; on connect the joiner's sends are listed before the host's. |
| First renewal tick with a candidate pending | `wire.md` §6 and `session-lifecycle.json` (`candidate_at_first_renewal`). The first request at the renewal time follows the skipped-retry rule: it is skipped but counts, and the 30-second wait starts at that tick. |
| Transport close on a failed flow | `wire.md` §10.6 rule 9 and the `pairing-e2e.json` and `pairing-attempts.json` conventions. When the joiner's flow fails with code C, it sends any message the same step produced, then one `GOAWAY(C)`, unless the host already closed the connection or it broke. The vectors do not list that `GOAWAY`; the `failed` output stands for it. A failed attempt sends only `CODE_ABORT` and keeps the connection. |

## Open

- `wire.md` §10.3 specifies `<computer> (<profile>)` for an in-app scan.
  The in-person fixtures supply only a flat name, such as `Phone`. The
  replay uses the supplied name and the pairing API formats both parts when
  a profile label is supplied. Send-link proofs use only the computer name.
- `wire.md` §8.2 specifies a 10-second proof timeout with
  `NOT_AUTHORIZED`. It leaves retry policy after that timeout while
  recovering a lost `PAIRED` to the caller. This package treats that
  timeout as a terminal flow failure.

The browser Worker certificate is pending in `session-cert.json` and
has no certificate bytes.
