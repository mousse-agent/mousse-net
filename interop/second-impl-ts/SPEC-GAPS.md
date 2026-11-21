# Spec gaps

## Resolved

| Original gap | Spec section and rule |
| --- | --- |
| Join proof timing | `wire.md` §8 and §10.3. Send `JOIN_PROOF` immediately after the joiner's `HELLO`. A live host gives its step 2 notice and then answers the proof with `AUTHORIZED` or an enrollment receipt in `PAIRED`. |
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
| In-person name and profile label | `wire.md` §10.3. In-person proofs combine both fixture fields, for example `Phone (Work)`. Send-link proofs use only the computer name. |
| Live-grant proof answer in the connect convention | `wire.md` §8 step 3. The `pairing-e2e.json` convention now says the proof gets `PAIRED` when the grant's receipt names this invitation, else a second `AUTHORIZED`. |
| `wss` route hints | `wire.md` §10.2.1. The `<port>` rule said the port is the text after the last `:`, which does not fit a `wss` hint, whose port is optional and comes before the path; and "vectors give the port explicitly" read as if hints carried it. The spec now says the host and port end at the first `/` after `wss://`, the port follows a `:` after the host (after `]` for IPv6), and a vector's result gives the port, 443 when the hint has none. |
| Proof timeout while learning a lost `PAIRED` | `wire.md` §10.6 rule 7. The flow ends with `NOT_AUTHORIZED` and leaves the pending mark stored. Reopening the ticket can resume recovery. |
| Relay default limits | `relay.md` §13. The defaults table gives every relay limit, and the vectors assume it unless a scenario's `limits` says otherwise. It includes `RELAY_MAX_CONNECTIONS` and `RELAY_CONNECTIONS_PER_IP`. |
| Relay address key | `relay.md` §13 ("Address key"). The key is 16 bytes: IPv4 in bytes 0 to 3 with byte 15 set to 4, or an IPv6 /64 in bytes 0 to 7 with byte 15 set to 6. In the vectors it is opaque and only equality matters. |
| What counts per address | `relay.md` §13 ("What counts"). Every open connection counts, whatever its role, from `RELAY_HELLO` until it closes. An accept leg leaves its address key's count once its `ACCEPT` is accepted. A connection over either connection limit is closed with 4006 and draws no nonce. |
| Start of the registration waits | `relay.md` §6. The `REGISTER` or `ENROLL` starts the registration idle wait, and `REGISTERED` starts the keepalive. |
| Relay firing order | `relay.md` §6. Due monotonic waits fire first, by time, then table row, then connection number. Then wall-clock items fire, whenever each came due: join expiries in order of the caller's leg, then key drops in order of fingerprint. |
| Join expiry and promotion | `relay.md` §9.3. A waiting join circuit at its expiry closes only the joiner's leg with 4006. A promoted circuit is no longer a join circuit, so neither the budget nor the expiry applies to it. |
| Accept proof key | `relay.md` §10.1 rule 2. The proof is checked against the key the handle is derived from, which is kept with the circuit, so an accept still works after the registration has closed or been replaced. |
| Close order on revocation and key drop | `relay.md` §10.3. The registration connection closes first, then each circuit in order of its caller's leg, the caller's leg before the accept leg. |
| Revocation output | `relay.md` §14. The operator's command has already changed the stored list, so `revoke` gives only the closes and no durable output. |
| Peer data on a leg that is not spliced | `relay.md` §14. `data` on a connection that is not a spliced leg is a protocol error (close 1002). A `recv` on a spliced leg is peer data of the message's length. |
| `SUCCESSOR` naming a listed key | `relay.md` §7.4 rule 4. A new key already on the authorized list, in any state, gets `REFUSED(not_authorized)`, and the registration closes with 1000. `successor_unauthorized_current` tests this in its last step. |
| Relay certificate signature | `relay.md` §2.1. Only `tbsCertificate` is fixed byte for byte. The vector certificate is signed with RFC 6979 nonces and no low-S normalization, so signing the same way reproduces it. |
| Relay pin check | `relay.md` §2.1. The pin check judges only the leaf's SPKI. A certificate off the profile passes if its key matches the pin. |
| Writing an enrollment link | `relay.md` §11. A reader accepts any host text that the `tcp` grammar accepts. A relay writes IPv4 in dotted decimal, IPv6 in RFC 5952 form in brackets and a DNS name in lowercase, and links in that form print back unchanged. |
| Join `INCOMING` class and hosted-only bounds | `relay.md` §4.3. The relay always sends class 0 in a join's `INCOMING`. Hosted-only fields are bounded only by the 16 384-byte message maximum until hosted mode sets their bounds. |
| Connection numbers in the vectors | `relay.md` §6. A running relay numbers connections in the order they open; in the vectors the numbers are the scenarios' `conn` values, whatever order those open in. Ties are ordered by number. |

## Open

The browser Worker certificate is pending in `session-cert.json` and
has no certificate bytes.
