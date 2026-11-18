# Spec gaps

1. **Join proof timing, wire §§8 and 10.3.** The caller is told to send a
   proof after HELLO if it has no grant, but it cannot know whether the host
   still has a grant. The host sends no message when it starts awaiting a
   proof. The caller sends its proof once it accepts the peer's HELLO. A
   host with a live grant ignores the proof as specified in §8.1.
   The end-to-end fixture groups the proof with the connect event before
   the HELLO delivery rows. The replay groups the output that way without
   sending the proof early.

2. **Retries after a terminal message, wire §§8.1, 10.5 and 10.7.** The
   resend rule says to replay the last reply, while §8.1 says to ignore
   pairing messages once live. The spec also does not say whether
   CODE_ABORT changes which payload counts as the last received one. The
   authorization gate runs first. While join-only, the host caches the last
   CODE_EXCHANGE payload and reply for each session and attempt. CODE_ABORT
   stops that attempt and leaves the cache in place. Another payload on a
   stopped attempt gets CODE_ABORT without a new debit. On a running
   attempt, a different payload is treated as the next CPace message and
   must pass confirmation.

3. **Responder draw order on bad points, CPace §5.3 and wire §10.6.** The
   flow diagram uses the responder scalar before it samples it. The host
   debits and draws its next code first, as the wire spec says. CPace
   validates the incoming point before drawing the responder scalar, then
   computes the share and the shared point. No vector pins the random
   draws for a malformed share.

4. **Repeat HELLO, wire §§2, 8 and 11.** HELLO must be first, yet the
   traffic tables allow it in every state. They do not define a second
   negotiation. The first HELLO fixes the version. Later HELLOs have no
   effect.

5. **Certificate error precedence, wire §§5.3–5.4.** The extension grammar
   specifies fixed lengths, but the verification order calls out key and
   raw-signature errors after the profile check. The verifier treats the
   extension lengths as those later checks. For the outer self-signature,
   malformed DER is a profile error and a well-formed INTEGER outside the
   scalar range is a self-signature error. The latter case has no vector.

6. **Attempt replay inputs, wire §§10.6–10.8 and vectors README.**
   `pairing-attempts.json` provides symbolic codes, connection numbers and
   state checks. It has no fixed random bytes, exporters or expected
   messages. The replay uses deterministic draws and distinct exporters per
   connection, checks every listed outcome, and compares the original and
   resent reply bytes. `pairing-e2e.json` supplies exact inputs and wire bytes
   for all six flows.

7. **Text and parser edge cases, wire §§3 and 10.2.** The CBOR prose lists
   error names without assigning an error to indefinite lengths. The
   vectors use `non_canonical` for allowed types in indefinite form. For
   link fragments the spec names disallowed characters but omits the
   treatment of unused Base64 bits. The decoder requires an exact
   unpadded base64url round trip. Route vectors preserve the spelling of
   embedded-IPv4 IPv6 hints. The spec requires lowercase comparison for DNS,
   and leaves IPv6 display normalization open, so the parser preserves the
   IPv6 text.

8. **Draft-only CPace outputs, CPace §§2 and 7.** Mousse does not negotiate
   ordered concatenation or output a CPace sid. The draft vectors cover
   these anyway. Their calculations follow [draft-21, Appendix A.3 and
   §10.6](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.html).
   Pairing uses only the initiator-responder profile and the supplied sid.

The browser Worker certificate is marked pending in `session-cert.json`.
There are no bytes to verify for it.
