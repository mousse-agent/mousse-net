# Phase 0 design review

Scope: (A) the session certificate and the authorization boundary,
(B) pairing and the CPace binding. Three independent reviewers read the
spec and the code; each finding was fixed before the design froze.

| Round | Reviewed at | Reviewer | A | B | Verdict |
|---|---|---|---|---|---|
| 1 | `3d8baf9` | Reviewer 1 | 8/10 | 6/10 | changes requested |
| 1 | `3d8baf9` | Reviewer 2 | 7/10 | 5/10 | changes requested |
| Final | `f7dba08` | Reviewer 3 | 8/10 | 7/10 | changes requested |
| Sign-off | `533f154` | Reviewer 2 | sign off | sign off | design approved; last code items fixed in `ffcf57b` |

## What changed because of the review

- **Pairing:**
  - Scan provenance is a local input. Kind-1 tickets are accepted only from the app's own scanner, and the command-line flag exists only in test builds.
  - Self-pairing is refused.
  - The pin is checked before the validity window.
  - Codes are entered only in the app or a trusted origin.
- **Recovery:**
  - Each grant keeps the invitation that made it. After a lost `PAIRED`, the device gets `PAIRED` back only for that invitation. Otherwise it learns "already paired", and the invitation's role is not in effect.
  - The joiner debits an attempt durably before the first CPace message, with compare-and-swap. It also marks the outcome pending before its final confirmation.
  - One join per link at a time.
- **Authorization:**
  - A host's grant authorizes the caller on the host only. A caller checks its own grants before acting on a stream the host opened.
  - Pairing steps re-check the gate under the same lock as a removal.
- **Host durability:** an enrollment is recorded as pending, together with the table it replaces. A restart never honors an enrollment that was reported as failed, and never loses an earlier grant.
- **Transport:**
  - Hybrid X25519MLKEM768 is always required on native, with no PSK and no 0-RTT.
  - Deadlines use a clock that counts sleep.
  - A late proof answer is refused at the deadline.
  - Any step-1 failure tries the next address.
- **Local control:** on Unix, the helper's control channel is an owner-only socket with peer-credential checks. Automatic approval is gone.
- **Privacy:** the mDNS fields and the exposure of the link fragment are documented.

## Sign-off

- **session-cert:** the frozen profile binds the exact session SPKI, the validity window and the version to the identity. TLS proves possession, and the caller enforces its pin.
- **cpace-binding:** both confirmations bind:
  - the canonical ticket hash;
  - the mode and the version;
  - the ordered identities and roles;
  - the inner TLS exporter.
  
  The attempt id and the exporter also bind `sid`. This matches CPace draft 21, §§7–10.
- **relay-admission:** reviewed when it freezes in Phase 3.
