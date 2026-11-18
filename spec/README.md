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
