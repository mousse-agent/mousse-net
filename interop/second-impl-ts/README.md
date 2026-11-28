# mousse-net wire protocol in TypeScript

This package implements the version 1 wire records and the pairing exchange
from the protocol spec, and the self-mode relay admission of
`spec/relay.md`. It also draws and reads the direct code of wire.md 10.9
and builds its kind-3 binding (`direct-code.ts`), reads and writes the
minor-4 Pair with IP messages (`JOIN_DIRECT`, `AUTHORIZED` keys 2 and 3),
runs the host side of Pair with IP (`direct-host.ts`: invitations, lookup,
attempts, approval requests, provisional grants that commit on the first
stream frame, the host gate's "commit first" and cancel exception of
wire.md 8.1, and recovery), runs the joiner side
(`direct-joiner.ts`: the typed address and code, the attempt ledger and
the pending record with their compare-and-swap writes, first contact,
recovery and cancel, and the first stream once paired, which commits the
host's provisional grant), and runs the caller's
pairing-only gate (wire.md 8.2). A TLS transport supplies the peer identity and the two TLS
exporters. The package issues and verifies session certificates,
signs and verifies TLS CertificateVerify bytes, and checks the negotiated
handshake against the native TLS policy. The transport configures TLS from
that policy, verifies CertificateVerify, and checks the host certificate
before sending the caller certificate. The vector replays run without a
network connection.

The caller passes the ticket's arrival source and supplies one durable
`JoinerFlowStore` per endpoint. All arrival sources share that store. The
store atomically replaces a record only when its previous bytes match. The
pairing flow saves each debit and its pending outcome before releasing the
corresponding message and saves the pin before clearing the pending mark.
A persistent host grant store writes the entire grant and its enrollment
receipt together. Before dispatching a privileged operation on a host-opened
stream, the caller checks the role returned by `hostStreamRole` against the
operation's required role using its own endpoint's grants.

The installed app or a trusted web-client origin supplies the pairing code.
A handoff page passes the ticket along without receiving a code. The app
reports the local `in_person_from_link` and `own_ticket` errors as
`PAIRING_FAILED` and presents the warning in wire.md §10.6 on code failure.

Run these commands from this directory with Node 24.

```powershell
npm ci
npm run check
npm test
```

The tests print case counts by vector file and end with `PASS second-impl` or
`FAIL second-impl`. They replay sixteen pairing flows,
twelve attempt sequences and the fifty-three Pair with IP host sequences
of `direct-host.json` (with its `before_msg_a` section) with the supplied
random draws, and compare the resulting messages and host events byte for
byte. The fourteen Pair with IP end-to-end sequences of `direct-joiner.json`
run the joiner against that host (or a fake host) from their draws and
compare every message, close and record write in order, then the joiner's
state, ledger, pending record and pin and the host's grant. The two kind-3 CPace runs (`pairing_runs`) are rebuilt from their
inputs, from `D`, `CI` and `sid` to `ISK` and both confirmations. The relay tests rebuild every relay
derivation and the relay certificate, decode and re-encode every relay message,
and replay the twenty-five self-mode relay scenarios with their draws,
comparing every output in order. The suite also checks retry
scheduling with a candidate path, clock rollback, reconnect after ticket
expiry, and mux stream ordering, closure, and limits.

Run the same tests with the identity-signature check deliberately disabled.

```powershell
$env:MOUSSE_SECOND_BREAK = 'verifier'
npm test
Remove-Item Env:MOUSSE_SECOND_BREAK
```

That run must exit with status 1 and fail
`delegation_over_wrong_tls_key`. See [SPEC-GAPS.md](SPEC-GAPS.md) for the
choices needed to replay the fixtures.
