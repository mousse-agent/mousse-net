# mousse-net wire protocol in TypeScript

This package implements the version 1 wire records and the pairing exchange
from the protocol spec. A TLS transport supplies the peer identity and the
two TLS exporters. The package issues and verifies session certificates,
signs and verifies TLS CertificateVerify bytes, and checks the negotiated
handshake against the native TLS policy. The transport configures TLS from
that policy, verifies CertificateVerify, and checks the host certificate
before sending the caller certificate. The vector replays run without a
network connection.

The caller passes the ticket's arrival source and supplies one durable
`JoinerFlowStore` per endpoint. All arrival sources share that store. The
store atomically replaces a record only when its previous bytes match. The
pairing flow saves each debit and its pending outcome before releasing the
corresponding message. The app
reports the vector's local `in_person_from_link` and `own_ticket` errors as
`PAIRING_FAILED` and presents the warning in wire.md §10.6 on code failure.

Run these commands from this directory with Node 24.

```powershell
npm ci
npm run check
npm test
```

The tests print case counts by vector file and end with `PASS second-impl` or
`FAIL second-impl`. They replay twelve pairing flows and
twelve attempt sequences with the supplied random draws, and compare
the resulting messages byte for byte. The suite also checks retry
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
