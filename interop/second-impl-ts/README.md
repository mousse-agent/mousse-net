# mousse-net wire protocol in TypeScript

This package implements the version 1 wire records and the pairing exchange
from the protocol spec. A TLS transport supplies the peer identity and the
two TLS exporters. The package can issue and verify session certificates,
and can sign and verify the bytes passed to a TLS CertificateVerify
operation. It runs the vector replays without a network connection.

Run these commands from this directory with Node 24.

```powershell
npm ci
npm run check
npm test
```

The tests print case counts by vector file and end with `PASS second-impl` or
`FAIL second-impl`. They replay eight pairing flows and
eleven attempt sequences with the supplied random draws, and compare
the resulting messages byte for byte. The suite also checks retry
scheduling with a candidate path, reconnect after ticket expiry, and mux
stream ordering, closure, and limits.

Run the same tests with the identity-signature check deliberately disabled.

```powershell
$env:MOUSSE_SECOND_BREAK = 'verifier'
npm test
Remove-Item Env:MOUSSE_SECOND_BREAK
```

That run must exit with status 1 and fail
`delegation_over_wrong_tls_key`. See [SPEC-GAPS.md](SPEC-GAPS.md) for the
choices needed to replay the fixtures.
