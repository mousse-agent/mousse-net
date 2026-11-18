# Phase 0 thin slice

The thin slice pairs two machines in person, runs a terminal from one on the
other, then removes the grant: the live terminal closes at once and the next
connection is refused. It runs on `mousse-net-io` and the `mousse-helper`
binary.

## On one machine

```
cargo test -p mousse-net-io
cargo test -p mousse-helper --test loopback --no-fail-fast
```

`mousse-helper/tests/loopback.rs` drives the real binary over loopback TCP:

- pair in person, run a terminal, remove the grant: the terminal closes with
  `GRANT_REVOKED` and a new connection is refused with `NOT_AUTHORIZED`;
- rejections: a host presenting another identity, a used ticket, a declined
  pairing;
- two endpoints on one computer stay separate: removing B's peer closes only
  B's channels, A's terminal stays open and A reconnects after a restart, and
  A's peer cannot reach B;
- a second process for the same endpoint does not start.

### Must-fail controls

Each control is a compile-time cfg and only builds with debug assertions:

```
RUSTFLAGS='--cfg mousse_control="skip-pin-check"' cargo test -p mousse-helper --test loopback --no-fail-fast
```

| Control | Breaks | Tests that fail (of 4) |
|---|---|---|
| `skip-pin-check` | the dialler accepts a host whose identity does not match the pin | rejections, two endpoints |
| `keep-removed-grant` | removing a grant leaves it in force | pair and remove, two endpoints |
| `shared-endpoint-state` | every endpoint on the machine uses one key and one grant table | rejections, two endpoints |
| `allow-break-env` | lets `serve` read `MOUSSE_HELPER_BREAK` (cross-machine control) | none on its own |

Use a separate `CARGO_TARGET_DIR` for control builds.

## Across machines: the PC dials the Mac over the LAN

The Mac listens and the PC only dials. Both sides keep the key in a plain file
(`--insecure-file-key`) because the Mac side runs over ssh.

Mac:

```
mousse-helper --state ./mac-state --insecure-file-key init
mousse-helper --state ./mac-state --insecure-file-key serve --listen-ip 0.0.0.0 --name mac-mini
mousse-helper --state ./mac-state --insecure-file-key invite --approve-next --no-qr
```

PC (Windows):

```
mousse-helper --state J:\...\pc-state --insecure-file-key init
mousse-helper --state J:\...\pc-state --insecure-file-key slice-check --name pc ^
  --route tcp://192.168.0.59:58505 --ticket <TICKET> --out result.json -- uname -a
```

When the PC prints `WAITING`, the Mac removes the grant:

```
mousse-helper --state ./mac-state --insecure-file-key grants
mousse-helper --state ./mac-state --insecure-file-key remove 1
```

### Run on 2026-11-18

Build `165425b+debug`, Windows 11 x64 dialling macOS 25.6 arm64.

PC:

```
PASS paired with mac-mini (8d1430a165e6c6c2) via tcp://192.168.0.59:58505 using X25519MLKEM768
PASS terminal ran "uname -a": Darwin Avarnics-Mac-mini.local 25.6.0 Darwin Kernel Version 25.6.0: ... RELEASE_ARM64_T8132 arm64
WAITING remove this device on the host (grant for "pc") within 240 s
PASS removal closed the live terminal with GRANT_REVOKED
PASS a new connection was refused: the host does not know this device (NOT_AUTHORIZED)
RESULT PASS
```

Mac:

```
"pc" (a92dee2caa85df5b) wants to pair. Is the device next to you? [y/N] y (--approve-next)
paired: grant 1 for a92dee2caa85df5b
connected a92dee2caa85df5b from 192.168.0.9:18989
enrolled grant 1 a92dee2caa85df5b
grant 1 closed 1 connection(s)
closed a92dee2caa85df5b: closed here (grant_revoked)
connected a92dee2caa85df5b from 192.168.0.9:19010
closed a92dee2caa85df5b: closed here (not_authorized)
```

An earlier run without `--route` paired over the first route in the ticket
(a VPN address) and also passed; `--route` pins the run to the LAN.

### Control: the Mac presents another identity

The Mac runs a build with `--cfg mousse_control="allow-break-env"` and
`MOUSSE_HELPER_BREAK=wrong-identity`, so the listener uses a fresh key while
its tickets name the real one. The PC must refuse:

```
FAIL pair in person: tcp://192.168.0.59:58505: another device answered (pin mismatch)
RESULT FAIL
```

Mac: `refused 192.168.0.9:19038: TLS handshake failed: received fatal alert: CertificateUnknown`.

### Result file

`slice-check --out` writes JSON that `mousse-check sign` can sign:

```json
{
  "check": "phase0.thin-slice-cross-machine",
  "target": "pc-to-mac-lan",
  "outcome": "PASS",
  "build": "165425b3351193d57c7e7be02b9b7367dde74c0c+debug",
  "details": "PASS paired with ...; PASS terminal ran ...; PASS removal closed the live terminal with GRANT_REVOKED; PASS a new connection was refused: ..."
}
```

The control run adds `"control": "wrong-identity"` and has `"outcome": "FAIL"`.
