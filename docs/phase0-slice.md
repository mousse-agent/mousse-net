# Phase 0 thin slice

The thin slice pairs two machines, runs a terminal from one on the other,
then removes the grant: the live terminal closes at once and the next
connection is refused. It runs on `mousse-net-io` and the `mousse-helper`
binary.

Pairing is in person by default: the host owner answers "Is the device next
to you?" for every request; nothing approves a device the owner has not
seen. With a send link (`invite --link`) the host shows a 6-digit code, a
fresh one for each attempt, and `join` asks for it; the code is checked
with CPace, and three wrong codes end the invitation.

## Joining

- How the ticket arrived matters. An in-person ticket pairs only when it
  was scanned from the host's screen: `join --in-person` (and
  `slice-check --in-person`) says so. Without the flag a ticket counts as
  sent (pasted or opened as a link), and an in-person one is refused with
  `PAIRING_FAILED` before anything is sent.
- The name in the join proof: in person `--name` or this computer's name;
  with a send link the computer name only, since the far end has not yet
  shown it is the real host (`--name` is not used).
- A rejected code shows "That code didn't work. If you typed it exactly as
  shown on the other device, the link may have been swapped; get a new one
  another way." The attempts left are kept per ticket in the endpoint's
  owner-only state (`joins/<ticket hash>.cbor`), so closing the helper and
  opening the link again does not give three new tries. Each attempt is
  saved before its first message goes out; if the save fails, nothing is
  sent.
- After sending its join proof the joiner waits 10 s for the host's answer,
  then closes with `NOT_AUTHORIZED`.
- Any certificate failure on a candidate address means "try the next one".
  An error shows only when no address passed, the clock message (the
  certificate is outside its time window) first. Another device at an
  address alone reads as `pin_mismatch`.

## Connections

- TLS 1.3 only, both sides authenticated, no resumption or early data. Key
  exchange offers X25519MLKEM768 then X25519 and requires X25519MLKEM768;
  there is no switch to turn it off.
- A connection ends at its deadline on the wall clock or the same span on
  the monotonic clock from when it started, whichever comes first. Both
  are read again at least once a second, so a device that slept past either
  closes as soon as it resumes, and setting the clock back never extends a
  connection.
- The host opens no stream on a connection before the caller has opened
  one.

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
- a second process for the same endpoint does not start;
- send link: the right code pairs and the grant carries the computer name
  only; three wrong codes end the invitation, a fresh code is shown for
  each attempt, the same device opening the link again has no tries left
  and another device is refused;
- an in-person ticket used without `--in-person` is refused before the
  owner is asked;
- removing the grant kills a silent command even after the caller finished
  sending (its stdin was empty);
- two devices join with one in-person ticket: "yes" to the question about
  the first pairs only the first, though the second asked meanwhile;
- the state folder, `control.json` and the control channel (the Windows
  pipe, the Unix socket) are owner-only;
- a `control.json` left by an older build does not stop `id`, `grants` and
  `remove` from working offline;
- `slice-check` runs end to end on loopback, and names chosen by the other
  device (with newlines and terminal escapes) print escaped in `serve`'s
  log, `invite`, `grants`, `peers` and the `slice-check` lines.

The tests run a private copy of the helper and first check, with
`mousse-helper --version` (`<version> build <id> control <cfg or none>`),
that it is the build they were compiled with. Cargo writes every build of
the helper to the same path whatever its flags, so a control build in the
same target folder would otherwise swap the binary under a running suite
(with `keep-removed-grant`, the removal tests then time out waiting for the
terminal to close). Give each configuration its own `CARGO_TARGET_DIR`.

## Local state and the control channel

The endpoint's state folder and every file the helper writes in it are
owner-only: on Windows a protected DACL that allows the current user alone,
on Unix `0700` folders and `0600` files. Opening the folder applies this
again to everything already in it, so files from an older build, or ones
that gained a wider access entry, are owner-only again. `serve` takes local
commands (`invite`, `grants`, `remove`, `stop`) over a control channel: on
Windows a named pipe that only the current user can open and that refuses
remote clients; on Unix a socket, `control.sock`, in the owner-only state
folder. On Unix each side checks the other's user id from the socket
(`SO_PEERCRED` or `getpeereid`): `serve` drops connections from another
user, and a command sends its token only to a listener run by its own user.
Commands always look for the socket in the state folder, never at an
address read from a file, so a `control.json` left by a crash cannot point
them elsewhere. A socket path is short (104 bytes on macOS), so the state
folder's path must stay under about 90 characters; `serve` says so if not. `control.json` holds where it listens and a random token
that every request must carry. A `control.json` that is not
in the current layout (an older build wrote `port`) counts as no `serve`
running, so the commands take their offline path.

Names another device chose (its device name on the host, the host's name on
the caller) are printed with control characters, newlines, bidirectional
and invisible formatting characters and backslashes escaped, so a name
cannot start a fake log line or drive the terminal.

An in-person approval question names its request: the joining connection
and the device shown. `invite` answers with that request id, so an answer
never applies to another device or to a newer request.

A removal or denial ends access at once. If saving the grant table fails,
`remove` reports it; the host retries the save every second, and if it
stops before a retry works the grant is back after a restart.

A new grant is saved before the joiner is told it is paired. If that save
fails, the pairing fails with `INTERNAL_ERROR` and the host keeps no grant,
so no device holds a pin for a host that would forget it on restart.

The owner test kit runs the same suite and its controls:

```
mousse-check phase0 --only phase0.thin-slice-loopback
```

### Must-fail controls

Each control is a compile-time cfg and only builds with debug assertions:

```
RUSTFLAGS='--cfg mousse_control="skip-pin-check"' cargo test -p mousse-helper --test loopback --no-fail-fast
```

| Control | Breaks | Tests that fail (of 10) |
|---|---|---|
| `skip-pin-check` | the dialler accepts a host whose identity does not match the pin | 2 |
| `keep-removed-grant` | removing a grant leaves it in force | 4 |
| `shared-endpoint-state` | every endpoint on the machine uses one key and one grant table | 3 or more (5 in the last run: endpoints of tests running at the same time collide) |
| `allow-break-env` | lets `serve` read `MOUSSE_HELPER_BREAK` (cross-machine control) | none on its own |

Use a separate `CARGO_TARGET_DIR` for control builds.

## Across machines: the PC dials the Mac over the LAN

The Mac listens and the PC only dials. Both sides keep the key in a plain file
(`--insecure-file-key`) because the Mac side runs over ssh.

Both binaries carry their build id, fixed when they are compiled:
`<commit>[-dirty]+<profile>`, where dirty means any uncommitted change
(untracked files included, except `checks/results` and `checks/runs`).
`MOUSSE_BUILD_ID` set at build time replaces it, for example when the
source was copied without its git folder. `serve` prints it in its `ready`
line (`ready <device> port <port> build <id> routes ...`).

Mac:

```
mousse-helper --state ./mac-state --insecure-file-key init
mousse-helper --state ./mac-state --insecure-file-key serve --listen-ip 0.0.0.0 --name mac-mini
mousse-helper --state ./mac-state --insecure-file-key invite --no-qr
```

`invite` asks "Is the device next to you?" when the PC joins; answer `y`.
A scripted run feeds the answer on its standard input.

PC (Windows):

```
mousse-helper --state J:\...\pc-state --insecure-file-key init
mousse-helper --state J:\...\pc-state --insecure-file-key slice-check --in-person --name pc ^
  --route tcp://192.168.0.59:58505 --ticket <TICKET> --host-build <MAC BUILD> ^
  --out result.json -- uname -a
```

After pairing, `slice-check` asks the host for its build over a
`helper-info` stream: it finishes its side of the stream at once, and the
host answers once that `FIN` arrives (within 5 s, else it resets the
stream), so the stream ends cleanly on both sides. `--host-build` (copied from the Mac's `ready` line)
fills in when the run never gets that far, as in the control below; when
both exist they must agree.

When the PC prints `WAITING`, the Mac removes the grant:

```
mousse-helper --state ./mac-state --insecure-file-key grants
mousse-helper --state ./mac-state --insecure-file-key remove 1
```

### Run on 2026-11-18

Build `165425b+debug`, Windows 11 x64 dialling macOS 25.6 arm64. The same
run was repeated on the build with core's CPace, caller gate and HELLO
negotiation; its result file goes to the owner test kit to be signed.

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
`MOUSSE_HELPER_BREAK=wrong-identity`. Tickets and pairing use the endpoint's
real key; only TLS presents a fresh one, so the PC's pin check is the one
thing that fails. The PC must refuse, for that reason:

```
FAIL pair in person: tcp://192.168.0.59:58505: another device answered (pin mismatch) reason=pin_mismatch
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
  "build": "<commit>+debug",
  "caller_build": "<commit>+debug",
  "host_build": "<commit>+debug",
  "details": "PASS paired with ...; PASS the host runs build ...; PASS terminal ran ...; PASS removal closed the live terminal with GRANT_REVOKED; PASS a new connection was refused: ..."
}
```

`build` and `caller_build` are the PC's build, `host_build` the Mac's. The
control run adds `"control": "wrong-identity"`, `"outcome": "FAIL"` and
`"reason": "pin_mismatch"`.
