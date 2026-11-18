# Limits

Every timeout, wait, attempt cap, validity window, retry delay, size and
count in `mousse-net-core`, `mousse-net-io` and `mousse-helper` is a named
default in one place per crate: `Limits` in
`crates/mousse-net-core/src/limits.rs` (the core takes it as a parameter),
`IoLimits` in `crates/mousse-net-io/src/limits.rs` (passed in through
`HostConfig::limits` and `Caller::new`), and `HelperLimits` in
`crates/mousse-helper/src/limits.rs`.

The helper reads `MOUSSE_NET_<NAME>` once at startup. A value must be a
whole number in the unit the name ends with (`_MS`, `_SECS`, `_BYTES`; no
unit means a count). A value that is not a whole number, is out of range,
or disagrees with another limit stops startup with a message that names the
variable and its allowed range. An unknown `MOUSSE_NET_*` name stops startup
too.

Where the peer or a security bound depends on a limit, its range ends at the
spec's value: it can only be tightened.

## Core

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_JOIN_PROOF_WAIT_MS` | 10000 | 1000 to 10000 | Host: time a connection with no grant has to send its `JOIN_PROOF` (wire.md 8). |
| `MOUSSE_NET_KEEPALIVE_MS` | 15000 | 1000 to 15000 | `PING` after this long without sending (wire.md 9.4). |
| `MOUSSE_NET_IDLE_TIMEOUT_MS` | 45000 | 30000 to 45000 | Close after this long without receiving; at least two of the peer's keepalives (wire.md 9.4). |
| `MOUSSE_NET_MAX_PEER_STREAMS` | 1024 | 1 to 1024 | Streams the peer may have open; more are refused (wire.md 9.2). |
| `MOUSSE_NET_SEND_CHUNK_BYTES` | 16384 | 1024 to 16384 | Largest `DATA` payload sent (wire.md 9.4). |
| `MOUSSE_NET_CREDIT_RETURN_BYTES` | 65536 | 1024 to 65536 | Consumed bytes that trigger a `CREDIT` (wire.md 9.3). |
| `MOUSSE_NET_CLOCK_SKEW_SECS` | 600 | 0 to 600 | Clock difference allowed on peer-signed times: certificates, session deadlines, ticket expiry (wire.md 1). |
| `MOUSSE_NET_RENEW_LEAD_SECS` | 1800 | 1800 to 7200 | Renew this long before the earlier `not_after`; only earlier than the spec; below `CERT_LIFETIME_SECS` (wire.md 6). |
| `MOUSSE_NET_RENEW_RETRY_FIRST_SECS` | 30 | 1 to 30 | First wait before asking again for a renewal (wire.md 6). |
| `MOUSSE_NET_RENEW_RETRY_MAX_SECS` | 300 | 1 to 300 | Longest wait between renewal requests; not below the first (wire.md 6). |
| `MOUSSE_NET_TICKET_LIFETIME_SECS` | 600 | 60 to 600 | How long a new pairing ticket is valid (wire.md 10.2). |
| `MOUSSE_NET_HOST_ATTEMPTS_PER_INVITATION` | 3 | 1 to 3 | Code attempts the host allows per invitation (wire.md 10.7). |
| `MOUSSE_NET_JOINER_ATTEMPTS_PER_FLOW` | 3 | 1 to 3 | Code attempts the joiner allows per ticket; the stored record holds at most 3 (wire.md 10.7). |

## I/O

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_PROOF_ANSWER_WAIT_MS` | 10000 | 1000 to 10000 | Caller: wait for the answer to its `JOIN_PROOF` (wire.md 8.2). |
| `MOUSSE_NET_OUTCOME_RETRIES` | 4 | 0 to 20 | Reconnects a join makes to learn an outcome a dropped connection left pending. |
| `MOUSSE_NET_OUTCOME_RETRY_FIRST_MS` | 250 | 10 to 10000 | Wait before the first of those reconnects; each next wait doubles. |
| `MOUSSE_NET_OUTCOME_RETRY_MAX_MS` | 2000 | 10 to 60000 | Longest of those waits; not below the first. |
| `MOUSSE_NET_CLOCK_RECHECK_MS` | 1000 | 10 to 1000 | Longest time between readings of both clocks: connection deadlines, renewal, the host's step 2 timers (wire.md 6). |
| `MOUSSE_NET_DEADLINE_POLL_MS` | 50 | 1 to 1000 | How often a pending write checks the connection deadline. |
| `MOUSSE_NET_CLOSE_LINGER_MS` | 2000 | 100 to 30000 | Time a closing connection has to send its last frame and shut the pipe. |
| `MOUSSE_NET_WRITE_HIGH_WATER_BYTES` | 262144 | 16384 to 67108864 | Queued bytes per stream above which a write waits. |
| `MOUSSE_NET_READ_BUFFER_BYTES` | 32768 | 1024 to 1048576 | Bytes read from the pipe at a time. |
| `MOUSSE_NET_HANDSHAKE_TIMEOUT_MS` | 10000 | 1000 to 60000 | TLS handshake time. |
| `MOUSSE_NET_CONNECT_TIMEOUT_MS` | 5000 | 100 to 60000 | TCP connect time. |
| `MOUSSE_NET_CERT_LIFETIME_SECS` | 86400 | 3600 to 86400 | Lifetime of the session certificates this device issues; verifiers reject more than 24 h (wire.md 5.2). |
| `MOUSSE_NET_MDNS_ROTATE_MS` | 900000 | 60000 to 900000 | How often the mDNS instance name changes (privacy.md). |
| `MOUSSE_NET_MDNS_ROTATE_CHECK_MS` | 5000 | 100 to 30000 | How often the advertiser checks whether the name is due to change. |

## Helper

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_TERM_PTY_READ_BYTES` | 16384 | 1024 to 65536 | Bytes read from the PTY at a time (one terminal `DATA` frame). |
| `MOUSSE_NET_TERM_STDIN_READ_BYTES` | 4096 | 64 to 65536 | Bytes read from local input at a time in a remote terminal. |
| `MOUSSE_NET_TERM_OUTPUT_QUEUE` | 64 | 1 to 4096 | Output chunks queued before the PTY reader waits. |
| `MOUSSE_NET_TERM_MAX_DIMENSION` | 1000 | 80 to 4000 | Largest terminal width or height a peer may ask for. |
| `MOUSSE_NET_TERM_CLOSE_DELAY_MS` | 300 | 0 to 10000 | After the command exits, time for its last output before the PTY closes. |
| `MOUSSE_NET_TERM_EXIT_GRACE_MS` | 3000 | 0 to 60000 | After the command exits, wait for the output to end before sending `EXIT` anyway. |
| `MOUSSE_NET_TERM_RESIZE_POLL_MS` | 500 | 50 to 10000 | How often a remote terminal checks the local window size. |
| `MOUSSE_NET_INFO_REQUEST_WAIT_MS` | 5000 | 100 to 60000 | Host: time a `helper-info` requester has to finish its empty request. |
| `MOUSSE_NET_INFO_ANSWER_MAX_BYTES` | 4096 | 256 to 65536 | Longest `helper-info` answer accepted. |
| `MOUSSE_NET_INFO_ANSWER_WAIT_MS` | 10000 | 100 to 120000 | Wait for a `helper-info` answer. |
| `MOUSSE_NET_CAPTURE_WAIT_MS` | 30000 | 100 to 600000 | Slice check: wait for its command to finish. |
| `MOUSSE_NET_REMOVAL_WAIT_SECS` | 300 | 1 to 86400 | Slice check: default wait for the host to remove this device (`--removal-timeout` overrides it). |
| `MOUSSE_NET_STOP_LINGER_MS` | 200 | 0 to 10000 | After `stop`, time closing connections get before the host exits. |
| `MOUSSE_NET_PIPE_BUSY_WAIT_MS` | 2000 | 0 to 60000 | Windows: how long to retry a busy control pipe. |
| `MOUSSE_NET_PIPE_BUSY_RETRY_MS` | 20 | 1 to 1000 | Windows: wait between tries on a busy control pipe. |
| `MOUSSE_NET_ENDPOINT_LOCK_WAIT_MS` | 2000 | 0 to 60000 | How long to retry an endpoint lock a process that just exited may still hold. |
| `MOUSSE_NET_ENDPOINT_LOCK_RETRY_MS` | 100 | 1 to 1000 | Wait between tries on a held endpoint lock. |
| `MOUSSE_NET_COMPUTER_NAME_MAX_BYTES` | 64 | 1 to 64 | Longest default device name taken from the computer name (names are at most 64 bytes). |

## Fixed on purpose

These are protocol constants, not limits, so they are not settings:

- Header sizes, field widths, version numbers, domain strings and the
  pairing code format: changing them changes the wire format.
- Frame and message maxima the peer enforces (`MAX_PAYLOAD` 65 536,
  `MAX_CONTROL_PAYLOAD` and `MAX_CONTROL_MESSAGE` 16 384, `MAX_OPEN_PAYLOAD`
  256, label 64, exchange payload 1 024, routes 8 of at most 255 bytes,
  names 128, CBOR depth 8, CPace lengths, the terminal protocol's 1 MiB
  frame): a lower value rejects conformant peers, a higher one breaks the
  bound the peer relies on.
- `INITIAL_CREDIT` (262 144) and `MAX_CREDIT` (2^30): both sides assume the
  same values.
- The verifier's 24 h certificate maximum (`MAX_LIFETIME_SECS`); a device
  can only issue shorter certificates (`CERT_LIFETIME_SECS`).
- The joiner record's bound of 3 attempts: the stored format rejects more.
- The mDNS name format (`mousse-` and 12 random characters, privacy.md).
