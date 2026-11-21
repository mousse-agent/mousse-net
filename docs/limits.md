# Limits

Every timeout, wait, attempt cap, validity window, retry delay, size and
count in `mousse-net-core`, `mousse-net-io` and `mousse-helper` is a named
default in one place per crate: `Limits` in
`crates/mousse-net-core/src/limits.rs` (the core takes it as a parameter),
`IoLimits` in `crates/mousse-net-io/src/limits.rs` (passed in through
`HostConfig::limits` and `Caller::new`), `HelperLimits` in
`crates/mousse-helper/src/limits.rs`, and for the relay `RelayLimits` in
`crates/mousse-net-core/src/relay/limits.rs`.

The helper reads `MOUSSE_NET_<NAME>` once at startup. A value must be a
whole number in the unit the name ends with (`_MS`, `_SECS`, `_BYTES`; no
unit means a count). A value that is not a whole number, is out of range,
or disagrees with another limit stops startup with a message that names the
variable and its allowed range. An unknown `MOUSSE_NET_*` name stops startup
too, except the app's own names, which reach the helper it starts:
`MOUSSE_NET_ENGINE_*` and `MOUSSE_NET_HELPER`, and the relay's
(`MOUSSE_NET_RELAY_*`, read only by `mousse-relay`).

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
| `MOUSSE_NET_CLOSE_LINGER_MS` | 2000 | 100 to 30000 | Time a closing connection has to send its last frame and shut the pipe, while it reads and drops what the peer still sends. |
| `MOUSSE_NET_WRITE_HIGH_WATER_BYTES` | 262144 | 16384 to 67108864 | Queued bytes per stream above which a write waits. |
| `MOUSSE_NET_READ_BUFFER_BYTES` | 32768 | 1024 to 1048576 | Bytes read from the pipe at a time. |
| `MOUSSE_NET_RX_CHUNK_BYTES` | 16384 | 1024 to 65536 | Size of the buffers received `DATA` frames share until read. A peer's tiny frames fill one buffer instead of an allocation each, so what waits unread costs about its bytes. |
| `MOUSSE_NET_HANDSHAKE_TIMEOUT_MS` | 10000 | 1000 to 60000 | TLS handshake time. |
| `MOUSSE_NET_CONNECT_TIMEOUT_MS` | 5000 | 100 to 60000 | TCP connect time. |
| `MOUSSE_NET_CERT_LIFETIME_SECS` | 86400 | 3600 to 86400 | Lifetime of the session certificates this device issues; verifiers reject more than 24 h (wire.md 5.2). |
| `MOUSSE_NET_MDNS_ROTATE_MS` | 900000 | 60000 to 900000 | How often the mDNS instance name changes (privacy.md). |
| `MOUSSE_NET_MDNS_ROTATE_CHECK_MS` | 5000 | 100 to 30000 | How often the advertiser checks whether the name is due to change. |
| `MOUSSE_NET_STREAMS_PER_CONNECTION` | 32 | 1 to 1024 | Open streams on one connection, both directions counted. A peer's open past it is reset with `REFUSED_STREAM`; an own open fails with `StreamLimit`. With the engine's 256 KiB initial credit per stream, this bounds what one connection can queue unread (wire.md 9.2). |
| `MOUSSE_NET_OWN_STREAMS_PER_CONNECTION` | 4 | 1 to 4 | Engine streams (labels starting `mousse-`, wire.md 9.5) open on one connection, both directions counted apart from `STREAMS_PER_CONNECTION` and `STREAMS_PER_ENDPOINT`, so the engine never takes the app's places. A peer's open past it is reset with `REFUSED_STREAM`. Tighten only. |
| `MOUSSE_NET_STREAMS_PER_ENDPOINT` | 128 | 1 to 1024 | Open streams on all of an endpoint's connections together, host and caller sides alike; past it as above. |
| `MOUSSE_NET_DIAL_PARALLEL` | 4 | 1 to 64 | Caller: candidate addresses for one host dialled at once (Phase 1a §6). |
| `MOUSSE_NET_DIAL_TIMEOUT_MS` | 2000 | 100 to 60000 | Caller: time one candidate address has to connect and pass step 1 before it is given up (Phase 1a §6). |
| `MOUSSE_NET_DIAL_MAX_CANDIDATES` | 16 | 1 to 64 | Caller: candidates kept for one search, in order: the last working route, the owner's addresses, approved hints, then browse results (Phase 1b §1.4). |
| `MOUSSE_NET_TIER_HEAD_START_MS` | 500 | 0 to 10000 | Caller: wait after the `tcp` tier starts before `ws`/`wss` candidates start; at once when there is no `tcp` candidate. Also when the `ssh` tier starts if the last working route was `ssh`. |
| `MOUSSE_NET_DIAL_FAST_TIERS_MS` | 12000 | 1000 to 60000 | Caller: latest start of the `ssh` tier, from the start of the search; it starts earlier once the `tcp` and `ws` tiers are done, so an SSH login never races a LAN path. |
| `MOUSSE_NET_DIAL_SEARCH_MS` | 45000 | 5000 to 300000 | Caller: one whole search across every tier; past it the search ends unreachable. |
| `MOUSSE_NET_WS_DIAL_TIMEOUT_MS` | 10000 | 500 to 60000 | Caller: one `ws`/`wss` try: connect, outer TLS, upgrade and step 1. |
| `MOUSSE_NET_SSH_DIAL_TIMEOUT_MS` | 20000 | 1000 to 120000 | Caller: one `ssh` try: login, marker, remote `pipe` and step 1. |
| `MOUSSE_NET_BROWSE_WAIT_MS` | 1500 | 100 to 30000 | How long an mDNS browse listens for answers (Phase 1a §6). |
| `MOUSSE_NET_BROWSE_CACHE_MS` | 60000 | 0 to 3600000 | How long browse results are reused before the next browse; 0 browses every time (Phase 1a §6). |
| `MOUSSE_NET_IFACE_POLL_MS` | 5000 | 100 to 60000 | How often the network watcher lists the interfaces and reads the monotonic clock (Phase 1a §6 and §8). |
| `MOUSSE_NET_WAKE_JUMP_MS` | 10000 | 1000 to 600000 | How far the monotonic clock may run past one watcher poll before the gap counts as a sleep and wake (Phase 1a §8). |
| `MOUSSE_NET_WAKE_PING_MS` | 2000 | 100 to 30000 | After a wake or an interface change, how long each connection has to answer a PING before it is closed as dead (Phase 1a §8). |
| `MOUSSE_NET_PREAUTH_TCP` | 48 | 1 to 48 | Host: TCP connections not yet live, per endpoint. The place is taken at accept, before anything is read, and held until the connection is live or closed (join-only: until enrollment, a close or the end of the invitation). One more is closed at accept (Phase 1b §6.2). |
| `MOUSSE_NET_PREAUTH_WS` | 16 | 1 to 16 | Host: `ws` connections not yet live, per endpoint; its own pool, so a flood through a tunnel takes no TCP or pipe place. |
| `MOUSSE_NET_PREAUTH_PIPE` | 4 | 1 to 4 | Host: pipe connections (an SSH login's `mousse-helper pipe`) not yet live, per endpoint; its own pool. |
| `MOUSSE_NET_PREAUTH_PER_SOURCE` | 8 | 1 to 8 | Host: of the TCP ones, connections from one IPv4 address or one IPv6 /64. |
| `MOUSSE_NET_WS_UPGRADE_WAIT_MS` | 5000 | 100 to 5000 | Host: time a `ws` connection has for its whole upgrade request; past it the socket is closed unanswered (Phase 1b §4.1). |
| `MOUSSE_NET_WS_HEADER_MAX_BYTES` | 8192 | 1024 to 8192 | Host: size of a `ws` upgrade request; past it the socket is closed unanswered. |
| `MOUSSE_NET_WS_MESSAGE_MAX_BYTES` | 65536 | 16384 to 65536 | One received `ws` message; a larger one ends the connection. Not below the 16 KiB every sender writes per message. |

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
| `MOUSSE_NET_APP_CREDIT_BUDGET_BYTES` | 8388608 | 262144 to 1073741824 | App mode: credit the helper grants the app in all, for data going to the engine. |
| `MOUSSE_NET_APP_CREDIT_INTERACTIVE_RESERVE_BYTES` | 1048576 | 0 to 1073741824 | App mode: the part of that budget only interactive streams may use; below the budget. |
| `MOUSSE_NET_APP_STREAM_CREDIT_BYTES` | 262144 | 65536 to 16777216 | App mode: most credit one stream holds; at most the budget less the reserve. |
| `MOUSSE_NET_APP_READ_AHEAD_BYTES` | 65536 | 65536 to 16777216 | App mode: the helper reads an engine stream only while the app's credit covers what it has queued for the app plus this. At least one `DATA` payload (65 536), so a read never goes past the app's credit. |
| `MOUSSE_NET_APP_CONTROL_QUEUE_BYTES` | 1048576 | 65536 to 67108864 | App mode: JSON and `CREDIT` queued for an app that is not reading; past it the channel ends and the helper exits. |
| `MOUSSE_NET_APP_LOG_MAX_BYTES` | 1048576 | 4096 to 1073741824 | App mode: size at which `helper.log` in the state directory starts a new file. |
| `MOUSSE_NET_APP_LOG_FILES` | 2 | 1 to 10 | App mode: log files kept (`helper.log`, `helper.log.1`, ...). |
| `MOUSSE_NET_REMOVAL_RETRY_MS` | 1000 | 10 to 60000 | While networking is paused because a removal (`grant.remove`) could not be saved, how often the helper tries the save again (Phase 1a §5.4). |
| `MOUSSE_NET_KEEP_RETRY_FIRST_MS` | 1000 | 10 to 60000 | App mode: wait before redialling a paired host that could not be reached; each next wait doubles (Phase 1a §6). |
| `MOUSSE_NET_KEEP_RETRY_MAX_MS` | 60000 | 10 to 3600000 | App mode: longest wait between those redials; not below the first. |
| `MOUSSE_NET_RELAY_SWITCH_MARGIN_MS` | 20 | 0 to 1000 | App mode, relay first: a host with a relay route is dialled through the relay first, then its direct routes are tried in the background. A direct path that comes up takes over (`path.reopen`) unless the relayed path's round trip (best of three `PING`s on each) is shorter by more than this. A tie goes to the direct path. The tries repeat on the `KEEP_RETRY_*` waits while the relayed path stays up. |
| `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` | 2592000 | 86400 to 2592000 | "Remove on all my hosts" (Phase 4 Part D): the oldest removal a host accepts and an admin device keeps queued, and how long a host keeps removal ids. Tighten only. |
| `MOUSSE_NET_REMOVAL_ANSWER_WAIT_MS` | 10000 | 1000 to 120000 | How long one side of `mousse-removal` waits for the other's message (the signed removal, or the host's answer). |
| `MOUSSE_NET_PLUS_TIMEOUT_MS` | 10000 | 1000 to 60000 | One Plus request. |
| `MOUSSE_NET_PLUS_ANSWER_MAX_BYTES` | 4194304 | 65536 to 67108864 | Largest answer from Plus the helper reads; a larger one counts as a failed request. |
| `MOUSSE_NET_PLUS_RETRY_FIRST_MS` | 1000 | 100 to 60000 | First wait before retrying a Plus request; each next wait doubles. |
| `MOUSSE_NET_PLUS_RETRY_MAX_MS` | 300000 | 1000 to 3600000 | Longest wait before retrying a Plus request; not below the first. |
| `MOUSSE_NET_PLUS_PREFETCH_PERCENT` | 50 | 10 to 90 | Use of the current relay lease, in percent, at which the next block is asked for; also the status threshold the helper gives a hosted relay. |
| `MOUSSE_NET_PLUS_NOT_BEFORE_RETRY_MS` | 1000 | 1000 to 10000 | Wait before presenting a block or admission token again that a relay refused for `not before`, or for having no Plus clock yet. |
| `MOUSSE_NET_PLUS_REFILL_DEADLINE_MS` | 5000 | 1000 to 9000 | After this long without a new block, relayed bulk shows paused; below the relay's default refill wait. |
| `MOUSSE_NET_PLUS_MAIL_POLL_SECS` | 300 | 30 to 86400 | How often a host fetches its Plus inbox (also after a network change). |
| `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS` | 86400 | 0 to 604800 | How long a move to another hosted relay stages the new route before cutting over. |
| `MOUSSE_NET_PLUS_MAIL_PAGES_MAX` | 100 | 1 to 10000 | Most inbox pages one mail round fetches, so a Plus that pages without end cannot hold the round. |
| `MOUSSE_NET_HANDLE_ROTATE_SECS` | 1209600 | 172800 to 7776000 | Hosted relays: a new registration key (handle) this often. At least twice `MANIFEST_OVERLAP_SECS`, so at most two handles per relay are live; startup refuses otherwise. |
| `MOUSSE_NET_PLUS_FLEET_REFRESH_SECS` | 3600 | 60 to 86400 | Hosted relays: how often the relay fleet is read from Plus; also at once when this host's relay cannot be reached. |
| `MOUSSE_NET_PLUS_SLOT_READ_SECS` | 300 | 10 to 86400 | Caller: the least time between two reads of one host's directory slot when no route reaches it (the slot's manifest brings rotated or moved routes). |
| `MOUSSE_NET_IPC_LINE_MAX_BYTES` | 65536 | 1024 to 65536 | Local control channel: longest line a client may send; a longer one closes the channel (Phase 1b §6.2). |
| `MOUSSE_NET_IPC_FIRST_LINE_WAIT_MS` | 2000 | 100 to 2000 | Local control channel: time a client has to send its first line before the channel is closed. |
| `MOUSSE_NET_VIA_RELAY_DIAL_MS` | 10000 | 1000 to 60000 | Through a relay: connect, outer TLS, upgrade, `CALL` or `JOIN`, the splice and step 1, for one try. Above the relay's refusal deadline, so an unlisted caller hears `UNREACHABLE` before it gives up (Phase 3 §B.6). |
| `MOUSSE_NET_VIA_RELAY_RETRY_FIRST_MS` | 1000 | 100 to 60000 | App mode: wait before registering on one of this computer's relays again after a registration ended or failed; each next wait doubles. |
| `MOUSSE_NET_VIA_RELAY_RETRY_MAX_MS` | 60000 | 1000 to 600000 | App mode: longest such wait; not below the first. |
| `MOUSSE_NET_VIA_RELAY_KEEPALIVE_MS` | 20000 | 1000 to 120000 | App mode: a relay registration sends `PING` after this long without sending. |
| `MOUSSE_NET_VIA_RELAY_IDLE_MS` | 60000 | 3000 to 600000 | App mode: a relay registration that hears nothing for this long is dropped and made again; above the keepalive. |
| `MOUSSE_NET_VIA_RELAY_CHECK_MS` | 30000 | 100 to 600000 | App mode: how often the helper checks relay invitation and recovery expiry, the end of rotation overlaps and manifest renewal. |
| `MOUSSE_NET_VIA_RELAY_ACCEPT_LEGS` | 64 | 1 to 64 | App mode: accept legs to this computer's relays being dialled at once. An `INCOMING` past it is not answered and times out at the relay, so a relay cannot make the host dial without bound. Tighten only; the default is the relay's own `RELAY_ACCEPT_LEGS_PER_HANDLE`. |
| `MOUSSE_NET_VIA_RELAY_ROTATION_RETRY_MS` | 1000 | 100 to 60000 | App mode: during a key rotation, the wait between tries to register the new key, and between `SUCCESSOR`s while the relay refuses it. The rotation is journaled and goes on after a restart; the old key stays current until the new one registers. |
| `MOUSSE_NET_MANIFEST_OVERLAP_SECS` | 604800 | 86400 to 604800 | How long an old relay route or registration key stays in the manifest, and registered, after a rotation (Phase 3 §B.4 and §B.11). It counts from the rotation's start, before any `SUCCESSOR`, less the 10-minute clock skew. At most the relay's largest `MOUSSE_NET_RELAY_SUCCESSOR_OVERLAP_SECS`; a self-hosted relay sends its own in `REGISTERED`, and the helper uses the smaller of the two, so the old route leaves the manifest before the relay drops the old key. Tighten only. |
| `MOUSSE_NET_MANIFEST_LIFETIME_SECS` | 2592000 | 604800 to 7776000 | When a manifest becomes stale. A stale manifest's routes are still dialled, after every other route. Above the overlap. |
| `MOUSSE_NET_VIA_RELAY_REJOIN_SECS` | 86400 | 600 to 86400 | Host: how long a consumed invitation's tag stays in the relay allow-set, so a joiner whose circuit dropped can finish (Phase 3 §B.7). Tighten only: the tag is a capability. |
| `MOUSSE_NET_SSH_CONNECT_TIMEOUT_SECS` | 10 | 1 to 120 | ssh: `ConnectTimeout` on every call, and the limit on `ssh -G` (Phase 1b §3.1). |
| `MOUSSE_NET_SSH_ALIVE_INTERVAL_SECS` | 15 | 1 to 300 | ssh: `ServerAliveInterval`. |
| `MOUSSE_NET_SSH_ALIVE_COUNT` | 3 | 1 to 20 | ssh: `ServerAliveCountMax`. |
| `MOUSSE_NET_SSH_TARGET_CONNECTS` | 5 | 1 to 5 | ssh: connections per resolved host and port per `SSH_TARGET_WINDOW_MS` (key fetches, setup sessions and pipe dials alike, every route and alias for the server together), so setup plus retries stay under `ufw limit`. One over waits; a wait past its call's deadline fails with `timeout`. |
| `MOUSSE_NET_SSH_TARGET_WINDOW_MS` | 30000 | 30000 to 600000 | ssh: the window `SSH_TARGET_CONNECTS` counts over. Tighten only, which here means longer. |
| `MOUSSE_NET_SSH_SETUP_TIMEOUT_MS` | 60000 | 1000 to 600000 | ssh: one `ssh.run` or `ssh.probe`; also how long a probed key is kept for `ssh.trust` (Phase 1b §3.2). |
| `MOUSSE_NET_SSH_STDERR_MAX_BYTES` | 16384 | 1024 to 1048576 | ssh: stderr kept to name the failure's reason; never shown raw. |
| `MOUSSE_NET_SSH_PREAMBLE_MAX_BYTES` | 65536 | 0 to 65536 | ssh: output skipped before the `mousse-ssh/1` marker (a login shell's rc files); past it the try fails with `remote_failed` (Phase 1b §3.3). |
| `MOUSSE_NET_SSH_REPLY_MAX_BYTES` | 1048576 | 1024 to 1048576 | ssh: one `ssh.run` reply after the marker; a longer one fails with `remote_failed` (Phase 1b §3.4). |
| `MOUSSE_NET_PIPE_CONNECT_WAIT_MS` | 2000 | 100 to 60000 | Remote `mousse-helper pipe`: reach the running helper's IPC and get its `ok`; past it, `not_running` (Phase 1b §3.3). |
| `MOUSSE_NET_JOIN_DONE_KEEP_SECS` | 86400 | 0 to 2592000 | App mode: how long a "Send link" completion record (`joins/<ticket hash>.done`) the app never acknowledged with `join.ack` is kept after its ticket expired. Until then `join.status` can replay it. |
| `MOUSSE_NET_INIT_HOLD_MS` | 0 | 0 to 60000 | Checks only: how long `init` waits before it makes the endpoint, so the hard-kill check can stop the app during a first start. Run for the app (`--app`), its stdin closing still ends it at once. |

## Settings

Settings are not limits: text values, read once at startup. An invalid
value stops startup with a message naming the variable.

| Variable | Default | What it sets |
|---|---|---|
| `MOUSSE_NET_PLUS_URL` | unset (no Plus) | The Plus origin, `https://host[:port]` with no path. Plus is not a trust anchor, so the platform verifier checks it and nothing is pinned. Debug builds also take `http://` on a loopback address, for the test stand-in. |

## Relay

`RelayLimits` in `crates/mousse-net-core/src/relay/limits.rs`. `mousse-relay`
reads `MOUSSE_NET_<NAME>` at startup with the same rules; every name starts
with `RELAY_`, and the relay accepts no other `MOUSSE_NET_*` name. Where a
client could push against a limit (connections, legs, circuits, budgets,
waits a client fills), its range ends at the default: it can only be
tightened. `RELAY_REFUSE_MS` must be below `RELAY_ACCEPT_WAIT_MS`
(spec/relay.md 9.1).

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_RELAY_MAX_CONNECTIONS` | 1024 | 1 to 65536 | Open outer connections (capacity; about 52 KB each, plus queued bytes). |
| `MOUSSE_NET_RELAY_CONNECTIONS_PER_IP` | 256 | 1 to 256 | Open connections per IPv4 address or IPv6 /64, except accept legs once their ACCEPT is accepted (tighten only). |
| `MOUSSE_NET_RELAY_ACCEPT_LEGS_PER_HANDLE` | 64 | 1 to 64 | Open accept legs per handle (tighten only). |
| `MOUSSE_NET_RELAY_CIRCUITS_PER_CALLER` | 8 | 2 to 8 | Open circuits per caller fingerprint and handle (tighten only). |
| `MOUSSE_NET_RELAY_MAX_REGISTRATIONS` | 1024 | 1 to 65536 | Live registrations (capacity). |
| `MOUSSE_NET_RELAY_HELLO_WAIT_MS` | 5000 | 500 to 5000 | Wait for the first client message after RELAY_HELLO (tighten only). |
| `MOUSSE_NET_RELAY_UPGRADE_WAIT_MS` | 5000 | 100 to 5000 | Whole TLS and WebSocket upgrade (tighten only). |
| `MOUSSE_NET_RELAY_HEADER_MAX_BYTES` | 8192 | 1024 to 8192 | Largest upgrade request (tighten only). |
| `MOUSSE_NET_RELAY_ACCEPT_WAIT_MS` | 10000 | 1000 to 30000 | Wait for the target's accept leg after INCOMING. |
| `MOUSSE_NET_RELAY_REFUSE_MS` | 500 | 500 to 5000 | Constant refusal deadline from a CALL or JOIN; below the accept wait. |
| `MOUSSE_NET_RELAY_PREACCEPT_BYTES` | 65536 | 16384 to 65536 | Peer bytes per join circuit and direction before promotion (tighten only). |
| `MOUSSE_NET_RELAY_PREACCEPT_PER_TARGET` | 4 | 1 to 4 | Join circuits per handle (tighten only). |
| `MOUSSE_NET_RELAY_KEEPALIVE_MS` | 15000 | 1000 to 15000 | PING on a registration connection after this long without sending (tighten only). |
| `MOUSSE_NET_RELAY_REGISTRATION_IDLE_MS` | 45000 | 30000 to 45000 | Registration closed after this long without receiving (tighten only). |
| `MOUSSE_NET_RELAY_CIRCUIT_IDLE_MS` | 60000 | 46000 to 600000 | Spliced circuit closed after this long with no bytes either way; above the peer idle timeout. |
| `MOUSSE_NET_RELAY_QUEUE_BYTES` | 262144 | 16384 to 262144 | Bytes buffered per circuit and direction before the relay stops reading that leg (tighten only). |
| `MOUSSE_NET_RELAY_EGRESS_BPS` | 12500000 | 125000 to 12500000000 | Shared egress ceiling in bytes per second (capacity). |
| `MOUSSE_NET_RELAY_ENROLL_SECS` | 3600 | 60 to 3600 | Enrollment code lifetime; single use (tighten only). |
| `MOUSSE_NET_RELAY_SUCCESSOR_OVERLAP_SECS` | 604800 | 3600 to 604800 | After a SUCCESSOR, how long the superseded registration key stays authorized (tighten only). |
| `MOUSSE_NET_RELAY_CHAIN_KEYS_MAX` | 4 | 2 to 4 | Keys one SUCCESSOR chain may hold at once, the current key and those it superseded (tighten only). A SUCCESSOR past it is `REFUSED(chain_full)` and the registration stays; the helper then drops that rotation and refuses the next one until the oldest key leaves. |
| `MOUSSE_NET_RELAY_STATE_POLL_MS` | 1000 | 100 to 1000 | How often the running relay re-reads its authorized list and enrollment codes, so `revoke` and `enroll` take effect (tighten only). |
| `MOUSSE_NET_RELAY_SEND_WAIT_MS` | 20000 | 1000 to 20000 | A write to one connection that makes no progress this long closes that connection (tighten only). |
| `MOUSSE_NET_RELAY_CONTROL_QUEUE_MESSAGES` | 64 | 8 to 64 | Control messages (PONG, REFUSED and the like) queued to one connection; more closes it (tighten only). |
| `MOUSSE_NET_RELAY_CLOSE_LINGER_MS` | 2000 | 100 to 2000 | Wait for the close frame and the TCP shutdown when the relay closes a connection (tighten only). |

Fixed on purpose in the relay protocol: the 16 384-byte relay message, the
65 536-byte WebSocket message, 256 caller fingerprints and 8 invitations per
allow-set, 4 lease ids per `RELEASE`, the path, the subprotocol, the close
codes, the refusal reasons, the domain strings and the exporter label
(spec/relay.md 13).

## Relay, hosted mode

A relay in hosted mode also reads these (`docs/phase34-design.md` §H.1),
with the same rules as the rows above. `HostedLimits` in
`crates/mousse-net-core/src/relay_hosted/mod.rs` holds them, and
`crates/mousse-relay-plus/src/settings.rs` reads them.

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_RELAY_REFILL_WAIT_MS` | 10000 | 1000 to 10000 | A paused class waits this long for a `LEASE` before its circuits close with 4001. With the longest peer keepalive (15 s) it stays below the shortest peer idle timeout (30 s), so it can only be shortened. |
| `MOUSSE_NET_RELAY_REPORT_MS` | 10000 | 1000 to 60000 | Snapshot interval; below Plus's boot silence time (120 s by default). |
| `MOUSSE_NET_RELAY_REPORT_MIN_MS` | 1000 | 100 to 5000 | Longest delay from a final to its snapshot, and the shortest gap between snapshots; below `REPORT_MS`. |
| `MOUSSE_NET_RELAY_FINAL_REPORT_WAIT_MS` | 5000 | 0 to 60000 | On a graceful stop, how long to wait for the stopping snapshot to be stored. |
| `MOUSSE_NET_RELAY_PLUS_TIMEOUT_MS` | 10000 | 1000 to 60000 | One call to Plus. |
| `MOUSSE_NET_RELAY_CLOCK_RTT_MS` | 2000 | 100 to 10000 | Longest round trip whose Plus answer may set the Plus clock; a longer one only ends leases earlier. |
| `MOUSSE_NET_RELAY_PLUS_RETRY_FIRST_MS` | 1000 | 100 to 60000 | First wait before sending a boot announcement or report part again after a failed call. Each next wait doubles; a `retry after` from Plus lengthens it. |
| `MOUSSE_NET_RELAY_PLUS_RETRY_MAX_MS` | 30000 | 1000 to 600000 | Longest such wait; not below the first. |
| `MOUSSE_NET_RELAY_PLUS_ANSWER_MAX_BYTES` | 65536 | 16384 to 1048576 | Largest Plus answer read. |

Fixed, not variables (Part A of the design): `REQUEST_MAX` 16 384,
`REPORT_MAX` 65 536, `REPORT_ENTRIES_MAX` 1024, `BLOCK_MAX_LIFETIME`
172 800 s, `FORWARD_MARGIN` 180 s, the one-second rate burst, the 65 536
rate-cap floor and smallest block, and at most four lease ids per
`RELEASE`.

### Settings

Settings are not limits: they have no default and no range.

| Variable | Required | Value |
| --- | --- | --- |
| `MOUSSE_NET_RELAY_PLUS_URL` | in hosted mode | The Plus base URL, `https://host[:port][/path]`. TLS 1.3 with the platform's certificate verifier and no pin (Plus is not a trust anchor). `http://` is accepted only to a loopback IP address, for tests on one machine. No user, query or fragment. A missing or bad value stops startup with a message naming the variable. |

### State directory files (hosted)

| File | What |
| --- | --- |
| `boot-generation` | The boot generation, a decimal number. At start, under the state directory's lock, the relay adds one and writes it durably (write, fsync, rename, folder sync) before it serves. A file that does not hold a number stops startup; the count never starts over. |
| `report-key` | The P-256 report key (hex secret, owner-only), made on first start. It signs boot and report bodies. Its public key is what an operator adds to Plus's fleet. |

| `issuer-keys` | The pinned issuer public keys, written by the operator: one per line as 130 hex digits (the 65-byte SEC1 point), blank lines and `#` comments ignored. Two overlap during a rotation. |

`mousse-relay run --hosted` runs a relay in hosted mode; it needs
`MOUSSE_NET_RELAY_PLUS_URL` and the `issuer-keys` file. The running relay
reads `issuer-keys` again with the rest of the state directory (every
`MOUSSE_NET_RELAY_STATE_POLL_MS`) and at once on `SIGHUP`, without ending
the boot; a file that does not parse leaves the keys in force.
`mousse-relay reload` checks the file.

## Debug-build test hooks

Debug builds also read these; release builds never do, and there they
count as unknown names.

| Variable | What it does |
| --- | --- |
| `MOUSSE_NET_TEST_EXTRA_ROOT` | A DER certificate file the outer `wss` TLS trusts besides the platform's roots, for a test tunnel stand-in (Phase 1b §4.2). Nothing is installed in an OS store. |
| `MOUSSE_NET_TEST_HELLO_MINOR` | The helper speaks this older newest minor version (and the one before it), as a peer from before it does; a value at or above the build's own is ignored (wire.md 2). |
| `MOUSSE_NET_TEST_CLASS_MAP` | Maps loopback ports to address classes, so checks can stand in for tailnet and public routes (Phase 1b §1.2): `<port>=<class>` entries (`lan`, `tailnet` or `public`) separated by commas, plus an optional `*=<class>` for every loopback port the map leaves out (otherwise `lan`). An inbound loopback connection takes the class of the listener port it arrived on when the map names that port. |
| `MOUSSE_NET_SSH_BIN` | The `ssh` client to run instead of the system's (Phase 1b §3.1). |
| `MOUSSE_NET_TEST_SSH_CONFIG` | The ssh config `ssh -G` reads instead of the user's own and the system's, so tests never read the owner's ssh config (Phase 1b §3.7). Every later call reads only the route's own config. |
| `MOUSSE_NET_TEST_EGRESS` | A check's egress fence (Phase 1b §14): when set, the helper dials only loopback and the comma-separated IP literals listed (the Mac's address in cross-machine cells), and resolves no name but `localhost`. Empty means loopback only. |
| `MOUSSE_NET_TEST_EGRESS_LOG` | A file the helper appends one JSON line to for each dial the fence refused; the check kit fails the run with `egress_attempted`. |

## Check kit (tests only)

The owner test kit's own waits and its relay. Nothing here is read by the
engine or the app.

| Variable | Default | Allowed | What it limits |
| --- | --- | --- | --- |
| `MOUSSE_NET_RELAY_MAX_STREAMS` | 16 | 1 to 16 (tighten) | Kit relay (`tools/app-check/relay.mjs`, Mac to PC for the chat-link check): connections carried at once. |
| `MOUSSE_NET_RELAY_FRAME_MAX_BYTES` | 65536 | 1024 to 65536 (tighten) | Kit relay: one frame on the control connection. |
| `MOUSSE_NET_RELAY_HELLO_WAIT_MS` | 5000 | 100 to 60000 | Kit relay: time for the control connection's first line. |
| `MOUSSE_CHECK_PROBE_CONNECT_MS` | 5000 | 1 or more | `mousse-check probe`: one TCP connect. |
| `MOUSSE_CHECK_PROBE_CLOSE_MS` | 5000 | 1 or more | Probe: time the host has to answer or close once it should. |
| `MOUSSE_CHECK_PROBE_SETTLE_MS` | 1000 | 1 or more | Probe: after a case, before the app's counters are read again. |
| `MOUSSE_CHECK_SMOKE_SERVE_MS` | 15000 | 1 or more | `tools/build-smoke.mjs`: for release `serve` and `invite` to be ready. |
| `MOUSSE_CHECK_SMOKE_PROBE_MS` | 120000 | 1 or more | Build smoke: one probe run. |

The probe reads the engine limits it tests (`MOUSSE_NET_PREAUTH_*`,
`MOUSSE_NET_JOIN_PROOF_WAIT_MS`, `MOUSSE_NET_HANDSHAKE_TIMEOUT_MS`,
`MOUSSE_NET_WS_UPGRADE_WAIT_MS`, `MOUSSE_NET_WS_HEADER_MAX_BYTES`) from the
same variables, so a check that tightens one for the host tightens it for
the probe.

### Relay tests

Settings of the relay's tests, not limits. The relay reads the first two
only in debug builds; the engine and the app read none of them (the
helper's check for unknown `MOUSSE_NET_*` names does not see them).

| Variable | What it does |
| --- | --- |
| `MOUSSE_RELAY_TAP` | A debug relay writes its decrypted view of both legs of every circuit to this file (`crates/mousse-relay/tests/marker.rs`). |
| `MOUSSE_RELAY_CONTROL_MARKER_FILE` | Under the `marker-in-relay-memory` control, the relay keeps copies of this file's marker in its heap. |
| `MOUSSE_RELAY_TEST_LINKS` | Enrollment links of a running `mousse-relay`, separated by whitespace or commas, each used once; links of several relays may be mixed. `crates/mousse-helper/tests/app_relay_remote.rs` (`phase3.relay-routes-cross`, `phase3.relay-rotation-cross`) needs them, at an IP address outside loopback: `routes_cross` seven (six of one relay, one of a second), `rotation_cross` three. Without them its tests fail with `reason=not_configured`. A relay route of `tools/app-check/run.mjs` (`--route relay`) passes them to the app script, and allows each relay outside loopback in `MOUSSE_NET_TEST_EGRESS`. |
| `MOUSSE_RELAY_TEST_HOST_BUILD` | The build of the relay those links name (`<commit>[-dirty]+<profile>`), written as `host_build` in the result of `app_relay_remote.rs`. Needed with `MOUSSE_RELAY_TEST_RESULT`. |
| `MOUSSE_RELAY_TEST_RESULT` | A file `app_relay_remote.rs` writes its unsigned result to, for `mousse-check sign`; `{check}` is replaced by the check id. No result is written when the run was not configured. |

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
- Engine-stream messages: at most 262 144 bytes (wire.md 9.5). Plus's fixed
  maxima (`REQUEST_MAX` 16 384, `DIR_ENTRY_MAX` 4096, `MAIL_ENVELOPE_MAX`
  8192, `DEPOSIT_TOKENS_MAX` 256, `BLOCK_MAX_LIFETIME` 172 800 s, the
  65 536-byte block and rate-cap floors).
- The mDNS name format (`mousse-` and 12 random characters, privacy.md).
- The `mousse-ssh/1` marker, the selector grammar (26 characters of
  `[a-z2-7]`) and the remote `pipe` exit codes (`not_running` 2,
  `no_endpoint` 3, `refused` 4): the two ends of an SSH route rely on them.
