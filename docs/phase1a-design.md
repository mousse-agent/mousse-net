# Phase 1a design: the engine inside the desktop app

Status: design, 2026-11-18. Scope: PLAN "Phase 1a" (two desktops on a LAN,
in-person pairing only). Engine base: `phase-1a` from the finished Phase 0.
App base: Mousse `master` at `0bc1d29d8`.

Phase 1a adds the engine **beside** Mousse Net v1. v1 keeps working until
Phase 2 deletes it; edits to v1 files are small seams only, and a
per-profile switch turns the new path on.

Next step: a two-member review council reads this design. The calls it
should challenge first are listed under "Open questions for review" (§9).

## Decisions

Calls made for this design. Each is final for Phase 1a unless a check or a
design review proves it wrong.

1. **The daemon owns the helper.** Each profile's daemon services spawn,
   attach to, restart and stop that profile's helper. The helper lives as
   long as the daemon plus a 60 s linger, so a restarted daemon re-attaches
   to the running helper. Hosting without a running daemon waits
   for the headless daemon (PLAN Phase 3/8).
2. **One app channel per helper, on the existing control listener.** The
   app attaches with the `control.json` token, then the connection switches
   to binary framing. Application streams are **multiplexed over that one
   channel** with per-stream credit; no socket per stream.
3. **The v1 session layer stays; its transport and identity go.**
   `NetSyncSession`, `DurableRpcDispatcher` and `SubscriptionReceiver` run
   over engine streams through a new `EngineMux`. v1 TLS, mux, roster and
   delegation checks, enrollment and route records are not used on this
   path.
4. **Identity:** the engine endpoint identity is the device. The app's
   `NodeId` for an engine peer is the peer's own node id, claimed in the
   session hello and bound to the endpoint fingerprint on first session
   (under the engine pin). Presets and per-device policy keep keying on
   `NodeId`; the device list keys on the fingerprint.
5. **Authorization in the app comes from the grant role.** Phase 1a creates
   only `owner` grants (in-person pairing by the owner). An `owner` peer is
   treated as this user's own computer; any other role is refused by the
   app until Teams lands on the engine path (Phase 1b at the earliest).
6. **Sessions are one-way.** A connection carries calls from the caller to
   the host only, authorized by the host's grant. The other direction uses
   the other side's own connection. **Pairing is made two-way** by an
   automatic "pair back" under the one in-person approval (see §2.4).
7. **Phase 1a sessions carry Bridge only:** core routed RPC, terminals and
   the private and display streams Bridge reads. Spaces, presence, editor
   tunnels and phone features stay on v1.
8. **The app helper never runs its own terminals.** In app mode the helper's
   `term` label is refused; terminals are the app's routed `pty.*` calls.
9. **QR on desktops:** the joining desktop scans the host's QR with its
   webcam (`jsQR` in the renderer). "Paste link" is the fallback, with the
   in-person warning. No codes in Phase 1a.
10. **Keep connected:** each helper keeps one outbound path to every paired
    host while both are online, so the device list shows live state and
    calls start at once.
11. **A computer paired over both v1 and the engine is two devices** in
    Phase 1a. An engine claim of a node id that is in the v1 roster is
    refused, so the two paths never share a policy row.
12. **Helper binary** is built from a pinned engine commit by
    `scripts/build-net-helper.mjs` and shipped as an extra resource, like
    `voice-engine`.

## 1. Helper lifecycle

**Spawn.** `MmsProfileServices.start()` creates `EngineHelper` when the
profile's switch is on (`<profileDir>/net-engine/settings.json`,
`{"enabled": true}`; default off; `MOUSSE_NET_ENGINE=1` turns it on in dev).
`ProfileHost.startActiveProfiles()` already starts every active profile, so
every networked profile gets its helper, not only the open one.

- State dir: `<profileDir>/net-engine/endpoint/` (owner-only, as in Phase 0).
  If no endpoint exists, the daemon runs `mousse-helper --state <dir> init`
  once; the endpoint makes its own random profile id.
- Command: `mousse-helper --state <dir> serve --app --listen-ip 0.0.0.0
  --name "<computer> (<profile name>)"`. Not `--insecure-file-key`: the key
  is in the OS keystore, one entry per endpoint id.
- stdout/stderr go to `<profileDir>/net-engine/helper.log` (2 × 1 MB,
  rotated by the daemon). Secrets are never logged (Phase 0 rule).

**Attach first.** Before spawning, the daemon reads `control.json`. If a
helper answers there (an orphan from a crashed daemon), it attaches. If the
orphan's `build` differs from the bundled helper's, it sends `shutdown` and
spawns the bundled one. The endpoint lock guarantees one helper per
endpoint; a spawn that fails on the lock retries attach.

**Binary.** Packaged: `process.resourcesPath/net-helper/mousse-helper[.exe]`.
Dev: `MOUSSE_NET_HELPER` or `native/net-helper/target/package/`. The engine
commit is pinned in `native/net-helper/ENGINE_COMMIT`;
`scripts/build-net-helper.mjs` builds `cargo build --release --locked -p
mousse-helper` from it (`--require` for packaging, like
`build-voice-engine.mjs`). macOS signs it with the app identity. No helper
in the build: the switch shows "Not in this build" and stays off.

**Version handshake.** The first app message is `hello {proto: [1, 0]}`
(major, minor). The helper answers with its `proto`, `build`, endpoint
identity, port and routes. Different major: the daemon stops it and
respawns the bundled binary; if that also differs, the switch shows
"Networking helper is out of date" and stays off. Minor: both use the
lower. The daemon also checks the identity against the one it recorded at
`init`; a different identity means a swapped state dir and is refused.

**Crash restart.** Exit or channel EOF without `shutdown`: restart after
0.5 s, doubling to 30 s; the backoff resets after 60 s up. Five crashes in
5 minutes stop retries and show "Networking helper keeps stopping" until the
switch is toggled or the app restarts. Each restart is a fresh attach; the
app's sessions on the dead helper end as link loss (§3.4).

**Detach and linger.** If the app channel closes, the helper closes every
peer connection (`GOAWAY NO_ERROR`), keeps listening, refuses app streams
with `REFUSED_STREAM`, and exits after 60 s without a new attach. A second
attach replaces the first (the old one gets `{ev: "replaced"}`).

**Shutdown.** Profile dispose, switch off or app quit: `shutdown`, the
helper closes with `NO_ERROR` and exits within 1 s; the daemon kills it
after 3 s.

**Kept port.** The helper owns it: `port` (and `fixed_port`, Phase 1b) in
the endpoint file, as `Endpoint::bind(PortChoice::Kept)` does today. The app
never stores a port. If the kept port is taken at start, the helper takes a
new one and keeps that; peers find it through mDNS.

## 2. App ↔ helper protocol

### 2.1 Transport and auth

The Phase 0 control listener: a named pipe on Windows that only the current
user can open and that refuses remote clients; `127.0.0.1` plus token on
Unix. The app reads `control.json` (owner-only), connects, and sends one
line `{"cmd":"app","token":…,"proto":[1,0]}`. A wrong token gets the
Phase 0 error line and the close. After `{"attached":true}` the connection
uses the framing below. CLI commands (`invite`, `grants`, …) keep working
on the same listener with line JSON.

Why not stdio: the helper must outlive a daemon restart and accept a new
attach. Why not a socket per stream: one auth point, no pipe-instance or
port churn, and stream resets, peer-down and removal events stay ordered
with the data they end.

### 2.2 Framing

`u32 BE length | u8 type | body`, length = type + body, at most 1 MiB.

| type | body |
|---|---|
| `0x01` JSON | one UTF-8 JSON object (request, reply or event) |
| `0x02` DATA | `u32 stream` + bytes (≤ 64 KiB) |
| `0x03` CREDIT | `u32 stream` + `u32 bytes` |

A bad length, type or JSON closes the channel. The app side reuses the
length-prefix idea of `src/mms/protocol/framing.ts` in its own module;
`framing.ts` is not changed.

### 2.3 Streams and backpressure

Each direction of each app stream starts with 256 KiB of credit, as on the
wire.

- **Helper → app:** the helper calls `StreamReader::read` only while it has
  app credit for that stream, so a slow app consumer leaves engine credit
  unreturned and the remote writer waits. Backpressure reaches the peer.
- **App → helper:** the app sends DATA only within credit; the helper
  returns credit when `StreamWriter::write` completes (it waits at the
  engine's high-water mark).
- **One pipe, two classes:** the helper writes interactive frames ahead of
  bulk frames to the app, and DATA frames are at most 64 KiB, so a bulk
  transfer cannot hold up a keystroke for more than one frame.

Stream ids are `u32`, assigned by the helper, never reused within an attach.

### 2.4 Messages (protocol 1.0)

Requests carry `id`; replies are `{re, ok…}` or `{re, error, reason}`.
Events carry `ev`. Identities are SEC1 hex; `device` is the 16-hex short id.

| Group | App → helper | Helper → app |
|---|---|---|
| Session | `hello {proto}`; `config.set {name}`; `shutdown` | `hello {proto, build, identity, device, port, routes, mdns}`; `ev: replaced` |
| Invite (host) | `invite.create {kind:"in_person"}` → `{invitation, ticket, uri, routes, expires_at}`; `invite.cancel {invitation}`; `approval.answer {request, yes}` | `ev: approval {request, invitation, name, device}`; `ev: enrolled {invitation, grant, identity}`; `ev: invite.ended {invitation, reason}`; `ev: stale {request}` |
| Join (caller) | `join {ticket, name}` → `{identity, name, role}` or `error`; `join.cancel {id}` | `ev: join.progress {re, step: dialing, waiting_approval or paired_back}` |
| Peers and grants | `grants.list`; `peers.list`; `grant.remove {grant, deny}`; `peer.forget {identity}`; `denials.list`; `deny.remove {identity}`; `peer.addresses.set {identity, routes}` | `ev: grant.closed {grant, connections}`; `ev: store.failed {what, error}` |
| Connections | `dial {identity}` → `{conn, route, current}`; `conn.close {conn}` | `ev: conn.up {conn, identity, dir: in or out, grant?, role, name, deadline}`; `ev: conn.down {conn, identity, reason}` |
| Paths | `path.reopened {conn}` | `ev: path.reopen {identity, from, conn}`; `ev: path.renew_failed {identity, error}` |
| Streams | `stream.open {conn, label, class}` → `{stream}`; `stream.accept {stream}`; `stream.fin {stream}`; `stream.reset {stream, code}`; DATA; CREDIT | `ev: stream.incoming {conn, stream, label, class}`; `ev: stream.fin`; `ev: stream.reset {stream, code}`; DATA; CREDIT |

Errors use the wire's reason words (`not_authorized`, `grant_revoked`,
`pin_mismatch`, `path_replaced`, …). `join` is the long-running request
that reports the pairing outcome; `grant.remove` replies only after the
channels it closed are closed.

**Pair back (new, engine side).** When `join` succeeds, the joiner's helper
makes an in-person invitation **pre-approved for exactly the host it just
pinned** and sends its ticket on a `mousse.pair-back` stream of the new
connection. The host's helper accepts it only from a joiner its owner
approved in this invitation, joins that ticket, and reports
`join.progress {step:"paired_back"}` and a second `enrolled` on the joiner.
Any other identity presenting that ticket is declined. One tap, two grants,
both `owner`. This is a helper behaviour plus a short spec addendum
(`spec/wire.md` §10.9); the wire itself is unchanged.

## 3. The app's session layer on the engine

### 3.1 What runs unchanged, what is cut

| Kept | Cut on the engine path |
|---|---|
| `NetSyncSession` message handling: RPC, subscriptions, blobs, snapshots, pings | v1 TLS (`SecureChannel` becomes a stub) |
| `DurableRpcDispatcher` ledger and idempotent ids, `outcome_uncertain` | v1 mux (`link/mux`) |
| `SubscriptionReceiver` cursors | roster and delegation in `hello`, roster listener, delegation expiry |
| `NodeStreamAuthority`, private streams, `SqliteNodePolicy` | enrollment, route records, `lan.port.v1`, presence, tunnels, Spaces discovery |

### 3.2 `EngineMux`

New `src/mms/netEngine/engineMux.ts` implements `Mux` (`contracts.ts`) over
three engine streams the caller opens after `conn.up`:

| v1 lane | label | class |
|---|---|---|
| control | `mousse.app.control` | interactive |
| bulk | `mousse.app.bulk` | bulk |
| tunnel | `mousse.app.tunnel` (opened, unused in 1a) | interactive |

Each message is `u32 BE length | encodeMessage(header, parts)` (`sync/codec.ts`).
`queued(lane)` is the bytes waiting for helper credit. A reset of any lane
stream, or `conn.down`, closes the mux with the mapped error. The host side
builds its session when `mousse.app.control` arrives and attaches the other
two as they come; any other label is reset with `REFUSED_STREAM`.

### 3.3 Seams in shared files (smallest edits)

- `sync/session.ts`: option `enginePeer?: { bind(claimed: NodeId): SyncSession['peer']; expiresAt(): number }`.
  With it, the session's own `hello` omits `roster` and `delegation` (both
  already optional in the wire type), `hello()` calls `bind` instead of the
  roster path, `revalidateIdentity`/`currentDelegation` are skipped, and the
  expiry timer uses `expiresAt()` (the connection deadline). About 50 lines.
- `sync/rpcDispatcher.ts`: option `enginePeerCaps?(peer): readonly NodeCapability[] | undefined`.
  When it returns caps, `authorize()` uses them instead of the roster
  lookup; the method checks, `requires` and `authorizeMethod` hook stay.
  About 10 lines. This is the same site where PR #868 wires its Teams
  decision (§3.5), so both paths share one authorization point.
- `NetService.ts`: constructor option `engine?: EnginePeers`; public
  `openEngineSession({mux, channel, enginePeer, dir})` that calls the
  existing `makeSession` (all per-node policy, authority and private-stream
  closures reused) and records the link as transport `engine`;
  `connectedHere`/`admitted` also accept a node the engine reports as
  granted. About 40 lines.

Because engine sessions live in `NetService`'s own session set,
`net.session(node)`, `streamSubscribed`, `publishDelta`, `publish` and
`failStream` work for them unchanged, so **Bridge (RoutedClient,
ThreadRouter, attached terminals, BridgeHub) needs no edit**: they ask
`net.session(node)` per call.

Direction (Decision 6): the host-side session gets `rpc` and the stream
store; the caller-side session gets no `rpc` port and an authority that
refuses every read, so a host can never call into a caller over that
caller's connection.

### 3.4 Connect, path switch, loss

- `EngineNetService` keeps one `SyncSupervisor` per paired host whose
  `connect()` is: `dial` → open the three lane streams → `openEngineSession`
  → `await opened`.
- **Path switch** (`ev: path.reopen`, from renewal or address change): build
  a second session on the new `conn` and wait for `opened`, so new lookups
  land on it; let the old session's in-flight RPCs finish (at most 5 s,
  still well inside the old deadline); then `path.reopened {conn}`. The
  helper calls `Caller::reopened`, the old connection closes with
  `PATH_REPLACED`, and subscriptions that were on it re-attach on the new
  session from their cursors (the attached-terminal `reconcile` path).
  Nothing is replayed blindly.
- **Loss** (helper crash, `conn.down`): sessions close as link loss.
  `RoutedClient` waits up to 30 s and retries with the **same** RPC id; the
  host's ledger returns the stored result, or `outcome_uncertain`, which the
  UI shows as "outcome unknown". Terminal input keeps its sequence numbers,
  so the host drops repeats.
- **Removal** (`grant_revoked` / `not_authorized`): the supervisor stops
  retrying, and the device shows "No longer accepts this computer" with
  Remove.

### 3.5 What to reuse from the paused v1 branches

Networking work on v1 has stopped, so neither branch constrains Phase 1a.

- **PR #868 (Teams access), reuse later, not in 1a:** `teamAccess()` in
  `src/mms/teams/access.ts` (pure, deny-by-default, typed reasons), the
  `TeamDirectory` port in `src/shared/teams/types.ts` and the `crossUser`
  column on routed rows in `src/shared/bridge/routed.ts`. When Teams comes
  to the engine path, `enginePeerCaps`' caller in `authorize()` calls
  `teamAccess()` with the peer's bound user id, exactly where #868 calls it
  for v1. Its `netTeams` flag and the roster checks it keeps for allowed
  teammates are v1 and are not inherited. Phase 1a does not depend on #868
  merging; if it never merges, those three files are taken as they are.
- **`lan-offline-connect`, ignore:** it teaches v1's multicast LAN transport
  to reconnect without the relay. The engine has its own discovery (§5), so
  none of it carries over.

## 4. Identity mapping

| Thing | Keyed on | Where |
|---|---|---|
| Who the peer is (TLS, pins, grants) | endpoint identity (P-256), fingerprint | helper state dir |
| Device list row | fingerprint | `netEngine.devices` |
| App node id | peer's own `self.node`, claimed in `hello.node` | `net_engine_peers(fingerprint PK, node UNIQUE, name, role, claimed_user, paired_at)` in the profile's `net.db`, created by the engine module |
| Presets and per-device policy | `NodeId` | existing `net_node_policy` via `SqliteNodePolicy` |
| RPC caps | grant role → caps | `enginePeerCaps`: `owner` → `COMPUTER_NODE_CAPABILITIES`; others → none in 1a |
| `peer.user` | `owner` → this profile's own user id | synthesized |
| `peer.delegation` | synthesized, never signed, sent or stored: `subject` node, `owner` self user, `name` grant name, `caps` as above, `keyEpoch 0`, `expiresAt` the connection deadline | in memory |

Binding rules: the first session with a fingerprint binds its claimed node.
A later different claim from that fingerprint, a claim of a node bound to
another fingerprint, or a claim of a node in this profile's v1 roster closes
the session with `conflict`. Removing a device deletes its row, so a
re-pair binds afresh.

Teams: the app keeps Teams authorization keyed on `(user, node)` as today.
On the engine path that needs a teammate's user id bound at pairing, which
Phase 1a does not create (open question 3).

The device list shows each engine device once, as its grant name
"<computer> (<profile>)" (the joiner sets this as its helper `--name`), with
the short id in a tooltip, and whether each direction is granted.

## 5. Discovery

- **Advertise:** the existing `Advertiser`: one rotating random instance
  (`mousse-` + 12 base32, new at every start and every 15 min), random host
  name, TXT `v=1` only. Never an owner, profile or computer name.
- **Candidates**, in order: the last working route; manual addresses set on
  the device; the ticket's route hints; mDNS results (browse 1.5 s on
  demand, cached 60 s). At most 32, dialled four at a time with a 2 s
  connect timeout.
- **Pin mismatch** on a candidate means another endpoint (another profile on
  that computer, or a device that took the address): skip it with no
  warning and no re-pin (`Caller::dial_candidates` already does this). The
  pinned host's own refusal stops the search.
- **Background:** while a paired host is down, retry at 1 s doubling to
  60 s; a new mDNS instance appearing, or a local interface change (polled
  every 5 s), retries at once. An interface change also re-registers mDNS
  and re-dials hosts whose current path used a vanished local address
  (make-before-break, §3.4).
- **Manual fallback:** "Add address" on a device stores `tcp://host:port`
  in the helper's peer record (`peer.addresses.set`). mDNS can be off and
  pairing still works through the ticket's hints.

## 6. UI (behind the switch)

New files only, under `src/renderer/components/netEngine/`, mounted with
one line each. Copy stays short; details go in tooltips.

- **Settings → Devices:** `EngineDevicesSection`, mounted in
  `SettingsPage.tsx` beside `NetDevicesSection` (which is not edited).
  - Switch: "New networking (LAN)". Tooltip: what it is, that v1 devices
    are unaffected.
  - Rows: name, online/offline, "LAN" or the address in use. A selected row
    gets a background highlight only. Row menu: Access (the existing preset
    control, reused read-only by `node`), Add address, Remove.
  - "Add device" opens a dialog with two tabs:
    - **Show QR** (this computer hosts): QR of the in-person ticket and
      "Copy link". Tooltip on Copy: "Sharing this link shares the tap."
    - **Scan** (this computer joins): webcam scan (`jsQR`), and "Paste link".
      Then "Waiting for <host> to accept…", then "Connected".
- **Approval prompt:** `EngineApprovalPrompt`, mounted in `main.tsx` beside
  `EnrollmentRequestPrompt`: "Is <computer> (<profile>) next to you?" with
  Yes and No; the short id under the name. One prompt per request id; it
  closes when the invitation ends.
- **Remove:** confirm "Remove <name>? It loses access at once." Removing
  removes the grant and forgets the pin. The other side's row then reads
  "No longer accepts this computer".
- **Second profile:** when the switch is turned on and another profile on
  this computer already has it on, one line under the switch: "Profiles on
  this computer pair separately but share this OS account."

Plumbing: `src/shared/netEngine/local.ts` lists `netEngine.status`,
`netEngine.enable`, `netEngine.invite.create`, `netEngine.invite.cancel`,
`netEngine.approval.answer`, `netEngine.join`, `netEngine.join.cancel`,
`netEngine.devices`, `netEngine.remove`, `netEngine.addresses.set`. Changes
push as `ui.notify {kind:"net-engine"}` → `netEngine:changed`.

## 7. Owner checks: `checks/phase1a.toml` (sketch)

Engine-only checks are cargo tests. Checks that need the app run the Mousse
harness `scripts/net-engine-check.mjs` (two daemons, real helpers) with the
`marker` judge. The harness prints the app commit in its details and as
`extra.app_build`. App controls are `MOUSSE_NET_ENGINE_CONTROL=<name>`,
honoured only in unpackaged builds.

```toml
phase = "phase1a"
title = "Two desktops on a LAN (in-person only)"
plan = "docs/PLAN.md#phase-1a-two-desktops-on-a-lan-in-person-only"
# No [defer]: Phase 1a has no CPace check (in person needs no code).
# Inline `control = [...]` is the same TOML as [[check.control]] blocks.

[[check]]  # local: cargo test -p mousse-helper --test app_channel
id = "phase1a.app-channel"
title = "Only the owner's app attaches; frames, credit and version are enforced"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 12
control = [{ name = "app-skip-token", breaks = "attach accepted without the control token",
             env = { RUSTFLAGS = '--cfg mousse_control="app-skip-token"' } }]

[[check]]  # local: cargo test -p mousse-helper --test app_streams
id = "phase1a.backpressure"
title = "A stalled app stream stops the remote writer; other streams keep moving"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 4
control = [{ name = "read-without-credit", breaks = "the helper reads engine streams without app credit",
             env = { RUSTFLAGS = '--cfg mousse_control="read-without-credit"' } }]

[[check]]  # device result: harness confirms 1.1.1.1:443 and DNS unreachable, times scan to connected
id = "phase1a.pair-offline"
title = "Router cable unplugged: scan, tap, connected in under 10 s"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
control = [{ name = "wan-only-hints", expect_reason = "unreachable",
             breaks = "tickets carry no LAN hints and mDNS is off, so pairing needs a route off the LAN",
             env = { MOUSSE_NET_ENGINE_CONTROL = "wan-only-hints" } }]

[[check]]  # local cells: loopback, restart with mDNS off, host moves 127.0.0.2 -> 127.0.0.3; device cell: real LAN, DHCP change
id = "phase1a.reconnect"
title = "Reconnects after a restart of either side and after the host's address changes"
targets = ["windows-x64", "linux-x64", "pc-to-mac-lan"]
judge = "marker"
control = [
  { name = "forget-kept-port", expect_reason = "unreachable", breaks = "a fresh port at every start (run with mDNS off)",
    env = { RUSTFLAGS = '--cfg mousse_control="forget-kept-port"' } },
  { name = "no-rediscovery", expect_reason = "unreachable", breaks = "the caller tries only the last working route",
    env = { RUSTFLAGS = '--cfg mousse_control="no-rediscovery"' } },
]

[[check]]
id = "phase1a.removal"
title = "Removal refused at once: routed call and live terminal end, next dial refused"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
control = [
  { name = "keep-removed-grant", expect_reason = "still_connected", breaks = "removing a grant leaves it in force",
    env = { RUSTFLAGS = '--cfg mousse_control="keep-removed-grant"' } },
  { name = "keep-engine-session", expect_reason = "still_served", breaks = "the app keeps serving after grant_revoked",
    env = { MOUSSE_NET_ENGINE_CONTROL = "keep-engine-session" } },
]

[[check]]  # A removes the shared desktop: A's channels close; B stays connected with a live terminal and reconnects after a restart; neither dials the other's peers
id = "phase1a.shared-computer"
title = "Two profiles on one desktop each pair both ways with their own second desktop"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
control = [{ name = "shared-endpoint-state", breaks = "one key and one grant table for every endpoint on the machine",
             env = { RUSTFLAGS = '--cfg mousse_control="shared-endpoint-state"' } }]

[[check]]  # `mousse-check proxy` cuts the pipe once the host's reply starts; the kit kills the caller's helper; the input "echo <marker> >> f" keeps its sequence number across retries; the kit counts <marker> in f
id = "phase1a.once-or-unknown"
title = "Dropped ack and killed helper: the effect happens once, or the caller shows outcome unknown"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
control = [
  { name = "no-host-dedupe", expect_reason = "duplicate_effect", breaks = "the host runs a repeated RPC id or input sequence again",
    env = { MOUSSE_NET_ENGINE_CONTROL = "no-host-dedupe" } },
  { name = "claim-success-on-loss", expect_reason = "false_outcome", breaks = "the caller reports success when the outcome is unknown",
    env = { MOUSSE_NET_ENGINE_CONTROL = "claim-success-on-loss" } },
]

[[check]]  # local: cargo test -p mousse-net-io --test discovery (mDNS capture on a private interface)
id = "phase1a.discovery-privacy"
title = "mDNS carries no name; a pin mismatch moves to the next candidate with no warning or re-pin"
targets = ["linux-x64", "macos-arm64"]
min_tests = 6
control = [
  { name = "name-in-instance", breaks = "the instance name carries the device name",
    env = { RUSTFLAGS = '--cfg mousse_control="name-in-instance"' } },
  { name = "stop-on-mismatch", breaks = "the caller gives up at the first candidate with another identity",
    env = { RUSTFLAGS = '--cfg mousse_control="stop-on-mismatch"' } },
]
```

The cable-unplugged check depends on the owner's network, so it is a
device result signed with `mousse-check sign`, never a local run. The
first-run firewall and local-network prompts are answered before timing
starts (Risk 4).

## 8. Work breakdown

Ordered; each slice is one agent's PR. "E" is the engine repo, "M" is
Mousse. Existing v1 files are in bold; their edits stay at the seams of
§3.3.

| # | Repo, paths | What | Proved by |
|---|---|---|---|
| E1 | E `crates/mousse-helper/src/{ipc.rs,serve.rs,main.rs}`, new `app.rs`, `appframe.rs` | `serve --app`; `app` attach on the control listener; framing; hello/version; replace and linger; `term` refused in app mode | `tests/app_channel.rs` (fake app in Rust): bad token, wrong major, oversize frame, second attach replaces first, `term` refused; control `app-skip-token` |
| E2 | E new `streams.rs`; `serve.rs` | app streams over the channel with credit, interactive-first writer | `tests/app_streams.rs`: 64 MiB round trip intact; stalled stream blocks the remote writer while another stream keeps flowing; control `read-without-credit` |
| E3 | E `serve.rs`, `peer.rs`, new `app_pairing.rs` | host and caller in one process: invite/approval/join, grants, peers, remove/deny, addresses | `tests/app_pairing.rs`: two app-mode helpers pair on loopback; stale approval refused; removal closes before the reply; existing `loopback.rs` still passes |
| E4 | E `mousse-net-io/src/{host.rs,caller.rs}`, `spec/wire.md` §10.9, `app_pairing.rs` | pair back: pre-approved invitation scoped to one identity, `mousse.pair-back` stream | both grants after one approval; a third identity with the ticket is declined; `sim` seed for the pre-approval |
| E5 | E new `paths.rs`; `mousse-net-io/src/discovery.rs` | dial candidates, keep connected, `start_renewals` → `path.reopen`/`reopened`, interface watcher, continuous browse | `tests/app_paths.rs` with `ManualClock`: renewal reopen and confirm; restart reconnect via kept port; address change on loopback aliases; pin mismatch skipped; controls `forget-kept-port`, `no-rediscovery`, `stop-on-mismatch`, `name-in-instance` |
| E6 | E `crates/mousse-check`, `checks/phase1a.toml` | manifest; `mousse-check proxy` (cut after N reply bytes) | kit self-tests; `mousse-check phase1a` lists every cell |
| M1 | M `scripts/build-net-helper.mjs`, `native/net-helper/ENGINE_COMMIT`, `package.json` (extraResources, script) | build and package the helper | script builds on Windows and macOS; packaged app has `resources/net-helper` |
| M2 | M new `src/mms/netEngine/{helperProcess,helperChannel,frames}.ts` | spawn/attach/restart/shutdown; requests, events, stream credit | `tests/netEngine/helperChannel.test.ts` against a fake helper; one test against the real binary when built (skipped otherwise) |
| M3 | M new `src/mms/netEngine/{engineMux,engineChannel}.ts` | `Mux` over three helper streams | `Mux` contract tests on `EngineMux`; `queued()` grows when credit is withheld |
| M4 | M **`sync/session.ts`**, **`sync/rpcDispatcher.ts`** | `enginePeer` and `enginePeerCaps` seams | two sessions over `EngineMux`: hello without roster; RPC allowed by `owner` caps, refused for other roles; conflicting node claim refused; focused v1 session and dispatcher tests unchanged |
| M5 | M **`NetService.ts`**, **`MmsProfileServices.ts`**, new `src/mms/netEngine/{service,peers,registerMethods}.ts` | `EngineNetService`: peer table, sessions in/out, supervisors, path switch, removal | two in-process profiles with real helpers: routed call and terminal over the engine; removal ends the terminal and refuses the next call; path switch keeps terminal output gap-free and without repeats; killed helper → restart → reconnect |
| M6 | M new `src/shared/netEngine/local.ts`; **`registerGuiIpc.ts`**, **`protocolEventBridge.ts`**, **`preload/index.ts`** | methods and the `netEngine:changed` push | allow-list test; event reaches the renderer |
| M7 | M new `src/renderer/components/netEngine/*`; **`SettingsPage.tsx`**, **`main.tsx`**; dependency `jsqr` | §6 UI | component tests (list, approve, remove, scan/paste); real-app before/after captures in the PR |
| M8 | M new `scripts/net-engine-check.mjs`, control hooks in `netEngine/*` | app-level checks and controls of §7 | each check prints PASS; each control prints FAIL with its reason |

**Existing Mousse files Phase 1a touches, and why**

| File | Why |
|---|---|
| `src/mms/net/sync/session.ts` | `enginePeer` option (§3.3) |
| `src/mms/net/sync/rpcDispatcher.ts` | `enginePeerCaps` option |
| `src/mms/net/NetService.ts` | `engine` option, `openEngineSession`, two `admitted` checks |
| `src/mms/MmsProfileServices.ts` | start/stop `EngineNetService` under the switch; register methods |
| `src/main/ipc/registerGuiIpc.ts` | spread `NET_ENGINE_LOCAL_METHODS` |
| `src/main/mms/protocolEventBridge.ts` | `net-engine` notify → `netEngine:changed` |
| `src/preload/index.ts` | `net.onEngineChanged` |
| `src/renderer/components/SettingsPage.tsx` | mount `EngineDevicesSection` |
| `src/renderer/main.tsx` | mount `EngineApprovalPrompt` |
| `package.json` | extraResources, build script, `jsqr` |

Not touched: `NetDevicesSection.tsx`, `components/devices/*`,
`transports/*`, `link/*`, `framing.ts`, `shared/net/local.ts`, Bridge. The
devices screen stays separate in Phase 1a so v1 keeps working untouched;
Phase 2 folds the engine list into it when v1 goes.

## 9. Risks and open questions

**Risks**

1. **The session seam may be bigger than 50 lines.** `session.ts` refers to
   roster and delegation about 100 times. If `enginePeer` cannot stay small,
   the fallback is a slim `EngineSession` that implements only what Bridge
   uses (`rpc`, `rpcResult`, `rpcCancel`, `subscribe`, `getBlob`), still
   with the same ledger and cursors.
2. **v1 regressions from the seams.** The three seams in v1 files are off
   unless an engine peer is present; M4 and M5 run the focused v1 session,
   dispatcher and NetService tests to show v1 is unchanged.
3. **Desktops without a webcam.** Paste is the fallback. It weakens "in
   person" to "whoever has the link", which the warning states.
4. **First-run OS prompts.** Windows Firewall on the first `0.0.0.0` listen
   and the macOS local-network prompt can blow the 10 s budget the first
   time. The check runs after the prompts are answered; the installer may
   add a firewall rule later.
5. **Linux without a secret service.** No keystore means no endpoint; the
   switch says so. `--insecure-file-key` is never used by the app.
6. **Pair-back auto-approval** is a new trust step. It is scoped to one
   pinned identity and one invitation, but it needs the design review
   before E4 merges.

**Open questions for review** (least sure first)

1. **Reusing `NetSyncSession` at all** (Decision 3). The alternative is a
   new, small engine-native app session (RPC + cursored streams only) that
   Phase 2 keeps while v1's session goes. Reuse is faster for 1a; a new one
   may be less to delete later. Which costs less over Phases 1a–2?
2. **The node id claim** (Decision 4, §4): binding the peer's self-claimed
   `NodeId` under the engine pin, versus a local random id per fingerprint
   (IDs here are "never derived from keys") plus translation of node ids
   that cross the wire (private stream keys, qualified results).
3. **One-way sessions plus pair back** (Decisions 6, §2.4): two
   connections per pair of desktops and an automatic second enrollment,
   versus one connection that both sides may call over, authorized by each
   side's own grant table.
4. **Multiplexing streams over the app channel** (§2.3) instead of the
   kernel's backpressure from one local socket per stream.
5. **Helper life tied to the daemon** (Decision 1) versus a helper that
   runs on its own for the OS session (PLAN §8). If tied, should the
   daemon start at login?
6. **`owner` peers act as this user** (Decision 5, synthesized
   `peer.user` and delegation): is synthesizing v1 identity objects
   acceptable as a Phase 1a bridge?

**Other open questions**

1. Should the joiner's display name include the profile name by default,
   or only when the computer has more than one networked profile?
2. Does an `owner` grant from pairing stay the only role until Phase 4, or
   does Phase 1b add a `client` role with a preset of its own?
3. Teams on the engine path: bind a teammate's user id at pairing (claimed
   in `hello`, held under the pin, shown in the approval), then key Teams
   rules on `(user, node)` as today? This needs deciding before Phase 2
   deletes v1.
4. Spaces sync, presence and editor tunnels over the engine: which phase,
   and with which author identity once the v1 roster is gone?
