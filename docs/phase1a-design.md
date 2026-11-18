# Phase 1a design: the engine inside the desktop app

Status: design, round 2 (2026-11-18). Scope: PLAN "Phase 1a" (two desktops
on a LAN, in-person pairing only). Engine base: `phase-1a`; host persistence
before `PAIRED` and grant expiry at the traffic gate are being fixed in
Phase 0 on `p0-fix3-io`, and this design assumes those fixes. App base:
Mousse `master` at `b495dd151`.

Phase 1a adds the engine beside Mousse Net v1. v1 keeps working until
Phase 2 deletes it, and edits to v1 files stay small. A per-profile switch
turns the new path on. The goal is that a remote thread and a terminal work
through the normal computer picker **with v1 networking off**, on a fresh
profile.

## Changes since round 1

Round 1 had two reviews, both 4/10. Each finding (F = first review,
S = second, number = finding) is mapped to where it is resolved, or why it
is rejected.

| Finding | Resolution |
|---|---|
| F2, S1, open question 1: `NetSyncSession` reuse fails on `verifyRecord`/`verifyAuthor` (`session.ts:1798`, `NetIdentityService.ts:420`) and `revalidateIdentity` | Not reused. A narrow engine session (§3) keeps `DurableRpcDispatcher`, `SubscriptionReceiver`, the stream store and the codec. Record authenticity comes from the pinned channel at ingest and from a stored origin on reopen (§3.4). |
| F1, S1: Bridge finds computers in the v1 roster (`ThreadRouter.pairedComputers`, `accountDevices`, `deviceNameOf`, stager, `BridgeHub.session`), and the renderer reads `net.status`/`bridge.nodes` | New Bridge peer-directory port fed by the v1 roster and the engine table (§4.3). Engine peers appear in the normal picker. Proved by check `phase1a.picker-v1-off`. |
| F3, S2: who can use the path, `makeSession` needs v1 enrollment, the node-id claim is unproven | The engine path owns its gates. It mints a local id per peer fingerprint and grant, translates ids at the session boundary, and creates no synthetic users or delegations (§4). The same-Mousse-ID case and two local profiles pairing each other are decided in §4.4. |
| F4, S3: pair back grants `owner` with no joiner consent; paste links have no code; hints not LAN-only; enrollment and removal persistence | The joiner consents explicitly. Pair back is a direct local grant and the host simply dials; no invitation or spec machinery (§5). Durable receipts, idempotent recovery and explicit partial states. Copy/paste links dropped. Ticket hints private-range only. Removal fails closed (§5.4). Host persistence before `PAIRED` comes from `p0-fix3-io`. |
| F5, S4: `preferredSession` returns any open session; no RPC on the caller side; old path wins | Direction-aware selection: newest outbound generation only. Client capability is separate from serving authority, and a late close cannot unpublish the replacement (§3.5). Revocation tears Bridge down at once (§3.6). |
| F6: both desktops need inbound reachability | Per-direction reachability shown with fix text (§7); Risk 3 covers both machines. |
| S5, F9 (queues): one-frame claim, blocked reader, read-ahead, messages over 256 KiB | Independent pumps, bounded queues, reserved control capacity, interactive-first both ways, bounded read-ahead, and one stream per call so large bodies stream under credit (§2.3, §3.2). Tests stall bulk in both directions. |
| S6, F9 (lifecycle): `startActiveProfiles` has no caller; isolation; fencing; log; retry; Windows; env var; signing | §1. `startActiveProfiles` has no caller (verified). A background start of networked profiles is added with per-profile isolation. The app channel is now the child's stdio, so it is fenced by the process and needs no attach, linger or takeover. The helper writes its own log. Slow retry. `MOUSSE_NET_HELPER` only unpackaged. Signing: see Rejected. |
| F7, S7: checks not bound to builds, controls in the wrong binary, physical steps, tautological controls, reconnect without discovery, blind byte cut, shared topology, no pair-back check | §9 rewritten: both builds bound; debug helpers spawned by the harness; physical steps ATTESTED; automated cells inject ticket and approval and say so; `cable-plugged` control; injectable browse source; reply dropped by id after the host effect; four-endpoint topology; a pair-back check; each check lands with its slice. |
| F8: risky seam late; E5/M5 too big; checks in M8 | Slice S0 (vertical spike) comes first; E5 and M5 are split; checks land with their slices (§10). |
| F9 minor: `self.node` claim, Remove clean-up, rename refresh, untested macOS permission and long call across a path switch | No claims any more. Remove deletes the local id's policy row and private-stream bindings (§5.4). The name refreshes on each connection (§3.3). macOS local-network/keychain spike in M1. Multi-minute call across a path switch tested in M5b. |
| Situations (both) | §8, one line each. |
| Cuts (both) | Done: tunnel lane, global approval prompt, deny messages in protocol 1.0, linger/takeover, "new mDNS instance" retry, identity-at-init check, pre-approved invitation machinery. |

**Rejected or changed**

- **Login start (S6):** not in 1a. A profile is reachable once Mousse has
  been opened since login; the daemon stays up after the window closes
  (`src/main/index.ts`: "daemon keeps running"). A login item is
  per-OS packaging work (Run key, `SMAppService`, autostart) and no 1a exit
  item needs it. It lands with the CLI and headless work in Phase 1b; the
  PLAN §8 wording is noted as Phase 1b.
- **Signing only the helper (F9, coordinator):** the Windows app itself is
  unsigned today (`package.json` `"signExecutable": false`). Signing only
  the helper buys nothing for SmartScreen or the firewall prompt. The
  helper is signed with the same certificate in the same release step that
  signs the app; until then it ships as unsigned as the app.
- **Upgrading helpers one profile at a time (S, daily use):** an update
  replaces the daemon, and every helper exits with its daemon (stdio EOF),
  so all helpers stop together and the new daemon starts them. A staggered
  upgrade adds nothing.
- **Keeping the node-id claim (F, open question 2):** superseded by the
  agreed local id per fingerprint.

## Decisions

1. **The daemon owns each profile's helper as a child process.** The app
   channel is the child's stdin/stdout. The helper exits when that channel
   closes, so it lives exactly as long as its daemon.
2. **One channel, multiplexed,** with independent read and write pumps,
   bounded queues, reserved control capacity and interactive-first
   scheduling both ways (§2).
3. **A narrow engine session** carries Bridge only: routed RPC, stream
   subscriptions (thread display, private streams, terminals) and blob
   reads. It uses one engine stream per call, per subscription and per blob.
   `DurableRpcDispatcher`, `SubscriptionReceiver`, the stream store and the
   codec are reused; `NetSyncSession` is not.
4. **Local ids:** each engine peer gets a locally minted `NodeId`, keyed by
   (local endpoint, peer fingerprint, grant). Re-pairing mints a new one.
   Peers never claim ids, and ids that cross the wire are translated at the
   session boundary.
5. **`owner` is a typed local grant.** It allows an explicit Bridge method
   and stream allowlist, plus the existing per-call policy checks.
   `RpcContext.caller` becomes a union, and engine callers carry no
   delegation.
6. **One-way connections, two-way pairing.** A connection carries calls
   from caller to host only. Pairing makes both directions in one ceremony:
   the joiner consents in its dialog and grants the host locally, and the
   host dials back. "Connected" means both directions work.
7. **Bridge reads computers through a peer-directory port** fed by the v1
   roster and the engine table. Engine peers appear in the normal picker.
8. **In person = webcam scan only in 1a.** No paste or copy of links;
   shared links (with a code) are Phase 1b. Ticket hints are private-range
   addresses only.
9. **Reachable once Mousse has been opened since login** (no login item in
   1a).
10. **Keep connected:** each helper keeps one outbound path to every paired
    host while both are online.

## 1. Helper lifecycle

**Which profiles run a helper.** `ProfileHost.startActiveProfiles()` has no
caller today, and the GUI starts a profile's services on demand. Phase 1a
adds `ProfileHost.startNetworkedProfiles()`. The daemon calls it in the
background after it reports ready (`MousseMainService.ts`), so startup is
not slowed. It starts services only for profiles whose switch is on
(`<profileDir>/net-engine/settings.json`, `{"enabled": true, "profile":
"<profile id>"}`). Each profile starts in its own `try`: a failure marks
that profile's switch status "Couldn't start" and logs it, and the other
profiles carry on.

**Spawn.** The profile's `EngineHelper` runs:

    mousse-helper --state <profileDir>/net-engine/endpoint serve --app --listen-ip 0.0.0.0

The display name is not on the command line; it arrives in `hello`. If no
endpoint exists, the daemon first runs `mousse-helper --state <dir> init`.
`settings.json` records the app profile id. If the endpoint was made for
another profile id (a copied profile folder), the folder is moved aside,
re-initialized, and its devices show "Pair again". The key stays in the OS
keystore, one entry per endpoint id; `--insecure-file-key` is never used.

**Channel and fencing.** In app mode the helper speaks the §2 framing on
stdin/stdout and writes nothing else there. Its log goes to
`<state>/helper.log`, which it rotates itself (2 × 1 MB, secrets never
logged). The channel belongs to one process, so there is no token, no
attach, no takeover and no linger. Every event the daemon handles is tagged
with that spawn's generation number, and events from an older generation
are dropped. The CLI keeps the Phase 0 control listener.

**Exit with the daemon.** When stdin reaches EOF (the daemon exited or
crashed), the helper sends `GOAWAY NO_ERROR` and exits within 1 s. On
Windows a crashed parent closes its pipe handles, so EOF arrives without a
job object; M2 tests a hard kill of the daemon stand-in on Windows and
macOS. If a spawn finds the endpoint lock still held, the daemon retries
for 5 s, then reports "Another helper is still running".

**Binary.** Packaged builds use `process.resourcesPath/net-helper/mousse-helper[.exe]`,
resolved in the daemon process. Unpackaged builds also honour
`MOUSSE_NET_HELPER`, then `native/net-helper/target/package/`. The engine
commit is pinned in `native/net-helper/ENGINE_COMMIT`, and
`scripts/build-net-helper.mjs` builds it like `build-voice-engine.mjs`. A
build with no helper shows "Not in this build".

**Version.** The first frame is `hello {proto: [1, 0], name, profile}`; the
helper answers with `{proto, build, identity, device, port, routes}`. A
different major is a packaging error: "Networking helper is out of date",
switch off. For the minor version, both sides use the lower one.

**Restart.** If the helper exits without `shutdown`, the daemon restarts it
after 0.5 s, doubling to 5 min, and keeps trying at 5 min. The backoff
resets after 60 s up. After three fast crashes the status reads "Networking
helper keeps stopping (retrying)".

**Shutdown.** Profile dispose, switch off, app update or quit sends
`shutdown`; the daemon kills the helper after 3 s.

**Kept port:** owned by the helper in its endpoint file (`Endpoint::bind`,
`PortChoice::Kept`). The app never stores a port.

## 2. App ↔ helper protocol

### 2.1 Framing

`u32 BE length | u8 type | body`; the length counts the type byte and the
body, and is at most 1 MiB.

- `0x01` JSON: one object.
- `0x02` DATA: `u32 stream` + up to 64 KiB.
- `0x03` CREDIT: `u32 stream` + `u32 bytes`.

A malformed frame closes the channel, and the daemon restarts the helper.

### 2.2 Pumps, queues and priority (both sides)

- **Independent pumps.** Reading never waits on writing. The helper has
  one reader task and one writer task. The daemon reads in its `data`
  handler and writes from one drain loop.
- **Writer queues on each side:** control (JSON) first, then interactive
  DATA, then bulk DATA. Within a class, streams take turns per frame.
  Credit frames count as control.
- **Bounds:**
  - Per stream: the peer's credit, at most 256 KiB, so the sender never
    queues more.
  - Aggregate DATA queued: 8 MiB per side. Above it the side stops
    returning credit.
  - Control queue: 1 MiB reserved and never used by DATA. Event floods
    such as `conn.*` are coalesced per connection.
- **Bounded read-ahead.** The engine's `StreamReader::read` returns wire
  credit at once (`conn.rs:202`). So the helper calls `read` for a stream
  only while bytes buffered for the app plus 64 KiB fit inside the app's
  credit for that stream. The remote writer therefore stalls when the app
  stalls.
- **Latency claim:** an interactive frame waits behind at most one DATA
  frame already being written (≤ 64 KiB) plus what the OS pipe already
  holds; the pipe buffer is set to 64 KiB where the OS allows. E2 measures
  it.

### 2.3 Messages (protocol 1.0)

Requests carry `id`; replies are `{re, ...}` or `{re, error, reason}`;
events carry `ev`. Reasons use the wire's words.

- **Session:** `hello`; `config.set {name}`; `shutdown`.
- **Host:** `invite.create` returns `{invitation, uri, routes,
  expires_at}`; `invite.cancel`; `approval.answer {request, yes}`. Events:
  `approval {request, invitation, name, device}`, `enrolled {invitation,
  grant, identity}`, `invite.ended`.
- **Joiner:** `join {ticket}` returns `{identity, name, role}`;
  `join.cancel`. Event: `join.progress {re, step}`.
- **Grants and peers:**
  - `grants.list`, `peers.list`;
  - `grant.add {identity, name, receipt}`: a direct `owner` grant, used
    only by pair back (§5);
  - `grant.remove {grant}` replies after the save, or after networking is
    paused (§5.4);
  - `peer.add {identity, name, routes}` and `peer.forget {identity}`;
  - `peer.addresses.set {identity, routes}`.
  - Events: `grant.closed {grant, connections}`, `store.failed {what}`.
- **Connections:** `dial {identity}` returns `{conn, route}`. Events:
  `conn.up {conn, identity, dir, grant?, role, deadline}`, `conn.down
  {conn, identity, reason}`.
- **Paths:** `path.reopened {conn}`. Events: `path.reopen {identity, from,
  conn}`, `path.renew_failed`.
- **Streams:** `stream.open {conn, label, class}` returns `{stream}`;
  `stream.accept`, `stream.fin`, `stream.reset {stream, code}`, DATA,
  CREDIT. Events: `stream.incoming {conn, stream, label, class}`,
  `stream.fin`, `stream.reset`.

Deny lists, send links and tunnels are not in 1.0.

On an outbound connection the helper resets every stream the host opens.
On an inbound connection it passes on only the §3.2 labels.

## 3. The engine session

New code in `src/mms/netEngine/session/`. It does not import
`NetSyncSession` or `link/mux`.

### 3.1 What it reuses

| Reused | How |
|---|---|
| `DurableRpcDispatcher` | serves engine calls through `request/result/cancel` with an engine caller (§4.2); same ledger, idempotent ids, `outcome_uncertain` |
| `SubscriptionReceiver` | per subscription, with an engine `verify` callback (§3.4) and the store's cursor |
| `SqliteStreamStore` (`rt.streams`) | stores received records, with a side table for their origin |
| `sync/codec.ts` | `encodeMessage`/`decodeEnvelope` for record bytes |

### 3.2 Streams

| Label | Class | Opened by | Carries |
|---|---|---|---|
| `mousse.hello` | interactive | caller, once per connection | `{proto, name}` both ways; then the stream stays open as the liveness and rename channel |
| `mousse.rpc` | per method: interactive, or bulk for `ROUTED_LARGE_READS` and long methods | caller, one per call | `call {id, idem, method, params, deadline}`, then `progress*` and `result`; `result.get {id}` and `cancel {id}` use their own stream |
| `mousse.sub` | interactive | caller, one per subscription | `subscribe {stream key, cursor}`, then `head`, `records`, `delta`, `snapshot*`, `end {code}` |
| `mousse.blob` | bulk | caller, one per fetch | `get {stream key, blob}`, then bytes, then `FIN` |

Each message is `u32 BE length | JSON header | binary parts`, at most
16 MiB. Large params and results stream under credit: the receiver
reassembles a message as its bytes arrive and returns credit as it buffers.
Per-message size and the 8 MiB aggregate bound memory, and a message over
16 MiB resets its stream with `too_large`. The 48 KiB staging path
(`RoutedStager`) is not used on engine sessions; the client tells
`RoutedClient` its inline limit (16 MiB).

### 3.3 Hello and names

The caller opens `mousse.hello` right after `conn.up`. Both sides send
`{proto: [1,0], name}`. A different major closes the connection, and the row
reads "Update Mousse on <name>". The name refreshes the device row on every
connection, so a rename shows up. No node ids are sent.

### 3.4 Record authenticity

- **At ingest:** a record received on a `mousse.sub` stream of a live
  outbound connection to pinned peer P is accepted only if:
  - its descriptor's authority is P's local id here;
  - its envelope names that stream;
  - the receiver's cursor and overlap rules pass.

  Signatures and v1 authors are not checked. The engine pin is the proof.
  The record is stored with its origin in a new table
  `net_engine_record_origin(stream, seq, peer_local_id, grant)`.
- **On reopen from disk:** readers of these streams (thread projection,
  hub, artifacts) ask the peer directory (§4.3) to verify a record.
  - **Engine origin:** valid while that local id still names a live
    pairing.
  - **Removed peer:** the stream reads as gone.
  - **v1 origin:** the existing `verifyAuthor` path.

  The local database is owner-only, like every other local store.
- **Host side:** records are produced as today by `ThreadStreamAdapter`,
  signed with the profile's local node key. The engine switch creates that
  local key and self identity if missing, using the existing local
  `bootstrapAuthority` with no passphrase. No v1 transport, listener or
  roster peer is turned on. S0 proves this on a fresh profile.

### 3.5 Direction and selection

- **Serving authority** exists only on inbound connections, from the
  grant in `conn.up`.
- **Client capability** exists only on outbound connections.

These are two objects, never inferred from what ports a session has.

`EngineSessions.client(localId)` returns the client of the newest outbound
generation that is open. Each new connection to a peer increments that
peer's generation. A closing client clears the slot only if the slot still
holds its own generation, so a late close cannot unpublish the replacement.
Both dial orders are tested.

### 3.6 Revocation, loss and path switch

- **Revocation** (`grant.closed`, or `conn.down` with `grant_revoked`):
  within one event turn the host side
  - aborts that caller's running handlers through the dispatcher,
  - ends its subscriptions and blob reads,
  - ends terminals it attached with no grace period,
  - and drops it from the directory.

  The caller side marks the computer "Removed by <name>" (§5.4).
- **Loss** (helper exit, `conn.down` for other reasons): open calls end as
  link loss. `RoutedClient` waits up to 30 s and retries with the same id;
  the host ledger returns the result or `outcome_uncertain`, shown as
  "outcome unknown". Terminal input keeps its sequence numbers, and the
  host drops repeats. PTYs are daemon-owned, so a helper restart does not
  end them. After a host daemon restart a terminal whose PTY is gone shows
  as ended.
- **Path switch** (`path.reopen`): run `hello` on the new connection;
  re-subscribe every live subscription on it from its cursor; wait until
  each has its `head`; publish the new generation; let calls on the old
  connection finish (at most 5 s); then send `path.reopened`. The old
  connection closes with `PATH_REPLACED`. M5b covers a multi-minute call
  across a switch.

## 4. Identity and Bridge

### 4.1 Local ids

`net_engine_peers(local_id PK, endpoint, fingerprint, grant, peer_record,
name, state, paired_at)` lives in the profile's `net.db`, created by the
engine module.

- `local_id` is `newId('node')`, minted when a pairing is first recorded.
  It is unique per (local endpoint, full peer fingerprint, grant).
- Removing a device deletes its row, its `net_node_policy` row, its
  private-stream bindings, its record origins and its streams. A re-pair
  gets a new id, so policy and ledger history never carry over.

**Translation at the session boundary:**

- The host fills any caller-node field in params from the session.
- Private stream keys travel with the reader segment as the token `@you`,
  which each side swaps for its own id.
- The caller qualifies results with its local id for the host.

S0 lists every node-id field in `ROUTED_METHODS` params and results and
assigns each to one of these three rules.

### 4.2 Authorization

`RpcContext.caller` becomes `V1Peer | EngineCaller`, where `EngineCaller`
is `{source: 'engine', node: local_id, user: self user, grant, endpoint}`
and has no `delegation`.

- **Owner principal:** an `owner` grant means the owner acting from
  another of their computers, so `user` is this profile's own user id.
  It is the key handlers already use for "who started this run" and
  uploads.
- **Compiler audit:** every reader of `caller.delegation` must narrow the
  union first.
- **Dispatcher:** `DurableRpcDispatcher.authorize()` sends engine callers
  to `authorizeEngine`. It checks:
  - the grant is live and still `owner`;
  - the method is in `ENGINE_OWNER_METHODS`, an explicit list in
    `src/shared/netEngine/allowlist.ts` taken from `ROUTED_METHODS` (no
    editor, tunnel or Spaces methods);
  - the existing `authorizeMethod` hook and per-node policy, keyed by
    `local_id`: blocked, terminal, max permission mode, bots, agent reach.
- **Streams:** served only if they are display streams of kind
  `node.thread` or lists, or private streams whose reader is that caller's
  `local_id`. Policy checks are as today.
- Other roles get nothing in 1a.

### 4.3 Bridge peer-directory port

New `src/mms/bridge/peers.ts`:

    interface PeerDirectory {
      computers(): ComputerRef[]          // listed, not blocked, connected
      name(node): string | undefined
      has(node): boolean
      client(node): BridgeClient          // rpc, rpcResult, rpcCancel, subscribe, getBlob; throws peer_offline
      verifyRecord(stream, record): void  // §3.4
      publish / publishDelta / discardDeltas / failStream / isSubscribed
    }

It merges two sources:

- **v1:** today's roster logic, moved behind the port unchanged.
- **Engine:** the engine table.

Today's Bridge code switches to the port:

- `ThreadRouter.pairedComputers` and `isOnline`
- `botReach.accountDevices`
- `deviceNameOf`
- `RoutedStager`: v1 only
- `BridgeHub.session`'s roster check (`hub/service.ts:256`) and the check
  in `canReceive` (`:1183`)
- the author and roster checks in `artifacts.ts` (`verifyAuthor` at `:191`, `:283`, `:381`; roster at `:531`)
- `ThreadStreamAdapter`'s `isSubscribed`, `onDelta` and `onRecord` fan-out,
  which today calls `net.publish`

Bridge's gate becomes "v1 Bridge features on, or the engine switch on".
`bridge.nodes` returns the merged list. In the renderer, `computers.ts`
asks for `bridge.nodes` when `netEngine.status` says on, even if
`net.status` is off. `NetService.ts` is not changed.

### 4.4 Cases

- **Same Mousse ID on both desktops, also paired over v1:** the computer
  appears twice in 1a, once per path. The row's tooltip says which path.
  Nothing links them, because that would need a cross-proof of v1 and
  engine keys, and v1 goes in Phase 2. With v1 off, one row.
- **Two profiles on one computer pairing each other:** allowed; they are
  separate endpoints. The approval shows "<computer> (<profile>)".
- **Teams:** none on the engine path in 1a. Before Phase 2 it needs
  account membership authenticated independently and bound to the
  endpoint, then `teamAccess()` (PR #868) at the `authorizeEngine` site.

## 5. Pairing both ways

### 5.1 Ceremony

1. Host: Add device → Show QR. `invite.create`; the QR holds the
   in-person ticket.
2. Joiner: Add device → Scan. After the scan the dialog reads
   "Connect to <host>? <host> will also be able to use this computer." and
   offers **Connect** and Cancel. This tap is the joiner's consent to both
   directions.
3. The joiner's helper joins. The host's dialog asks "Is <computer>
   (<profile>) next to you?" with Yes and No. The approval lives inside the
   host's Add-device dialog; closing it or switching profile cancels the
   invitation.
4. Host persists the grant, then sends `PAIRED` (`p0-fix3-io`). The
   joiner's app writes a durable receipt (`state = joined`, the host's
   identity, `receipt = random 128-bit`).
5. The joiner calls `grant.add {host identity, name, receipt}` and records
   `state = granted`. Its client then sends `pairback {routes, receipt}` on
   its `mousse.hello` stream.
6. The host's app checks that the identity of that connection is the grant
   it just made, then calls `peer.add {identity from the connection,
   routes}` and dials back. A successful `conn.up` (out) there and its
   `hello` mark `state = connected` on the host, which answers
   `pairback.done {receipt}`. The joiner records `state = connected`.

The host's identity and the routes come from the pinned connection, never
from a ticket either side could have forwarded.

### 5.2 States and recovery

Device rows show:

- `connected`: "Connected", both directions work.
- `joined` or `granted` on the joiner, `peer_added` on the host: "Finishing
  pairing…". This is retried on every connection: the joiner re-sends
  `pairback` until `pairback.done`. `grant.add` and `peer.add` are
  idempotent by identity and receipt.
- One direction failing for 2 minutes: "<host> can't reach this computer"
  or "This computer can't reach <host>", with fix text (firewall, same
  network). Remove is always offered.

If Cancel is pressed before the host's Yes, nothing is granted on either
side. If the joiner crashes after `PAIRED`, its receipt resumes the steps
at next start. If the host crashes before dialling back, the joiner's
retry resumes them.

### 5.3 Ticket hints

1a tickets carry only RFC 1918, IPv4 link-local excluded, and IPv6 ULA
(`fc00::/7`) addresses. CGNAT/tailnet (`100.64/10`) addresses are left out;
they come in Phase 1b.

### 5.4 Removal (fail-closed)

Remove on A for B:

1. Remove B's grant and forget B's pin, both in A's helper.
2. Delete B's row and data (§4.1).

The helper's grant removal writes the grant table before replying. If the
save fails, the helper **pauses all networking**: it closes every
connection, stops listening and refuses dials. It retries the save every
second, and the app shows "Couldn't save a removal; networking is paused".
A restart in that state starts paused until the save succeeds. A removed
device can never come back because of a failed save.

On B, a refusal from the pinned A with `not_authorized` or
`grant_revoked` removes B's grant for A as well. The row then reads
"Removed by <A>", with Remove to clear it.

## 6. Discovery

- **Advertise:** the existing rotating random instance; TXT `v=1` only.
- **Candidates**, in order: last working route; manual addresses; ticket
  hints; mDNS results (browse 1.5 s, cached 60 s). They are persisted in
  the helper's peer record (`peers.json`), since `Caller` keeps routes in
  memory only (`caller.rs:108`).
- **Dialling:** in parallel, four at a time, 2 s connect timeout. This
  replaces the sequential `dial_candidates` loop (`caller.rs:395`) in E5a.
- **Pin mismatch:** the next candidate, with no warning and no re-pin. The
  pinned host's own refusal stops the search.
- **Background:** while a paired host is down, retry at 1 s doubling to
  60 s. A local interface change (polled every 5 s) or a wake (§8) retries
  at once. A new mDNS instance name is not a trigger, because names rotate.
- **Browse source:** a trait with the mDNS implementation and a
  file-backed one that only debug builds read (`MOUSSE_HELPER_BROWSE_FILE`),
  for checks.

## 7. UI

All new components live under `src/renderer/components/netEngine/`.

- **Settings → Devices:** `EngineDevicesSection`, mounted in
  `SettingsPage.tsx`.
  - Switch "New networking (LAN)".
  - Rows: name, the short id in small text (two profiles look alike),
    state from §5.2 per direction, and "LAN" or the address in use.
  - Clock errors use the PLAN's neutral message: "the certificate is
    outside its validity window; check this device's clock".
  - Menu: Access (the existing preset control, by `local_id`), Add
    address, Remove.
  - A selected row gets a background highlight only.
- **Add device dialog:** Show QR or Scan (webcam, `jsQR`). The host's
  approval question appears inside this dialog. If the helper restarts
  during an invitation, the QR regenerates. No camera: "Scan from the
  other computer instead" (both directions pair either way).
- **Normal picker:** engine computers appear wherever v1 computers do,
  through `bridge.nodes`.
- **Push:** `ui.notify {kind: "net-engine", profileId}` →
  `netEngine:changed`. Windows refresh only for their own profile.

## 8. Situations

- **Sleep/wake:** the helper sees a monotonic jump over 10 s. It pings
  every connection with a 2 s deadline, drops dead ones, resets backoff,
  re-registers mDNS and re-dials; clients resume from cursors.
- **App update:** the daemon stops profiles, so helpers get `shutdown` or
  EOF and exit; the new daemon starts them. No lock outlives the old
  daemon by more than 3 s.
- **Profile switch:** every networked profile's helper keeps running.
  Dialogs and actions apply to the selected profile, and its open
  Add-device dialog cancels its invitation.
- **Profile remove:** stop the helper, delete the keystore entry and the
  state folder.
- **Profile restore without its key:** re-init; devices show "Pair again".
- **Profile copy:** the profile-id mismatch (§1) re-inits the copy.
- **Helper restart mid-invitation:** the invitation is gone. The host's QR
  regenerates; the joiner sees "Scan again".
- **Wrong clock:** the neutral message on the device row; no guess about
  which side is wrong.
- **Mixed versions:** an engine wire minor mismatch negotiates down. An app
  protocol major mismatch shows "Update Mousse on <name>".
- **Helper restart with live terminals:** PTYs survive (daemon-owned), and
  output resumes from the cursor.

## 9. Owner checks: `checks/phase1a.toml` (sketch)

**Build binding.** App-level checks run `scripts/net-engine-check.mjs`
(Mousse repo) with `MOUSSE_NET_HELPER` pointing at the kit's own build of
the helper. A control check builds that helper in debug with the control's
cfg, so the defect is in the binary the harness spawns.

Every result carries `extra.app_build` (clean Mousse commit) and
`extra.helper_build`. A kit change, landing in E6, adds
`require_extra = ["app_build", "helper_build"]` and requires `helper_build`
to equal the build under test. App controls are
`MOUSSE_NET_ENGINE_CONTROL=<name>`; app faults are
`MOUSSE_NET_ENGINE_FAULT=<name>`. Both work only in unpackaged builds.

**Topology.** Shared-computer checks use four endpoints:

- PC profile A paired with Mac profile C;
- PC profile B paired with Mac profile D.

```toml
phase = "phase1a"
title = "Two desktops on a LAN (in-person only)"
plan = "docs/PLAN.md#phase-1a-two-desktops-on-a-lan-in-person-only"
# Inline `control = [...]` equals [[check.control]] blocks. A slice lands its checks.

[[check]]  # S0: cargo-free; node harness, two fresh profiles in one machine, v1 off
id = "phase1a.picker-v1-off"
title = "With v1 off on fresh profiles, a remote thread and a terminal work through the normal picker"
targets = ["windows-x64", "macos-arm64"]
judge = "marker"
control = [{ name = "roster-only-directory", expect_reason = "not_listed",
  breaks = "the peer directory reads only the v1 roster", env = { MOUSSE_NET_ENGINE_CONTROL = "roster-only-directory" } }]

[[check]]  # E1+E2: cargo test -p mousse-helper --test app_channel --test app_streams
id = "phase1a.app-channel"
title = "Channel framing, credit, pumps and priority: bulk stalled both ways, interactive echo p95 < 20 ms, revocation event < 100 ms"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 14
control = [
  { name = "read-without-credit", breaks = "the helper reads engine streams without app credit",
    env = { RUSTFLAGS = '--cfg mousse_control="read-without-credit"' } },
  { name = "fifo-writer", breaks = "one FIFO writer queue for control, interactive and bulk",
    env = { RUSTFLAGS = '--cfg mousse_control="fifo-writer"' } },
]

[[check]]  # automated LAN cell: the kit injects the ticket and answers the approval (stated in details); offline verified
id = "phase1a.pair-offline"
title = "Internet unreachable: pair over LAN and connected both ways in under 10 s"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
control = [{ name = "cable-plugged", expect_reason = "internet_reachable",
  breaks = "run with the router's WAN cable in; the harness must refuse it", env = { MOUSSE_CHECK_EXPECT_ONLINE = "1" } }]

[[check]]
id = "phase1a.pair-in-person"
title = "Router cable unplugged: webcam scan, Connect, Yes, connected in under 10 s"
targets = ["pc-to-mac-lan"]
manual = true
steps = "unplug WAN; Show QR on the Mac; Scan on the PC; Connect; Yes; time to Connected on both"

[[check]]  # E5a+M5a: loopback; restart with mDNS off (kept port); host moves 127.0.0.2 -> .3 found via the browse file
id = "phase1a.reconnect"
title = "Reconnects after a restart of either side and after the host's address changes"
targets = ["windows-x64", "linux-x64", "pc-to-mac-lan"]
judge = "marker"
control = [
  { name = "forget-kept-port", expect_reason = "unreachable", breaks = "a fresh port at every start",
    env = { RUSTFLAGS = '--cfg mousse_control="forget-kept-port"' } },
  { name = "no-rediscovery", expect_reason = "unreachable", breaks = "the caller tries only the last working route",
    env = { RUSTFLAGS = '--cfg mousse_control="no-rediscovery"' } },
]

[[check]]  # M5a: one ceremony gives both directions; kill joiner after PAIRED and host before dial-back: recovers to Connected; Cancel before Yes grants nothing
id = "phase1a.pair-both-ways"
title = "Pair back: consent, durable recovery, Connected only when both directions work"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
control = [{ name = "no-pairback-retry", expect_reason = "one_way_stuck",
  breaks = "the joiner does not resend pairback after a crash", env = { MOUSSE_NET_ENGINE_CONTROL = "no-pairback-retry" } }]

[[check]]  # M5a: routed call and live terminal end at once; next dial refused; save failure pauses networking and a restart keeps it refused
id = "phase1a.removal"
title = "Removal refused at once, closes channels and tears down Bridge work; fails closed on a save error"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
control = [
  { name = "keep-removed-grant", expect_reason = "still_connected", breaks = "removing a grant leaves it in force",
    env = { RUSTFLAGS = '--cfg mousse_control="keep-removed-grant"' } },
  { name = "keep-engine-work", expect_reason = "stale_work", breaks = "the host app keeps handlers and subscriptions after grant.closed",
    env = { MOUSSE_NET_ENGINE_CONTROL = "keep-engine-work" } },
  { name = "save-fails-open", expect_reason = "served_after_failed_save", breaks = "a failed save leaves networking on",
    env = { RUSTFLAGS = '--cfg mousse_control="save-fails-open"' } },
]

[[check]]  # four endpoints (A<->C, B<->D); A removes C: A's channels close; B<->D stays, B's terminal stays live, B reconnects after restart; A cannot dial D, B cannot dial C
id = "phase1a.shared-computer"
title = "Two profiles on one desktop, each paired both ways with its own profile on the second desktop"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
control = [{ name = "shared-endpoint-state", expect_reason = "other_profile_affected",
  breaks = "one key and one grant table for every endpoint on the machine",
  env = { RUSTFLAGS = '--cfg mousse_control="shared-endpoint-state"' } }]

[[check]]  # host fault drops the reply of the identified call after the effect; kit kills the caller's helper; retry; kit reads the effect file. PTY input dedupe tested separately.
id = "phase1a.once-or-unknown"
title = "Dropped reply and killed helper: the effect happens once, or the caller shows outcome unknown"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
control = [
  { name = "no-host-dedupe", expect_reason = "duplicate_effect", breaks = "the host runs a repeated call id or input sequence again",
    env = { MOUSSE_NET_ENGINE_CONTROL = "no-host-dedupe" } },
  { name = "claim-success-on-loss", expect_reason = "false_outcome", breaks = "the caller reports success when the outcome is unknown",
    env = { MOUSSE_NET_ENGINE_CONTROL = "claim-success-on-loss" } },
]

[[check]]  # E5a: mDNS capture; pin mismatch skips to the next candidate
id = "phase1a.discovery"
title = "mDNS carries no name; a pin mismatch moves on with no warning or re-pin; hints are private-range only"
targets = ["linux-x64", "macos-arm64"]
min_tests = 8
control = [
  { name = "name-in-instance", breaks = "the instance name carries the device name",
    env = { RUSTFLAGS = '--cfg mousse_control="name-in-instance"' } },
  { name = "stop-on-mismatch", breaks = "the caller gives up at the first candidate with another identity",
    env = { RUSTFLAGS = '--cfg mousse_control="stop-on-mismatch"' } },
]
```

## 10. Work breakdown

Each slice is one agent's PR and lands its own checks. E = engine repo,
M = Mousse. Existing Mousse files are in bold.

| # | Paths | What | Proved by |
|---|---|---|---|
| S0 | M new `src/mms/netEngine/session/*`, `peers.ts` stub; **`rpcDispatcher.ts`** (`EngineCaller`) | vertical spike over in-memory engine streams, no helper: two fresh profiles, v1 off, one routed call and one terminal stream; node-id field list (§4.1); local bootstrap of the signing key | `tests/netEngine/spike.test.ts`; output is the go/no-go for §3–§4 |
| E1 | E `mousse-helper/src/{main.rs,serve.rs}`, new `app.rs`, `appframe.rs`, `log.rs` | `serve --app` on stdio, framing, hello, own log, exit on EOF, `term` refused | `tests/app_channel.rs` |
| E2 | E new `streams.rs` | pumps, queues, credit, read-ahead, priority | `tests/app_streams.rs`: bulk stalled both ways; latency thresholds; 64 MiB intact; controls `read-without-credit`, `fifo-writer` |
| E3 | E `serve.rs`, `peer.rs`, new `app_pairing.rs`; `mousse-net-io/src/host.rs` (`grant_direct`) | host and caller in one process; invite/approval/join; `grant.add`/`remove` with fail-closed pause; `peer.add`/`forget`/`addresses` | `tests/app_pairing.rs`; control `save-fails-open`; Phase 0 `loopback.rs` passes |
| E5a | E new `paths.rs`; `mousse-net-io/src/{caller.rs,discovery.rs}` | persisted candidates, parallel dial, keep connected, browse-source trait, private-range hints | `tests/app_paths.rs`; check `phase1a.discovery` |
| E5b | E `paths.rs` | renewals → `path.reopen`/`reopened`, interface watcher, wake detection | `ManualClock` tests: reopen then confirm; wake; address change |
| E6 | E `crates/mousse-check`, `checks/phase1a.toml` | `require_extra`, build binding | kit self-tests |
| M1 | M `scripts/build-net-helper.mjs`, `native/net-helper/ENGINE_COMMIT`, **`package.json`** | build and package; macOS local-network and keychain spike for a daemon-spawned helper | packaged app runs the helper on Windows and macOS |
| M2 | M new `src/mms/netEngine/{helperProcess,helperChannel}.ts`; **`ProfileHost.ts`**, **`MousseMainService.ts`** | spawn, restart, shutdown, pumps; `startNetworkedProfiles` with isolation | fake-helper tests; real-helper test; hard kill of the parent on Windows and macOS ends the helper |
| M3 | M `netEngine/session/*` | full engine session over the helper; dispatcher `authorizeEngine`; allowlist | session tests; check `phase1a.once-or-unknown` |
| M4 | M **`bridge/peers.ts`** (new) and the Bridge call sites in §4.3; **`BridgeProfileService.ts`** | peer-directory port; publish fan-out; gate | v1 Bridge tests unchanged; check `phase1a.picker-v1-off` |
| M5a | M new `netEngine/{service,peers,pairing}.ts`; **`MmsProfileServices.ts`** | peer table, selection, revocation teardown, both-ways pairing, removal | checks `phase1a.pair-both-ways`, `phase1a.removal`, `phase1a.reconnect` |
| M5b | M `netEngine/service.ts` | path switch | terminal output gap-free across a switch; multi-minute call survives it |
| M6 | M new `src/shared/netEngine/local.ts`; **`registerGuiIpc.ts`**, **`protocolEventBridge.ts`**, **`preload/index.ts`**, **`renderer/lib/computers.ts`** | methods, push, picker source | allow-list test |
| M7 | M new `components/netEngine/*`; **`SettingsPage.tsx`**; dependency `jsqr` | §7 UI | component tests; real-app captures; checks `phase1a.pair-offline`, `phase1a.pair-in-person`, `phase1a.shared-computer` |

**Existing Mousse files touched, and why**

- **Profiles and daemon:**
  - `ProfileHost.ts` and `MousseMainService.ts`: background
    `startNetworkedProfiles`.
  - `MmsProfileServices.ts`: start and stop the engine service under the
    switch.
- **Dispatcher:** `sync/rpcDispatcher.ts` and `contracts.ts`
  (`RpcContext.caller` union): `EngineCaller` and `authorizeEngine`.
- **Bridge:** `BridgeProfileService.ts`, `routed/ThreadRouter.ts`,
  `remote/botReach.ts`, `routed/deviceName.ts`, `routed/stager.ts`,
  `routed/RoutedClient.ts` (inline limit), `hub/service.ts`,
  `artifacts.ts`: read peers, sessions and record checks through the port.
- **Handlers:** any that read `caller.delegation`, as the compiler lists
  them.
- **Main, preload and renderer:**
  - `registerGuiIpc.ts`, `protocolEventBridge.ts` and `preload/index.ts`:
    methods and the push;
  - `renderer/lib/computers.ts`: the picker source;
  - `SettingsPage.tsx`: the mount.
- **Packaging:** `package.json`.

Not touched: `NetService.ts`, `sync/session.ts`, `sync/supervisor.ts`,
`transports/*`, `link/*`, `NetDevicesSection.tsx`, `components/devices/*`.

## 11. Risks and open questions

**Risks**

1. **Bridge identity runs deeper than listed.** S0 is the gate. If the
   node-id field list or the record-check sites in §4.3 grow past a day's
   work, stop and re-plan before E-slices beyond E2.
2. **Host-side signing still uses the local v1 key** (§3.4). It is local
   only, but Phase 2 must replace the record author when v1 identity goes.
3. **Both desktops need inbound reachability**, so Windows Firewall and the
   macOS local-network prompt can appear on either machine. Rows say which
   direction fails and how to fix it. The in-person check runs after the
   prompts are answered.
4. **Linux without a secret service:** no endpoint; the switch says so.
5. **No webcam on either desktop:** cannot pair until Phase 1b send links.

**Open questions for round 2**

1. Is the origin-table trust model (§3.4) enough for records read back
   after a peer is removed and re-paired under a new local id? This design
   deletes them on removal.
2. `EngineCaller.user = self user` for `owner` (§4.2): acceptable as the
   owner's own principal, or should handlers move to a separate principal
   field now?
3. Should "Finishing pairing…" time out into an automatic removal of the
   half grant, rather than staying until Remove?
4. Is the `@you` token swap for private stream keys enough, or should
   engine sessions use stream handles that carry no node ids at all?
