# Phase 1a design: the engine inside the desktop app

Status: design, frozen (2026-11-18). Scope: PLAN "Phase 1a" (two desktops
on a LAN, in-person pairing only).

- **Engine base:** `phase-1a`. Host persistence before `PAIRED` and grant
  expiry at the traffic gate are Phase 0 fixes on `p0-fix3-io`; this design
  assumes them.
- **App base:** Mousse `master` at `b495dd151`. All app line references
  are against it.

Phase 1a adds the engine beside Mousse Net v1. v1 keeps working until
Phase 2 deletes it, and edits to v1 files stay small. A per-profile switch
turns the new path on.

**Goal:** a remote thread and a terminal work through the normal computer
picker, with v1 networking off, on a fresh profile that has no `net.db`.

The review history is in this file's git log.

**Amendment after S0.** The frozen text said the picker's views avoid the
Hub. That was false.

- The routed thread, terminal, list and Git-progress views all attach
  through `BridgeHub.attach` (`attachedThreads.ts:300`, `:742`;
  `attachedTerminals.ts:173`; `mergedLists.ts:450`).
- The Hub therefore gets its engine branch in S0 and M4, which is Risk 1's
  remedy moved forward (§4.3).
- `bridge.hub.*` local methods still answer `not_supported` for engine ids.

## Decisions

1. **The helper is a child process of the daemon.** There is one per
   networked profile, and the app channel is its stdin/stdout. The helper
   exits when that channel closes.
2. **One multiplexed channel**, with independent pumps, an aggregate credit
   budget, reserved control capacity, and interactive traffic first in both
   directions (§2).
3. **A narrow engine session** carries Bridge only. It reuses the runtime's
   own `rt.rpc` (`DurableRpcDispatcher`), `SubscriptionReceiver`, stream
   store, codec, artifacts and paging. `NetSyncSession` is not used.
4. **Local ids.** Each pairing gets a `NodeId` minted on this computer,
   keyed by (local endpoint, peer fingerprint, grant). Ids are never claimed
   by the peer.
5. **`owner` is a typed local grant.** It covers an explicit method and
   stream allowlist, plus the shared per-node policy (`checkNodePolicy`).
6. **One-way connections, two-way pairing.** One ceremony pairs both
   directions. The joiner consents, and the host dials back. "Connected"
   means both directions work.
7. **Bridge reads computers through a peer directory**, which merges v1 and
   the engine. With v1 off, the engine service builds the runtime and
   activates Bridge.
8. **In person means webcam scan only in 1a.** Every address a peer
   supplies must be in a private range.
9. **Reachability.** A profile is reachable once Mousse has been opened
   since login. There is no login item in 1a.
10. **Keep connected.** Each helper keeps one outbound path to every paired
    host while both are online.
11. **No hard-coded limits.** Every timeout, cap, window, size, count and
    retry delay is a named default in one place, overridable by a
    `MOUSSE_NET_*` environment variable read once at startup. Bad values are
    reported at startup. Limits a security bound depends on are clamped to
    the spec's safe range. Every variable is documented.

## 1. Helper lifecycle

**Which profiles run a helper.** `ProfileHost.startActiveProfiles()` has no
caller today.

- Phase 1a adds `ProfileHost.startNetworkedProfiles()`. The daemon calls it
  in the background after it reports ready (`MousseMainService.ts`).
- It starts each profile whose switch is on, read from
  `<profileDir>/net-engine/settings.json`
  (`{"enabled": true, "profile": "<id>"}`).
- Each profile starts in its own `try`. A failure marks only that profile
  "Couldn't start".

**Spawn.** The command is
`mousse-helper --state <profileDir>/net-engine/endpoint serve --app --listen-ip 0.0.0.0`.

- With no endpoint, the daemon first runs `init --app` with its stdin
  piped. Like `serve --app`, it exits at once when that stdin closes, so
  a daemon killed during a first start leaves no `init` behind.
- The key is kept in the OS keystore, one entry per endpoint.
- If `settings.json` names another profile id (a copied folder), the
  endpoint is moved aside and re-initialized. Its devices then show "Pair
  again".

**Channel and fencing.**

- The helper writes only §2 frames to stdout.
- Its log is `<state>/helper.log`, rotated by the helper (2 × 1 MB, with
  no secrets).
- The channel belongs to one process, so there is no attach, takeover or
  linger.
- Events are tagged with the spawn's generation, and the daemon drops
  events from older generations.
- The CLI keeps the Phase 0 control listener.

**Exit.**

- On stdin EOF (the daemon exited or crashed), the helper sends
  `GOAWAY NO_ERROR` and exits within 1 s. M2 tests a hard kill of the
  parent on Windows and macOS.
- If the endpoint lock is still held at spawn, the daemon retries for 5 s,
  then reports "Another helper is still running".

**Binary.**

- Packaged builds use `process.resourcesPath/net-helper/mousse-helper[.exe]`.
- `MOUSSE_NET_HELPER` is read only in unpackaged builds.
- The engine commit is pinned in `native/net-helper/ENGINE_COMMIT`, and
  `scripts/build-net-helper.mjs` builds it.
- A build with no helper shows "Not in this build".

**Version.** The daemon sends `hello {proto: [1,0], name, profile}`. The
helper answers `{proto, build, identity, device, port, routes}`.

- A different major is a packaging error, and the switch turns off.
- For the minor, both sides use the lower one.

**Restart.** If the helper exits without `shutdown`, the daemon restarts
it.

- Backoff starts at 0.5 s and doubles to 5 min, then retries every 5 min.
  It resets after 60 s up.
- After three fast crashes, the status reads "Networking helper keeps
  stopping (retrying)".

**Shutdown.** Profile dispose, switch off, update or quit sends `shutdown`.
The daemon kills the helper after 3 s.

**Port.** The kept port lives in the helper's endpoint file; the app never
stores a port.

## 2. App ↔ helper protocol

### 2.1 Framing

Each frame is `u32 BE length | u8 type | body`, at most 1 MiB.

- `0x01` JSON
- `0x02` DATA: `u32 handle | u8 flags` + at most 64 KiB. Flag `0x01` is
  FIN.
- `0x03` CREDIT: `u32 handle | u32 bytes`

A malformed frame closes the channel, and the daemon restarts the helper.

**Stream handles.** Wire stream numbers restart on every connection
(`mux/mod.rs:233`), so two peers or two paths can use the same number at
once.

- The helper gives every stream a handle that is unique for the life of
  the spawn and never reused.
- A handle is bound to (connection, generation, wire stream).
- `stream.open` returns a handle, and `stream.incoming` carries one.
- DATA, CREDIT and `stream.reset` name only handles.
- A frame for an unknown or closed handle is dropped and counted.

**FIN in order.**

- FIN is a flag on a DATA frame, which may be empty, in that stream's own
  queue. It therefore follows every byte queued before it.
- There is no JSON `stream.fin`.
- `stream.reset` is JSON and may overtake queued data, because a reset
  discards the stream.

E1 tests both: two connections using the same wire stream number at once,
and a final write stalled on credit with FIN queued behind it.

### 2.2 Pumps, budget and priority (both sides)

- **Independent pumps.** Reading never waits on writing.
- **Writer order:** control (JSON and CREDIT), then interactive DATA, then
  bulk DATA. Streams take turns within a class.
- **Admission at the engine receive queue.**
  - The engine gives every wire stream 256 KiB of initial credit when it
    opens (`INITIAL_CREDIT`, `mux/mod.rs:29`). It queues arriving DATA in an
    unbounded channel before any read (`conn.rs:866`).
  - With up to 1,024 peer streams (`MAX_PEER_STREAMS`), that is 256 MiB per
    connection, which app credit cannot bound.
  - E2 therefore caps open streams at 32 per connection (both directions
    counted) and 128 per helper. Bot streams (`mousse.botsub`,
    `mousse.botrpc`, `mousse.botview`) have places of their own, 16 per
    connection and 64 per helper, and engine streams 4 per connection.
    That keeps initial credit at or below 13 MiB per connection (52
    streams) and 48 MiB per helper for app and bot streams (192 streams),
    plus 1 MiB per connection for engine streams. Each connection raises
    its mux's `MAX_PEER_STREAMS`, where lower, to all of the places its
    admission gives (52 by default), so the mux never refuses an open
    before its room's cap is looked at.
  - A peer's open beyond a cap is reset; E2 names the reset code in
    `spec/wire.md`. The app session queues its own opens past the cap.
  - Credit beyond the initial grant returns only as the app reads (see
    read-ahead below).
  - E2 measures the queued bytes with app reads stalled on every stream,
    and asserts they stay within these bounds.
- **App credit.** Each side grants app-channel credit from an 8 MiB budget,
  at most 256 KiB per stream, with 1 MiB reserved for interactive streams.
  A stream that cannot get credit waits. A bot's chat and calls
  (`mousse.botsub`, `mousse.botrpc`) draw on a 4 MiB pool of their own
  instead, apart from the budget: threads can't use it and bots can't use
  the budget. One bot stream holds at most a quarter of that pool, so a
  stalled reader can't pin it. `mousse.botview` counts as bulk and uses
  neither reserve nor the bot pool.
- **Control.** 1 MiB of queue is reserved for control. `conn.*` events are
  coalesced per connection.
- **Read-ahead.** The engine's `StreamReader::read` returns wire credit
  immediately (`conn.rs:202`). The helper therefore reads a stream only
  while the app's credit covers what it has buffered plus 64 KiB. A remote
  writer stalls when the app stalls.
- **Latency.** An interactive frame waits behind at most one DATA frame
  already being written, plus the OS pipe buffer (64 KiB where it can be
  set). E2 measures it.

### 2.3 Messages (protocol 1.0)

Requests carry `id`. Replies are `{re, ...}` or `{re, error, reason}`.
Events carry `ev`.

- **Session:** `hello`, `config.set {name}`, `shutdown`.
- **Host:** `invite.create` returns `{invitation, uri, routes, expires_at}`.
  - Also `invite.cancel` and `approval.answer {request, yes}`.
  - Events: `approval`, `enrolled {invitation, grant, identity}` and
    `invite.ended`.
- **Joiner:** `join {ticket, pinned}` returns
  `{identity, name, role, already}`.
  - `pinned` accepts "already paired" from the ticket's host identity (§5.1).
  - Also `join.cancel`. Event: `join.progress`.
- **Grants and peers:**
  - `grants.list`, `peers.list`;
  - `grant.add {identity, name, receipt}`, idempotent;
  - `grant.remove {grant}` (§5.4);
  - `peer.add {identity, name, routes}`, `peer.forget`;
  - `peer.addresses.set {identity, routes}`. Routes outside private ranges
    are refused with `bad_route`.
  - Events: `grant.closed {grant, connections}` and `store.failed`.
- **Connections:** `dial {identity}`.
  - Events: `conn.up {conn, identity, dir, grant?, role, deadline}` and
    `conn.down {conn, identity, reason}`.
- **Paths:** `path.reopened {conn}`.
  - Events: `path.reopen {identity, from, conn}` and `path.renew_failed`.
- **Streams:** `stream.open {conn, label, class}` returns `{handle}`.
  - Also `stream.accept {handle}`, `stream.reset {handle, code}`, DATA
    (with FIN) and CREDIT.
  - Events: `stream.incoming {conn, handle, label, class}` and
    `stream.reset`.

Not in 1.0: deny lists, send links and tunnels. On an outbound connection,
the helper resets every stream the host opens. On an inbound connection, it
passes on only the §3.2 labels.

**Both ways on one connection (protocol minor 3, added after 1.0).** Every
`conn.up` carries `both`: `true` when the connection's agreed minor is 3 or
more, so it carries calls both ways.
- On an inbound connection with `both`, the app may `stream.open` toward
  the caller (after the caller has opened a stream: wire.md 8, step 4).
  Without it, `stream.open` there answers `one_way`.
- On an outbound connection with `both`, a stream the host opens arrives as
  `stream.incoming {conn, handle, label, class, grant, role}`. `grant` and
  `role` are this computer's live grant for the host, which the app serves
  the stream under, as it serves an inbound connection under the grant on
  its `conn.up`. A host without a live grant here gets `REFUSED_STREAM`,
  and the app sees nothing.
- When that grant stops being live (a removal, an expiry, a pause), the
  helper resets the streams served under it: `stream.reset {handle, code:
  "grant_revoked"}`. The connection stays up.
- A peer from before minor 3 gives `both: false`, and calls stay one way.

## 3. The engine session

The session code is new, in `src/mms/netEngine/session/`. It does not
import `NetSyncSession` or `link/mux`.

### 3.1 Reused, unchanged

| Reused | How it is used |
|---|---|
| `rt.rpc` (`DurableRpcDispatcher`) | The runtime's own instance, so the real daemon handlers serve engine calls. Same ledger, idempotent ids and `outcome_uncertain` behaviour. |
| `SubscriptionReceiver` | One per subscription, with the engine `verify` callback (§3.4). |
| `rt.streams` | Engine streams keep the host's stream id, and each is bound to one pairing (§3.4). |
| `sync/codec.ts` | `MAX_JSON_NODES` (16,384) applies to params, as today. |
| `ArtifactPublisher`, `routed.page`, `RoutedStager` | Large results and params take the existing paths (§3.3). |

### 3.2 Streams

| Label | Class | Opened by | Carries |
|---|---|---|---|
| `mousse.hello` | interactive | caller, once per connection | `{proto, name}` both ways, then `pairback`; kept open as the liveness and rename channel |
| `mousse.rpc` | per method: interactive, or bulk for `ROUTED_LARGE_READS` | caller, one per call | `call {id, idem, method, params, deadline}`, then `progress*` and `result`. Also `result.get` and `cancel`. |
| `mousse.sub` | interactive | caller, one per subscription | `subscribe {stream, cursor}`, then `head`, `records`, `delta`, `snapshot*`, `end` |
| `mousse.blob` | bulk | caller, one per fetch | `get {stream, blob}`, then raw bytes, then `FIN` |
| `mousse.put` | bulk | caller, for staging | `append {stream, event, envelope}` or `blob.put {stream, blob}` followed by the bytes; only into the caller's own `node.artifact` input streams (§4.4) |
| `mousse.botsub` | interactive | caller, one per bot subscription | as `mousse.sub`, for a bot's feed and chat |
| `mousse.botrpc` | interactive | caller, one per bot call | as `mousse.rpc`, for bot methods |
| `mousse.botview` | bulk | caller, one per watched bot browser | a bot's live browser pictures, newest only: the sender skips stale pictures when credit runs short; nothing is stored or retried |

The three bot labels take places of their own in the receiver's stream
admission (`BOT_STREAMS_PER_CONNECTION`, `BOT_STREAMS_PER_ENDPOINT`), apart
from the caps of §2.2, so thread traffic never refuses a bot's chat, call or
browser view. The helper passes them like the others; which methods and
kinds each may carry is the app's to check.

Each message is `u32 BE length | JSON header | binary parts`.

### 3.3 Sizes

- A message is at most `MAX_FRAME_BYTES` (64 KiB), as on v1. A record
  batch splits at that limit. Blob bytes stream raw under credit.
- Three large-data paths, each exercised separately in S0:
  - **Paged read:** a non-durable reply over `ROUTED_REPLY_MAX_BYTES` is
    held in the owner's page cache (`OwnerRoutes.ts:702`), keyed by the
    caller's local id. It is fetched with `routed.page`.
  - **Durable artifact reply:** a ledgered result over 63 KiB goes to the
    artifact publisher (`rpcDispatcher.ts:250`). That creates a
    `node.artifact` stream owned by the caller, which the caller subscribes
    to before fetching its blob (§4.4).
  - **Staged write:** params larger than a message, or over 16,384 JSON
    nodes, go through `RoutedStager`. It calls `bridge.artifacts.open`,
    then `blob.put` and `append` on `mousse.put`, then `routed.stage`. S0
    runs this through the production allowlist.
    - Today the host checks the staged record's v1 author (`artifacts.ts`
      `verifyAuthor` sites).
    - The engine branch instead checks that the stream is an input artifact
      whose `caller` is the session's local id. It ignores the author fields
      and the signature.
- Artifact ownership and method authorization stay on the host.
- Reassembly is bounded by the §2.2 budget: at most one 64 KiB message per
  stream, inside the aggregate.

### 3.4 Record identity (caller side)

Engine streams keep the host's stream id. The stream checks in the receiver
(`subscription.ts:55`, `:122`), the store (`streams.ts:69`) and the Hub
therefore pass unchanged.

- **Binding.** The first subscribe writes
  `net_engine_streams(stream PK, peer_local_id)` in the same transaction as
  the descriptor, which gets `authority = peer_local_id`.
- **One binding per stream.** A subscribe is refused with
  `stream_bound_elsewhere` if the stream already has a descriptor under
  another authority: another pairing, or v1.
- Cursors, epochs and snapshot generations are the store's own, because
  each stream belongs to one pairing.
- **At ingest**, the `verify` callback accepts a record only if:
  - the subscription runs on a live outbound connection of the pairing
    that the stream's row names;
  - the receiver's own checks pass.

  Signatures and v1 author checks are not run on this branch; the pinned
  channel is the proof. S0 covers live records and a snapshot install.
- **On reopen**, a stream whose authority is an engine local id is read
  only through `directory.verifyStream(stream)`. That requires both:
  - a `net_engine_streams` row;
  - a `net_engine_peers` row for it in a serving state (§5.2).

  Otherwise the stream reads as gone.

### 3.5 Host-side author (v1 off)

- Records are produced by `ThreadStreamAdapter` and signed with the
  profile's local node key, as today.
- If the profile has no `identity.self()`, the engine service runs
  `rt.identity.bootstrapAuthority(name)` with no passphrase.
- The self-delegation lasts 7 days (`NODE_DELEGATION_TTL_MS`), and v1
  renews it only after `activate()`. `renewExpiring()` also skips a
  delegation that lapsed 30 or more days ago (`NetIdentityService.ts:809`).
- The engine service therefore calls a new `identity.renewSelf()` at start
  and hourly while the switch is on. It re-issues this profile's own
  delegation however long it has lapsed, because the profile is its own
  authority.
- S0 runs again with the clock moved 8 days and 40 days, and holds a
  terminal open through a renewal.
- **Non-keeper profiles.** A profile that joined another computer's v1
  network holds no root key, so `renewSelf()` cannot sign
  (`NetIdentityService.ts:792`).
  - There, the switch works only while v1 is on, because v1 keeps renewing
    through its keeper.
  - With v1 off, the switch refuses with "This profile's network is managed
    by another computer. Turn its networking on, or Start over."
  - S0 covers both cases.
- **Roster changes.** The roster listener in `net.runtime()` releases
  private resources for every node missing from the v1 roster
  (`NetService.ts:910`, `BridgeProfileService.ts:689`). Engine local ids are
  never in that roster, so `release` also keeps every node that the peer
  directory lists in a serving state.

**Consequence.** The profile becomes a v1 keeper. A later v1 join on it
fails with "Local identity already exists" (`NetIdentityService.ts:155`)
until v1 "Start over".

- Start over moves the whole `net/` folder aside (`NetService.ts:1605`),
  and the engine's rows are in that folder.
- So Start over first stops the engine service, then moves `net-engine/`
  aside with `net/`. Devices show "Pair again".
- This uses a new `onSetAside` hook in `setAsideNetwork`.

### 3.6 Direction and selection

- Serving authority exists only on inbound connections, from `conn.up`'s
  grant.
- Client capability exists only on outbound connections.
- `EngineSessions.client(localId)` returns the newest outbound generation
  that is open and handoff-ready (§3.7).
- A closing client clears the slot only if the slot still holds its own
  generation. Both dial orders are tested.

### 3.7 Revocation, loss and path switch

**Revocation** (`grant.closed`, or `conn.down` with `grant_revoked`). Within
one event turn, the host:

- aborts that caller's handlers;
- ends its subscriptions, blob reads and staged writes;
- ends the terminals it attached;
- drops it from the directory.

Only revocation aborts handlers.

- Teardown is one idempotent function, `teardown(localId)`. It runs:
  - on `grant.closed`;
  - when the app sets the row to `removing` (§5.4);
  - again on recovery, for every `removing` or `removed` row.
- So a helper that dies after saving a removal, but before it sends
  `grant.closed`, leaves nothing running.

**Loss** (any other `conn.down`, or a helper exit):

- Host handlers keep running to their deadline, and their results land in
  the ledger keyed by the local id.
- The caller retries on the next connection with the same id.
- `result.get` waits only for engine callers: the dispatcher branches on
  `caller.source` (`rpcDispatcher.ts:404-418`), and v1 is unchanged.
  - A `running` record whose execution is live in this process is waited
    on, up to the call's deadline.
  - A `running` record with no live execution here (the daemon restarted)
    answers `outcome_uncertain` at once.
  - `authorizeEngine` is checked again after the wait.
- RoutedClient asks with the call's remaining budget instead of a fixed
  15 s (`RoutedClient.ts:385`). v1 hosts answer at once, so v1 behaviour
  does not change.
- Terminal input keeps its sequence numbers, and the host drops repeats.
- PTYs are owned by the daemon and survive a helper restart.

**Path switch** (`path.reopen`):

1. Run `hello` on the candidate.
2. Re-subscribe every live subscription from its cursor, and wait for each
   `head`.
3. The candidate is now handoff-ready. Publish its generation; new calls
   use it.
4. Keep the old connection until its calls have results. This is bounded
   by each call's deadline and by the connection's effective deadline. If
   that deadline cuts a call off, it is collected with `result.get` on the
   new connection.
5. Send `path.reopened`. The old connection closes with `PATH_REPLACED`.

If the candidate fails before step 3, it is dropped and the old path
stays. `PATH_REPLACED` never aborts a handler.

## 4. Identity and Bridge

### 4.1 Local ids

`net_engine_peers(local_id PK, endpoint, fingerprint, grant, name, state,
receipt, paired_at)` lives in `net.db`.

- `local_id` comes from `newId('node')`.
- A re-pair after Remove gets a new id, so policy, ledger and artifacts
  never carry over.

### 4.2 The engine caller

`RpcContext.caller` becomes `V1Peer | EngineCaller`:

    { source: 'engine', node: LocalId, user: SelfUser, role: 'owner', grant, endpoint }

- **`user`.** An `owner` grant is the owner acting from another of their
  computers, so `user` is this profile's own user id. Handlers compare
  `caller.user` the same way today (`dispatch/service.ts:123`,
  `RemoteApi.ts`, `artifacts.ts:413`).
- **`role` is the literal `'owner'`.** No other role can produce an
  `EngineCaller` in 1a.
- **`node` is the local id.** It keys policy, the ledger
  (`net_rpc_aliases.caller`), artifact ownership
  (`net_bridge_artifacts.caller`), private readers and run audit ("started
  from <device>").
- The union is narrowed wherever `caller.delegation` is read. The compiler
  lists those sites.

### 4.3 Running with v1 off

**Shared policy.** The per-node part of `authorizeMethod`
(`NetService.ts:660-681`: blocked, `workOnThreads`, terminal, work) moves
into a new `checkNodePolicy(method, node, policy, config)`.

- `NetService`'s hook keeps its v1 gates (`assertEnabled`, `assertFeature`,
  `connectedHere`), then calls `checkNodePolicy`.
- The engine branch of `DurableRpcDispatcher.authorize()` calls
  `authorizeEngine`, which checks, in order:
  - the grant is live and `owner`;
  - the method is in `ENGINE_OWNER_METHODS` (`src/shared/netEngine/allowlist.ts`);
  - then `checkNodePolicy`.

**`ENGINE_OWNER_METHODS`** contains:

- the `routed.*` rows of `ROUTED_METHODS`;
- `routed.stream.open`, `routed.stream.close` and `routed.page` from
  `ROUTED_TRANSPORT_METHODS`;
- `bridge.artifacts.open` and `routed.stage`, for staging.
  `bridge.artifacts.open` authorizes its `forMethod` through the same
  allowlist (`artifacts.ts:94-99`);
- `net.info`, read-only, which RoutedClient uses to negotiate versions
  (`RoutedClient.ts:132`).

It excludes the editor, tunnel and Spaces methods.

**Who builds and activates.** When the switch is on, `NetEngineService.start()`:

1. calls `net.runtime()`. That opens or creates `net.db` and composes
   Bridge through `composeRuntime`. It starts no transport; S0 asserts no
   listener and that `net.status` stays off.
2. bootstraps the author if needed (§3.5).
3. calls `bridge.activateBridge()`, the `netBridge` branch of
   `onActivated` (`BridgeProfileService.ts:783-788`) moved into its own
   method. `onActivated` calls it too.

**Gates.** `BridgeProfileService` gains:

- `bridgeOn() = net.featureEnabled('netBridge') || engine.on()`;
- `bridgeThreadsOn() = (netBridge && netBridgeThreads) || engine.on()`.

They replace the gates at:

- `ThreadRouter.ts:148`;
- `BridgeProfileService.ts:738`, `:755` and `:783`;
- the `MmsProfileServices.bridge` getter (`:354`).

Spaces gates stay v1-only.

**Entry points.**

- `bridge.nodes` (in `NET_LOCAL_METHODS`, served from `NetService.request`
  at `:1089`) is routed in `mms/net/registerMethods.ts` to
  `profile.peers.nodes()`. That includes `net.nodesView()` only when v1 is
  on.
- **`bridge.policy`:** served today by `NetService.request` behind
  `assertEnabled` (`:1056`) and a roster lookup (`:1255`).
  - It is routed in `registerMethods.ts`. For an engine local id it goes to
    `engine.setPolicy`, which requires a serving `net_engine_peers` row and
    writes `rt.policy`.
  - Other ids go to `NetService` as today.
  - The Access control and `picker-v1-off` set terminal access through it.
- The other Bridge methods reach `profile.bridge` through
  `registerBridgeMethods`. The `bridge.hub.*` and activity handlers there
  (`bridge/registerMethods.ts:110`, `:138`) call `bridgeOn()` instead of
  `net.assertFeature('netBridge')`.
- `BridgeProfileService.ts:135` and `:447` read the directory instead of
  `net.request('bridge.nodes')`.
- **The Hub's engine branch.** The routed views attach through
  `BridgeHub.attach` (see the amendment). For engine-bound streams the Hub
  changes in four places:
  - **Session:** it gets its session from `directory.client(node)`, not
    `net.session(node)` (`BridgeProfileService.ts:525`).
  - **Attach:** it checks authority against the stream's
    `net_engine_streams` binding, not the v1 node (`hub/service.ts:970`).
    It writes that binding in the same transaction as its own descriptor
    write.
  - **Records:** `verifyRecord`, replay and snapshot install
    (`:1203-1215`, `:1243`, `:1097`) use the engine `verify` callback
    (§3.4) instead of v1 author checks.
  - **Session calls:** the Hub's `subscribe`, `onClosed`, `onEphemeral` and
    `state` (`:1012`, `:1043`, `:1049`) come from `BridgeClient`.

  `bridge.hub.*` local methods still answer `not_supported` for engine
  ids.
- In the renderer, `computers.ts:105-112` also lists computers when
  `netEngine.status` is on.

**`NetService.ts` edits:**

- extract `checkNodePolicy`;
- make `nodesView` public;
- remove the `bridge.nodes` branch;
- add the `onSetAside` hook (§3.5).

### 4.4 Streams and blobs served to an engine caller

1a serves only streams explicitly bound to the caller; there is no
display-stream fallback. Every subscribe, delivered batch, blob fetch and
`mousse.put` write needs one of these:

1. **Routed private stream** (thread, lists, channel or terminal).
   - `privateAccess(stream)` returns `open: true`, and `reader` equals the
     caller's local id.
   - If the stream also has a bound reader (`boundReader`, as on a phone's
     lists), that equals the local id too.
   - Current policy allows the kind: a terminal needs `terminal`; every
     kind, terminal included, needs the device not blocked and Work on
     threads not off. (Settled in S0.)
2. **Artifact.** A `node.artifact` stream whose
   `net_bridge_artifacts.caller` equals the local id, with a matching
   capability. `mousse.put` may write only into the caller's own input
   artifacts.

Anything else is refused, including display streams and any stream whose
binding was deleted. The checks run again on every batch. A blob also needs
`blobs.isReferenced(blob, stream)`.

At removal the host deletes the caller's private streams together with
their bindings (§5.4), so no unbound stream is left behind.

**Keys stay on the host.** `routed.stream.open` builds the private key from
the session's reader (`privateStreams.ts:27`), and callers name streams by
`{kind, subject}`. S0's field list checks that no reader id or private key
crosses the wire.

### 4.5 Peer directory

New `src/mms/bridge/peers.ts`:

    interface PeerDirectory {
      nodes(): NodesView                       // bridge.nodes rows: v1 (if on) + engine
      computers(): ComputerRef[]; name(node); has(node)
      client(node): BridgeClient               // the SyncSession subset RoutedClient and the Hub use: rpc, rpcResult, rpcCancel, subscribe, getBlob, append, putBlob, state, onClosed, onEphemeral
      verifyStream(stream): void
      publish / publishDelta / discardDeltas / failStream / isSubscribed
    }

These call sites move to the directory:

- `ThreadRouter`'s `RoutedClient` session (`ThreadRouter.ts:113`, today
  `net.session(node)`), plus `pairedComputers` and `isOnline`
- `botReach.accountDevices` and `deviceNameOf`
- `RoutedStager` (its session and roster lookup)
- the roster sites in `artifacts.ts`, with the §3.3 staging branch
- `ThreadStreamAdapter`'s fan-out

**Session hooks.** These are the engine's equivalents of `onSessionOpened`
and `onSessionClosed` (`BridgeProfileService.ts:752-777`).

- When a client becomes handoff-ready, the engine service calls
  `router.nodeOnline(id)` and `lists.nodeOnline(id)`.
- When its last client closes, it calls `lists.nodeOffline(id)`.
- It calls `hub.reconnect(id)` before those, as v1's `onSessionOpened` does.

### 4.6 Cases

- **Same Mousse ID, also paired over v1:** two rows in 1a, one per path.
  - Each stream is bound to whichever path subscribed first; the other
    path's subscribe is refused (§3.4).
  - Routed private streams and artifacts are keyed by the reader's id,
    which differs per path, so in practice they do not collide.
  - With v1 off there is one row.
- **Two profiles on one computer pairing each other:** allowed, because
  they are separate endpoints. The approval shows "<computer> (<profile>)".
- **Teams:** none on the engine path in 1a. Phase 2 adds independently
  authenticated membership, then `teamAccess()` (PR #868) inside
  `authorizeEngine`.

## 5. Pairing both ways

### 5.1 Ceremony

1. **Host:** Add device, then Show QR (`invite.create`).
2. **Joiner:** Scan. The dialog reads "Connect to <host>? <host> will also
   be able to use this computer." When the user taps **Connect**:
   - the app first writes the joiner's journal, a `net_engine_peers` row
     `{state: consented, fingerprint, invitation, ticket, receipt}`. The
     ticket is deleted at `joined`;
   - then it calls `join {ticket, pinned: true}`.
3. **Host:** "Is <computer> (<profile>) next to you?" with Yes and No.
   - The question appears inside the Add-device dialog. Closing the dialog
     or switching profile cancels the invitation.
   - Yes saves the grant, then sends `PAIRED` (`p0-fix3-io`).
   - On `enrolled`, the host writes `{state: awaiting_pairback}` and shows
     "<name> can use this computer; finishing the other direction…".
4. **Joiner:** records `state = joined`, calls `grant.add`, then records
   `state = granted`, and sends `pairback {routes, receipt}` on
   `mousse.hello`.
5. **Host:** checks that the connection's identity holds the grant it just
   made.
   - It checks every route is private-range (§5.3).
   - It calls `peer.add` and dials back.
   - Its own `hello` succeeding marks `connected`. It then replies
     `pairback.done`, and the joiner marks `connected`.

**Recovery.** Each state resumes at the next start, or at the next
connection.

- **`consented`:**
  1. Dial the ticket's host as an ordinary caller. If that connects, the
     host already holds a grant for this computer: go to `joined`.
  2. Otherwise, repeat `join` with the stored ticket.
     - Per `wire.md:814-821`, a joiner whose `PAIRED` was lost reconnects
       with the same ticket, even after its joiner-side expiry.
       `AUTHORIZED {live}` means already paired.
     - E3 makes the helper's joiner (`joiner.rs:200`) follow that rule for
       `pinned` joins.
  3. `AUTHORIZED {join_only}` with the invitation gone: the row reads
     "Pairing didn't finish", with Remove.
- **`joined`:** replay `grant.add` (idempotent), then go to `granted`.
- **`granted`:** resend `pairback` on every connection until
  `pairback.done`.
- **Host:** the app may crash between `enrolled` and its write. So at
  start, and on each inbound `conn.up`, a live owner grant with no
  `net_engine_peers` row gets a new row in `awaiting_pairback`.
  `grant.add` and `peer.add` are idempotent.

### 5.2 Row states

| State | Row reads | Actions |
|---|---|---|
| `connected` | Connected | Access, Add address, Remove |
| `consented`, `joined`, `granted`, `awaiting_pairback` | Finishing pairing… | none for 2 minutes; then Retry and Remove |
| one direction failing for 2 minutes | "<host> can't reach this computer" or "This computer can't reach <host>", with fix text (firewall, same network) | Retry, Remove |
| refused with `not_authorized` or `grant_revoked` | "<host> no longer accepts this computer" | Remove |
| `removing` | Removing… | none |

Bridge work is served only for rows that are not `removing` or `removed`;
those are the serving states. No state removes a grant by itself. Every grant in this flow was consented
to on its own side, so there is no provisional grant to expire.

### 5.3 Private ranges

These address types are allowed:

- RFC 1918;
- IPv4 link-local;
- IPv6 ULA (`fc00::/7`).

The limit applies to ticket hints, `pairback.routes` and
`peer.addresses.set`. CGNAT and tailnet addresses come in Phase 1b.

### 5.4 Removal (journaled, fail-closed)

Remove on A for B:

1. **App:** B's row is set to `removing` durably, before anything else.
   - From then on, `authorizeEngine`, §4.4 and the directory refuse all
     Bridge work for that id. This holds even if the app crashes before it
     calls the helper.
   - The same write starts `teardown(localId)` (§3.7). Handlers are
     aborted, subscriptions and terminals end, and private resources are
     released.
   - At start, `teardown` runs again for every `removing` row. The row is
     then replayed from step 2 before the engine service serves anything.
   - A replay that finds the grant already gone carries on.
2. **Helper (`grant.remove`):**
   1. Journal `revoke {grant}` to `<state>/revoke.journal` and fsync.
   2. Apply the change and save the grant table.
   3. Clear the journal entry.

   Failures:
   - If the journal write fails, nothing changed, and the call fails with
     "Couldn't remove; try again". The row stays `removing`, so B is still
     refused.
   - If the save fails, networking pauses: every connection closes, the
     helper stops listening and refuses dials. It retries every second.
   - At start, the helper replays the journal **before opening the
     listener**. If that fails, it stays paused.
3. **App:** `peer.forget`, then one transaction that:
   - deletes B's `net_node_policy` row, its `net_engine_streams` rows and
     their streams;
   - deletes the host-side private streams and bindings for that reader;
   - deletes its `net_rpc_aliases`, `net_bridge_artifacts` and
     `net_bridge_hub_threads` rows;
   - sets the row to `removed`.

   Remove reports success only after this commits.
4. **Tombstone.** The `removed` row stays. A start-up sweep deletes any
   rows that still carry a tombstoned id (late writes from aborting
   handlers), then deletes the tombstone. The sweep works only from
   tombstoned ids, because local ids look like v1 node ids.

The other side is never removed automatically (§5.2).

## 6. Discovery

- **Advertise:** the existing rotating random instance, with TXT `v=1`.
- **Candidates**, in order:
  - the last working route;
  - manual addresses;
  - ticket hints;
  - mDNS results (browse 1.5 s, cached 60 s).

  They persist in `peers.json` (`Caller` routes are in memory,
  `caller.rs:112`).
- **Dialling:** four at a time, 2 s timeout. This replaces the sequential
  `dial_candidates` (`caller.rs:395`).
- **Pin mismatch:** go to the next candidate. The pinned host's own refusal
  stops the search.
- **Retry:** while a host is down, from 1 s doubling to 60 s. An interface
  change (polled every 5 s) or a wake retries at once.
- **Browse source:** a trait. The file-backed version
  (`MOUSSE_HELPER_BROWSE_FILE`) exists only in debug builds.

## 7. UI

Components live in `src/renderer/components/netEngine/`.

- **Settings → Devices:** `EngineDevicesSection`.
  - A switch, "New networking (LAN)".
  - Each row shows the name, the short id, the §5.2 state and "LAN" or the
    address.
  - The menu has Access (the existing preset control), Add address and
    Remove.
  - The selected row gets a background highlight only.
  - Clock errors use the neutral PLAN message.
- **Add device dialog:** Show QR, or Scan (webcam, `jsQR`). The host's
  approval appears inside it.
  - With no camera, the dialog says "Scan from the other computer instead".
- **Second profile on the same OS account:** this notice appears when the
  switch turns on while another profile under this OS account already has
  it on. One line: "Profiles in this account can read each other's files
  and keys." Its tooltip explains the threat model (`PLAN.md:56`).
- **Picker:** engine computers appear through `bridge.nodes`.
- **Push:** `ui.notify {kind: "net-engine", profileId}` sends
  `netEngine:changed`.

## 8. Situations

- **Sleep/wake:** a monotonic jump over 10 s pings every connection
  (2 s deadline), drops dead ones and resets backoff. mDNS re-registers
  and the helper re-dials. Clients resume from their cursors.
- **App update:** helpers get `shutdown` or EOF and exit. The new daemon
  starts them. No lock outlives the old daemon by more than 3 s.
- **Profile switch:** all networked helpers keep running. The switched-away
  profile's open Add-device dialog cancels its invitation.
- **Profile remove:** the helper stops, and the keystore entry and state
  folder are deleted.
- **Profile restore without its key, or a copy:** the endpoint is
  re-initialized and devices show "Pair again".
- **Helper restart mid-invitation:** the QR regenerates. The joiner
  resumes from its journal (§5.1).
- **Delegation expiry:** re-issued hourly (§3.5). S0 tests at +8 and +40 days.
- **Helper crash after a removal is saved:** teardown already ran when the
  row became `removing`, and it runs again at recovery.
- **v1 Start over:** also sets `net-engine/` aside; devices show "Pair again".
- **Wrong clock:** the neutral certificate-window message.
- **Mixed versions:** the wire minor negotiates down. A different app major
  shows "Update Mousse on <name>".
- **Helper restart with live terminals:** the PTYs survive, and output
  resumes from the cursor.

## 9. Owner checks: `checks/phase1a.toml`

**Build binding.**

- The engine repo pins the Mousse revision in `app/MOUSSE_REVISION`. That
  file is outside `checks/`, so changing it changes the build under test.
- **E6 kit change:** a check with `app = true` runs only if
  `MOUSSE_APP_DIR` is a clean checkout at that revision. Its results count
  only with `extra.app_build` equal to it.
- **Cross-machine cells** use the signed device-result path.
  - The host's `run.mjs --role host` reports its helper and app builds over
    the test link.
  - The caller's `run.mjs --role caller --result <file>` writes the result
    with `build`, `extra.host_build`, `extra.app_build` and
    `extra.host_app_build`.
  - `sign` keeps those fields (an E6 change). The kit counts the result only
    if both helper builds are the build under test and both app builds
    equal `app/MOUSSE_REVISION`.
- `tools/app-check/run.mjs` builds the debug helper from `{root}` (with any
  `RUSTFLAGS`). It runs `node scripts/net-engine-check.mjs <check>` in the
  app checkout with `MOUSSE_NET_HELPER` pointing at that helper. It prints
  `app_build=` and the marker line.
- App controls set `MOUSSE_NET_ENGINE_CONTROL`, read only by unpackaged
  builds.

**Topology.** `phase1a.shared-computer` uses four endpoints: PC profile A
with Mac profile C, and PC profile B with Mac profile D.

**Not a check.** The in-memory S0 spike (`tests/netEngine/spike.test.ts`)
is a unit test. `picker-v1-off` runs two real daemons and helpers through
the renderer's daemon methods.

```toml
phase = "phase1a"
title = "Two desktops on a LAN (in-person only)"
plan = "docs/PLAN.md#phase-1a-two-desktops-on-a-lan-in-person-only"
# `local = [...]` and `control = [...]` are the inline form of [[check.local]] and [[check.control]].

[[check]]
id = "phase1a.app-channel"
title = "Unique handles under equal wire stream ids, FIN after a stalled final write, engine admission bounds with app reads stalled, priority with bulk stalled both ways"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 14
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_channel", "--test", "app_streams", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_channel", "--test", "app_streams", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_channel", "--test", "app_streams", "--no-fail-fast"] },
]
control = [
  { name = "read-without-credit", breaks = "the helper reads engine streams without app credit", env = { RUSTFLAGS = '--cfg mousse_control="read-without-credit"' } },
  { name = "fifo-writer", breaks = "one FIFO writer queue for control, interactive and bulk", env = { RUSTFLAGS = '--cfg mousse_control="fifo-writer"' } },
  { name = "fin-overtakes", breaks = "FIN is sent as a control message ahead of the stream's queued DATA", env = { RUSTFLAGS = '--cfg mousse_control="fin-overtakes"' } },
  { name = "no-stream-cap", breaks = "the engine admits every peer stream at full initial credit", env = { RUSTFLAGS = '--cfg mousse_control="no-stream-cap"' } },
]

[[check]]
id = "phase1a.helper-removal"
title = "A crash between the grant change and its save never re-admits the removed peer at helper admission"
targets = ["windows-x64", "linux-x64"]
min_tests = 6
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_pairing", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_pairing", "--no-fail-fast"] },
]
control = [
  { name = "no-revoke-journal", breaks = "removal is not journaled, so a crash between change and save re-admits the peer", env = { RUSTFLAGS = '--cfg mousse_control="no-revoke-journal"' } },
]

[[check]]
id = "phase1a.discovery"
title = "mDNS carries no name; a pin mismatch moves on; peer-supplied routes are private-range only"
targets = ["linux-x64", "macos-arm64"]
min_tests = 8
local = [
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_paths", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_paths", "--no-fail-fast"] },
]
control = [
  { name = "stop-on-mismatch", breaks = "the caller gives up at the first candidate with another identity", env = { RUSTFLAGS = '--cfg mousse_control="stop-on-mismatch"' } },
  { name = "public-routes", breaks = "pairback and peer.addresses.set accept public addresses", env = { RUSTFLAGS = '--cfg mousse_control="public-routes"' } },
]

[[check]]
id = "phase1a.picker-v1-off"
title = "Fresh profiles with no net.db, v1 off: terminal access set through bridge.policy, then a remote thread and terminal through the daemon's picker methods, also at +8 and +40 days"
targets = ["windows-x64", "macos-arm64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.picker-v1-off", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.picker-v1-off", "--out", "{out}"] },
]
control = [
  { name = "roster-only-directory", expect_reason = "not_listed", breaks = "the peer directory reads only the v1 roster", env = { MOUSSE_NET_ENGINE_CONTROL = "roster-only-directory" } },
  { name = "no-renewal", expect_reason = "bad_delegation", breaks = "the engine service does not renew the self-delegation", env = { MOUSSE_NET_ENGINE_CONTROL = "no-renewal" } },
]

[[check]]
id = "phase1a.private-streams"
title = "A second paired caller cannot read, fetch blobs from or write to the first caller's private streams or artifacts, before or after the first is removed"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.private-streams", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.private-streams", "--out", "{out}"] },
]
control = [
  { name = "second-reader", expect_reason = "foreign_read", breaks = "engine delivery serves a stream with no explicit binding to this caller", env = { MOUSSE_NET_ENGINE_CONTROL = "second-reader" } },
]

[[check]]
id = "phase1a.pair-both-ways"
title = "Consent, recovery from a crash in every state, Connected only when both directions work, no automatic removal"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.pair-both-ways", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.pair-both-ways", "--out", "{out}"] },
]
control = [
  { name = "no-consent-journal", expect_reason = "one_way_stuck", breaks = "the joiner writes nothing before join, so a crash after PAIRED loses the pairing", env = { MOUSSE_NET_ENGINE_CONTROL = "no-consent-journal" } },
]

[[check]]
id = "phase1a.removal"
title = "Removal refused at once, tears down Bridge work (also when the helper dies after saving it with a PTY open), prunes rows, fails closed"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.removal", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.removal", "--out", "{out}"] },
]
control = [
  { name = "keep-removed-grant", expect_reason = "still_connected", breaks = "removing a grant leaves it in force", env = { RUSTFLAGS = '--cfg mousse_control="keep-removed-grant"' } },
  { name = "keep-engine-work", expect_reason = "stale_work", breaks = "the host keeps handlers and subscriptions after grant.closed", env = { MOUSSE_NET_ENGINE_CONTROL = "keep-engine-work" } },
  { name = "teardown-on-event-only", expect_reason = "stale_work", breaks = "teardown waits for grant.closed; the helper dies after saving the removal with a PTY open", env = { MOUSSE_NET_ENGINE_CONTROL = "teardown-on-event-only" } },
]

[[check]]
id = "phase1a.once-or-unknown"
title = "Reply dropped after the host effect, caller helper killed: effect once or outcome unknown"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.once-or-unknown", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.once-or-unknown", "--out", "{out}"] },
]
control = [
  { name = "no-host-dedupe", expect_reason = "duplicate_effect", breaks = "the host runs a repeated call id or input sequence again", env = { MOUSSE_NET_ENGINE_CONTROL = "no-host-dedupe" } },
]

[[check]]
id = "phase1a.path-switch"
title = "A multi-minute call and a terminal survive a path switch with no gap in output"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.path-switch", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.path-switch", "--out", "{out}"] },
]
control = [
  { name = "abort-on-path-replaced", expect_reason = "false_outcome", breaks = "closing the old path aborts its running handlers", env = { MOUSSE_NET_ENGINE_CONTROL = "abort-on-path-replaced" } },
]

[[check]]
id = "phase1a.reconnect"
title = "Reconnects after either side restarts and after the host's address changes (browse file)"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.reconnect", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.reconnect", "--out", "{out}"] },
]
control = [
  { name = "no-rediscovery", expect_reason = "unreachable", breaks = "the caller tries only the last working route once it has one", env = { RUSTFLAGS = '--cfg mousse_control="no-rediscovery"' } },
]

[[check]]
id = "phase1a.pair-offline"
title = "Internet unreachable: pair over LAN, connected both ways in under 10 s (ticket and approval injected)"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
device_steps = "Mac: node tools/app-check/run.mjs phase1a.pair-offline --role host. PC: mousse-check config-digest phase1a.pair-offline --target pc-to-mac-lan, then node tools/app-check/run.mjs phase1a.pair-offline --role caller --result r.json, then mousse-check sign --device-key <key> --config <digest> r.json. Controls: add --control <name> to all three."
control = [
  { name = "cable-plugged", expect_reason = "internet_reachable", breaks = "run with the WAN cable in; the harness must refuse it", env = { MOUSSE_CHECK_EXPECT_ONLINE = "1" } },
]

[[check]]
id = "phase1a.shared-computer"
title = "PC A pairs with Mac C, PC B with Mac D. A removes C: A's channels close; B's terminal to D stays usable throughout and reconnects after a restart; A cannot dial D and B cannot dial C"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
device_steps = "As phase1a.pair-offline, with phase1a.shared-computer and --topology four-endpoints on both run.mjs commands."
control = [
  { name = "shared-endpoint-state", expect_reason = "other_profile_affected", breaks = "one key and one grant table for every endpoint on the machine", env = { RUSTFLAGS = '--cfg mousse_control="shared-endpoint-state"' } },
]

[[check]]
id = "phase1a.pair-in-person"
title = "WAN cable unplugged: webcam scan, Connect, Yes, connected both ways in under 10 s"
targets = ["pc-to-mac-lan"]
manual = true
steps = "Unplug WAN; Show QR on the Mac; Scan on the PC; Connect; Yes; time to Connected on both; attest with both app and helper builds."
```

## 10. Work breakdown

Each slice is one PR and lands its own checks. E = engine repo,
M = Mousse.

| # | Repo | What | Proved by |
|---|---|---|---|
| S0 | M | **Spike** over in-memory engine streams, on a profile with no `net.db`, through the production caller path (`ThreadRouter` → `RoutedClient` → `directory.client`) and the real `rt.rpc`. Includes `EngineCaller`, `checkNodePolicy`, `renewSelf`, runtime build and activation, the `bridgeOn` gates, `bridge.policy` routing and the Hub's engine branch. | `tests/netEngine/spike.test.ts` (see the list below); go/no-go for §3–§4 |
| E1 | E | `serve --app` on stdio: framing with stream handles and in-order FIN, hello, the helper's own log, exit on EOF | `tests/app_channel.rs`: equal wire ids on two connections; a stalled final write |
| E2 | E | pumps, app credit, engine receive admission (stream caps), read-ahead, priority | `phase1a.app-channel` |
| E3 | E | invite, approval, `join {pinned}`, idempotent `grant.add`, the revoke journal with pause and replay, peers | `phase1a.helper-removal`; Phase 0 `loopback.rs` |
| E5a | E | persisted candidates, parallel dial, keep connected, browse-source trait, private-range routes | `phase1a.discovery` |
| E5b | E | renewals → `path.reopen`, interface watcher, wake | `ManualClock` tests |
| E6 | E | kit: `app = true`, `app/MOUSSE_REVISION`, app builds in signed results, `tools/app-check/run.mjs` | kit self-tests |
| M1 | M | build and package the helper; macOS local-network and keychain spike | the packaged app runs the helper on Windows and macOS |
| M2 | M | spawn, restart, shutdown, pumps; `startNetworkedProfiles` | fake and real helper tests; packaged Windows and macOS parent hard kill |
| M3 | M | engine session over the helper; `authorizeEngine` and allowlist; engine-only `result.get` waiting; §4.4 delivery checks; staging branch | `phase1a.once-or-unknown`, `phase1a.private-streams` |
| M4 | M | peer directory, the §4.3 and §4.5 call sites, the Hub's engine branch, session hooks, stream binding, roster-release fix | v1 Bridge tests unchanged; `phase1a.picker-v1-off` |
| M5a | M | peer table, selection, `teardown(localId)`, pairing journals and recovery, removal with tombstones, Start over hook | `phase1a.pair-both-ways`, `phase1a.removal`, `phase1a.reconnect` |
| M5b | M | path switch | `phase1a.path-switch` |
| M6 | M | local methods, push, picker source | allow-list test |
| M7 | M | §7 UI, including the same-account notice; `jsqr` | component tests; real-app captures; `phase1a.pair-offline`, `phase1a.shared-computer`, `phase1a.pair-in-person` (attested) |

**S0 covers:**

- terminal access set through `bridge.policy`;
- one routed call;
- a thread and a terminal (`net.info`, `routed.stream.open`);
- a paged read, a durable artifact reply and a staged write, the last
  through the production allowlist (`routed.stage`);
- live records and a snapshot;
- +8 and +40 days, and a terminal held open through a renewal;
- a v1 non-keeper profile: refused with v1 off, working with v1 on;
- the Hub's engine branch: a thread, a terminal, lists and Git progress,
  each attached through `BridgeHub.attach` with replay and snapshot
  install;
- a list of every node-id, reader and stream field in routed params and
  results, including `artifact.caller`.

**Existing Mousse files touched**

- **Net, kept small:**
  - `net/NetService.ts`: extract `checkNodePolicy`, make `nodesView`
    public, drop the `bridge.nodes` branch, add the `onSetAside` hook.
  - `net/registerMethods.ts`: route `bridge.nodes` and `bridge.policy`.
  - `net/identity/NetIdentityService.ts`: `renewSelf`.
  - `net/sync/rpcDispatcher.ts` and `contracts.ts`: the `EngineCaller`
    union, `authorizeEngine`, and `result.get` waiting.
- **Profiles:** `ProfileHost.ts`, `MousseMainService.ts`,
  `MmsProfileServices.ts` (start, stop and the `bridge` gate).
- **Bridge:**
  - `BridgeProfileService.ts`: gates, `activateBridge`, reading the
    directory, and `release` keeping serving engine nodes.
  - `bridge/registerMethods.ts`: the `bridgeOn()` gates.
  - `routed/ThreadRouter.ts` (client from the directory),
    `routed/RoutedClient.ts` (remaining budget), `remote/botReach.ts`,
    `routed/deviceName.ts` and `routed/stager.ts`.
  - `hub/service.ts`: the engine branch (session from the directory,
    binding-based authority and descriptor write, engine `verify` for
    records, replay and snapshots); local `bridge.hub.*` methods answer
    `not_supported` for engine ids.
  - `artifacts.ts`: the staging branch.
  - `remote/ThreadStreamAdapter.ts`: per-delivery checks.
- **Handlers:** those that read `caller.delegation`, as the compiler lists
  them.
- **Main, preload and renderer:** `registerGuiIpc.ts`,
  `protocolEventBridge.ts`, `preload/index.ts`, `renderer/lib/computers.ts`
  and `SettingsPage.tsx`.
- **Packaging:** `package.json`.

Not touched: `sync/session.ts`, `sync/supervisor.ts`, `transports/*`,
`link/*`, `NetDevicesSection.tsx` and `components/devices/*`.

## 11. Risks and settled questions

**Risks**

1. **The Hub's engine branch touches the Hub's core** (§4.3). S0 proves it
   for the four routed views. M4 lands it with the v1 Hub tests unchanged.
2. **The host author is still v1's local key** (§3.5). Phase 2 replaces it
   when v1 identity goes.
3. **Inbound reachability on both desktops.** The Windows Firewall and
   macOS local-network prompts can appear on either machine, so each row
   names the failing direction.
4. **Linux without a secret service:** no endpoint; the switch says so.
5. **No webcam on either desktop:** no pairing until Phase 1b send links.

**Settled questions**

1. **`result.get` waiting:** for engine callers only (§3.7).
2. **Start-up sweep:** enough, because the `removing` and `removed` states
   fence authorization and removal commits before it reports success
   (§5.4).

**Found in S0 (to fix in the named slice)**

1. `RoutedClient.settle` rejects a durable artifact reply (a result over
   63 KiB) as `bad_reply`, on v1 too. M3 fixes it and covers it through a
   window call.
2. If the clock moves back after a renewal, the owner refuses new streams
   with `bad_delegation`, because the delegation now starts in the future.
   M3 handles a clock that goes back, using the same skew allowance as the
   engine.
3. App-side limits live in `src/mms/netEngine/limits.ts` as
   `MOUSSE_NET_ENGINE_*` variables. A bad value is logged and keeps its
   default, so a typo never stops the daemon; the helper still refuses to
   start on a bad `MOUSSE_NET_*` value.

**Decided while building E1 and E2**

1. **Framing details.** The length counts the type byte and the body.
   DATA flag bits other than FIN, a CREDIT of 0 bytes, and DATA beyond the
   app's credit are malformed: the helper exits nonzero. Requests name
   their method in `op`; only a request with `id` gets a reply.
2. **Generation.** Connection numbers are per spawn and never reused, so a
   reconnect is a new number; that number is the handle's generation.
   `conn.down` ends every handle on that connection (no per-stream event).
3. **Hello.** A `profile` that is not this endpoint's is `wrong_profile`;
   another major is `unsupported_proto`; any other request first is
   `no_hello`. `name` waits for `config.set` (E3).
4. **Stream caps live in `mousse-net-io`** (`STREAMS_PER_CONNECTION`,
   `STREAMS_PER_ENDPOINT`), shared by the host and the app's outbound
   caller. A place is held until the mux is done with the stream and its
   reader is gone. A peer's open past a cap gets `RESET REFUSED_STREAM`,
   now named in `spec/wire.md` §9.2; the app's own open past it gets
   `stream_limit`. `StreamReader::reset_by_peer` tells a pump held back by
   read-ahead that the peer reset the stream.
5. **Read-ahead needs 64 KiB of credit.** With credit below
   `APP_READ_AHEAD_BYTES` plus what is queued, nothing moves, FIN
   included: the app keeps at least 64 KiB granted on a stream it reads.
6. **A stalled app.** Control past `APP_CONTROL_QUEUE_BYTES` ends the
   channel, and the helper exits (the daemon restarts it).
7. **Exit.** On EOF or `shutdown` the helper sends `GOAWAY NO_ERROR` on
   every connection, waits `STOP_LINGER_MS` and exits 0.
8. **Until E3.** App mode keeps the control listener, so `invite` and
   `join` on the command line pair endpoints for the tests. Inbound
   connections are announced once live (the joining connection too) with
   `grant` and `role`; outbound ones have no `role` until E3. A minimal
   `dial {identity}` uses the stored peer's routes. A `stats` request
   reports the engine queue, stream places, app buffering and dropped
   frames for tests and diagnostics.
9. **Environment.** The helper ignores the app's own `MOUSSE_NET_ENGINE_*`
   names and `MOUSSE_NET_HELPER` when it checks for unknown limits.

**Decided while building E3**

1. **`join {ticket, pinned}`.** `pinned` means the app recorded its
   consent first (§5.1): the ticket's host counts as pinned, and a join
   past the ticket's joiner-side expiry stores "outcome pending" and
   reconnects with the same ticket (`Caller::join_pinned_with_redial`).
   `PAIRED` then means this invitation enrolled the device,
   `AUTHORIZED {live}` that it is already paired, and a host with no grant
   for it closes with `INVITATION_INVALID`. Only in-person tickets join
   (send links are not in 1.0: `not_supported`), as an in-app scan. The
   reply adds `conn`: the pairing connection stays up and is announced as
   `conn.up {dir: "out", role}`. `join.progress {invitation, step:
   "connecting", route}` comes once per address tried; `join.cancel
   {invitation}` answers the join with `cancelled`.
2. **Names.** `config.set {name}` and `hello {name}` set the name `PAIRED`
   and joins send (`bad_name` if empty or over 128 bytes). Until then it
   is `serve --name`.
3. **Invitations.** `invite.create` makes in-person invitations only. `uri`
   is the ticket's fragment, the text the QR holds (`join` also takes a
   link ending in `#fragment`). `approval` is `{request, invitation,
   identity, device, name}`; the request id names the connection and the
   full fingerprint. An answer to a request that is gone is `no_request`,
   a yes the host can no longer apply is `stale`. A question for an
   invitation this channel did not make is declined. `invite.ended.reason`
   is the error code's name.
4. **`grant.add {identity, name, receipt}`** makes an owner grant and keeps
   `receipt` as its enrollment receipt (`grants.list` shows it as
   `receipt`). If the identity holds a live grant, that grant is returned
   with `already: true` and nothing closes. A failed save is
   `store_failed`; the grant is in effect, the host retries, and the app
   may repeat the call.
5. **Peers.** `peer.add {identity, name, routes, role?}` stores a peer;
   `role` defaults to `owner`, since 1a grants are owner grants. Repeated,
   it updates the name and role and adds routes. Routes must parse
   (`bad_route`); the private-range rule (§5.3) and `peer.addresses.set`
   come with E5a. `peer.forget` also closes this side's outbound
   connections to the peer (`CANCELLED`). Outbound `conn.up` carries the
   role stored for the peer: from `PAIRED`, or from `peer.add`. An
   "already paired" join with no stored record has `role: null`.
6. **Removal.** The journal is `revoke.journal` in the endpoint's state
   folder, beside `grants.json`, rewritten whole and durably on each
   entry. A grant that is already gone answers `{removed: false}`. A
   journal write that fails answers `journal_failed`, "Couldn't remove;
   try again", and changes nothing. A save that fails answers `{removed:
   true, paused: true}` and pauses networking:
   - every connection closes with `INTERNAL_ERROR` (the removed peer's
     with `GRANT_REVOKED` first);
   - inbound TCP connections are dropped as they are accepted. The
     listener stays bound, so the kept port stays this endpoint's;
   - `dial` and `join` answer `paused`;
   - events `net.paused {reason}` and `net.resumed`; `hello` reports
     `paused`.

   Every `REMOVAL_RETRY_MS` (`MOUSSE_NET_REMOVAL_RETRY_MS`, 1 s) the
   helper replays the journal, saves and clears it. At start the replay
   runs before the accept loop; if it fails, the helper starts paused. The
   command line's `remove` keeps its Phase 0 behaviour (not journaled);
   the start-up replay and the pause apply in both modes.
7. **Retired.** App mode binds no control listener and writes no
   `control.json`; the app tests pair through `invite.create`, `join` and
   `approval.answer`. `dial` uses the peer store and announces the role.
   This replaces item 8 of the E1 and E2 list.
8. **Stored roles.** A join now stores the role's name (`owner`), not its
   debug form; readers accept both.

**Decided while building E5a**

1. **Private ranges (§5.3).** A peer-supplied or owner-supplied address
   must be a `tcp://` route to an IP literal in RFC 1918, IPv4 link-local
   or `fc00::/7` (an IPv4-mapped IPv6 address counts as its IPv4 address).
   Names, including `.local`, are refused, since they can resolve
   anywhere. `peer.add` routes (the pairback's) and `peer.addresses.set`
   answer `bad_route` naming the first address that fails, and store
   nothing; a ticket's other hints are skipped, and a ticket with none
   left answers `no_route`. Debug builds also take loopback, so the tests
   run on one computer without listening on the LAN; release builds never
   do. The command line keeps its Phase 0 behaviour.
2. **Candidates.** `peers.json` gains `addresses` (the owner's, set whole
   by `peer.addresses.set`, listed by `peers.list`). The order is the last
   working route, then `addresses`, then the hints (`routes`), each
   filtered as in item 1. The browse runs only when none of those answers
   as the host, and its addresses are tried after them; they are not
   stored, except as the last working route once one works. A re-pair
   keeps `addresses`.
3. **Parallel dial.** Up to `DIAL_PARALLEL` candidates at once, launched
   in order; each has `DIAL_TIMEOUT_MS` to connect and pass step 1. The
   first to pass step 1 is the host and the other tries end. Session
   state changes only for that one: step 1 runs before the path is begun,
   so a losing or failing try never replaces a candidate path. Renewals
   use the same dial.
4. **Keep connected.** After the first `hello`, the helper keeps one
   outbound path to every stored peer, as `conn.up {dir: "out"}`.
   `dial {identity}` still opens a new path (the reply adds `already:
   true` when another dial opened one while it waited; one dial per host
   runs at a time). A host that cannot be reached is retried after
   `KEEP_RETRY_FIRST_MS`, doubling to `KEEP_RETRY_MAX_MS`; after a path
   drops, the first retry also waits `KEEP_RETRY_FIRST_MS`. Each failure
   is an event `dial.failed {identity, why, reason, retry_ms}` (not in
   §2.3; the §5.2 row states need it). A host that refuses this device
   (`not_authorized`, `grant_revoked`) is not retried (`retry_ms: null`)
   until `dial`, `peer.add`, `peer.addresses.set`, `net.resumed` or a
   restart. Nothing is dialled while networking is paused.
5. **Browse source.** `BrowseSource` in `discovery.rs`, with `MdnsBrowse`
   and `CachedBrowse` (`BROWSE_WAIT_MS`, `BROWSE_CACHE_MS`, timed by the
   monotonic clock; a failed browse is not kept). The helper browses with
   mDNS only where it advertises (`--mdns` and not loopback). Debug builds
   read `MOUSSE_HELPER_BROWSE_FILE` instead when it is set: one `ip:port`
   (or `tcp://ip:port`) per line, read on every browse.
6. **mDNS record.** The proof is the record the advertiser registers
   (`discovery::record`): instance and host name both the random
   `mousse-` name, TXT only `v=1`. No test on this PC opens multicast; a
   live LAN mDNS test needs the Mac listening.
7. **Controls.** `stop-on-mismatch` (net-io) and `public-routes` (helper)
   for `phase1a.discovery`. `no-rediscovery` (helper: only the last
   working route once a pairing has one, no browse) is in place for `phase1a.reconnect`.

**Decided while building E5b**

1. **Renewals in app mode.** The helper takes the caller's renewals from
   the start. A renewed path is announced as `conn.up {dir: "out"}`, then
   `path.reopen {identity, from, conn}` (`from` is null when the old path
   is already gone). `path.reopened {conn}` makes it current and closes
   the old one with `PATH_REPLACED`; it answers `no_conn`, or
   `not_renewed` for a path that is not a renewed one waiting (an inbound
   path, or one already current). An outbound path a `dial` opened while
   another was up waits the same way, announced by its `conn.up` alone,
   and `path.reopened` takes it too. A failed try is `path.renew_failed
   {identity, why, reason}`, and the caller tries again on the session's
   schedule. While networking is paused, a renewed path is closed at once
   and reported as `path.renew_failed {why: "paused"}`. `dial` reuses the
   oldest outbound path, which stays current while a renewed one waits.
2. **Watcher.** `watch.rs` in net-io polls every `IFACE_POLL_MS`: the
   interface list (`if-addrs`, already in the tree through `mdns-sd`;
   name, address and up or down, loopback left out) and the monotonic
   clock. A clock that ran more than `WAKE_JUMP_MS` past one interval is
   a wake. It runs in every `serve`, which then announces the mDNS record
   again (`Advertiser::refresh`; `mdns-sd` also checks addresses itself
   every 5 s).
3. **The reaction** (app mode) is the same for both changes: drop the
   browse cache, ping every connection, inbound and outbound, and close
   any that does not answer within `WAKE_PING_MS` with `IDLE_TIMEOUT`,
   then reset every host's backoff so the ones without a path are
   dialled at once. §8 asks for the ping after a wake only; it runs after
   an interface change too, since a lost interface leaves TCP paths
   silently dead until the 45 s idle timeout. `Connection::ping` uses a
   new core `Mux::ping`, which reuses a `PING` already queued or
   unanswered. The app gets no event for the change itself; it sees
   `conn.down` and `conn.up`.
4. **Test hooks**, debug builds only: `MOUSSE_HELPER_INTERFACES_FILE`
   (the interface list, one line each, read at every poll) and
   `MOUSSE_HELPER_MANUAL_CLOCK=1` with the op `test.clock {advance_secs,
   advance_mono_ms}`. The net-io watcher tests run a `ManualClock` on
   paused tokio time; the helper tests (`tests/app_changes.rs`) move both
   helpers' clocks. Row E5b names no check cell, so none was added and no
   control build either; each helper test was checked to fail with the
   close after a missed ping, the backoff reset, or the renewal
   forwarding taken out.

**Decided while building E6**

1. **The pin.** `app/MOUSSE_REVISION` holds one full commit hash (40 or
   64 hex digits); an abbreviated one is refused. It pins `8789ae66`, the
   tip of the app's `net-engine-1a` branch when E6 landed. Without a
   readable pin, every app cell is INCOMPLETE.
2. **Digest.** `app = true` joins the configuration digest only when set,
   so every check without it keeps its digest and its signed evidence
   (checked against a committed Phase 0 result). `app` with `manual` is
   refused: a manual step is attested with both builds instead.
3. **The gate.** The kit runs an app check only if `MOUSSE_APP_DIR` is a
   git checkout whose HEAD is the pin and whose `git status --porcelain`
   is empty (ignored files such as `node_modules` are fine). Otherwise it
   says why and runs nothing, so no record is written. A run record keeps
   the run's `app_build=` line as `app_build`, and `run --sign-with` signs
   it as `extra.app_build`. Records and results count only with the
   pinned app build; a `-dirty` one never counts, `--allow-dirty` or not.
   `sign` also keeps `app_build` and `host_app_build`, and notes when an
   app result names another app build.
4. **`run.mjs`.** The helper build it reports is `<source commit>[-dirty]
   +debug`, named the way the kit names this checkout. The kit records
   app runs with the profile `unknown`, since it cannot see what a script
   builds; the app cells set no `profile`. The helper build reaches the
   app as `MOUSSE_NET_ENGINE_HELPER_BUILD`, inside the app's own
   namespace: the helper refuses to start with a `MOUSSE_NET_*` name it
   does not know, so `MOUSSE_NET_HELPER_BUILD` would stop it. `run.mjs`
   only warns when the app build is not the pin: the kit refuses the run,
   and a device result is judged when it is evaluated.
5. **Device runs.** `--control <name>` takes the control's environment
   from the manifest through a new `mousse-check control-env`, which
   prints it as JSON (controls that change the command are refused).
   `--result` takes `host_build` and `host_app_build` from the app's
   `host_build=` and `host_app_build=` lines. The app script has no
   `--role` yet, so that is the contract for it.
6. **Cells.** The three app checks the app script runs today
   (`picker-v1-off`, `private-streams`, `once-or-unknown`) joined
   `checks/phase1a.toml` as written in §9; the others join with their M
   slices. On Windows, against a clean clone of the app at the pin, all
   three passed and every control failed with its reason.
7. **A lost GOAWAY.** `an_ungranted_identity_cannot_open_streams` failed
   about once in 50 runs under load: the peer read
   `ConnectionAborted` and no GOAWAY. That was a real bug. A
   connection closed its socket as soon as the GOAWAY was written, with
   the peer's later data unread. Closing with unread data resets the
   connection, and on Windows the reset destroys what the peer has not
   read yet, so a refused or removed device saw a network error instead
   of the reason. The driver now reads and drops what the peer still
   sends until it closes too, within `CLOSE_LINGER_MS`.
   `a_refused_peer_that_keeps_sending_still_reads_why` fails every time
   without that. The one-off hang of a loopback test binary in E5a did
   not recur in about 500 suite runs under load. Its cause is unknown.
   The unbounded awaits left in those tests (`dial`, `connect`, reads
   and writes after a close) are now bounded, so a recurrence names its
   step.
