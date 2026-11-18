# Phase 1a design: the engine inside the desktop app

Status: design, round 3 (2026-11-18). Scope: PLAN "Phase 1a" (two desktops
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

The design goes to the review council for its last round. Round-1 changes
are in commit `bddb00e`.

## Changes since round 2

F = first review, S = second review, followed by the finding number.

| Finding | Resolution |
|---|---|
| F1, S3: the reused gates are in `NetService.ts`; Bridge is built only by `net.runtime()` and activated only by `activate()`; the `featureEnabled` gates; the `bridge.nodes` and `services.bridge` entry points; the transport methods | §4.3. The per-node policy part of `authorizeMethod` moves into `checkNodePolicy`, which both paths call. The engine service builds the runtime and activates Bridge. Gates read `bridgeOn()`. `bridge.nodes` is served by the peer directory. The allowlist includes `net.info`, `routed.stream.open`, `routed.stream.close` and `routed.page`. S0 runs through the real `rt.rpc` on a profile with no `net.db`. |
| F2, S4 (author): the self-delegation lapses after 7 days | §3.5: the engine service renews it at start and hourly. S0 runs at +8 days. The profile becomes a v1 keeper; the consequence is stated. |
| S1: private streams are also `node.thread` | §4.4: the host-side binding is resolved first. Every delivery and blob fetch requires an open stream, the exact reader and current policy. Reader ids and private keys stay on the host. Control `second-reader`. |
| F4, S4 (records): origin table off the commit path; `(stream, seq)` is not an identity; `author.node`/`author.user` checks | §3.4: the origin table is cut. Engine streams are stored under a local stream id per pairing and remote stream, bound to a live `net_engine_peers` row. That binding is checked at ingest and on reopen; a missing or unknown row fails closed. The engine branch skips `hub/service.ts:1209-1210`. |
| F3, S5 (path switch) | §3.7: `PATH_REPLACED` never aborts handlers. The old path stays until its calls finish. `result.get` waits on a running engine execution. A failed candidate keeps the old path. A replacement is published only when handoff-ready. |
| F5, S5 (sizes) | §3.3: the 16 MiB inline path is cut. Engine messages keep v1's 64 KiB frame limit, and the existing artifact, paging and staging paths are served on engine sessions. Credit is admitted against an aggregate budget. The 16,384 JSON-node cap is noted. |
| S2: crash windows; wire close reasons used for removal | §5: consent and the pinned host are journaled before `join`, and reconcile through "already paired". Removal intent is journaled before the grant changes and replayed before the listener opens. Close reasons are directional status only. |
| S3 question, F question 3: stuck pairing | §5.2: after 2 minutes, a visible partial state with Retry and Remove; no automatic removal. The host's state between enrolment and pair-back is named `awaiting_pairback`. |
| F6: private-range limit | §5.3: it also applies to `pairback.routes` and `peer.addresses.set`. |
| F6: orphaned rows | §5.4: prunes `net_rpc_aliases`, `net_bridge_artifacts` and `net_bridge_hub_threads` by the removed local id. |
| S6: evidence | §9: the app revision is pinned in the engine repo and verified. Cross-machine cells record both endpoints' builds. Check entries are runnable. The S0 spike is a unit test, separate from `phase1a.picker-v1-off`. |
| Questions 2 and 4 | §4.2: `user = self user` with `role: 'owner'` in the type; the local id stays on authorization, ownership and audit paths. `@you` is cut; an opaque handle is used only if S0 finds a key on the wire. |
| Login start, signing | `docs/PLAN.md` §8 now records the Phase 1b exception. The signing claim is reduced to what `package.json` shows. |
| F cut | The duplicate-row tooltip is removed. |

**Rejected:** none.

**Kept from round 2's rejections, with both reviewers' agreement:**

- A daemon-wide helper upgrade.
- No claimed node ids.
- Login start deferred to Phase 1b.
- Windows helper signing deferred. `package.json` sets
  `"signExecutable": false`, so signing only the helper would ship it inside
  an unsigned app. Both are signed in the release step that signs the app.

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

- With no endpoint, the daemon first runs `init`.
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
- `0x02` DATA: `u32 stream` + at most 64 KiB
- `0x03` CREDIT: `u32 stream` + `u32 bytes`

A malformed frame closes the channel, and the daemon restarts the helper.

### 2.2 Pumps, budget and priority (both sides)

- **Independent pumps.** Reading never waits on writing.
- **Writer order:** control (JSON and CREDIT), then interactive DATA, then
  bulk DATA. Streams take turns within a class.
- **Admission.** Each side has an aggregate receive budget of 8 MiB.
  - A side grants credit to a stream only from that budget, so the credit
    granted and not yet consumed across all streams never exceeds it.
  - Each stream gets at most 256 KiB.
  - 1 MiB of the budget is reserved for interactive streams.
  - A stream that cannot get credit waits. Its sender stalls, and nothing
    buffers past the budget.
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
- **Streams:** `stream.open {conn, label, class}`, `stream.accept`,
  `stream.fin`, `stream.reset`, DATA and CREDIT.
  - Event: `stream.incoming`.

Not in 1.0: deny lists, send links and tunnels. On an outbound connection,
the helper resets every stream the host opens. On an inbound connection, it
passes on only the §3.2 labels.

## 3. The engine session

The session code is new, in `src/mms/netEngine/session/`. It does not
import `NetSyncSession` or `link/mux`.

### 3.1 Reused, unchanged

| Reused | How it is used |
|---|---|
| `rt.rpc` (`DurableRpcDispatcher`) | The runtime's own instance, so the real daemon handlers serve engine calls. Same ledger, idempotent ids and `outcome_uncertain` behaviour. |
| `SubscriptionReceiver` | One per subscription, with the engine `verify` callback (§3.4). |
| `rt.streams` | Engine streams are stored under local stream ids (§3.4). |
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

Each message is `u32 BE length | JSON header | binary parts`.

### 3.3 Sizes

- A message is at most `MAX_FRAME_BYTES` (64 KiB), as on v1. A record
  batch splits at that limit. Blob bytes stream raw under credit.
- Results keep the dispatcher's rule: over 63 KiB they go to the artifact
  publisher (`rpcDispatcher.ts:250`). The publisher creates a `node.artifact`
  stream bound to the caller, which RoutedClient then reads through
  `routed.page`.
- Params larger than a message, or over 16,384 JSON nodes, are staged
  through `RoutedStager` as today. Staging writes go over `mousse.put`.
- Reassembly is bounded by the §2.2 budget: at most one 64 KiB message per
  stream, inside the aggregate.

### 3.4 Record identity (caller side)

**Storage.** Engine streams are stored under a local stream id.

- When a subscription first creates a descriptor, the session writes
  `net_engine_streams(local_stream PK, peer_local_id, remote_stream, kind)`
  in the same transaction.
- `local_stream` is a new `StreamId`. The stored descriptor has
  `authority = peer_local_id`.
- The same host reached over v1 and over the engine therefore never shares
  a stream. Two pairings never share one either.
- Cursors, epochs and snapshot generations are the store's own. Each local
  stream has exactly one pairing.

**At ingest**, the `verify` callback accepts a record only if:

- the subscription runs on a live outbound connection of that pairing;
- the stream's `net_engine_streams` row names that pairing;
- the envelope's `stream` equals `remote_stream`;
- the receiver's cursor rules pass.

Signatures and the v1 `author.node`/`author.user` checks are skipped on
this branch (`hub/service.ts:1209-1210` and the `verifyAuthor` calls in
`artifacts.ts`). The pinned channel is the proof.

**On reopen**, readers of an engine stream go through
`directory.verifyStream(local_stream)`. It requires both:

- a `net_engine_streams` row;
- a live `net_engine_peers` row for that row's `peer_local_id`.

Otherwise the stream reads as gone. A descriptor whose `authority` is an
engine local id but has no `net_engine_streams` row also fails closed.

**Translation.** Bridge code keeps naming streams by (node, remote stream
id). The directory maps them to local stream ids. S0 lists every
`rt.streams` reader in Bridge (thread projection, hub, artifacts) and routes
each one through the map.

### 3.5 Host-side author (v1 off)

- Records are produced by `ThreadStreamAdapter` and signed with the
  profile's local node key, as today.
- If the profile has no `identity.self()`, the engine service runs
  `rt.identity.bootstrapAuthority(name)` with no passphrase.
- The self-delegation lasts 7 days (`NODE_DELEGATION_TTL_MS`). v1's renewal
  runs only after `activate()`. The engine service therefore calls
  `identity.renewExpiring()` at start and every hour while the switch is on.
- S0 runs again with the clock moved 8 days.

**Consequence.** The profile becomes a v1 keeper. A later v1 join on it
fails with "Local identity already exists" (`NetIdentityService.ts:155`).
Joining another v1 network from that profile needs v1 "Start over", which
replaces the signing identity. Engine pairings survive that, because
callers bind authority by pairing, not by author.

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

**Loss** (any other `conn.down`, or a helper exit):

- Host handlers keep running to their deadline, and their results land in
  the ledger keyed by the local id.
- The caller retries on the next connection with the same id.
- On engine callers, `result.get` for a running execution waits for it up
  to the call's deadline, instead of answering `outcome_uncertain`. This is
  a small dispatcher change (`rpcDispatcher.ts:404-418`).
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
- `bridge.artifacts.open`, for staging;
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
- The other Bridge methods already reach `profile.bridge` through
  `registerBridgeMethods`.
- `BridgeProfileService.ts:135` reads the directory instead of
  `net.request('bridge.nodes')`.
- In the renderer, `computers.ts:105-112` also lists computers when
  `netEngine.status` is on.

**`NetService.ts` edits:** extract `checkNodePolicy`, make `nodesView`
public, and remove the `bridge.nodes` branch. Nothing else changes.

### 4.4 Streams and blobs served to an engine caller

Every subscribe, every delivered batch, every blob fetch and every
`mousse.put` write first resolves the host-side binding:

1. **Private stream:** `ThreadStreamAdapter.privateAccess(stream)` is
   defined. This is checked first, because private terminal, thread and
   list streams are also `node.thread`.
   - Served only if `open` is true and `reader` equals the caller's local id
     exactly.
   - Current policy must also allow the kind: terminal needs `terminal`, and
     work streams need `work`.
2. **Display stream:** no private binding, and kind `node.thread` (thread
   display or lists) owned by this profile. `checkNodePolicy` applies.
3. **Artifact:** `node.artifact` whose `net_bridge_artifacts.caller` equals
   the local id and whose capability matches. `mousse.put` is allowed only
   into the caller's own input artifacts.
4. Anything else is refused.

These checks run again on each delivery, not only at subscribe, so a
closed stream or a policy change stops the next batch. A blob is served
only if the same stream passes and `blobs.isReferenced(blob, stream)` is
true.

**Keys stay on the host.** `routed.stream.open` builds the private key from
the session's reader (`privateStreams.ts:27`). Callers name streams by
`{kind, subject}`, and records carry no reader. S0's field list confirms
that no reader id or private key appears in any routed param or result. If
one does, the session swaps it for an opaque handle scoped to the pairing.

### 4.5 Peer directory

New `src/mms/bridge/peers.ts`:

    interface PeerDirectory {
      nodes(): NodesView                       // bridge.nodes rows: v1 (if on) + engine
      computers(): ComputerRef[]; name(node); has(node)
      client(node): BridgeClient               // rpc, rpcResult, rpcCancel, subscribe, getBlob, append, putBlob
      localStream(node, remote): StreamId; verifyStream(local): void
      publish / publishDelta / discardDeltas / failStream / isSubscribed
    }

These call sites move to the directory:

- `ThreadRouter.pairedComputers` and `isOnline`
- `botReach.accountDevices`
- `deviceNameOf`
- `RoutedStager` (its session and roster lookup)
- `BridgeHub.session` (`hub/service.ts:256`) and `canReceive` (`:1183`)
- the `verifyAuthor` and roster sites in `artifacts.ts`
- `ThreadStreamAdapter`'s fan-out

### 4.6 Cases

- **Same Mousse ID, also paired over v1:** two rows in 1a, one per path. With
  v1 off there is one row.
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
     `{state: consented, fingerprint from ticket, invitation, receipt}`;
   - then it calls `join {ticket, pinned: true}`.
3. **Host:** "Is <computer> (<profile>) next to you?" with Yes and No.
   - The question appears inside the Add-device dialog. Closing the dialog
     or switching profile cancels the invitation.
   - Yes saves the grant, then sends `PAIRED` (`p0-fix3-io`).
   - The host then writes `{state: awaiting_pairback}` and shows "<name>
     can use this computer; finishing the other direction…".
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

- **`consented`:** the joiner repeats `join` with the same ticket.
  - If the host already enrolled it, the host's `AUTHORIZED {live}` reads
    as "already paired" (`wire.md:827-830`). That is accepted because the
    journal pinned the ticket's host.
  - If the invitation is gone and no grant exists, the row reads "Pairing
    didn't finish" with Remove.
- **`joined` or `granted`:** the joiner resends `pairback` on every
  connection until `pairback.done`.
- **`awaiting_pairback`:** the host waits for `pairback`. `grant.add` and
  `peer.add` are idempotent by identity and receipt.

### 5.2 Row states

| State | Row reads | Actions |
|---|---|---|
| `connected` | Connected | Access, Add address, Remove |
| `consented`, `joined`, `granted`, `awaiting_pairback` | Finishing pairing… | none for 2 minutes; then Retry and Remove |
| one direction failing for 2 minutes | "<host> can't reach this computer" or "This computer can't reach <host>", with fix text (firewall, same network) | Retry, Remove |
| refused with `not_authorized` or `grant_revoked` | "<host> no longer accepts this computer" | Remove |

No state removes a grant by itself. Every grant in this flow was consented
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

1. **App:** set B's row to `removing` (durable) before anything else. At
   start, `removing` rows are replayed before the switch reports ready.
2. **Helper (`grant.remove`):** journal `revoke {grant}` to
   `<state>/revoke.journal` and fsync, then apply the change and save the
   grant table, then clear the journal entry.
   - If the journal write fails, nothing has changed, and the call fails
     with "Couldn't remove; try again".
   - If the save fails, networking pauses: every connection closes, the
     helper stops listening and refuses dials. It retries every second.
   - At start, the helper replays the journal **before opening the
     listener**. If that fails, it stays paused.
3. **App:** `peer.forget`, then delete B's data in one transaction:
   - its `net_engine_peers` row and its `net_node_policy` row;
   - its `net_engine_streams` rows and their streams;
   - its private-stream bindings;
   - its `net_rpc_aliases` (caller = id), `net_bridge_artifacts`
     (caller = id) and `net_bridge_hub_threads` (target = id) rows.

   A start-up sweep deletes rows in those tables whose engine local id has
   no `net_engine_peers` row.

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
- **Delegation expiry:** renewed hourly (§3.5). S0 tests at +8 days.
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
- **Cross-machine cells** also need `extra.host_app_build`, next to the
  kit's `host_build`.
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
title = "Channel framing, credit admission, pumps and priority; bulk stalled both ways"
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
title = "Fresh profiles with no net.db, v1 off: remote thread and terminal through the daemon's picker methods, also at +8 days"
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
title = "A second paired caller cannot read, fetch blobs from or write to the first caller's private streams or artifacts"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.private-streams", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.private-streams", "--out", "{out}"] },
]
control = [
  { name = "second-reader", expect_reason = "foreign_read", breaks = "engine delivery checks the stream kind but not the private reader", env = { MOUSSE_NET_ENGINE_CONTROL = "second-reader" } },
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
title = "Removal refused at once, tears down Bridge work, prunes rows; a crash or failed save never re-admits the device"
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
  { name = "no-revoke-journal", expect_reason = "served_after_restart", breaks = "removal is not journaled, so a crash between change and save re-admits the device", env = { RUSTFLAGS = '--cfg mousse_control="no-revoke-journal"' } },
]

[[check]]
id = "phase1a.once-or-unknown"
title = "Reply dropped after the host effect, caller helper killed: effect once or outcome unknown; a long call survives a path switch"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.once-or-unknown", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1a.once-or-unknown", "--out", "{out}"] },
]
control = [
  { name = "no-host-dedupe", expect_reason = "duplicate_effect", breaks = "the host runs a repeated call id or input sequence again", env = { MOUSSE_NET_ENGINE_CONTROL = "no-host-dedupe" } },
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
  { name = "no-rediscovery", expect_reason = "unreachable", breaks = "the caller tries only the last working route", env = { RUSTFLAGS = '--cfg mousse_control="no-rediscovery"' } },
]

[[check]]
id = "phase1a.pair-offline"
title = "Internet unreachable: pair over LAN, connected both ways in under 10 s (ticket and approval injected)"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
device_steps = "Mac: node tools/app-check/run.mjs phase1a.pair-offline --role host. PC: mousse-check run phase1a.pair-offline --target pc-to-mac-lan --sign-with <key>; the result carries host_build and host_app_build from the Mac."
control = [
  { name = "cable-plugged", expect_reason = "internet_reachable", breaks = "run with the WAN cable in; the harness must refuse it", env = { MOUSSE_CHECK_EXPECT_ONLINE = "1" } },
]

[[check]]
id = "phase1a.shared-computer"
title = "Two profiles per desktop, each paired with its own profile on the other; removing one pairing leaves the other working"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
device_steps = "As phase1a.pair-offline, with --topology four-endpoints on both machines."
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

| # | What | Proved by |
|---|---|---|
| S0 | M: `netEngine/session/*`, a `peers.ts` stub, `EngineCaller`, `checkNodePolicy`, runtime build and activation with v1 off, the `bridgeOn` gates. Over in-memory engine streams: a profile with no `net.db`, through the real daemon handlers and `rt.rpc`. Covers one routed call, a terminal (`net.info` and `routed.stream.open`), a large result through `routed.page`, and the same at +8 days. Lists every node-id, reader and stream field in routed params and results, including `artifact.caller`. | `tests/netEngine/spike.test.ts`; go/no-go for §3–§4 |
| E1 | `serve --app` on stdio, framing, hello, the helper's own log, exit on EOF | `tests/app_channel.rs` |
| E2 | pumps, credit admission, read-ahead, priority | `phase1a.app-channel` |
| E3 | invite, approval, `join {pinned}`, idempotent `grant.add`, the revoke journal with pause and replay, peers | `tests/app_pairing.rs`; Phase 0 `loopback.rs` |
| E5a | persisted candidates, parallel dial, keep connected, browse-source trait, private-range routes | `phase1a.discovery` |
| E5b | renewals → `path.reopen`, interface watcher, wake | `ManualClock` tests |
| E6 | kit: `app = true`, `app/MOUSSE_REVISION`, `host_app_build`, `tools/app-check/run.mjs` | kit self-tests |
| M1 | build and package; macOS local-network and keychain spike | the packaged app runs the helper on Windows and macOS |
| M2 | spawn, restart, shutdown, pumps; `startNetworkedProfiles` | fake and real helper tests; parent hard kill |
| M3 | engine session over the helper; `authorizeEngine`; allowlist; `result.get` waiting; §4.4 delivery checks | `phase1a.once-or-unknown`, `phase1a.private-streams` |
| M4 | peer directory and the §4.3 and §4.5 call sites; local stream map | v1 Bridge tests unchanged; `phase1a.picker-v1-off` |
| M5a | peer table, selection, revocation teardown, pairing journals, removal with pruning | `phase1a.pair-both-ways`, `phase1a.removal`, `phase1a.reconnect` |
| M5b | path switch | `phase1a.once-or-unknown` (long call); terminal output with no gap |
| M6 | local methods, push, picker source | allow-list test |
| M7 | §7 UI; `jsqr` | component tests; real-app captures; the cross-machine and manual checks |

**Existing Mousse files touched**

- **Net, kept small:**
  - `net/NetService.ts`: extract `checkNodePolicy`, make `nodesView`
    public, drop the `bridge.nodes` branch.
  - `net/registerMethods.ts`: route `bridge.nodes`.
  - `net/sync/rpcDispatcher.ts` and `contracts.ts`: the `EngineCaller`
    union, `authorizeEngine`, and `result.get` waiting.
- **Profiles:** `ProfileHost.ts`, `MousseMainService.ts`,
  `MmsProfileServices.ts` (start, stop and the `bridge` gate).
- **Bridge:**
  - `BridgeProfileService.ts`: gates, `activateBridge`, and reading the
    directory.
  - `routed/ThreadRouter.ts`, `remote/botReach.ts`, `routed/deviceName.ts`
    and `routed/stager.ts`.
  - `hub/service.ts` and `artifacts.ts`: the engine branches.
  - `remote/ThreadStreamAdapter.ts`: per-delivery checks.
- **Handlers:** those that read `caller.delegation`, as the compiler lists
  them.
- **Main, preload and renderer:** `registerGuiIpc.ts`,
  `protocolEventBridge.ts`, `preload/index.ts`, `renderer/lib/computers.ts`
  and `SettingsPage.tsx`.
- **Packaging:** `package.json`.

Not touched: `sync/session.ts`, `sync/supervisor.ts`, `transports/*`,
`link/*`, `NetDevicesSection.tsx` and `components/devices/*`.

## 11. Risks and open questions

**Risks**

1. **The stream-id map may reach more readers than S0 finds.** S0 is the
   gate. If the map's call sites exceed a day's work, re-plan before going
   past E2.
2. **The host author is still v1's local key** (§3.5). Phase 2 replaces it
   when v1 identity goes.
3. **Inbound reachability on both desktops.** The Windows Firewall and
   macOS local-network prompts can appear on either machine, so each row
   names the failing direction.
4. **Linux without a secret service:** no endpoint; the switch says so.
5. **No webcam on either desktop:** no pairing until Phase 1b send links.

**Open questions for round 3**

1. `result.get` waiting on a running execution (§3.7) is limited to engine
   callers. Should v1 get it too, or should it stay out of v1 files?
2. Is a start-up sweep for orphaned rows (§5.4) enough, or should removal
   also refuse to finish until the sweep confirms none are left?
