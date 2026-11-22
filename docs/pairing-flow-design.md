# Pairing flow design: one direction, one chosen way

Status: **agreed** (2026-11-22). Base: engine `main` at `fe4163a`. The wire
protocol stays at major 1, minor 3, and the ticket stays at version 1.
Tracking issue: mousse-agent/mousse#1510.

This document says what the engine adds so the app can offer the pairing
flow below. §10 splits the work into pull requests and says which of them
change authorization and are held for review by the second teammate.

## The flow

1. **Two verbs, one direction at a time.** "Use this computer from your
   phone or another computer" shows a code and a link. "Use another
   computer from here" takes a pasted or scanned link, or connects over
   SSH. Pairing grants one direction. An unticked box at Connect, "Also let
   <name> use this computer", adds the other.
2. **The computer that shows the code picks how the other device
   connects:** same Wi-Fi, Tailscale, a port forward, a tunnel or a relay.
   The picker shows which are ready. The code carries only the chosen way.
3. **Opening a link says at once when it cannot work from there,** and
   when it can, that the host answered.
4. **Later, either side can ask for the other direction** over the
   connection that exists, with no new code. The other side answers Allow
   or Not now.
5. **The access level is chosen with Allow,** applies from the moment the
   grant exists, and narrowing it cuts work already running.

Out of scope: Mousse ID and Mousse Plus, native phones, reaching a computer
through another paired one (#11), and setting up a tunnel (#10).

## Decisions

1. **A ticket carries one way.** `invite.create {way}` selects it from this
   computer's own inventory. The ticket format does not change (§2).
2. **Readiness and link inspection are helper operations with no network
   traffic** (`routes.available`, `join.check`; §3, §4). The classifier,
   the interface list and the address policy live in the helper, and the
   app does not repeat them.
3. **Reachability is a separate, bounded probe** (`join.probe`; §5). It
   stops once the inner TLS connection matched the ticket's host identity.
   Approve-before-dial (Phase 1b §1.3) has no exception.
4. **One-way pairing needs no wire change** (§6). A pairing creates no
   grant on the joiner, and minor 3 already refuses a host-opened stream
   that the caller's own grant table does not allow.
5. **Asking for the other direction is an app message** on a
   `mousse.hello` exchange. The helper adds one operation,
   `grant.add_connected`, that grants to the peer of a live connection
   (§7).
6. **The access level is the grant's `role`** (§8). The engine reads no
   order into role names and keeps treating only `owner` specially. The
   role is fixed when a link invitation is made and chosen with the answer
   for an in-person approval. A role edit keeps the grant and closes its
   paths.
7. **No prompt after the code for "Send link".** The showing owner is
   present when the invitation is made and picks the level there. A prompt
   after the code exchange would change the ceremony and need wire minor 4;
   it is left as a possible later change.
8. **The app checks features before it sends a new field** (§1). An older
   helper ignores fields it does not know and would answer with a wider
   ticket or an `owner` grant.

## 1. App ↔ helper protocol 1.2

Additions only. A 1.2 helper serves a 1.1 app unchanged.

- The `hello` reply adds `features: string[]` on a negotiated 1.2 channel.
  Each feature is listed only by a helper that implements it:

  | Feature | Covers |
  |---|---|
  | `invite-way` | `invite.create {way, route}` |
  | `route-readiness` | `routes.available`, `join.check` |
  | `join-probe` | `join.probe`, `join.probe.cancel` |
  | `grant-revoke-local` | `grant.revoke_local` |
  | `grant-roles` | `role` on `invite.create`, `approval.answer` and `grant.add`; `grant.set_role`; grant fields on `stream.incoming` |
  | `grant-add-connected` | `grant.add_connected` |

- **Unknown fields.** Every new operation rejects a field it does not know
  with `bad_request`. `invite.create` rejects unknown fields only when
  `way` is present; without `way` it behaves as in 1.1. `routes.config`
  keeps its existing errors.
- **No silent fallback.** An app that asked for a way or a role and got an
  error does not repeat the request with the field removed.

## 2. Choosing the way: `invite.create`

`invite.create {kind?, way?, route?}`

- `kind`: `in_person` or `link`, default `in_person`, as today.
- `way`: one of `lan`, `tailnet`, `public`, `tunnel`, `relay`.
- `route`: optional, valid only with `way`. An exact canonical hint taken
  from `routes.available`. It selects one entry of this computer's
  inventory; it never adds an address.

The reply keeps `{invitation, uri, routes, expires_at, code?,
attempts_left?}` and adds `ways`: the distinct ways of the routes carried,
in order. With `way` it is exactly `[way]`.

**Inventory.** The helper lists every candidate before any cap, then
selects, then caps at `MAX_ROUTES`. Today's `advertised()` caps while it
inserts, so a later class can be cut before selection; the selected path
does not use that list. A candidate's way comes from where it came from:

| Way | Candidates |
|---|---|
| `lan` | private IPv4 literals the listener serves |
| `tailnet` | `100.64.0.0/10` literals the listener serves |
| `public` | entries of the `public` list, whatever their address class |
| `tunnel` | configured and CLI tunnel origins, and #10's managed tunnel, while the WebSocket listener runs |
| `relay` | hints of this computer's registered relays |

Order within a way is today's order. Candidates are deduplicated by
canonical text.

**Rules.**

- Neither `way` nor `route`: the 1.1 path, with the same routes in the same
  order.
- `way: null`, an unknown way, a selector of the wrong type, or `route`
  without `way`: `bad_request`.
- A well-formed selection with nothing to offer now: `way_unavailable`.
- The selection is made before the invitation, its code or a relay
  allow-set entry exists. A failed request leaves none of them behind.
- `relay`: the relay allow-set slot is checked and reserved under one lock
  with the creation. A new invitation never displaces an open invitation
  or a recovery entry; when it would, the request fails with
  `way_unavailable`. A failed store read is `store_failed`, never an empty
  list.
- `in_person` with `relay` is allowed. The kind decides the ceremony and
  the way decides the path. The relay destination is still approved by the
  joiner.

**What selection does not do.** It limits the hints this ticket discloses.
It is not a transport rule on the grant: a paired device may later reach
the host over any route it learns and its owner approves.

## 3. Readiness: `routes.available`

`routes.available {}` → `{ways: [{way, state, reason, routes}]}`

All five ways, in the order of §2. `routes` is exactly what a selection of
that way alone would put in a ticket now.

| State | Reason | Meaning |
|---|---|---|
| `ready` | `null` | at least one candidate |
| `off` | `disabled` | LAN or tailnet is switched off and the interface is present |
| `unavailable` | `no_interface` | no address of that class on this computer |
| `unavailable` | `interface_unknown` | the interfaces could not be listed |
| `unavailable` | `not_bound` | selected, but its socket is not bound |
| `unavailable` | `restart_required` | the saved setting for this way differs from the one running |
| `unavailable` | `not_configured` | no port forward, tunnel or relay is set |
| `unavailable` | `origin_unavailable` | a tunnel is set but the WebSocket listener is not running |
| `unavailable` | `relay_not_registered` | a relay is set but not registered now |
| `unavailable` | `relay_capacity` | no free allow-set slot for a new invitation |
| `unavailable` | `paused` | networking is paused until a removal is saved |

- `ready` means this helper can issue a ticket with that way. It says
  nothing about the other device's path to it.
- A pending restart for one way does not hide another way that works.
- `no_interface` supports "No Tailscale address on this computer". It does
  not prove Tailscale is stopped: the range is shared with carrier NAT, and
  routed setups exist.
- The app asks again when the dialog opens and on the network, config and
  relay events it already receives. There is no readiness event.
- Errors: `bad_request`, `store_failed`.

## 4. Inspecting a link: `join.check`

`join.check {ticket, arrival}` → `{kind, invitation, hints}`

`arrival` is required: `scan` or `link`. `hints` has one entry per ticket
hint, in ticket order:

`{route, way, eligibility, destination, reason, local}`

- `way`: the class the receiver can infer (`lan`, `tailnet`, `public`,
  `tunnel`, `relay`) or `null`. A DNS-named `tcp` hint is `null`: the wire
  carries only the text, not where the host took it from.
- `eligibility`: `automatic` (a private `tcp` literal), `approval_required`
  or `skip`.
- `destination`: for `approval_required`, the canonical text the owner
  approves: the full `tcp` or `wss` route, or `relay://host:port`.
  Otherwise `null`.
- `reason`: for `skip`, one of `reserved`, `unknown_scheme`, `malformed`,
  `forbidden_address`, `unsupported_transport` (a valid `mdns:` hint, which
  this helper does not dial from a ticket). Otherwise `null`.
- `local`: `interface_present`, `no_matching_interface` or `unknown`.
  Advice only. It never proves that routing works or fails.

**Rules.**

- No DNS lookup, mDNS browse, socket, relay contact, approval, flow record
  or event. Nothing is written.
- The decisions are the code `join` uses, not a copy: the arrival rule for
  kind 1, a ticket naming this computer, expiry, stored attempts, and the
  candidate filter.
- It reads stored flow records without taking a join hold or replaying a
  completion.
- Errors: `bad_request`, `bad_ticket`, `pairing_failed`, `expired`,
  `attempts_exhausted`, `paused`, `store_failed`.

## 5. Reachability: `join.probe`

`join.probe {ticket, arrival, approved?}` → one reply:

- `{reachable: true, route, ms}`: the inner TLS connection matched the
  ticket's host identity on that route.
- `{reachable: null, reason}`: an option was left untried:
  `approval_required` (every usable hint needs approval) or
  `relay_unprobed`.
- `{reachable: false, reason}`: nothing is left: `no_route`, `timeout`,
  `unreachable`, `forbidden_address`, `pin_mismatch`, `peer_certificate`
  or `tls`.

`join.probe.cancel {probe}` → `{cancelled}`. `probe` is the request id of
the `join.probe` on the same channel. A cancel that wins ends the probe
with the error `cancelled`, once; `cancelled: true` means the dial and its
slot are released.

**Rules.**

- It dials what `join` would dial: private literals, plus hints that are
  in both the ticket and `approved`. `approved` holds at most `MAX_ROUTES`
  entries. Nothing given here is stored as an approval.
- It reuses `Caller::probe_route`: the pinned inner TLS handshake, then the
  pipe is dropped. No `HELLO`, `JOIN_PROOF`, code exchange or stream. No
  pin, peer, approval, completion or key is stored, and no connection is
  announced to the app.
- **Relay hints are not probed.** A relay join opens a circuit and uses the
  host's pre-accept quota, which the join that follows needs. With a relay
  hint left and no direct route passed, the answer is `reachable: null,
  reason: "relay_unprobed"`.
- One search, one route at a time, one monotonic deadline over lookup,
  every address, outer TLS and WebSocket, and inner TLS. No candidate
  starts after the deadline or a cancel.
- One probe per ticket hash. A second, or one over the cap, is `busy`.
- It ends on cancel, on networking pause and when the channel closes.
- No progress event and no cache of results.
- Errors: those of `join.check`, plus `busy` and `cancelled`.

**Cost to the host.** A probe from a device with no grant holds one
pre-auth slot of its listener kind until it closes. It spends no pairing
attempt and does not rotate a code. A host that already granted the probing
device recognizes it at step 1; the promise is that no invitation or grant
changes, not that the host sees nothing.

**What a positive answer means.** The endpoint named in the link answered.
It does not show that the invitation is still open, and it does not
replace the code.

**Limits** (`crates/mousse-helper/src/limits.rs`, `docs/limits.md`; an
override may only lower them):

| Name | Default | Range | Meaning |
|---|---|---|---|
| `MOUSSE_NET_JOIN_PROBE_MS` | 10 000 | 500 to 10 000 | the whole probe |
| `MOUSSE_NET_JOIN_PROBES_MAX` | 2 | 1 to 2 | probes running at once per helper |

## 6. One-way pairing

A shows the link and B joins. Afterwards A holds a grant for B and B holds
a peer record for A. Neither needs the other record, and the engine needs
no new operation to pair this way.

What the engine already does:

- **Keep connected** lists peer records and keeps an outbound path. A
  computer that holds only a grant does not dial.
- **`conn.up.both`** says the connection can carry host-opened streams. It
  does not say the caller granted the host anything. The caller's helper
  checks its own grant on every stream the host opens.
- **Relay keys and manifests** follow the caller's direction and work
  without a grant on the joiner. Nothing of them can be copied to start the
  other direction.
- **`join.status` and `join.ack`** recover the joiner's enrollment only.

What the app changes (not part of the engine work): it records each
direction on its own, finishes a one-way pairing without `grant.add` and
pairback, and never reads a peer's old `pairback` message as consent.

### 6.1 Ending one direction: `grant.revoke_local`

`grant.remove` also drops this computer's approvals and completion records
for that identity, which belong to the other direction.

`grant.revoke_local {grant}` → `{removed}` or `{removed: true, paused:
true}`

- It removes the named grant through the same journal as `grant.remove`,
  closes its connections with `GRANT_REVOKED`, and drops that grant's
  caller key and recovery entries.
- It leaves the outbound peer record, its approvals, its relay secrets and
  its completion record alone.
- Before it replies, the streams the peer opened are reset, on this
  computer's own connections to it and on the peer's connections here
  (which close only afterwards), and data queued for the app on them is
  dropped. No data from them reaches the app after the reply.
  `grant.remove` does the same.
- An id that is no longer this computer's grant answers `{removed:
  false}`, also when a newer pairing of the same peer replaced it; the
  newer grant stays.
- Errors: `bad_request`, `journal_failed`. Events: the existing
  `grant.closed`, `net.paused` and `net.resumed`.

As built, relay cleanup for any removal:

- A start drops the caller keys and recovery entries of grants that are
  gone, so a crash between the journal and the cleanup leaves none on
  disk. A cleanup whose save fails is logged and runs again at the next
  removal or start. A leftover entry never admits anyone: the allow-set
  lists only keys and recovery entries of live grants.
- A caller key is stored only if the connection it came on still holds
  the same grant under the relay file's lock. A key from a grant that
  ended or was replaced meanwhile is refused, so it cannot erase the
  replacement's key.

## 7. Asking for the other direction

The request is an app message; the grant is made by the helper.

**App side** (in the Mousse app, listed here so the engine part is
understood). After both apps advertised the feature in `mousse.hello`, the
caller opens one long-lived `mousse.hello` exchange per peer and both sides
may write on it:

- `access.request {id}`: "I want to use your computer". No identity, role
  or routes: the receiver takes the identity from the connection.
- `access.answer {id, decision: "allow" | "not_now"}`.
- `access.state`: what the sender now grants the receiver. Sent at setup,
  after a local change and after a reconnect. It is information; it never
  creates or widens a grant on the receiver.

The app holds one pending request per peer and direction, lets a request
expire, and does not prompt again by itself after Not now. Those limits
are app limits.

**Helper side:** `grant.add_connected {conn, name, role}` → `{grant, role,
already}`

- `conn` is a connection number of this channel. The identity is the
  authenticated peer of that connection; the request carries none.
- The connection must be published and live when the grant is committed.
  The lookup and the commit are serialized with close, `peer.forget`,
  revocation and the removal pause.
- An existing live grant is returned as it is, with its own role, even when
  the request names a wider one.
- The grant is saved before the reply.
- Errors: `bad_request`, `no_conn`, `paused`, `refused`, `store_failed`.

After Allow the new direction uses the existing connection on minor 3. A
computer that was granted access and has no route of its own to dial reads
"available when the other computer connects".

## 8. Access level: the grant's role

`spec/wire.md` §7 already defines the role: 1 to 32 bytes of `[a-z0-9-]`,
given meaning by the app. The engine keeps two meanings of `owner`: the
`mousse-grants` stream and signed removals.

### 8.1 Choosing the role

- `invite.create {role?}`: the role fixed in the invitation. Absent:
  `owner`, as today.
- `approval.answer {request, yes, role?}`: for an in-person approval, the
  role of the grant. Absent: the invitation's role. A role with `yes:
  false` is `bad_request`. The role is checked before the pending request
  is consumed. It is passed with the winning approval and never written
  into the invitation, so one waiting joiner's answer cannot reach another.
- `grant.add {identity, name, receipt?, role?}` → adds `role` to the
  reply. Absent: `owner` for a new grant. An existing grant is returned
  with its own role, unchanged.
- "Send link" keeps the role fixed in the invitation.
- `enrolled` adds `role`. `grants.list` adds `revision`.

**Spec.** `spec/wire.md` §10.4 and §10.8 change in words only: an
in-person approval may select the role, defaulting to the invitation's.
`PAIRED` already carries the role. The role is in no ticket, MAC,
transcript or confirmation, so no vector changes; one vector is added with
different invitation and approved roles, and both implementations replay
it. A `PAIRED` sent again for a receipt carries the grant's current role.

### 8.2 Changing the role: `grant.set_role`

`grant.set_role {grant, expected_revision, role}` → `{grant, role,
revision, changed}`

- Each grant has a revision, 1 for a new or migrated grant, one higher
  after each edit.
- The grant id, identity, name, receipt, authorizing owner, times, caller
  key and pair secret stay. The edit is made in place, not by replacing the
  grant.
- The same role with the current revision: `changed: false`. A revision
  that is not current: `revision_conflict`.
- Event after the save: `grant.role_changed {grant, role, revision}`.
- Errors: `bad_request`, `no_grant`, `revision_conflict`, `paused`,
  `store_failed`.
- **Saving.** The check, the save and admission are serialized. A save
  whose result is unknown fails closed: the helper serves neither role for
  that grant until the stored table is read again. A narrowing is never
  reported as done while the wider role can still be served.
- **Store version.** Once a grant with a role other than `owner` is
  stored, the grants file has a version an older helper refuses to load,
  including the table kept in an enrollment journal. An older helper
  treats every grant as `owner`.

### 8.3 Cutting work under the old role

A role edit closes every path that serves the peer under that grant with
`CANCELLED`: inbound connections bound to the grant, and outbound or
renewing paths on which this computer serves the peer's streams. Streams
queued under the old revision are dropped behind a fence, not delivered.
`GRANT_REVOKED` keeps meaning that the grant is gone.

The peer's keep-connected reconnects: `cancelled` does not park it, and
its first retry is `KEEP_RETRY_FIRST_MS` away at most.

Closing connections does not stop work the app already started. The app
that asks for the edit first stops serving that grant, cancels its running
calls, subscriptions, terminals and jobs, and checks the revision again
before queued work commits.

### 8.4 Enforcing the role

- Every `stream.incoming` carries `{grant, role, revision}` of the local
  grant it is served under, on both physical directions.
- A helper hands traffic of a grant whose role is not `owner` to its app
  only when that app listed `grant-roles` in its `hello`. Otherwise those
  streams are refused.
- Standalone `mousse-helper serve` opens a terminal only for a role it
  names as allowed.
- A demotion from `owner` ends that peer's `mousse-grants` stream and
  drops what was queued for it. A signed removal from a signer without a
  live `owner` grant is refused, also when it was signed earlier.
- How the caller learns its role after an edit: the serving app says it in
  its `mousse.hello` reply. `AUTHORIZED` stays as it is. The serving side
  enforces from its own grant only.

## 9. Relay-only completion recovery

A "Send link" join over a relay saves its completion record first and the
relay route, its approval and the sealed temporary tag afterwards. A crash
between them leaves a paired device that cannot reconnect, and with a
relay-only ticket there is no direct route to fall back on.

The fix stores the approved relay route and destination and the sealed
tag with the completion record, replays them before the pairing is
reported complete, and never brings back a tag after the caller key was
enrolled, the peer was removed or the tag expired. No plain tag, ticket
secret or link is written. Until it lands, a relay-only pairing has this
window, and the app says "Pairing was saved, but relay setup didn't
finish" when it knows.

## 10. Work breakdown

| # | Pull request | Changes authorization | Depends on |
|---|---|---|---|
| 1 | Choose a way; readiness; `join.check`; protocol 1.2 (§1 to §4) | no | none |
| 2 | `join.probe` (§5) | no | 1 |
| 3 | `grant.revoke_local` (§6.1) | yes | none |
| 4 | Roles: choose, edit, enforce (§8) | yes | none |
| 5 | `grant.add_connected` (§7) | yes | 4 |
| 6 | Relay-only completion recovery (§9) | stores an admission credential | none |

1 and 2 are a complete step by themselves: a ticket discloses one way, a
link can be inspected without traffic, and its host can be checked. 3 to 6
are held for review by the second teammate before they merge.

**Files.**

- **1** owns the invitation and candidate assembly in
  `crates/mousse-helper/src/app/pairing.rs`, new
  `app/pairing/availability.rs` and `app/pairing/check.rs`, the
  ticket-policy function in `app/paths.rs`, the interface snapshot in
  `app/changes.rs`, relay inventory and reservation in `app/relay.rs`,
  candidate enumeration in `crates/mousse-net-io/src/routes.rs`, and in
  `app/mod.rs` only the protocol constant and the `features` line after
  `proto`. New operations are dispatched through `pairing::OPS`.
- **2** owns new `app/pairing/probe.rs`, its dispatch, the two limits and
  `docs/limits.md`.
- **3** owns new `app/pairing/revoke_local.rs` and its dispatch beside
  `grant.remove`. It reuses `Removal::remove`.
- **4** owns `crates/mousse-net-core/src/grants.rs` and
  `pairing/host.rs`, `crates/mousse-net-io/src/host.rs` and `store.rs`,
  the invitation, approval, add and list handlers, new
  `app/pairing/roles.rs`, both `stream.incoming` paths, standalone
  serving, `engine/removals.rs`, `spec/wire.md`, the new vector and both
  replays.
- **5** owns new `app/pairing/connected.rs` and its dispatch beside
  `dial`.
- **6** owns completion records in `crates/mousse-helper/src/peer.rs` and
  `crates/mousse-net-io/src/store.rs`, and `app/relay.rs` and
  `app/relay_store.rs`.

**#10 (managed tunnel).** It owns `routes.managed_tunnel`, the
`managed_tunnel` listener slot, the keeper's start sequence and the wait
for the caller's `HELLO`. Pull request 1 reads tunnel candidates through
one function; the managed slot is added to that function, with a test,
once #10 is merged.

## 11. Checks

Each check is a `mousse-check` entry in `checks/pairing-flow.toml` with a
must-fail control (`cfg!(mousse_control = "...")`, listed in the workspace
`check-cfg`). Each control fails its own assertion while the normal build
passes.

| Check | Control | The bug it plants |
|---|---|---|
| `pairing.invite-way` | `select-after-route-cap` | the way is selected from the capped list |
| | `selector-adds-address` | a `route` outside the inventory is put in the ticket |
| | `relay-reservation-overbooks` | a new invitation takes a slot in use |
| | `invite-all-ways` | a selected ticket carries another way's hint |
| `pairing.join-check` | `check-dials-destination` | inspection makes network traffic |
| | `check-auto-approves-public` | a public hint is reported `automatic` |
| | `link-accepts-kind1` (existing) | a pasted in-person ticket is taken as scanned |
| `pairing.join-probe` | `probe-accepts-outer-tls` | success without the inner identity |
| | `probe-sends-join-proof` | the probe advances the invitation |
| | `probe-dials-unapproved` | an unapproved destination is dialled |
| | `probe-opens-relay-circuit` | a relay hint is probed |
| | `probe-restarts-deadline` | each candidate gets a new deadline |
| | `probe-cancel-keeps-slot` | a cancelled probe keeps its slot |
| `pairing.revoke-local` | `local-revoke-forgets-peer` | the outbound peer goes with the grant |
| | `local-revoke-keeps-inbound-access` | the grant survives |
| | `no-revoke-journal` (existing) | the removal is not journaled |
| `pairing.grant-roles` | `approval-uses-invitation-role` | the chosen role is ignored |
| | `role-edit-ignores-revision` | a stale edit is applied |
| | `role-edit-keeps-reverse-path` | a path under the old role stays open |
| | `restricted-grant-served-to-legacy-app` | an app without `grant-roles` gets the traffic |
| | `restricted-grant-opens-standalone-terminal` | `serve` ignores the role |
| | `demoted-owner-keeps-grants` | `mousse-grants` stays open after demotion |
| | `restricted-store-readable-by-old-helper` | the store version is not raised |
| `pairing.grant-connected` | `grant-from-stale-connection` | a closed connection's identity is granted |
| | `connected-grant-upgrades-existing` | an existing grant is widened |
| | `connected-grant-trusts-request-identity` | the identity is read from the request |
| `pairing.relay-completion` | `completion-omits-relay-admission` | the crash window stays |
| | `completion-replays-retired-tag` | a retired tag comes back |
| | `completion-stores-clear-tag` | the tag is stored unsealed |
| | `relay-replay-after-forget` | a replay restores a removed peer |

## 12. Acceptance for pull requests 1 and 2

Run with two real helpers that have their own identities and profiles.

**Choosing a way and inspecting a link**

- A ticket made with `way: "lan"` decodes to private `tcp` literals only.
  `tailnet`, `public`, `tunnel` and `relay` each carry only their own
  hints. An exact `route` yields that one hint, byte for byte.
- With enough earlier candidates to fill a ticket, a later ready way still
  appears when selected. Every ticket holds at most `MAX_ROUTES` hints.
  With no selector the ticket has the 1.1 routes in the 1.1 order.
- A way that is off, has no interface, is not bound, is not configured or
  waits for a restart reports that reason, and a healthy way stays
  selectable. An invalid or unavailable selection leaves no invitation,
  code or relay allow-set entry. Two requests for the last relay slot
  cannot both succeed.
- `join.check` on a ticket mixing private, tailnet, public, `wss`, relay,
  `mdns:`, reserved, unknown, malformed and forbidden hints keeps their
  order and gives the exact approval destination for each. During it there
  is no DNS request, browse, connection, relay contact or store change.
  The `join` that follows dials only the automatic and approved hints.
- A pasted in-person ticket, this computer's own ticket, a damaged ticket
  and an expired one fail before any traffic. An unknown field on
  `join.check` or on a selected `invite.create` is `bad_request`; a
  1.1-shaped `invite.create` with an extra field behaves as before.

**Reachability**

- B probes A's LAN ticket and gets `reachable: true` with the route and
  the time. A shows no approval, enrollment or new code, and its pre-auth
  count returns to where it was. B's peers, approvals, completion and
  attempt records are unchanged. The join that follows accepts the code
  first shown, with every attempt left.
- A ticket naming A but pointing at another helper does not report
  `reachable: true`, also when a tunnel's outer TLS succeeds.
- A tailnet, public or tunnel hint causes no lookup and no connection
  until its exact destination is in `approved`. Nothing passed to the
  probe appears in `approvals.list` afterwards.
- A relay-only ticket answers `reachable: null, reason: "relay_unprobed"`
  and the relay sees no join from the probe. The join that follows uses
  the relay.
- With stalled candidates and `MOUSSE_NET_JOIN_PROBE_MS=500` the request
  ends after one deadline. Two probes run at once by default; a third, or
  a second for the same ticket, is `busy`. An override cannot raise either
  limit.
- A cancelled probe ends once with `cancelled`, its slot is free at once,
  and a second cancel reports `cancelled: false`. The same holds on pause
  and when the channel closes.
