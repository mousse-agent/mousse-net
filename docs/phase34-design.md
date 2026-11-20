# Phase 3 and 4 design: the relay and the engine's side of Plus

Status: **frozen** (2026-11-19), after three council rounds and the final
review. Scope: PLAN "Phase 3" (self-hosted relay) and the engine's part of
"Phase 4" (the hosted relay, the helper's Plus client and "remove on all
my hosts"), and PLAN §5. Phase 5 onward, including the browser relay
profile (WSS with Web PKI, ACME IP certificates), is out of scope.

**Plus itself** (its server, accounts, accounting, operations and website)
is specified in the private Plus plan, which is the source for every
message in Part A below. Part A repeats only what the helper and the
hosted relay send to Plus and receive from it, with the plan's section
numbers, so engine code is built and tested against the open Plus double
and contract tests without the plan.

## Background

- **Engine base:** `main` at `4035044` (Phase 0). Phase 1a (`phase-1a`,
  frozen design in `docs/phase1a-design.md` on that branch) and Phase 1b
  (`phase-1b`, frozen design in `docs/phase1b-design.md` on that branch)
  are being built. This design builds on their frozen designs, not on
  their code.
- **Why now:** the relay and the helper's relay client follow 1b, and a
  separate Plus team builds Plus at the same time against the same
  messages (Part A). Part F says which engine slices come in which order.

**Goal of Phase 3:** a self-hosted `mousse-relay` on a $5 VPS with no
domain carries a call from a phone on cellular to a host at home in under
5 minutes from a fresh VPS, and removing one phone leaves another phone
connected.

**Goal of Phase 4 (engine):** the hosted relay forwards only against
prepaid blocks that never name an account, the helper keeps a host
reachable through a Plus outage for as long as its blocks last, and "remove
on all my hosts" reaches hosts that are offline.

---

# Part A: What the engine exchanges with Plus

Every request, answer and signed record here is frozen; the private Plus
plan is their source, and a change starts there. The open Plus double
(`mousse-plus-double`, in memory, on loopback) and the contract tests
(`mousse-plus-contract`) implement exactly these messages. Section numbers
follow the plan; sections about Plus's internals are left out.

## A.1 Parties and what Plus may do

| Party | What it is | Talks to Plus with |
|---|---|---|
| **Endpoint** | One profile's `mousse-helper` on one device (wire.md §1). Hosts and callers are both endpoints. | Its Plus key (§A.3). |
| **App** | The Mousse desktop or phone app. | Nothing directly: through the helper's app channel, and a browser for the Plus website. |
| **Hosted relay** | `mousse-relay` in hosted mode, run by us. | Its report key (§A.3). |

**Plus may:**

- hold accounts and linked endpoints (platform and dates only);
- store and serve opaque ciphertext in the directory and mailbox;
- issue relay admission tokens and lease blocks for endpoints it serves;
- receive relay usage reports and account for them.

**Plus may never:**

- add, change or remove a grant or a pin on any endpoint. No endpoint
  accepts anything Plus signs or serves as authority over trust: a
  manifest counts only if the pinned host signed it, and a removal only if
  an owner-role device signed it (§B.11, Part D). Unlinking an endpoint
  from an account only stops Plus services for it;
- read directory or mailbox contents. Plus never receives the keys;
- name an account in anything a relay sees. Blocks and admission tokens
  carry no account, email or endpoint id;
- be needed for LAN, user routes or a self-hosted relay. Every Plus call
  is optional to everything but the hosted relay and the mailbox.

**What Plus learns** (stated in `spec/privacy.md`, §B.16): the account's
email and payment state; each linked endpoint's Plus key, platform and
IP; which relay handles each endpoint registered; lease sizes and usage
per handle; how many directory slots and deposit tokens an endpoint holds
(roughly how many devices it is paired with); when mail is deposited and
fetched; the IP of anyone reading a directory slot.

## A.2 Conventions

- **Transport:** HTTPS, TLS 1.3, Web PKI at the Plus origin, not behind a
  logging proxy. The base URL is the setting `MOUSSE_NET_PLUS_URL` on the
  helper and `MOUSSE_NET_RELAY_PLUS_URL` on a hosted relay. Plus is not a
  trust anchor (A.1), so clients use the platform verifier and no pin.
- **Bodies:** `Content-Type: application/cbor`. Each body is one canonical
  CBOR map as wire.md §3 defines it. A request body is at most
  `REQUEST_MAX` = 16 384 bytes (fixed), except `POST /v1/relay/report`,
  whose body is at most `REPORT_MAX` = 65 536 bytes (fixed). Larger is
  `too_large`. A report part of `REPORT_ENTRIES_MAX` entries with every
  counter at its largest value is about 42 000 bytes, so a part built by
  the rule of A.12 always fits; `plus-report.json` has that vector.
- **Requests are strict; responses are open.** A request with an unknown
  key is `invalid`. A client ignores response keys it does not know, so
  responses may gain keys in a later minor version.
- **Capability ids never go in a URL.** Slot, inbox and message ids travel
  in request bodies, and answers that carry or depend on them are
  `Cache-Control: no-store`.
- **Versions:** the path carries the major (`/v1`). Each request sends
  `Mousse-Plus-Api: 1.<minor>`. The server serves every minor from 0 to
  its current one within the major, and answers a newer one with
  `version`. This design is minor 0.
- **Times** are Unix seconds (uint), except the Plus time in boot and
  report answers, which is Unix milliseconds.
- **Freshness, per signed record.** Each record says how its time is
  checked; nothing else is checked against a clock:

| Record | Freshness check | A stale one |
|---|---|---|
| `mousse-plus-link-v1` | `issued at` within Plus's clock skew allowance (at most 600 s) | `unauthorized` |
| `mousse-plus-token-v1` | `issued at` within the skew, and a new nonce | `unauthorized` |
| `mousse-plus-handle-v1` | none (no time; bound to relay and endpoint) | — |
| boot record | none: `started at` is information only, so the same record retried after any outage is acknowledged | — |
| report part | none for acceptance; Plus uses `sent at` only to tell when the relay could no longer accept a lease | — |
| admission token, lease block (Plus-signed) | checked by the relay on its Plus clock (A.9 duty 12) | refused by the relay |

Vectors `boot_retry_old_started_at` (a boot record whose `started at` is
days old is acknowledged) and `link_poll_stale` (refused) are in P1.

- **Idempotency:** every request that creates or spends something carries
  a 16-byte `request id`. Its scope is the credential and the path: the
  same id from the same endpoint (or deposit token) on the same path with
  the same body returns the first answer; with a different body it is
  `conflict`. Ids are kept for at least a day, except
  lease request ids, which are kept until the block is settled and
  expired (A.8); a repeat after that reserves a fresh block.
- **Errors:** an HTTP status and a body `{1: code (text), 2: retry after
  (uint seconds, optional)}`. A client that does not know a code acts on
  the HTTP status alone, so codes may be added. Codes never change
  meaning:

| Code | HTTP | Meaning |
|---|---|---|
| `invalid` | 400 | Bad encoding, unknown key, field out of range |
| `version` | 400 | API version not served |
| `unauthorized` | 401 | Missing, expired or bad credential |
| `forbidden` | 403 | Credential valid, action not allowed for it |
| `not_found` | 404 | No such object, or not visible to this credential |
| `conflict` | 409 | Version mismatch, or a request id reused with another body |
| `quota` | 409 | A count limit: slots, linked endpoints, inbox or per-tag messages |
| `too_large` | 413 | Body or field over its fixed maximum |
| `rate_limited` | 429 | Over a rate limit; `retry after` set |
| `not_plus` | 402 | The account has no active plan |
| `allowance_used` | 402 | Bulk allowance for this period is spent |
| `balance_empty` | 402 | Interactive balance is spent, or the account has debt |
| `cap_reached` | 409 | An outstanding cap for this handle, endpoint or account (A.8) |
| `fleet_paused` | 503 | Plus has paused issuing for the whole fleet |
| `unknown_boot` | 409 | Plus has no live record of that relay boot |
| `stale_generation` | 409 | A boot record whose generation is not above the highest seen for that relay, under another boot id |
| `handle_taken` | 409 | Another endpoint already holds this relay handle |
| `issuer_not_ready` | 503 | Plus is starting, restoring or paused, or a repeat whose issuer key is lost (A.8) |
| `internal` | 500 | Anything else |

## A.3 Auth

### Endpoints (helper)

Each endpoint makes a P-256 **Plus key** in its keystore when it first
links. It is separate from the identity key, so Plus never learns an
identity key. The Plus key signs only the domain-tagged records below (the
wire.md §4.1 rule, applied to this key).

**Link** (a device-authorization flow; the user types the app's code into
the browser, so a link started by someone else cannot be approved by
accident):

1. `POST /v1/link/start`, body `{1: Plus public key (65 bytes SEC1), 2:
   platform (text, 1–64 bytes, for example "macOS arm64")}` → `{1: link
   id (16), 2: user code (text, 8 characters from an unambiguous alphabet,
   shown as `XXXX-XXXX`), 3: verify URL (text, without the code), 4:
   expires at, 5: poll interval (uint ms)}`. `link/start` is rate limited
   per IP.
2. The app shows the code and opens the verify URL on the Plus website.
   The signed-in user types the code; the page shows the platform and asks
   to approve or deny. Wrong codes are limited per account.
3. `POST /v1/link/poll`, body: a signed envelope (A.12) of `{1:
   "mousse-plus-link-v1", 2: link id, 3: issued at}` → `{1: state (0
   pending, 1 approved, 2 denied, 3 expired), 2: endpoint id (16, when
   approved)}`. Approval is single use: once approved or denied the link
   cannot be approved again. The result stays readable: every poll signed
   by the link's Plus key returns the same state and endpoint id until the
   link's `expires at`, which approval moves later. The helper keeps polling until Plus answers
   state 2 or 3 or `not_found`, never stopping at its own copy of the
   expiry, so a lost answer is recovered by polling again. Polling one
   link faster than its interval is `rate_limited`.
4. **Durability:** an approved result survives a Plus crash or restore
   together with the endpoint, so a poll never says pending for a linked
   endpoint. A pending or denied link may not survive a restore; then the
   poll answers `not_found` and the helper starts again.
5. **One endpoint per Plus key:** approving a link whose Plus key is
   already linked to the same account returns that endpoint's id and
   creates nothing; to another account it is `conflict`. A helper that
   missed its result and links again therefore never leaves a ghost
   endpoint.

Custom labels ("Alex's laptop") stay in the app; Plus knows only the
platform and dates.

**Access tokens:** `POST /v1/token`, body: a signed envelope of `{1:
"mousse-plus-token-v1", 2: endpoint id, 3: audience (text: the Plus
origin), 4: issued at, 5: token nonce (16)}` → `{1: access token (text),
2: expires at}`. Plus checks the signature against the endpoint's Plus
key, that `issued at` is within the skew of its clock, and that the nonce
is new. Nonces are kept for twice the skew, the whole time an `issued at`
can be accepted. Failed token requests are limited per IP. The token is
256 random bits, valid until `expires at`, and sent as `Authorization:
Bearer <token>`. An unlinked endpoint's tokens stop at once.

### Deposit tokens (mailbox senders)

A sender deposits into a host's inbox with `Authorization: Deposit
<base64url 32 bytes>`. The host makes one token per paired device and
registers only its SHA-256 and a 16-byte tag (§A.6). Senders need no
account. A token removed from its inbox's set stops at once.

### Directory readers

None. A slot id is a 256-bit capability (§A.5).

### Relays

Each hosted relay has a P-256 **report key** in its state directory,
separate from its TLS identity key. An operator adds the relay to Plus's
fleet with its identity key, report key, region and endpoints. Boot and
report bodies are signed envelopes under that key (A.9).

### How fast revocation takes effect

| Action | Effect |
|---|---|
| Unlink an endpoint | Bearer tokens, admission renewals and new blocks stop at once. Blocks already held (at most a current and a pending per class and handle, on one relay) run out or expire. A live relay registration ends when its admission token has expired and it holds no usable block (§B.4): at most one admission token lifetime (1 h by default) or the held blocks' expiry, whichever is later. Its directory slots and inbox are deleted. |
| Remove a deposit token from an inbox | Deposits with it, and state queries with it, are `unauthorized` at once; its waiting messages are deleted. |

## A.4 Accounts and endpoints API

All with a bearer token.

| Request | Body | Answer |
|---|---|---|
| `GET /v1/account` | none | `{1: plan state (0 none, 1 active, 2 past due, 3 cancelled), 2: plan id (text), 3: period ends at, 4: this endpoint id, 5: linked endpoints (uint)}` |
| `GET /v1/usage` | none | `{1: period starts at, 2: period ends at, 3: bulk {1: allowance, 2: used, 3: reserved, 4: available}, 4: interactive {1: balance, 2: used, 3: reserved, 4: available, 5: debt}, 5: this endpoint {1: bulk used, 2: interactive used}}`, all in bytes |
| `POST /v1/endpoint/unlink` | `{1: request id}` | `{}`; effects as in A.3 |

Unlinking another endpoint and deleting the account are done on the Plus
website only.

## A.5 Directory API

A **slot** holds one opaque ciphertext of at most `DIR_ENTRY_MAX` = 4096
bytes (fixed). The engine writes one slot per pairing (§B.12).

| Request | Auth | Body | Answer |
|---|---|---|---|
| `POST /v1/dir/put` | bearer | `{1: request id, 2: slot id (32), 3: version (uint), 4: ciphertext (bytes)}` | `{}`. Creating needs version 1; updating needs the stored version + 1, else `conflict`. Only the endpoint that created the slot may write it, else `not_found`. A deleted slot id is never created again (`not_found`). Over `MOUSSE_PLUS_DIR_SLOTS_PER_ENDPOINT` is `quota`. |
| `POST /v1/dir/get` | none | `{1: slot id}` | `{1: version, 2: ciphertext}`, or `not_found` |
| `POST /v1/dir/delete` | bearer, owner | `{1: slot id}` | `{}` once the deletion is durable (below); absent is also `{}` |
| `POST /v1/dir/list` | bearer | `{}` | `{1: [{1: slot id, 2: version}]}`: this endpoint's slots |

- Reads are anonymous so that a caller from another owner, who has no Plus
  account, can still read its host's slot. They are rate limited per IP.
- Slots go when the owning endpoint unlinks or the account is deleted.
- **Deletions are durable.** A delete is answered only once it survives
  a Plus crash or restore, and Plus never serves a deleted slot again,
  from any server or restored copy, so a removed caller that still holds
  its slot id and key never reads it. An unlink or account deletion
  deletes every slot the endpoint owns, in the same way.

## A.6 Mailbox API

Each host endpoint has at most one **inbox**. Messages are opaque
envelopes of at most `MAIL_ENVELOPE_MAX` = 8192 bytes (fixed).

| Request | Auth | Body | Answer |
|---|---|---|---|
| `POST /v1/inbox/put` | bearer | `{1: request id, 2: inbox id (32), 3: sequence (uint), 4: [{1: tag (16), 2: token hash (32)}]}`, at most `DEPOSIT_TOKENS_MAX` = 256 (fixed) | `{}`. Creates the inbox or replaces its token set. The sequence must grow, else `conflict`. Only the creating endpoint may write it. Messages under a tag that leaves the set are deleted. |
| `POST /v1/inbox/deposit` | deposit token | `{1: request id, 2: inbox id, 3: envelope (bytes)}` | `{1: message id (16)}`. A wrong token or unknown inbox is `unauthorized`, the same for both. Too many messages waiting under this tag, or in the inbox, is `quota`. |
| `POST /v1/inbox/fetch` | bearer, owner | `{1: inbox id, 2: after (uint, optional)}` | `{1: [{1: message id, 2: sequence (uint), 3: tag, 4: received at, 5: envelope}]}`, ordered by sequence, at most one page |
| `POST /v1/inbox/ack` | bearer, owner | `{1: inbox id, 2: [message id]}` | `{}`; acknowledged messages are deleted and become `delivered` |
| `POST /v1/message/state` | the deposit token used | `{1: message id}` | `{1: state (0 pending, 1 delivered, 2 expired)}` |

- **Cursor, for paging only:** each message gets the inbox's next sequence
  number. `after` returns only later messages; without `after`, every
  waiting message from the oldest. A client starts every fetch round
  without `after` and uses it only to page within that round; it never
  stores it. Sequences may restart after a Plus restore (A.13), and
  unacknowledged messages stay waiting, so a round from the oldest always
  sees every waiting message.
- Ids are random: inbox 32 bytes, message 16.
- Deposits and state queries are limited per deposit token; these
  requests have no per-IP limit, so a home or carrier NAT never shares one. The per-tag
  quota is well below the inbox total, so one paired device (for example
  the one being removed) cannot fill the inbox for others.
- Messages expire after 30 days by default; delivered and expired states
  stay readable for 30 days by default.

## A.7 Issuer: relay admission tokens

A hosted relay accepts a registration only with an admission token for
that relay and handle (§B.4). It is not bound to the relay's boot, so it
survives a relay restart.

`POST /v1/relay-admission` (bearer), body `{1: request id, 2: relay id
(32), 3: registration public key (65), 4: handle proof (64)}` → `{1:
admission token (signed envelope, A.12)}`.

- **Relay id** = SHA-256 of the relay's identity public key (SEC1, 65
  bytes). **Handle** `H = SHA-256("mousse-relay-handle-v1" ‖ relay id ‖
  registration public key)`. Both frozen.
- **Handle proof:** a raw signature by the registration key over the
  canonical CBOR `{1: "mousse-plus-handle-v1", 2: relay id, 3: endpoint
  id}`. Plus computes H itself and checks the proof, so nobody can claim
  another endpoint's handle at Plus.
- The first endpoint to present a handle holds it, durably.
  Another endpoint gets `handle_taken`.
- A handle is **live** while it holds an unexpired admission token. At
  most two live handles per endpoint and relay by default. A handle the helper stops renewing frees itself at most one
  token lifetime later, even if its blocks are still settling, so handle
  rotation (§B.4) never waits for Plus to finish with its blocks.
- Needs an active plan (`not_plus`). Valid one hour by default.
  The helper asks for a new one at half life and presents it on the live
  registration with `ADMIT` (§B.3). Past the token's `not after` the relay
  keeps the registration only while the handle holds a usable block, and
  takes no new `LEASE` for it; with no usable block it closes it with
  4004 (§B.4). So a Plus outage never stops forwarding sooner than the
  blocks the host already holds.
- `GET /v1/relays` (bearer) → `{1: [{1: relay identity key (65), 2:
  region (text), 3: endpoints (array of text `host:port`)}]}`: the fleet,
  for building manifests (§B.11).

## A.8 Issuer: leases (prefetch)

A **block** (A.12) lets one relay boot forward a number of bytes of one
class for one handle. The target asks for the next block when the current
one is half spent (`MOUSSE_NET_PLUS_PREFETCH_PERCENT`), or at once when it
has none.

`POST /v1/lease` (bearer), body `{1: request id (16), 2: relay id (32),
3: boot id (16, as the relay announced it, §B.3), 4: handle (32), 5:
class (0 interactive, 1 bulk)}` → `{1: block (signed envelope)}`, or an
error.

The helper stores the request id before sending and retries a failed or
unanswered request, also after a restart, **with the same request id**,
and gets the same block if one was reserved. Plus keeps a lease request id
until its block is settled and expired; a repeat after that reserves a
fresh block.

**What a request can get.** Plus answers the first check that fails, in
its own order:

- **A repeat request id gets one canonical answer:** the block first
  signed for it, byte for byte, even after a Plus crash or an issuer key
  rotation. An issuer key that stops issuing new blocks at a rotation is
  kept for repeats until every block naming it is done, and relays keep
  pinning it that long (the rotation overlap is at least
  `BLOCK_MAX_LIFETIME` plus Plus's report grace, five minutes by default). If
  that key is lost, a repeat
  answers `issuer_not_ready` until the block is done, and after that a
  repeat reserves a fresh block (A.2). Vector
  `lease_repeat_after_rotation`.
- `forbidden`: the handle is not held by this endpoint.
- `not_plus`, `balance_empty`: no active plan, or debt.
- `unknown_boot`: Plus has no live record of that relay boot.
- `cap_reached`, for any of:
  - two blocks for this handle, class and boot are not yet final (a spent
    block is final at once, A.9, so steady bulk is never held up);
  - **one funded relay per endpoint:** another relay holds a block for
    this endpoint that Plus has not finished with. A move to another relay
    is a **staged cutover with a short interruption** (§B.11): the new
    route is staged and approved while the old one serves; at cutover the
    helper releases its old blocks (`RELEASE`, §B.10), and the new relay
    is funded once every old block is done on a **verified stop** (a
    final, a complete snapshot, a complete stopping snapshot, or an
    operator retiring that relay boot) or Plus's clock is past its
    **latest forwarding time** `e + FORWARD_MARGIN` (A.9 duty 12). A
    silent relay's blocks therefore never fund another relay while its
    clock could still call them usable. Handle rotation on the same relay
    is not a move;
  - **newest handle only:** a block is issued only for the endpoint's
    newest live handle on that relay. A superseded handle spends only the
    blocks it already holds;
  - Plus's own outstanding limits for the endpoint or account.
- `fleet_paused`: Plus has paused issuing.
- `allowance_used` (bulk) or `balance_empty` (interactive). A block may be
  smaller than the default when the balance is lower, never below 65 536
  bytes.
- `issuer_not_ready`: Plus could not make the block durable in time; the
  helper retries with the same id.

## A.9 Relay → Plus: boot, reports and the relay's duties

| Request | Body | Answer |
|---|---|---|
| `POST /v1/relay/boot` | signed envelope of the boot record (A.12) | `{1: Plus time (Unix ms) when the answer is built}`, also for a repeat of a stored record; `stale_generation` for a generation not above the highest seen under another boot id |
| `POST /v1/relay/report` | signed envelope of a report part (A.12) | `{1: highest report sequence stored for this boot, 2: [lease id]: every lease in this part that is settled when Plus answers, on every part, repeats included, so a lost answer is made good by the next part; the relay may stop listing them, 3: [lease id]: leases to stop forwarding (reserved; empty in v1), 4: Plus time (Unix ms) when the answer is built}` |

Plus never refuses a part for arriving early or late.

**The relay's duties** (frozen; the relay's lease counters implement
them):

1. **Boot generation.** At start, under the state directory's exclusive
   lock, the relay adds one to the boot generation stored there and writes
   it durably (write, fsync, rename) before it serves. Generations only
   grow, so Plus can order boots however their announcements arrive.
2. **Announce** each boot as soon as it starts, in the background, and
   retry the same record until Plus answers; a repeat of a stored record
   is acknowledged, never treated as a new boot. On `stale_generation`
   (for example a state directory rolled back with its VPS) the relay
   logs it and keeps retrying; an operator resolves it at Plus. Plus
   issues no block for a boot it has not
   heard from, so a relay restart during a Plus outage interrupts hosted
   service until Plus is back (disclosed, PLAN §6).
3. **Counters are cumulative** per lease, across reconnects and circuits,
   and never go down.
4. **Snapshots.** Every `MOUSSE_NET_RELAY_REPORT_MS`, and so that every
   final is in a snapshot taken within twice
   `MOUSSE_NET_RELAY_REPORT_MIN_MS` of it, the relay sends a **snapshot**:
   the counters of every lease it has accepted in this boot and that Plus
   has not yet listed as settled, all taken at one instant. (Coalescing
   finals by spacing snapshot instants at least `REPORT_MIN_MS` apart is
   relay behaviour, not part of this duty.) A snapshot is split, in
   lease-id order, into parts of at most `REPORT_ENTRIES_MAX` = 1024
   entries with consecutive report sequences; such a part always fits
   `REPORT_MAX`. A snapshot with no leases is one part with no entries
   (the heartbeat).
5. **Final** when the lease is spent, expires, is released by its target
   (`RELEASE`, §B.10), is current when its class closes with 4001, or the
   relay stops. A final entry's counters never change again; Plus keeps
   the first final it receives.
6. **Higher sequences only.** The relay accepts a `LEASE` only if its block
   sequence is above the last one it accepted for that handle and class in
   this boot (§B.10). A refused `LEASE` does not change that number, so
   the same block may be presented again. A settled lease can therefore never be presented
   again, even after the relay has forgotten it, and a lower sequence
   that was never presented never can be.
7. **Byte-exact splitting.** A spliced message is forwarded whole and
   counted byte by byte: the current lease takes the bytes it has left
   and is then spent; the pending lease becomes current and takes the
   rest. A message the current lease cannot cover, with no pending lease,
   waits while the class pauses (§B.10). No block is smaller than 65 536
   bytes, the largest WebSocket message, so one fresh block always covers
   the rest.
8. **Rate.** Per `{rate group, class}`, summed over every socket, block and
   handle in the group, the cap is the rate cap of the block most recently
   accepted for that group and class, enforced as a token bucket holding
   at most one second at that cap. A cap is never below 65 536 bytes per
   second (A.12 key 9), so one message always fits the bucket. In any
   interval of T seconds a group and class forward at most `cap × (T +
   1)` bytes.
9. **Strict `not before`.** A block or admission token is refused before
   its `not before` by the relay's Plus clock (duty 12); no tolerance is
   added. The helper presents a token or block refused only for `not
   before`, or for the relay having no Plus clock yet, again after
   `MOUSSE_NET_PLUS_NOT_BEFORE_RETRY_MS`.
10. **Admission.** Past its admission token's `not after` a registration
   is kept only while its handle holds a usable block in this boot
   (current or pending, not spent, not expired), and takes no `LEASE`;
   `ADMIT` with a valid token restores it. A `REGISTER` whose token is
   past `not after` but otherwise valid (issuer signature, this relay,
   this handle) is accepted on the same terms, so a host whose connection
   drops during a Plus outage comes back. Without a usable block the
   registration closes with 4004, and so does every circuit of that
   handle.
11. **Stopping:** on a graceful stop the relay stops forwarding, accepts no
   `LEASE`, finalizes every lease, sends a snapshot with boot state 1, and
   waits up to `MOUSSE_NET_RELAY_FINAL_REPORT_WAIT_MS`.
12. **The Plus clock.** The relay judges every block window, and every
   admission token once it has a Plus clock, on its estimate of Plus's
   clock, never its own wall clock. It notes its monotonic clock when it
   **sends** each boot or report request; from an answer whose round trip
   took at most `MOUSSE_NET_RELAY_CLOCK_RTT_MS` it sets `Plus clock =
   answer's Plus time + (monotonic now − monotonic send time)`. Plus built
   the answer after the request was sent, so this estimate is never
   behind Plus's real clock except by monotonic drift. The relay accepts
   no `LEASE` before the boot's first such answer (`LEASE_STATUS` state
   3), and a lease stops being usable when the Plus clock reaches its
   `expires at`, or once the request behind the current Plus clock was
   sent more than `BLOCK_MAX_LIFETIME` ago, whichever is first. Report `sent at` is read from the same clock. With
   a monotonic rate error of at most 1000 ppm, a relay forwards nothing
   on a lease after Plus time `e + FORWARD_MARGIN` (180 s, fixed), however
   wrong its wall clock is and whether or not Plus still hears from it.
   That is the lease's **latest forwarding time**.

Plus takes, per `{relay, boot, lease}`, the highest counters reported, or
the first final. Duplicate, late and reordered parts change nothing else.

## A.10 "Remove on all my hosts": what Plus does

Only the mailbox (A.6). The admin device deposits one sealed removal into
each offline host's inbox and asks each message's state. Plus never learns
that a message is a removal, who is removed or whether it was applied.
The design is Part D.

## A.12 Signed record formats (frozen)

Every signed record is a **signed envelope**: the canonical CBOR map `{1:
record (bytes: the canonical CBOR of the record), 2: signature (64 bytes,
raw r‖s, wire.md §4.2)}`, ECDSA P-256 with SHA-256 over the record bytes.
Each record's key 1 is its domain string; any other key or a missing one
rejects the record (wire.md §3, "Records with fixed fields"). Verifiers
reject DER signatures (`not_raw`).

**Issuer key id:** the first 8 bytes of SHA-256 of the issuer's public key
(SEC1). Relays pin a list of issuer public keys in their config, reloaded
without a restart (§B.10); two overlap during rotation, for at least
`BLOCK_MAX_LIFETIME` plus Plus's report grace, five minutes by default
(A.8).

### Admission token (issuer → endpoint → relay)

| Key | Value |
|---|---|
| 1 | `"mousse-relay-admit-v1"` |
| 2 | issuer key id (8) |
| 3 | relay id (32) |
| 4 | handle (32) |
| 5 | not before |
| 6 | not after |

### Lease block (issuer → endpoint → relay)

| Key | Value |
|---|---|
| 1 | `"mousse-lease-v1"` |
| 2 | issuer key id (8) |
| 3 | lease id (16, random) |
| 4 | relay id (32) |
| 5 | boot id (16) |
| 6 | handle (32): the target registration |
| 7 | class: 0 interactive, 1 bulk |
| 8 | block sequence (uint, from 1, per handle, class and boot) |
| 9 | rate cap (uint bytes per second, both directions together, at least 65 536; a relay refuses a lower one) |
| 10 | bytes (uint): peer ciphertext the relay may forward, both directions together |
| 11 | not before |
| 12 | expires at; at most `BLOCK_MAX_LIFETIME` = 172 800 s (fixed) after not before |
| 13 | rate group (16) |

- The block never names an account, email, endpoint id or Plus key.
- **Rate group** (an addition to PLAN §6's list): the relay applies the
  rate cap per `{rate group, class}`, summed over every socket and block
  in the group, so parallel sockets never multiply it. Plus draws a
  **fresh random rate group for each handle**, so a rate group never
  links one handle to the next (the privacy-safer choice, stated in
  `spec/privacy.md`). The cost: while a superseded handle spends the
  blocks it still holds, the endpoint's two handles on that relay have
  their own caps. That excess is bounded: only the newest handle gets new
  blocks (A.8), the old one spends at most what it already holds,
  and Plus admits a new handle for an endpoint and relay at most once a
  day by default. When blocks of one group and
  class carry different caps (only after an operator changes the
  defaults), the cap of the block most
  recently accepted applies (A.9 duty 8); vector `rate_group_cap_latest`.
- Signatures use RFC 6979 nonces; the block is fully determined by its
  reservation at Plus.

### Boot record (relay → Plus)

`{1: "mousse-relay-boot-v1", 2: relay id (32), 3: boot id (16), 4:
started at, 5: build id (text, 1–128 bytes), 6: boot generation (uint, ≥ 1,
A.9 duty 1)}`

### Report part (relay → Plus)

| Key | Value |
|---|---|
| 1 | `"mousse-relay-report-v1"` |
| 2 | relay id (32) |
| 3 | boot id (16) |
| 4 | report sequence (uint, from 1, +1 per part in this boot) |
| 5 | sent at, on the relay's Plus clock (A.9 duty 12; its wall clock before the boot's first answer) |
| 6 | boot state: 0 running, 1 stopping |
| 7 | snapshot: the report sequence of the snapshot's first part |
| 8 | part count (uint, ≥ 1); this part's number is key 4 − key 7 + 1 |
| 9 | entries: array of at most `REPORT_ENTRIES_MAX` = 1024 (fixed), in lease-id order, `{1: lease id, 2: bytes forwarded caller→target, 3: bytes forwarded target→caller, 4: state (0 active, 1 final)}` |

A snapshot is **complete** when Plus holds all its parts. A report part
is at most `REPORT_MAX` (A.2): with 1024 entries whose counters are all
2^64 − 1 it is about 42 000 bytes (vector `report_max_size`).

**Charged unit:** peer ciphertext forwarded, each direction counted once:
the payload bytes of spliced WebSocket messages (§B.8). WebSocket and
outer TLS framing are not counted.

### Endpoint records

`mousse-plus-link-v1` and `mousse-plus-token-v1` (A.3), signed by the Plus
key; `mousse-plus-handle-v1` (A.7), signed by a registration key.

## A.13 A Plus restore, as clients see it

Plus can be restored from a backup. A restore never brings back a revoked
credential, an unlinked endpoint, a removed deposit token or a deleted
directory slot, and it ends every website session and link in progress.
It can lose recent Plus-side writes; clients handle that as follows:

| Lost | Client sees | Client does |
|---|---|---|
| A directory slot write | `conflict` on the next put, or an old version on get | `dir/list`, then put again with the stored version + 1 |
| A waiting message | `not_found` on `message/state` | Deposit again; the host deduplicates by removal id |
| Inbox sequence numbers | sequences restart | Nothing: `after` is never stored (A.6) |
| A web session or link in progress | `unauthorized` or `not_found` | Sign in again; start the link again |
| An access token | `unauthorized` | Ask for a new one |

## A.15 Fixed constants

**Fixed on purpose** (the engine relies on them): `REQUEST_MAX` 16 384,
`REPORT_MAX` 65 536, `REPORT_ENTRIES_MAX` 1024, `DIR_ENTRY_MAX` 4096,
`MAIL_ENVELOPE_MAX` 8192, `DEPOSIT_TOKENS_MAX` 256, `BLOCK_MAX_LIFETIME`
172 800 s, `FORWARD_MARGIN` 180 s, the one-second rate burst, the 65 536
rate-cap floor, one funded relay per endpoint, the domain strings, the id
widths and the error codes.

Plus's own limits are named `MOUSSE_PLUS_*` defaults in the Plus plan.

---

# Decisions

The choices behind Parts A to D, in one place. Plus's own decisions are in
the Plus plan.

1. **Plus can never add trust or read traffic.** It holds ciphertext only
   for the directory and mailbox, and signs only relay leases and relay
   admission tokens. Nothing Plus signs or serves is accepted by an
   endpoint as a grant, a pin, a manifest or a removal (§A.1).
2. **The helper is Plus's only client among the user's devices.** The app
   reaches Plus through the helper's app channel, and opens the Plus
   website in a browser. Each endpoint links with its own **Plus key**,
   never its identity key. Custom labels stay in the app (§A.3).
3. **Engine API is canonical CBOR over HTTPS** at `/v1/*`, with wire.md
   §3's encoding. Signed records reuse the wire rules: a domain string at
   key 1, raw P-256 signatures (§A.2, §A.12).
4. **Shared open code:** `mousse-plus-proto` (Part A's records and
   requests, with vectors) and the relay's lease counters (no I/O), in
   the open engine repo, used by the relay, the helper, the Plus double
   and Plus.
5. **Relay admission** (Part C): registration by proof of a registration
   key bound to the live outer connection; per-pairing caller keys in an
   allow-set pushed by the target; one answer, at one constant deadline,
   for unlisted, unknown, offline and unfunded; joins by hash pre-image
   under a pre-accept budget; one accept leg per circuit, signed by the
   registration key. Self-hosted relays admit targets from an operator
   list; hosted relays by a short-lived Plus admission token, and forward
   only against leases.
6. **"Remove on all my hosts" is an engine feature that uses the mailbox
   as a dumb pipe** (Part D). It names the recipient's grant id and needs
   the same stored owner on both grants.
7. **Startup stays fast.** No helper or relay start waits for the
   network. Plus calls and relay registration run in the background after
   ready (§B.14).
8. **No hard-coded limits.** Every timeout, cap, size, count, rate and
   retry delay is a named default: `MOUSSE_NET_*` for the helper and
   `MOUSSE_NET_RELAY_*` for the relay. Peer-bound and security-bound ones
   only tighten. Sizes the other side relies on are fixed protocol
   constants (§A.15, Part H).
9. **Tests:** no real accounts, sign-ins, email, payment calls or cloud
   storage, ever; fakes on loopback, with egress guards as in 1b §14. The
   Windows PC listens only on loopback; cross-machine cells run the relay
   and the Plus double on the Mac, and the PC dials out (Part G).

---

# Part B: The relay (Phase 3, with Phase 4's hosted mode)

## B.1 Shape

`mousse-relay` is one binary in the open engine repo. It joins two
**outgoing** connections, one from a caller and one from the target, and
forwards bytes between them. It never terminates the peer session: the
peer TLS (`mousse/1`, wire.md §5) runs end to end inside, pinned to each
side's identity.

- **Modes:** `self` (Phase 3: an operator's list of authorized targets, no
  leases) and `hosted` (Phase 4: Plus admission tokens and leases). One
  mode per process.
- **Core logic** (registration, allow-sets, calls, joins, budgets) is a
  no-I/O state machine in `mousse-net-core::relay`; lease counting comes
  from the shared lease counters (Decision 4). `mousse-sim` replays any
  run.
- **State directory:** identity key, report key and boot generation
  (hosted), the authorized target list and enrollment codes (self),
  config, and an **exclusive lock**, so one process per relay identity. No user data, no payload, no
  IP logs, no allow-sets (memory only).

## B.2 The outer connection

- **WSS on TCP** (default port 443). TLS 1.3 only, ALPN `http/1.1`, path
  `/mousse-relay/1`, subprotocol `mousse-relay.1`, binary messages only,
  no compression, at most 65 536 bytes per message. Everything is TCP, so
  UDP being blocked changes nothing.
- **Relay identity is its TLS key.** The certificate is self-signed on the
  relay's P-256 identity key. Native clients **pin** the relay id (A.7);
  the chain and name are ignored. Native clients require the hybrid
  post-quantum key exchange, as wire.md §5.4 does for the peer session. A
  wrong relay key fails before any relay message.
- **Binding:** both sides derive the outer exporter
  `EXPORTER-mousse-relay-v1` (32 bytes, empty context). Every proof signs
  it.
- **Close codes** (WebSocket close, sent by the relay): 4000 `removed`,
  4001 `lease_exhausted`, 4002 `idle`, 4003 `relay_stopping`, 4004
  `admission_expired`, 4005 `replaced`, 4006 `limit`. The helper maps each
  to a one-line reason.

## B.3 Relay messages

Before a connection is spliced, each WebSocket message is one canonical
CBOR map whose key 0 is the type, at most `RELAY_MESSAGE_MAX` = 16 384
bytes (fixed). Unknown types, missing or extra keys close the connection.

| Type | Name | Direction | Fields |
|---|---|---|---|
| 1 | `RELAY_HELLO` | relay → client, first | 1: version (1), 2: nonce (32, fresh per connection), 3: boot id (16), 4: mode (0 self, 1 hosted) |
| 2 | `REGISTER` | target → relay | 1: registration public key (65), 2: proof (64), 3: admission token (hosted only), 4: status threshold percent (hosted only, 10–90) |
| 3 | `ENROLL` | target → relay (self) | 1: registration public key (65), 2: proof (64), 3: enrollment code (16) |
| 4 | `REGISTERED` | relay → target | 1: handle (32), 2: successor overlap in seconds (self mode only) |
| 5 | `ALLOW_SET` | target → relay | 1: sequence, 2: caller key fingerprints (array of 32 bytes, at most `ALLOW_CALLERS_MAX` = 256), 3: invitations (array of `{1: invitation tag hash (32), 2: expires at}`, at most `ALLOW_INVITATIONS_MAX` = 8) |
| 6 | `ALLOW_SET_OK` | relay → target | 1: sequence |
| 7 | `CALL` | caller → relay | 1: handle, 2: caller public key (65), 3: proof (64), 4: class (0 interactive, 1 bulk) |
| 8 | `JOIN` | joiner → relay | 1: handle, 2: invitation tag (32) |
| 9 | `INCOMING` | relay → target | 1: circuit id (16), 2: kind (0 call, 1 join), 3: class, 4: caller key fingerprint (call only) |
| 10 | `ACCEPT` | target → relay, on a new connection | 1: handle, 2: circuit id, 3: proof (64) |
| 11 | `SPLICED` | relay → both legs | none; from here on messages are peer bytes |
| 12 | `UNREACHABLE` | relay → caller or joiner | none; then close |
| 13 | `PROMOTE` | target → relay | 1: circuit id, 2: caller key fingerprint |
| 14 | `LEASE` | target → relay (hosted) | 1: block (signed envelope, A.12) |
| 15 | `LEASE_STATUS` | relay → target (hosted) | 1: array of `{1: lease id, 2: class, 3: used, 4: bytes, 5: state (0 pending, 1 current, 2 final, 3 refused)}` |
| 16 | `REFUSED` | relay → target | 1: reason (text, from a fixed list), then close |
| 17 | `ADMIT` | target → relay (hosted) | 1: a renewed admission token for this handle |
| 18 | `SUCCESSOR` | target → relay (self) | 1: new registration public key (65), 2: proof by the new key (64), 3: proof by the current key (64) |
| 19 | `PING` / 20 `PONG` | both, registration connection | 1: 8 opaque bytes |
| 21 | `RELEASE` | target → relay (hosted) | 1: lease ids (array of 16 bytes, at most 4) |

## B.4 Registration

- Each endpoint has its own **registration key** per relay (P-256,
  software key in the endpoint's keystore). Its handle is `H` (A.7). A
  handle means nothing on another relay.
- **Proof:** a raw signature by the registration key over the canonical
  CBOR `{1: "mousse-relay-register-v1", 2: relay id, 3: handle, 4: relay
  nonce, 5: outer exporter}`. The relay derives H itself, so a target can
  only register the handle of a key it holds (Phase 3 exit).
- **Who may register:**
  - self mode: the registration key's fingerprint is in the authorized
    list (§B.9), else `REFUSED(not_authorized)`;
  - hosted mode: the admission token verifies under a pinned issuer key,
    names this relay and this handle, and is in its window, else
    `REFUSED(admission)`. `ADMIT` replaces it on the live registration.
    Past the token's `not after` the registration stays, and a dropped one
    may register again with the expired token, only while its handle
    holds a usable block in this boot (A.9 duty 10); it then takes no
    `LEASE`, and without a usable block it closes with 4004. A token
    refused only for `not before` is presented again after
    `MOUSSE_NET_PLUS_NOT_BEFORE_RETRY_MS` (A.9 duty 9).
- **One live registration per handle.** A new registration of the same
  handle replaces the old connection (4005). The relay forgets the
  allow-set with it.
- **Circuits outlive their registration connection.** A spliced circuit
  belongs to the handle: a replaced (4005) or dropped registration
  connection leaves it running, under the last allow-set it was admitted
  by and its lease. A 4004 close, and a self-mode `revoke`, close every
  circuit of that handle with the same code. So with a usable block, an
  admission deadline never cuts forwarding short, and the outage time the
  app shows is the lease time (PLAN §6).
- **After a relay restart** the relay knows no handle. Calls get
  `UNREACHABLE` until the target registers again and pushes its allow-set
  (Phase 3 exit).
- **Keepalive:** `PING` after `MOUSSE_NET_RELAY_KEEPALIVE_MS` without
  sending; closed after `MOUSSE_NET_RELAY_REGISTRATION_IDLE_MS` without
  receiving.
- **Rotation:**
  - **Self mode:** no automatic rotation; the operator is the owner, and a
    long-offline phone keeps its route. A manual rotation ("New relay
    key" in the app) sends `SUCCESSOR`: signed by the new key (the
    register proof shape with domain `mousse-relay-successor-v1`) and by
    the current, authorized key over the same record. The relay adds the
    new key to the authorized list and drops the old one after its
    `MOUSSE_NET_RELAY_SUCCESSOR_OVERLAP_SECS`, which it sends in
    `REGISTERED`; the helper keeps the old route for the smaller of that
    and `MOUSSE_NET_MANIFEST_OVERLAP_SECS`. A key the operator never
    authorized can therefore only arrive vouched for by one they did. A
    chain already holding `MOUSSE_NET_RELAY_CHAIN_KEYS_MAX` keys gets
    `REFUSED(chain_full)` and the registration stays up; the helper drops
    that rotation and refuses the next until the oldest key leaves. A
    pending rotation can be cancelled.
  - **Hosted mode:** the helper rotates every
    `MOUSSE_NET_HANDLE_ROTATE_SECS`, each new handle with its own
    admission token and its own rate group (A.12). Old and new are
    registered at once for `MOUSSE_NET_MANIFEST_OVERLAP_SECS`, with the
    same allow-set, and the manifest lists both. New blocks go only to the
    new handle (A.8, newest handle only); the old one serves its callers with the
    blocks it already holds and, once they are spent or expired, answers
    `UNREACHABLE`, after which a caller reads its directory slot (§B.12).
    At the end of the overlap the helper stops renewing the old handle's
    token and releases what is left (`RELEASE`), so the old handle stops
    being live at Plus within one token lifetime (A.7). The helper's
    startup check requires the overlap to be at most half the rotation
    period, so at most two handles per relay are ever live. A caller
    offline through the whole overlap reads its directory slot (§B.12).

## B.5 Allow-sets and caller keys

- **Caller keys are per pairing:** one P-256 key per caller and host, made
  by the caller and enrolled with the host through the authenticated peer
  session (§B.12), never through the relay.
- **The allow-set** holds caller key fingerprints (SHA-256 of the SEC1
  key) and open invitations. Each `ALLOW_SET` replaces the whole set; a
  sequence not above the last is ignored. The relay closes, at once, every
  circuit whose caller fingerprint left the set (4000). Nobody else's
  circuit is touched.
- **The target pushes** its allow-set to every relay in its manifest: at
  registration, on every pairing or removal, and when an invitation opens
  or ends.
- **Removing a device** is one allow-set push to each relay. The local
  grant removal commits first (1a §5.4's journal); the pushes follow and
  are replayed from the journal after a crash (Phase 3 exit "remove one
  phone").
- **More than 256 callers:** a pairing past the 256th gets no relay entry.
  Its row in the host's app says "Not reachable through the relay (limit
  256)"; LAN and user routes still work.

## B.6 Calling

1. The caller dials a relay route from the host's manifest that it may
   dial (§B.11), pinned to that relay id, and reads `RELAY_HELLO`.
2. It sends `CALL`. Proof: a raw signature by the caller key over `{1:
   "mousse-relay-call-v1", 2: relay id, 3: handle, 4: relay nonce, 5:
   outer exporter, 6: class}`.
3. On `CALL` the relay sets a **refusal deadline** of
   `MOUSSE_NET_RELAY_REFUSE_MS` from its arrival, before any lookup. It
   then checks, in one code path: a live registration for the handle, the
   caller fingerprint in its allow-set, the proof, the per-caller circuit
   cap, and in hosted mode a current lease of that class. If any fails,
   `UNREACHABLE` is sent exactly at the deadline. An unlisted caller, an
   unknown handle, an offline target and an unfunded class look the same
   and take the same time (Phase 3 exit). A listed caller is not told
   which; otherwise a removed device could tell it was removed.
4. Otherwise the relay sends `INCOMING` to the target and waits for the
   accept leg (§B.8) up to `MOUSSE_NET_RELAY_ACCEPT_WAIT_MS`. If none
   comes, `UNREACHABLE`.
5. On `SPLICED` the caller starts the peer TLS handshake as the TLS client,
   with the host's identity pin (wire.md §5.4). A wrong peer identity fails
   before any data (Phase 3 exit).

**Bulk on relay routes** uses its own outer connection and its own peer
session: a second `CALL` with class 1 (PLAN §4). On LAN and user routes
bulk stays a mux class on the same session.

## B.7 Joining (pre-accept)

- An invitation reachable through a relay carries an **invitation tag**:
  `tag = HKDF-SHA256(salt = invitation id, IKM = ticket secret, info =
  "mousse-relay-invite-v1", L = 32)`. The allow-set lists `SHA-256(tag)`;
  the joiner presents the tag itself. Only a holder of the ticket can
  start a join, and the relay never learns the invitation id or the
  secret.
- `JOIN` goes through the same refusal path and deadline as `CALL` when
  the tag's hash is not listed or has expired, the target is offline, or,
  in hosted mode, it has no current interactive lease.
- A joined circuit runs under the **pre-accept budget**: at most
  `MOUSSE_NET_RELAY_PREACCEPT_BYTES` each way, at most
  `MOUSSE_NET_RELAY_PREACCEPT_PER_TARGET` such circuits per handle, and no
  longer than the invitation's expiry. Over budget, the relay closes it.
  In hosted mode pre-accept bytes are charged to the target's interactive
  lease.
- When pairing enrolls the joiner and its caller key arrives (§B.12), the
  host pushes the new allow-set and sends `PROMOTE {circuit, caller
  fingerprint}`. The fingerprint must be in the set it just pushed. The
  circuit leaves the budget and becomes that caller's circuit.
- The host consumes the invitation atomically, as on every route (wire.md
  §10.8).
- **Recovery after a drop (frozen with Part C).** If the circuit drops
  after the host consumed the invitation but before it stored the
  joiner's caller key, the joiner can neither `JOIN` (the invitation is
  consumed) nor `CALL` (its key is not listed). So when the invitation is
  consumed, the host keeps its tag hash in the allow-set as a **recovery
  entry**, expiring `MOUSSE_NET_VIA_RELAY_REJOIN_SECS` later, and drops it
  as soon as the grant that invitation made has its caller key, or the
  grant goes. Until the joiner holds the host's `mousse-keys` answer it
  reaches the host by `JOIN` with the ticket's tag. On a join circuit
  that matches a recovery entry the host accepts only the identity of the
  grant whose enrollment receipt is that invitation (wire.md §7
  `enrolled_by`): a joiner whose `PAIRED` was lost gets `PAIRED` again
  (wire.md §10.8), a joiner that had it runs a normal session on its
  grant, and either then sends its caller key on `mousse-keys`, after
  which the host pushes the allow-set and sends `PROMOTE`. Any other
  identity, or a pairing attempt, gets `INVITATION_INVALID`, so recovery
  never makes a second grant. A drop before `PAIRED` needs none of this:
  the invitation is still open and its tag still listed. The relay sees
  an ordinary invitation entry, counted against `ALLOW_INVITATIONS_MAX`;
  nothing changes on the relay wire.

## B.8 Accept legs and splicing

- On `INCOMING`, the target opens a **new outer connection** and sends
  `ACCEPT`. Proof: a raw signature by the registration key over `{1:
  "mousse-relay-accept-v1", 2: relay id, 3: handle, 4: circuit id, 5:
  relay nonce of this connection, 6: this connection's outer exporter}`.
- The relay checks the proof against the handle's registered key and that
  the circuit is waiting, then sends `SPLICED` on both legs. From then on
  each WebSocket message's payload is forwarded to the other leg as is.
  Counted bytes are those payloads.
- One leg per circuit keeps the relay a plain splice with exact counting.
  E-R0 measures the extra handshake per incoming call and confirms it.
- Accept legs count against the handle's
  `MOUSSE_NET_RELAY_ACCEPT_LEGS_PER_HANDLE`, not the per-IP limit, so a
  busy host behind one address is not refused.
- A circuit ends when either leg closes, its caller leaves the allow-set
  (4000), it is idle for `MOUSSE_NET_RELAY_CIRCUIT_IDLE_MS` (4002), its
  lease runs out with no refill (4001, §B.10), its handle's registration
  closes for admission (4004, §B.4), or the relay stops (4003).
- **Egress priority:** interactive circuits are written before bulk at the
  relay's shared egress, under `MOUSSE_NET_RELAY_EGRESS_BPS`. Per circuit
  and direction at most `MOUSSE_NET_RELAY_QUEUE_BYTES` is buffered; above
  it the relay stops reading that leg, so TCP pushes back.

## B.9 Self-hosted authorization (`init`, `enroll`, `revoke`)

- `mousse-relay init --public <host:port>` makes the identity key and state
  directory, and prints the relay id and an **enrollment link**:
  `mousse-relay://<host:port>/#<base64url relay id>.<base64url code>`. The
  code is 16 random bytes, stored hashed, single use, valid
  `MOUSSE_NET_RELAY_ENROLL_SECS`.
- In the app (Settings → Reach → "Your own relay") the owner pastes the
  link. The helper dials the relay pinned to that id and sends `ENROLL`;
  the relay adds the registration key to the authorized list and treats
  the connection as registered. Pasting the link is also the owner's
  approval of that relay route (§B.11).
- `mousse-relay enroll` prints a new link for another endpoint;
  `mousse-relay list` and `mousse-relay revoke <fingerprint>` manage the
  list. A revoked target's registration closes.
- A self-hosted relay has no leases. Its local limits (§H.1) apply.

## B.10 Hosted mode (Phase 4)

- Registration needs an admission token (§B.4). A registration with no
  usable lease is kept, but every call and join to it is refused (§B.6).
- **Leases:** the target sends `LEASE` with each block. The relay checks
  the issuer signature against its pinned keys, this relay id, this boot
  id, this handle, the window on its Plus clock (A.9 duty 12),
  `BLOCK_MAX_LIFETIME`, and that the block
  sequence is above the last accepted for that handle and class in this
  boot. It holds at most a current and a pending per class and handle. A
  refused `LEASE` is answered `LEASE_STATUS` with state 3.
- **Counting** (the shared lease counters, A.9 duties 3 to 7): per lease,
  cumulative, byte-exact across message boundaries. When the current lease
  is spent it is final, the pending lease becomes current, and a snapshot
  follows within `MOUSSE_NET_RELAY_REPORT_MIN_MS`. An expired lease is
  final at once.
- **Pause:** with no pending lease, a class whose current lease cannot
  cover the next message **pauses**: the relay stops reading those legs
  for at most `MOUSSE_NET_RELAY_REFILL_WAIT_MS`. A `LEASE` in that time
  resumes it. Otherwise the current lease is final with what it forwarded
  and the class's circuits close with 4001. The other class carries on. A
  paused leg forwards nothing, the peers' keepalives included, so the
  wait plus the longest peer keepalive (15 s, wire.md §9.4) must stay below
  the shortest peer idle timeout (30 s): the default is 10 s, and it can
  only be shortened.
- **Release:** `RELEASE {lease ids}` from the target makes those leases
  final at once with their counters, so Plus finishes with them and returns the unused bytes to the account. The
  helper uses it when it moves to another relay (A.8, one funded relay) and when it
  stops using a handle.
- **Rate:** A.9 duty 8.
- **Status to the target:** `LEASE_STATUS` when the current lease crosses
  the threshold the target gave in `REGISTER` (key 4, its
  `MOUSSE_NET_PLUS_PREFETCH_PERCENT`), when a lease is final, and when a
  `LEASE` is refused. Nothing periodic.
- **Admission expiry:** A.9 duty 10.
- **Stopping:** after its stopping snapshot the relay accepts no `LEASE`
  and forwards nothing (A.9 duty 11).
- **Issuer keys:** `mousse-relay reload` (or `SIGHUP`) re-reads the pinned
  issuer keys without ending the boot.
- **Reports and boot:** A.9. Counters live in memory only; the boot
  generation is the only lease-related state on disk. Plus handles a
  relay killed before its final report on its own side; the relay's part
  is the Plus clock (A.9 duty 12).

## B.11 Manifests, the `relay` route hint and dial approval

**Manifest** (signed by the host's identity key under a new domain, built
only by a typed core constructor, `IdentityRecord::manifest`, so
`IdentitySigner` still never signs anything else):

| Key | Value |
|---|---|
| 1 | `"mousse-manifest-v1"` |
| 2 | host identity key (65) |
| 3 | sequence (uint, grows) |
| 4 | issued at |
| 5 | expires at (at most `MOUSSE_NET_MANIFEST_LIFETIME_SECS` later) |
| 6 | routes: array of at most `MANIFEST_ROUTES_MAX` = 4 of `{1: relay identity key (65), 2: endpoints (array of 1–4 `host:port` texts), 3: handle (32), 4: region (text, 0–32 bytes)}` |

- It travels inside sessions on the engine stream `mousse-manifest`
  (§B.12) and, with Plus, in each pairing's directory slot. Callers keep
  the highest sequence they have seen from the pinned host, and refuse any
  manifest not signed by that pin, including one served by Plus.
- **Expiry** marks a manifest stale, nothing more: its routes are still
  tried, after every other route, and the caller refreshes it from the
  session or its directory slot when it can. The peer pin protects every
  dial.
- **Rotation on a self-hosted relay** (a new relay, key or handle): the
  new route is added, the manifest is sent through the old route, and the
  old route stays for `MOUSSE_NET_MANIFEST_OVERLAP_SECS` (Phase 3 exit: an
  offline phone back within the overlap gets the new manifest through the
  old route). Hosted handle rotation is in §B.4.
- **Moving to another hosted relay** is a staged cutover with a short,
  stated interruption, because only one relay per endpoint is funded
  (A.8, one funded relay):
  1. **Stage.** The helper registers on the new relay (admission token,
     no blocks), pushes its allow-set, and adds the new route to the
     manifest. The old route keeps serving. Callers see the new
     destination and approve it while the old route still works.
  2. **Cut over** after `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS`, or at once if
     the old relay is gone. The helper sends `RELEASE` for every old
     block; the old relay reports them final; Plus finishes with them and funds
     the new relay. From `RELEASE` until the first new block (normally
     seconds), relayed calls to this host are refused and relayed circuits
     on the old relay pause and then close (4001); peer sessions
     reconnect over the new route. The app shows "Moving to a new relay".
     If the old relay is dead or silent, Plus finishes with its blocks only at their
     latest forwarding time (A.9 duty 12) or when an operator retires
     that relay boot at Plus, and the interruption lasts until then.
  3. The old route leaves the manifest at cutover. A caller that has not
     approved the new destination reaches this host by relay again once
     it does.
- **Ticket hint:** wire.md §10.2.1 defines `relay` (now reserved):
  `relay://<host>:<port>/<base64url relay id>/<base64url handle>`, at most
  255 bytes. A reader that still treats it as reserved skips it, so no
  version changes. Vectors in `ticket.json`.
- **Dial approval (1b §1.3).** Relay routes are destinations a peer
  supplies, so each one needs the owner's approval, exactly as 1b §1.3
  treats any other destination:
  - The approved **destination** is the canonical relay endpoint:
    `relay://<lower-case host>:<port>`. Approval is per peer and per
    destination. There is no blanket approval for a host, including hosts
    where this device has the owner role.
  - A relay hint in a ticket is listed in the join dialog's destinations
    like any other ("Through relay 203.0.113.5:443") and approved by
    Connect (source `ticket`).
  - A manifest route whose destination has no approval for that peer shows
    one line on the device row: "<host> can be reached through relay
    203.0.113.5:443. Allow?" (source `manifest`). Until then it is not
    dialled.
  - A **new relay**, or a relay endpoint that **moves** to another host or
    port, is a new destination and asks again. The old route keeps working
    through the overlap meanwhile.
  - A **handle or relay key change** at an approved destination needs no
    prompt: the destination is the same, the new relay key is pinned from
    the host-signed manifest, and the peer pin is checked inside.
  - Relay endpoints must classify as `public` or `tailnet` (1b §1.2);
    `lan` and `forbidden` ones are dropped. DNS names are resolved once and
    the classified address is dialled.
  - The owner's own relay (pasted enrollment link, §B.9) is approved by
    the paste (source `owner`).
  - Every relay dial is filtered like any other: the search, `last_route`
    and renewals (1b §1.3). Removing the approval in the row stops relay
    dials to that destination.
  - **Change to 1b's `approvals.json`** (E-R3): the destination form gains
    `relay://host:port`, and the source gains `manifest`. `peer.forget`
    and a removal still delete that peer's entries.
- **Launch:** one home relay per host; manifests already hold lists.

## B.12 Per-pairing material over the peer session

Engine-owned streams have labels starting `mousse-`; the helper handles
them and never passes them to the app. Wire minor 1 (Phase 3) adds
`mousse-keys` and `mousse-manifest`; minor 2 (Phase 4) adds
`mousse-grants` and `mousse-removal` (Part D). Each is opened only when
the agreed minor allows it.

- **`mousse-keys`** (caller opens it after its first live connection, and
  again whenever the host's answer is missing):
  - caller → host: `{1: caller relay public key (65)}`;
  - host → caller: `{1: pair secret (32)}`.

  The host stores the caller key fingerprint and the pair secret with the
  grant (local fields; wire.md §7 lists them). A new pairing of the same
  device replaces both. Removing the grant deletes them.
- **Derived from the pair secret** (HKDF-SHA256, salt empty):

| Info | Use |
|---|---|
| `mousse-dir-slot-v1` | directory slot id (32) |
| `mousse-dir-key-v1` | directory slot key (32), XChaCha20-Poly1305 |
| `mousse-mail-deposit-v1` | deposit token (32) |
| `mousse-mail-tag-v1` | deposit tag (first 16 bytes) |
| `mousse-mail-key-v1` | mail key (32), XChaCha20-Poly1305 |

- **`mousse-manifest`** (host opens it): the current signed manifest,
  again on every change.
- The **directory slot** holds `{1: random nonce (24), 2: AEAD(manifest
  envelope ‖ inbox id)}`, so a caller offline through a rotation finds the
  new route and the host's inbox. One slot per pairing means a removal
  deletes exactly that caller's slot and token.

## B.13 Headless daemon (minimal)

- `mousse-helper serve --headless --state <dir>`: one endpoint, no app.
  The 1b standalone CLI drives it (invite, peers, remove, routes, relay).
- **Keystore:** where no OS keystore is available, a software key in a
  `0600` file in the state directory. The threat model says so.
- **Pairing:** `invite --qr` prints the ticket as a terminal QR code for
  the phone's in-app scanner (kind 1), or `invite --link` with the code
  shown in the terminal.
- **One process per endpoint:** the state directory's exclusive lock
  (Phase 0) stops a second process with the same identity; a second
  profile's endpoint starts (Phase 3 exit).
- A systemd unit is shipped. (A Docker example waits for Phase 8.)

## B.14 Engine startup

- The helper reports ready before any relay or Plus contact. Relay
  registrations, allow-set pushes, Plus token, admission and prefetch
  start in the background after ready, in parallel, with backoff
  (`MOUSSE_NET_VIA_RELAY_RETRY_*`, `MOUSSE_NET_PLUS_RETRY_*`).
- Plus account state and the last usage figures are cached on disk and
  shown at once.
- The relay writes its boot generation (one small fsync), then binds and
  serves; its boot announce runs in the background (A.9).

## B.15 Releases, Docker, install and the template

- **Reproducible builds:** pinned toolchain, `--locked`,
  `SOURCE_DATE_EPOCH`, `--remap-path-prefix`, static musl for Linux
  relays. Two independent builds must produce the same hash.
- **Signed** with an offline minisign key: each artifact, its checksums,
  and the Docker image digest. The install script embeds the public key
  and refuses unsigned or mismatched downloads.
- **Docker:** a static, distroless relay image with a read-only root, one
  state volume, no shell, core dumps off.
- **One-command install:** `install.sh` (verify, place the binary, create a
  service user and a systemd unit with only `CAP_NET_BIND_SERVICE`, run
  `init`, print the enrollment link).
- **The template:** one plain cloud-init file for any low-cost VPS that
  takes user data, deployed and upgraded by an independent tester on their
  own VPS (PLAN Phase 3). Upgrades keep the state volume, so the relay
  identity survives. Platforms that end TLS at their own proxy cannot carry
  a pinned relay key and wait for Phase 5's profile.
- **Inspection:** `mousse-relay status --json` prints the build hash, the
  log configuration and the state directory listing. The kit compares the
  hash with a local reproducible build.

## B.16 Privacy and threat model updates

`spec/privacy.md` fills its Phase 3 and 4 headings; `spec/threat-model.md`
gains "Relays" and "Plus".

- **A relay sees:** both legs' IPs, timing and sizes; handles; caller key
  fingerprints in allow-sets; which caller fingerprint opens which circuit
  to which handle; that two handles share an IP. During a hosted handle
  rotation both handles carry the same caller fingerprints, so the relay
  can tell they are one endpoint even when the IP changes. Never content: the peer
  TLS is pinned inside. Per-pairing caller keys keep it from seeing one
  device call two hosts by key, but not by IP and timing. Allow-sets are
  memory only.
- **Hosted relays also see:** lease ids, sizes, classes and rate groups.
  Each handle has its own rate group, so nothing in a paid block links
  one handle to the next; the shared caller fingerprints, IP and
  registration timing during a rotation still do (`spec/privacy.md`).
- **Plus sees:** A.1's list. With the relay's metadata, we as operator can
  link an account to its handles, so to the IPs and timing of its relayed
  traffic.
- **Instrumentation, persistence and crash dumps** (relay): logs carry
  aggregate counters only; no IP, handle or fingerprint is ever logged;
  core dumps off (`PR_SET_DUMPABLE` 0, `ulimit -c 0` in the image); panic
  messages carry no payload; the state directory holds only §B.1's files.
  *Settled in E-R6:* the relay itself sets both at start of every command,
  in every build: the core-dump limit to 0 (soft and hard, since the image
  has no shell for `ulimit`) and `PR_SET_DUMPABLE` 0. Debug builds only
  honour `MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE=1`, which skips the second, so
  `phase3.marker` can sample the relay's memory; release builds ignore it.
  `status --json` reports both; `phase3.relay-hardening` checks them (control
  `relay-dumpable`), and `phase3.install` checks them in the release image
  and under the systemd unit.
- **Threats:** Part C's table, plus: Plus can deny service but never add
  trust; a stolen issuer key lets the thief forward relay traffic at our
  cost until rotation, never read or authorize anything.

---

# Part C: Relay admission, settled

This is the design the Phase 0 review left open ("relay-admission:
reviewed when it freezes in Phase 3", `checks/reviews/phase0-design-review.md`).
It is §B.2 to §B.10; this part states the rules the review signs off and
the vectors that prove them.

## C.1 Rules

1. **Relay identity** is the key in its TLS certificate; native clients
   pin its hash. No relay message is sent on a connection that failed the
   pin.
2. **Every proof is bound** to the relay id, the handle, a fresh relay
   nonce, the outer exporter, and a domain string of its own
   (`mousse-relay-register-v1`, `-successor-v1`, `-call-v1`,
   `-accept-v1`). None can be replayed on another connection, relay or
   purpose.
3. **A handle is derived, never claimed:** `H` comes from the relay id and
   the registration key that proved itself.
4. **Who may register** is the operator's list, extended only by a key the
   list already holds (self), or a Plus admission token for this relay and
   handle, which expires (hosted).
5. **Admission to a target** is only by the target's own live allow-set,
   pushed over its registration connection. The relay adds nothing to it.
6. **One answer** for unlisted, unknown, offline and unfunded, from one
   code path, at a constant deadline set when the request arrives. Listed
   callers are told nothing more.
7. **Joins** need the invitation tag (a pre-image only ticket holders have)
   and run under the pre-accept budget until the target promotes them to a
   listed caller. After the invitation is consumed its tag stays listed
   only as a recovery entry, which the host honours only for the grant
   that invitation made (§B.7).
8. **Accept legs** are signed by the registration key and name the
   circuit.
9. **Removal is immediate and narrow:** a new allow-set closes exactly the
   removed caller's circuits on every relay the target pushes to.
10. **Nothing survives a reboot** but the identity, the operator list and
    enrollment codes. Admission resumes only when targets re-register.
11. **The relay never decides trust.** Every circuit still runs wire.md
    step 1 (pins) and step 2 (grants) inside; a relay that admits wrongly
    reaches a host that refuses.

## C.2 Attacks and defences

| Attack | Defence | Proved by |
|---|---|---|
| Register someone else's handle | Handle derived from the proving key (rule 3) | vector `register_other_key`; Phase 3 exit |
| Add an unauthorized key on a self-hosted relay | `SUCCESSOR` needs the current authorized key's proof (rule 4) | vectors `successor_without_current_key`, `successor_unauthorized_current` |
| Replay a registration or call proof | Nonce and exporter bound (rule 2) | vectors `call_replayed_other_connection`, `register_replayed` |
| Use a proof on another relay | Relay id bound | vector `call_other_relay` |
| Learn whether a caller is listed, or a host online | One answer, one path, constant deadline (rule 6) | vector `unlisted_equals_offline`; `phase3.relay-admission` timing rule (§G) |
| Removed device keeps a circuit | Allow-set replacement closes it at once (rule 9) | vector `removed_caller_closed`; Phase 3 exit across reboot and rotation |
| Removing one device disturbs another | Per-pairing caller keys; only listed fingerprints close | vector `removal_leaves_others` |
| Fill a target with join circuits | Tag pre-image, per-circuit bytes, per-target cap, expiry (rule 7) | vectors `join_without_tag`, `preaccept_over_budget`, `preaccept_per_target` |
| Hijack a waiting circuit | Accept leg signed over the circuit id (rule 8) | vector `accept_wrong_key` |
| Present a settled or old block again | Block sequence must rise per handle, class and boot | vector `lease_sequence_replayed`; control `accept-replayed-lease` |
| Relay or a stranger reads traffic | Peer TLS pinned inside (rule 11) | `phase3.marker` with packet and memory positive controls |
| Relay connects a caller to the wrong host | The caller's peer pin fails before data | Phase 3 exit "wrong peer identity" |
| A malicious relay admits strangers | The host's step 2 refuses them (rule 11) | Phase 1b admission checks over a relay route |
| Fill a hosted relay's registration table | Admission tokens, capped per endpoint at Plus | `phase4.relay-leases` |
| Parallel sockets multiply the bulk rate | Rate per rate group and class; one funded relay per endpoint | `phase4.relay-leases`, `phase4.abuse` |
| Stolen issuer key | Bounded by rotation and reload; cannot read or authorize | threat model |

## C.3 Vectors

`spec/relay.md` (normative) and `spec/vectors/relay-admission.json`,
replayed by `mousse-net-core`'s relay state machine and by an independent
implementation from the spec alone (the Phase 0 practice). Rejection
vectors: every row of C.2 that names one, plus non-canonical messages, DER
proofs, a handle that does not match the key, an `ALLOW_SET` with a lower
sequence, a `PROMOTE` for a fingerprint not in the set, a `LEASE` for
another boot, relay or handle, an expired or over-long block, an
admission token for another handle, an `ADMIT` for another handle, a
`RELEASE` naming another handle's lease, a hosted `REGISTER` without a
status threshold, a block or token before its `not before` on the Plus
clock (and the same one accepted after it), a `LEASE` before the boot's
first Plus answer, a block past its `expires at` on the Plus clock while
the relay's wall clock is behind, a block with a rate cap below 65 536,
and a `REGISTER` with an expired token for a handle with no usable block
(the same with a usable block is accepted).

## C.4 What sign-off covers

The council signs off C.1 to C.3 and the formats of B.3, B.4 and B.7.
After sign-off they are frozen for relay protocol version 1, and the
review record gets the line: "relay-admission: frozen profile binds every
proof to the relay, handle, nonce, outer exporter and purpose; admission
comes only from the target's live allow-set; one answer at a constant
deadline for unlisted and offline; joins by pre-image under a pre-accept
budget; relay-only pairing recovery bound to the grant the consumed
invitation made; self-hosted keys added only by an authorized key."

---

# Part D: "Remove on all my hosts" (Phase 4, engine)

## D.1 What the admin device knows

On wire minor 2 the host opens `mousse-grants` to every caller whose grant
has role `owner`, and sends `{1: [{1: identity key (65), 2: grant id
(uint), 3: role, 4: name}]}` at connection start and on every change.
Grant ids are the host's local ids, never reused (wire.md §7), so a grant
id names one pairing. A grant that replaces another (a new pairing of the
same device) takes a new id; E-L4 adds that sentence to wire.md §7, which
today says only that ids are never reused. Other callers never get this
list.

The admin device's **hosts** are the peers whose `PAIRED` gave it role
`owner`. When the user removes device X, a removal is made for each host
whose last grant list named a grant for X, naming that grant id. Nothing
is queued for a host whose list did not name X: its row says "Not known on
<host>". If a later grant list from that host names X, the app asks again
("<X> is also on <host>. Remove it there?"); a removal is only ever made
for a grant id the user saw when confirming.

## D.2 The removal record

Signed by the admin device's identity key under a new domain, built only by
the typed core constructor `IdentityRecord::removal`:

| Key | Value |
|---|---|
| 1 | `"mousse-removal-v1"` |
| 2 | signer identity key (65) |
| 3 | recipient: host identity key (65) |
| 4 | removed identity key (65) |
| 5 | grant id on the recipient (uint) |
| 6 | removal id (16, random) |
| 7 | issued at |

A removal is signed once and kept, with its original `issued at`, until
its result is known; every resend carries the same bytes.

## D.3 Delivery and what the user sees

| Case | How | State shown |
|---|---|---|
| Connected | sent on `mousse-removal`; the host answers `{1: removal id, 2: result (0 applied, 1 stale, 2 refused)}` | "Removed", "Already replaced by a newer pairing" or "Refused" |
| Answer lost, or delivered by mail | the same removal is sent again on the next session; the host returns its journaled result (D.4 check 3) | as above |
| Not connected, host has an inbox | sealed with that pairing's mail key, `{1: nonce (24), 2: AEAD(removal envelope)}`, deposited with that pairing's deposit token | "Waiting (sent)" until the message is `delivered`, then "Delivered, not confirmed" until the next session returns the result |
| Deposit answered `quota` | kept and deposited again at the next mail poll interval | "Waiting for <host> to collect its mail" |
| Neither | kept on the admin device | "Waits until this device reaches <host>" |
| Older than `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` | dropped | "Couldn't remove from <host>; remove it there" |

"Delivered" is Plus's word for "the host fetched it"; only the host's
answer shows "Removed".

## D.4 What a host accepts

Under the host's admission lock (1b §6.2's fence lock), in order; a
failure is answered `refused` or `stale` and changes nothing else:

1. The signature checks, and the signer holds a live grant with role
   `owner` on this endpoint.
2. The recipient is this endpoint's identity.
3. The removal id is new. A known removal id whose record bytes hash to
   the journaled hash returns its **journaled result** and does nothing
   else, so a resend after a lost answer shows the real outcome. A known
   id with other bytes is `refused`. `issued at` is within
   `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` (plus the clock skew).
4. The removed identity holds a grant whose **grant id equals key 5**.
   Otherwise `stale`: a newer pairing of that device stays.
5. That grant's stored authorizing owner equals the **signer's grant's**
   stored authorizing owner. Otherwise `refused`: a grant another owner
   authorized (Teams) is untouched.

Then, still under the lock:

1. Journal the removal id, the record hash and the result (for every
   result from check 3 on), and for `applied` also `revoke {grant, removal
   id}` (1a §5.4); fsync. Removal ids are kept for
   `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` plus the skew, after which check 3's
   age test refuses the record anyway.
2. On `applied`, remove the grant and close its channels with
   `GRANT_REVOKED`.
3. Answer (on a session) or acknowledge the message (mailbox).

After the lock, from the journal, retried in the background until done:
push the new allow-set to every relay, delete that pairing's directory
slot, and drop its deposit tag from the inbox. A local denial still always
wins. Another profile's endpoint on the same computer has its own grants
and its own owner, so the signer holds no owner grant there and is refused
at check 1 (Phase 4 owner check "shared computer").

## D.5 Inbox polling

The host fetches its inbox in the background after ready, every
`MOUSSE_NET_PLUS_MAIL_POLL_SECS`, and after a network change, each round
from the oldest message (A.6). It acknowledges each message after acting
on it, whatever the result, and deduplicates by removal id.

---

# Part F: Slices

Each slice is one PR in the engine repo. E-slices continue 1b's numbering
(`R` for Phase 3, `L` for Phase 4); M-slices are the Mousse app. Plus's
slices (P-numbers) are in the Plus plan; engine slices depend only on the
open parts of them: `mousse-plus-proto` and its vectors (P1), the shared
lease counters (P2), and the Plus double from P6 and P8.

## F.1 Engine slices

| # | Phase | What | Prerequisite | Exit test |
|---|---|---|---|---|
| E-R0 | 3 | Spike: WSS splice throughput and latency in a VPS-sized container; self-signed relay TLS with pinning through `tokio-tungstenite`; accept-leg cost per call; per-IP and per-handle connection counts | 1b E8 (`WsPipe`) | numbers for §H.1 defaults and the accept-leg decision, recorded in this file |
| E-R1 | 3 | `spec/relay.md`, `mousse-net-core::relay` state machine, `relay-admission.json` vectors, `mousse-sim` admission seeds, an independent implementation from the spec | `main` | vectors pass in both implementations; council sign-off of Part C; control `relay-skip-allow-set` prints FAIL |
| E-R2 | 3 | `mousse-relay` self mode: listener, splice, constant refusal deadline, budgets, egress priority, close codes, local limits, `init`/`enroll`/`list`/`revoke`/`status`, `SUCCESSOR`, circuits outliving registrations, state directory and lock | E-R1, E-R0 | `phase3.relay-admission`, `phase3.relay-reboot`, `phase3.relay-limits` |
| E-R3 | 3 | Helper relay client: registration keys, `mousse-keys`, caller keys, allow-set pushes after the journaled removal, relay dial and bulk connection, accept legs, the enrollment link, relay-route approvals per destination (the `approvals.json` change of §B.11: `relay://host:port` destinations and the `manifest` source); relay-only pairing recovery (§B.7); wire minor 1; `limits.rs` skips the `MOUSSE_NET_RELAY_` prefix | E-R2, 1b | `phase3.relay-routes`; Phase 1b app checks over a relay route |
| E-R4 | 3 | Manifests through `IdentityRecord::manifest`, `mousse-manifest`, the `relay` ticket hint, address classes on manifest routes, stale-manifest dialling, manual key rotation | E-R3 | `phase3.relay-rotation` |
| E-R5 | 3 | Headless daemon (§B.13) | 1b | `phase3.headless` |
| E-R6 | 3 | Reproducible signed releases, the relay Docker image, `install.sh`, the cloud-init template | E-R2 | `phase3.reproducible`, `phase3.install` |
| E-R7 | 3 | Privacy and threat model updates, the marker test, `mousse-check relay-inspect`, `checks/phase3.toml` | E-R3 | `phase3.marker` with both positive controls |
| M15 | 3 | App: "Your own relay" (paste link), relay route labels and approval prompt, manifest status, the 256-caller note | E-R3 | component tests; real captures |
| — | 3 | **The cellular owner checks** (`phase3.vps-demo`) need a phone with the relay client, so they wait for **Phase 2**'s FFI as well | Phase 2, E-R4, E-R6 | attested |
| E-L1 | 4 | Relay hosted mode: admission tokens, `ADMIT` and the keep-while-funded rule, leases with sequences, byte-exact splitting, classes, rate groups and the bucket, pause and refill, `RELEASE`, threshold `LEASE_STATUS`, the boot generation, the Plus clock, coalesced snapshot reports, finals on stop, `reload`; a settings table for `MOUSSE_NET_RELAY_PLUS_URL` | E-R2, P1, P2, **P8's double** | `phase4.relay-leases` against the double |
| E-L2 | 4 | Helper Plus client: link (polling again after a lost answer), tokens, admission and renewal, stored request ids, prefetch, relay moves with `RELEASE`, remaining time per class, bulk pause on a failed refill, outage display; app channel `plus.*`; a settings table for `MOUSSE_NET_PLUS_URL` | E-R4, P6's double, **P8's double** | `phase4.helper-plus` against the double |
| E-L3 | 4 | Directory slots and inbox from the pair secret; slot writes on manifest change and the restore table of A.13; inbox polling; refusal of anything not signed by the pin | E-L2, P7's double | `phase4.directory` |
| E-L4 | 4 | `mousse-grants`, `IdentityRecord::removal`, confirmation per grant id, delivery and resend, host checks under the admission lock, journaled results and cleanup (Part D); wire minor 2; the wire.md §7 sentence on replacing grants | E-L3 | `phase4.remove-everywhere` against the double, including the shared computer |
| M16 | 4 | App: Plus sign-in (code typed in the browser), usage and remaining time, top-up status line, "Remove on all my hosts" with per-host states | E-L2, E-L4 | component tests; real captures |
| M17 | 4 | App: paid relay as a route; pause and resume of relayed bulk; no prompt for bulk | E-L2 | `phase4.bulk-pause` |

**Order.** After 1b, E-R0 and E-R1 (E-R1's spec may start before 1b
lands), then E-R2, E-R3 with E-R5 and E-R6 in parallel, then E-R4, E-R7
and M15. Phase 4: E-L1 and E-L2 in parallel against the double, then
E-L3, E-L4, M16 and M17.

---

# Part G: Owner checks

The kit, judges and controls are as in 1a §9 and 1b §14. Topology for
every cell:

- **Single machine:** the relay, the Plus double, and every endpoint run
  on one machine on loopback. On the Windows PC nothing
  listens off loopback.
- **Cross-machine:** the relay and Plus run on the Mac; endpoints on the
  PC dial out to them. A target registers by dialling out, so a PC host
  needs no listener. The Mac never dials the PC.
- **Linux cells** (marker, memory sample, reproducible build) run in WSL on
  loopback or in a Linux container on the Mac.
- **No real accounts:** the Plus double on loopback. The VPS demo and the
  outside-host template run are attested owner steps; agents never create
  or sign in to a VPS, cloud or Plus account.
- **Egress:** the 1b guards, with the relay's and Plus's addresses added
  to the allowed list per cell.
- **Timing rule** (same answer, same time): 1000 refused requests each
  for an unlisted caller, an unknown handle, an offline target and
  (hosted) an unfunded class, interleaved. On loopback every answer
  arrives between the deadline and the deadline + 50 ms, and the medians
  of any two groups differ by under 5 ms.
- **Abuse bounds:** over the run, bytes forwarded per lease never exceed
  its bytes; in every 10 s window the bytes forwarded per rate group and
  class are at most the group's cap × 11 s (the bucket, A.9 duty 8); no
  endpoint ever has funded blocks on two relays at once.

## G.1 `checks/phase3.toml`

| Check | Proves | Cells | Must-fail controls |
|---|---|---|---|
| `phase3.relay-admission` | Every C.2 vector; the timing rule; wrong relay key and wrong peer identity fail before data; `SUCCESSOR` needs the current key | all desktop targets (loopback) | `skip-allow-set`, `refuse-early` (answers unlisted at once), `no-pin-relay`, `successor-unchecked` |
| `phase3.relay-reboot` | Identity kept; calls refused until re-registration and allow-set push; removal survives the reboot | linux-x64, macos-arm64 | `persist-allow-set` (reloads an old set after reboot) |
| `phase3.relay-limits` | Per-IP, per-handle accept legs, per-caller circuits, queue, idle, egress and pre-accept limits; tighten-only variables refuse to loosen | linux-x64, windows-x64 | `no-preaccept-budget` |
| `phase3.relay-routes` | 1b's app cases over a relay route; bulk on its own outer connection; remove one caller and the other stays connected; a relay route is dialled only after its destination is approved, `lan` relay endpoints are dropped; relay-only pairing with the circuit dropped on each side of `PAIRED`, from both ends, recovers with one grant | pc-to-mac (relay on the Mac) | `shared-caller-key`, `close-all-on-removal`, `manifest-unapproved`, `blanket-approval` (a second relay destination from the same host is dialled without asking), `no-pairing-recovery`, `recovery-makes-grant` |
| `phase3.relay-rotation` | Manual key rotation with no prompt; a new relay, or a moved endpoint, asks once while the old route keeps working; an offline caller back within the overlap gets the new manifest; a stale manifest's routes are still tried; removal holds across rotation; forbidden manifest addresses dropped | linux-x64, pc-to-mac | `no-overlap`, `stale-manifest-dropped`, `prompt-on-key-change` |
| `phase3.headless` | A second process with the same endpoint refuses to start; another profile's endpoint starts; terminal QR pairs | linux-x64, macos-arm64 | `no-endpoint-lock` |
| `phase3.reproducible` | Two independent builds give the same hash; the signature verifies; `install.sh` refuses a tampered artifact | linux-x64 (two containers) | `unsigned-accepted` |
| `phase3.install` | Fresh container to enrollment link with `install.sh` and Docker | linux container on the Mac | `skip-verify` |
| `phase3.marker` | A packet capture of both legs and the relay's decrypted view of them (a debug relay tap), and a relay memory sample, find the marker 0 times | linux-x64 | `marker-in-splice` (packet positive control: the caller also writes the marker unencrypted inside the splice, with the debug relay's outer TLS off, so it must appear in the capture and the tap); `marker-in-relay-memory` (memory positive control: the debug relay copies the marker into its heap, so the sample must find it) |
| `phase3.vps-demo` | Fresh $5 VPS, no domain, to a call from a phone on cellular in under 5 minutes; UDP blocked; remove one phone while a second on cellular stays connected, across a relay reboot and a key rotation | manual, attested (needs Phase 2) | none (manual) |
| `phase3.outside-template` | An independent tester deploys and upgrades the cloud-init template | manual, attested | none (manual) |
| `phase3.inspect` | The kit prints the deployed hash against a local build, the log configuration and the state directory | manual, attested | none (manual) |

## G.2 `checks/phase4.toml`

| Check | Proves | Cells | Must-fail controls |
|---|---|---|---|
| `phase4.relay-leases` | Lease checks with sequences, aggregate rates and the abuse bounds, interactive before bulk; a message split byte-exactly across current and pending; pause then 4001 with the current lease final, the peer session still alive through the pause; `RELEASE`; finals on stop; past admission expiry a funded registration and its circuits carry on, a dropped one registers again with its expired token, an unfunded one closes with 4004; a block below the 65 536 rate-cap floor is refused; a block refused for `not before` is accepted when presented again | linux-x64, macos-arm64 | `per-socket-rate`, `fifo-egress`, `accept-replayed-lease`, `ignore-admission-expiry`, `close-funded-at-expiry`, `refuse-expired-reregister` |
| `phase4.relay-move-clock` | Two relays on one machine, the old one's wall clock 10 minutes behind (then ahead), cut off from Plus while it still forwards a funded caller; the byte counters of both are sampled every 100 ms: the old relay forwards nothing after the lease's latest forwarding time on Plus's clock, and no sample shows funded bytes forwarded for the endpoint on both | linux-x64, macos-arm64 | `expiry-on-relay-wall-clock`, `fund-before-forward-limit` |
| `phase4.helper-plus` | Prefetch at the threshold with a retried request id, also across a helper restart; one current and one pending; bulk pauses alone on a failed refill; a hosted relay move stages the new route, then cuts over with an interruption the app shows and the check measures; a block refused for `not before` is presented again after a second; handle rotation with the default numbers never meets `cap_reached`; remaining time shown | windows-x64, macos-arm64 | `no-prefetch`, `new-request-id-on-retry`, `fund-two-relays` |
| `phase4.directory` | Slots per pairing; a removed caller's slot and token go, and its original slot id stays unreadable; an offline caller finds a rotated route; a hostile Plus is refused: a swapped slot, a manifest signed by another key, a removal deposited by Plus itself | windows-x64, linux-x64 | `keep-removed-slot`, `unpinned-manifest`, `trust-from-plus` |
| `phase4.remove-everywhere` | Each D.3 state; a stale grant id leaves the newer pairing; a grant learned after the user acted is removed only after a second confirmation; a resend after a lost answer shows the journaled result; a non-owner signer, a wrong-owner grant and a reused removal id with other bytes are refused; a removed device cannot block delivery by filling the inbox; nine removals to one offline host all arrive; the other profile on a shared computer is untouched | pc-to-mac | `accept-any-signer`, `ignore-owner`, `ignore-grant-id`, `no-tag-quota`, `auto-send-unknown`, `resend-refused` |
| `phase4.no-account-at-relay` | The relay's memory sample, its logs and every byte it receives from targets and Plus contain no account id, email or endpoint id from the run | linux-x64 | `account-in-block` (a debug issuer writes the account id into a block) |
| `phase4.bulk-pause` | A tiny allowance runs out mid-copy; typing continues; switching to LAN finishes with no prompt and no relay charge | pc-to-mac | `pause-all-classes` |
| `phase4.abuse` | The abuse script prints bytes granted against bytes forwarded, parallel bulk sockets and a relay move included, within the abuse bounds | manual, attested | none |
| `phase4.latency` | Bulk saturating the uplink keeps typing under the threshold; with the allowance gone the relay adds under 150 ms at p95 against the idle path | manual, attested | none |
| `phase4.outage` | A Plus outage longer than the admission token lifetime, at a stated rate, with the host's registration connection dropped after its token expired, lasts the displayed time and charges only what was forwarded; stopping Plus leaves LAN, user routes and a self-hosted relay working | manual, attested | none |

Plus's own checks are in the Plus plan.

---

# Part H: New engine limits

Read once at startup as `docs/limits.md` describes. "Tighten" means an
override may only make the limit stricter. These rows join
`docs/limits.md` with the slices that add them. The `MOUSSE_NET_RELAY_`
prefix belongs to `mousse-relay`, which reads only names with it; the
helper skips that prefix instead of treating its names as unknown (E-R3),
so one environment can hold both. URLs are settings, not limits, and E-L2
adds them as a separate table (`MOUSSE_NET_PLUS_URL`).

## H.1 Relay (`MOUSSE_NET_RELAY_*`)

Defaults marked † are set from E-R0's measurements. Limits a peer can
push against are tighten-only, so their range ends at the default (which
E-R0 may lower, never raise past the range shown). Limits marked
"capacity" size the operator's own machine and may be raised.

| Variable | Default | Allowed | What it limits |
|---|---|---|---|
| `MOUSSE_NET_RELAY_MAX_CONNECTIONS` | 1024 | 1 to 65536 (capacity) | Open outer connections |
| `MOUSSE_NET_RELAY_CONNECTIONS_PER_IP` † | 256 | 1 to 256 (tighten) | Callers' and targets' control connections per IPv4 address or IPv6 /64; accept legs not counted |
| `MOUSSE_NET_RELAY_ACCEPT_LEGS_PER_HANDLE` † | 64 | 1 to 64 (tighten) | Open accept legs per handle |
| `MOUSSE_NET_RELAY_CIRCUITS_PER_CALLER` † | 8 | 2 to 8 (tighten) | Open circuits per caller fingerprint and handle |
| `MOUSSE_NET_RELAY_MAX_REGISTRATIONS` | 1024 | 1 to 65536 (capacity) | Live registrations |
| `MOUSSE_NET_RELAY_HELLO_WAIT_MS` | 5000 | 500 to 5000 (tighten) | First client message after `RELAY_HELLO` |
| `MOUSSE_NET_RELAY_UPGRADE_WAIT_MS` | 5000 | 100 to 5000 (tighten) | Whole WebSocket upgrade |
| `MOUSSE_NET_RELAY_HEADER_MAX_BYTES` | 8192 | 1024 to 8192 (tighten) | Upgrade request size |
| `MOUSSE_NET_RELAY_ACCEPT_WAIT_MS` | 10000 | 1000 to 30000 | Wait for the target's accept leg |
| `MOUSSE_NET_RELAY_REFUSE_MS` | 500 | 500 to 5000 | Constant refusal deadline from a `CALL` or `JOIN`; below `MOUSSE_NET_RELAY_ACCEPT_WAIT_MS` |
| `MOUSSE_NET_RELAY_PREACCEPT_BYTES` | 65536 | 16384 to 65536 (tighten) | Per join circuit and direction before promotion |
| `MOUSSE_NET_RELAY_PREACCEPT_PER_TARGET` | 4 | 1 to 4 (tighten) | Join circuits per handle |
| `MOUSSE_NET_RELAY_KEEPALIVE_MS` | 15000 | 1000 to 15000 (tighten) | `PING` on a quiet registration connection |
| `MOUSSE_NET_RELAY_REGISTRATION_IDLE_MS` | 45000 | 30000 to 45000 (tighten) | Registration closed after this long without receiving |
| `MOUSSE_NET_RELAY_CIRCUIT_IDLE_MS` | 60000 | 46000 to 600000 | Spliced circuit with no bytes either way; above the peer idle timeout |
| `MOUSSE_NET_RELAY_QUEUE_BYTES` † | 262144 | 16384 to 262144 (tighten) | Buffered per circuit and direction |
| `MOUSSE_NET_RELAY_EGRESS_BPS` † | 12500000 | 125000 to 12500000000 (capacity) | Shared egress ceiling |
| `MOUSSE_NET_RELAY_ENROLL_SECS` | 3600 | 60 to 3600 (tighten) | Enrollment code lifetime (single use) |
| `MOUSSE_NET_RELAY_SUCCESSOR_OVERLAP_SECS` | 604800 | 3600 to 604800 (tighten) | How long a key superseded by a `SUCCESSOR` stays authorized |
| `MOUSSE_NET_RELAY_CHAIN_KEYS_MAX` | 4 | 2 to 4 (tighten) | Keys of one `SUCCESSOR` chain on the authorized list at once; `revoke` removes the whole chain |
| `MOUSSE_NET_RELAY_STATE_POLL_MS` | 1000 | 100 to 1000 (tighten) | How often a running self-hosted relay rereads its state directory; a `SUCCESSOR` rereads it at once |
| `MOUSSE_NET_RELAY_SEND_WAIT_MS` | 20000 | 1000 to 20000 (tighten) | One write to a connection; a client that stops reading is closed with 4006 |
| `MOUSSE_NET_RELAY_CONTROL_QUEUE_MESSAGES` | 64 | 8 to 64 (tighten) | Relay messages queued toward one connection; one more closes it with 4006 |
| `MOUSSE_NET_RELAY_CLOSE_LINGER_MS` | 2000 | 100 to 2000 (tighten) | What is queued and the close frame when the relay closes a connection; a close never waits behind a blocked write |
| `MOUSSE_NET_RELAY_REFILL_WAIT_MS` | 10000 | 1000 to 10000 (tighten) | Paused class waits this long for a `LEASE` before 4001; plus the longest peer keepalive (15 s) it stays below the shortest peer idle timeout (30 s) |
| `MOUSSE_NET_RELAY_REPORT_MS` | 10000 | 1000 to 60000 | Snapshot interval (hosted); below Plus's boot silence time (120 s by default) |
| `MOUSSE_NET_RELAY_REPORT_MIN_MS` | 1000 | 100 to 5000 | Longest delay from a final to its snapshot, and the shortest gap between snapshots (hosted); below `REPORT_MS` |
| `MOUSSE_NET_RELAY_FINAL_REPORT_WAIT_MS` | 5000 | 0 to 60000 | Wait for the stopping snapshot to be stored (hosted) |
| `MOUSSE_NET_RELAY_PLUS_TIMEOUT_MS` | 10000 | 1000 to 60000 | One call to Plus (hosted) |
| `MOUSSE_NET_RELAY_CLOCK_RTT_MS` | 2000 | 100 to 10000 | Longest round trip whose Plus answer may set the Plus clock (hosted, A.9 duty 12); a longer one only ends leases earlier |

### E-R0 results

Measured 2026-11-19 with `mousse-relay` itself (release build) and its
bench client (`crates/mousse-relay/examples/relay_bench.rs`), the relay on
the Mac mini (Apple silicon, 10 cores, 16 GB) and the client on the PC
across the home LAN (ICMP 4 to 93 ms, so at least one end is on Wi-Fi),
then both on the Mac over loopback for the CPU ceiling. Pinned self-signed
relay TLS with X25519MLKEM768, WebSocket through `tokio-tungstenite` 0.30.

| Measure | LAN, PC to Mac | Loopback on the Mac |
|---|---|---|
| Dial (TCP, TLS, upgrade, `RELAY_HELLO`), p50 / p90 | 19 to 23 ms / 22 to 41 ms | 0.7 ms / 0.7 ms |
| Call setup, `CALL` to `SPLICED`, p50 / p90 | 38 ms / 62 to 131 ms | 1.5 ms / 1.5 ms |
| of which the accept leg's own dial, p50 | 22 to 24 ms | 0.7 ms |
| Round trip of 64 bytes through a splice, p50 / p99 | 15 ms / 116 ms | 0.08 ms / 0.10 ms |
| Throughput, 1 / 4 / 8 bulk circuits, ceiling lifted | 52 / 41 to 54 / 41 to 49 MB/s | 1944 / 3626 / 3715 MB/s |
| Relay CPU at that throughput | 0.28 core | 3.4 cores |
| Throughput at the default 12.5 MB/s ceiling | 13.8 / 12.8 / 13.3 MB/s | |
| Relay memory, idle / per open connection | 4.4 MB / 52 KB | |

What they settle:

- **The accept leg costs one dial per call:** about one TLS and upgrade
  round trip on the network, 0.7 ms of relay CPU. Accept legs on new
  connections stay (§B.8).
- **CPU is not the limit.** One Apple core splices about 1.1 GB/s with
  both legs' TLS; a VPS core several times slower still has a wide margin
  over the egress ceiling. `RELAY_EGRESS_BPS` stays 12 500 000 (100 Mbit/s,
  a small VPS's port and monthly quota), a capacity limit operators raise.
- **Memory is.** With the library's default 128 KiB WebSocket read and
  write buffers a connection cost about 168 KB; with a 16 KiB read buffer
  and no write buffer (now fixed in `mousse-relay`) 52 KB, at the same
  throughput. Queued bytes add at most 2 x `RELAY_QUEUE_BYTES` per spliced
  circuit. `RELAY_MAX_CONNECTIONS` drops from 4096 to **1024**: 52 MB of
  connections and at most 256 MB of queues fit a 1 GB VPS; operators
  with more memory raise it.
- **`RELAY_QUEUE_BYTES` stays 262144:** 16 and 64 KiB gave 28 to 47 MB/s on
  the LAN where 256 KiB gave 49 to 54 MB/s.
- **`RELAY_CONNECTIONS_PER_IP` stays 256** (13 MB per address at most),
  `RELAY_ACCEPT_LEGS_PER_HANDLE` stays 64 (a 65th accept leg was refused
  with `REFUSED(limit)` in the hold run, as specified) and
  `RELAY_CIRCUITS_PER_CALLER` stays 8.

The relay's other numbers come from the waits of `spec/relay.md` and need
no measurement.

## H.2 Helper (`MOUSSE_NET_*`)

| Variable | Default | Allowed | What it limits |
|---|---|---|---|
| `MOUSSE_NET_VIA_RELAY_DIAL_MS` | 10000 | 1000 to 60000 | Connect, outer TLS, upgrade, `CALL`, splice and step 1; above the refusal deadline |
| `MOUSSE_NET_VIA_RELAY_RETRY_FIRST_MS` | 1000 | 100 to 60000 | First wait before re-registering |
| `MOUSSE_NET_VIA_RELAY_RETRY_MAX_MS` | 60000 | 1000 to 600000 | Longest such wait; not below the first |
| `MOUSSE_NET_HANDLE_ROTATE_SECS` | 1209600 | 172800 to 7776000 | Handle rotation on hosted relays; at least twice the overlap |
| `MOUSSE_NET_MANIFEST_OVERLAP_SECS` | 604800 | 86400 to 2592000 | How long an old route or key stays |
| `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS` | 86400 | 0 to 604800 | How long a hosted relay move stages the new route before cutting over |
| `MOUSSE_NET_MANIFEST_LIFETIME_SECS` | 2592000 | 604800 to 7776000 | When a manifest becomes stale; above the overlap |
| `MOUSSE_NET_PLUS_TIMEOUT_MS` | 10000 | 1000 to 60000 | One Plus request |
| `MOUSSE_NET_PLUS_RETRY_FIRST_MS` | 1000 | 100 to 60000 | First wait before retrying Plus |
| `MOUSSE_NET_PLUS_RETRY_MAX_MS` | 300000 | 1000 to 3600000 | Longest such wait |
| `MOUSSE_NET_PLUS_PREFETCH_PERCENT` | 50 | 10 to 90 | Lease use that triggers the next request |
| `MOUSSE_NET_PLUS_NOT_BEFORE_RETRY_MS` | 1000 | 1000 to 10000 | Wait before presenting a block or token again that a relay refused for `not before` or for having no Plus clock yet |
| `MOUSSE_NET_VIA_RELAY_REJOIN_SECS` | 86400 | 600 to 86400 (tighten) | How long a consumed invitation's tag stays listed for relay-only pairing recovery (§B.7) |
| `MOUSSE_NET_PLUS_REFILL_DEADLINE_MS` | 5000 | 1000 to 9000 | After this without a new block, relayed bulk shows paused; below the relay's default refill wait |
| `MOUSSE_NET_PLUS_MAIL_POLL_SECS` | 300 | 30 to 86400 | Inbox poll interval |
| `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` | 2592000 | 86400 to 2592000 (tighten) | Oldest removal accepted or kept queued; how long removal ids are kept |

Fixed on purpose: `RELAY_MESSAGE_MAX` 16 384, `ALLOW_CALLERS_MAX` 256,
`ALLOW_INVITATIONS_MAX` 8, `MANIFEST_ROUTES_MAX` 4, the 65 536-byte
WebSocket message maximum, the `/mousse-relay/1` path, the `mousse-relay.1`
subprotocol, the close codes, every domain string and exporter label, and
Part A's fixed maxima.

---

# Part I: Risks

1. **Phase 3's cellular exit waits for Phase 2.** The relay client lives in
   `mousse-net-io`, which phones reach only through Phase 2's FFI.
2. **Plus and relay metadata together link accounts to traffic.** Stated
   in the privacy doc; per-pairing keys and a fresh rate group per handle
   limit it to what caller fingerprints, IP and timing already show.
3. **Interactive balance can run out.** Typing over the paid relay stops
   while LAN and user routes still work; the app shows a status line,
   never a prompt.
4. **A hosted relay move interrupts relayed calls.** With one funded relay
   per endpoint, the cutover stops relayed calls until the new relay is
   funded: seconds with `RELEASE`, but a dead old relay holds it until its
   blocks pass their latest forwarding time or an operator retires its
   boot. Self-hosted moves keep their overlap.

**Settled:** every question from the three council rounds and the final
review. The relay defaults marked † in §H.1 are set from E-R0's numbers
("E-R0 results", §H.1).
