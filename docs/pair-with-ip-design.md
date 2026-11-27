# Pair with IP: design

Status: **agreed** (2026-11-27). Base: engine `main` at `b33e8c1`, app
`master` at `d82b0c8f3`. Tracking issue: mousse-agent/mousse#1510.

This adds one more way to pair two desktop computers on the same network or
on the same tailnet: the host shows an address and a 12-character code, and
the joiner types both. QR codes, links, sent links with a 6-digit code and
SSH all stay as they are.

## The problem

Every pairing today starts from a **ticket** (`spec/wire.md` 10.2): about
150 bytes carrying the host's identity key, the invitation id and a 128-bit
single-use secret. The 6-digit code of a sent link is a second factor on top
of it. A person who can only read things aloud or retype them (two computers
side by side without a camera, someone helping on the phone) cannot move a
ticket, so cannot pair. There is no invitation a joiner can find and
authenticate with nothing but an address and a short secret.

### The flow

1. **Host shows.** Let a device in → Pair with IP. The owner picks the way
   (same network or Tailscale). The dialog shows the address and the code,
   with its expiry and the attempts left:
   `192.168.1.20:47100`, code `K7QM-2XPA-9RTE`. Cancel ends the invitation.
2. **Joiner types.** Use another computer → Pair with IP → address and
   code → Connect. The code field forgives case, spaces and dashes.
3. **Code accepted.** The host owner is asked to Allow the device, with its
   name, short device id and the access level, as after a QR scan. The
   joiner shows "Waiting for Allow" with its own short device id, so the
   owner can compare. Allow grants and the joiner pins the host. Decline
   grants nothing.
4. **Wrong code.** The joiner says the code didn't work and how many tries
   are left. The host keeps showing the same code.
5. **Wrong address.** Nothing there: "Can't reach that address." Another
   Mousse computer or a typo in the first four characters: "No open
   invitation there. Check the address and the first four characters." Not
   Mousse: "Can't reach Mousse at that address."
6. **Expired, used up, cancelled, host restarted:** "This code is no longer
   open. Ask for a new one."
7. **Lost connection after the code passed:** the joiner reconnects on its
   own and learns the outcome without the code (§1.6).
8. **Undo:** Remove works as for any grant.

### Rules

1. Only the address, the port and the code pass from the host's screen to
   the joiner. No ticket, QR or link.
2. A joiner that reached the wrong endpoint, or one that does not know the
   code, pins nothing and is granted nothing; that endpoint gains no grant
   and nothing that lets it test codes offline.
3. Guessing is online only, a bounded number of times, with the chance
   stated (§3).
4. The code authenticates both sides and is bound to this TLS session and
   both identity keys, as the code exchange is today (`wire.md` 10.5).
5. An invitation is used at most once, expires, and ends on cancel and on
   host restart.
6. Kinds 1 and 2, ticket version 1 and their vectors are unchanged. The app
   offers Pair with IP only when its helper lists the feature.
7. `mousse-net-core` does no I/O and builds for `wasm32-unknown-unknown`.
8. Every new limit is a named default with a `MOUSSE_NET_*` variable;
   limits that bound security are clamped (`docs/limits.md`).
9. The code and everything derived from it are zeroized and never logged.
10. A paired device that this change cuts off (§5) is shown as needing an
    update, and stays disabled until it is updated.

## Decisions

1. **A new invitation kind 3, "direct", with no ticket.** Its own core
   files, its own wire message and its own durable records. Kinds 1 and 2
   are not touched.
2. **The code is a public lookup plus a secret.** 12 characters: the first
   4 find the invitation (20 bits), the last 8 are the CPace password (40
   bits).
3. **Wire minor 4**, under the normal rule: a minor-4 endpoint speaks 3 and
   4 and no longer talks to minor-2 endpoints. Mousse tells people which
   devices that cuts off and why, before and after the update (§5).
4. **First contact has no pin**, on a connection that can do nothing but
   this pairing until the host has proven it knows the code.
5. **The host owner still taps Allow** after the code passes. The code is
   the only factor and travels by voice, the easiest channel to overhear;
   Allow is the presence check. Dropping it later is a host-only change with
   no wire change.
6. **The same code for the whole invitation.** A person who misheard one
   character fixes it; with 40 secret bits a failed guess removes one
   candidate in 2^40.

## 1. Shape

### 1.1 The code

- Alphabet: Crockford base32, `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Shown as
  three groups of four: `K7QM-2XPA-9RTE`.
- Generation (core, randomness passed in): 12 bytes, each mapped to
  `ALPHABET[b & 0x1f]`. Uniform, no redraw, replayable from vectors. The
  host redraws the whole code when its lookup equals the lookup of another
  open kind-3 invitation of this endpoint.
- Entry (core, pure): drop ASCII spaces and `-`, uppercase ASCII letters,
  read `O` as `0` and `I`, `L` as `1`. Anything else, or a length other than
  12, is `bad_code`: no dial and no attempt.
- **Lookup `L`:** characters 1 to 4, sent inside TLS. Public once used.
- **Secret `S`:** characters 5 to 12, as 8 ASCII bytes. Never sent; it is
  the CPace `PRS`. Independent of `L`.
- The alphabet, the length and the 4 + 8 split are wire format, listed in
  `docs/limits.md` "Fixed on purpose".

### 1.2 State and owners

| State | Owner | Life |
|---|---|---|
| Host invitation: invitation id `I` (16 random bytes), `L`, `S`, `expires_at`, attempts left, role, joiners and which one passed the code | `HostPairing` (`crates/mousse-net-core/src/pairing/host.rs`), indexed by `I` and by `L` | Memory only. Ends on enrollment, decline, cancel, expiry, exhaustion or restart. |
| Code type (`DirectCode`, `DirectSecret`: zeroized, `Debug` hidden, constant-time compare) | `pairing/direct_code.rs` (new) | |
| Joiner state machine | `DirectJoinerPairing`, `pairing/direct_joiner.rs` (new); no I/O | One flow |
| **Joiner attempt ledger**, keyed by the typed `L` | core decides, io stores (`FlowRecords`, compare-and-swap, as `wire.md` 10.7) | Per profile; an entry is dropped 24 h after its first debit |
| **Joiner pending record:** `L`, host key, `I`, attempt id, address | same | From a verified host confirmation until the outcome is settled |
| Grant with receipt `I` | `GrantTable` / `GrantStore`, unchanged | Durable |
| Pin, the typed address as an owner route, tailnet approval, completion record | helper `peer.rs` and `app/pairing.rs`, after `PAIRED` only | Durable |
| Dialogs and device row | app `EnginePairing` (`src/mms/netEngine/pairing.ts`), `LetDeviceInDialog.tsx`, `UseComputerDialog.tsx` | |

The ledger is keyed by what the person typed, not by the key the far end
shows. An endpoint that shows a new identity key on every connection still
draws from the same count.

### 1.3 Step 1 without a pin

Every existing dial keeps `tls::connect` and its `PinnedHostVerifier`
(`crates/mousse-net-io/src/tls.rs:203`). Pair with IP's first contact uses a
separate `tls::connect_unpinned` with its own `UnpinnedPairVerifier`:

- the checks of `wire.md` 5.4 except check 9 (the host side already verifies
  with no pin, `tls.rs:494`), with the full TLS policy;
- it refuses a certificate whose identity is this endpoint's own key, or a
  key this profile denied, **inside** `verify_server_cert`, before the
  client certificate goes out;
- the identity it saw is a candidate, trusted only after the host's CPace
  confirmation verifies.

The connection starts in a new caller gate state, **pairing only**: it
accepts `HELLO`, `AUTHORIZED`, `CODE_EXCHANGE`, `CODE_ABORT`, `PAIRED` and
`GOAWAY`, refuses every stream, and becomes live only on `PAIRED` after a
verified host confirmation. Today's `CallerGate` can pass through `Live` on a
second `AUTHORIZED {live}` before the pairing layer closes
(`crates/mousse-net-core/src/authz.rs:425-437`); the new state removes that
window by structure. Recovery (§1.6) and every other dial are pinned.

### 1.4 Wire flow

1. **Dial.** The joiner parses `<IPv4>:<port>` or `[<IPv6>]:<port>` with the
   route grammar (`pairing/route.rs`); no DNS in this version. It approves
   exactly that destination and dials it.
2. **TLS** with `connect_unpinned` (§1.3). A handshake that is not Mousse
   is "Can't reach Mousse at that address".
3. **`HELLO`** both ways. If `agreed < 4` the joiner closes with
   `UNSUPPORTED_VERSION` and reports `needs_update` (that computer runs an
   older Mousse).
4. **`JOIN_DIRECT {1: L, 2: name, 3?: receipt}`**, joiner to host, right
   after `HELLO`. The name is the computer name only, as for a sent link
   (`wire.md` 10.3). `receipt` is `I`, only when recovering (§1.6). The
   host's step 2 runs as for `JOIN_PROOF`. Its answer is the outcome; an
   `AUTHORIZED {live}` notice from step 2 is not:
   - an open kind-3 invitation with this `L`: `AUTHORIZED {1: join_only,
     2: I}`;
   - no match: the host holds the connection for `DIRECT_MISS_HOLD_MS`
     (1 s), keeping its pre-authorization place, then closes with
     `INVITATION_INVALID`. A device that already holds a grant gets the
     same close, so a typo reads as a typo, never as "already paired".
5. **Attempt.** The joiner debits its ledger entry for `L` (durable) and
   sends `CODE_EXCHANGE {A, msg_a}` with a fresh attempt id `A`. The host
   closes with `ATTEMPTS_EXHAUSTED` when none are left; otherwise it debits,
   emits the code event (same code, fewer attempts) and answers
   `CODE_EXCHANGE {A, msg_b}` (its share and `Tb`).
6. **Wrong code.** `Tb` fails: the joiner sends `CODE_ABORT {A,
   PAIRING_FAILED}` and closes. **One attempt per connection:** the next try
   is a new Connect, so the person can fix the address as well. The host's
   invitation stays open while attempts are left.
7. **Code passed.** `Tb` verifies: the host key and `I` are now
   authenticated. The joiner writes its pending record (durable), then sends
   `CODE_EXCHANGE {A, msg_c}`.
8. **Allow.** The host verifies `Ta`, marks this joiner identity as having
   passed the code and asks the owner (name, short device id, access level).
   - **Allow** enrolls as `wire.md` 10.8 with receipt `I`, then sends
     `PAIRED {host name, role}` if the connection is still up. The
     enrollment does not need the connection: the identity proved the code
     with `Ta`, so a short drop while the owner walks to the screen does not
     lose the pairing.
   - **Decline** closes with `PAIRING_DECLINED` and ends the invitation.
   - While a joiner that passed the code waits for Allow, the invitation does
     not end for lack of attempts. Today `end_if_exhausted` would end it when
     another connection closes (`host.rs:793-800`); kind 3 counts a passed,
     undecided attempt as running.
9. **Joiner finishes.** On `PAIRED` it pins the host key, stores the typed
   address as an owner route (and the tailnet approval when it is one),
   writes its completion record and clears the pending record.

### 1.5 Binding

For kind 3, with `H` = SHA-256 and canonical CBOR (`wire.md` 3):

```
D   = H(CBOR {1: "mousse-direct-invite-v1", 2: L (text, 4), 3: I (16 bytes)})
CI  = CBOR {1: "mousse-direct-pair-v1",
            2: D,
            3: 3,                                  (kind)
            4: 1,                                  (direct ceremony version)
            5: [[1, joiner identity key], [2, host identity key]],
            6: pair exporter (EXPORTER-mousse-pair-v1)}
sid = as wire.md 10.5 (attempt id, pair exporter)
PRS = S, 8 ASCII bytes          (len_zpad = 128 − 1 − 9 − 18 = 100)
```

CPace profile 1 is unchanged: empty AD, joiner initiator, host responder, both
confirmations, `ISK` unused. `D` holds only public values; nothing on the
wire before `msg_b` depends on `S`. A vector holds two codes with the same
lookup and different secrets and checks that every byte before `msg_b` is
the same.

### 1.6 Recovery after a lost connection

A joiner with a pending record reconnects **pinned** to the host key it
verified, sends `HELLO`, then `JOIN_DIRECT {L, name, receipt: I}`. No code is
needed. The host answers:

- a grant for this identity with receipt `I`: `PAIRED {host name, role}`
  (also after a host restart);
- this identity passed the code and still waits for Allow: `AUTHORIZED
  {join_only, I}`, and the waiting request moves to this connection;
- declined, cancelled, expired, or consumed by another device: a close with
  `PAIRING_DECLINED`, `CANCELLED` or `INVITATION_INVALID`.

The joiner clears the pending record on `PAIRED` (once the pin is stored) and
on every terminal close. Today `PAIRING_DECLINED` leaves the mark
(`crates/mousse-net-core/src/pairing/joiner.rs:787-789`) because kinds 1 and
2 never decline after it; kind 3 does. A recovery that gets no answer
within 10 s leaves the record, and the app offers to resume.

## 2. Spec changes

- **`wire.md` §2.** Minor 4 adds `JOIN_DIRECT`, `AUTHORIZED` key 2 and
  kind 3. "Ticket version fixes the pairing algorithms" gets a sentence for
  ticketless kinds: kind 3's algorithms are fixed by minor 4 and the
  ceremony version in its `CI`. "Security requirements never weaken": a dial
  without a pin is allowed only on a pairing-only connection the person
  started with Pair with IP (§1.3); every other dial, including recovery,
  is pinned.
- **`wire.md` 5.4.** A third pin case: Pair with IP first contact.
- **`wire.md` 8, 8.1, 8.2.** `JOIN_DIRECT` follows `JOIN_PROOF`'s host
  gate rows and is caller-only; the pairing-only caller state and its rows.
- **`wire.md` 10.1.** Row: `Direct | 3 | Lookup, code exchange with the
  12-character code, then the host owner approves.` Kind 3 never appears in
  a ticket; a ticket with kind 3 stays `unknown_kind` (`ticket.json`
  `kind_3` unchanged).
- **`wire.md` 10.9 (new), "Direct flow":** §1 of this document: code
  format and draws, lookup, the flow, one attempt per connection, approval
  after the exchange, recovery, limits, the joiner's records
  (`{1: "mousse-direct-joiner-v1", 2: L, 3: attempts left, 4: first debit
  time}` and `{1: "mousse-direct-pending-v1", 2: L, 3: host key, 4: I, 5:
  attempt id, 6: address}`).
- **`wire.md` 11.** Type 7 `JOIN_DIRECT {0: 7, 1: text (4), 2: text (1 to
  128 bytes), 3?: bytes (16)}`; `AUTHORIZED` key 2, bytes (16), only with
  `join_only` on `agreed ≥ 4` in answer to `JOIN_DIRECT`. **§12:** no new
  codes.
- **`cpace.md` §4.** The `PRS` rule is per kind: 6 ASCII digits for kind 2,
  8 code characters for kind 3. One more full run in
  `cpace-ristretto255-sha512-mousse.json` with an 8-byte `PRS`.
- **`threat-model.md`.** A section "Pairing by typed address" with §3 below;
  "Guessing the code" and "Fake host" gain the kind-3 numbers.
- **`privacy.md`.** A Pair with IP joiner shows its identity key, computer
  name and the lookup to whatever Mousse endpoint answers at the typed
  address.
- **Vectors.** New `direct-code.json` (draws to code, entry rules,
  rejections, `D`, `CI`). `control.json`, `hello.json`, `join-proof.json`
  (kind-3 binding), `pairing-attempts.json` and `pairing-e2e.json` gain
  kind-3 cases: success with Allow, wrong secret, wrong lookup (no debit),
  decline, exhausted, lost `PAIRED`, drop while waiting for Allow, a far end
  that changes keys between tries, own device, and a minor-3 host.
  `interop/second-impl-ts` replays them. Existing cases are unchanged.

### Limits

| Variable | Default | Allowed |
|---|---|---|
| `MOUSSE_NET_DIRECT_INVITE_LIFETIME_SECS` | 600 | 60 to 600 |
| `MOUSSE_NET_DIRECT_HOST_ATTEMPTS` | 5 | 1 to 5 |
| `MOUSSE_NET_DIRECT_JOINER_ATTEMPTS` | 5 | 1 to 5 |
| `MOUSSE_NET_DIRECT_JOINER_LEDGER_SECS` | 86400 | 86400 to 2592000 |
| `MOUSSE_NET_DIRECT_MAX_OPEN` | 4 | 1 to 8 |
| `MOUSSE_NET_DIRECT_MISS_HOLD_MS` | 1000 | 1000 to 5000 |

All are clamped toward safety: fewer attempts, shorter lives, longer holds.

## 3. Security

- **Guessing at the real host:** at most 5 / 2^40 per invitation.
- **A fake endpoint at the typed address** gets one guess per Connect (it
  must send `Tb` before it sees anything that depends on the code), at most
  5 per typed lookup in 24 h, whatever keys it shows.
- **Together:** at most 10 / 2^40 ≈ 9.1 × 10^-12 per invitation, about 1 in
  110 billion. A sent link today is 6 in 1 000 000 (`threat-model.md`).
- **Offline:** CPace gives no offline test from a failed or a successful
  transcript; `L`, `I` and `D` do not depend on `S`.
- **In the middle:** a TLS-terminating attacker has a different exporter
  and different identity keys on each side, so the confirmations cannot be
  relayed. It can block pairing, as today.
- **Burning attempts:** an attacker must first hit a 20-bit lookup. Each
  miss holds a pre-authorization place for 1 s, so the 48 places
  (`MOUSSE_NET_PREAUTH_TCP`) allow at most 48 tries a second for the whole
  endpoint, 8 per source address: at most 28 800 in 10 minutes, a 2.7 %
  chance of hitting one open invitation's lookup. A hit can use up that
  invitation's attempts; the owner makes a new one with a new lookup. Other
  invitations and grants are untouched. Filling the 48 places blocks
  pairing more cheaply, and that exists today. No per-source block is kept
  after the hold, so a neighbour on the same IPv6 /64 cannot lock an
  honest joiner out.
- **Someone overhears the whole code:** they can reach the Allow prompt.
  The owner sees a name and a short device id they can compare with the
  joiner's screen. Decline ends the invitation; the owner makes a new one.

## 4. Helper and app

### Helper protocol (1.2 additions, feature `pair-with-ip`)

- `invite.create {kind: "direct", way: "lan" | "tailnet", route?, role?}` →
  `{invitation, kind, address, addresses, code, attempts_left, expires_at,
  ways}`; no `uri`. `address` is the first candidate of the way;
  `addresses` lists the others. Physical interfaces come before virtual
  adapters (WSL, Hyper-V, Docker, VPN), so the first one shown is the one
  most likely to work. Other ways and unknown fields are `bad_request`.
- Reused: `invite.code` (attempts left), `approval` (now with the short
  device id), `approval.answer`, `invite.cancel`, `enrolled`,
  `invite.ended`.
- `join.direct {address, code}` → `join.progress {step: connecting |
  checking_code | awaiting_approval, short_id}`, then the join reply or an
  error: `bad_address`, `bad_code`, `unreachable`, `not_mousse`,
  `needs_update`, `invitation_invalid`, `pairing_failed {attempts_left}`,
  `attempts_exhausted`, `declined`, `cancelled`, `paused`.
- `join.direct.cancel`; `join.direct.resume` (from the pending record, no
  code).
- The CLI reads the code from a prompt, never from an argument, so it does
  not land in shell history.

### App

Both dialogs already have tabs (mousse-agent/mousse#2039). Behind the helper
feature, as `invite-way` and `managed-tunnel` gate today:

- **Let a device in → Pair with IP:** the way (same network or Tailscale),
  the address with "Other addresses", the code in groups, "Expires in m:ss
  · N tries left", Cancel; then the existing Allow prompt with the short
  device id and the access level.
- **Use another computer → Pair with IP:** Address, Code, Connect, the
  messages of "The flow", and "Waiting for Allow on <host>" with this
  computer's short device id. Next to it, Pair with SSH.

The code is shown and typed in ordinary fields, as the 6-digit code is
today (`SendLinkParts.tsx`); it is cleared from the dialog state when the
dialog closes and never logged.

## 5. Devices left behind by minor 4

A minor-4 endpoint speaks minors 3 and 4. An endpoint built before minor 3
(engine commit `ae9691c`, 2026-11-21) speaks only 1 and 2, so it can no
longer connect to an updated one, in either direction. Mousse says so
plainly and keeps such a device disabled until it is updated.

**Engine.** Both sides read the peer's `HELLO` before closing with
`UNSUPPORTED_VERSION`, so the helper knows the peer's newest minor. It
reports it to the app:

- on a dial: the error `unsupported_version {peer_minor, side}` with
  `side` `peer_older` or `peer_newer`;
- on an incoming connection it refused: a `peer.incompatible {identity,
  peer_minor, side}` event, at most once an hour per identity.

**Device row.** A paired device last refused for its version shows
**Needs update** in Settings → Devices and is disabled: no connecting, no
threads and no remote actions. Remove and the update actions stay. The row
says which computer has to update and how, using the existing update ways
(`computerUpdateWay`): over SSH when this computer installed it (that path
does not need the engine connection), otherwise "Update Mousse on <name> to
use it from here." For `peer_newer`: "<name> runs a newer Mousse. Update
this computer to use it." The row clears on the first connection that
negotiates a version.

**Notice.** The first time a device is found cut off, one notice: "<name>
needs a Mousse update. It stays disabled here until it's updated."

**Before the update.** The release that moves to minor 4 carries, in its
update metadata, the oldest app version its peers must run. The update
prompt of the release before it reads that field and lists paired computers
last seen on an older version: "After this update, <name> can't connect
until it's updated too", with "Update <name> first" where an update way
exists. So the reader ships one release before the minor bump (slice 0).

Endpoints already on minor 2 cannot be changed; what they show is what they
show today. Everything above runs on the updated side, which is the side the
person is looking at.

## 6. Easy, hard, undo

- **Easy:** kind 3 lives in its own files and messages; kinds 1 and 2 and
  their vectors do not move. A random `I` keeps receipts unique. The Allow
  step can be dropped later without a wire change. A public port forward,
  a DNS name or an mDNS pick needs only the helper's address parsing to
  widen: nothing in core or on the wire names the address.
- **Hard:** the dial without a pin, kept to one entry point and one gate
  state. The minor-2 cut-off and its messages (§5). A typo in the first
  group reads as "no open invitation", on purpose: anything else would be an
  oracle for open invitations.
- **Undo:** removing `pair-with-ip` from the helper's features hides it;
  grants it made are ordinary grants and recovery keeps working. Once
  shipped, message type 7, `AUTHORIZED` key 2, the domain strings, the
  record formats and the code format are permanent; changing them means a
  kind 4.

### Facts this rests on, and how each is checked

1. A caller verifier with no pin completes the handshake and exports the
   keying material: a `tls.rs` unit test.
2. The own-key refusal inside `verify_server_cert` stops the client
   certificate from going out: a self-dial test in `mousse-net-io`.
3. CPace takes an 8-byte `PRS`: `python -I spec/vectors/cpace-mousse-vectors.py`
   with the added run, and `cargo test -p mousse-net-core cpace`.
4. The miss hold keeps the pre-authorization place
   (`crates/mousse-net-io/src/preauth.rs`): a host test that counts places
   during a miss.
5. Which app releases bundle a minor-2 helper, for §5's metadata: map engine
   commit `ae9691c` to the first app release that bundled it.
6. The helper sees the peer's minor before an `UNSUPPORTED_VERSION` close
   on both sides: `cargo test -p mousse-helper` with
   `MOUSSE_NET_TEST_HELLO_MINOR`.

## 7. Slices

The thin slice is phases 1 and 2: two helpers on loopback pair from the CLI
(`mousse-helper invite --direct` prints address and code; `mousse-helper
join-direct <address>` asks for the code), wrong code once, Allow, open a
stream, Remove.

| Phase | What | Check |
|---|---|---|
| 0 | App and helper: version-gap reporting, Needs update rows, the notice, the pre-update reader (§5). Ships before minor 4. | `cargo test -p mousse-helper` (minor mismatch cases); `node scripts/verify.mjs tests/renderer/engineDevicesSection.test.ts` |
| 1 | Spec, vectors, core: code, kind 3, `JOIN_DIRECT`, binding, ledger, pending record, pairing-only gate, minor 4; second implementation | `cargo test -p mousse-net-core && cargo check -p mousse-net-core --target wasm32-unknown-unknown`; `npm test` in `interop/second-impl-ts` |
| 2 | io and helper: `connect_unpinned`, miss hold, host and caller drivers, records, operations, CLI, sim drills, must-fail controls (`direct-unpinned-dial`, `direct-skip-allow`, `direct-ledger-by-key`, `direct-proof-depends-on-secret`) | `cargo test -p mousse-helper --test app_pair_ip`; `cargo run -p mousse-sim -- run pairing-direct`; `mousse-check` must-fail |
| 3 | App: Pair with IP tabs in both dialogs | `node scripts/verify.mjs tests/netEngine/pairing.test.ts tests/renderer/engineDevicesSection.test.ts` |

Not checked by these commands: two real computers on one LAN and on
Tailscale, address ranking with virtual adapters on Windows, and the §5
messages against a real minor-2 build. Each is listed as INCOMPLETE until
run by hand.

## 8. How this was decided

Three proposals were written independently and judged blind by a council of
three against a rubric written beforehand. Each judge chose a different
proposal, so the choice went to the owner, who chose C and added rule 10
(§5).

| Proposal | Shape | Chosen by |
|---|---|---|
| A | Reuse `JOIN_PROOF` with an invitation id and proof key derived from the host key and the lookup; minor stays 3 | Judge 1 |
| B | Five new messages; minor 4 with an exception that keeps minor 2; native secret-entry fields | Judge 2 |
| C | One new message `JOIN_DIRECT`, random invitation id, own modules; minor 4 under the normal rule | Judge 3, the owner |

Marks (met / partly / not met), judges 1, 2, 3:

| Criterion | A | B | C |
|---|---|---|---|
| 1. One owner per piece of state | M M M | P M P | M M M |
| 2. Rules kept by structure | P P P | M M P | M P P |
| 3. Next two features fit | M P M | P P N | P P M |
| 4. Parts replaceable alone | P P P | M P P | M P M |
| 5. No unremoved compatibility layer | M P M | P M N | M M M |
| 6. Guessing bounded and stated | M P P | M M M | P P P |
| 7. Attempt-burning survivable | M P P | M P P | P P M |
| 8. Old unchanged, new implementable | M P M | P P N | N P P |

**Rejected, and why.** A: its invitation id has only 20 bits behind it, so
receipts are not unique and a re-pair can be told "paired" for an old grant;
its join proof proves nothing, which the spec would have to carve out. B:
the most work, a lasting exception to the version rule, a host check on the
local socket address that breaks tunnels and relays, and native entry fields
on three systems.

**Taken from the others.** From B: the joiner's count keyed by the typed
lookup (all three judges found that A and C let a far end that changes keys
reset the count), the pairing-only caller gate, stale Allow prompts handled,
recovery serialized with Allow. From A: clearing the pending record on
decline, the entry rules, the "same bytes before `msg_b`" vector, the copy
that names the first four characters. From the judges: the passed attempt
that `end_if_exhausted` would end, enrollment that survives a drop while
waiting for Allow, the joiner's short device id, address ranking.
**Changed from C:** its per-source miss limit is replaced by the 1 s hold,
because a block per IPv6 /64 lets any neighbour lock out an honest joiner;
the name stays in `JOIN_DIRECT`, before the code, as a sent link does today.

**Worth revisiting** if minor-2 devices turn out to be common in the field
(then a one-release overlap as in B), if lookup scanning is seen in
practice, if Allow is dropped, or when discovery or a tunnel route is added.
