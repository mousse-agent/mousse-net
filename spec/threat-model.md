# Threat model

Status: Phase 3 draft. Covers what Phase 0 builds (two desktop devices that
pair in person on a LAN, open channels over one TLS connection, and remove a
grant) and, under "Relays", the self-hosted relay of Phase 3. Plus, phones
and browsers come later and extend this document.

## What we protect

- **Host access.** Only devices the host owner approved may open channels
  (terminal, RPC, files) on a host.
- **Traffic.** Channel contents and metadata inside TLS.
- **Identity keys.** A device's identity key never leaves the device.
- **Pairing secrets.** The ticket secret and the pairing code.

## Who we defend against

| Attacker | Can do |
|---|---|
| **Network attacker** on the LAN or path | Read, drop, delay, replay, reorder and inject bytes; run its own devices; answer discovery. |
| **Stranger device** | Hold its own valid identity key and certificates; connect to any host it can reach. |
| **Ticket holder** | Someone who saw or was sent a ticket (QR photo, forwarded link) but is not the intended device. |
| **Fake host** | A device that pretends to be a host, for example by forwarding a link or answering on a route. |
| **Former device** | A device whose grant was removed or denied, still holding its keys. |
| **Other person on this computer** | A different OS user on the same computer: can reach the same loopback and LAN ports, run their own Mousse profile, and take a port the helper is not holding. |

Out of scope for Phase 0: a compromised host or joiner OS, malware with the
user's privileges, physical extraction from hardware keystores, denial of
service by an attacker who can block the network, and isolation between
profiles under the same OS user (see "Other people on the same computer").

## Threats and defences

### Impersonating a known device or host

- Every connection is TLS 1.3 with mutual authentication on session
  certificates. The identity key signs the session key and window; the
  session key proves possession in `CertificateVerify`.
- The pin is checked on **every** connection: reconnects, bulk sessions and
  path switches, not only first contact. A valid certificate from another
  identity is rejected (`pin_mismatch`).
- An identity signature is bound to one SPKI. Reusing it with another session
  key fails (`identity_signature_invalid`).
- Certificates live at most 24 h, are checked against their signed window
  with ±10 min skew, and live connections close at the effective deadline,
  also when the wall clock is set back (a monotonic cap). A stolen session
  key is useful only until its certificate expires.
- **Signing access is worth more than a session key.** Whoever can make the
  identity key sign, even briefly (malware running as the user, an unlocked
  keystore), can sign session records for any future window, and those
  certificates stay usable after that access ends: each lives 24 h, but
  nothing limits how far ahead its window starts. Only removing or denying
  the device's grant on each host stops them. Hardware keys raise the bar
  for copying the key, not for using it while the attacker runs on the
  device.
- **A cloned identity is one device.** A virtual machine clone, or a device
  restored from a backup that includes the identity key, holds the same key
  as the original. Hosts cannot tell the copies apart: both pass step 1 and
  both use the same grant. Removing or denying that grant removes both. A
  copy that should be its own device needs a new identity key and a new
  pairing.

### Using a host without a grant

- TLS proves only identity. Authorization is a separate step 2 from the
  host's own grant table.
- Without a grant, a connection may only present a join proof within 10 s,
  and after a valid proof may only pair. Any stream (RPC, terminal, files)
  before a grant closes the connection (`not_authorized`).
- Roles come only from the host's grant. Certificates carry no role, so a
  device cannot claim more than it was given.

### Misusing a ticket

- The ticket secret is 128 bits, single use, and expires 10 minutes after
  creation. One enrollment per invitation; consumption is atomic across all
  routes, and other joiners are dismissed.
- The join proof is an HMAC over both identities and the peer TLS session's
  exporter. It cannot be replayed on another connection or by another
  device, and does not reveal the secret.
- **In person:** a ticket holder can still reach the approval prompt. The
  owner sees the device name and is asked "Is the device next to you?". A
  warning says that sharing the QR shares that tap. This is the accepted
  risk of the in-person kind.
- **Send link:** a ticket alone is not enough. The 6-digit code reaches the
  joiner by another channel, is never sent, and is checked by CPace bound to
  the ticket hash, kind, version, both identities and the peer TLS exporter.

### Guessing the code

- Each code guess is a full online exchange; CPace gives an attacker no
  offline test.
- The host allows 3 attempts per invitation across all routes, and the joiner
  allows 3 per ticket, kept in a stored record so that reopening the link or
  restarting the app does not reset them. Both debit before any exchange
  work, so aborting or dropping the connection does not refund an attempt.
  A new TLS session is a new attempt.
- Each attempt uses a fresh code, so a failed guess says nothing about the
  next one.
- Two parties can guess. A ticket holder guesses at the real host: 3 guesses
  per invitation. A fake host behind a swapped link guesses at the code the
  user types into the joiner: 3 more guesses per link the user opens, since
  the joiner's own count is per ticket. Chance that one invitation and its
  link fall to guessing: at most 6 in 1 000 000.
- When a code the user typed exactly as shown fails, the joiner says that
  the link may have been swapped and asks for a new one by another way
  ([`wire.md`](wire.md) 10.6 rule 6), so the user does not keep feeding a
  fake host guesses with fresh links from the same channel.

### Fake host

- On first contact the joiner pins the host identity from the ticket. A
  device that does not hold that identity key fails step 1.
- A fake host that forwards traffic cannot complete the code exchange,
  because the exchange is bound to the peer TLS exporter and both
  identities.
- A fake host can use up the joiner's local attempts. It cannot spend the
  real host's attempts, because each side counts its own.
- A swapped link cannot claim "in person" to skip the code: the joiner
  accepts an in-person ticket only from the app's own scanner, reading the
  host's screen ([`wire.md`](wire.md) 10.1).
- A swapped link cannot make the joiner believe "already paired" unless the
  joiner already pinned that host before ([`wire.md`](wire.md) 10.6 rule 8).
- A fake host learns the joiner's identity key and computer name before the
  code fails ([`privacy.md`](privacy.md)).

### Other people on the same computer

Each Mousse profile on a computer is its own **endpoint**: its own identity
key, grants and denials, invitations, pins and listener.

- **A different OS user is in scope.** An endpoint's state directory (keys,
  grants, pins, invitations) and its local IPC are readable and writable only
  by its own OS user. Another user who takes the endpoint's port cannot
  present its identity, so connecting devices fail the pin (`pin_mismatch`),
  send nothing, and try their next address.
- **Profiles under the same OS user are not isolated from each other.** They
  share that user's files and processes, so one can read the other's state.
  This is out of scope, and the app says so where profiles are set up.
- A pin mismatch on a LAN address is expected when two endpoints share a
  computer, so it causes no warning and no re-pin.

### Removed or denied devices

- Removing, expiring or denying a grant closes every connection bound to it
  at once (`grant_revoked`). A local denial always wins and blocks new grants
  until lifted.

### Parsing attacks

- Every format is strict and canonical: one encoding per value, fixed
  certificate profile, bounded sizes (frames 64 KiB, control 16 KiB, CBOR
  depth 8). Parsers reject rather than repair.
- The core has no unsafe code and returns typed errors on untrusted input.
- Stream count and credit are bounded per connection.

### Clock problems

- A wrong clock and an expired certificate look the same. The app shows one
  neutral message and does not guess.
- Skew is fixed at ±10 min everywhere.

## Relays

A relay ([`relay.md`](relay.md)) carries connections between devices that
cannot reach each other directly. It is trusted for availability only:
never to read traffic, never to decide who may use a host.

| Attacker | Can do |
|---|---|
| **Relay operator** (or whoever controls its machine) | Run modified relay code: see and drop everything the relay handles, admit anyone, connect anyone to any leg, replay old messages. |
| **Stranger at the relay** | Reach the relay's port with its own keys; register, call, join and accept with them; open many connections. |
| **Removed caller** | A device whose grant the host removed, still holding its caller key. |

Defences (`docs/phase34-design.md` Part C, each proved by a vector in
`relay-admission.json` or a check in `checks/phase3.toml`):

- **Nothing is readable at the relay.** Each circuit carries the peer TLS
  session, pinned to the other device's identity key, end to end. A relay
  that connects a caller to the wrong leg fails the caller's pin before any
  data. A malicious relay that admits a stranger reaches a host that still
  runs step 1 and step 2 itself, and refuses it. (`phase3.marker`,
  Phase 1b's admission checks over a relay route.)
- **The relay is pinned.** Native clients pin the relay id, the hash of its
  TLS key, and require the hybrid key exchange; another relay key fails the
  handshake before any relay message (`no-pin-relay` control).
- **Proofs cannot be reused.** Every proof is bound to the relay id, the
  handle, a fresh relay nonce, the outer TLS exporter and its purpose, so a
  proof from one connection, relay or message cannot stand for another
  (`register_replayed`, `call_replayed_other_connection`,
  `call_other_relay`).
- **Handles are derived, never claimed.** A target can register only the
  handle of a key it holds, and only if the operator's list holds that key
  or a key on it vouched for it with `SUCCESSOR` (`register_other_key`,
  `successor_without_current_key`, `successor_unauthorized_current`).
- **Only the target admits.** A call reaches a target only if its caller key
  is in the allow-set the target pushed on its live registration; the relay
  adds nothing. A removed caller's circuits close when the next allow-set
  arrives, and no other caller's do (`removed_caller_closed`,
  `removal_leaves_others`).
- **Refusals say nothing.** An unlisted caller, an unknown handle, an
  offline target and a bad proof get the same `UNREACHABLE` from one code
  path at the same deadline, so a stranger cannot learn whether a caller is
  listed or a host is online (`unlisted_equals_offline`; the timing rule of
  `phase3.relay-admission`).
- **Joins are bounded.** A join needs the invitation tag, which only a
  ticket holder can compute, and runs under a byte budget, a per-target
  cap and the invitation's expiry until the target promotes it
  (`join_without_tag`, `preaccept_over_budget`, `preaccept_per_target`).
- **Accept legs are signed** over the circuit by the handle's registration
  key (`accept_wrong_key`).
- **A reboot forgets admission.** Registrations and allow-sets live in
  memory only; after a restart every call is refused until the target
  registers again and pushes its set (`phase3.relay-reboot`).
- **Local limits** bound connections per address, accept legs per handle,
  circuits per caller, queued bytes and egress, and are tighten-only where a
  client could push against them (`phase3.relay-limits`).

What a relay can still do:

- **Deny service.** It can drop or delay anything; devices fall back to
  their other routes.
- **See metadata.** IP addresses, timing, sizes, handles, caller
  fingerprints and who calls whom ([`privacy.md`](privacy.md), "Through a
  relay").
- **Impersonate itself with a stolen key.** Whoever copies the relay's
  identity key can run a relay clients accept, with the same powers as the
  operator above and no more. Registration keys and caller keys never leave
  the devices.

## Residual risks in Phase 0

- In-person approval relies on the owner checking that the device is next to
  them.
- An attacker on the LAN can see that two devices talk, when and how much
  (see [`privacy.md`](privacy.md)).
- An attacker who can drop traffic can stop pairing or channels; it cannot
  make them succeed wrongly.
- CPace may be **DEFERRED** in Phase 0. Until it passes review, "Send link"
  is not enabled.
- Software identity keys on desktops are protected by the OS keystore only.
- Identity keys must sign without a user-presence prompt while the device is
  unlocked ([`wire.md`](wire.md) 4.1), so that renewal works; a hardware key
  therefore protects against copying, not against use by code running as
  the user.
