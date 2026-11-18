# Threat model, Phase 0

Status: Phase 0 draft. Covers what Phase 0 builds: two desktop devices that
pair in person on a LAN, open channels over one TLS connection, and remove a
grant. Relays, Plus, phones and browsers come later and extend this document.

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

Out of scope for Phase 0: a compromised host or joiner OS, malware with the
user's privileges, physical extraction from hardware keystores, and denial of
service by an attacker who can block the network.

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
  with ±10 min skew, and live connections close at the effective deadline.
  A stolen session key is useful only until its certificate expires.

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
  allows 3 per code-entry flow. Both debit before any exchange work, so
  aborting or dropping the connection does not refund an attempt. A new TLS
  session is a new attempt.
- Chance of one invitation falling to guessing: at most 3 in 1 000 000.

### Fake host

- On first contact the joiner pins the host identity from the ticket. A
  device that does not hold that identity key fails step 1.
- A fake host that forwards traffic cannot complete the code exchange,
  because the exchange is bound to the peer TLS exporter and both
  identities.
- A fake host can use up the joiner's local attempts. It cannot spend the
  real host's attempts, because each side counts its own.

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
