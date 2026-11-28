# mousse-net wire protocol, version 1

Status: Phase 0 draft. Normative.

This document defines everything two Mousse devices exchange: identity keys,
session certificates, the authorization step after TLS, pairing, the stream
multiplexer and its control messages. An implementation that follows it,
and passes every file in [`vectors/`](vectors/README.md), interoperates with
`mousse-net-core`.

The code exchange used by "Send link" pairing (CPace) is specified in
[`cpace.md`](cpace.md). This document defines how it is bound and carried.

## 1. Conventions

- **MUST**, **MUST NOT**, **SHOULD** and **MAY** are used as in RFC 2119.
- All multi-byte integers on the wire are **big-endian** (network order).
- **Times** are Unix seconds (seconds since 1970-01-01T00:00:00Z, leap
  seconds ignored) as unsigned 64-bit integers. **Durations** inside one
  device (timeouts) use a monotonic clock in milliseconds and never cross the
  wire.
- **Skew.** Wall clocks of two devices may differ. Every check that compares
  a peer-signed time with the local clock allows **600 s** of skew
  (`CLOCK_SKEW`). Checks against a device's own records use no skew.
- `‖` is byte concatenation. `H(x)` is SHA-256. "Hex" in vectors is
  lowercase with no separators.
- "Close the connection with code C" means: send `GOAWAY(C)` (section 9.4)
  if the mux is running, then close the pipe. Before the mux runs (during
  TLS) it means: abort the handshake.
- An **endpoint** is one Mousse profile's helper on one device. Each endpoint
  has its own identity key, grant and denial table, invitations, pins,
  listener and relay registration. Two profiles on one computer are two
  endpoints and share none of these. Where this document says "device" or
  "host" for one of these, it means an endpoint.

## 2. Versions

| Name | Value | Where |
|---|---|---|
| Major protocol version | `1` | Session certificate (record and extension), pairing ticket, `HELLO` |
| Minor protocol version | `3` | `HELLO` |
| TLS ALPN | `mousse/1` | TLS ClientHello and ServerHello |

- A peer MUST reject a certificate or ticket whose major version it does not
  support (`unsupported_version`). A change of major version means devices
  pair again.
- The ALPN value carries the major version. A TLS peer MUST offer exactly
  `mousse/1` and MUST fail the handshake if it is not selected.
- **One major version per connection.** The ALPN major, the version in both
  session certificates (extension and signed record, which a verifier
  requires to be equal) and the major in `HELLO` MUST all be the same
  number. A certificate whose version differs from the negotiated ALPN major
  is `unsupported_version`; a `HELLO` whose major differs closes with
  `UNSUPPORTED_VERSION` (below). Major `1` has exactly one of each.
- **The ticket version fixes the pairing algorithms.** Ticket version `1`
  means CPace profile 1 ([`cpace.md`](cpace.md)), the join proof of 10.3 and
  the transcript of 10.5. There is no algorithm negotiation inside a
  ticket version; a new profile needs a new ticket version. A ticketless
  kind has no ticket version: the algorithms of kind 3 (direct, 10.9) are
  fixed by minor `4` and the ceremony version in its binding transcript.
- **Security requirements never weaken within a major version.** A newer
  minor version may add requirements; it MUST NOT relax any MUST of this
  document (TLS policy in 5.4, the checks of 5.4, pins, grants, the join
  proof, attempt limits). Two compatible minors therefore always meet the
  stricter set of rules. One exception, on the caller only: on a
  pairing-only connection the person started with Pair with IP (5.4, 8.2),
  check 9 of 5.4 is replaced by the code exchange's confirmation over both
  identity keys, and the caller trusts nothing from the host before it
  verifies. The host's checks do not change, and every other dial,
  including a Pair with IP recovery, is pinned.

**Minor version negotiation.** Each side speaks one major version and a
range of minor versions, from its oldest to its newest. An implementation
speaks its current minor version and the one before it (oldest = current −
1, or 0). Each side sends `HELLO {1: major, 2: newest minor}` (section 11).
When the peer's `HELLO` arrives, each side decides on its own:

1. If the peer's major version is not its own, close with
   `UNSUPPORTED_VERSION`.
2. `agreed = min(own newest minor, peer minor)`.
3. If `agreed` is below its own oldest minor, close with
   `UNSUPPORTED_VERSION`.
4. Otherwise the connection uses `agreed`.

When both sides accept, they reach the same `agreed`.

**What each minor adds.** Minor `1` adds two engine streams (9.5),
`mousse-keys` and `mousse-manifest`, for relays; minor `2` adds
`mousse-grants` and `mousse-removal`. Each is opened only on a connection
whose `agreed` minor is at least the one that added it; a minor `0` peer
never sees them. Minor `3` makes one connection carry calls both ways: on a
connection whose `agreed` minor is at least `3`, the host may open
application streams, and the caller serves them under its own grant for the
host (8, step 5). Below minor `3` a host opens no application stream, and a
caller resets any it receives with `REFUSED_STREAM`. Minor `4` (draft: this
version still sends minor `3`) adds Pair with IP: `JOIN_DIRECT` and
`AUTHORIZED` keys 2 and 3 (section 11). They are defined only on a
connection whose `agreed` minor is at least `4`; a receiver closes with
`PROTOCOL_ERROR` on one that arrives below it, as on any message its
version does not define. Vectors: `control.json` `before_minor_4`.

**Only the first `HELLO` counts.** The peer's first `HELLO` on a connection
fixes `agreed` or closes the connection. A later `HELLO` on the same
connection has no effect, whatever its fields hold: it is ignored, not
negotiated again and not an error. A side does not wait for the peer's
`HELLO` before sending its own next messages (section 8), with one
exception: a Pair with IP joiner waits for the host's `HELLO` before it
sends `JOIN_DIRECT`, because it needs `agreed`. If `agreed` is below `4` it
closes with `UNSUPPORTED_VERSION` (the host runs an older version). Vectors:
`hello.json` `cases` and `repeated`.

Since a peer speaks only its newest minor and the one before it, a side
MAY also close with `UNSUPPORTED_VERSION` when `agreed` is below the peer's
minor − 1: the peer refuses it anyway. Doing so at the peer's `HELLO` keeps
a caller from going live on a connection the host refuses once it reads the
caller's `HELLO`. A side that closes with `UNSUPPORTED_VERSION` sends its
own `HELLO` before the `GOAWAY` (it does not drop a `HELLO` still queued),
so the peer always learns its newest minor.

## 3. Canonical CBOR

Every structured record in this protocol (session record, ticket, join-proof
input, binding transcript, `OPEN` payload, control messages) uses this
deterministic subset of CBOR (RFC 8949). Encoders MUST produce exactly it.
Decoders MUST reject anything else.

- **Allowed major types:** 0 (unsigned integer), 2 (byte string), 3 (text
  string), 4 (array), 5 (map). Nothing else: no negative integers, tags,
  floats, `true`/`false`/`null`/`undefined` or other simple values.
- **Shortest form.** Every integer, length and count uses the shortest head:
  values 0–23 in the initial byte, then 1, 2, 4 or 8 following bytes only
  when the value does not fit the smaller form. Indefinite lengths are
  forbidden.
- **Maps** have unsigned-integer keys only, in **strictly ascending** order
  (so no duplicates).
- **Text** MUST be valid UTF-8.
- **Depth.** An item nested inside more than 8 arrays or maps is rejected.
- **Exactly one item.** Bytes after the top-level item are an error.

Error names used in vectors: `truncated`, `trailing_bytes`, `non_canonical`,
`unsorted_keys`, `non_integer_key`, `unsupported`, `invalid_utf8`,
`too_deep`.

**Which error.** A decoder reads from the first byte on and reports the
first rule broken. For each item, in this order:

1. The item would sit inside more than 8 arrays or maps: `too_deep`.
2. Major type 1, 6 or 7 (so a lone break byte `ff` too): `unsupported`.
3. Additional information 28 to 30: `unsupported`. Additional information
   31 (an indefinite length, on any major type): `non_canonical`.
4. Bytes of the head are missing: `truncated`. A head that is not in its
   shortest form: `non_canonical`.
5. Byte and text strings: fewer bytes left than the length says,
   `truncated`; text that is not UTF-8, `invalid_utf8`.
6. Arrays: a count larger than the bytes left (every item takes at least
   one byte) is `truncated` before any item is read. Maps: a count larger
   than half the bytes left is `truncated` in the same way. Then, for each
   entry: a key whose major type is not 0, `non_integer_key`; the key's
   head by rules 3 and 4; a key not greater than the one before,
   `unsorted_keys`, before its value is read; then the value.

After the top-level item, any byte left is `trailing_bytes`. Vectors:
`cbor.json`.

**Records with fixed fields.** When this document lists a record as
`{1: ..., 2: ...}`, every listed key is required unless marked optional, the
value type is as listed, and **any other key is an error**. A record whose
field fails its rule is rejected as a whole.

## 4. Keys and signatures

### 4.1 Identity key

Each endpoint has one long-lived **identity key**: ECDSA on NIST P-256
(secp256r1) with SHA-256. Its public key is always written as a **SEC1
uncompressed point**: 65 bytes, `0x04 ‖ X ‖ Y`. Compressed points, the
point at infinity and points not on the curve are rejected.

The identity key may live in hardware (Secure Enclave, StrongBox/TEE), in a
keystore-wrapped software key, or in a non-extractable WebCrypto key. Only
its public key and its signatures appear on the wire.

The **fingerprint** of a public key is `H(65-byte SEC1 point)`. It is a local
display and indexing value; it does not appear on the wire.

**What the identity key signs (frozen).** The identity key signs only
canonical CBOR maps (section 3) whose key `1` is a text domain string, and
each domain string names exactly one record type. Major version 1 has
these domains: `mousse-session-v1`, the session record (5.1),
`mousse-manifest-v1`, a host's relay manifest (9.5), and
`mousse-removal-v1`, a removal from an owner-role device (9.5). A new signed record
needs a new domain string that no other record uses; the identity key MUST
never sign raw bytes, a hash supplied from outside, or a record without its
domain at key 1. This keeps any two signed things from ever being confused,
whatever is added later. In `mousse-net-core`, `IdentitySigner` accepts only
an `IdentityRecord`, which only the core builds.

Relay proofs ([relay.md](relay.md) section 5) follow the same rule (canonical
CBOR, a domain string of their own at key 1) but are signed by an
endpoint's relay keys (a registration key per relay, a caller key per
pairing), never by the identity key.

**Hardware keys stay usable while unlocked.** A session certificate is
renewed in the background (section 6). A key store that asks for user
presence (a fingerprint, a PIN, a tap) on every signature would stop
renewal, and every session would end at its certificate's deadline. An
identity key MUST be usable for signing without a user-presence prompt from
the device's first unlock after start until it shuts down; a platform
option that requires presence per use MUST NOT be set on it.

### 4.2 Raw signatures

Wherever this document says **raw signature**, the value is exactly 64 bytes:
`r ‖ s`, each a 32-byte big-endian integer, left-padded with zeros.

- Any other length is rejected as `not_raw`. In particular a DER signature
  where a raw one is required is rejected, never converted.
- `r` and `s` MUST each be in `[1, n−1]` (n is the P-256 group order),
  otherwise `out_of_range`.
- Verifiers MUST accept both low and high `s`.
- Signers MAY use any secure nonce; `mousse-net-core` uses RFC 6979.

### 4.3 DER to raw

Platforms that return DER (`Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s
INTEGER }`), such as the Secure Enclave and Android Keystore, convert before
the signature is placed on the wire. The conversion is strict:

1. The input is exactly one DER `SEQUENCE` containing exactly two `INTEGER`s
   and nothing else, with minimal definite lengths. Otherwise `bad_der`.
2. Each `INTEGER` is non-negative (top bit of the first content byte clear)
   and minimal (no leading `0x00` unless the next byte has its top bit set).
   Otherwise `bad_der`.
3. After removing the one permitted leading `0x00`, each magnitude is at most
   32 bytes, otherwise `out_of_range`.
4. Left-pad each magnitude with zeros to 32 bytes; output `r ‖ s`.
5. Check the range rule of 4.2 (`out_of_range` for zero).

The reverse direction (raw to DER) produces minimal INTEGERs. TLS 1.3
`CertificateVerify` carries DER and is unaffected by this rule.

## 5. Session certificates

A TLS connection between two devices is authenticated with short-lived
**session certificates**. Each is a self-signed X.509 v3 certificate on a fresh
P-256 **session key**, carrying a signature by the device's identity key over
that session key and a validity window.

### 5.1 Session record

The identity key signs this canonical CBOR map (the **session record**):

| Key | Value |
|---|---|
| 1 | text `"mousse-session-v1"` |
| 2 | bytes: the session key's `SubjectPublicKeyInfo`, DER (91 bytes, see 5.3) |
| 3 | uint: `not_before` |
| 4 | uint: `not_after` |
| 5 | uint: major protocol version (`1`) |

The **identity signature** is a raw signature (4.2) by the identity key, with
SHA-256, over the record bytes.

There is no role in the record. A device's role on a host endpoint comes only
from that endpoint's grant (section 7).

### 5.2 Validity window

- `not_before < not_after`, and `not_after − not_before ≤ 86 400` (24 h).
  Otherwise `window_invalid`.
- The signed window is authoritative. The X.509 `validity` field carries the
  same two values (5.3) and is not interpreted separately.
- A verifier at wall time `now` accepts the certificate when
  `not_before − 600 ≤ now ≤ not_after + 600`. Both bounds are inclusive.
  Otherwise `outside_window`.
- An issuer SHOULD set `not_before` to its current time. `mousse-net-core`
  issues 24 h certificates and renews 30 min before `not_after`
  (section 6).

When a certificate is rejected as `outside_window`, the user-facing message is
neutral, because a wrong clock and an expired certificate look the same:
"The certificate is outside its validity window; check this device's clock."

### 5.3 Certificate profile

The certificate is fixed byte for byte, given its inputs (session key,
window, version, identity key, identity signature, self-signature). All
lengths are minimal definite DER lengths.

```
Certificate ::= SEQUENCE {
  tbsCertificate SEQUENCE {
    version          [0] EXPLICIT INTEGER 2                    -- a0 03 02 01 02
    serialNumber     INTEGER, 16 content bytes (see below)
    signature        SEQUENCE { OID 1.2.840.10045.4.3.2 }      -- ecdsa-with-SHA256, no parameters
    issuer           Name (see below)
    validity         SEQUENCE { notBefore Time, notAfter Time }
    subject          Name, identical to issuer
    subjectPublicKeyInfo  (91 bytes, see below)
    extensions       [3] EXPLICIT SEQUENCE { one Extension }
  }
  signatureAlgorithm SEQUENCE { OID 1.2.840.10045.4.3.2 }      -- 30 0a 06 08 2a 86 48 ce 3d 04 03 02
  signatureValue     BIT STRING { 0x00 unused bits ‖ DER Ecdsa-Sig-Value }
}
```

- **serialNumber:** the first 16 bytes of `H(SubjectPublicKeyInfo DER)`, then
  the first byte set to `(b & 0x3f) | 0x40`. The INTEGER is therefore
  positive, always 16 content bytes, with no leading zero.
- **Name:** `SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (commonName),
  UTF8String "mousse-session" } } }`.
- **Time:** the instant written as `YYMMDDHHMMSSZ` in a `UTCTime` for years
  before 2050, and as `YYYYMMDDHHMMSSZ` in a `GeneralizedTime` from 2050
  (RFC 5280 rule). Seconds are always present; no fractions; always `Z`.
- **SubjectPublicKeyInfo:** the fixed 26-byte prefix
  `30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00`
  (id-ecPublicKey, prime256v1, BIT STRING with 0 unused bits) followed by the
  65-byte uncompressed session public key.
- **Extension:** exactly one, non-critical (the `critical` field is absent):
  `SEQUENCE { OID, OCTET STRING { binding } }`.
  - OID: `2.25.67239088527495828216221962252461137669` (a UUID-derived arc,
    UUID `3295c703-df61-413a-9593-69f74c5ddf05`). Its DER content bytes are
    `69 e5 95 e3 c0 fb f6 8a 84 f5 95 c9 da be f4 e2 f7 be 05`.
  - binding: `SEQUENCE { INTEGER version, OCTET STRING identity_key (65 bytes),
    OCTET STRING identity_signature (64 bytes) }`. `version` is the major
    protocol version. The lengths are what an issuer writes. For the
    verifier, `version` is any non-negative minimal INTEGER of at most 8
    content bytes, and the two OCTET STRINGs may have any length; checks 2,
    3 and 5 of 5.4 judge their values.
- **signatureValue:** a signature by the **session** key over the DER bytes of
  `tbsCertificate`, ECDSA P-256 with SHA-256, DER encoded (this is X.509, so
  DER is correct here). Read the value with the strict conversion of 4.3:
  a value it rejects as `bad_der` is not this profile (`malformed`, check
  1); a value it rejects as `out_of_range` (a well-formed INTEGER that is
  zero, too long or not below the group order) fails check 7
  (`self_signature_invalid`).

A verifier MUST reject (`malformed`) any certificate that is not exactly this
profile: other names, serials, algorithms, time forms, extension sets,
critical flags, extra fields, non-minimal DER or trailing bytes. One simple
way to do this, and the way `mousse-net-core` does it, is to parse the fields
listed above, re-encode them with these rules and require byte equality.

### 5.4 Verification (step 1)

TLS between two devices is **TLS 1.3 only** with **mandatory mutual
authentication**. Both certificates are session certificates. The signature
scheme for `CertificateVerify` is `ecdsa_secp256r1_sha256`. TLS server name
and Web PKI checks do not apply; the checks below replace them.

**TLS policy.** These are requirements, not defaults:

- **Full mutual TLS on every connection.** Each side sends and verifies a
  session certificate on every connection, including reconnects, bulk
  sessions and path switches.
- **No resumption, no PSK.** A client MUST NOT offer a pre-shared key or a
  resumption ticket; a server MUST NOT issue tickets and MUST NOT accept a
  PSK. Every connection runs a full handshake and the checks below.
- **No 0-RTT.** Neither side sends or accepts early data.
- **Key exchange groups.** A native endpoint offers `X25519MLKEM768` first
  and `X25519` second, and no others. A native endpoint MUST complete the
  handshake only on `X25519MLKEM768`: a connection that negotiated any other
  group is closed before any application data. `X25519` alone is reserved
  for a future browser profile that cannot do the hybrid group (Phase 5,
  deferred and not specified here); until that profile exists, no endpoint
  accepts a classical-only connection.
- **ALPN** exactly `mousse/1` (section 2).

Each side verifies the peer's certificate at its own wall time `now`, with an
**expected identity** (pin):

- **every connection to a known peer**: the pin this endpoint stored for
  that peer endpoint, on first connections, reconnects, bulk sessions and
  path switches alike;
- **a joiner's first contact with a host**: the host endpoint's identity
  from the ticket;
- **a Pair with IP joiner's first contact** (10.9): no pin. Checks 1 to 8
  and 10 and the full TLS policy still apply, and the caller refuses a
  certificate whose identity is its own endpoint's key or one this profile
  denied before its own certificate goes out. The identity it saw is only a
  candidate: the connection is pairing only (8.2) and the caller trusts that
  identity only once the host's code-exchange confirmation verifies. A
  recovery connection after that is pinned to the verified identity;
- **a host accepting a connection**: no pin; step 2 decides (section 8).

Pins belong to one endpoint. Another profile's endpoint on the same device
has its own pins and never uses these.

Checks run in this order; the first failure is the result. Vectors expect
this exact order, including certificates that break more than one rule
(`session-cert.json` cases named `precedence_*`).

1. Profile and DER (5.3), else `malformed`.
2. Extension version is supported, else `unsupported_version`.
3. Identity key is a valid point (4.1), else `identity_key_invalid`.
4. Session key is a valid point, else `session_key_invalid`.
5. Identity signature is 64 bytes, else `identity_signature_not_raw`. (A
   64-byte value whose `r` or `s` is zero or not below the group order
   passes here and fails check 8.)
6. Window rules (5.2), else `window_invalid`.
7. The self-signature's scalars are in range and it verifies with the
   session key over `tbsCertificate`, else `self_signature_invalid`.
8. Build the session record (5.1) from **this certificate's** SPKI, window
   and version; the identity signature verifies over it with the identity
   key, else `identity_signature_invalid`. (An identity signature made for
   another session key fails here.)
9. If a pin is given, the identity key equals it byte for byte, else
   `pin_mismatch`.
10. `now` is inside the widened window (5.2), else `outside_window`.

The pin comes before the window on purpose: a certificate from some other
endpoint is `pin_mismatch` whatever its window says, so a foreign endpoint
on a candidate address always reads as "not this peer", never as a clock
problem (`session-cert.json` case `precedence_pin_before_window`).

The TLS stack separately verifies `CertificateVerify` with the session key,
as usual. Together, these prove that the peer holds the session key now and
that the identity key vouched for that session key and window.

**Another endpoint on the address.** A LAN address (a route hint, a
discovered address or a remembered one) is only a candidate. When the
endpoint that answers on a candidate fails the pin (`pin_mismatch`), another
endpoint holds that address: for example another profile's helper on the
same computer, or another computer that took the address. The caller aborts
that handshake before sending any data, tries the next candidate, shows no
warning and keeps its pin unchanged. The same holds for any other step 1
failure on a candidate address: the caller tries the next candidate, and
shows an error (for `outside_window`, the clock message) only when no
candidate succeeded. Vectors: `session-cert.json` cases
`another_endpoint_on_lan_address` and `precedence_pin_before_window`.

### 5.5 TLS exporters

Pairing binds values to the TLS session between the two devices (the **peer
session**) with TLS 1.3 exporters (RFC 8446 section 7.5): 32 bytes each,
zero-length context (an absent context and an empty one give the same value
in TLS 1.3).

| Label | Used for |
|---|---|
| `EXPORTER-mousse-join-v1` | Join proof (10.3) |
| `EXPORTER-mousse-pair-v1` | Binding transcript (10.5) |

If the peer session runs inside another TLS connection (for example a
WebSocket to a relay), the exporters MUST come from the inner peer session,
never the outer one. The outer connection to a relay has its own exporter,
`EXPORTER-mousse-relay-v1`, used only by relay proofs
([relay.md](relay.md) sections 2 and 5).

A TLS 1.3 exporter is derived before the client's certificate is sent, so it
does not by itself name the client. Every construction that uses one also
includes both identity keys.

## 6. Session lifetime

- A connection's **effective deadline** is
  `min(local not_after, peer not_after) + 600`. The connection may run
  through that second and MUST close with `CERT_EXPIRED` at the first second
  after it, whatever it is doing.
- **Renewal** starts at `min(not_after) − 1800`, but never before the later
  `not_before`. The side whose certificate runs out first issues a new one.
  Renewal is a path switch. While no new path with a later renewal time has
  become current, renewal is retried: 30 s after the first try, then waits
  of 60, 120 and 240 s, then every 300 s, until the effective deadline. A
  new path whose renewal time is no later than the old one's (the peer has
  not renewed yet, for example because its clock is behind) becomes current
  as usual but keeps the pending retries and their waits. Each wait starts
  when its retry actually runs (a late clock tick pushes the schedule back;
  it never fires twice to catch up). A retry that falls due while a
  candidate path is still being brought up is skipped, but it still counts:
  the next wait starts then and grows as if the retry had run, and the
  skipped retry is not made up when the candidate fails. The first request
  at the renewal time follows the same rule: if a candidate is already being
  brought up then, the request is skipped but counts, and the 30 s wait
  starts at that tick. Vectors: `session-lifecycle.json`.
- **Path switch:** open a new connection to the same peer, run step 1 with
  the **same pin**, reopen channels on it (the application resumes from its
  own cursors), then close the old connection with `PATH_REPLACED`. If the
  new connection fails, the old one keeps running until its own deadline.
- A device holds at most one current and one candidate path per peer. A newer
  candidate replaces an older one, which closes with `PATH_REPLACED`.
- **The wall clock cannot extend a connection.** When step 1 passes, each
  side also notes its monotonic clock and caps the connection at that reading
  plus the time that was left until the effective deadline:
  `mono_deadline = mono_at_authentication + (effective deadline + 1 −
  now) × 1000` ms. The connection closes with `CERT_EXPIRED` at the first of
  the two: the wall clock passing the effective deadline, or the monotonic
  clock reaching `mono_deadline`. Setting the wall clock back therefore never
  keeps a connection open past its certificates, and renewal still runs on
  the wall clock. The monotonic clock must keep counting while the device
  sleeps or suspends (on Linux `CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`),
  else a suspend followed by setting the wall clock back would stretch the
  cap; the device checks both again when it resumes. Vectors:
  `session-lifecycle.json` `clock_rollback`.

## 7. Grants

Authorization lives on each host endpoint as its own table of **grants** and
**denials**. Two endpoints on one device never share a table. This section
fixes the semantics both ends rely on; the storage format is local.

A grant is `{identity, name, role, source, authorizing owner, adopted_into,
enrolled_by, granted_at, expires_at?}`:

- `identity`: the peer endpoint's 65-byte identity key.
- `name`: 1 to 128 bytes of UTF-8. The app uses `<computer> (<profile>)`.
- `role`: 1 to 32 bytes of `[a-z0-9-]`. `owner` and `client` are defined
  now; the application gives them meaning.
- `source`: `local` (until rosters exist).
- `authorizing owner`: the **profile id** of the profile that approved it:
  16 random bytes (128 bits), drawn once when the profile is created and
  never changed. Never a display name. With one owner profile per endpoint,
  this is the endpoint's own profile.
- `adopted_into`: always empty in version 1.
- `enrolled_by`: the grant's **enrollment receipt**: the id of the
  invitation whose enrollment (10.8) made this grant, or empty for a grant
  made any other way. It is stored with the grant, so it survives restarts,
  and it goes when the grant goes. The host uses it to answer a joiner whose
  `PAIRED` was lost (10.6 rule 7).
- `expires_at`: optional. At that second the grant is already expired.

Local fields a host keeps with a grant, never sent: the **caller key
fingerprint** and the **pair secret** a caller enrolled on `mousse-keys`
(9.5). A new pairing of the same device replaces both, and removing the
grant deletes them.

Rules:

- At most one grant per identity on an endpoint. A new grant for the same
  identity replaces the old one entirely (name, role and authorizing owner),
  and the old one's channels close with `GRANT_REVOKED`.
- Each authorized connection is **bound** to the grant that authorized it.
  Removing, expiring or denying that grant closes the bound connections at
  once with `GRANT_REVOKED`.
- A **local denial** covers the whole endpoint and always wins: denying an
  identity removes its grant, closes its connections, and blocks new grants
  until the denial is lifted. Lifting a denial grants nothing. It has no
  effect on other endpoints of the same device.
- Grant ids are local and never reused, also across restarts: an endpoint
  stores the next grant id with its grants, because the grant that last
  used an id may already be gone. A grant that replaces another (a new
  pairing of the same device) takes a new id, so a grant id names exactly
  one pairing.
- **Editing the role in place.** The owner may change a grant's role
  without replacing it: the id, identity, name, receipt, authorizing owner,
  times and the local caller key and pair secret stay. Each grant keeps a
  local **revision**, 1 when the grant is made, one higher after each edit;
  an edit names the revision it was made against and is refused if that is
  not the current one. The revision is local and never sent. An edit is
  stored before it takes effect, and then closes every connection bound to
  the grant with `CANCELLED`: the grant is not gone, so `GRANT_REVOKED`
  does not apply. The peer connects again and is served under the new role.

**Removal from another device (later phases).** Phase 0 removes grants only
locally. When removal messages are added, an endpoint accepts one only from
a signer that holds a live grant with role `owner` on that same endpoint,
and only after checking the signature, that the message names this endpoint
as its recipient, and that it is not a replay. A removal names the pairing it
ends; a stale removal, for a pairing that a newer pairing of the same device
has replaced, leaves the newer grant alone.

## 8. Connection start and step 2

After TLS completes, both sides start the mux (section 9). The **caller** is
the TLS client and the **host** is the TLS server.

1. Each side sends `HELLO` first (control message type 1), without waiting
   for the peer's (section 2). Message logs in the vectors
   (`pairing-attempts.json`) leave these two out and start at the next
   message, such as `JOIN_PROOF`.
2. The host runs **step 2** for the peer identity from step 1, as soon as
   the connection starts and before it reads any control message from the
   caller. It sends nothing to say that it awaits a proof:
   - identity denied: close with `NOT_AUTHORIZED`;
   - a provisional grant (Pair with IP, 10.9), whether or not the identity
     also holds a grant: bind the connection to the provisional grant and
     send `AUTHORIZED {state: live}`. Its first stream frame commits that
     grant (8.1);
   - a live grant: bind the connection to it and send
     `AUTHORIZED {state: live}`;
   - otherwise: wait for a `JOIN_PROOF`. If none arrives within **10 s**,
     close with `NOT_AUTHORIZED`.
3. The host answers a `JOIN_PROOF` (10.3) with one `AUTHORIZED` or a close:
   - awaiting a proof: a valid join proof for an open invitation makes the
     connection **join-only** and the host sends
     `AUTHORIZED {state: join_only}`;
   - live: a granted device may send one `JOIN_PROOF`, before any stream
     frame. A valid proof for an open invitation makes the connection
     join-only, and the host sends `AUTHORIZED {state: join_only}`: the
     device pairs again, and enrollment replaces its grant (section 7). Any
     other proof opens nothing, and the connection stays live under its
     grant. If the grant's enrollment receipt names the proof's invitation,
     the host answers `PAIRED {host name, role}` with the grant's role
     (10.6 rule 7); the connection is already authenticated as the grant's
     identity, so this answer needs no valid MAC, and the invitation may be
     gone. Otherwise the host answers `AUTHORIZED {state: live}` again. A
     second proof, or one after a stream frame, closes with
     `PROTOCOL_ERROR`.

   On a join-only connection only pairing messages are allowed. When pairing
   enrolls the device, the connection becomes live under the new grant.

   `JOIN_DIRECT` (Pair with IP, minor `4`) passes the host's gate exactly as
   `JOIN_PROOF` does (8.1): from a connection awaiting a proof, or once from
   a live one before any stream frame, and a connection may carry one of the
   two at most. How the host answers it is in 10.9.
4. **The caller opens streams first.** A host opens no stream on a
   connection until the caller has opened one. A caller that sent a
   `JOIN_PROOF` or a `JOIN_DIRECT` opens no stream before the host's answer
   to it. So a host
   stream can never cross the answer to a proof. This rule only orders
   streams; it gives the host no authority (step 5).
5. **Grants point one way.** Step 2 and the host's `AUTHORIZED` decide what
   the caller may do on the host, never what the host may do on the caller.
   Once the caller is live, its gate (8.2) lets a stream the host opens
   through, but before the caller dispatches any privileged operation on
   such a stream, it MUST authorize the host itself against its own grant
   table (section 7): the host identity needs a live grant there, and the
   operation must fit that grant's role. Without one, the caller refuses the
   operation (for example by resetting the stream) and the connection stays
   up. A pairing creates no grant on the joiner, so a joiner's host has no
   authority on it unless the joiner's owner grants it separately. From
   minor `3` (section 2) this is how the host calls the caller: an
   application stream the host opens is served under the caller's live
   grant for the host, read when the stream arrives; without one it is
   reset with `REFUSED_STREAM`, and when that grant stops being live the
   streams served under it are reset with `GRANT_REVOKED`. The connection
   stays up either way: it is the caller's access to the host. Vectors:
   `authz.json` `host_opened_stream_needs_the_callers_grant`.

### 8.1 What the host accepts

Inbound traffic on the host is classified and checked against the
connection's state:

| Traffic | Awaiting proof | Join-only | Live |
|---|---|---|---|
| `PING`, `PONG`, `HELLO`, `GOAWAY` | allow | allow | allow |
| `JOIN_PROOF`, `JOIN_DIRECT` | allow once (one of the two); a second closes `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow once (one of the two), before any stream frame; otherwise close `PROTOCOL_ERROR` |
| `CODE_EXCHANGE`, `CODE_ABORT` | close `NOT_AUTHORIZED` | allow | ignore |
| Any stream frame (`OPEN`, `DATA`, `CREDIT`, `FIN`, `RESET`) | close `NOT_AUTHORIZED` | close `NOT_AUTHORIZED` | allow |
| `AUTHORIZED`, `PAIRED` (host-only messages) | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |

After a close, everything else is ignored. A valid identity with no grant can
therefore never reach RPC or any other channel.

A live connection bound to a **provisional** grant (Pair with IP, 10.9)
follows the live column with two differences, until the grant commits:

- **First stream frame.** The gate does not let it through on its own: it
  answers "commit first". The I/O layer has the host commit the grant
  (10.9, "Provisional grant") and store the grant table with it before it
  releases that frame or anything after it; when the commit fails, the
  connection closes with `GRANT_REVOKED`, and when it cannot be stored,
  with `INTERNAL_ERROR`. After the commit every connection bound to that grant,
  not only the one whose frame committed it, is live as any other.
- **Cancel.** On the connection the host enrolled after a code exchange, a
  `CODE_ABORT` whose attempt id is the attempt that passed on that
  connection is allowed. Every other `CODE_EXCHANGE` and `CODE_ABORT` is
  ignored, as on any live connection, and so is that one once the grant
  has committed, whichever connection committed it.

A connection the host holds after a lookup that found nothing (10.9,
"Lookup") lets only `PING`, `PONG`, `HELLO` and `GOAWAY` through until the
host closes it; everything else, a stream frame included, is ignored and
commits nothing.

### 8.2 What the caller accepts

The caller checks what the host sends in the same way. It starts **awaiting
authorization**; `AUTHORIZED` moves it to live or join-only. A join-only
caller becomes live when it accepts `PAIRED` (10.4, 10.6), which for "Send
link" is only after it verified the host's confirmation.

A caller that sent a `JOIN_PROOF` on the connection reads a first
`AUTHORIZED {live}` as step 2's notice only and moves to **awaiting the
answer**; the next `AUTHORIZED`, or a `PAIRED` (an enrollment receipt), is
the host's answer to the proof (8, step 3). If it read the notice before its
proof went out, it moves to awaiting the answer when it sends the proof. A
caller that has had no answer 10 s after sending its proof closes the
connection with `NOT_AUTHORIZED`; a joiner's flow then ends (10.6 rule
7). On a pinned connection a `JOIN_DIRECT` (a Pair with IP recovery, 10.9)
counts as the proof in all of this.

| Traffic from the host | Awaiting `AUTHORIZED` | Awaiting the answer | Join-only | Live |
|---|---|---|---|---|
| `PING`, `PONG`, `HELLO`, `GOAWAY` | allow | allow | allow | allow |
| `AUTHORIZED` | allow, then live or join-only; `live` after this side sent a proof: awaiting the answer | allow, then live or join-only | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |
| `CODE_EXCHANGE`, `CODE_ABORT` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow | ignore |
| `PAIRED` | close `PROTOCOL_ERROR` | allow, then live (the answer to the proof) | allow | close `PROTOCOL_ERROR` |
| Any stream frame, including a stream the host opens | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow |
| `JOIN_PROOF`, `JOIN_DIRECT` (caller-only messages) | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |

So a host can never open a stream on a caller that has not been told it is
live. Being live lets the host's streams through this gate only; what they
may do is decided by the caller's own grants (8, step 5). After a close,
everything else is ignored. Vectors: `authz.json` `caller_cases`.

**Pairing only.** The first contact of Pair with IP is not pinned (5.4), so
the caller starts that connection in its own state, **pairing only**, and
not in the table above. It can do nothing but this pairing: it accepts
`HELLO`, `AUTHORIZED`, `CODE_EXCHANGE`, `CODE_ABORT`, `PAIRED`, `GOAWAY` and
keepalive (`PING`, `PONG`), and never a stream. Keepalive is needed here:
the host may wait up to 5 minutes for its person to allow the join, longer
than the 45 s idle timeout (9.4). It becomes live only when the joiner has
verified the host's code-exchange confirmation and accepted `PAIRED`;
`AUTHORIZED {live}` never makes it live.

| Traffic from the host | Awaiting the answer | Notice seen | Join-only | Paired |
|---|---|---|---|---|
| `PING`, `PONG`, `HELLO`, `GOAWAY` | allow | allow | allow | allow |
| `AUTHORIZED {live}` | allow, then notice seen (step 2's notice for a device the host grants) | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |
| `AUTHORIZED {join_only}` | allow, then join-only | allow, then join-only | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |
| `CODE_EXCHANGE`, `CODE_ABORT` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow | ignore |
| `PAIRED` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow, then paired | close `PROTOCOL_ERROR` |
| Any stream frame | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |
| `JOIN_PROOF`, `JOIN_DIRECT` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |

From paired, the connection is live once the joiner's pairing has verified
the host's confirmation (10.9); until then nothing from the host is
trusted. Vectors: `authz.json` caller cases with `start` `pairing_only`.

## 9. Mux

### 9.1 Frames

The TLS byte stream carries a sequence of frames. Each frame is a 9-byte
header followed by a payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | stream id (uint32) |
| 4 | 1 | type (uint8) |
| 5 | 4 | payload length (uint32) |
| 9 | length | payload |

| Type | Name | Stream | Payload |
|---|---|---|---|
| 0 | `DATA` | ≠ 0 | 1 to 65 536 bytes of stream data |
| 1 | `OPEN` | ≠ 0 | canonical CBOR `{1: class, 2: label}`, at most 256 bytes |
| 2 | `CREDIT` | ≠ 0 | uint32 increment, ≥ 1 |
| 3 | `FIN` | ≠ 0 | empty |
| 4 | `RESET` | ≠ 0 | uint16 error code |
| 5 | `PING` | 0 | 8 opaque bytes |
| 6 | `PONG` | 0 | the 8 bytes from the `PING` |
| 7 | `CONTROL` | 0 | 1 to 16 384 bytes: one control message (section 11) |
| 8 | `GOAWAY` | 0 | uint16 error code |

`OPEN` fields: `class` is `0` (interactive) or `1` (bulk); `label` is 1 to 64
bytes of UTF-8 naming the channel kind (for example `rpc`, `terminal`). Label
meanings belong to the application.

A receiver decodes in this order, so that every implementation gives the same
answer for the same bytes:

1. Fewer than 9 bytes: wait for more.
2. Type above 8: close with `PROTOCOL_ERROR`.
3. Length above the type's limit (65 536; 16 384 for `CONTROL`; 256 for
   `OPEN`): close with `FRAME_TOO_LARGE`. This is decided from the header
   alone, before the payload arrives.
4. Stream id 0 for a stream type, or non-zero for `PING`, `PONG`, `CONTROL`,
   `GOAWAY`: close with `PROTOCOL_ERROR`.
5. Payload incomplete: wait for more.
6. Payload rules from the table (sizes, `CREDIT` ≥ 1, `OPEN` record, label
   length, class, canonical CBOR): close with `PROTOCOL_ERROR`.

An unknown error code in `RESET` or `GOAWAY` is not a frame error; treat it as
`INTERNAL_ERROR`.

### 9.2 Streams

- The caller opens streams with **odd** ids starting at 1; the host with
  **even** ids starting at 2. Each side opens its ids in order with no gaps
  (1, 3, 5, … and 2, 4, 6, …), so every id up to a side's highest opened id
  was opened. A peer `OPEN` with any other id (wrong parity, repeated, lower
  or skipping one) is `PROTOCOL_ERROR`.
- A stream starts with `OPEN`. `DATA` may follow at once.
- `FIN` ends one direction. `DATA` or a second `FIN` after the peer's `FIN`
  is `STREAM_CLOSED`. A stream is gone when both sides have sent `FIN`.
- `RESET` aborts both directions at once; queued data is dropped.
- A frame for a stream id that was **never opened** is `PROTOCOL_ERROR`. A
  frame for a stream that was opened and is now gone is ignored (a normal
  race).
- A side may keep at most **1 024** streams opened by its peer. A further
  `OPEN` is answered with `RESET REFUSED_STREAM`; the connection stays up.
- A side may keep fewer, counting its own streams too (the reference
  implementation keeps 32 per connection and 128 per endpoint, to bound
  the initial credit it has granted). It answers an `OPEN` past its own
  limit the same way: `RESET REFUSED_STREAM`, connection up. A sender that
  gets `REFUSED_STREAM` may open the stream again once one of its streams
  on that connection has ended.

### 9.3 Flow control

- Each direction of each stream starts with **262 144 bytes** of credit.
  Only `DATA` payload bytes count.
- The receiver returns credit with `CREDIT` as the application consumes data.
  `mousse-net-core` sends a `CREDIT` once at least 65 536 consumed bytes have
  not been returned yet.
- A sender MUST NOT exceed its credit; a receiver that gets more `DATA` than
  the credit it granted closes with `FLOW_CONTROL`.
- Available send credit above 2^30 bytes is `FLOW_CONTROL`.
- No credit is returned after the peer's `FIN`.

### 9.4 Priority, keepalive and closing

- **Priority** is a sender rule: control frames (everything on stream 0, and
  `CREDIT` and `RESET`) go first, then interactive streams, then bulk,
  round-robin within a class. `mousse-net-core` sends `DATA` in chunks of at
  most 16 384 bytes so an interactive frame waits for at most one bulk chunk.
- **Keepalive:** send `PING` after **15 s** without sending anything. Answer
  each `PING` with a `PONG` carrying the same 8 bytes.
- **Idle timeout:** close with `IDLE_TIMEOUT` after **45 s** without
  receiving anything.
- **GOAWAY** ends the connection: the sender sends nothing after it and closes
  the pipe; the receiver stops sending and closes too.

### 9.5 Engine streams

Streams whose label starts with `mousse-` belong to the engine: an
implementation handles them itself and never passes them to an
application, and an application cannot open them. Each is opened only when
the connection's agreed minor version (section 2) allows it; any other
`mousse-` stream is answered with `RESET REFUSED_STREAM`.

Each message on an engine stream is a 4-byte big-endian length followed by
that many bytes of one canonical CBOR map (section 3). A message is at most
**262 144** bytes; a longer declared length is a protocol error on that
stream (`RESET PROTOCOL_ERROR`).

| Label | Minor | Opened by | Carries |
|---|---|---|---|
| `mousse-keys` | 1 | caller, on every new connection to a host, as its first stream | caller → host: `{1: caller relay public key (65, SEC1)}`; host → caller: `{1: pair secret (32)}`; then both finish. The host answers only on a connection bound to a live grant |
| `mousse-manifest` | 1 | host, once the caller has opened a stream, and again on every change | one signed manifest envelope (below); then the host finishes |
| `mousse-grants` | 2 | host, to a caller whose live grant has role `owner` | `{1: [{1: identity key (65), 2: grant id (uint), 3: role (text), 4: name (text)}]}`: every grant on the host, at the stream's start and again on every change |
| `mousse-removal` | 2 | caller | caller → host: one signed removal envelope; host → caller: `{1: removal id (16), 2: result (0 applied, 1 stale, 2 refused)}`; then both finish |

**The caller key** is one P-256 key per caller and host; a relay admits a
call by its fingerprint (`relay.md`). The pair secret is one 32-byte
random value per grant; the host keeps it for that grant.

**The manifest record** (domain `mousse-manifest-v1`), signed by the
host's identity key; the envelope is `{1: record bytes, 2: raw signature
(64)}` over the record bytes:

| Key | Value |
|---|---|
| 1 | text `"mousse-manifest-v1"` |
| 2 | bytes: host identity key (65) |
| 3 | uint: sequence (grows) |
| 4 | uint: issued at |
| 5 | uint: expires at |
| 6 | array of at most 4 routes `{1: relay identity key (65), 2: 1 to 4 endpoint texts host:port, 3: handle (32), 4: region text (0 to 32 bytes)}` |

A caller keeps a manifest only if the identity key at key 2 is the pinned
host and the signature verifies under it, and only if its sequence is above
the one it keeps. Endpoint texts follow the `tcp` hint host and port rules
(10.2.1), lower case. Past `expires at` the manifest is stale: its routes
are still tried, after every other route.

**The removal record** (domain `mousse-removal-v1`), signed by the admin
device's identity key: `{1: "mousse-removal-v1", 2: signer identity key
(65), 3: recipient host identity key (65), 4: removed identity key (65), 5:
grant id on the recipient (uint), 6: removal id (16, random), 7: issued at
(Unix seconds)}`. The envelope is `{1: record bytes, 2: raw signature (64)}`
over the record bytes. A removal is signed once; every resend carries the
same bytes.

**What a host accepts**, under the lock under which it admits connections
and enrolls devices, in order; a failure answers `refused` or `stale` and
changes nothing else:

1. The signature verifies under key 2, and that signer holds a live grant
   with role `owner` on this endpoint.
2. Key 3 is this endpoint's identity.
3. The removal id is new. A known id whose record bytes hash (SHA-256) to
   the stored hash returns the stored result and does nothing else; a known
   id with other bytes is `refused`. `issued at` is at most the removal
   maximum age plus the clock skew in the past, and at most the clock skew
   in the future.
4. Key 4 holds a grant whose id equals key 5; otherwise `stale` (a newer
   pairing of that device stays).
5. That grant's authorizing owner equals the signer's grant's authorizing
   owner; otherwise `refused`.

The host stores the removal id, the record hash and the result durably for
every result from check 3 on, before it acts; for `applied` it then removes
the grant, whose connections close with `GRANT_REVOKED`. It keeps removal
ids for the maximum age plus the skew.

## 10. Pairing

Pairing turns an unknown endpoint (the **joiner**) into one with a grant on
a host endpoint. The host endpoint creates an **invitation**; the joiner
receives its **ticket**. Invitations belong to the endpoint that created
them: the ticket names that endpoint's identity key, and other endpoints on
the same device know nothing of it.

### 10.1 Invitation kinds

The host picks the kind when it creates the invitation. It is fixed in the
host's record and in the ticket.

| Kind | Value | Flow |
|---|---|---|
| In person | 1 | Join proof, then the host owner approves with one tap. No code. |
| Send link | 2 | Join proof, then the code exchange with a 6-digit code shown on the host. |
| Direct | 3 | Lookup, code exchange with the 12-character code, then the host owner approves (10.9). |

Browsers always use "Send link". Kind 3 has no ticket and never appears in
one: a ticket with kind 3 is `unknown_kind` (10.2).

**The kind is believed only as far as the ticket's arrival supports it.**
"In person" skips the code, so it is safe only when the ticket came straight
off the host's screen. The joiner's app tells the pairing flow how the ticket
arrived:

- **in-app scan:** the app's own scanner read the QR code from a screen in
  front of the user;
- **link:** anything else, including a link opened from another app or a
  browser, a pasted link, and a QR code opened through the system camera
  (which hands the app a link).

A ticket of kind 1 is accepted only from an in-app scan. Any other arrival
of a kind 1 ticket ends the flow with `PAIRING_FAILED` before the joiner
dials, so a swapped link that claims "in person" can neither be approved by
a fake host nor end as "already paired"; nothing is pinned. A held pin does
not change this. Kind 2 is accepted from either arrival. Vectors:
`pairing-e2e.json` `swapped_in_person_link`.

**A device never pairs with itself.** A joiner whose own identity key is the
ticket's host identity ends the flow with `PAIRING_FAILED` before it dials
(10.3 covers the host side). Vectors: `pairing-e2e.json` `own_ticket`.

### 10.2 Ticket

The ticket is a canonical CBOR map:

| Key | Value |
|---|---|
| 1 | uint: ticket version (`1`) |
| 2 | uint: kind (10.1) |
| 3 | bytes: host identity key (65 bytes) |
| 4 | bytes: invitation id (16 random bytes) |
| 5 | bytes: secret (16 random bytes, single use) |
| 6 | uint: `expires_at` (host clock) |
| 7 | array of 0 to 8 route hints, each a text string of 1 to 255 bytes |

- Decoders check the **version first** (key 1); an unsupported version is
  `unsupported_version` even if other fields are unknown. An unknown kind is
  `unknown_kind`. Other field errors are `field`; CBOR errors are `cbor`.
- **Route hints** are in the host's order of preference (10.2.1). The ticket
  accepts any text of 1 to 255 bytes there; reading a hint happens later and
  never makes the ticket invalid.
- `expires_at` is creation time + **600 s**.
- The **ticket hash** is `H(ticket CBOR bytes)`, over the canonical encoding.
  Because decoders accept only canonical CBOR, the joiner can hash the bytes
  it decoded from the link and the host the bytes it created; both are the
  same.
- **Link form:** the ticket bytes in base64url (RFC 4648 section 5) **without
  padding**, placed in the URL fragment after `#`. Decoders reject `=`, the
  standard alphabet's `+` and `/`, any other character, a length of 1 mod 4,
  and a last character whose unused low bits are not all zero (all
  `encoding`). So each byte string has exactly one accepted text form, the
  one an encoder writes. The fragment never reaches a web server.

Expiry:

- The host accepts a join proof while `now < expires_at` on its own clock.
  At `expires_at` the invitation ends and its join-only connections close
  with `INVITATION_INVALID`.
- The joiner refuses to start while `now ≥ expires_at + 600` (its clock may
  differ). A joiner that is only learning the outcome of an earlier attempt
  (10.6) reconnects even after that.

Invitations live only in the host endpoint's memory in version 1. When the
host restarts, its open invitations end; their tickets then fail with
`INVITATION_INVALID`, and the owner creates a new invitation. Grants made
before the restart are stored and stay.

The joiner pins the ticket's host identity for step 1 on first contact.

#### 10.2.1 Route hints

The **scheme** is the text before the first `:`, matched exactly
(lowercase only). Each hint is either usable or **skipped** with a reason.
A skipped hint is not an error: the joiner tries the next one.

| Scheme | Form | Meaning |
|---|---|---|
| `tcp` | `tcp://<host>:<port>` | A direct TLS connection. |
| `wss` | `wss://<host>[:<port>]<path>` | The same TLS connection, carried in WebSocket binary messages inside an outer TLS connection to a tunnel the host's owner runs. |
| `mdns` | `mdns:<instance>` | Browse for this service instance on the local network. |
| `relay` | `relay://<host>:<port>/<relay id>/<handle>` | Through a relay ([relay.md](relay.md)). Readers that do not dial relays skip it as `reserved`. |
| `ssh`, `ws` | reserved | Kept for transports that never appear on the wire (`ssh`, plain `ws`). Skipped as `reserved`. |
| anything else, or no `:` | | Skipped as `unknown_scheme`. |

A `tcp`, `wss` or `mdns` hint that breaks its grammar is skipped as
`malformed`:

- `<port>`: decimal 1 to 65535, ASCII digits only, no sign, no leading zero.
  In a `tcp` hint the port is the text after the last `:`.
- `<host>` is read by its shape:
  - in square brackets: an IPv6 address in an RFC 4291 section 2.2 text form
    (an embedded IPv4 part follows the IPv4 rule below), with no zone id;
  - only ASCII digits and dots: an IPv4 address, four decimal parts 0 to 255
    with no leading zeros (`1.2.3` and `192.168.01.20` are malformed, not DNS
    names);
  - anything else: a DNS name. Labels of 1 to 63 ASCII letters, digits and
    `-`, not starting or ending with `-`, joined by single dots; at most 253
    bytes; no trailing dot; the last label is not all digits. A reader
    lowercases the name (ASCII letters only) and uses and compares only the
    lowercased form.
- Nothing else may appear in a `tcp` hint: no user part, path, query or
  fragment.
- `wss`: `<host>` as above, then an optional `:<port>` (443 when absent),
  then `<path>`: 1 to 200 bytes of ASCII letters, digits and `.`, `_`, `~`,
  `/`, `-`, starting with `/` and ending with `/mousse-net/1`. No user part,
  query, fragment or percent-encoding. The host and port end at the first
  `/` after `wss://`; a port is the text after a `:` that follows the host
  (after the `]` of an IPv6 host). A vector's result always gives the port,
  443 when the hint has none.
  The outer TLS connection verifies the tunnel's certificate for `<host>`;
  the inner one is checked against the pin like any other route.
- `<instance>`: 1 to 63 bytes of UTF-8 with no control characters (Unicode
  general category Cc).

An IPv6 host is its 128-bit address: every accepted text form of the same
address (upper or lower case hex, leading zeros in a group, `::`, an
embedded IPv4 part) is the same host, and the text form is not kept.
Vectors give it as the 16 address bytes in hex. An IPv4 host is given in
dotted decimal, and a DNS name lowercased.

A `relay` hint names a relay and the host's handle there: `<host>:<port>`
by the `tcp` rules, then the relay id and the handle, each 32 bytes in
base64url without padding, the whole hint at most 255 bytes. The relay id
pins the relay's own TLS key; the host is still checked against the
ticket's pin inside. A joiner dials it only if the owner approved its
destination, `relay://<lower-case host>:<port>`. Vectors: `ticket.json`
`relay_hints`.

Whichever route reaches it, the host is checked against the ticket's pin. A
pin mismatch on a LAN candidate means another endpoint holds that address
(5.4): try the next candidate, with no warning and no re-pin. Vectors:
`ticket.json` `route_hints`.

### 10.3 Join proof

A joiner in a pairing flow sends `JOIN_PROOF` on **every** connection of
the flow, right after its own `HELLO`, without waiting for anything from
the host. It cannot know whether the host already holds a grant for it
(after a lost `PAIRED`, 10.6, it may), and the host never says that it is
waiting for a proof. A host whose step 2 found a live grant has already sent
`AUTHORIZED {live}`; it answers the proof as section 8, step 3 says, and the
joiner takes that answer, not step 2's notice, as the outcome (10.6 rule 8).
A caller that is not in a pairing flow never sends `JOIN_PROOF`. Vectors:
`pairing-e2e.json` (the `connect` steps, `outcome_after_lost_paired`,
`role_change_not_committed` and `re_pair_while_granted`).

The proof is:

```
key   = HKDF-SHA256(salt = invitation id, IKM = secret,
                    info = "mousse-join-proof-v1", L = 32)
input = CBOR {1: "mousse-join-v1",
              2: invitation id (16 bytes),
              3: host identity key (65 bytes),
              4: joiner identity key (65 bytes),
              5: join exporter (32 bytes, label EXPORTER-mousse-join-v1)}
mac   = HMAC-SHA256(key, input)
```

The host recomputes `mac` with the identity keys from this TLS session and
compares in constant time. The host closes with `INVITATION_INVALID` if the
invitation is unknown, not open, or the `mac` is wrong; it uses one code for
all of these on purpose (on a live connection it answers `AUTHORIZED
{live}` instead, section 8). A denied identity, and a joiner whose identity
key is the host's own, get `NOT_AUTHORIZED`. A second `JOIN_PROOF` on a
join-only connection is `PROTOCOL_ERROR`. Vectors: `pairing-attempts.json`
`join_proof_from_own_identity`.

The proof shows that the joiner holds the ticket, bound to this TLS session
and to both identities, so it cannot be replayed on another connection or by
another device.

The joiner's **name** (`JOIN_PROOF` key 3) is not covered by the MAC. It is a
claim the joiner makes about itself, shown to the host owner as sent and
stored in the grant. The field allows 1 to 128 bytes. The proof goes out
before the code has shown that the far end is the real host, so the name
reveals no more than needed:

- "In person" (from an in-app scan, 10.1): the app sends
  `<computer> (<profile>)`: the computer name, one space, and the joining
  profile's label in parentheses, such as `Phone (Work)`. A joiner with no
  profile label sends `<computer>` alone.
- "Send link": the app sends `<computer>` only, never the profile label.
  The label is sent only after the host's confirmation verified; version 1
  has no message for that yet, so a send-link grant is named after the
  computer until a later minor version adds one ([`privacy.md`](privacy.md)).

The host shows and stores the name exactly as sent; it never splits it.
Vectors give the two parts and the name they make: in `pairing-e2e.json`
the joiner is computer `Phone` with profile label `Work`, so its in-person
proof names `Phone (Work)` and its send-link proof `Phone`; in
`pairing-attempts.json` each joiner's computer name is its letter with
profile label `Work` (`a (Work)` in person, `a` for a send link).

### 10.4 In-person flow

1. Join proof accepted; the host sends `AUTHORIZED {join_only}`.
2. The host asks its owner: "Is the device next to you?", showing the
   joiner's name from `JOIN_PROOF`.
3. On approval the host enrolls (10.8). The owner may choose the role of
   this grant with the approval; without a choice it is the role fixed in
   the invitation. The choice applies to this enrollment only and does not
   change the invitation. On decline it closes with `PAIRING_DECLINED`; on
   cancel, `CANCELLED`.
4. The joiner accepts `PAIRED` and becomes live (8.2).

### 10.5 Binding transcript

The code exchange is bound to this canonical CBOR map:

| Key | Value |
|---|---|
| 1 | text `"mousse-pair-v1"` |
| 2 | bytes: ticket hash (32) |
| 3 | uint: kind (mode) |
| 4 | uint: ticket version |
| 5 | array `[[1, joiner identity key], [2, host identity key]]` |
| 6 | bytes: pair exporter (32, label `EXPORTER-mousse-pair-v1`) |

The initiator comes first, as CPace requires; the numbers are the roles in
the exchange (1 = initiator = joiner, 2 = responder = host). The transcript
bytes are the exchange's channel identifier (`CI`) and are bound into **both**
key confirmations ([`cpace.md`](cpace.md)). Each side builds them from its own
values: the ticket it holds, the identity keys of this TLS session and its
own exporter. Vectors: `join-proof.json` `binding`.

#### Session id

Each attempt has its own session id:

```
sid = H(CBOR {1: "mousse-pair-sid-v1",
              2: attempt id (16 bytes),
              3: pair exporter (32 bytes)})
```

`sid` is 32 bytes and public. A fresh attempt id gives a fresh `sid`; the same
attempt id on another TLS session gives another `sid`, because the exporter
differs. Vectors: `join-proof.json` `sid`.

#### Code exchange

"Send link" runs CPace profile 1 ([`cpace.md`](cpace.md)) once per attempt
with these inputs:

| CPace input | Value |
|---|---|
| `PRS` | the attempt's code (10.6): its 6 ASCII digits |
| `CI` | the binding transcript bytes |
| `sid` | the attempt's session id |
| `ADa`, `ADb` | empty. Senders MUST send empty AD. A receiver refuses a share with non-empty AD as malformed, before any group work. |
| Initiator (A) | the joiner |
| Responder (B) | the host |

The three CPace messages travel in `CODE_EXCHANGE {attempt, payload}`, one
message per payload, in this order:

1. joiner → host: `msg_a`;
2. host → joiner: `msg_b` (the host's share and its confirmation `Tb`);
3. joiner → host: `msg_c` (the joiner's confirmation `Ta`).

The joiner sends `msg_c` only after `Tb` verified. The host enrolls (10.8)
only after `Ta` verified, and its `PAIRED` is how the joiner learns that the
host accepted `Ta`. Any CPace error (a malformed message, an invalid point,
a wrong tag, a message out of order) fails the attempt: the side that saw it
sends `CODE_ABORT {attempt, PAIRING_FAILED}` and gives no other detail. The
CPace output `ISK` is not used by pairing in version 1.

### 10.6 Send-link flow and the code

1. Join proof accepted; the host sends `AUTHORIZED {join_only}` and shows the
   invitation's current **code**: 6 ASCII digits. Generation: draw a uniform
   32-bit integer `x`; redraw while `x ≥ 4 294 000 000`; the code is
   `x mod 1 000 000`, zero-padded to 6 digits. The first code is drawn when
   the invitation is created.
2. The owner types the code into the joiner. It reaches the joiner
   independently of the link (from the host's screen or a separate call). The
   digits are never transmitted. **Codes are typed only where the joiner's
   identity lives:** in the installed app, or in a web client at a trusted
   origin the user bookmarked or installed. A page reached from a link (a
   handoff or landing page) never asks for or receives a code; it can only
   hand the ticket to the app or the trusted client. A script on any page
   that opens the link can read the ticket in its fragment
   ([`privacy.md`](privacy.md)), so the code is what keeps such a page from
   pairing.
3. The joiner starts an **attempt**: it picks a random 16-byte attempt id and
   runs the code exchange (10.5) as **initiator**. The host runs it as
   **responder** and answers with the same attempt id.
4. **A fresh code for each attempt.** When the first message of a new attempt
   arrives, the host debits it (10.7) and takes the code it is showing; that
   is the attempt's code. If attempts are left, the host draws a new code and
   shows it in place of the old one. A wrong guess therefore says nothing
   about the next code, and after a failure the owner reads the new code off
   the host's screen. When no attempts are left, no new code is drawn.
5. An attempt **succeeds** only when both confirmations verify: the joiner
   verifies the host's, the host verifies the joiner's. Then the host
   enrolls (10.8). The joiner accepts `PAIRED` only after it has verified the
   host's confirmation, and then becomes live (8.2).
6. Either side ends a failed attempt with `CODE_ABORT {attempt,
   PAIRING_FAILED}`. The joiner shows the attempts it has left and the owner
   may type the new code on the same connection. Because a right-looking code
   that fails may mean the far end is not the real host, the joiner says so:
   "That code didn't work. If you typed it exactly as shown on the other
   device, the link may have been swapped; get a new one another way."
7. **Outcome after a lost connection.** Once the joiner has verified the
   host's confirmation, it marks the outcome pending (10.7) and sends
   `msg_c`; from then on the host may have enrolled it. If the connection
   closes before `PAIRED` arrives, the joiner does not count the attempt as
   failed yet. It reconnects with the same ticket, even with no attempts
   left and even after the ticket's joiner-side expiry, sends `HELLO` and
   `JOIN_PROOF` as usual, and the host's answer to the proof gives the
   outcome (a host that holds a grant for it sends step 2's `AUTHORIZED
   {live}` first, then answers the proof; section 8):
   - `PAIRED {host name, role}`: this invitation enrolled it, with that
     role: the host found its grant's enrollment receipt (section 7). The
     pairing succeeded; the joiner pins the ticket's host identity as for
     any `PAIRED`.
   - `AUTHORIZED {live}`: the device has access, but not from this
     invitation (its grant came from elsewhere, for example an earlier
     pairing). The role this invitation offered is **not** in effect and the
     joiner must not report it. The flow ends "already paired" and the
     joiner pins the ticket's host identity.
   - `AUTHORIZED {join_only}`: not enrolled. With attempts left the owner
     may type the current code; with none left the flow ends with
     `ATTEMPTS_EXHAUSTED`.
   - A close with `INVITATION_INVALID` or `ATTEMPTS_EXHAUSTED`: not
     enrolled; the flow ends.

   The joiner keeps "outcome pending" in its stored flow record (10.7), so
   it still learns the outcome after the app was closed or killed. It clears
   the mark only once the outcome is settled: after `PAIRED` or `AUTHORIZED
   {live}`, once the pin is durably stored; otherwise when the answer above
   arrives.

   **A proof that gets no answer ends the flow.** If the answer to the proof
   does not arrive within 10 s (8.2), the joiner closes with
   `NOT_AUTHORIZED` and the flow ends with that code, also while it is
   learning a pending outcome: it does not reconnect on its own. The
   pending mark stays stored, so opening the same ticket again starts a new
   flow that reconnects and asks again (allowed with no attempts left and
   after the joiner-side expiry, as above). Vectors: `pairing-e2e.json`
   `outcome_after_lost_paired`, `role_change_not_committed` and
   `lost_paired_then_proof_timeout`.
8. **"Already paired" needs a reason to trust the host.** A link travels
   over channels anyone may tamper with, so a swapped link can name another
   key, and step 1 then passes against whoever holds it. A "Send link"
   joiner therefore accepts `AUTHORIZED {live}` or `PAIRED` as the answer
   to its proof (on a connection that step 2 made live) only when it
   already held a pin for the ticket's host identity before this flow
   started (an earlier pairing, not this ticket), or while it is learning
   the outcome of its own lost `PAIRED` (7). Otherwise the flow ends with `PAIRING_FAILED`, the joiner closes the
   connection with it (9), and nothing is pinned. A joiner with no pin whose
   host still holds a grant for it is not stuck: the host answers a valid
   proof with `AUTHORIZED {join_only}` and the pairing replaces the grant
   (section 8). An in-person ticket comes only from an in-app scan (10.1), so
   this rule does not apply to it. Vectors: `pairing-e2e.json`
   `send_link_live_needs_a_pin` and `re_pair_while_granted`.
9. **A failed flow closes the connection.** When the joiner's flow ends
   with an error code C (for example `PAIRING_FAILED` under 8, or
   `ATTEMPTS_EXHAUSTED` after its third failed attempt), the joiner first
   sends any message the same step produced (such as its `CODE_ABORT`),
   then closes the connection with C: one `GOAWAY(C)` (section 1), with no
   `CODE_ABORT` of its own for the flow. If the flow ended because the
   host closed the connection or the connection broke, the joiner sends
   nothing more. A failed attempt (6) is not a failed flow: it sends only
   `CODE_ABORT` and the connection stays up.

**Random draws in the vectors.** The order of random draws is a convention
of the vector harness, not a requirement: an implementation may draw in any
order, from any secure source, and replays the vectors by feeding its draws
from the listed values. The reference implementation draws as follows, and
the vectors list draws in this order: the host draws the invitation id (16
bytes), the secret (16 bytes) and, for "Send link", the first code when it
creates the invitation; for each new attempt, the next code (if attempts are
left) and then its CPace scalar, after the debit and before it reads that
attempt's first message. The joiner draws, for each attempt, the attempt id
(16 bytes) and then its CPace scalar. A code is one 32-bit draw, repeated
while it is at least 4 294 000 000; a CPace scalar is one 32-byte draw
(repeated only in the 2^-252 case of zero, [`cpace.md`](cpace.md) 5.2).
Vectors: `pairing-attempts.json` lists every draw of every sequence.

### 10.7 Attempt limits

- **Debit first.** Each side debits one attempt **before** any exchange work
  for it: the joiner when the code is submitted, the host when the first
  message of a new attempt arrives. A debit is never returned, whether the
  attempt fails, is aborted or its connection drops.
- **Host:** 3 attempts per invitation, across all connections and routes.
  When none are left and no attempt is running, the invitation ends and its
  join-only connections close with `ATTEMPTS_EXHAUSTED`. A new attempt with
  none left closes its connection with `ATTEMPTS_EXHAUSTED`.
- **Joiner:** 3 attempts per ticket, counted across every time the link is
  opened. The joiner stores a **flow record** keyed by the ticket hash: the
  attempts it has left and whether an outcome is pending (10.6 rule 7). It
  loads the record when the same ticket is opened again, so neither
  reopening the link nor killing the app resets the count. A record for
  another ticket hash is refused. Every change to the record is written
  durably **before** what depends on it goes out:
  1. **The debit:** written before the attempt's first message (`msg_a`).
  2. **The pending mark:** set after the host's confirmation verified and
     written before the joiner's own confirmation (`msg_c`) goes out, so a
     crash right after sending it cannot forget that the host may have
     enrolled it.
  3. **Clearing the mark:** only once the outcome is durable: after
     `PAIRED` or "already paired", once the pin is stored; otherwise with
     the answer that settled it.

  Each write is atomic and conditional on the stored record being the one
  this flow last read or wrote (compare and swap), so two flows on the same
  ticket (two windows, or a link opened twice) cannot both spend the same
  attempt. If a write fails or the stored record changed, nothing that
  waited for it is sent and the flow ends with `INTERNAL_ERROR`; opening the
  ticket again starts from the stored record. Vectors: `pairing-e2e.json`
  (`persist` outputs; `crash_after_pending_mark`).
  After the third failure the flow ends; a later start with no attempts left
  and nothing pending ends at once with `ATTEMPTS_EXHAUSTED`. A fake host can
  use up the joiner's attempts but cannot cancel the real host's invitation;
  each side's count is local. Vectors: `pairing-e2e.json`
  `joiner_cap_survives_reopening`.

  The record is canonical CBOR `{1: "mousse-joiner-flow-v1", 2: ticket hash
  (32 bytes), 3: attempts left (0 to 3), 4: outcome pending (0 or 1)}`. It
  is local state: its format is fixed so stored records survive upgrades.
- **Attempt key.** The host keys attempts by **(TLS session, attempt id)**.
  An attempt id seen on another TLS session is a new attempt on this one:
  it is debited first like any other, and it can never succeed, because its
  messages are bound to the other session's exporter and the other
  joiner's identity. Vectors: `pairing-attempts.json`
  `attempt_replayed_on_another_connection_is_debited`.
- **No resends.** The transport is reliable and ordered, so a sender never
  sends a message twice. The connection's gate (8.1) runs first; the rules
  below apply only to `CODE_EXCHANGE` and `CODE_ABORT` it allows
  (join-only). For a `CODE_EXCHANGE` on an attempt the host already has on
  this TLS session:
  1. on an attempt that ended (succeeded, failed, or aborted by the
     joiner): send `CODE_ABORT {attempt, PAIRING_FAILED}`, with no debit
     and no other work;
  2. on a running attempt: the payload is the next exchange message, and
     the attempt goes on or fails as 10.5 says. A repeated message does not
     fit the next step, so it fails the attempt.

  A `CODE_ABORT` from the joiner ends a running attempt (its debit stays).
  A `CODE_ABORT` for an attempt the host does not have on this TLS session
  is ignored. On the joiner, a host message that does not fit the current
  attempt's next step fails that attempt in the same way; any message for
  an attempt that is not its current one is ignored. Vectors:
  `pairing-attempts.json`.

### 10.8 Enrollment

Enrollment is atomic and happens at most once per invitation, across all
routes:

1. Mark the invitation consumed.
2. Add the grant (identity, the name from `JOIN_PROOF`, the role and
   authorizing owner fixed in the invitation, or, in person, the role the
   owner chose with the approval, 10.4). If the identity already holds
   a grant on this endpoint (for example two invitations joined at the same
   time), the new grant replaces it (section 7).
3. Bind this connection to the new grant; it becomes live.
4. Send `PAIRED {host name, role}` with the grant's role. The host name is
   the host endpoint's display name, `<computer> (<profile>)` in the app.
5. Close every other join-only connection of the invitation with
   `INVITATION_INVALID`.

Step 2's grant records this invitation as its enrollment receipt (section
7), in the same atomic step.

Cancelling or declining an invitation grants nothing. A joiner that already
holds a live grant gets `AUTHORIZED {live}` at step 2; if the invitation is
still open, its valid proof starts a normal pairing that replaces the grant
(section 8, step 3). Otherwise the host's answer is `PAIRED` again if this
invitation made the grant, carrying the grant's role now (an edit since,
section 7, shows), which is how a joiner whose `PAIRED` was lost
learns that it was enrolled (10.6 rule 7), and `AUTHORIZED {live}` if it did
not; then pairing ends with "already paired". A "Send link" joiner believes
either answer only for a host it pinned before the flow, or for its own
lost `PAIRED` (10.6, rule 8). When a pairing replaces a grant, the
connection it ran on is bound to the new grant and every other connection
bound to the old one closes with `GRANT_REVOKED`.

### 10.9 Direct flow

*The joiner's side (its attempt ledger and pending record) follows; this
section gives the code, the binding and the host's side.*

The direct flow pairs two endpoints with no ticket: the host shows its
address and a **direct code**, and the joiner's owner types both. The host
owner then allows the device, as in person (10.4).

#### Code

- **Alphabet:** Crockford base32, `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no
  `I`, `L`, `O`, `U`).
- **Length:** 12 characters. The host shows them as three groups of four
  joined by `-`: `K7QM-2XPA-9RTE`.
- **Generation:** draw 12 bytes; byte `b` becomes `ALPHABET[b & 0x1f]`.
  Every character is uniform and independent; nothing is redrawn except as
  the host's lookup rule below says.
- **Lookup `L`:** characters 1 to 4 (20 bits). It finds the invitation on
  the host and is sent inside TLS; it is not secret once used. When a new
  code's lookup equals the lookup of another open direct invitation of the
  same endpoint, the host draws a whole new code.
- **Secret `S`:** characters 5 to 12 (40 bits), as their 8 ASCII bytes. It
  is the code exchange's password and is never sent. It is independent of
  `L`.
- **Entry:** the joiner reads typed text as follows. ASCII spaces (0x20) and
  `-` are dropped; ASCII letters are uppercased; `O` reads as `0`, and `I`
  and `L` as `1`. Any other character is `bad_character`. If what remains is
  not 12 characters long, it is `wrong_length`. A bad character is reported
  before a wrong length. Either error means the text is not a code: nothing
  is dialled and no attempt is spent.

The code, `L` and `S` are never logged. Vectors: `direct-code.json`.

#### Invitation

The host keeps each direct invitation **in memory only**: the invitation id
`I` (16 random bytes), the code, `expires_at`, the attempts left, the role
it offers and the authorizing owner, the approval requests, and the
outcomes it keeps for recovery (below). A restart ends every direct
invitation; grants they made stay. Creating one draws `I` (16 bytes), then
the code (12 bytes, drawn again while its lookup is the lookup of another
open direct invitation of this endpoint). At most `DIRECT_MAX_OPEN` (4)
direct invitations are open at once on an endpoint; another is refused
until one ends. An invitation **takes attempts** while it is open and
before `expires_at` = creation time + `DIRECT_INVITE_LIFETIME_SECS` (600).
It ends on enrollment, decline, the owner's cancel, exhaustion, and at
expiry unless a request is still inside its Allow window. The host's own
timer ends it at expiry; an attempt refused at `expires_at` closes only its
connection.

#### Binding

```
D   = H(CBOR {1: "mousse-direct-invite-v1", 2: L (text, 4), 3: I (bytes, 16)})
CI  = CBOR {1: "mousse-direct-pair-v1",
            2: D,
            3: 3,                                 (kind)
            4: 1,                                 (direct ceremony version)
            5: [[1, joiner identity key], [2, host identity key]],
            6: pair exporter (EXPORTER-mousse-pair-v1)}
sid = the attempt's session id (10.5)
PRS = S, its 8 ASCII bytes
```

`H` is SHA-256 and the maps are canonical CBOR (section 3). The code
exchange is CPace profile 1 as in 10.5: empty AD, the joiner the initiator,
the host the responder, both confirmations, `ISK` unused. `D` holds only
public values, and nothing on the wire before `msg_a` depends on `S`;
`msg_a` does, through the generator ([`cpace.md`](cpace.md) 5.1). Key 4 is
1 for the life of kind 3 and never appears on the wire; a new ceremony is a
new kind. Vectors: `cpace-ristretto255-sha512-mousse.json` `pairing_runs`
(every value from the inputs), `direct-host.json` `before_msg_a`.

#### Lookup

The joiner dials the typed address, sends `HELLO` and waits for the host's
(it needs `agreed`; with `agreed < 4` it closes with `UNSUPPORTED_VERSION`),
then sends `JOIN_DIRECT {1: L, 2: name}`. The name is the computer name, as
for a sent link (10.3). `JOIN_DIRECT` passes the host's gate as
`JOIN_PROOF` does (8.1); step 2 runs first as for any connection, and its
`AUTHORIZED {live}` notice is not the answer. The host answers it only on a
connection its TCP listener accepted, the one that took a
pre-authorization place for it at accept; on any other (WebSocket, pipe,
relay circuit, a connection no listener admitted) it closes with
`INVITATION_INVALID` at once, with no hold. A host that admits no new
connections for now (paused) closes it with `INTERNAL_ERROR`. From a live
connection, `JOIN_DIRECT` first takes a new pre-authorization place counted
against the connection's source address; with none free the host closes
with `INTERNAL_ERROR`. Then, in this order:

- the joiner's identity is the host's own, or denied here: close with
  `NOT_AUTHORIZED`, whatever the lookup;
- an invitation that takes attempts with this `L`: the connection becomes
  join-only for it and the host answers `AUTHORIZED {1: join_only, 2: I}`;
- anything else: the host holds the connection, and with it its
  pre-authorization place, for `DIRECT_MISS_HOLD_MS` (1000 ms), then closes
  it with `INVITATION_INVALID`. The 10 s wait for a `JOIN_PROOF` (section 8,
  step 2) stops for a held connection: the hold's close, after the full
  hold, is the only one. A device that holds a grant here gets the same
  answer. Every "no open invitation" (another endpoint's code, a typo
  in `L`, expired, used up, cancelled, a restart) looks the same.

#### Attempt

**One attempt per connection.** The joiner debits its own count, then sends
`CODE_EXCHANGE {A, msg_a}` with a fresh attempt id `A`. The host, for the
first message of a new attempt:

1. refuses it at or after `expires_at`, or once the invitation stopped
   taking attempts, by closing with `INVITATION_INVALID` (a running attempt
   ends the same way: a code passes only before `expires_at`);
2. refuses a second attempt on the connection by closing with
   `PROTOCOL_ERROR`, with no debit;
3. closes with `ATTEMPTS_EXHAUSTED` when none are left;
4. otherwise **debits first** (`DIRECT_HOST_ATTEMPTS`, 5 per invitation,
   across all connections), tells its owner the attempts left (the code
   stays the same) and draws the attempt's CPace scalar, then answers
   `CODE_EXCHANGE {A, msg_b}`.

A repeat on an attempt follows 10.7 ("No resends"). A wrong code fails at
the joiner when it checks `Tb`: it sends `CODE_ABORT {A, PAIRING_FAILED}`
and closes; the next try is a new connection. When no attempts are left, no
attempt runs and no request is inside its Allow window, the invitation ends
and its join-only connections close with `ATTEMPTS_EXHAUSTED`.

#### Requests

When the host verifies `Ta`, the device **passed the code**. The host opens
an **approval request keyed by (invitation, joiner identity)**, not by
connection, and asks its owner, showing the name from `JOIN_DIRECT`, the
short device id and the role. The role and the name belong to the request;
the role the owner picks with the answer goes to that enrollment only.

- **One request per identity.** The same identity passing again (on a new
  connection) keeps its request: the same id, now pointing at the new
  connection. Another identity that passes gets its own request.
- A request is **connected** while its connection is up and **away** once it
  closed without `CANCELLED`; it is kept either way.
- **The Allow window.** A request may be allowed, and claimed by recovery,
  until `DIRECT_ALLOW_WINDOW_SECS` (300) after its identity first passed the
  code, also past `expires_at`. Then it ends, and its connection, if up,
  closes with `INVITATION_INVALID`. While any request is inside its window
  the invitation neither ends at expiry nor for lack of attempts; at
  `expires_at` it stops taking lookups and attempts, and its join-only
  connections without a request close with `INVITATION_INVALID`.
- **Allow, connected:** enrollment (10.8) on that connection with receipt
  `I`, except that the grant it adds is provisional (below); the host sends
  `PAIRED {host name, role}`. Every other request ends and its connection
  closes with `INVITATION_INVALID`.
- **Allow, away:** the request is marked allowed, every other request ends
  as above, and the invitation takes no lookups or attempts. The device's
  recovery (below) is enrolled at once. Enrollment always happens on a
  connection of the device that passed the code.
- **Decline:** the request's connection closes with `PAIRING_DECLINED` and
  the invitation ends; every other connection closes with
  `INVITATION_INVALID`.
- **The joiner cancels.** Connected: `CODE_ABORT {A, CANCELLED}`, then a
  close with `CANCELLED`; the host ends the request and closes the
  connection with `CANCELLED`. Only the attempt that passed
  counts, the one the request remembers (a recovery that moves the request
  to another connection keeps it): a `CODE_ABORT` naming another attempt,
  one merely running on the request's connection included, ends no
  request (that running attempt still counts as failed). Away: the cancel comes with its recovery.
  Only a close without `CANCELLED` keeps a request.
- **Cancel crossing Allow.** The cancel wins while the grant is
  provisional. A `CODE_ABORT {A, CANCELLED}` for the attempt that passed
  (it passes the live gate, 8.1), or a `GOAWAY` with `CANCELLED`, on the
  connection the host enrolled, or a cancel by recovery, removes the
  provisional grant and nothing else, and the host closes with `CANCELLED`.
  A committed grant is never cancelled: the `CODE_ABORT` is ignored, the
  `GOAWAY` is an ordinary close, and a recovery's cancel is answered as a
  recovery without one (`PAIRED`).
- A declined or cancelled request's outcome is kept with the invitation
  until its Allow window ends, for its recovery. Which identities passed
  the code is kept until the host forgets the invitation.

#### Provisional grant

Direct enrollment adds a **provisional grant**: the identity, the request's
name, the role the owner allowed, the invitation's authorizing owner and
grant expiry, receipt `I`, and a mark that a direct invitation made it. It is
stored with the grant table and survives a restart. It is not the
identity's grant yet: step 2 binds a new connection of that identity to it
(section 8), but a grant the identity already holds stays, and so do the
connections bound to that grant.

- **Before it is made,** at Allow or when a recovery claims an Allow, the
  host checks everything that can fail: the identity is not denied, and
  the grant expiry, if any, is still ahead. A failed check changes nothing
  in the grant table, and a claim that fails it sends nothing before its
  close (no `AUTHORIZED`). Making it never closes the connection it is
  made on: that connection is detached from any grant first, even when it
  was bound to the provisional grant this one replaces. Allow is refused (`denied`, checked first, or
  `grant_expired`); at a claim the invitation ends with
  `INVITATION_INVALID` (its requests, the allowed one too, end as
  dismissed) and the connection closes with it.
- **It commits** on the first stream frame of any connection bound to it:
  the connection the host enrolled, a recovery connection, or the joiner's
  first ordinary connection after `PAIRED`. The I/O layer reports that
  frame and has the commit done and stored before it releases the stream
  (8.1), so a restart never finds provisional a grant a stream ran under.
  Committing first checks that the identity is not denied and the grant has
  not expired, then, in one step, replaces the identity's grant, if any
  (its connections close with `GRANT_REVOKED`), and makes the provisional
  grant the identity's grant, with the same id and receipt `I`. The
  connections bound to it stay bound. When a check fails, the provisional
  grant is removed, its connections close with `GRANT_REVOKED`, and the old
  grant and its connections stay.
- **It is removed** by a cancel (above), by a denial of the identity, at its
  expiry, and when another direct invitation makes a new provisional grant
  for the identity. Its connections close with `GRANT_REVOKED` (the
  cancelling connection with `CANCELLED`), before the host reports the
  removal; the removal is reported also when no connection was bound.
- On the enrolled connection, a `CODE_ABORT` for the attempt that passed
  with any code other than `CANCELLED` passes the gate and is ignored.

A recovery opens no stream before the host's answer (section 8, step 4), so
a joiner that cancelled never commits the grant it is cancelling. A device
that already held a grant may commit through another of its connections
before its cancel arrives; that cancel then comes too late.

#### Recovery

A joiner whose connection closed after the host's confirmation verified
reconnects **pinned** to the host key it verified and sends `JOIN_DIRECT
{1: L, 2: name, 3: I, 4?: 1}` (key 4: it cancels). No code is needed. The
host answers, in this order:

1. an unexpired provisional or committed grant for this identity, made by
   a direct invitation, with receipt `I` (also after a restart; a receipt
   from a ticket never matches): with the cancel flag, a provisional grant is
   removed and the host closes with `CANCELLED`. Otherwise, and for a
   committed grant whatever the flag, the host answers `PAIRED {host name,
   role}` with the grant's role. When step 2 did not bind the connection to
   that grant (it appeared later, for example by an Allow on the original
   connection, or step 2 bound the identity's older grant), the host binds
   it first, and sends `AUTHORIZED {live}` first when step 2 sent none;
2. no direct invitation `I` with this `L`: the miss hold, as for a lookup;
   from here on, with the cancel flag the host first retires every
   attempt and pairing connection of this identity on the invitation (they
   close with `CANCELLED`), whatever the answer below;
3. a kept outcome for this identity: close with `PAIRING_DECLINED` or
   `CANCELLED`; with the cancel flag, an invitation its retirements leave
   with nothing to take then ends, as in 4;
4. with the cancel flag (its attempts and connections retired, so a
   confirmation still on its way opens no request after the cancel): the
   request, if any, ends; then the host closes with
   `CANCELLED` (an invitation that no longer takes anything gets the miss
   hold instead: one neither allowed nor open with its own deadline ahead or
   a request inside its Allow window, whether or not the host's timer has
   run). An allowed request that is cancelled ends the invitation;
   so does any cancel that leaves it with no attempts, no running attempt
   and no request inside its Allow window (`ATTEMPTS_EXHAUSTED`);
5. this identity's request is allowed: `AUTHORIZED {join_only, I}`,
   enrollment on this connection, `PAIRED`;
6. its request waits for Allow: `AUTHORIZED {join_only, I}`; the request
   (same id, same prompt) now points at this connection and an older
   connection of it closes with `PATH_REPLACED`;
7. the invitation takes attempts and this identity never passed the code
   on it (the host never had its `msg_c`): `AUTHORIZED {join_only, I,
   not_received}`;
8. anything else (expired, consumed by another device, another identity,
   an identity that passed the code whose outcome is forgotten): the miss
   hold.

Only the identity that passed the code learns that it was declined.

#### Limits

| Limit | Default | Allowed |
|---|---|---|
| `DIRECT_INVITE_LIFETIME_SECS` | 600 | 60 to 600 |
| `DIRECT_HOST_ATTEMPTS` | 5 | 1 to 5 |
| `DIRECT_JOINER_ATTEMPTS` | 5 | 1 to 5 |
| `DIRECT_ALLOW_WINDOW_SECS` | 300 | 60 to 300 |
| `DIRECT_MAX_OPEN` | 4 | 1 to 4 |
| `DIRECT_MISS_HOLD_MS` | 1000 | 1000 to 5000 |

Each is set by `MOUSSE_NET_<name>` and can only move toward safety: fewer
attempts and invitations, shorter lives and windows, longer holds
([`../docs/limits.md`](../docs/limits.md)). The code's alphabet, length and
4 + 8 split are fixed.

#### Records

The host stores nothing for a direct invitation. What outlives it is the
grant enrollment made, provisional or committed, with receipt `I` and the
mark that a direct invitation made it (section 7, 10.8), stored with the
grant table; recovery reads it, also after a restart. Vectors:
`direct-host.json`.

## 11. Control messages

Each `CONTROL` frame carries exactly one message: a canonical CBOR map whose
key `0` is the message type. At most 16 384 bytes. Unknown types, missing or
extra keys and field rule failures close the connection with
`PROTOCOL_ERROR`.

| Type | Name | Direction | Fields |
|---|---|---|---|
| 1 | `HELLO` | both, first | `1`: uint major version, `2`: uint newest minor version (section 2) |
| 2 | `AUTHORIZED` | host → caller | `1`: uint state, `1` live or `2` join-only. Sent at step 2, and once more as the answer to a `JOIN_PROOF` on a live connection (section 8). Authorizes the caller on the host only (section 8, step 5). From minor `4`, in answer to a `JOIN_DIRECT` only: `2`?: bytes invitation id (16), only with join-only; `3`?: uint `1`, not received (the host has no request from this identity), only with key `2` and only in answer to a `JOIN_DIRECT` with a receipt |
| 3 | `JOIN_PROOF` | caller → host | `1`: bytes invitation id (16), `2`: bytes mac (32), `3`: text joiner name (1–128 bytes, not covered by the MAC) |
| 4 | `CODE_EXCHANGE` | both | `1`: bytes attempt id (16), `2`: bytes payload (1–1024) |
| 5 | `CODE_ABORT` | both | `1`: bytes attempt id (16), `2`: uint error code (at most 65 535; unknown codes read as `INTERNAL_ERROR`) |
| 6 | `PAIRED` | host → joiner | `1`: text host name (1–128 bytes), `2`: text role (section 7 rules). Sent on enrollment (10.8), and as the answer to a `JOIN_PROOF` on a live connection whose grant this invitation made (section 8, step 3) |
| 7 | `JOIN_DIRECT` | caller → host, minor `4` | `1`: text lookup (exactly 4 characters of the code alphabet, canonical, 10.9), `2`: text joiner name (1–128 bytes), `3`?: bytes receipt, the invitation id (16), only when recovering, `4`?: uint `1`, cancel, only with key `3` |

A flag (`AUTHORIZED` key `3`, `JOIN_DIRECT` key `4`) is absent when false
and holds exactly `1` when true; any other value is a field rule failure
(canonical CBOR has no `true`, section 3). `JOIN_DIRECT` and `AUTHORIZED`
keys `2` and `3` are defined only on a connection whose `agreed` minor is
at least `4` (section 2). Vectors: `control.json`.

## 12. Error codes

Carried as uint16 in `RESET`, `GOAWAY` and `CODE_ABORT`. Values never change.

| Code | Name | Meaning |
|---|---|---|
| 0 | `NO_ERROR` | Normal close |
| 1 | `PROTOCOL_ERROR` | A framing or message rule was broken |
| 2 | `FRAME_TOO_LARGE` | A frame length is over its limit |
| 3 | `FLOW_CONTROL` | Data beyond credit, or credit above the cap |
| 4 | `STREAM_CLOSED` | Data or `FIN` after the peer's `FIN` |
| 5 | `IDLE_TIMEOUT` | Nothing received for 45 s |
| 6 | `NOT_AUTHORIZED` | Step 2 refused, or traffic not allowed in this state |
| 7 | `GRANT_REVOKED` | The connection's grant was removed, expired or denied |
| 8 | `CERT_EXPIRED` | The session passed its effective deadline |
| 9 | `UNSUPPORTED_VERSION` | No common version |
| 10 | `PAIRING_FAILED` | A code-exchange attempt failed |
| 11 | `INVITATION_INVALID` | Unknown, expired, consumed or cancelled invitation, or a wrong proof |
| 12 | `ATTEMPTS_EXHAUSTED` | The attempt limit is used up |
| 13 | `PAIRING_DECLINED` | The host owner declined |
| 14 | `PATH_REPLACED` | A newer path replaced this connection |
| 15 | `REFUSED_STREAM` | Too many open streams |
| 16 | `CANCELLED` | Cancelled locally |
| 17 | `INTERNAL_ERROR` | Internal failure on the sender, or an unknown code |

## 13. Test vectors

[`vectors/`](vectors/README.md) holds the vectors for every rule above,
including the rejection cases. A conforming implementation passes all of
them. [`vectors/README.md`](vectors/README.md) maps each file to its
sections. `pairing-e2e.json` replays whole pairings, in person and by "Send
link", from fixed random draws: every message, frame and decision, byte for
byte, including wrong codes, the joiner's own attempt limit, tampered tickets
and a proof made on another TLS session.
