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
| Minor protocol version | `0` | `HELLO` |
| TLS ALPN | `mousse/1` | TLS ClientHello and ServerHello |

- A peer MUST reject a certificate or ticket whose major version it does not
  support (`unsupported_version`). A change of major version means devices
  pair again.
- The ALPN value carries the major version. A TLS peer MUST offer exactly
  `mousse/1` and MUST fail the handshake if it is not selected.

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

**Only the first `HELLO` counts.** The peer's first `HELLO` on a connection
fixes `agreed` or closes the connection. A later `HELLO` on the same
connection has no effect, whatever its fields hold: it is ignored, not
negotiated again and not an error. A side does not wait for the peer's
`HELLO` before sending its own next messages (section 8). Vectors:
`hello.json` `cases` and `repeated`.

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

Each side verifies the peer's certificate at its own wall time `now`, with an
**expected identity** (pin):

- **every connection to a known peer**: the pin this endpoint stored for
  that peer endpoint, on first connections, reconnects, bulk sessions and
  path switches alike;
- **a joiner's first contact with a host**: the host endpoint's identity
  from the ticket;
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
9. `now` is inside the widened window (5.2), else `outside_window`.
10. If a pin is given, the identity key equals it byte for byte, else
    `pin_mismatch`.

The TLS stack separately verifies `CertificateVerify` with the session key,
as usual. Together, these prove that the peer holds the session key now and
that the identity key vouched for that session key and window.

**Another endpoint on the address.** A LAN address (a route hint, a
discovered address or a remembered one) is only a candidate. When the
endpoint that answers on a candidate fails the pin (`pin_mismatch`), another
endpoint holds that address: for example another profile's helper on the
same computer, or another computer that took the address. The caller aborts
that handshake before sending any data, tries the next candidate, shows no
warning and keeps its pin unchanged. Vector: `session-cert.json` case
`another_endpoint_on_lan_address`.

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
never the outer one.

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
  as usual but keeps the pending retries and their waits. A retry is
  skipped while a candidate path is still being brought up. Vectors:
  `session-lifecycle.json`.
- **Path switch:** open a new connection to the same peer, run step 1 with
  the **same pin**, reopen channels on it (the application resumes from its
  own cursors), then close the old connection with `PATH_REPLACED`. If the
  new connection fails, the old one keeps running until its own deadline.
- A device holds at most one current and one candidate path per peer. A newer
  candidate replaces an older one, which closes with `PATH_REPLACED`.

## 7. Grants

Authorization lives on each host endpoint as its own table of **grants** and
**denials**. Two endpoints on one device never share a table. This section
fixes the semantics both ends rely on; the storage format is local.

A grant is `{identity, name, role, source, authorizing owner, adopted_into,
granted_at, expires_at?}`:

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
- `expires_at`: optional. At that second the grant is already expired.

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
  used an id may already be gone.

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

1. Each side sends `HELLO` first (control message type 1).
2. The host runs **step 2** for the peer identity from step 1:
   - identity denied: close with `NOT_AUTHORIZED`;
   - a live grant: bind the connection to it and send
     `AUTHORIZED {state: live}`;
   - otherwise: wait for a `JOIN_PROOF`. If none arrives within **10 s**,
     close with `NOT_AUTHORIZED`.
3. After a valid join proof (10.3) the connection is **join-only** and the
   host sends `AUTHORIZED {state: join_only}`. On a join-only connection only
   pairing messages are allowed. When pairing enrolls the device, the
   connection becomes live under the new grant.

### 8.1 What the host accepts

Inbound traffic on the host is classified and checked against the
connection's state:

| Traffic | Awaiting proof | Join-only | Live |
|---|---|---|---|
| `PING`, `PONG`, `HELLO`, `GOAWAY` | allow | allow | allow |
| `JOIN_PROOF` | allow | close `PROTOCOL_ERROR` | ignore |
| `CODE_EXCHANGE`, `CODE_ABORT` | close `NOT_AUTHORIZED` | allow | ignore |
| Any stream frame (`OPEN`, `DATA`, `CREDIT`, `FIN`, `RESET`) | close `NOT_AUTHORIZED` | close `NOT_AUTHORIZED` | allow |
| `AUTHORIZED`, `PAIRED` (host-only messages) | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |

After a close, everything else is ignored. A valid identity with no grant can
therefore never reach RPC or any other channel.

### 8.2 What the caller accepts

The caller checks what the host sends in the same way. It starts **awaiting
authorization**; `AUTHORIZED` moves it to live or join-only. A join-only
caller becomes live when it accepts `PAIRED` (10.4, 10.6), which for "Send
link" is only after it verified the host's confirmation.

| Traffic from the host | Awaiting `AUTHORIZED` | Join-only | Live |
|---|---|---|---|
| `PING`, `PONG`, `HELLO`, `GOAWAY` | allow | allow | allow |
| `AUTHORIZED` | allow, then live or join-only | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |
| `CODE_EXCHANGE`, `CODE_ABORT` | close `PROTOCOL_ERROR` | allow | ignore |
| `PAIRED` | close `PROTOCOL_ERROR` | allow | close `PROTOCOL_ERROR` |
| Any stream frame, including a stream the host opens | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | allow |
| `JOIN_PROOF` (caller-only message) | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` | close `PROTOCOL_ERROR` |

So a host can never open a stream on a caller that has not been told it is
live. After a close, everything else is ignored. Vectors: `authz.json`
`caller_cases`.

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
  **even** ids starting at 2. Each side's ids strictly increase. A peer-opened
  id with the wrong parity, or not above the highest one seen, is
  `PROTOCOL_ERROR`.
- A stream starts with `OPEN`. `DATA` may follow at once.
- `FIN` ends one direction. `DATA` or a second `FIN` after the peer's `FIN`
  is `STREAM_CLOSED`. A stream is gone when both sides have sent `FIN`.
- `RESET` aborts both directions at once; queued data is dropped.
- A frame for a stream id that was **never opened** is `PROTOCOL_ERROR`. A
  frame for a stream that was opened and is now gone is ignored (a normal
  race).
- A side may keep at most **1 024** streams opened by its peer. A further
  `OPEN` is answered with `RESET REFUSED_STREAM`; the connection stays up.

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

Browsers always use "Send link".

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
| `mdns` | `mdns:<instance>` | Browse for this service instance on the local network. |
| `ssh`, `ws`, `wss`, `relay` | reserved | Kept for later transports. Skipped as `reserved`. |
| anything else, or no `:` | | Skipped as `unknown_scheme`. |

A `tcp` or `mdns` hint that breaks its grammar is skipped as `malformed`:

- `<port>`: decimal 1 to 65535, ASCII digits only, no sign, no leading zero.
  The port is the text after the last `:`.
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
- Nothing else may appear: no user part, path, query or fragment.
- `<instance>`: 1 to 63 bytes of UTF-8 with no control characters (Unicode
  general category Cc).

An IPv6 host is its 128-bit address: every accepted text form of the same
address (upper or lower case hex, leading zeros in a group, `::`, an
embedded IPv4 part) is the same host, and the text form is not kept.
Vectors give it as the 16 address bytes in hex. An IPv4 host is given in
dotted decimal, and a DNS name lowercased.

Whichever route reaches it, the host is checked against the ticket's pin. A
pin mismatch on a LAN candidate means another endpoint holds that address
(5.4): try the next candidate, with no warning and no re-pin. Vectors:
`ticket.json` `route_hints`.

### 10.3 Join proof

After `HELLO`, a joiner without a grant sends `JOIN_PROOF`:

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
all of these on purpose. A denied identity gets `NOT_AUTHORIZED`. A second
`JOIN_PROOF` on a join-only connection is `PROTOCOL_ERROR`.

The proof shows that the joiner holds the ticket, bound to this TLS session
and to both identities, so it cannot be replayed on another connection or by
another device.

The joiner's **name** (`JOIN_PROOF` key 3) is not covered by the MAC. It is a
claim the joiner makes about itself, shown to the host owner as sent and
stored in the grant. The app sends `<computer> (<profile>)`, so the field
allows 1 to 128 bytes.

### 10.4 In-person flow

1. Join proof accepted; the host sends `AUTHORIZED {join_only}`.
2. The host asks its owner: "Is the device next to you?", showing the
   joiner's name from `JOIN_PROOF`.
3. On approval the host enrolls (10.8). On decline it closes with
   `PAIRING_DECLINED`; on cancel, `CANCELLED`.
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
   digits are never transmitted.
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
   may type the new code on the same connection.
7. **Outcome after a lost connection.** Once the joiner has sent `msg_c`,
   the host may have enrolled it. If the connection closes before `PAIRED`
   arrives, the joiner does not count the attempt as failed yet. It
   reconnects with the same ticket, even with no attempts left and even
   after the ticket's joiner-side expiry, sends `HELLO` and `JOIN_PROOF` as
   usual, and step 2 gives the outcome:
   - `AUTHORIZED {live}`: the host enrolled it. Pairing succeeded ("already
     paired"); the joiner keeps the ticket's host identity as its pin.
   - `AUTHORIZED {join_only}`: not enrolled. With attempts left the owner
     may type the current code; with none left the flow ends with
     `ATTEMPTS_EXHAUSTED`.
   - A close with `INVITATION_INVALID` or `ATTEMPTS_EXHAUSTED`: not
     enrolled; the flow ends.

Random draws, in order (vectors depend on it): the host draws the invitation
id (16 bytes), the secret (16 bytes) and, for "Send link", the first code
when it creates the invitation; for each new attempt, the next code (if
attempts are left) and then its CPace scalar. The joiner draws, for each
attempt, the attempt id (16 bytes) and then its CPace scalar.

### 10.7 Attempt limits

- **Debit first.** Each side debits one attempt **before** any exchange work
  for it: the joiner when the code is submitted, the host when the first
  message of a new attempt arrives. A debit is never returned, whether the
  attempt fails, is aborted or its connection drops.
- **Host:** 3 attempts per invitation, across all connections and routes.
  When none are left and no attempt is running, the invitation ends and its
  join-only connections close with `ATTEMPTS_EXHAUSTED`. A new attempt with
  none left closes its connection with `ATTEMPTS_EXHAUSTED`.
- **Joiner:** 3 attempts per code-entry flow (one ticket, one local flow).
  After the third failure the flow ends. A fake host can use up the joiner's
  attempts but cannot cancel the real host's invitation; each side's count is
  local.
- **Attempt key.** The host keys attempts by **(TLS session, attempt id)**.
  An attempt id the host has already seen on another TLS session of the
  invitation is a replay: its messages are bound to the old session's
  exporter and can never succeed. The host answers it with `CODE_ABORT
  {attempt, PAIRING_FAILED}` **before** any debit and without exchange work
  or a new code, so replays cannot spend the invitation's attempts.
  Vectors: `pairing-attempts.json`
  `attempt_replayed_on_another_connection_is_refused`.
- **Resends.** A sender may resend only a **byte-identical** message. When the
  host receives, for an existing attempt, a payload identical to the last one
  it received, it replies with the same bytes it sent before and does no new
  work. A different payload on an attempt that already ended gets
  `CODE_ABORT`. The joiner ignores a repeated identical host message.

### 10.8 Enrollment

Enrollment is atomic and happens at most once per invitation, across all
routes:

1. Mark the invitation consumed.
2. Add the grant (identity, the name from `JOIN_PROOF`, the role and
   authorizing owner fixed in the invitation). If the identity already holds
   a grant on this endpoint (for example two invitations joined at the same
   time), the new grant replaces it (section 7).
3. Bind this connection to the new grant; it becomes live.
4. Send `PAIRED {host name, role}`. The host name is the host endpoint's
   display name, `<computer> (<profile>)` in the app.
5. Close every other join-only connection of the invitation with
   `INVITATION_INVALID`.

Cancelling or declining an invitation grants nothing. A joiner that already
holds a live grant gets `AUTHORIZED {live}` at step 2 and pairing ends with
"already paired". That is also how a joiner whose `PAIRED` was lost learns
that it was enrolled (10.6).

## 11. Control messages

Each `CONTROL` frame carries exactly one message: a canonical CBOR map whose
key `0` is the message type. At most 16 384 bytes. Unknown types, missing or
extra keys and field rule failures close the connection with
`PROTOCOL_ERROR`.

| Type | Name | Direction | Fields |
|---|---|---|---|
| 1 | `HELLO` | both, first | `1`: uint major version, `2`: uint newest minor version (section 2) |
| 2 | `AUTHORIZED` | host → caller | `1`: uint state, `1` live or `2` join-only |
| 3 | `JOIN_PROOF` | caller → host | `1`: bytes invitation id (16), `2`: bytes mac (32), `3`: text joiner name (1–128 bytes, not covered by the MAC) |
| 4 | `CODE_EXCHANGE` | both | `1`: bytes attempt id (16), `2`: bytes payload (1–1024) |
| 5 | `CODE_ABORT` | both | `1`: bytes attempt id (16), `2`: uint error code (at most 65 535; unknown codes read as `INTERNAL_ERROR`) |
| 6 | `PAIRED` | host → joiner | `1`: text host name (1–128 bytes), `2`: text role (section 7 rules) |

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
