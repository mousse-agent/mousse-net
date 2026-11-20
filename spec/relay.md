# mousse-net relay protocol, version 1

Status: Phase 3 draft. Normative.

A **relay** joins two outgoing connections, one from a caller and one from
the target it calls, and forwards bytes between them. It never terminates
the peer session: the peer TLS of [`wire.md`](wire.md) section 5 runs end
to end inside the spliced connection, pinned to each side's identity, so a
relay that admits wrongly reaches a host that refuses (wire.md step 1 and
step 2 still run).

This document defines the outer connection, the relay messages, the proofs,
registration, allow-sets, calling, joining, accept legs, splicing and the
self-hosted authorization. The design and its reasoning are in
`docs/phase34-design.md` Parts B and C. An implementation that follows this
document and passes [`vectors/relay-admission.json`](vectors/relay-admission.json)
interoperates with `mousse-net-core::relay` and `mousse-relay`.

Conventions are those of [`wire.md`](wire.md) section 1: big-endian
integers, Unix seconds for times, `‖` for concatenation, `H(x)` for
SHA-256. Every record and message is canonical CBOR (wire.md section 3),
and every signature is a raw P-256 signature (wire.md 4.2): exactly 64
bytes, `r` and `s` in range; a DER signature is rejected, never converted.

## 1. Parties and modes

- **Relay:** one `mousse-relay` process, with one **relay identity key**
  (P-256) in its state directory.
- **Target:** an endpoint (wire.md 1) that registers with the relay and is
  called through it. Hosts are targets.
- **Caller:** an endpoint that calls a target through the relay.
- **Joiner:** an endpoint that holds a pairing ticket and reaches the host
  through the relay before it is paired (section 9).

A relay runs in one **mode**: `self` (mode 0: an operator's list of
authorized targets, no leases, Phase 3) or `hosted` (mode 1: admission
tokens and leases, Phase 4). This version of the document specifies `self`
mode. Messages that only `hosted` mode uses are listed so that their type
numbers and fields are fixed; a `self` relay treats them as protocol errors
(section 4.3).

## 2. The outer connection

- **Transport:** WebSocket (RFC 6455) over TLS 1.3 over TCP. Default port
  443. Everything is TCP, so a network that blocks UDP changes nothing.
- **TLS:** TLS 1.3 only. ALPN `http/1.1`. No session resumption, no PSK, no
  early data. The relay offers and native clients require the hybrid key
  exchange `X25519MLKEM768`, as wire.md 5.4 requires for the peer session;
  a native client closes a connection that negotiated anything else before
  it sends the upgrade request. The `CertificateVerify` scheme is
  `ecdsa_secp256r1_sha256`.
- **Upgrade:** `GET /mousse-relay/1` with `Sec-WebSocket-Protocol:
  mousse-relay.1`. The relay refuses any other path or subprotocol, and
  never negotiates an extension (no `permessage-deflate`).
- **Messages:** binary only, at most **65 536 bytes** each. A text message
  or a larger one closes the connection (WebSocket close 1003 or 1009).
- **Relay identity is its TLS key** (2.1). A native client pins the relay
  id; a wrong relay key fails during the TLS handshake, before any relay
  message.
- **Binding:** both ends derive the TLS 1.3 exporter
  `EXPORTER-mousse-relay-v1` (RFC 8446 7.5), 32 bytes, empty context: the
  **outer exporter**. Every proof signs it (section 5), so no proof can be
  replayed on another connection.

### 2.1 Relay certificate

The relay presents one self-signed X.509 certificate on its identity key:

```
Certificate ::= SEQUENCE {
  tbsCertificate SEQUENCE {
    version          [0] EXPLICIT INTEGER 2
    serialNumber     INTEGER, 16 content bytes: H(SubjectPublicKeyInfo DER)[0..16],
                     first byte set to (b & 0x3f) | 0x40
    signature        SEQUENCE { OID 1.2.840.10045.4.3.2 }       -- ecdsa-with-SHA256
    issuer           Name: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "mousse-relay" } } }
    validity         SEQUENCE { UTCTime 700101000000Z, GeneralizedTime 99991231235959Z }
    subject          Name, identical to issuer
    subjectPublicKeyInfo  the 26-byte prefix of wire.md 5.3 ‖ 65-byte relay identity key
  }
  signatureAlgorithm SEQUENCE { OID 1.2.840.10045.4.3.2 }
  signatureValue     BIT STRING { 0x00 ‖ DER Ecdsa-Sig-Value by the relay identity key over tbsCertificate }
}
```

The certificate has no extensions and does not expire (RFC 5280 4.1.2.5's
"no well-defined expiration date"). A relay writes exactly this profile.
Only `tbsCertificate` is fixed byte for byte: the signature depends on the
ECDSA nonce. The vector (`relay-admission.json`,
`derivations.relay_certificate`) is signed with RFC 6979 nonces and no
low-S normalization, so an implementation that signs the same way
reproduces it exactly.

A **native client** does not judge the chain, the name, the validity, the
self-signature or anything else of the profile: a certificate off the
profile whose key matches the pin passes. It reads the
`subjectPublicKeyInfo` of the leaf certificate, requires the 26-byte prefix followed by a valid uncompressed
P-256 point (wire.md 4.1), requires `H(point)` to equal the pinned relay id
(section 3), and verifies the handshake's `CertificateVerify` with that
key. Anything else fails the handshake. A browser profile (Web PKI) is
Phase 5 and out of scope here.

## 3. Identifiers

| Name | Size | Value |
|---|---|---|
| relay id | 32 | `H(relay identity public key, 65 bytes SEC1)` |
| handle | 32 | `H("mousse-relay-handle-v1" ‖ relay id ‖ registration public key (65))`, the domain string as its 22 ASCII bytes with no length prefix |
| boot id | 16 | random, drawn at each relay start |
| nonce | 32 | random, drawn per outer connection, sent in `RELAY_HELLO` |
| circuit id | 16 | random, drawn per accepted call or join |
| caller fingerprint | 32 | `H(caller public key, 65 bytes SEC1)` |
| registration fingerprint | 32 | `H(registration public key, 65 bytes SEC1)`: what an operator's list holds |
| invitation tag | 32 | `HKDF-SHA256(salt = invitation id (16), IKM = ticket secret (16), info = "mousse-relay-invite-v1", L = 32)` (wire.md 10.2) |
| tag hash | 32 | `H(invitation tag)` |
| enrollment code | 16 | random, single use (section 11) |
| code hash | 32 | `H(enrollment code)` |

A handle is **derived, never claimed**: the relay computes it from the
registration key that proved itself, so a target can only register the
handle of a key it holds. A handle means nothing on another relay.

Each endpoint uses its own **registration key** per relay and its own
**caller key** per pairing (one P-256 key per caller and host, enrolled with
the host through the peer session, never through the relay).

## 4. Relay messages

Before a connection is spliced, every WebSocket message is one canonical
CBOR map whose key `0` is the message type, at most **16 384 bytes**
(`RELAY_MESSAGE_MAX`). After `SPLICED` (section 10) messages are peer bytes
and this section no longer applies to them.

### 4.1 Types

| Type | Name | Direction | Fields |
|---|---|---|---|
| 1 | `RELAY_HELLO` | relay → client, first | 1: version (uint, `1`), 2: nonce (32), 3: boot id (16), 4: mode (uint, 0 self, 1 hosted) |
| 2 | `REGISTER` | target → relay | 1: registration public key (65), 2: proof (64); hosted only, both or neither: 3: admission token (bytes), 4: status threshold percent (uint, 10–90) |
| 3 | `ENROLL` | target → relay (self) | 1: registration public key (65), 2: proof (64), 3: enrollment code (16) |
| 4 | `REGISTERED` | relay → target | 1: handle (32) |
| 5 | `ALLOW_SET` | target → relay | 1: sequence (uint), 2: caller fingerprints (array of 0–256 byte strings of 32), 3: invitations (array of 0–8 maps `{1: tag hash (32), 2: expires at (uint)}`) |
| 6 | `ALLOW_SET_OK` | relay → target | 1: sequence (uint) |
| 7 | `CALL` | caller → relay | 1: handle (32), 2: caller public key (65), 3: proof (64), 4: class (uint, 0 interactive, 1 bulk) |
| 8 | `JOIN` | joiner → relay | 1: handle (32), 2: invitation tag (32) |
| 9 | `INCOMING` | relay → target | 1: circuit id (16), 2: kind (uint, 0 call, 1 join), 3: class (uint, 0 or 1), 4: caller fingerprint (32; present for a call, absent for a join) |
| 10 | `ACCEPT` | target → relay, first on a new connection | 1: handle (32), 2: circuit id (16), 3: proof (64) |
| 11 | `SPLICED` | relay → both legs | none |
| 12 | `UNREACHABLE` | relay → caller or joiner | none |
| 13 | `PROMOTE` | target → relay | 1: circuit id (16), 2: caller fingerprint (32) |
| 14 | `LEASE` | target → relay (hosted) | 1: block (bytes: a signed envelope) |
| 15 | `LEASE_STATUS` | relay → target (hosted) | 1: array of `{1: lease id (16), 2: class (uint, 0 or 1), 3: used (uint), 4: bytes (uint), 5: state (uint, 0 pending, 1 current, 2 final, 3 refused)}` |
| 16 | `REFUSED` | relay → target | 1: reason (text, one of section 4.4) |
| 17 | `ADMIT` | target → relay (hosted) | 1: admission token (bytes) |
| 18 | `SUCCESSOR` | target → relay (self) | 1: new registration public key (65), 2: proof by the new key (64), 3: proof by the current key (64) |
| 19 | `PING` | both, registration connection | 1: 8 opaque bytes |
| 20 | `PONG` | both, registration connection | 1: the 8 bytes of the `PING` |
| 21 | `RELEASE` | target → relay (hosted) | 1: lease ids (array of 1–4 byte strings of 16) |

### 4.2 Field rules

A message is **malformed** when any of these fails:

- it is canonical CBOR (wire.md 3) and a map, at most 16 384 bytes;
- key 0 is a uint naming a type in 4.1;
- it has exactly the keys its type lists (wire.md 3, "Records with fixed
  fields"), with the types and sizes listed. `REGISTER`'s keys 3 and 4 are
  both present or both absent; `INCOMING`'s key 4 is present exactly when
  its kind is 0;
- every public key is a valid uncompressed P-256 point (wire.md 4.1);
- every proof is a raw signature: exactly 64 bytes with `r` and `s` in
  range (wire.md 4.2). A DER signature is malformed;
- enumerated uints (version, mode, kind, class, state, threshold) are
  within their listed values;
- the fingerprints of one `ALLOW_SET` are all different, and so are its
  tag hashes;
- a `REFUSED` reason is one of 4.4.

### 4.3 What the relay does with a message

Each outer connection takes one **role**, set by the first message the
client sends after `RELAY_HELLO`:

| First message | Role |
|---|---|
| `REGISTER`, `ENROLL` | registration connection |
| `CALL` | call leg |
| `JOIN` | join leg |
| `ACCEPT` | accept leg |

Then:

- A registration connection may send `ALLOW_SET`, `PROMOTE`, `SUCCESSOR`,
  `PING` and `PONG` (and, in hosted mode, `LEASE`, `ADMIT` and
  `RELEASE`).
- A call or join leg sends nothing more until `SPLICED`.
- An accept leg sends nothing more until `SPLICED`.

A malformed message, a message the connection's role or the relay's mode
does not allow, a relay-to-client type sent by a client, or a second
`REGISTER` or `ENROLL` on a registration connection is a **protocol
error**: the relay closes the connection at once with WebSocket close code
**1002** and acts as if the client had closed it (section 10.3). Nothing
else is sent. A protocol error never depends on admission state, so it
tells a client nothing about which handles exist or who is listed.

`REGISTER` with keys 3 and 4 in self mode, and without them in hosted mode,
is a protocol error.

The relay always sends class 0 in a join's `INCOMING`. Size bounds of the
hosted-only fields (admission tokens, `LEASE` blocks, `LEASE_STATUS`
entries, distinct `RELEASE` ids) are set with hosted mode; until then only
the 16 384-byte message maximum bounds them.

### 4.4 Close codes and refusal reasons

The relay closes connections with these WebSocket close codes:

| Code | Name | When |
|---|---|---|
| 1000 | normal | after `UNREACHABLE` or `REFUSED`; the other leg of a circuit whose leg closed |
| 1002 | protocol | a protocol error (4.3) |
| 4000 | `removed` | the caller left the allow-set; the operator revoked the target; its registration key was dropped |
| 4001 | `lease_exhausted` | hosted: a class ran out of lease with no refill |
| 4002 | `idle` | no first message in time; a registration or circuit idle too long |
| 4003 | `relay_stopping` | the relay stops |
| 4004 | `admission_expired` | hosted: no admission and no usable block |
| 4005 | `replaced` | a new registration of the same handle replaced this one |
| 4006 | `limit` | a local limit: connections, the pre-accept budget, an invitation's expiry |

`REFUSED` reasons (text): `not_authorized` (a registration or accept leg
that did not prove an authorized key), `enrollment` (an enrollment code
that is unknown, used or expired), `limit` (a local limit on registrations
or accept legs), `admission` (hosted: no valid admission token). The relay
sends `REFUSED`, then closes with 1000.

## 5. Proofs

Each proof is a raw signature (wire.md 4.2), ECDSA P-256 with SHA-256 over
the canonical CBOR bytes of a record. Each record's key 1 is its own domain
string, so no proof can stand for another purpose. Every field is bound:
the relay id (no use on another relay), the handle, the connection's relay
nonce and the outer exporter (no replay on another connection).

| Proof | Signed by | Record |
|---|---|---|
| register | registration key | `{1: "mousse-relay-register-v1", 2: relay id, 3: handle, 4: nonce, 5: outer exporter}` |
| successor | the new key, and the current key | `{1: "mousse-relay-successor-v1", 2: relay id, 3: handle of the new key, 4: nonce, 5: outer exporter}` |
| call | caller key | `{1: "mousse-relay-call-v1", 2: relay id, 3: handle, 4: nonce, 5: outer exporter, 6: class}` |
| accept | registration key | `{1: "mousse-relay-accept-v1", 2: relay id, 3: handle, 4: circuit id, 5: nonce, 6: outer exporter}` |

`ENROLL` carries a register proof. `handle` in a register or enroll proof is
the handle the relay derives from key 1 of the message; in a successor
proof, the handle of the new key. `nonce` and `outer exporter` are those of
the connection the message arrives on.

## 6. Timers and time

The relay keeps two clocks: a **monotonic** clock in milliseconds for every
wait in this document, and its **wall clock** in Unix seconds for times that
come from elsewhere (invitation expiries, enrollment code expiries, key
drops). The waits are the relay limits of `docs/limits.md` ("Relay"):

| Wait | Limit | Started by | Ends with |
|---|---|---|---|
| first message | `RELAY_HELLO_WAIT_MS` | `RELAY_HELLO` | close 4002 if no first message |
| refusal deadline | `RELAY_REFUSE_MS` | the arrival of a `CALL` or `JOIN` | `UNREACHABLE` for a refused one |
| accept wait | `RELAY_ACCEPT_WAIT_MS` | `INCOMING` | `UNREACHABLE` if no accept leg came |
| registration idle | `RELAY_REGISTRATION_IDLE_MS` | each message received on a registration connection, starting with its `REGISTER` or `ENROLL` | close 4002 |
| keepalive | `RELAY_KEEPALIVE_MS` | each message sent on a registration connection, starting with its `REGISTERED` | `PING` |
| circuit idle | `RELAY_CIRCUIT_IDLE_MS` | `SPLICED`, and each peer message either way | close both legs 4002 |

A wait of `w` ms started at `t` **fires** when the monotonic clock reaches
`t + w`. Before it handles anything, the relay fires every wait that is
due, in order of the time each fires; waits that fire at the same moment
in the order of the table's rows; and within a row in increasing order of
connection number (for a circuit, its caller's leg). A running relay
numbers its connections in the order they open; in the vectors the numbers
are the scenarios' `conn` values, whatever order those open in. A
wait that firing starts (the keepalive after a `PING`) fires in turn if it
is due as well.

Wall-clock times fire after every due wait, whatever time each came due:
first every join circuit whose invitation expiry the wall clock has
reached (section 9.3), in order of the caller's leg; then every superseded
registration key whose drop time it has reached (section 7.4), in order of
fingerprint.

## 7. Registration

### 7.1 `REGISTER`

A target opens an outer connection, reads `RELAY_HELLO`, and sends
`REGISTER {1: key, 2: proof}`. The relay, in order:

1. derives the handle from the relay id and key 1;
2. verifies the register proof against key 1 with this connection's nonce
   and outer exporter;
3. requires the key's registration fingerprint to be on the authorized list
   (section 11) and not superseded past its drop time;
4. requires the number of live registrations, not counting this handle's,
   to be below `RELAY_MAX_REGISTRATIONS` (else `REFUSED(limit)`).

A failure of 2 or 3 is `REFUSED(not_authorized)`. On success the relay
records the registration, sends `REGISTERED {1: handle}`, and the
connection becomes the handle's registration connection.

**One live registration per handle.** If the handle already has a
registration connection, the relay closes that connection with 4005 first,
and forgets its allow-set. The new registration starts with no allow-set:
until the target pushes one, every call and join to the handle is refused.

**Circuits outlive their registration connection.** A circuit belongs to
the handle. A replaced (4005) or dropped registration connection leaves its
circuits running, and an accept leg may still answer an `INCOMING` the old
connection received. Only a revocation, a key drop (section 7.4) or a new
allow-set without the caller (section 8) closes them.

### 7.2 Keepalive

On a registration connection the relay sends `PING {1: 8 random bytes}`
when the keepalive wait fires, and closes the connection with 4002 when the
registration idle wait fires. It answers a `PING` with a `PONG` carrying the
same bytes; a `PONG` needs no answer. Every message received restarts the
idle wait; every message sent restarts the keepalive wait.

### 7.3 After a relay restart

Nothing about registrations survives a relay restart (section 12). Calls
get `UNREACHABLE` until the target registers again and pushes its
allow-set.

### 7.4 `SUCCESSOR` (manual key rotation, self mode)

A registered target that wants a new registration key sends, on its
registration connection, `SUCCESSOR {1: new key, 2: proof by the new key,
3: proof by the current key}`. Both proofs are over the same successor
record (section 5), with the handle of the new key. The relay requires:

1. the new key's proof verifies against key 1;
2. the current key's proof verifies against the key this connection
   registered with;
3. the current key is on the authorized list and has not itself been
   superseded;
4. the new key is not on the authorized list at all (so two keys can
   never keep each other alive);
5. the current key's **chain** holds fewer than `RELAY_CHAIN_KEYS_MAX`
   keys on the list.

Every key on the list belongs to one chain, named by the fingerprint it
started from: a key the operator listed or enrolled starts its own, and a
successor joins the chain of the key that vouched for it. A self-hosted
relay checks a `SUCCESSOR` against its stored list as it is when the
message arrives, not as of its last read, so a key the operator just
revoked cannot vouch for one.

If any fails, the relay sends `REFUSED(not_authorized)` and closes the
registration connection with 1000 (its circuits keep running). Otherwise it
adds the new key's fingerprint to the authorized list and marks the current
key **superseded**, with a drop time `RELAY_SUCCESSOR_OVERLAP_SECS` after
now on its wall clock. Nothing is sent. The new key registers on its own
connection like any authorized key, and both are registered during the
overlap. At the drop time the relay removes the old key from the list and
closes its registration and every circuit of its handle with 4000, in the
order of section 10.3.

A superseded key can still register until it is dropped, but it can never
vouch for another successor, so a key the operator never authorized only
arrives vouched for by a current key the operator did. Revoking any key
of a chain revokes the whole chain (section 11).

There is no automatic rotation in self mode.

## 8. Allow-sets

`ALLOW_SET {1: sequence, 2: caller fingerprints, 3: invitations}` replaces
the handle's whole allow-set. The first allow-set of a registration is
accepted with any sequence; after that a sequence not above the last one
accepted on this registration is ignored (no answer, no change). The relay
answers an accepted set with `ALLOW_SET_OK {1: sequence}`.

When an allow-set is accepted, the relay first closes, with 4000 on both
legs, every **call** circuit of the handle whose caller fingerprint is not
in the new set (waiting or spliced, in order of the caller's leg), then
sends `ALLOW_SET_OK`. No other circuit is touched. Join circuits are not affected
by allow-set changes (section 9).

The relay adds nothing to an allow-set and keeps it in memory only.

## 9. Calling and joining

### 9.1 `CALL`

A caller opens an outer connection to a relay it pinned, reads
`RELAY_HELLO`, and sends `CALL {1: handle, 2: caller key, 3: proof, 4:
class}`. When the `CALL` arrives the relay sets the call's **refusal
deadline**, `RELAY_REFUSE_MS` later, before it looks anything up. It then
checks, in one code path:

1. the call proof verifies against key 2 with this connection's nonce and
   outer exporter and the message's handle and class;
2. the handle has a live registration with an allow-set;
3. the caller fingerprint `H(key 2)` is in that allow-set;
4. fewer than `RELAY_CIRCUITS_PER_CALLER` circuits of this handle are open
   for this caller fingerprint.

If any check fails, the call is **refused**: the relay sends `UNREACHABLE`
exactly when the refusal deadline fires, then closes with 1000. An unlisted
caller, an unknown handle, an offline target and a bad proof look the same
and take the same time. A listed caller is not told which check failed.

Otherwise the relay draws a circuit id, sends `INCOMING {1: circuit, 2: 0,
3: class, 4: caller fingerprint}` on the registration connection, and
starts the accept wait. If no accept leg splices the circuit before the
accept wait fires, the relay sends `UNREACHABLE` to the caller and closes
with 1000. `RELAY_REFUSE_MS` is below `RELAY_ACCEPT_WAIT_MS`, so an
`UNREACHABLE` never comes before the refusal deadline.

### 9.2 `JOIN`

A joiner holding a ticket sends `JOIN {1: handle, 2: invitation tag}`. The
relay sets the refusal deadline the same way and checks, in one code path:

1. the handle has a live registration with an allow-set;
2. `H(tag)` is one of its invitations, and that invitation's expiry is
   after now on the relay's wall clock;
3. fewer than `RELAY_PREACCEPT_PER_TARGET` join circuits of this handle are
   open.

A failure is refused exactly like a call. Otherwise the relay draws a
circuit id and sends `INCOMING {1: circuit, 2: 1, 3: 0}`; the accept wait
follows as for a call. The relay never learns the invitation id or the
ticket secret: only a ticket holder can compute the tag.

### 9.3 The pre-accept budget

A join circuit, until it is promoted, may carry at most
`RELAY_PREACCEPT_BYTES` of peer bytes in each direction (the sum of the
payload lengths of the peer messages forwarded that way). A peer message
that would take a direction over the budget is not forwarded: the relay
closes both legs with 4006. A join circuit also closes with 4006 when the wall clock
reaches the expiry its invitation had when the `JOIN` was admitted: both
legs if it is spliced, the joiner's leg if it is still waiting. A promoted
circuit is no longer a join circuit: neither the budget nor the expiry
applies to it.

### 9.4 `PROMOTE`

When pairing over a join circuit has enrolled the joiner and its caller key
has arrived through the peer session, the target pushes an allow-set that
lists the new caller fingerprint and then sends `PROMOTE {1: circuit, 2:
caller fingerprint}` on its registration connection. The relay promotes the
circuit only if it is a spliced, not yet promoted join circuit of this
handle and the fingerprint is in the handle's current allow-set; otherwise
it ignores the `PROMOTE` (no answer, no change). A promoted circuit leaves
the pre-accept budget and the join count, and from then on is that caller's
call circuit: it counts toward the caller's circuits and closes when the
fingerprint leaves the allow-set.

## 10. Accept legs and splicing

### 10.1 `ACCEPT`

On `INCOMING` the target opens a **new** outer connection and sends
`ACCEPT {1: handle, 2: circuit, 3: proof}` as its first message. The relay
requires:

1. the circuit is waiting for its accept leg and belongs to key 1's handle;
2. the accept proof verifies, with this connection's nonce and outer
   exporter, against the registration key the handle is derived from. The
   relay keeps that key with the circuit, so this works after the
   registration connection has closed or been replaced;
3. fewer than `RELAY_ACCEPT_LEGS_PER_HANDLE` accept legs of this handle are
   open.

A failure of 1 or 2 is `REFUSED(not_authorized)`, of 3 `REFUSED(limit)`; the
circuit keeps waiting. On success the relay sends `SPLICED` on the caller's
leg, then on the accept leg, and the circuit is **spliced**.

### 10.2 Spliced circuits

From `SPLICED` on, the relay forwards each WebSocket message's payload from
one leg to the other unchanged. The caller starts the peer TLS handshake as
the TLS client with the host's identity pin (wire.md 5.4); a wrong peer
identity fails before any data. Exporters for pairing come from that inner
peer session, never from the outer connection (wire.md 5.5).

The relay counts payload bytes only: WebSocket and outer TLS framing are not
counted.

### 10.3 How circuits end

A circuit ends when:

- either leg closes: the relay closes the other with 1000;
- its caller leaves the allow-set: both legs 4000 (section 8);
- the operator revokes the target, or its key is dropped: both legs 4000;
- it is idle for `RELAY_CIRCUIT_IDLE_MS`: both legs 4002;
- a join circuit goes over its budget or reaches its invitation's expiry:
  both legs 4006 (section 9.3);
- the relay stops: both legs 4003.

When the relay closes both legs it closes the caller's leg first. When it
closes a registration and circuits together (a revocation, a key drop),
it closes the registration connection first, then each circuit in order of
its caller's leg. A call or
join leg that closes before its circuit is spliced ends the circuit; an
`ACCEPT` for it is then refused like any unknown circuit. A registration
connection that closes ends the registration (its allow-set is forgotten)
but not its circuits.

## 11. Self-hosted authorization

A self-hosted relay keeps an **authorized list** of registration
fingerprints in its state directory, each optionally marked superseded with
a drop time (section 7.4), and a set of **enrollment codes**, each stored as
its code hash with an expiry.

- `mousse-relay init --public <host:port>` creates the identity key and the
  state directory and prints the relay id and an **enrollment link**.
- `mousse-relay enroll` prints a new enrollment link.
- `mousse-relay list` prints the authorized list, with the chain of each
  key a `SUCCESSOR` added; `mousse-relay revoke <fingerprint>` removes
  that key and every key of its chain (section 7.4), so a successor never
  outlives the key it came from. The relay then closes each removed key's
  registration and every circuit of its handle with 4000.

**Enrollment link:** `mousse-relay://<host>:<port>/#<relay id>.<code>`,
where `<host>:<port>` follows the grammar of wire.md 10.2.1 for `tcp`
hints (an IPv6 address in brackets), and the relay id (32 bytes) and the
enrollment code (16 bytes) are written in base64url without padding with
the strict rules of wire.md 10.2 (link form). Nothing else may appear. The
code is valid for `RELAY_ENROLL_SECS` and single use. A reader accepts any
host text the `tcp` grammar accepts. A relay writes the host in one form:
IPv4 dotted decimal, IPv6 in RFC 5952 form in brackets, a DNS name in
lowercase; links in that form print back unchanged.

**`ENROLL`** `{1: key, 2: register proof, 3: code}` is the first message of
a registration connection. The relay, in order:

1. verifies the register proof as for `REGISTER` (else
   `REFUSED(not_authorized)`);
2. requires `H(code)` to be a stored code hash whose expiry is after now on
   its wall clock (else `REFUSED(enrollment)`);
3. checks the registration limit as for `REGISTER` (else
   `REFUSED(limit)`);
4. removes the code hash and adds the key's fingerprint to the authorized
   list, durably, before it answers;
5. registers the connection as for `REGISTER` and sends `REGISTERED`.

Pasting the link in the app is also the owner's approval of that relay
route (`docs/phase34-design.md` B.11).

## 12. State

The relay's state directory holds its identity key, the authorized list
(with each key's chain), the enrollment code hashes, its configuration and
an exclusive lock, so one process runs per relay identity. The directory
and its files are owner-only, each file from its creation; the relay
refuses an identity key file other users can read. It holds no user data, no payload, no IP
addresses and no allow-sets. Registrations, allow-sets and circuits live in
memory only and end with the process.

## 13. Local limits

Every wait, count and size above that is not a protocol constant is a relay
limit, read from `MOUSSE_NET_<name>` and documented in `docs/limits.md`
("Relay"). Limits a client can push against may only be tightened. The
defaults, which the vectors assume unless a scenario's `limits` says
otherwise:

| Limit | Default | What it bounds |
|---|---|---|
| `RELAY_MAX_CONNECTIONS` | 1024 | open connections |
| `RELAY_CONNECTIONS_PER_IP` | 256 | open connections per address key |
| `RELAY_ACCEPT_LEGS_PER_HANDLE` | 64 | accept legs of spliced circuits per handle |
| `RELAY_CIRCUITS_PER_CALLER` | 8 | open circuits per caller fingerprint and handle |
| `RELAY_MAX_REGISTRATIONS` | 1024 | live registrations |
| `RELAY_HELLO_WAIT_MS` | 5000 | first message wait (section 6) |
| `RELAY_UPGRADE_WAIT_MS` | 5000 | the TLS handshake and upgrade together |
| `RELAY_HEADER_MAX_BYTES` | 8192 | the upgrade request |
| `RELAY_ACCEPT_WAIT_MS` | 10000 | accept wait |
| `RELAY_REFUSE_MS` | 500 | refusal deadline; below the accept wait |
| `RELAY_PREACCEPT_BYTES` | 65536 | pre-accept budget per direction |
| `RELAY_PREACCEPT_PER_TARGET` | 4 | join circuits per handle |
| `RELAY_KEEPALIVE_MS` | 15000 | keepalive |
| `RELAY_REGISTRATION_IDLE_MS` | 45000 | registration idle |
| `RELAY_CIRCUIT_IDLE_MS` | 60000 | circuit idle |
| `RELAY_QUEUE_BYTES` | 262144 | bytes queued per circuit and direction |
| `RELAY_EGRESS_BPS` | 12500000 | shared egress, bytes per second |
| `RELAY_ENROLL_SECS` | 3600 | enrollment code lifetime |
| `RELAY_SUCCESSOR_OVERLAP_SECS` | 604800 | overlap after `SUCCESSOR` |
| `RELAY_CHAIN_KEYS_MAX` | 4 | keys of one `SUCCESSOR` chain on the list at once |
| `RELAY_STATE_POLL_MS` | 1000 | how often the running relay rereads its state directory |
| `RELAY_SEND_WAIT_MS` | 20000 | one write to a connection; one that does not finish closes it with 4006 |
| `RELAY_CONTROL_QUEUE_MESSAGES` | 64 | relay messages queued toward one connection; one more closes it with 4006 |
| `RELAY_CLOSE_LINGER_MS` | 2000 | sending what is queued and the close frame when the relay closes a connection |

**Address key.** Connections count against the **address key** of their
peer: 16 bytes, an IPv4 address in bytes 0 to 3 with byte 15 set to 4 (an
IPv4-mapped IPv6 address counts as its IPv4 address), or the first 64 bits
of an IPv6 address in bytes 0 to 7 with byte 15 set to 6, all other bytes
zero. The key never leaves the relay's memory. In the vectors it is opaque:
only equality matters.

**What counts.** Every open connection counts against its address key and
`RELAY_MAX_CONNECTIONS`, whatever its role, from `RELAY_HELLO` until it
closes, except that an accept leg stops counting against its address key
once its `ACCEPT` is accepted; it then counts against its handle's
`RELAY_ACCEPT_LEGS_PER_HANDLE`. A connection that would go over either
connection limit is closed with 4006 before `RELAY_HELLO`, and no nonce is
drawn for it. A relay also counts connections still in their TLS handshake
or upgrade the same way, so handshakes cannot get around the limits.

Interactive circuits are written before bulk ones at the relay's shared
egress. Per circuit and direction at most `RELAY_QUEUE_BYTES` are buffered;
above that the relay stops reading that leg, so TCP pushes back on the
sender. A client that stops reading is closed: a write to it that does not
finish within `RELAY_SEND_WAIT_MS`, or a relay message beyond
`RELAY_CONTROL_QUEUE_MESSAGES` queued toward it, closes it with 4006, and
its circuit with it. A close never waits behind a blocked write: what is
queued gets `RELAY_CLOSE_LINGER_MS` to go out before the close frame.

Fixed on purpose: `RELAY_MESSAGE_MAX` 16 384, at most 256 caller
fingerprints and 8 invitations per allow-set, the 65 536-byte WebSocket
message maximum, the path, the subprotocol, the close codes, the refusal
reasons, every domain string and the exporter label.

## 14. Test vectors

[`vectors/relay-admission.json`](vectors/relay-admission.json):

- `derivations`: relay id, handle, every proof record and its signature,
  invitation tag and tag hash, enrollment link, and the relay certificate;
- `messages`: messages that decode and re-encode unchanged, and malformed
  ones (section 4.2);
- `scenarios`: scripted runs of one relay in self mode. Each lists the
  relay's setup (`relay_key`, `boot_id`, `wall_base`, the `authorized`
  list with optional `drop_at` and `chain`, a missing `chain` being the
  key's own fingerprint, enrollment `codes` as hash and expiry, and
  `limits` that differ from the defaults), the random values it draws in
  order (`draws`, hex), and its `events`, each with the outputs (`out`) it
  must produce, byte for byte. Hosted mode is not covered here.

**Replay model.** A scenario's relay starts at monotonic time 0 and wall
time `wall_base`; at monotonic time `t` ms its wall clock reads `wall_base
+ floor(t / 1000)`. Each event is `{"event": name, "at": t, ...}`, with
`at` never going back. Before handling an event the relay fires every wait
due at or before `at` as section 6 says and lists their outputs first.
Connections are numbered by the scenario. Events:

| Event | Meaning |
|---|---|
| `open` | a client connection `conn` with address key `ip` and outer exporter `exporter` completed its upgrade; the relay draws a nonce and sends `RELAY_HELLO`, or closes it with 4006 if a connection limit is reached |
| `recv` | the client on `conn` sent the message `hex` |
| `data` | the client on `conn` sent a peer message of `len` bytes. On a connection that is not a spliced leg this is a protocol error (close 1002). A `recv` on a spliced leg is the same as `data` with the message's length. |
| `closed` | the client closed `conn` |
| `tick` | nothing happens but time |
| `revoke` | the operator revoked the registration fingerprint `fingerprint`, and with it every key of its chain. The operator's command has already changed the stored list, so there is no durable output, only the closes: for each removed key in order of fingerprint, as for a dropped key. |

Outputs: `{"send": conn, "message": type name, "hex": ...}`, `{"close": conn, "code": ...}`,
`{"splice": [caller conn, accept conn], "circuit": ..., "class": ...}`, `{"forward":
[from conn, to conn], "len": ...}`, and the durable changes to the
authorized list and codes: `{"authorize": fingerprint, "chain": chain}`, `{"supersede":
fingerprint, "drop_at": ...}`, `{"drop": fingerprint}`, `{"consume_code":
code hash}`. A connection the relay closed produces no further outputs, and
events on it are ignored.

Random values are drawn in this order: one nonce (32 bytes) per `open`
that is not refused, one circuit id (16) per admitted `CALL` or `JOIN`, and
8 bytes per `PING`.
