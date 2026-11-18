# CPace in Mousse

Status: profile 1, for design review (Phase 0, spike 5). Code: `crates/mousse-net-core/src/cpace/`.

This document says exactly how Mousse runs CPace during pairing. You should be able to write a second implementation from this file and the draft alone. The pairing spec defines the bytes that go into CI, sid, ADa and ADb, which roles the host and joiner take, and how the three messages travel. CPace treats those bytes as opaque.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Source

- **Draft:** draft-irtf-cfrg-cpace-21, "CPace, a balanced composable PAKE", dated 23 April 2026. On 2026-11-18 this was the newest revision. The IRTF has sent it to the RFC Editor, and the RFC Editor's work is still in progress. "§" below means a section of that draft.
- **Group:** ristretto255, RFC 9496.
- **Hash:** SHA-512, RFC 6234. **MAC:** HMAC, RFC 2104.

If the published RFC changes any computation below, Mousse will define a new profile. Profile 1 stays exactly as written here.

## 2. Profile

| Item | Value | Draft |
|---|---|---|
| Cipher suite | CPACE-RISTR255-SHA512 | §5, §8.3 |
| Setting | initiator-responder (A speaks first), `transcript_ir` | §4.3, §6.3, §7 |
| Key confirmation | the construction in §10.4, with MAC = HMAC-SHA-512 and 64-byte tags | §10.4 |
| Sid output (§10.6) | not used, because sid is always provided | §4.2 |

Constants:

- `DSI` = `b"CPaceRistretto255"` (17 bytes). `DSI_ISK` = `DSI || b"_ISK"` = `b"CPaceRistretto255_ISK"` (21 bytes).
- `H.s_in_bytes` = 128. `H.b_in_bytes` = 64.
- `G.I` = 32 zero bytes, the ristretto255 encoding of the identity element.
- `l` = 2^252 + 27742317777372353535851937790883648493, the group order.

## 3. Notation

These follow §6.3 and Appendix A:

- `LEB128(n)`: 7 bits per byte, least significant group first, bit 7 set on every byte except the last. Lengths below 128 take one byte.
- `prepend_len(x)` = `LEB128(len(x)) || x`.
- `lv_cat(x1, ..., xn)` = `prepend_len(x1) || ... || prepend_len(xn)`.
- `encode` and `decode` are the ristretto255 encoding and decoding of RFC 9496 §4.3.2 and §4.3.1. `decode` fails for non-canonical or invalid strings.
- `one_way_map(b)` is the ristretto255 element derivation function of RFC 9496 §4.3.4. It takes 64 uniform bytes. The draft calls it `element_derivation` (§8.3).
- `HMAC(k, m)` is HMAC-SHA-512 with the full 64-byte output.

## 4. Inputs

Each party gets the following. A party MUST reject its own inputs if they break these rules. The error is shown after each rule.

| Input | Mousse meaning | Rules |
|---|---|---|
| `PRS` | The pairing code: the 6 digits shown by the host, as ASCII bytes `0x30`–`0x39`. No spaces or separators; leading zeros are kept. | Not empty (`EmptyPassword`). CPace accepts any bytes here; the pairing layer MUST pass exactly the 6 digits. |
| `CI` | The binding transcript ([`wire.md`](wire.md) 10.5): ticket hash, mode, version, the identities with their roles (initiator first), and the peer session's TLS exporter. | Opaque. Never sent. Both sides MUST build identical bytes. Any length. |
| `sid` | The attempt's session id ([`wire.md`](wire.md) 10.5, "Session id"): 32 bytes, a hash of the attempt id and the peer session's TLS exporter. | At least 16 bytes (`SidTooShort`). Public. Identical on both sides. MUST NOT be reused across attempts (§10.9). |
| `ADa`, `ADb` | Each party's associated data. Sent in clear inside its message. Mousse pairing sends both empty and refuses a share that carries AD (`Malformed`). | At most 4096 bytes (`AdTooLong`). |

Requirements on the pairing layer (from §10.1.1 and §10.1.2):

- The joiner is the initiator (A) and the host the responder (B).
- Party identities and roles that CPace must authenticate go into `CI`. The encoding MUST tie each identity to its role and MUST put the initiator's identity first. It MUST be unambiguous, so that no two different binding transcripts give the same bytes.
- A party MUST NOT take both roles for the same (`PRS`, `sid`).
- `ADa` and `ADb` are authenticated only once confirmation succeeds. If the pairing layer depends on their content, it MUST check that content after confirmation.

## 5. Computation

### 5.1 Generator (§8.1, §8.3, Appendix A.2)

```
len_zpad  = max(0, 128 - 1 - len(prepend_len(PRS)) - len(prepend_len(DSI)))
gen_str   = lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
gen_hash  = SHA-512(gen_str)                  # 64 bytes
g         = one_way_map(gen_hash)
```

For a 6-digit code, `len_zpad` = 128 − 1 − 7 − 18 = 102.

### 5.2 Scalars (§8.3)

`sample_scalar()`: take 32 random bytes and clear the top four bits of the last byte (`b[31] &= 0x0f`). Read the result as a little-endian integer, which is always below `l`. If the result is zero, sample again. Every attempt uses fresh scalars (§10.9). The draft also allows uniform sampling in [1, l−1]. The peer can't tell which method was used.

### 5.3 Flow

```
Initiator A                                          Responder B
ya = sample_scalar()
Ya = encode(ya * g)
msg_a = lv_cat(Ya, ADa)          ---- msg_a ---->
                                                     parse msg_a (section 6)
                                                     K = scalar_mult_vfy(yb, Ya); abort if K == G.I
                                                     yb = sample_scalar(); Yb = encode(yb * g)
                                                     body_b = lv_cat(Yb, ADb)
                                                     ISK = SHA-512(lv_cat(DSI_ISK, sid, K) || msg_a || body_b)
                                                     mac_key = SHA-512(b"CPaceMac" || sid || ISK)
                                                     Tb = HMAC(mac_key, body_b)
                                 <---- msg_b ----    msg_b = body_b || Tb
parse msg_b (section 6)
K = scalar_mult_vfy(ya, Yb); abort if K == G.I
ISK = SHA-512(lv_cat(DSI_ISK, sid, K) || msg_a || body_b)
mac_key = SHA-512(b"CPaceMac" || sid || ISK)
abort unless Tb == HMAC(mac_key, body_b)
Ta = HMAC(mac_key, msg_a)
output (ISK, ADb)                ---- msg_c ---->
msg_c = Ta                                           abort unless msg_c == HMAC(mac_key, msg_a)
                                                     output (ISK, ADa)
```

Notes:

- `scalar_mult_vfy(y, X)` (§8.3) returns `G.I` if `decode(X)` fails, and `encode(y * decode(X))` otherwise. ristretto255 has prime order and `y` is never zero, so `K == G.I` exactly when `X` fails to decode or is the identity. Both cases end with `InvalidPoint`.
- `msg_a || body_b` is `transcript_ir(Ya, ADa, Yb, ADb)` from §6.3. Each share's bytes on the wire are the same bytes the transcript uses.
- `mac_key` is plain concatenation with no length prefixes, exactly as §10.4 writes it. `ISK` always takes the last 64 bytes, so the input can be read only one way.
- Tags MUST be compared in constant time. A tag of the wrong length is `Malformed`, and a wrong tag is `ConfirmationFailed`.
- A's `ISK` exists only after `Tb` checks out. B outputs `ISK` only after `Ta` checks out. A never learns whether B accepted `Ta`, so the pairing layer must tell it with its own approval message.
- `K`, `mac_key` and the scalars never leave the CPace code (§10.3). They are wiped after use, along with `ISK` when it is dropped.

### 5.4 Output

The output is `ISK` (64 bytes) and the peer's AD. Mousse MUST NOT use `ISK` directly as a key. The pairing layer derives any keys it needs from it with HKDF-SHA-512, using its own labels (§4, §10.3).

## 6. Messages

The pairing exchange carries these three messages as opaque payloads and supplies each one's total length. They have no type or version byte of their own. The pairing layer frames and versions them, and the version is bound through `CI`.

| Message | Sender | Bytes |
|---|---|---|
| `msg_a` | initiator | `0x20 · Ya (32) · LEB128(len ADa) · ADa` |
| `msg_b` | responder | `0x20 · Yb (32) · LEB128(len ADb) · ADb · Tb (64)` |
| `msg_c` | initiator | `Ta (64)` |

A receiver MUST reject a message, with `Malformed`, if:

- the first byte of a share isn't `0x20`, or the 32 point bytes are missing;
- the AD length isn't in the shortest LEB128 form (no `0x80`-continued byte followed by a final `0x00`), takes more than 2 bytes, or exceeds 4096;
- fewer AD bytes are present than the length says;
- `msg_a` has any bytes after its AD;
- `msg_b` doesn't have exactly 64 bytes after its AD;
- `msg_c` isn't exactly 64 bytes.

These rules give each share exactly one encoding. That matters because only byte-identical messages may be resent.

A receiver MUST reject an undecodable or identity point with `InvalidPoint`, and a wrong tag with `ConfirmationFailed`.

Any error ends the attempt, and the state is discarded. The pairing layer counts the attempt before any CPace work and doesn't reveal the error to the peer beyond "attempt failed". Both of those are its job.

## 7. Test vectors

- `vectors/cpace-ristretto255-sha512.json`: every value in the draft that applies to this suite. That covers Appendix A.1 and A.3 (`prepend_len`, `lv_cat`, ordering, `o_cat`, `transcript_ir`, `transcript_oc`) and Appendix B.3: generator string, hash and `g`; `ya`, `Ya`, `yb`, `Yb`; `K`; the ISK inputs and `ISK` for both transcript kinds; sid outputs; one valid `scalar_mult` case; and two invalid points. The values were copied from the draft's embedded JSON and checked against the hex printed in its text.
- `vectors/cpace-ristretto255-sha512-mousse.json`: Mousse's own vectors, because the draft has none for key confirmation or framing. It holds two full runs and 24 rejection cases. The first run uses the B.3 inputs, so its `ISK` equals the draft's `ISK_IR`. The second has a 200-byte `ADa`, which needs a two-byte length, and an empty `ADb`. Each run lists `mac_key`, `Ta`, `Tb`, `msg_a`, `msg_b` and `msg_c`. Each rejection names the receiving step, the message and the required error.
- `vectors/cpace-mousse-vectors.py` builds the Mousse file from the draft file using only Python's `hashlib` and `hmac`. It doesn't depend on the Rust code: `python -I cpace-mousse-vectors.py cpace-ristretto255-sha512.json cpace-ristretto255-sha512-mousse.json`.

An implementation passes when it reproduces every value in both files bit for bit and fails every rejection with the listed error.

## 8. Review notes

**Deviations from the draft:** none. Every value the draft defines for this suite is computed as written, and the implementation reproduces all of the draft's B.3 vectors. The choices below are ones the draft leaves to the application, plus two places where its text is loose.

What a reviewer should check:

1. **MAC choice.** §10.4 says "such as HMAC". We use HMAC-SHA-512 with full 64-byte tags. The draft has no confirmation vectors, so ours come from an independent Python script built on the draft's values.
2. **Confirmation order.** B sends `Tb` together with its share, and A sends `Ta` third. The §10.4 construction doesn't depend on order. Because `Tb` goes first, an active attacker playing A gets one offline check of one guessed code per attempt. That is the usual online guess, and the pairing layer's 3-attempt limits bound it.
3. **Binding goes through CI.** The plan requires both confirmations to bind the ticket hash, mode, version, ordered identities and roles, and the peer session's TLS exporter. Here they reach the tags through `CI → g → K → ISK → mac_key`, not as extra MAC input. The pairing spec's `CI` ([`wire.md`](wire.md) 10.5) is a canonical CBOR map, so it reads only one way; it pairs each identity with its role number, puts the initiator first, and uses the inner peer session's exporter (5.5). The `sid` also mixes in that exporter, so the same attempt id on another session gives another generator.
4. **Roles.** The draft requires fixed roles (§10.1). Approval needs both confirmations, and only B sees `Ta` checked, so the host is the responder and the joiner the initiator ([`wire.md`](wire.md) 10.5). The joiner learns that `Ta` was accepted from the host's `PAIRED`.
5. **Mousse restrictions.** `sid` must be at least 16 bytes (the draft allows an empty sid), `PRS` must not be empty, and AD may be at most 4096 bytes. These narrow what the draft allows; they don't change it.
6. **Framing.** The wire form of a share is `lv_cat(Y, AD)` itself, with the shortest-LEB128 rule added. The draft leaves encodings to the application (§4.3).
7. **Loose text in the draft.** §8.3's `sample_scalar` uses `G.group_size_bytes`, which the draft never defines for ristretto255. We read it as 32, and peers can't tell the difference. §8.3 says "element derivation function from the abstraction" without naming RFC 9496 §4.3.4. Vector B.3.1 confirms the one-way map is meant. Resampling a zero scalar isn't in the draft; the chance of hitting one is 2^-252.
8. **Draft status.** -21 is in the RFC Editor queue. Check that the published RFC doesn't change a computation, especially §10.4, which isn't covered by the draft's vectors.
9. **Constant time.** Group operations and the one-way map are constant time in `curve25519-dalek` 5.0.0, and tags are compared with `subtle`. Parsing branches only on public bytes. SHA-512 over the padded generator string follows §10.10. None of this has been measured on wasm32, where the JavaScript engine's JIT is outside our control.
10. **Targets.** The vectors run on x86_64 Windows with the GNU and MSVC toolchains. wasm32-unknown-unknown is only compile-checked so far. Spike 5 needs the vectors to pass on every target in the matrix.
