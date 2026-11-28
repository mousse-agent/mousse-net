"""Builds cpace-ristretto255-sha512-mousse.json.

These vectors cover what the draft has no vectors for: key confirmation
(draft section 10.4 with HMAC-SHA-512), the Mousse message framing, and
rejection cases. The first two runs reuse the points and K from the draft's
Appendix B.3 (K does not depend on AD). The pairing runs compute everything
from their inputs, with the small ristretto255 (RFC 9496) below, first checked
against the draft's generator, shares and K. Everything uses only the Python
standard library and is independent of the Rust code.

Usage: python -I cpace-mousse-vectors.py <cpace-ristretto255-sha512.json> <output.json>
"""

import hashlib
import hmac
import json
import sys

# ---------------------------------------------------------------------------
# ristretto255 (RFC 9496), plain integers. Not constant time: vectors only.
# ---------------------------------------------------------------------------

P = 2**255 - 19
L_ORDER = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = (D - 1) * (D - 1) % P


def is_negative(x):
    return x % P % 2 == 1


def ct_abs(x):
    return (-x) % P if is_negative(x) else x % P


def sqrt_ratio_m1(u, v):
    u, v = u % P, v % P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    correct = check == u
    flipped = check == (-u) % P
    flipped_i = check == (-u) * SQRT_M1 % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return correct or flipped, ct_abs(r)


def check_constants():
    assert SQRT_M1 * SQRT_M1 % P == P - 1
    assert SQRT_AD_MINUS_ONE * SQRT_AD_MINUS_ONE % P == (-D - 1) % P
    assert INVSQRT_A_MINUS_D * INVSQRT_A_MINUS_D % P * ((-1 - D) % P) % P == 1
    assert ONE_MINUS_D_SQ == (1 - D * D) % P
    assert D_MINUS_ONE_SQ == (D - 1) * (D - 1) % P


IDENTITY_POINT = (0, 1, 1, 0)


def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(scalar, point):
    out = IDENTITY_POINT
    for bit in reversed(range(scalar.bit_length())):
        out = point_add(out, out)
        if (scalar >> bit) & 1:
            out = point_add(out, point)
    return out


def decode(b):
    s = int.from_bytes(b, "little")
    if len(b) != 32 or s >= P or is_negative(s):
        return None
    ss = s * s % P
    u1, u2 = (1 - ss) % P, (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 % P * u1) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = ct_abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or is_negative(t) or y == 0:
        return None
    return (x, y, 1, t)


def encode(point):
    x0, y0, z0, t0 = point
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2)
    den1, den2 = invsqrt * u1 % P, invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    if is_negative(t0 * z_inv):
        x, y, den_inv = y0 * SQRT_M1 % P, x0 * SQRT_M1 % P, den1 * INVSQRT_A_MINUS_D % P
    else:
        x, y, den_inv = x0, y0, den2
    if is_negative(x * z_inv):
        y = -y % P
    return ct_abs(den_inv * (z0 - y)).to_bytes(32, "little")


def ristretto_map(b):
    r0 = int.from_bytes(b, "little") % 2**255 % P
    r = SQRT_M1 * r0 % P * r0 % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    c = P - 1
    if not was_square:
        s, c = (-ct_abs(s * r0)) % P, r
    n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0, w1 = 2 * s * v % P, n * SQRT_AD_MINUS_ONE % P
    w2, w3 = (1 - s * s) % P, (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def one_way_map(b64):
    return point_add(ristretto_map(b64[:32]), ristretto_map(b64[32:]))


def generator(prs, ci, sid):
    dsi = b"CPaceRistretto255"
    zpad = max(0, 128 - 1 - len(prepend_len(prs)) - len(prepend_len(dsi)))
    return one_way_map(sha512(lv_cat(dsi, prs, bytes(zpad), ci, sid)))


def scalar_mult(y, encoded):
    point = decode(encoded)
    if point is None:
        return bytes(32)
    return encode(point_mul(int.from_bytes(y, "little"), point))


# ---------------------------------------------------------------------------
# Canonical CBOR (wire.md 3), only what the binding needs.
# ---------------------------------------------------------------------------


def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for extra, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 2 ** (8 * size):
            return bytes([major << 5 | extra]) + n.to_bytes(size, "big")
    raise ValueError("too large")


def cbor(value):
    if isinstance(value, int):
        return cbor_head(0, value)
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return cbor_head(3, len(raw)) + raw
    if isinstance(value, list):
        return cbor_head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        items = sorted((cbor(k), cbor(v)) for k, v in value.items())
        return cbor_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(type(value))


def sha256(b):
    return hashlib.sha256(b).digest()


def leb128(n):
    out = bytearray()
    while True:
        if n < 0x80:
            out.append(n)
            return bytes(out)
        out.append((n & 0x7F) | 0x80)
        n >>= 7


def prepend_len(b):
    return leb128(len(b)) + b


def lv_cat(*parts):
    return b"".join(prepend_len(p) for p in parts)


def sha512(b):
    return hashlib.sha512(b).digest()


def run(d, ada, adb):
    sid, k, ya_pt, yb_pt = (bytes.fromhex(d[x]) for x in ("sid", "K", "Ya", "Yb"))
    msg_a = lv_cat(ya_pt, ada)
    body_b = lv_cat(yb_pt, adb)
    isk = sha512(lv_cat(b"CPaceRistretto255_ISK", sid, k) + msg_a + body_b)
    mac_key = sha512(b"CPaceMac" + sid + isk)
    ta = hmac.new(mac_key, msg_a, hashlib.sha512).digest()
    tb = hmac.new(mac_key, body_b, hashlib.sha512).digest()
    return {
        "ADa": ada.hex(),
        "ADb": adb.hex(),
        "ISK": isk.hex(),
        "mac_key": mac_key.hex(),
        "Ta": ta.hex(),
        "Tb": tb.hex(),
        "msg_a": msg_a.hex(),
        "msg_b": (body_b + tb).hex(),
        "msg_c": ta.hex(),
    }


def check_against_draft(d):
    """The ristretto255 code above reproduces the draft's B.3 values."""
    check_constants()
    prs, ci, sid = (bytes.fromhex(d[x]) for x in ("PRS", "CI", "sid"))
    g = generator(prs, ci, sid)
    assert encode(g).hex() == d["g"], "generator must match the draft's g"
    g_enc = encode(g)
    ya, yb = bytes.fromhex(d["ya"]), bytes.fromhex(d["yb"])
    assert scalar_mult(ya, g_enc).hex() == d["Ya"]
    assert scalar_mult(yb, g_enc).hex() == d["Yb"]
    assert scalar_mult(yb, bytes.fromhex(d["Ya"])).hex() == d["K"]
    assert scalar_mult(ya, bytes.fromhex(d["Yb"])).hex() == d["K"]
    assert encode(point_mul(L_ORDER, g)) == bytes(32)  # the group order


# Pair with IP (wire.md 10.9): the identity keys of join-proof.json (host A
# and the joiner), the code K7QM-2XPA-9RTE, a fixed invitation id, exporter
# and attempt id.
DIRECT_HOST_KEY = bytes.fromhex(
    "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
    "194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
)
DIRECT_JOINER_KEY = bytes.fromhex(
    "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3"
    "50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
)


def direct_run(d, name, code, invitation, pair_exporter, attempt):
    """A full run with kind 3's inputs: PRS is the code's 8 secret
    characters, CI the direct binding transcript, sid as wire.md 10.5."""
    lookup, secret = code[:4], code[4:]
    digest = sha256(cbor({1: "mousse-direct-invite-v1", 2: lookup, 3: invitation}))
    ci = cbor({
        1: "mousse-direct-pair-v1",
        2: digest,
        3: 3,
        4: 1,
        5: [[1, DIRECT_JOINER_KEY], [2, DIRECT_HOST_KEY]],
        6: pair_exporter,
    })
    sid = sha256(cbor({1: "mousse-pair-sid-v1", 2: attempt, 3: pair_exporter}))
    prs = secret.encode("ascii")
    g = encode(generator(prs, ci, sid))
    ya, yb = bytes.fromhex(d["ya"]), bytes.fromhex(d["yb"])
    ya_pt, yb_pt = scalar_mult(ya, g), scalar_mult(yb, g)
    k = scalar_mult(yb, ya_pt)
    assert k == scalar_mult(ya, yb_pt)
    msg_a = lv_cat(ya_pt, b"")
    body_b = lv_cat(yb_pt, b"")
    isk = sha512(lv_cat(b"CPaceRistretto255_ISK", sid, k) + msg_a + body_b)
    mac_key = sha512(b"CPaceMac" + sid + isk)
    ta = hmac.new(mac_key, msg_a, hashlib.sha512).digest()
    tb = hmac.new(mac_key, body_b, hashlib.sha512).digest()
    return {
        "name": name,
        "lookup": lookup,
        "invitation": invitation.hex(),
        "host_identity": DIRECT_HOST_KEY.hex(),
        "joiner_identity": DIRECT_JOINER_KEY.hex(),
        "pair_exporter": pair_exporter.hex(),
        "attempt": attempt.hex(),
        "D": digest.hex(),
        "PRS": prs.hex(),
        "zpad_len": 128 - 1 - len(prepend_len(prs)) - 18,
        "CI": ci.hex(),
        "sid": sid.hex(),
        "ya": d["ya"],
        "yb": d["yb"],
        "g": g.hex(),
        "Ya": ya_pt.hex(),
        "Yb": yb_pt.hex(),
        "K": k.hex(),
        "ISK": isk.hex(),
        "mac_key": mac_key.hex(),
        "Ta": ta.hex(),
        "Tb": tb.hex(),
        "msg_a": msg_a.hex(),
        "msg_b": (body_b + tb).hex(),
        "msg_c": ta.hex(),
    }


def main():
    draft = json.load(open(sys.argv[1], encoding="utf-8"))
    d = draft["cpace"]
    check_against_draft(d)
    common = {k: d[k] for k in ("PRS", "CI", "sid", "ya", "yb", "Ya", "Yb", "K")}

    v1 = run(d, bytes.fromhex(d["ADa"]), bytes.fromhex(d["ADb"]))
    assert v1["ISK"] == d["ISK_IR"], "ISK must match the draft's ISK_IR"
    v2 = run(d, bytes(range(200)), b"")

    ya_pt = bytes.fromhex(d["Ya"])
    yb_pt = bytes.fromhex(d["Yb"])
    ada = bytes.fromhex(v1["ADa"])
    adb = bytes.fromhex(v1["ADb"])
    msg_a = bytes.fromhex(v1["msg_a"])
    body_b = lv_cat(yb_pt, adb)
    ta = bytes.fromhex(v1["Ta"])
    tb = bytes.fromhex(v1["Tb"])
    identity = bytes(32)
    draft_invalid = bytes.fromhex(draft["scalar_mult_vfy_invalid"]["points"][0])
    p_le = bytes.fromhex("ed" + "ff" * 30 + "7f")  # 2^255 - 19, not canonical
    one_le = bytes([1]) + bytes(31)  # odd field element: negative, rejected
    flip = lambda b: b[:-1] + bytes([b[-1] ^ 0x01])

    def rej(name, stage, message, error):
        return {"name": name, "stage": stage, "message": message.hex(), "error": error}

    rejections = [
        rej("empty", "msg_a", b"", "Malformed"),
        rej("truncated", "msg_a", msg_a[:-1], "Malformed"),
        rej("trailing-byte", "msg_a", msg_a + b"\x00", "Malformed"),
        rej("point-length-31", "msg_a", b"\x1f" + ya_pt[:31] + prepend_len(ada), "Malformed"),
        rej("point-length-33", "msg_a", b"\x21" + ya_pt + b"\x00" + prepend_len(ada), "Malformed"),
        rej("ad-length-not-shortest", "msg_a", b"\x20" + ya_pt + b"\x83\x00" + ada, "Malformed"),
        rej("ad-too-long", "msg_a", lv_cat(ya_pt, bytes(4097)), "Malformed"),
        rej("identity-point", "msg_a", lv_cat(identity, ada), "InvalidPoint"),
        rej("draft-invalid-point", "msg_a", lv_cat(draft_invalid, ada), "InvalidPoint"),
        rej("non-canonical-point", "msg_a", lv_cat(p_le, ada), "InvalidPoint"),
        rej("negative-point", "msg_a", lv_cat(one_le, ada), "InvalidPoint"),
        rej("missing-tag", "msg_b", body_b, "Malformed"),
        rej("short-tag", "msg_b", body_b + tb[:63], "Malformed"),
        rej("long-tag", "msg_b", body_b + tb + b"\x00", "Malformed"),
        rej("tag-bit-flip", "msg_b", body_b + flip(tb), "ConfirmationFailed"),
        rej("reflected-initiator-tag", "msg_b", body_b + ta, "ConfirmationFailed"),
        rej("ad-tampered", "msg_b", lv_cat(yb_pt, b"ADc") + tb, "ConfirmationFailed"),
        rej("identity-point", "msg_b", lv_cat(identity, adb) + tb, "InvalidPoint"),
        rej("draft-invalid-point", "msg_b", lv_cat(draft_invalid, adb) + tb, "InvalidPoint"),
        rej("empty", "msg_c", b"", "Malformed"),
        rej("short", "msg_c", ta[:63], "Malformed"),
        rej("long", "msg_c", ta + b"\x00", "Malformed"),
        rej("tag-bit-flip", "msg_c", flip(ta), "ConfirmationFailed"),
        rej("reflected-responder-tag", "msg_c", tb, "ConfirmationFailed"),
    ]

    doc = {
        "profile": "Mousse CPace profile 1: CPACE-RISTR255-SHA512, initiator-responder, key confirmation with HMAC-SHA-512. See spec/cpace.md.",
        "source": "Not from the draft. Built by cpace-mousse-vectors.py from the draft's Appendix B.3 values (draft-irtf-cfrg-cpace-21) with Python's hashlib and hmac.",
        "encoding": "All byte strings are lowercase hex.",
        "common": common,
        "vectors": [dict(name="draft-inputs", **v1), dict(name="long-ada-empty-adb", **v2)],
        "rejections_note": "Each rejection uses the 'common' inputs with ADa/ADb from vector 'draft-inputs'. stage msg_a: the responder receives 'message' as msg_a. stage msg_b: the initiator (after sending the vector's msg_a) receives 'message' as msg_b. stage msg_c: the responder (after receiving the vector's msg_a) receives 'message' as msg_c. 'error' is the CpaceError the step must return; the attempt is over.",
        "rejections": rejections,
        "pairing_runs_note": "Full runs with the inputs pairing gives CPace, every value computed from them (no draft points reused), with empty ADa and ADb. Kind 3, Pair with IP (wire.md 10.9): PRS is the code's 8 secret characters as ASCII (len_zpad 100), CI the direct binding transcript built from lookup, invitation, both identity keys and the pair exporter (D is its digest of the lookup and the invitation id), sid the attempt's session id (wire.md 10.5). The scalars are the draft's ya and yb. The two runs share the lookup and differ only in the secret: D, CI and sid are the same, and msg_a is not.",
        "pairing_runs": [
            direct_run(d, "direct-code", "K7QM2XPA9RTE", bytes(range(16)), bytes([0xE2]) * 32, bytes([0xA7]) * 16),
            direct_run(d, "direct-code-other-secret", "K7QMZZZZ0000", bytes(range(16)), bytes([0xE2]) * 32, bytes([0xA7]) * 16),
        ],
    }
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
