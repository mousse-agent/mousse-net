"""Builds cpace-ristretto255-sha512-mousse.json.

These vectors cover what the draft has no vectors for: key confirmation
(draft section 10.4 with HMAC-SHA-512), the Mousse message framing, and
rejection cases. They reuse the points and K from the draft's Appendix B.3
(K does not depend on AD), so this script needs only SHA-512 and HMAC from the
Python standard library. It is independent of the Rust code.

Usage: python -I cpace-mousse-vectors.py <cpace-ristretto255-sha512.json> <output.json>
"""

import hashlib
import hmac
import json
import sys


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


def main():
    draft = json.load(open(sys.argv[1], encoding="utf-8"))
    d = draft["cpace"]
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
    }
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
