//! The building blocks of CPace with ristretto255 and SHA-512, as defined in
//! draft-irtf-cfrg-cpace-21. Section numbers below refer to that draft.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

/// G_Ristretto255.DSI (section 8.3).
pub(crate) const DSI: &[u8] = b"CPaceRistretto255";
/// G.DSI || b"_ISK" (section 7.2).
pub(crate) const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
/// Label for the key-confirmation MAC key (section 10.4).
pub(crate) const MAC_LABEL: &[u8] = b"CPaceMac";
/// H.s_in_bytes for SHA-512 (section 6.2).
pub(crate) const S_IN_BYTES: usize = 128;

/// Length of an encoded ristretto255 element.
pub const POINT_LEN: usize = 32;
/// Length of the intermediate session key: H.b_in_bytes for SHA-512.
pub const ISK_LEN: usize = 64;
/// Length of a key-confirmation tag: the full HMAC-SHA-512 output.
pub const TAG_LEN: usize = 64;

/// G.I: the encoding of the neutral element (all zero bytes for ristretto255).
pub(crate) const IDENTITY: [u8; POINT_LEN] = [0u8; POINT_LEN];

/// Appends the LEB128 encoding of `len` (section 6.3).
pub(crate) fn push_leb128(mut len: usize, out: &mut Vec<u8>) {
    loop {
        if len < 0x80 {
            out.push(len as u8);
            return;
        }
        out.push((len & 0x7f) as u8 | 0x80);
        len >>= 7;
    }
}

/// prepend_len(data), appended to `out` (Appendix A.1.1).
pub(crate) fn push_prepend_len(data: &[u8], out: &mut Vec<u8>) {
    push_leb128(data.len(), out);
    out.extend_from_slice(data);
}

/// lv_cat(parts...) (Appendix A.1.3).
pub(crate) fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 2).sum());
    for part in parts {
        push_prepend_len(part, &mut out);
    }
    out
}

/// Length of prepend_len(data).
fn prepend_len_size(data: &[u8]) -> usize {
    let mut n = 1;
    let mut len = data.len() >> 7;
    while len > 0 {
        n += 1;
        len >>= 7;
    }
    n + data.len()
}

/// generator_string(G.DSI, PRS, CI, sid, H.s_in_bytes) (section 8.1, Appendix A.2).
/// Holds the password, so it is wiped on drop.
pub(crate) fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
    // Must-fail control: the generator leaves the session id out.
    #[cfg(mousse_control = "break-cpace-sid")]
    let sid: &[u8] = {
        let _ = sid;
        &[]
    };
    let len_zpad = S_IN_BYTES
        .saturating_sub(1)
        .saturating_sub(prepend_len_size(prs))
        .saturating_sub(prepend_len_size(DSI));
    let zpad = Zeroizing::new(vec![0u8; len_zpad]);
    let mut out = Zeroizing::new(Vec::with_capacity(
        prepend_len_size(DSI)
            + prepend_len_size(prs)
            + prepend_len_size(&zpad)
            + prepend_len_size(ci)
            + prepend_len_size(sid),
    ));
    for part in [DSI, prs, &zpad[..], ci, sid] {
        push_prepend_len(part, &mut out);
    }
    out
}

/// H.hash(generator_string, 2 * field_size_bytes): the 64 bytes passed to the
/// element derivation function (section 8.3).
pub(crate) fn generator_hash(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<[u8; 64]> {
    let gen_str = generator_string(prs, ci, sid);
    Zeroizing::new(Sha512::digest(&gen_str[..]).into())
}

/// G.calculate_generator(H, PRS, CI, sid) (section 8.3). The element
/// derivation function is the ristretto255 one-way map of RFC 9496
/// section 4.3.4 (`RistrettoPoint::from_uniform_bytes`).
pub(crate) fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&generator_hash(prs, ci, sid))
}

/// G.sample_scalar() as RECOMMENDED in section 8.3: 32 random bytes with the
/// bits above bit 251 cleared, read as a little-endian integer. The result is
/// always below the group order. Zero is resampled (probability 2^-252).
pub(crate) fn sample_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Zeroizing<Scalar> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut bytes[..]);
        bytes[31] &= 0x0f;
        let mut scalar = Scalar::from_bytes_mod_order(*bytes);
        if !bool::from(scalar.ct_eq(&Scalar::ZERO)) {
            return Zeroizing::new(scalar);
        }
        scalar.zeroize();
    }
}

/// G.scalar_mult(y, g) = encode(y * g) (section 8.3).
pub(crate) fn scalar_mult(y: &Scalar, g: &RistrettoPoint) -> [u8; POINT_LEN] {
    (y * g).compress().to_bytes()
}

/// G.scalar_mult_vfy(y, X) (section 8.3): G.I if X does not decode,
/// otherwise encode(y * decode(X)). The caller must abort on G.I.
pub(crate) fn scalar_mult_vfy(y: &Scalar, x: &[u8; POINT_LEN]) -> Zeroizing<[u8; POINT_LEN]> {
    match CompressedRistretto(*x).decompress() {
        Some(point) => Zeroizing::new((y * point).compress().to_bytes()),
        None => Zeroizing::new(IDENTITY),
    }
}

/// True if `encoded` is G.I, compared in constant time.
pub(crate) fn is_identity(encoded: &[u8; POINT_LEN]) -> Choice {
    encoded.ct_eq(&IDENTITY)
}

/// lv_cat(G.DSI || b"_ISK", sid, K) || transcript (section 7.2). Holds K, so it
/// is wiped on drop.
pub(crate) fn isk_input(
    sid: &[u8],
    k: &[u8; POINT_LEN],
    transcript: &[&[u8]],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        prepend_len_size(DSI_ISK)
            + prepend_len_size(sid)
            + prepend_len_size(k)
            + transcript.iter().map(|t| t.len()).sum::<usize>(),
    ));
    push_prepend_len(DSI_ISK, &mut out);
    push_prepend_len(sid, &mut out);
    push_prepend_len(k, &mut out);
    for part in transcript {
        out.extend_from_slice(part);
    }
    out
}

/// ISK = H.hash(isk_input) (section 7.2).
pub(crate) fn isk(
    sid: &[u8],
    k: &[u8; POINT_LEN],
    transcript: &[&[u8]],
) -> Zeroizing<[u8; ISK_LEN]> {
    Zeroizing::new(Sha512::digest(&isk_input(sid, k, transcript)[..]).into())
}

/// mac_key = H.hash(b"CPaceMac" || sid || ISK) (section 10.4). Plain
/// concatenation, exactly as the draft writes it.
pub(crate) fn mac_key(sid: &[u8], isk: &[u8; ISK_LEN]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    h.update(MAC_LABEL);
    h.update(sid);
    h.update(isk);
    Zeroizing::new(h.finalize().into())
}

/// MAC(mac_key, msg) with MAC = HMAC-SHA-512 (section 10.4, RFC 2104).
pub(crate) fn tag(mac_key: &[u8; 64], msg: &[u8]) -> Zeroizing<[u8; TAG_LEN]> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(mac_key)
        .expect("HMAC accepts keys of any length");
    mac.update(msg);
    Zeroizing::new(mac.finalize().into_bytes().into())
}
