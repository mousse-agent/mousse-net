//! Rebuild a session certificate with another identity-signature field.
//!
//! The certificate profile (spec `wire.md` 5.3) ends `tbsCertificate` with
//! the extensions, whose single extension's value is the binding
//! `SEQUENCE { version, identity_key, identity_signature }`. The identity
//! signature is therefore the last leaf on the "last child" path:
//!
//! ```text
//! tbs 30 > [3] a3 > 30 > Extension 30 > OCTET STRING 04 > binding 30 > 04
//! ```
//!
//! [`replace_identity_signature`] swaps that leaf's content, fixes every
//! length on the way up, and signs the new `tbsCertificate` again with the
//! session key (a closure returning a DER ECDSA signature). Only the spike's
//! negative cases and controls use it.

/// Tags on the path from `tbsCertificate` down to the identity signature.
const PATH: [u8; 7] = [0x30, 0xa3, 0x30, 0x30, 0x04, 0x30, 0x04];

/// One DER element: tag, and where its content sits in the input.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    /// The whole element, header included.
    whole: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let tag = *input.first().ok_or("empty input")?;
    if tag & 0x1f == 0x1f {
        return Err("multi-byte tags are not used here".into());
    }
    let first = *input.get(1).ok_or("truncated length")?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("unsupported length form".into());
        }
        let bytes = input.get(2..2 + n).ok_or("truncated length")?;
        let len = bytes.iter().fold(0usize, |acc, b| acc << 8 | *b as usize);
        (len, 2 + n)
    };
    let end = header + len;
    let whole = input.get(..end).ok_or("truncated content")?;
    Ok((
        Tlv {
            tag,
            content: &whole[header..],
            whole,
        },
        &input[end..],
    ))
}

fn children(content: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (tlv, next) = read_tlv(rest)?;
        out.push(tlv);
        rest = next;
    }
    Ok(out)
}

/// `tag ‖ minimal definite length ‖ content`.
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = Vec::with_capacity(len + 6);
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Replace the last leaf on the last-child path of `element`, `depth`
/// levels down, checking each tag against `tags`.
fn replace_last(element: &[u8], tags: &[u8], leaf: &[u8]) -> Result<Vec<u8>, String> {
    let (tlv, rest) = read_tlv(element)?;
    if !rest.is_empty() {
        return Err("trailing bytes".into());
    }
    if tlv.tag != tags[0] {
        return Err(format!(
            "expected tag {:02x}, found {:02x}",
            tags[0], tlv.tag
        ));
    }
    if tags.len() == 1 {
        return Ok(encode(tlv.tag, leaf));
    }
    let kids = children(tlv.content)?;
    let (last, head) = kids.split_last().ok_or("no children")?;
    let mut content = Vec::with_capacity(tlv.content.len() + leaf.len());
    for k in head {
        content.extend_from_slice(k.whole);
    }
    content.extend_from_slice(&replace_last(last.whole, &tags[1..], leaf)?);
    Ok(encode(tlv.tag, &content))
}

/// The identity-signature field of a session certificate, as stored.
pub fn identity_signature_field(cert: &[u8]) -> Result<Vec<u8>, String> {
    let (outer, _) = read_tlv(cert)?;
    let kids = children(outer.content)?;
    let mut element = kids.first().ok_or("no tbsCertificate")?.whole;
    for (i, tag) in PATH.iter().enumerate() {
        let (tlv, _) = read_tlv(element)?;
        if tlv.tag != *tag {
            return Err(format!("expected tag {tag:02x}, found {:02x}", tlv.tag));
        }
        if i == PATH.len() - 1 {
            return Ok(tlv.content.to_vec());
        }
        element = children(tlv.content)?.last().ok_or("no children")?.whole;
    }
    Err("path too short".into())
}

/// Rebuild `cert` with `field` as its identity-signature content, signing
/// the new `tbsCertificate` with `sign_tbs` (DER ECDSA P-256 / SHA-256).
pub fn replace_identity_signature(
    cert: &[u8],
    field: &[u8],
    sign_tbs: impl Fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    let (outer, rest) = read_tlv(cert)?;
    if outer.tag != 0x30 || !rest.is_empty() {
        return Err("not a single certificate SEQUENCE".into());
    }
    let kids = children(outer.content)?;
    let [tbs, algorithm, _signature] = kids.as_slice() else {
        return Err("certificate must have three parts".into());
    };
    let new_tbs = replace_last(tbs.whole, &PATH, field)?;
    let mut bits = vec![0u8];
    bits.extend_from_slice(&sign_tbs(&new_tbs));
    let mut content = new_tbs;
    content.extend_from_slice(algorithm.whole);
    content.extend_from_slice(&encode(0x03, &bits));
    Ok(encode(0x30, &content))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use mousse_net_core::identity::{RawSignature, SoftwareKey};
    use mousse_net_core::session_cert::{self, CertError, ValidityWindow};
    use mousse_net_core::time::UnixTime;
    use rand_core::UnwrapErr;

    const NOW: u64 = 1_790_000_000;

    fn issue() -> (session_cert::SessionCertificate, SoftwareKey) {
        let identity = SoftwareKey::from_secret_bytes(&[0x11; 32]).unwrap();
        let mut rng = UnwrapErr(getrandom::SysRng);
        let window = ValidityWindow::starting_at(UnixTime(NOW), 86_400).unwrap();
        let cert = session_cert::issue(&identity, &mut rng, window).unwrap();
        (cert, identity)
    }

    #[test]
    fn same_field_keeps_a_valid_certificate() {
        let (cert, identity) = issue();
        let field = identity_signature_field(cert.der()).unwrap();
        assert_eq!(field.len(), 64);
        let again =
            replace_identity_signature(cert.der(), &field, |tbs| cert.key().sign_tls(tbs)).unwrap();
        // Only the self-signature changes (RFC 6979: here not even that).
        assert_eq!(again, cert.der());
        let ok = session_cert::verify(&again, UnixTime(NOW), Some(&identity.public_key())).unwrap();
        assert_eq!(ok.identity, identity.public_key());
    }

    #[test]
    fn der_field_is_refused_as_not_raw() {
        let (cert, identity) = issue();
        let raw = RawSignature::from_slice(&identity_signature_field(cert.der()).unwrap()).unwrap();
        let der = replace_identity_signature(cert.der(), &raw.to_der(), |tbs| {
            cert.key().sign_tls(tbs)
        })
        .unwrap();
        assert_eq!(identity_signature_field(&der).unwrap(), raw.to_der());
        assert_eq!(
            session_cert::verify(&der, UnixTime(NOW), Some(&identity.public_key())),
            Err(CertError::IdentitySignatureNotRaw)
        );
    }

    #[test]
    fn signature_over_another_spki_is_refused() {
        let (cert, identity) = issue();
        let (other, _) = issue();
        let foreign = identity_signature_field(other.der()).unwrap();
        let spliced =
            replace_identity_signature(cert.der(), &foreign, |tbs| cert.key().sign_tls(tbs))
                .unwrap();
        assert_eq!(
            session_cert::verify(&spliced, UnixTime(NOW), Some(&identity.public_key())),
            Err(CertError::IdentitySignatureInvalid)
        );
    }
}
