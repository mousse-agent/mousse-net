//! The relay's self-signed TLS certificate (spec `relay.md` 2.1) and the
//! native client's pin check.
//!
//! The relay identity is the key in this certificate. Native clients ignore
//! the chain, the name, the validity and the self-signature: they take the
//! key from `subjectPublicKeyInfo`, require its hash to be the pinned relay
//! id, and let TLS check `CertificateVerify` with it.

use core::fmt;

use crate::asn1;
use crate::identity::{PublicKey, SoftwareKey, PUBLIC_KEY_LEN};
use crate::session_cert::{serial_for, ECDSA_WITH_SHA256, OID_COMMON_NAME, SPKI_PREFIX};

use super::proof::RelayId;

/// Common name of the relay certificate.
pub const RELAY_COMMON_NAME: &str = "mousse-relay";

/// `notBefore`: 1970-01-01T00:00:00Z as UTCTime.
const NOT_BEFORE: &[u8] = b"700101000000Z";
/// `notAfter`: no well-defined expiry (RFC 5280 4.1.2.5).
const NOT_AFTER: &[u8] = b"99991231235959Z";

/// Why a relay certificate did not pass the pin check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayCertError {
    /// Not a certificate whose key is an uncompressed P-256 point.
    Malformed,
    /// The key's hash is not the pinned relay id.
    PinMismatch,
}

impl fmt::Display for RelayCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the relay certificate does not carry a P-256 key",
            Self::PinMismatch => "the relay key is not the one this route names",
        })
    }
}

impl std::error::Error for RelayCertError {}

fn name() -> Vec<u8> {
    let attr = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::OID, &OID_COMMON_NAME),
            &asn1::tlv(asn1::UTF8_STRING, RELAY_COMMON_NAME.as_bytes()),
        ],
    );
    asn1::tlv(asn1::SEQUENCE, &asn1::tlv(asn1::SET, &attr))
}

/// The relay certificate for `identity`, byte for byte as `relay.md` 2.1
/// gives it.
pub fn relay_certificate(identity: &SoftwareKey) -> Vec<u8> {
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(identity.public_key().as_bytes());
    let validity = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::UTC_TIME, NOT_BEFORE),
            &asn1::tlv(asn1::GENERALIZED_TIME, NOT_AFTER),
        ],
    );
    let name = name();
    let tbs = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::CONTEXT_0, &asn1::tlv(asn1::INTEGER, &[2])),
            &asn1::tlv(asn1::INTEGER, &serial_for(&spki)),
            &ECDSA_WITH_SHA256,
            &name,
            &validity,
            &name,
            &spki,
        ],
    );
    let mut bits = vec![0u8];
    bits.extend_from_slice(&identity.sign_raw(&tbs).to_der());
    asn1::wrap(
        asn1::SEQUENCE,
        &[
            &tbs,
            &ECDSA_WITH_SHA256,
            &asn1::tlv(asn1::BIT_STRING, &bits),
        ],
    )
}

/// The key in a certificate's `subjectPublicKeyInfo`, if it is an
/// uncompressed P-256 point with the fixed prefix. Nothing else is judged.
pub fn certificate_key(der: &[u8]) -> Result<PublicKey, RelayCertError> {
    let malformed = |_| RelayCertError::Malformed;
    let cert = asn1::Reader::new(der)
        .read(asn1::SEQUENCE)
        .map_err(malformed)?;
    let tbs = asn1::Reader::new(cert)
        .read(asn1::SEQUENCE)
        .map_err(malformed)?;
    let mut fields = asn1::Reader::new(tbs);
    // An optional [0] version, then serial, signature, issuer, validity,
    // subject, subjectPublicKeyInfo.
    let (tag, _, _) = fields.read_any().map_err(malformed)?;
    if tag == asn1::CONTEXT_0 {
        fields.read(asn1::INTEGER).map_err(malformed)?;
    } else if tag != asn1::INTEGER {
        return Err(RelayCertError::Malformed);
    }
    for _ in 0..4 {
        fields.read(asn1::SEQUENCE).map_err(malformed)?;
    }
    let spki = fields.read_raw(asn1::SEQUENCE).map_err(malformed)?;
    let point = spki
        .strip_prefix(&SPKI_PREFIX[..])
        .filter(|p| p.len() == PUBLIC_KEY_LEN)
        .ok_or(RelayCertError::Malformed)?;
    PublicKey::from_sec1(point).map_err(|_| RelayCertError::Malformed)
}

/// The native client's check: the certificate's key hashes to `pin`.
/// Returns the key, for checking `CertificateVerify`.
pub fn check_pin(der: &[u8], pin: &RelayId) -> Result<PublicKey, RelayCertError> {
    let key = certificate_key(der)?;
    // Must-fail control (phase3.relay-admission `no-pin-relay`): any relay
    // key passes.
    if cfg!(mousse_control = "no-pin-relay") {
        return Ok(key);
    }
    if RelayId::of(&key) != *pin {
        return Err(RelayCertError::PinMismatch);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn the_certificate_carries_the_identity_and_only_its_pin_passes() {
        let relay = SoftwareKey::from_secret_bytes(&[0x66; 32]).unwrap();
        let other = SoftwareKey::from_secret_bytes(&[0x77; 32]).unwrap();
        let der = relay_certificate(&relay);
        assert_eq!(certificate_key(&der), Ok(relay.public_key()));
        let pin = RelayId::of(&relay.public_key());
        assert_eq!(check_pin(&der, &pin), Ok(relay.public_key()));
        assert_eq!(
            check_pin(&relay_certificate(&other), &pin),
            Err(RelayCertError::PinMismatch)
        );
        assert_eq!(
            certificate_key(&der[..der.len() - 1]),
            Err(RelayCertError::Malformed)
        );
    }
}
