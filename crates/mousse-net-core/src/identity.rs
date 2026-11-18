//! Device identity keys (ECDSA P-256) and fixed-width raw signatures.
//!
//! Every identity signature on the wire is raw `r ‖ s`: two 32-byte
//! big-endian integers, 64 bytes total. Platforms that sign in DER (Secure
//! Enclave, Android Keystore) convert with [`RawSignature::from_der`].

use std::fmt;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::asn1;

/// Length of an uncompressed SEC1 P-256 point: `0x04 ‖ X ‖ Y`.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Length of a raw P-256 signature `r ‖ s`.
pub const RAW_SIGNATURE_LEN: usize = 64;

/// Why a public key was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not 65 bytes, or the first byte is not `0x04`.
    NotUncompressed,
    /// The coordinates are not a point on P-256 (or are the identity).
    NotOnCurve,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::NotUncompressed => "public key is not a 65-byte uncompressed SEC1 point",
            KeyError::NotOnCurve => "public key is not a valid P-256 point",
        })
    }
}

impl std::error::Error for KeyError {}

/// Why a signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// A raw signature is not exactly 64 bytes (for example, DER was given
    /// where raw is required).
    NotRaw,
    /// DER input is not a strict DER `Ecdsa-Sig-Value`.
    BadDer,
    /// `r` or `s` is zero or not below the group order.
    OutOfRange,
    /// The signature does not verify.
    Invalid,
}

impl SignatureError {
    /// Stable snake_case name, used in test vectors.
    pub const fn code(self) -> &'static str {
        match self {
            SignatureError::NotRaw => "not_raw",
            SignatureError::BadDer => "bad_der",
            SignatureError::OutOfRange => "out_of_range",
            SignatureError::Invalid => "invalid",
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignatureError::NotRaw => "signature is not 64-byte raw r||s",
            SignatureError::BadDer => "signature is not strict DER",
            SignatureError::OutOfRange => "signature scalar out of range",
            SignatureError::Invalid => "signature does not verify",
        })
    }
}

impl std::error::Error for SignatureError {}

/// A validated P-256 public key in uncompressed SEC1 form.
///
/// Used for identity keys and, inside [`crate::session_cert`], for session
/// keys. Ordering and hashing are over the 65 encoded bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    sec1: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// Parse and validate a 65-byte uncompressed SEC1 point.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, KeyError> {
        let sec1: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| KeyError::NotUncompressed)?;
        if sec1[0] != 0x04 {
            return Err(KeyError::NotUncompressed);
        }
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| KeyError::NotOnCurve)?;
        Ok(Self { sec1 })
    }

    pub(crate) fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_sec1_point(false);
        let mut sec1 = [0u8; PUBLIC_KEY_LEN];
        sec1.copy_from_slice(point.as_bytes());
        Self { sec1 }
    }

    /// The 65 encoded bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sec1
    }

    /// SHA-256 of the 65 encoded bytes. Short, stable, safe to display.
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.sec1).into()
    }

    fn verifying_key(&self) -> VerifyingKey {
        // Validated in every constructor.
        VerifyingKey::from_sec1_bytes(&self.sec1).expect("validated P-256 point")
    }

    /// Verify an ECDSA P-256 / SHA-256 signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &RawSignature) -> Result<(), SignatureError> {
        let sig = Signature::from_slice(&signature.0).map_err(|_| SignatureError::OutOfRange)?;
        self.verifying_key()
            .verify(message, &sig)
            .map_err(|_| SignatureError::Invalid)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = self.fingerprint();
        write!(f, "PublicKey(")?;
        for b in &fp[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// A device's long-lived identity public key.
pub type IdentityPublicKey = PublicKey;

/// A fixed-width ECDSA P-256 signature: `r ‖ s`, each 32 bytes big-endian.
/// Both scalars are checked to be in `[1, n-1]` on construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawSignature(pub(crate) [u8; RAW_SIGNATURE_LEN]);

impl RawSignature {
    /// Accept exactly 64 bytes. Anything else, including a DER signature,
    /// is [`SignatureError::NotRaw`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        // Must-fail control: quietly convert DER where raw is required.
        #[cfg(mousse_control = "break-raw-signature")]
        if bytes.len() != RAW_SIGNATURE_LEN {
            return Self::from_der(bytes);
        }
        let raw: [u8; RAW_SIGNATURE_LEN] = bytes.try_into().map_err(|_| SignatureError::NotRaw)?;
        Signature::from_slice(&raw).map_err(|_| SignatureError::OutOfRange)?;
        Ok(Self(raw))
    }

    /// Convert a strict DER `Ecdsa-Sig-Value` to raw form.
    ///
    /// Rules (spec `wire.md`, "DER to raw"): one SEQUENCE of two INTEGERs and
    /// nothing else; minimal lengths; each INTEGER non-negative and minimal;
    /// after removing at most one leading `0x00`, at most 32 bytes; each is
    /// left-padded with zeros to 32 bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, SignatureError> {
        let seq = asn1::single(der, asn1::SEQUENCE).map_err(|_| SignatureError::BadDer)?;
        let mut reader = asn1::Reader::new(seq);
        let r = reader
            .read(asn1::INTEGER)
            .map_err(|_| SignatureError::BadDer)?;
        let s = reader
            .read(asn1::INTEGER)
            .map_err(|_| SignatureError::BadDer)?;
        reader.finish().map_err(|_| SignatureError::BadDer)?;
        let mut raw = [0u8; RAW_SIGNATURE_LEN];
        for (content, half) in [(r, 0usize), (s, 1usize)] {
            let magnitude =
                asn1::parse_uint_content(content).map_err(|_| SignatureError::BadDer)?;
            if magnitude.len() > 32 {
                return Err(SignatureError::OutOfRange);
            }
            let end = 32 * (half + 1);
            raw[end - magnitude.len()..end].copy_from_slice(magnitude);
        }
        Self::from_slice(&raw)
    }

    /// Strict DER `Ecdsa-Sig-Value` for this signature.
    pub fn to_der(&self) -> Vec<u8> {
        let r = asn1::tlv(asn1::INTEGER, &asn1::uint_content(&self.0[..32]));
        let s = asn1::tlv(asn1::INTEGER, &asn1::uint_content(&self.0[32..]));
        asn1::wrap(asn1::SEQUENCE, &[&r, &s])
    }

    /// The 64 raw bytes.
    pub fn as_bytes(&self) -> &[u8; RAW_SIGNATURE_LEN] {
        &self.0
    }
}

impl fmt::Debug for RawSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawSignature(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// Signing failed in the backing key store (hardware busy, key missing,
/// user cancelled). Carries no secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerError(pub String);

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identity signer failed: {}", self.0)
    }
}

impl std::error::Error for SignerError {}

/// Every domain string an identity key may sign under (spec `wire.md` 4.1).
/// A new signed record needs a new, unique entry here.
pub const IDENTITY_DOMAINS: [&str; 1] = [crate::session_cert::SESSION_DOMAIN];

/// A record the identity key is allowed to sign: canonical CBOR, a map
/// whose key 1 is one of [`IDENTITY_DOMAINS`].
///
/// Only this crate builds these (today: the session record of a
/// [`crate::session_cert::PendingCertificate`]), so an identity key held
/// behind [`IdentitySigner`] can never be asked to sign arbitrary bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    domain: &'static str,
    bytes: Vec<u8>,
}

impl IdentityRecord {
    /// Wrap a record built by this crate. `bytes` MUST be a canonical CBOR
    /// map whose key 1 is `domain`.
    pub(crate) fn new(domain: &'static str, bytes: Vec<u8>) -> Self {
        debug_assert!(IDENTITY_DOMAINS.contains(&domain));
        Self { domain, bytes }
    }

    /// The domain string at key 1.
    pub fn domain(&self) -> &'static str {
        self.domain
    }

    /// The exact bytes to sign (ECDSA P-256, SHA-256).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for IdentityRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityRecord({}, {} bytes)",
            self.domain,
            self.bytes.len()
        )
    }
}

/// Something that holds an identity private key: a hardware key store, a
/// WebCrypto key, or [`SoftwareIdentityKey`].
///
/// `sign` is ECDSA P-256 with SHA-256 over the record's bytes.
/// Implementations that get DER from their platform convert it with
/// [`RawSignature::from_der`]. The identity key signs nothing else: it takes
/// only typed [`IdentityRecord`]s, never raw bytes.
pub trait IdentitySigner {
    /// The identity public key.
    fn public_key(&self) -> IdentityPublicKey;
    /// Sign `record` (the signer hashes its bytes with SHA-256).
    fn sign(&self, record: &IdentityRecord) -> Result<RawSignature, SignerError>;
}

/// A software P-256 key. Used for identity keys where no hardware store
/// exists, and inside [`crate::session_cert::SessionKey`].
///
/// Signatures are deterministic (RFC 6979). The secret scalar is zeroized on
/// drop.
#[derive(Clone)]
pub struct SoftwareKey {
    key: SigningKey,
}

impl SoftwareKey {
    /// A fresh key from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            key: SigningKey::generate_from_rng(rng),
        }
    }

    /// Load a key from its 32-byte big-endian secret scalar.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        SigningKey::from_slice(bytes)
            .map(|key| Self { key })
            .map_err(|_| KeyError::NotOnCurve)
    }

    /// The 32-byte secret scalar, for sealing into a key store.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.key.to_bytes());
        out
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_verifying_key(self.key.verifying_key())
    }

    /// ECDSA P-256 / SHA-256 over `message`, raw form.
    pub fn sign_raw(&self, message: &[u8]) -> RawSignature {
        let sig: Signature = self.key.sign(message);
        RawSignature(sig.to_bytes().into())
    }
}

impl fmt::Debug for SoftwareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SoftwareKey({:?})", self.public_key())
    }
}

/// A software identity key.
pub type SoftwareIdentityKey = SoftwareKey;

impl IdentitySigner for SoftwareKey {
    fn public_key(&self) -> IdentityPublicKey {
        SoftwareKey::public_key(self)
    }

    fn sign(&self, record: &IdentityRecord) -> Result<RawSignature, SignerError> {
        Ok(self.sign_raw(record.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn key(seed: u8) -> SoftwareKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    #[test]
    fn sign_and_verify_and_reject_tampering() {
        let k = key(1);
        let sig = k.sign_raw(b"hello");
        assert_eq!(k.public_key().verify(b"hello", &sig), Ok(()));
        assert_eq!(
            k.public_key().verify(b"hellO", &sig),
            Err(SignatureError::Invalid)
        );
        assert_eq!(
            key(2).public_key().verify(b"hello", &sig),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn high_s_signatures_are_accepted() {
        // P-256 group order n, big-endian.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let k = key(1);
        let sig = k.sign_raw(b"m");
        // s' = n - s also verifies; verifiers must not demand low s.
        let mut flipped = *sig.as_bytes();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(sig.as_bytes()[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            flipped[32 + i] = d.rem_euclid(256) as u8;
        }
        assert_ne!(&flipped, sig.as_bytes());
        let other = RawSignature::from_slice(&flipped).unwrap();
        k.public_key().verify(b"m", &other).unwrap();
    }

    #[test]
    fn der_round_trips_and_matches_an_independent_encoder() {
        let k = key(3);
        for msg in [&b"a"[..], b"b", b"c", b"d", b"e", b"f", b"g", b"h"] {
            let raw = k.sign_raw(msg);
            let der = raw.to_der();
            let reference = ecdsa::Signature::<p256::NistP256>::from_slice(raw.as_bytes())
                .unwrap()
                .to_der();
            assert_eq!(der, reference.as_bytes());
            assert_eq!(RawSignature::from_der(&der), Ok(raw));
        }
    }

    #[test]
    fn der_where_raw_is_required_is_rejected() {
        let raw = key(4).sign_raw(b"x");
        assert_eq!(
            RawSignature::from_slice(&raw.to_der()),
            Err(SignatureError::NotRaw)
        );
    }

    #[test]
    fn non_strict_der_is_rejected() {
        let raw = key(5).sign_raw(b"y");
        let der = raw.to_der();
        // Trailing byte after the SEQUENCE.
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(
            RawSignature::from_der(&trailing),
            Err(SignatureError::BadDer)
        );
        // r padded with a needless leading zero.
        let r = asn1::tlv(
            asn1::INTEGER,
            &[&[0u8][..], &asn1::uint_content(&raw.0[..32])].concat(),
        );
        let s = asn1::tlv(asn1::INTEGER, &asn1::uint_content(&raw.0[32..]));
        let padded = asn1::wrap(asn1::SEQUENCE, &[&r, &s]);
        assert_eq!(RawSignature::from_der(&padded), Err(SignatureError::BadDer));
        // Zero r.
        let zero = asn1::wrap(asn1::SEQUENCE, &[&asn1::tlv(asn1::INTEGER, &[0]), &s]);
        assert_eq!(
            RawSignature::from_der(&zero),
            Err(SignatureError::OutOfRange)
        );
    }

    #[test]
    fn public_keys_must_be_uncompressed_points_on_the_curve() {
        let pk = key(6).public_key();
        assert_eq!(PublicKey::from_sec1(pk.as_bytes()), Ok(pk));
        let mut off_curve = *pk.as_bytes();
        off_curve[64] ^= 1;
        assert_eq!(PublicKey::from_sec1(&off_curve), Err(KeyError::NotOnCurve));
        let mut compressed_tag = *pk.as_bytes();
        compressed_tag[0] = 0x02;
        assert_eq!(
            PublicKey::from_sec1(&compressed_tag),
            Err(KeyError::NotUncompressed)
        );
        assert_eq!(
            PublicKey::from_sec1(&pk.as_bytes()[..33]),
            Err(KeyError::NotUncompressed)
        );
    }
}
