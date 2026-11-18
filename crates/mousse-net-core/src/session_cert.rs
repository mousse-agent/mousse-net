//! Session certificates: step 1 of every connection (identity only).
//!
//! A session certificate is a self-signed X.509 v3 certificate on a fresh
//! P-256 session key. One non-critical extension carries the device's
//! identity public key and the identity key's signature over a canonical CBOR
//! record that names this certificate's exact SPKI and validity window. The
//! profile is fixed byte for byte (spec `wire.md`, "Session certificate"): the
//! certificate is a pure function of the session public key, the window, the
//! protocol version, the identity key and the two signatures.
//!
//! [`verify`] checks, in this order: structure, version, keys, raw signature
//! form, window length, self-signature, identity signature over this SPKI,
//! the expected pin, and the validity window with ±10 min skew.

use std::fmt;

use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::asn1::{self, Reader};
use crate::cbor::{self, Value};
use crate::identity::{
    IdentityPublicKey, IdentityRecord, IdentitySigner, KeyError, PublicKey, RawSignature,
    SignatureError, SignerError, SoftwareKey, PUBLIC_KEY_LEN,
};
use crate::limits::Limits;
use crate::time::UnixTime;
use crate::PROTOCOL_VERSION;

/// Domain string, the first field of the signed record.
pub const SESSION_DOMAIN: &str = "mousse-session-v1";

/// Longest allowed window, `not_after - not_before`, in seconds (24 h).
/// Every verifier enforces it, so it is a protocol constant; an issuer may
/// use a shorter lifetime.
pub const MAX_LIFETIME_SECS: u64 = 86_400;

/// The Mousse session-binding extension OID, under the UUID arc `2.25`
/// (UUID `3295c703-df61-413a-9593-69f74c5ddf05`).
pub const EXTENSION_OID: &str = "2.25.67239088527495828216221962252461137669";

/// DER content octets of [`EXTENSION_OID`].
pub const EXTENSION_OID_DER: [u8; 19] = [
    0x69, 0xe5, 0x95, 0xe3, 0xc0, 0xfb, 0xf6, 0x8a, 0x84, 0xf5, 0x95, 0xc9, 0xda, 0xbe, 0xf4, 0xe2,
    0xf7, 0xbe, 0x05,
];

/// Common name used for both issuer and subject.
pub const COMMON_NAME: &str = "mousse-session";

/// The neutral message the app shows when a certificate is outside its
/// window. A wrong clock and an expired certificate look the same, so it
/// does not guess which.
pub const CLOCK_ERROR_MESSAGE: &str =
    "The certificate is outside its validity window; check this device's clock.";

/// `AlgorithmIdentifier` for ecdsa-with-SHA256 (1.2.840.10045.4.3.2), no
/// parameters.
const ECDSA_WITH_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// SPKI DER prefix for an uncompressed P-256 point: id-ecPublicKey with
/// namedCurve prime256v1, then the BIT STRING header and its zero
/// unused-bits byte. The 65-byte point follows.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// OID 2.5.4.3 (commonName), content octets.
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

/// Why a certificate was rejected (or could not be built).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// Not DER, or not exactly the Mousse certificate profile.
    Malformed,
    /// The binding extension's version is not one this build supports.
    UnsupportedVersion,
    /// The identity key in the extension is not a valid P-256 point.
    IdentityKeyInvalid,
    /// The certificate's public key is not a valid P-256 point.
    SessionKeyInvalid,
    /// The identity signature is not 64-byte raw `r ‖ s` (for example, DER).
    IdentitySignatureNotRaw,
    /// `not_before >= not_after`, or the window is longer than 24 h.
    WindowInvalid,
    /// The certificate's self-signature does not verify with its own key.
    SelfSignatureInvalid,
    /// The identity signature does not verify over the record built from
    /// this certificate's SPKI and window.
    IdentitySignatureInvalid,
    /// The current time is outside the window widened by ±10 min.
    OutsideWindow,
    /// The identity is valid but is not the one pinned for this peer.
    PinMismatch,
}

impl CertError {
    /// Stable snake_case name, used in test vectors.
    pub const fn code(self) -> &'static str {
        match self {
            CertError::Malformed => "malformed",
            CertError::UnsupportedVersion => "unsupported_version",
            CertError::IdentityKeyInvalid => "identity_key_invalid",
            CertError::SessionKeyInvalid => "session_key_invalid",
            CertError::IdentitySignatureNotRaw => "identity_signature_not_raw",
            CertError::WindowInvalid => "window_invalid",
            CertError::SelfSignatureInvalid => "self_signature_invalid",
            CertError::IdentitySignatureInvalid => "identity_signature_invalid",
            CertError::OutsideWindow => "outside_window",
            CertError::PinMismatch => "pin_mismatch",
        }
    }
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertError::OutsideWindow => f.write_str(CLOCK_ERROR_MESSAGE),
            other => write!(f, "session certificate rejected: {}", other.code()),
        }
    }
}

impl std::error::Error for CertError {}

/// A signed validity window: `not_before < not_after`, at most 24 h long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityWindow {
    not_before: UnixTime,
    not_after: UnixTime,
}

impl ValidityWindow {
    /// Validate a window.
    pub fn new(not_before: UnixTime, not_after: UnixTime) -> Result<Self, CertError> {
        if not_before >= not_after || not_after.secs() - not_before.secs() > MAX_LIFETIME_SECS {
            return Err(CertError::WindowInvalid);
        }
        if not_after.secs() > MAX_ENCODABLE_TIME {
            return Err(CertError::WindowInvalid);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// A window from `start` lasting `lifetime_secs`.
    pub fn starting_at(start: UnixTime, lifetime_secs: u64) -> Result<Self, CertError> {
        Self::new(start, start.plus(lifetime_secs))
    }

    /// First second the certificate is valid (signed value).
    pub fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// Last second the certificate is valid (signed value).
    pub fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// Whether `now` is inside `[not_before - 10 min, not_after + 10 min]`
    /// (the default skew).
    pub fn accepts(&self, now: UnixTime) -> bool {
        self.accepts_with_skew(now, Limits::DEFAULT.clock_skew_secs())
    }

    /// Whether `now` is inside `[not_before - skew, not_after + skew]`.
    pub fn accepts_with_skew(&self, now: UnixTime, skew_secs: u64) -> bool {
        now >= self.not_before.minus(skew_secs) && now <= self.deadline_with_skew(skew_secs)
    }

    /// The last second a session on this certificate may stay open:
    /// `not_after + 10 min` (the default skew).
    pub fn effective_deadline(&self) -> UnixTime {
        self.deadline_with_skew(Limits::DEFAULT.clock_skew_secs())
    }

    /// The last second a session on this certificate may stay open:
    /// `not_after + skew`.
    pub fn deadline_with_skew(&self, skew_secs: u64) -> UnixTime {
        self.not_after.plus(skew_secs)
    }
}

/// The DER SPKI for a P-256 public key (always 91 bytes).
pub fn spki_der(key: &PublicKey) -> Vec<u8> {
    spki_from_point(key.as_bytes())
}

fn spki_from_point(point: &[u8]) -> Vec<u8> {
    [&SPKI_PREFIX[..], point].concat()
}

/// The canonical CBOR record the identity key signs:
/// `{1: "mousse-session-v1", 2: spki_der, 3: not_before, 4: not_after, 5: version}`.
pub fn session_record(
    spki_der: &[u8],
    not_before: UnixTime,
    not_after: UnixTime,
    version: u64,
) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, Value::Text(SESSION_DOMAIN.to_owned())),
        (2, Value::Bytes(spki_der.to_vec())),
        (3, Value::Uint(not_before.secs())),
        (4, Value::Uint(not_after.secs())),
        (5, Value::Uint(version)),
    ]))
}

/// A fresh P-256 session key. Lives only as long as its certificate.
#[derive(Clone, Debug)]
pub struct SessionKey(SoftwareKey);

impl SessionKey {
    /// A fresh key from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(SoftwareKey::generate(rng))
    }

    /// Load from a 32-byte secret scalar.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        SoftwareKey::from_secret_bytes(bytes).map(Self)
    }

    /// The session public key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// The DER SPKI of the public key.
    pub fn spki_der(&self) -> Vec<u8> {
        spki_der(&self.public_key())
    }

    /// The private key as PKCS#8 v1 DER (RFC 5208 wrapping an RFC 5915
    /// `ECPrivateKey` with the public key included), as TLS libraries load it.
    pub fn private_key_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let secret = self.0.secret_bytes();
        let public = self.public_key();
        let mut bit_string = Vec::with_capacity(66);
        bit_string.push(0);
        bit_string.extend_from_slice(public.as_bytes());
        let ec_private = Zeroizing::new(asn1::wrap(
            asn1::SEQUENCE,
            &[
                &asn1::tlv(asn1::INTEGER, &[1]),
                &asn1::tlv(asn1::OCTET_STRING, secret.as_slice()),
                &asn1::tlv(asn1::CONTEXT_1, &asn1::tlv(asn1::BIT_STRING, &bit_string)),
            ],
        ));
        let algorithm = &SPKI_PREFIX[2..23];
        Zeroizing::new(asn1::wrap(
            asn1::SEQUENCE,
            &[
                &asn1::tlv(asn1::INTEGER, &[0]),
                algorithm,
                &asn1::tlv(asn1::OCTET_STRING, &ec_private),
            ],
        ))
    }

    /// ECDSA P-256 / SHA-256 signature in DER, as TLS 1.3 CertificateVerify
    /// (`ecdsa_secp256r1_sha256`) carries it.
    pub fn sign_tls(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign_raw(message).to_der()
    }

    fn sign_raw(&self, message: &[u8]) -> RawSignature {
        self.0.sign_raw(message)
    }
}

/// A certificate waiting for its identity signature. Use this when the
/// identity key signs asynchronously (hardware, WebCrypto).
#[derive(Debug)]
pub struct PendingCertificate {
    key: SessionKey,
    window: ValidityWindow,
    record: IdentityRecord,
}

impl PendingCertificate {
    /// Prepare the record for `key` and `window` at [`PROTOCOL_VERSION`].
    pub fn new(key: SessionKey, window: ValidityWindow) -> Self {
        let record = session_record(
            &key.spki_der(),
            window.not_before,
            window.not_after,
            PROTOCOL_VERSION,
        );
        Self {
            key,
            window,
            record: IdentityRecord::new(SESSION_DOMAIN, record),
        }
    }

    /// The record the identity key must sign (ECDSA P-256, SHA-256 over
    /// [`IdentityRecord::as_bytes`]).
    pub fn record(&self) -> &IdentityRecord {
        &self.record
    }

    /// Assemble the certificate. The identity signature is checked first, so
    /// a broken signer can never produce a certificate.
    pub fn finish(
        self,
        identity: IdentityPublicKey,
        signature: RawSignature,
    ) -> Result<SessionCertificate, CertError> {
        identity
            .verify(self.record.as_bytes(), &signature)
            .map_err(|_| CertError::IdentitySignatureInvalid)?;
        let der = build_certificate(
            &self.key,
            self.window.not_before,
            self.window.not_after,
            PROTOCOL_VERSION,
            identity.as_bytes(),
            signature.as_bytes(),
        )?;
        Ok(SessionCertificate {
            der,
            key: self.key,
            identity,
            window: self.window,
        })
    }
}

/// Why [`issue`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// The identity signer failed.
    Signer(SignerError),
    /// The result did not form a valid certificate.
    Cert(CertError),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueError::Signer(e) => write!(f, "{e}"),
            IssueError::Cert(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IssueError {}

/// Make a session certificate with a fresh session key from `rng`.
pub fn issue<R: CryptoRng + ?Sized>(
    signer: &dyn IdentitySigner,
    rng: &mut R,
    window: ValidityWindow,
) -> Result<SessionCertificate, IssueError> {
    let pending = PendingCertificate::new(SessionKey::generate(rng), window);
    let signature = signer.sign(pending.record()).map_err(IssueError::Signer)?;
    pending
        .finish(signer.public_key(), signature)
        .map_err(IssueError::Cert)
}

/// Our own certificate and its session private key.
#[derive(Clone, Debug)]
pub struct SessionCertificate {
    der: Vec<u8>,
    key: SessionKey,
    identity: IdentityPublicKey,
    window: ValidityWindow,
}

impl SessionCertificate {
    /// The certificate DER, as sent in the TLS Certificate message.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The session key (for TLS CertificateVerify).
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// The identity this certificate speaks for.
    pub fn identity(&self) -> &IdentityPublicKey {
        &self.identity
    }

    /// The signed window.
    pub fn window(&self) -> ValidityWindow {
        self.window
    }
}

/// A peer certificate that passed every step 1 check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSessionCert {
    /// The peer's identity key. Step 2 and pins use this.
    pub identity: IdentityPublicKey,
    /// The peer's session public key (verifies TLS CertificateVerify).
    pub session_key: PublicKey,
    /// The exact SPKI DER from the certificate.
    pub spki_der: Vec<u8>,
    /// The signed window.
    pub window: ValidityWindow,
    /// The protocol version from the binding extension.
    pub version: u64,
}

impl VerifiedSessionCert {
    /// Verify a TLS 1.3 CertificateVerify signature (`ecdsa_secp256r1_sha256`,
    /// DER) made by this certificate's session key over `message`.
    pub fn verify_tls_signature(
        &self,
        message: &[u8],
        der_signature: &[u8],
    ) -> Result<(), SignatureError> {
        let raw = RawSignature::from_der(der_signature)?;
        self.session_key.verify(message, &raw)
    }
}

/// Step 1: verify a peer's session certificate at `now`.
///
/// `expected_identity` is the pin for this peer: the stored pin on every
/// reconnect, bulk session and path switch, or the ticket's host identity on
/// first contact. Pass `None` only where step 2 will decide (a host accepting
/// an incoming connection). Allows the default clock skew; see
/// [`verify_with_skew`].
pub fn verify(
    der: &[u8],
    now: UnixTime,
    expected_identity: Option<&IdentityPublicKey>,
) -> Result<VerifiedSessionCert, CertError> {
    verify_with_skew(
        der,
        now,
        expected_identity,
        Limits::DEFAULT.clock_skew_secs(),
    )
}

/// [`verify`] allowing `skew_secs` of clock difference
/// ([`Limits::clock_skew_secs`]).
pub fn verify_with_skew(
    der: &[u8],
    now: UnixTime,
    expected_identity: Option<&IdentityPublicKey>,
    skew_secs: u64,
) -> Result<VerifiedSessionCert, CertError> {
    let parts = parse(der)?;

    if parts.version != PROTOCOL_VERSION {
        return Err(CertError::UnsupportedVersion);
    }
    let identity =
        PublicKey::from_sec1(parts.identity_key).map_err(|_| CertError::IdentityKeyInvalid)?;
    let session_key =
        PublicKey::from_sec1(&parts.session_point).map_err(|_| CertError::SessionKeyInvalid)?;
    let identity_signature = match RawSignature::from_slice(parts.identity_signature) {
        Ok(sig) => Some(sig),
        Err(SignatureError::NotRaw) => return Err(CertError::IdentitySignatureNotRaw),
        // Right length, scalars out of range: it cannot verify.
        Err(_) => None,
    };
    let window = ValidityWindow::new(parts.not_before, parts.not_after)?;

    let self_signature = RawSignature::from_der(parts.self_signature_der)
        .map_err(|_| CertError::SelfSignatureInvalid)?;
    session_key
        .verify(parts.tbs, &self_signature)
        .map_err(|_| CertError::SelfSignatureInvalid)?;

    let spki = spki_from_point(&parts.session_point);
    let record = session_record(&spki, parts.not_before, parts.not_after, parts.version);
    let identity_signature = identity_signature.ok_or(CertError::IdentitySignatureInvalid)?;
    // Must-fail control: skip the identity-signature check.
    #[cfg(not(mousse_control = "break-session-cert"))]
    identity
        .verify(&record, &identity_signature)
        .map_err(|_| CertError::IdentitySignatureInvalid)?;
    #[cfg(mousse_control = "break-session-cert")]
    let _ = (&record, &identity_signature);

    // The pin comes before the window: a foreign endpoint on a candidate
    // address must read as "not this peer, try the next address", never as
    // a clock problem.
    if let Some(expected) = expected_identity {
        if *expected != identity {
            return Err(CertError::PinMismatch);
        }
    }
    if !window.accepts_with_skew(now, skew_secs) {
        return Err(CertError::OutsideWindow);
    }
    Ok(VerifiedSessionCert {
        identity,
        session_key,
        spki_der: spki,
        window,
        version: parts.version,
    })
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Latest second representable in the certificate (9999-12-31T23:59:59Z).
const MAX_ENCODABLE_TIME: u64 = 253_402_300_799;

/// Serial number: SHA-256 of the SPKI DER, first 16 bytes, with the first
/// byte forced into `0x40..=0x7f` (positive, no leading zero, fixed length).
pub(crate) fn serial_for(spki: &[u8]) -> [u8; 16] {
    let hash = Sha256::digest(spki);
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&hash[..16]);
    serial[0] = (serial[0] & 0x3f) | 0x40;
    serial
}

fn name_der() -> Vec<u8> {
    let attr = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::OID, &OID_COMMON_NAME),
            &asn1::tlv(asn1::UTF8_STRING, COMMON_NAME.as_bytes()),
        ],
    );
    asn1::tlv(asn1::SEQUENCE, &asn1::tlv(asn1::SET, &attr))
}

pub(crate) fn binding_der(version: u64, identity_key: &[u8], identity_signature: &[u8]) -> Vec<u8> {
    asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::INTEGER, &asn1::uint_content(&version.to_be_bytes())),
            &asn1::tlv(asn1::OCTET_STRING, identity_key),
            &asn1::tlv(asn1::OCTET_STRING, identity_signature),
        ],
    )
}

pub(crate) fn tbs_der(
    session_point: &[u8],
    not_before: UnixTime,
    not_after: UnixTime,
    version: u64,
    identity_key: &[u8],
    identity_signature: &[u8],
) -> Result<Vec<u8>, CertError> {
    let spki = spki_from_point(session_point);
    let validity = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &encode_time(not_before.secs())?,
            &encode_time(not_after.secs())?,
        ],
    );
    let extension = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::OID, &EXTENSION_OID_DER),
            &asn1::tlv(
                asn1::OCTET_STRING,
                &binding_der(version, identity_key, identity_signature),
            ),
        ],
    );
    let extensions = asn1::tlv(asn1::CONTEXT_3, &asn1::tlv(asn1::SEQUENCE, &extension));
    let name = name_der();
    Ok(asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::CONTEXT_0, &asn1::tlv(asn1::INTEGER, &[2])),
            &asn1::tlv(asn1::INTEGER, &serial_for(&spki)),
            &ECDSA_WITH_SHA256,
            &name,
            &validity,
            &name,
            &spki,
            &extensions,
        ],
    ))
}

fn certificate_der(tbs: &[u8], self_signature: &RawSignature) -> Vec<u8> {
    certificate_with_signature_value(tbs, &self_signature.to_der())
}

/// The certificate around `tbs` with these signature-value bytes (normally
/// a DER `Ecdsa-Sig-Value`). Vectors use it to build bad self-signatures.
pub(crate) fn certificate_with_signature_value(tbs: &[u8], signature_value: &[u8]) -> Vec<u8> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(signature_value);
    asn1::wrap(
        asn1::SEQUENCE,
        &[tbs, &ECDSA_WITH_SHA256, &asn1::tlv(asn1::BIT_STRING, &bits)],
    )
}

/// Build a certificate from raw parts. Does not check the identity parts, so
/// tests can build rejection vectors with it.
pub(crate) fn build_certificate(
    key: &SessionKey,
    not_before: UnixTime,
    not_after: UnixTime,
    version: u64,
    identity_key: &[u8],
    identity_signature: &[u8],
) -> Result<Vec<u8>, CertError> {
    let point = key.public_key();
    let tbs = tbs_der(
        point.as_bytes(),
        not_before,
        not_after,
        version,
        identity_key,
        identity_signature,
    )?;
    let self_signature = key.sign_raw(&tbs);
    Ok(certificate_der(&tbs, &self_signature))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct Parts<'a> {
    tbs: &'a [u8],
    session_point: [u8; PUBLIC_KEY_LEN],
    not_before: UnixTime,
    not_after: UnixTime,
    version: u64,
    identity_key: &'a [u8],
    identity_signature: &'a [u8],
    self_signature_der: &'a [u8],
}

fn parse(der: &[u8]) -> Result<Parts<'_>, CertError> {
    let parts = parse_fields(der).map_err(|_| CertError::Malformed)?;
    // The profile is fixed: re-encoding the parsed fields must give back the
    // exact input. This rejects every alternative encoding (other names,
    // serials, extra extensions, critical flags, time forms, non-minimal DER).
    let tbs = tbs_der(
        &parts.session_point,
        parts.not_before,
        parts.not_after,
        parts.version,
        parts.identity_key,
        parts.identity_signature,
    )
    .map_err(|_| CertError::Malformed)?;
    if tbs != parts.tbs {
        return Err(CertError::Malformed);
    }
    let mut bits = vec![0u8];
    bits.extend_from_slice(parts.self_signature_der);
    let rebuilt = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &tbs,
            &ECDSA_WITH_SHA256,
            &asn1::tlv(asn1::BIT_STRING, &bits),
        ],
    );
    if rebuilt != der {
        return Err(CertError::Malformed);
    }
    // The signature value is part of the profile: a strict DER
    // `Ecdsa-Sig-Value` (spec 4.3). Well-formed scalars that are zero or not
    // below the group order fail later, as a self-signature error.
    if matches!(
        RawSignature::from_der(parts.self_signature_der),
        Err(SignatureError::BadDer)
    ) {
        return Err(CertError::Malformed);
    }
    Ok(parts)
}

fn parse_fields(der: &[u8]) -> Result<Parts<'_>, asn1::DerError> {
    use asn1::DerError;
    let certificate = asn1::single(der, asn1::SEQUENCE)?;
    let mut cert = Reader::new(certificate);
    let tbs = cert.read_raw(asn1::SEQUENCE)?;
    let _algorithm = cert.read(asn1::SEQUENCE)?;
    let signature_bits = cert.read(asn1::BIT_STRING)?;
    cert.finish()?;
    let self_signature_der = match signature_bits {
        [0, rest @ ..] => rest,
        _ => return Err(DerError),
    };

    let mut t = Reader::new(asn1::single(tbs, asn1::SEQUENCE)?);
    let _version = t.read(asn1::CONTEXT_0)?;
    let _serial = t.read(asn1::INTEGER)?;
    let _algorithm = t.read(asn1::SEQUENCE)?;
    let _issuer = t.read(asn1::SEQUENCE)?;
    let validity = t.read(asn1::SEQUENCE)?;
    let _subject = t.read(asn1::SEQUENCE)?;
    let spki = t.read_raw(asn1::SEQUENCE)?;
    let extensions = t.read(asn1::CONTEXT_3)?;
    t.finish()?;

    let mut v = Reader::new(validity);
    let (nb_tag, _, nb) = v.read_any()?;
    let (na_tag, _, na) = v.read_any()?;
    v.finish()?;
    let not_before = parse_time(nb_tag, nb)?;
    let not_after = parse_time(na_tag, na)?;

    let point = spki.strip_prefix(&SPKI_PREFIX[..]).ok_or(DerError)?;
    let session_point: [u8; PUBLIC_KEY_LEN] = point.try_into().map_err(|_| DerError)?;

    let mut list = Reader::new(asn1::single(extensions, asn1::SEQUENCE)?);
    let extension = list.read(asn1::SEQUENCE)?;
    list.finish()?;
    let mut e = Reader::new(extension);
    let oid = e.read(asn1::OID)?;
    if oid != EXTENSION_OID_DER {
        return Err(DerError);
    }
    let value = e.read(asn1::OCTET_STRING)?;
    e.finish()?;

    let mut b = Reader::new(asn1::single(value, asn1::SEQUENCE)?);
    let version_bytes = asn1::parse_uint_content(b.read(asn1::INTEGER)?)?;
    if version_bytes.len() > 8 {
        return Err(DerError);
    }
    let version = version_bytes
        .iter()
        .fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    let identity_key = b.read(asn1::OCTET_STRING)?;
    let identity_signature = b.read(asn1::OCTET_STRING)?;
    b.finish()?;

    Ok(Parts {
        tbs,
        session_point,
        not_before,
        not_after,
        version,
        identity_key,
        identity_signature,
        self_signature_der,
    })
}

// ---------------------------------------------------------------------------
// X.509 time: UTCTime for years 1950-2049, GeneralizedTime from 2050 (RFC 5280).
// ---------------------------------------------------------------------------

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn encode_time(secs: u64) -> Result<Vec<u8>, CertError> {
    if secs > MAX_ENCODABLE_TIME {
        return Err(CertError::WindowInvalid);
    }
    let secs = secs as i64;
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    if year < 2050 {
        let text = format!(
            "{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z",
            year % 100
        );
        Ok(asn1::tlv(asn1::UTC_TIME, text.as_bytes()))
    } else {
        let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        Ok(asn1::tlv(asn1::GENERALIZED_TIME, text.as_bytes()))
    }
}

fn parse_time(tag: u8, content: &[u8]) -> Result<UnixTime, asn1::DerError> {
    use asn1::DerError;
    let digits = |s: &[u8]| -> Result<i64, DerError> {
        s.iter().try_fold(0i64, |acc, c| {
            if c.is_ascii_digit() {
                Ok(acc * 10 + i64::from(c - b'0'))
            } else {
                Err(DerError)
            }
        })
    };
    let (year, rest) = match (tag, content.len()) {
        (asn1::UTC_TIME, 13) => {
            let yy = digits(&content[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &content[2..])
        }
        (asn1::GENERALIZED_TIME, 15) => (digits(&content[..4])?, &content[4..]),
        _ => return Err(DerError),
    };
    if rest[10] != b'Z' {
        return Err(DerError);
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let minute = digits(&rest[6..8])?;
    let second = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return Err(DerError);
    }
    let days = days_from_civil(year, month, day);
    // Reject impossible days such as February 30th: they would not round-trip.
    if civil_from_days(days) != (year, month, day) {
        return Err(DerError);
    }
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).map(UnixTime).map_err(|_| DerError)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const T0: UnixTime = UnixTime(1_790_000_000); // 2026-09-21

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn identity(seed: u8) -> SoftwareKey {
        SoftwareKey::generate(&mut rng(seed))
    }

    fn cert(id: &SoftwareKey, seed: u8) -> SessionCertificate {
        let window = ValidityWindow::starting_at(T0, 86_400).unwrap();
        issue(id, &mut rng(seed), window).unwrap()
    }

    #[test]
    fn oid_bytes_match_the_uuid_integer() {
        let mut n: u128 = 67_239_088_527_495_828_216_221_962_252_461_137_669;
        let mut groups = Vec::new();
        while n > 0 {
            groups.push((n & 0x7f) as u8);
            n >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        let mut expected = vec![2 * 40 + 25];
        for (i, g) in groups.iter().enumerate() {
            expected.push(if i == last { *g } else { g | 0x80 });
        }
        assert_eq!(expected, EXTENSION_OID_DER);
    }

    #[test]
    fn issued_certificate_verifies_and_returns_the_identity() {
        let id = identity(1);
        let c = cert(&id, 2);
        let v = verify(c.der(), T0, Some(&id.public_key())).unwrap();
        assert_eq!(v.identity, id.public_key());
        assert_eq!(v.session_key, c.key().public_key());
        assert_eq!(v.spki_der, c.key().spki_der());
        let msg = b"tls transcript";
        assert_eq!(v.verify_tls_signature(msg, &c.key().sign_tls(msg)), Ok(()));
        assert!(v
            .verify_tls_signature(b"other", &c.key().sign_tls(msg))
            .is_err());
    }

    #[test]
    fn spki_is_91_bytes_and_parses_as_p256() {
        let key = SessionKey::generate(&mut rng(3));
        let spki = key.spki_der();
        assert_eq!(spki.len(), 91);
        let reader = asn1::single(&spki, asn1::SEQUENCE);
        assert!(reader.is_ok());
    }

    #[test]
    fn window_edges_with_skew() {
        let id = identity(1);
        let c = cert(&id, 2);
        let nb = T0;
        let na = T0.plus(86_400);
        for (now, ok) in [
            (nb.minus(600), true),
            (nb.minus(601), false),
            (na.plus(600), true),
            (na.plus(601), false),
        ] {
            let r = verify(c.der(), now, None);
            assert_eq!(r.is_ok(), ok, "now={now:?}");
            if !ok {
                assert_eq!(r.unwrap_err(), CertError::OutsideWindow);
            }
        }
    }

    #[test]
    fn pin_mismatch_is_rejected_even_when_everything_else_is_valid() {
        let c = cert(&identity(1), 2);
        assert_eq!(
            verify(c.der(), T0, Some(&identity(9).public_key())),
            Err(CertError::PinMismatch)
        );
    }

    #[test]
    fn pin_is_checked_before_the_window() {
        // A foreign endpoint whose certificate is also out of its window
        // must still read as "not this peer".
        let c = cert(&identity(1), 2);
        assert_eq!(
            verify(
                c.der(),
                T0.plus(10 * 86_400),
                Some(&identity(9).public_key())
            ),
            Err(CertError::PinMismatch)
        );
    }

    #[test]
    fn identity_signature_over_a_different_spki_is_rejected() {
        let id = identity(1);
        let tls_key = SessionKey::generate(&mut rng(2));
        let other_key = SessionKey::generate(&mut rng(3));
        let window = ValidityWindow::starting_at(T0, 3600).unwrap();
        let record = session_record(
            &other_key.spki_der(),
            window.not_before(),
            window.not_after(),
            1,
        );
        let sig = id.sign_raw(&record);
        let der = build_certificate(
            &tls_key,
            window.not_before(),
            window.not_after(),
            1,
            id.public_key().as_bytes(),
            sig.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify(&der, T0, None),
            Err(CertError::IdentitySignatureInvalid)
        );
    }

    #[test]
    fn der_identity_signature_is_rejected() {
        let id = identity(1);
        let key = SessionKey::generate(&mut rng(2));
        let window = ValidityWindow::starting_at(T0, 3600).unwrap();
        let record = session_record(&key.spki_der(), window.not_before(), window.not_after(), 1);
        let der_sig = id.sign_raw(&record).to_der();
        let der = build_certificate(
            &key,
            window.not_before(),
            window.not_after(),
            1,
            id.public_key().as_bytes(),
            &der_sig,
        )
        .unwrap();
        assert_eq!(
            verify(&der, T0, None),
            Err(CertError::IdentitySignatureNotRaw)
        );
    }

    #[test]
    fn long_windows_are_rejected_at_build_and_verify() {
        assert_eq!(
            ValidityWindow::starting_at(T0, 86_401),
            Err(CertError::WindowInvalid)
        );
        assert_eq!(ValidityWindow::new(T0, T0), Err(CertError::WindowInvalid));
        let id = identity(1);
        let key = SessionKey::generate(&mut rng(2));
        let na = T0.plus(86_401);
        let record = session_record(&key.spki_der(), T0, na, 1);
        let sig = id.sign_raw(&record);
        let der =
            build_certificate(&key, T0, na, 1, id.public_key().as_bytes(), sig.as_bytes()).unwrap();
        assert_eq!(verify(&der, T0, None), Err(CertError::WindowInvalid));
    }

    #[test]
    fn any_single_byte_change_is_rejected() {
        let c = cert(&identity(1), 2);
        let der = c.der().to_vec();
        for i in 0..der.len() {
            let mut bad = der.clone();
            bad[i] ^= 0x01;
            assert!(verify(&bad, T0, None).is_err(), "flip at byte {i} accepted");
        }
        let mut longer = der.clone();
        longer.push(0);
        assert_eq!(verify(&longer, T0, None), Err(CertError::Malformed));
        assert_eq!(
            verify(&der[..der.len() - 1], T0, None),
            Err(CertError::Malformed)
        );
    }

    #[test]
    fn a_marked_critical_extension_is_rejected() {
        let c = cert(&identity(1), 2);
        // Insert BOOLEAN TRUE after the OID inside the extension: the
        // re-encoding check must refuse it.
        let der = c.der();
        let oid_tlv = asn1::tlv(asn1::OID, &EXTENSION_OID_DER);
        let at = der
            .windows(oid_tlv.len())
            .position(|w| w == oid_tlv)
            .unwrap()
            + oid_tlv.len();
        let mut bad = der[..at].to_vec();
        bad.extend_from_slice(&[0x01, 0x01, 0xff]);
        bad.extend_from_slice(&der[at..]);
        assert_eq!(verify(&bad, T0, None), Err(CertError::Malformed));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let id = identity(1);
        let key = SessionKey::generate(&mut rng(2));
        let window = ValidityWindow::starting_at(T0, 3600).unwrap();
        let record = session_record(&key.spki_der(), window.not_before(), window.not_after(), 2);
        let sig = id.sign_raw(&record);
        let der = build_certificate(
            &key,
            window.not_before(),
            window.not_after(),
            2,
            id.public_key().as_bytes(),
            sig.as_bytes(),
        )
        .unwrap();
        assert_eq!(verify(&der, T0, None), Err(CertError::UnsupportedVersion));
    }

    #[test]
    fn times_round_trip_across_the_utc_generalized_boundary() {
        for secs in [
            0u64,
            951_782_400,
            1_790_000_000,
            2_524_607_999,
            2_524_608_000,
            MAX_ENCODABLE_TIME,
        ] {
            let tlv = encode_time(secs).unwrap();
            let expected_tag = if secs < 2_524_608_000 {
                asn1::UTC_TIME
            } else {
                asn1::GENERALIZED_TIME
            };
            assert_eq!(tlv[0], expected_tag, "secs={secs}");
            assert_eq!(parse_time(tlv[0], &tlv[2..]), Ok(UnixTime(secs)));
        }
        assert_eq!(encode_time(1_790_000_000).unwrap()[2..], *b"260921141320Z");
        assert!(parse_time(asn1::UTC_TIME, b"260230000000Z").is_err());
        assert!(parse_time(asn1::UTC_TIME, b"2609211403Z00").is_err());
    }

    #[test]
    fn pkcs8_has_the_standard_layout() {
        let key = SessionKey::generate(&mut rng(4));
        let der = key.private_key_pkcs8_der();
        assert_eq!(der.len(), 138);
        assert_eq!(der[..3], [0x30, 0x81, 0x87]);
        assert_eq!(&der[der.len() - 65..], key.public_key().as_bytes());
    }

    #[test]
    fn pending_certificate_refuses_a_bad_identity_signature() {
        let id = identity(1);
        let pending = PendingCertificate::new(
            SessionKey::generate(&mut rng(2)),
            ValidityWindow::starting_at(T0, 60).unwrap(),
        );
        let wrong = id.sign_raw(b"not the record");
        assert_eq!(
            pending.finish(id.public_key(), wrong).unwrap_err(),
            CertError::IdentitySignatureInvalid
        );
    }
}
