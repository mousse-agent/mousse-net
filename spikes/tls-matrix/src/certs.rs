//! Fresh self-signed P-256 certificates, built without any rustls provider.
//!
//! Signing uses the RustCrypto `p256` crate, so the same code runs on every
//! target, including wasm32 where neither aws-lc-rs nor (without clang) ring
//! is available.

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A certificate, its private key, and the key's SubjectPublicKeyInfo (the pin).
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivatePkcs8KeyDer<'static>,
    /// DER SubjectPublicKeyInfo of the certificate key. Peers pin this.
    pub spki: Vec<u8>,
}

impl Identity {
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

#[derive(Debug)]
pub enum CertError {
    Entropy(String),
    Key(String),
    Cert(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Entropy(e) => write!(f, "entropy: {e}"),
            CertError::Key(e) => write!(f, "key: {e}"),
            CertError::Cert(e) => write!(f, "certificate: {e}"),
        }
    }
}

impl std::error::Error for CertError {}

struct P256Signer {
    key: SigningKey,
    /// SEC1 uncompressed public point, as rcgen expects.
    public: Vec<u8>,
}

impl rcgen::PublicKeyData for P256Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for P256Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let sig: Signature = self.key.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn fresh_signing_key() -> Result<SigningKey, CertError> {
    // Rejection sampling: almost every 32-byte string is a valid scalar.
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| CertError::Entropy(e.to_string()))?;
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            bytes.fill(0);
            return Ok(key);
        }
    }
    Err(CertError::Key("no valid scalar after 16 draws".into()))
}

/// Makes a new key and a self-signed certificate for it.
pub fn generate(name: &str) -> Result<Identity, CertError> {
    let key = fresh_signing_key()?;
    let verifying = *key.verifying_key();
    let public = verifying.to_sec1_point(false).as_bytes().to_vec();
    let spki = verifying
        .to_public_key_der()
        .map_err(|e| CertError::Key(e.to_string()))?
        .as_bytes()
        .to_vec();
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| CertError::Key(e.to_string()))?
        .as_bytes()
        .to_vec();

    let signer = P256Signer { key, public };
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
        .map_err(|e| CertError::Cert(e.to_string()))?;
    // rcgen only picks a serial itself when built with a crypto backend.
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).map_err(|e| CertError::Entropy(e.to_string()))?;
    serial[0] &= 0x7f; // keep it positive
    serial[0] |= 0x01; // and without a leading zero byte
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let cert = params
        .self_signed(&signer)
        .map_err(|e| CertError::Cert(e.to_string()))?;

    Ok(Identity {
        cert: cert.der().clone(),
        key: PrivatePkcs8KeyDer::from(pkcs8),
        spki,
    })
}
