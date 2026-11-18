//! mousse-net-core inside a browser Worker.
//!
//! The Worker holds the identity key as a non-extractable WebCrypto key, so
//! the core never sees it. The core builds the session record, the Worker
//! signs it with WebCrypto (ECDSA P-256, SHA-256, which returns raw `r ‖ s`)
//! and the core assembles the certificate. The core draws no randomness: the
//! Worker passes in the session key's 32 secret bytes from
//! `crypto.getRandomValues`.

use mousse_net_core::identity::{PublicKey, RawSignature};
use mousse_net_core::session_cert::{self, PendingCertificate, SessionKey, ValidityWindow};
use mousse_net_core::time::UnixTime;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn js_err(text: impl std::fmt::Display) -> JsError {
    JsError::new(&text.to_string())
}

fn identity_key(bytes: &[u8]) -> Result<PublicKey, JsError> {
    PublicKey::from_sec1(bytes).map_err(|e| js_err(format!("identity key: {e}")))
}

fn raw_signature(bytes: &[u8]) -> Result<RawSignature, JsError> {
    RawSignature::from_slice(bytes).map_err(|e| js_err(format!("identity signature: {e}")))
}

/// A session certificate waiting for the Worker's identity signature.
#[wasm_bindgen]
pub struct SessionDraft {
    secret: Zeroizing<[u8; 32]>,
    window: ValidityWindow,
    pending: PendingCertificate,
}

#[wasm_bindgen]
impl SessionDraft {
    /// A draft for a fresh session key (`secret`: 32 random bytes) and the
    /// window `[not_before, not_after]` in Unix seconds.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &[u8], not_before: u64, not_after: u64) -> Result<SessionDraft, JsError> {
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| js_err("the session secret must be 32 bytes"))?;
        let secret = Zeroizing::new(secret);
        let key = SessionKey::from_secret_bytes(&secret).map_err(js_err)?;
        let window = ValidityWindow::new(UnixTime(not_before), UnixTime(not_after))
            .map_err(|e| js_err(e.code()))?;
        Ok(Self {
            pending: PendingCertificate::new(key, window),
            secret,
            window,
        })
    }

    fn key(&self) -> Result<SessionKey, JsError> {
        SessionKey::from_secret_bytes(&self.secret).map_err(js_err)
    }

    /// The session record the identity key signs (canonical CBOR).
    pub fn record(&self) -> Vec<u8> {
        self.pending.record().as_bytes().to_vec()
    }

    /// The session key's SubjectPublicKeyInfo, DER.
    pub fn spki(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.key()?.spki_der())
    }

    /// Assemble the certificate. The core checks the identity signature
    /// first and refuses one that does not verify.
    pub fn finish(self, identity: &[u8], signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let cert = self
            .pending
            .finish(identity_key(identity)?, raw_signature(signature)?)
            .map_err(|e| js_err(e.code()))?;
        Ok(cert.der().to_vec())
    }

    /// Must-fail control `tampered-cert`: a certificate for this session key
    /// whose identity signature covers another session key's SPKI.
    ///
    /// The core refuses to assemble it (checked here), so the spike makes
    /// the honest certificate with `own_signature`, puts `foreign_signature`
    /// in its place and signs the certificate again with the session key.
    /// Only the identity binding is wrong; the native verifier must refuse.
    pub fn finish_with_foreign_signature(
        self,
        identity: &[u8],
        own_signature: &[u8],
        foreign_signature: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let identity = identity_key(identity)?;
        let own = raw_signature(own_signature)?;
        let foreign = raw_signature(foreign_signature)?;
        let key = self.key()?;
        if PendingCertificate::new(key.clone(), self.window)
            .finish(identity, foreign)
            .is_ok()
        {
            return Err(js_err(
                "the core assembled a certificate with a signature over another SPKI",
            ));
        }
        let honest = self
            .pending
            .finish(identity, own)
            .map_err(|e| js_err(e.code()))?;
        resign_with(honest.der(), own.as_bytes(), foreign.as_bytes(), &key)
    }
}

/// The certificate profile's signatureAlgorithm, ecdsa-with-SHA256.
const ECDSA_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..=0x7f => vec![len as u8],
        0x80..=0xff => vec![0x81, len as u8],
        _ => vec![0x82, (len >> 8) as u8, len as u8],
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    [&[tag][..], &der_len(content.len()), content].concat()
}

/// Swap `from` for `to` inside the tbsCertificate of `der` and sign it again
/// with `key`. Both certificates in this spike use two-byte lengths.
fn resign_with(der: &[u8], from: &[u8], to: &[u8], key: &SessionKey) -> Result<Vec<u8>, JsError> {
    let malformed = || js_err("unexpected certificate layout");
    if der.get(..2) != Some(&[0x30, 0x82]) || der.get(4..6) != Some(&[0x30, 0x82]) {
        return Err(malformed());
    }
    let tbs_len = usize::from(der[6]) << 8 | usize::from(der[7]);
    let mut tbs = der.get(4..8 + tbs_len).ok_or_else(malformed)?.to_vec();
    let at = tbs
        .windows(from.len())
        .position(|w| w == from)
        .ok_or_else(malformed)?;
    tbs[at..at + from.len()].copy_from_slice(to);
    let mut bits = vec![0u8];
    bits.extend_from_slice(&key.sign_tls(&tbs));
    let body = [&tbs[..], &ECDSA_SHA256, &tlv(0x03, &bits)].concat();
    Ok(tlv(0x30, &body))
}

/// The core's own step 1 check, run inside the Worker: `"ok"` or the
/// rejection name. `pin` may be empty for no pin.
#[wasm_bindgen]
pub fn verify_in_worker(der: &[u8], now: u64, pin: &[u8]) -> String {
    let pin = if pin.is_empty() {
        None
    } else {
        match PublicKey::from_sec1(pin) {
            Ok(key) => Some(key),
            Err(_) => return "bad_pin".into(),
        }
    };
    match session_cert::verify(der, UnixTime(now), pin.as_ref()) {
        Ok(_) => "ok".into(),
        Err(e) => e.code().into(),
    }
}
