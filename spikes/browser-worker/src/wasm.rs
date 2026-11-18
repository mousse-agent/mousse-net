//! The Worker's side, exported with wasm-bindgen.
//!
//! The session key is made here, in Rust, from `crypto.getRandomValues`
//! (through `getrandom`). The identity key never enters wasm: JavaScript
//! signs [`Pending::record`] with WebCrypto and hands back the raw `r ‖ s`
//! signature and the SEC1 public key, and [`Pending::finish`] assembles the
//! certificate. Time comes from the host as an explicit value.

use mousse_net_core::identity::{PublicKey, RawSignature};
use mousse_net_core::session_cert::{
    PendingCertificate, SessionCertificate, SessionKey, ValidityWindow,
};
use mousse_net_core::time::UnixTime;
use rand_core::UnwrapErr;
use wasm_bindgen::prelude::*;

use crate::splice;

fn secs(value: f64, what: &str) -> Result<u64, JsError> {
    if value.is_finite() && value >= 0.0 && value <= u64::MAX as f64 {
        Ok(value as u64)
    } else {
        Err(JsError::new(&format!("{what} is not a time in seconds")))
    }
}

/// A certificate waiting for the WebCrypto identity signature.
#[wasm_bindgen]
pub struct Pending {
    inner: Option<PendingCertificate>,
    window: ValidityWindow,
}

#[wasm_bindgen]
impl Pending {
    /// A fresh session key and a window `[now, now + lifetime]`.
    #[wasm_bindgen(constructor)]
    pub fn new(now_secs: f64, lifetime_secs: f64) -> Result<Pending, JsError> {
        let window = ValidityWindow::starting_at(
            UnixTime(secs(now_secs, "now")?),
            secs(lifetime_secs, "lifetime")?,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        let key = SessionKey::generate(&mut UnwrapErr(getrandom::SysRng));
        Ok(Pending {
            inner: Some(PendingCertificate::new(key, window)),
            window,
        })
    }

    /// The exact bytes the identity key signs (ECDSA P-256, SHA-256).
    pub fn record(&self) -> Result<Vec<u8>, JsError> {
        match &self.inner {
            Some(p) => Ok(p.record().to_vec()),
            None => Err(JsError::new("already finished")),
        }
    }

    #[wasm_bindgen(getter, js_name = notBefore)]
    pub fn not_before(&self) -> f64 {
        self.window.not_before().secs() as f64
    }

    #[wasm_bindgen(getter, js_name = notAfter)]
    pub fn not_after(&self) -> f64 {
        self.window.not_after().secs() as f64
    }

    /// Assemble the certificate. `signature` must be the 64-byte raw form;
    /// anything else (DER included) is refused.
    pub fn finish(&mut self, identity_sec1: &[u8], signature: &[u8]) -> Result<Cert, JsError> {
        let pending = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("already finished"))?;
        let identity =
            PublicKey::from_sec1(identity_sec1).map_err(|e| JsError::new(&e.to_string()))?;
        let signature =
            RawSignature::from_slice(signature).map_err(|e| JsError::new(&e.to_string()))?;
        let inner = pending
            .finish(identity, signature)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Cert { inner })
    }
}

/// A finished certificate and its session key.
#[wasm_bindgen]
pub struct Cert {
    inner: SessionCertificate,
}

#[wasm_bindgen]
impl Cert {
    /// The certificate DER.
    pub fn der(&self) -> Vec<u8> {
        self.inner.der().to_vec()
    }

    /// For negative cases and controls only: the same certificate with
    /// `field` in place of the identity signature, self-signed again with
    /// this session key so only the identity signature is wrong.
    #[wasm_bindgen(js_name = withIdentitySignature)]
    pub fn with_identity_signature(&self, field: &[u8]) -> Result<Vec<u8>, JsError> {
        let key = self.inner.key();
        splice::replace_identity_signature(self.inner.der(), field, |tbs| key.sign_tls(tbs))
            .map_err(|e| JsError::new(&e))
    }
}

/// Strict DER for a 64-byte raw signature (what a platform that returns DER
/// would hand over).
#[wasm_bindgen(js_name = rawToDer)]
pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>, JsError> {
    RawSignature::from_slice(raw)
        .map(|s| s.to_der())
        .map_err(|e| JsError::new(&e.to_string()))
}
