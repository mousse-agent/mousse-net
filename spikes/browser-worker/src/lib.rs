//! Phase 0 spike 2: a browser Worker issues a session certificate.
//!
//! The Worker (wasm32, [`wasm`]) makes the session key in Rust, asks
//! WebCrypto to sign the session record with a non-extractable P-256
//! identity key, and assembles the certificate with
//! [`mousse_net_core::session_cert::PendingCertificate`]. The native
//! verifier (`src/bin/verify_worker_cert.rs`) checks what the Worker made.
//!
//! [`splice`] rebuilds a certificate with a different identity-signature
//! field. It exists only to make the negative cases and must-fail controls
//! (an identity signature over another SPKI, a DER identity signature) as
//! properly self-signed certificates, so the native verifier refuses them for
//! the right reason.
#![deny(unsafe_code)]

pub mod splice;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// The check this spike reports.
pub const CHECK_ID: &str = "phase0.browser-worker-cert";

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse lowercase or uppercase hex.
pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let digit = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("bad hex digit {:?}", c as char)),
        }
    };
    text.as_bytes()
        .chunks(2)
        .map(|p| Ok(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}
