//! Per-pairing material for Plus's directory and mailbox (design B.12 and
//! D.3), derived from the pair secret a host sends its caller on
//! `mousse-keys`.
//!
//! | Info | Use |
//! |---|---|
//! | `mousse-dir-slot-v1` | directory slot id (32) |
//! | `mousse-dir-key-v1` | directory slot key (32), XChaCha20-Poly1305 |
//! | `mousse-mail-deposit-v1` | deposit token (32) |
//! | `mousse-mail-tag-v1` | deposit tag (first 16 bytes) |
//! | `mousse-mail-key-v1` | mail key (32), XChaCha20-Poly1305 |
//!
//! All with HKDF-SHA256 and an empty salt. A sealed value is the canonical
//! CBOR `{1: nonce (24), 2: ciphertext}`, with no associated data; the keys
//! are separate per use. Plus stores and serves these opaque bytes and
//! never holds a key. Nothing read from Plus counts unless the pinned host
//! signed it (`manifest::Manifest::open`, in the reader) or, for a removal,
//! an owner-role device signed it.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, Fields, Value};

/// Length of an inbox id.
pub const INBOX_ID_LEN: usize = 32;

/// Length of the nonce of a sealed value.
pub const NONCE_LEN: usize = 24;

/// A pairing's secret (32 bytes). Zeroized on drop.
#[derive(Clone)]
pub struct PairSecret(Zeroizing<[u8; 32]>);

impl fmt::Debug for PairSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairSecret(…)")
    }
}

impl PairSecret {
    /// Wrap 32 secret bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, self.0.as_slice());
        let mut out = Zeroizing::new([0u8; 32]);
        // 32 bytes is far below HKDF-SHA256's 8160-byte limit.
        hk.expand(info, out.as_mut_slice())
            .expect("32 bytes is a valid HKDF output length");
        out
    }

    /// The pairing's directory slot id.
    pub fn slot_id(&self) -> [u8; 32] {
        *self.derive(b"mousse-dir-slot-v1")
    }

    /// The key that seals the slot.
    pub fn slot_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive(b"mousse-dir-key-v1")
    }

    /// The deposit token the caller presents to the host's inbox.
    pub fn deposit_token(&self) -> Zeroizing<[u8; 32]> {
        self.derive(b"mousse-mail-deposit-v1")
    }

    /// SHA-256 of the deposit token: what the host registers.
    pub fn deposit_token_hash(&self) -> [u8; 32] {
        Sha256::digest(self.deposit_token().as_slice()).into()
    }

    /// The deposit tag (16 bytes).
    pub fn tag(&self) -> [u8; 16] {
        let full = self.derive(b"mousse-mail-tag-v1");
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full[..16]);
        tag
    }

    /// The key that seals mail for this pairing.
    pub fn mail_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive(b"mousse-mail-key-v1")
    }
}

/// Why a sealed value or a slot was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// Not `{1: nonce (24), 2: ciphertext}`.
    Format,
    /// The ciphertext does not open under this key.
    Open,
    /// The slot's plaintext is shorter than an inbox id.
    Short,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SealError::Format => "not a sealed value",
            SealError::Open => "does not open under this pairing's key",
            SealError::Short => "slot too short",
        })
    }
}

impl std::error::Error for SealError {}

/// Seal `plaintext` under `key` with `nonce` (24 fresh random bytes).
pub fn seal(key: &[u8; 32], nonce: [u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext)
        .expect("XChaCha20-Poly1305 seals any message this small");
    cbor::encode(&Value::Map(vec![
        (1, Value::Bytes(nonce.to_vec())),
        (2, Value::Bytes(ciphertext)),
    ]))
}

/// Open a sealed value.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let mut f = Fields::decode(sealed).map_err(|_| SealError::Format)?;
    let nonce = f.fixed::<NONCE_LEN>(1).map_err(|_| SealError::Format)?;
    let ciphertext = f.bytes(2).map_err(|_| SealError::Format)?;
    f.finish().map_err(|_| SealError::Format)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&XNonce::from(nonce), ciphertext.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| SealError::Open)
}

/// The slot's plaintext: the manifest envelope, then the inbox id.
pub fn slot_plaintext(manifest: &[u8], inbox: &[u8; INBOX_ID_LEN]) -> Vec<u8> {
    let mut out = manifest.to_vec();
    out.extend_from_slice(inbox);
    out
}

/// Split a slot's plaintext into the manifest envelope and the inbox id.
pub fn split_slot(plaintext: &[u8]) -> Result<(&[u8], [u8; INBOX_ID_LEN]), SealError> {
    if plaintext.len() < INBOX_ID_LEN {
        return Err(SealError::Short);
    }
    let (manifest, inbox) = plaintext.split_at(plaintext.len() - INBOX_ID_LEN);
    let mut id = [0u8; INBOX_ID_LEN];
    id.copy_from_slice(inbox);
    Ok((manifest, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> PairSecret {
        PairSecret::from_bytes([b; 32])
    }

    #[test]
    fn each_use_gets_its_own_value_and_pairings_differ() {
        let s = secret(1);
        let values = [
            s.slot_id(),
            *s.slot_key(),
            *s.deposit_token(),
            *s.mail_key(),
        ];
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(s.slot_id(), secret(2).slot_id());
        assert_ne!(s.tag(), secret(2).tag());
        assert_eq!(s.tag(), s.tag());
    }

    #[test]
    fn derivations_follow_hkdf_sha256_with_an_empty_salt() {
        // RFC 5869 extract with an empty salt is HMAC with 32 zero bytes;
        // checked here against the HKDF crate's own extract-then-expand of
        // the same input, through the public value.
        let s = secret(9);
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &[9u8; 32]);
        let mut expected = [0u8; 32];
        hk.expand(b"mousse-dir-slot-v1", &mut expected).unwrap();
        assert_eq!(s.slot_id(), expected);
    }

    #[test]
    fn a_sealed_value_opens_only_under_its_key() {
        let key = *secret(1).mail_key();
        let sealed = seal(&key, [7; 24], b"removal envelope");
        assert_eq!(open(&key, &sealed).unwrap().as_slice(), b"removal envelope");
        let other = *secret(2).mail_key();
        assert_eq!(open(&other, &sealed), Err(SealError::Open));
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(open(&key, &tampered), Err(SealError::Open));
        assert_eq!(open(&key, b"\xa0"), Err(SealError::Format));
    }

    #[test]
    fn a_slot_carries_the_manifest_then_the_inbox_id() {
        let plain = slot_plaintext(b"manifest", &[5; 32]);
        let (m, inbox) = split_slot(&plain).unwrap();
        assert_eq!((m, inbox), (&b"manifest"[..], [5; 32]));
        assert_eq!(split_slot(&[1; 31]), Err(SealError::Short));
    }
}
