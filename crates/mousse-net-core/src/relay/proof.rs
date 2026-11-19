//! Relay identifiers and proofs (spec `relay.md` sections 3 and 5).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::identity::{PublicKey, RawSignature, SignatureError, SoftwareKey};
use crate::pairing::{InvitationId, TicketSecret};

use super::msg::Class;

/// TLS exporter label of the outer connection (32 bytes, empty context).
pub const OUTER_EXPORTER_LABEL: &[u8] = b"EXPORTER-mousse-relay-v1";

/// Domain prefix of the handle hash.
pub const HANDLE_DOMAIN: &str = "mousse-relay-handle-v1";
/// Register proof domain (also `ENROLL`).
pub const REGISTER_DOMAIN: &str = "mousse-relay-register-v1";
/// Successor proof domain.
pub const SUCCESSOR_DOMAIN: &str = "mousse-relay-successor-v1";
/// Call proof domain.
pub const CALL_DOMAIN: &str = "mousse-relay-call-v1";
/// Accept proof domain.
pub const ACCEPT_DOMAIN: &str = "mousse-relay-accept-v1";
/// HKDF info of the invitation tag.
pub const INVITE_TAG_INFO: &str = "mousse-relay-invite-v1";

/// The 32-byte relay id: `H(relay identity key)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayId(pub [u8; 32]);

impl RelayId {
    /// The id of a relay identity key.
    pub fn of(key: &PublicKey) -> Self {
        Self(key.fingerprint())
    }
}

impl core::fmt::Debug for RelayId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RelayId(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// The 32-byte handle a registration key gets on a relay.
pub fn handle(relay: &RelayId, registration_key: &PublicKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HANDLE_DOMAIN.as_bytes());
    h.update(relay.0);
    h.update(registration_key.as_bytes());
    h.finalize().into()
}

/// What a proof is bound to on one outer connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The relay's nonce from `RELAY_HELLO`.
    pub nonce: [u8; 32],
    /// The outer exporter.
    pub exporter: [u8; 32],
}

fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

fn t(text: &str) -> Value {
    Value::Text(text.to_owned())
}

/// The register (and enroll) proof record.
pub fn register_record(relay: &RelayId, handle: &[u8; 32], binding: &Binding) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, t(REGISTER_DOMAIN)),
        (2, b(&relay.0)),
        (3, b(handle)),
        (4, b(&binding.nonce)),
        (5, b(&binding.exporter)),
    ]))
}

/// The successor proof record; `new_handle` is the handle of the new key.
pub fn successor_record(relay: &RelayId, new_handle: &[u8; 32], binding: &Binding) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, t(SUCCESSOR_DOMAIN)),
        (2, b(&relay.0)),
        (3, b(new_handle)),
        (4, b(&binding.nonce)),
        (5, b(&binding.exporter)),
    ]))
}

/// The call proof record.
pub fn call_record(relay: &RelayId, handle: &[u8; 32], binding: &Binding, class: Class) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, t(CALL_DOMAIN)),
        (2, b(&relay.0)),
        (3, b(handle)),
        (4, b(&binding.nonce)),
        (5, b(&binding.exporter)),
        (6, Value::Uint(class as u64)),
    ]))
}

/// The accept proof record.
pub fn accept_record(
    relay: &RelayId,
    handle: &[u8; 32],
    circuit: &[u8; 16],
    binding: &Binding,
) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, t(ACCEPT_DOMAIN)),
        (2, b(&relay.0)),
        (3, b(handle)),
        (4, b(circuit)),
        (5, b(&binding.nonce)),
        (6, b(&binding.exporter)),
    ]))
}

/// Verify a proof over `record` by `key`.
pub fn verify(key: &PublicKey, record: &[u8], proof: &RawSignature) -> Result<(), SignatureError> {
    key.verify(record, proof)
}

/// A registration or caller key held in software (the relay keys of an
/// endpoint are software keys in its keystore, `phase34-design.md` B.4).
/// It signs only the relay proof records of this module.
#[derive(Clone, Debug)]
pub struct RelayClientKey(SoftwareKey);

impl RelayClientKey {
    /// Wrap a software key.
    pub fn new(key: SoftwareKey) -> Self {
        Self(key)
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// The fingerprint of the public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.0.public_key().fingerprint()
    }

    /// The handle of this key as a registration key on `relay`.
    pub fn handle(&self, relay: &RelayId) -> [u8; 32] {
        handle(relay, &self.0.public_key())
    }

    /// Register (or enroll) proof.
    pub fn register_proof(&self, relay: &RelayId, binding: &Binding) -> RawSignature {
        self.0
            .sign_raw(&register_record(relay, &self.handle(relay), binding))
    }

    /// Successor proof over the record for `new_key` (sign with both keys).
    pub fn successor_proof(
        &self,
        relay: &RelayId,
        new_key: &PublicKey,
        binding: &Binding,
    ) -> RawSignature {
        self.0
            .sign_raw(&successor_record(relay, &handle(relay, new_key), binding))
    }

    /// Call proof.
    pub fn call_proof(
        &self,
        relay: &RelayId,
        handle: &[u8; 32],
        binding: &Binding,
        class: Class,
    ) -> RawSignature {
        self.0.sign_raw(&call_record(relay, handle, binding, class))
    }

    /// Accept proof (by the registration key of `handle`).
    pub fn accept_proof(
        &self,
        relay: &RelayId,
        circuit: &[u8; 16],
        binding: &Binding,
    ) -> RawSignature {
        self.0
            .sign_raw(&accept_record(relay, &self.handle(relay), circuit, binding))
    }

    /// The secret scalar, for sealing into a keystore.
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.0.secret_bytes()
    }
}

/// The invitation tag a joiner presents in `JOIN`.
pub fn invitation_tag(invitation: &InvitationId, secret: &TicketSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&invitation.0), secret.expose());
    let mut out = [0u8; 32];
    hk.expand(INVITE_TAG_INFO.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// `H(tag)`: what an allow-set lists.
pub fn tag_hash(tag: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(tag).into()
}

/// `H(code)`: what the relay stores for an enrollment code.
pub fn code_hash(code: &[u8; 16]) -> [u8; 32] {
    Sha256::digest(code).into()
}
