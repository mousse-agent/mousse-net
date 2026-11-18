//! Values bound to the TLS session: the join proof and the code-exchange
//! binding transcript.
//!
//! Both use TLS 1.3 exporters (RFC 8446 §7.5) of the **peer** session (the
//! end-to-end TLS between the two devices, never an outer TLS to a relay),
//! with a zero-length context and 32 bytes of output.
//!
//! A TLS 1.3 exporter is derived before the client's certificate, so it does
//! not by itself name the joiner. Both constructions therefore also include
//! the two identity keys explicitly.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AttemptId, InvitationId, InvitationKind, TicketSecret};
use crate::cbor::{self, Value};
use crate::identity::IdentityPublicKey;

/// Exporter output length in bytes.
pub const EXPORTER_LEN: usize = 32;

/// Exporter label for the join proof.
pub const JOIN_EXPORTER_LABEL: &str = "EXPORTER-mousse-join-v1";

/// Exporter label for the code-exchange binding transcript.
pub const PAIR_EXPORTER_LABEL: &str = "EXPORTER-mousse-pair-v1";

/// Domain string of the join-proof input record.
pub const JOIN_PROOF_DOMAIN: &str = "mousse-join-v1";

/// HKDF `info` for the join-proof key.
pub const JOIN_PROOF_KEY_INFO: &str = "mousse-join-proof-v1";

/// Domain string of the binding transcript.
pub const PAIR_TRANSCRIPT_DOMAIN: &str = "mousse-pair-v1";

/// The two exporter values of one peer TLS session, computed by the I/O
/// layer with [`JOIN_EXPORTER_LABEL`] and [`PAIR_EXPORTER_LABEL`], zero-length
/// context, 32 bytes each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionExporters {
    /// Exporter for the join proof.
    pub join: [u8; EXPORTER_LEN],
    /// Exporter for the binding transcript.
    pub pair: [u8; EXPORTER_LEN],
}

impl std::fmt::Debug for SessionExporters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionExporters(..)")
    }
}

/// Join-proof key: HKDF-SHA256 with salt = invitation id, IKM = ticket
/// secret, info = [`JOIN_PROOF_KEY_INFO`], 32 bytes.
fn join_proof_key(secret: &TicketSecret, invitation: &InvitationId) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&invitation.0), secret.expose());
    let mut key = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's 8160-byte limit.
    hk.expand(JOIN_PROOF_KEY_INFO.as_bytes(), key.as_mut_slice())
        .expect("32-byte HKDF output");
    key
}

/// The record the join proof authenticates:
/// `{1: "mousse-join-v1", 2: invitation id, 3: host identity, 4: joiner identity, 5: join exporter}`.
pub fn join_proof_input(
    invitation: &InvitationId,
    host: &IdentityPublicKey,
    joiner: &IdentityPublicKey,
    join_exporter: &[u8; EXPORTER_LEN],
) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, Value::Text(JOIN_PROOF_DOMAIN.to_owned())),
        (2, Value::Bytes(invitation.0.to_vec())),
        (3, Value::Bytes(host.as_bytes().to_vec())),
        (4, Value::Bytes(joiner.as_bytes().to_vec())),
        (5, Value::Bytes(join_exporter.to_vec())),
    ]))
}

fn join_mac(
    secret: &TicketSecret,
    invitation: &InvitationId,
    host: &IdentityPublicKey,
    joiner: &IdentityPublicKey,
    join_exporter: &[u8; EXPORTER_LEN],
) -> Hmac<Sha256> {
    let key = join_proof_key(secret, invitation);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice())
        .expect("HMAC accepts any key length");
    mac.update(&join_proof_input(invitation, host, joiner, join_exporter));
    mac
}

/// The join proof: HMAC-SHA256(join-proof key, join-proof input).
pub fn join_proof_mac(
    secret: &TicketSecret,
    invitation: &InvitationId,
    host: &IdentityPublicKey,
    joiner: &IdentityPublicKey,
    join_exporter: &[u8; EXPORTER_LEN],
) -> [u8; 32] {
    join_mac(secret, invitation, host, joiner, join_exporter)
        .finalize()
        .into_bytes()
        .into()
}

/// Check a join proof in constant time.
pub fn verify_join_proof(
    secret: &TicketSecret,
    invitation: &InvitationId,
    host: &IdentityPublicKey,
    joiner: &IdentityPublicKey,
    join_exporter: &[u8; EXPORTER_LEN],
    tag: &[u8; 32],
) -> bool {
    join_mac(secret, invitation, host, joiner, join_exporter)
        .verify_slice(tag)
        .is_ok()
}

/// The code-exchange binding transcript. The code exchange uses these exact
/// bytes as its channel identifier / associated data (spec `cpace.md`), so
/// both key confirmations bind them.
#[derive(Clone, PartialEq, Eq)]
pub struct BindingTranscript(Vec<u8>);

impl BindingTranscript {
    /// The canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for BindingTranscript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingTranscript({} bytes)", self.0.len())
    }
}

/// Role numbers inside the binding transcript: the exchange roles.
const ROLE_INITIATOR: u64 = 1;
const ROLE_RESPONDER: u64 = 2;

/// Build the binding transcript, the code exchange's channel identifier (CI):
/// `{1: "mousse-pair-v1", 2: ticket hash, 3: kind (mode), 4: ticket version,
///   5: [[1, joiner identity], [2, host identity]], 6: pair exporter}`.
///
/// The joiner is the exchange initiator (role 1) and comes first; the host is
/// the responder (role 2). Each identity sits next to its role number, and
/// canonical CBOR gives every transcript exactly one encoding.
pub fn binding_transcript(
    ticket_hash: &[u8; 32],
    kind: InvitationKind,
    ticket_version: u64,
    host: &IdentityPublicKey,
    joiner: &IdentityPublicKey,
    pair_exporter: &[u8; EXPORTER_LEN],
) -> BindingTranscript {
    BindingTranscript(cbor::encode(&Value::Map(vec![
        (1, Value::Text(PAIR_TRANSCRIPT_DOMAIN.to_owned())),
        (2, Value::Bytes(ticket_hash.to_vec())),
        (3, Value::Uint(kind.as_u64())),
        (4, Value::Uint(ticket_version)),
        (
            5,
            Value::Array(vec![
                Value::Array(vec![
                    Value::Uint(ROLE_INITIATOR),
                    Value::Bytes(joiner.as_bytes().to_vec()),
                ]),
                Value::Array(vec![
                    Value::Uint(ROLE_RESPONDER),
                    Value::Bytes(host.as_bytes().to_vec()),
                ]),
            ]),
        ),
        (6, Value::Bytes(pair_exporter.to_vec())),
    ])))
}

/// Length of a code-exchange session id.
pub const SID_LEN: usize = 32;

/// Domain string of the session-id input.
pub const SID_DOMAIN: &str = "mousse-pair-sid-v1";

/// The code exchange's session id for one attempt:
/// `SHA-256(CBOR {1: "mousse-pair-sid-v1", 2: attempt id, 3: pair exporter})`.
///
/// The attempt id is fresh for every attempt and the exporter for every TLS
/// session, so a session id is never reused across attempts.
pub fn attempt_sid(attempt: &AttemptId, pair_exporter: &[u8; EXPORTER_LEN]) -> [u8; SID_LEN] {
    let input = cbor::encode(&Value::Map(vec![
        (1, Value::Text(SID_DOMAIN.to_owned())),
        (2, Value::Bytes(attempt.0.to_vec())),
        (3, Value::Bytes(pair_exporter.to_vec())),
    ]));
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::identity::SoftwareKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn key(seed: u8) -> IdentityPublicKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
    }

    #[test]
    fn join_proof_binds_secret_exporter_and_both_identities() {
        let secret = TicketSecret::from_bytes([1; 16]);
        let inv = InvitationId([2; 16]);
        let (host, joiner) = (key(1), key(2));
        let exp = [3u8; 32];
        let tag = join_proof_mac(&secret, &inv, &host, &joiner, &exp);
        assert!(verify_join_proof(&secret, &inv, &host, &joiner, &exp, &tag));
        assert!(!verify_join_proof(
            &TicketSecret::from_bytes([9; 16]),
            &inv,
            &host,
            &joiner,
            &exp,
            &tag
        ));
        assert!(!verify_join_proof(
            &secret,
            &InvitationId([9; 16]),
            &host,
            &joiner,
            &exp,
            &tag
        ));
        assert!(!verify_join_proof(
            &secret, &inv, &joiner, &host, &exp, &tag
        ));
        assert!(!verify_join_proof(
            &secret,
            &inv,
            &host,
            &key(3),
            &exp,
            &tag
        ));
        assert!(!verify_join_proof(
            &secret, &inv, &host, &joiner, &[4; 32], &tag
        ));
    }

    #[test]
    fn transcript_changes_with_every_bound_input() {
        let (h, j) = (key(1), key(2));
        let base = binding_transcript(&[0; 32], InvitationKind::SendLink, 1, &h, &j, &[5; 32]);
        let variants = [
            binding_transcript(&[1; 32], InvitationKind::SendLink, 1, &h, &j, &[5; 32]),
            binding_transcript(&[0; 32], InvitationKind::InPerson, 1, &h, &j, &[5; 32]),
            binding_transcript(&[0; 32], InvitationKind::SendLink, 2, &h, &j, &[5; 32]),
            binding_transcript(&[0; 32], InvitationKind::SendLink, 1, &j, &h, &[5; 32]),
            binding_transcript(&[0; 32], InvitationKind::SendLink, 1, &h, &j, &[6; 32]),
        ];
        for v in variants {
            assert_ne!(v, base);
        }
    }
}
