//! "Remove on all my hosts" (Phase 4, design Part D): the grant list a host
//! sends its owner-role callers, the signed removal record, and the checks a
//! host runs before it applies one.
//!
//! - **`mousse-grants`** (host → caller, wire minor 2): `{1: [{1: identity
//!   key, 2: grant id, 3: role, 4: name}]}`, sent at connection start and on
//!   every change, only to a caller whose grant has role `owner`.
//! - **The removal record** (domain `mousse-removal-v1`), signed by the admin
//!   device's identity key and built only by [`IdentityRecord::removal`]. It
//!   names the recipient host, the removed device and the grant id on the
//!   recipient, so a newer pairing of the same device (a new grant id) is
//!   never removed by an old removal.
//! - **`mousse-removal`** (caller → host): the signed envelope; the host
//!   answers `{1: removal id, 2: result}`.
//! - **[`decide`]**: the host's checks (Part D.4), in order, as a pure
//!   function of the grant table, the removal journal and the time.
//!
//! Nothing Plus serves is ever accepted here: a removal counts only if an
//! owner-role device on this endpoint signed it, however it arrived.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::cbor::{self, FieldError, Fields, Value};
use crate::grants::{Grant, GrantId, GrantTable, Role};
use crate::identity::{
    IdentityPublicKey, IdentityRecord, IdentitySigner, PublicKey, RawSignature, SignatureError,
    SignerError,
};
use crate::time::UnixTime;

/// Domain string of the removal record.
pub const REMOVAL_DOMAIN: &str = "mousse-removal-v1";

/// Label of the engine stream on which a host sends its grant list to an
/// owner-role caller.
pub const GRANTS_LABEL: &str = "mousse-grants";

/// Label of the engine stream on which an admin device sends a removal to a
/// host.
pub const REMOVAL_LABEL: &str = "mousse-removal";

/// The lowest agreed wire minor version on which `mousse-grants` and
/// `mousse-removal` may be opened.
pub const REMOVAL_MIN_MINOR: u64 = 2;

/// Length of a removal id.
pub const REMOVAL_ID_LEN: usize = 16;

/// A removal's random id. The host journals it, so a resend of the same
/// removal returns its first result and a reused id with other bytes is
/// refused.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemovalId(pub [u8; REMOVAL_ID_LEN]);

impl fmt::Debug for RemovalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RemovalId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// Why a removal record, envelope, answer or grant list was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalError {
    /// Not the expected canonical CBOR map.
    Format(FieldError),
    /// Key 1 is not [`REMOVAL_DOMAIN`].
    WrongDomain,
    /// A public key is not a valid uncompressed P-256 point.
    BadKey,
    /// The signature is not raw, or does not verify under the signer key
    /// the record names.
    BadSignature(SignatureError),
    /// The signer given to [`SignedRemoval::sign`] is not the record's
    /// signer.
    WrongSigner,
}

impl fmt::Display for RemovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemovalError::Format(e) => write!(f, "malformed removal: {e}"),
            RemovalError::WrongDomain => f.write_str("not a removal record"),
            RemovalError::BadKey => f.write_str("removal names an invalid key"),
            RemovalError::BadSignature(e) => write!(f, "removal signature: {e}"),
            RemovalError::WrongSigner => f.write_str("the signer is not the record's signer"),
        }
    }
}

impl std::error::Error for RemovalError {}

impl From<FieldError> for RemovalError {
    fn from(e: FieldError) -> Self {
        RemovalError::Format(e)
    }
}

impl From<cbor::CborError> for RemovalError {
    fn from(e: cbor::CborError) -> Self {
        RemovalError::Format(FieldError::Cbor(e))
    }
}

fn key(bytes: &[u8]) -> Result<PublicKey, RemovalError> {
    PublicKey::from_sec1(bytes).map_err(|_| RemovalError::BadKey)
}

/// A removal record (design D.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    /// The admin device that signs it (key 2).
    pub signer: IdentityPublicKey,
    /// The host it is for (key 3).
    pub recipient: IdentityPublicKey,
    /// The device to remove (key 4).
    pub removed: IdentityPublicKey,
    /// The removed device's grant id on the recipient (key 5).
    pub grant: GrantId,
    /// Random id (key 6).
    pub id: RemovalId,
    /// When the admin device made it (key 7). Kept on every resend.
    pub issued_at: UnixTime,
}

impl Removal {
    /// The canonical CBOR of the record.
    pub fn to_cbor(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(REMOVAL_DOMAIN.to_owned())),
            (2, Value::Bytes(self.signer.as_bytes().to_vec())),
            (3, Value::Bytes(self.recipient.as_bytes().to_vec())),
            (4, Value::Bytes(self.removed.as_bytes().to_vec())),
            (5, Value::Uint(self.grant.0)),
            (6, Value::Bytes(self.id.0.to_vec())),
            (7, Value::Uint(self.issued_at.0)),
        ]))
    }

    /// Parse a record: exactly keys 1 to 7, canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self, RemovalError> {
        let mut f = Fields::decode(bytes)?;
        if f.text(1)? != REMOVAL_DOMAIN {
            return Err(RemovalError::WrongDomain);
        }
        let signer = key(&f.bytes(2)?)?;
        let recipient = key(&f.bytes(3)?)?;
        let removed = key(&f.bytes(4)?)?;
        let grant = GrantId(f.uint(5)?);
        let id = RemovalId(f.fixed::<REMOVAL_ID_LEN>(6)?);
        let issued_at = UnixTime(f.uint(7)?);
        f.finish()?;
        Ok(Self {
            signer,
            recipient,
            removed,
            grant,
            id,
            issued_at,
        })
    }
}

impl IdentityRecord {
    /// The identity record for `removal`: the only way an identity key
    /// signs a removal.
    pub fn removal(removal: &Removal) -> Self {
        IdentityRecord::new(REMOVAL_DOMAIN, removal.to_cbor())
    }
}

/// A signed removal: the envelope `{1: record bytes, 2: raw signature}`.
/// Every resend carries the same bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRemoval {
    removal: Removal,
    record: Vec<u8>,
    signature: RawSignature,
}

impl fmt::Debug for SignedRemoval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedRemoval({:?})", self.removal.id)
    }
}

impl SignedRemoval {
    /// Sign `removal` with the admin device's identity key. The key must be
    /// the record's signer.
    pub fn sign(removal: Removal, signer: &dyn IdentitySigner) -> Result<Self, SignError> {
        if signer.public_key() != removal.signer {
            return Err(SignError::WrongSigner);
        }
        let record = IdentityRecord::removal(&removal);
        let signature = signer.sign(&record).map_err(SignError::Signer)?;
        Ok(Self {
            record: record.as_bytes().to_vec(),
            removal,
            signature,
        })
    }

    /// Parse an envelope and check its signature under the signer key the
    /// record names. Whether that signer may remove anything is the host's
    /// question ([`decide`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, RemovalError> {
        let mut f = Fields::decode(bytes)?;
        let record = f.bytes(1)?;
        let signature =
            RawSignature::from_slice(&f.bytes(2)?).map_err(RemovalError::BadSignature)?;
        f.finish()?;
        let removal = Removal::decode(&record)?;
        if cfg!(mousse_control = "removal-unsigned") {
            // Must-fail control (tests only): skip the signature check.
        } else {
            removal
                .signer
                .verify(&record, &signature)
                .map_err(RemovalError::BadSignature)?;
        }
        Ok(Self {
            removal,
            record,
            signature,
        })
    }

    /// The envelope bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(self.record.clone())),
            (2, Value::Bytes(self.signature.as_bytes().to_vec())),
        ]))
    }

    /// The record.
    pub fn removal(&self) -> &Removal {
        &self.removal
    }

    /// SHA-256 of the record bytes: what the host journals with the id.
    pub fn record_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.record).into()
    }
}

/// Why [`SignedRemoval::sign`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The key is not the record's signer.
    WrongSigner,
    /// The key store failed.
    Signer(SignerError),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::WrongSigner => f.write_str("the signer is not the record's signer"),
            SignError::Signer(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SignError {}

/// What a host did with a removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemovalResult {
    /// The grant is removed.
    Applied,
    /// The removed device holds a newer grant (another id): it stays.
    Stale,
    /// Not accepted: a signer without an owner grant, another recipient, a
    /// reused id with other bytes, too old, or a grant another owner
    /// authorized.
    Refused,
}

impl RemovalResult {
    /// The wire value.
    pub const fn code(self) -> u64 {
        match self {
            RemovalResult::Applied => 0,
            RemovalResult::Stale => 1,
            RemovalResult::Refused => 2,
        }
    }

    /// From the wire value.
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(RemovalResult::Applied),
            1 => Some(RemovalResult::Stale),
            2 => Some(RemovalResult::Refused),
            _ => None,
        }
    }

    /// Stable lower-case name.
    pub const fn name(self) -> &'static str {
        match self {
            RemovalResult::Applied => "applied",
            RemovalResult::Stale => "stale",
            RemovalResult::Refused => "refused",
        }
    }
}

/// The host's answer on `mousse-removal`: `{1: removal id, 2: result}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemovalAnswer {
    /// The removal it answers.
    pub id: RemovalId,
    /// Its result.
    pub result: RemovalResult,
}

impl RemovalAnswer {
    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(self.id.0.to_vec())),
            (2, Value::Uint(self.result.code())),
        ]))
    }

    /// Parse an answer.
    pub fn decode(bytes: &[u8]) -> Result<Self, RemovalError> {
        let mut f = Fields::decode(bytes)?;
        let id = RemovalId(f.fixed::<REMOVAL_ID_LEN>(1)?);
        let result = RemovalResult::from_code(f.uint(2)?)
            .ok_or(RemovalError::Format(FieldError::Invalid(2)))?;
        f.finish()?;
        Ok(Self { id, result })
    }
}

/// One entry of a host's grant list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEntry {
    /// The device.
    pub identity: IdentityPublicKey,
    /// Its grant id on the host.
    pub grant: GrantId,
    /// Its role there.
    pub role: Role,
    /// Its name there.
    pub name: String,
}

impl GrantEntry {
    /// The entry for a grant.
    pub fn of(grant: &Grant) -> Self {
        Self {
            identity: grant.identity,
            grant: grant.id,
            role: grant.role.clone(),
            name: grant.name.clone(),
        }
    }
}

/// The message on `mousse-grants`: `{1: [{1: identity key, 2: grant id, 3:
/// role, 4: name}]}`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantList {
    /// Every grant on the host, in grant id order.
    pub grants: Vec<GrantEntry>,
}

impl GrantList {
    /// The list for a host's grants.
    pub fn of<'a>(grants: impl IntoIterator<Item = &'a Grant>) -> Self {
        let mut grants: Vec<GrantEntry> = grants.into_iter().map(GrantEntry::of).collect();
        grants.sort_by_key(|g| g.grant);
        Self { grants }
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let entries = self
            .grants
            .iter()
            .map(|g| {
                Value::Map(vec![
                    (1, Value::Bytes(g.identity.as_bytes().to_vec())),
                    (2, Value::Uint(g.grant.0)),
                    (3, Value::Text(g.role.as_str().to_owned())),
                    (4, Value::Text(g.name.clone())),
                ])
            })
            .collect();
        cbor::encode(&Value::Map(vec![(1, Value::Array(entries))]))
    }

    /// Parse a list. Each entry must have exactly keys 1 to 4, a valid key,
    /// role and name; duplicate grant ids or identities are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, RemovalError> {
        let mut f = Fields::decode(bytes)?;
        let items = f.array(1)?;
        f.finish()?;
        let mut grants = Vec::with_capacity(items.len());
        for item in items {
            let mut e = Fields::from_value(item)?;
            let identity = key(&e.bytes(1)?)?;
            let grant = GrantId(e.uint(2)?);
            let role =
                Role::new(&e.text(3)?).map_err(|_| RemovalError::Format(FieldError::Invalid(3)))?;
            let name = e.text(4)?;
            crate::grants::validate_name(&name)
                .map_err(|_| RemovalError::Format(FieldError::Invalid(4)))?;
            e.finish()?;
            if grants
                .iter()
                .any(|g: &GrantEntry| g.grant == grant || g.identity == identity)
            {
                return Err(RemovalError::Format(FieldError::Invalid(1)));
            }
            grants.push(GrantEntry {
                identity,
                grant,
                role,
                name,
            });
        }
        Ok(Self { grants })
    }

    /// The grant this list names for `identity`, if any.
    pub fn grant_for(&self, identity: &IdentityPublicKey) -> Option<GrantId> {
        self.grants
            .iter()
            .find(|g| g.identity == *identity)
            .map(|g| g.grant)
    }
}

/// A removal id the host has journaled, with its record hash and result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journaled {
    /// SHA-256 of the record bytes.
    pub record_hash: [u8; 32],
    /// The result answered.
    pub result: RemovalResult,
}

/// What the host must do with a removal ([`decide`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answer `refused` and journal nothing (checks 1 and 2: the signer or
    /// the recipient is wrong, so the id is not this host's to keep).
    Refuse,
    /// A resend of a journaled removal: answer its journaled result and do
    /// nothing else.
    Replay(RemovalResult),
    /// A known id with other bytes: answer `refused`, journal nothing (the
    /// id is already journaled).
    RefuseReused,
    /// Journal the id, hash and result; for [`RemovalResult::Applied`] also
    /// remove `grant`. Then answer `result`.
    Journal {
        /// The result to journal and answer.
        result: RemovalResult,
        /// The grant to remove (only with `Applied`).
        grant: Option<GrantId>,
    },
}

impl Decision {
    /// The result the host answers.
    pub fn result(&self) -> RemovalResult {
        match self {
            Decision::Refuse | Decision::RefuseReused => RemovalResult::Refused,
            Decision::Replay(r) => *r,
            Decision::Journal { result, .. } => *result,
        }
    }
}

/// The host's checks (design D.4), in order. Run under the host's admission
/// lock; the caller then journals (durably) and applies the decision under
/// the same lock.
///
/// 1. The signer holds a live grant with role `owner` here.
/// 2. The recipient is `me`.
/// 3. The id is new (a known id with the same record hash replays its
///    journaled result; with other bytes it is refused), and `issued at` is
///    within `max_age_secs` (plus `skew_secs`) of `now`, and not more than
///    `skew_secs` ahead of it.
/// 4. The removed identity holds a grant whose id is the record's grant id;
///    otherwise `stale` (a newer pairing of that device stays).
/// 5. That grant's authorizing owner is the signer's grant's authorizing
///    owner; otherwise `refused` (another owner's grant is untouched).
#[allow(clippy::too_many_arguments)]
pub fn decide(
    removal: &SignedRemoval,
    me: &IdentityPublicKey,
    grants: &GrantTable,
    journaled: Option<Journaled>,
    now: UnixTime,
    max_age_secs: u64,
    skew_secs: u64,
) -> Decision {
    let r = removal.removal();
    // Check 1.
    let signer_grant = grants.live_grant(&r.signer, now).filter(|g| {
        // Must-fail controls (tests only): any live grant may sign; a grant
        // whose role was edited (a demoted owner) still may.
        cfg!(mousse_control = "accept-any-signer")
            || (cfg!(mousse_control = "demoted-signer-removes") && g.revision > 1)
            || g.role.as_str() == Role::OWNER
    });
    let Some(signer_grant) = signer_grant else {
        return Decision::Refuse;
    };
    let signer_owner = signer_grant.authorizing_owner;
    // Check 2.
    if r.recipient != *me {
        return Decision::Refuse;
    }
    // Check 3.
    if let Some(known) = journaled {
        if known.record_hash == removal.record_hash() {
            if cfg!(mousse_control = "resend-refused") {
                // Must-fail control (tests only): a resend is refused
                // instead of getting its journaled result.
                return Decision::RefuseReused;
            }
            return Decision::Replay(known.result);
        }
        return Decision::RefuseReused;
    }
    let too_old = now.secs() > r.issued_at.secs().saturating_add(max_age_secs + skew_secs);
    let too_new = r.issued_at.secs() > now.secs().saturating_add(skew_secs);
    if too_old || too_new {
        return Decision::Journal {
            result: RemovalResult::Refused,
            grant: None,
        };
    }
    // Check 4.
    let held = grants
        .live_grant(&r.removed, now)
        .filter(|g| cfg!(mousse_control = "ignore-grant-id") || g.id == r.grant);
    let Some(held) = held else {
        return Decision::Journal {
            result: RemovalResult::Stale,
            grant: None,
        };
    };
    // Check 5.
    if held.authorizing_owner != signer_owner && !cfg!(mousse_control = "ignore-owner") {
        return Decision::Journal {
            result: RemovalResult::Refused,
            grant: None,
        };
    }
    Decision::Journal {
        result: RemovalResult::Applied,
        grant: Some(held.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{NewGrant, OwnerRef};
    use crate::identity::SoftwareKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const NOW: UnixTime = UnixTime(1_800_000_000);
    const MAX_AGE: u64 = 2_592_000;
    const SKEW: u64 = 600;

    fn key(seed: u8) -> SoftwareKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    struct World {
        host: SoftwareKey,
        admin: SoftwareKey,
        phone: SoftwareKey,
        table: GrantTable,
        phone_grant: GrantId,
    }

    fn grant(table: &mut GrantTable, who: &SoftwareKey, role: Role, owner: u8) -> GrantId {
        table
            .add(
                NewGrant {
                    identity: who.public_key(),
                    name: "device".into(),
                    role,
                    authorizing_owner: OwnerRef::from_bytes([owner; 16]),
                    expires_at: None,
                    enrolled_by: None,
                },
                NOW,
            )
            .unwrap()
            .0
    }

    fn world() -> World {
        let (host, admin, phone) = (key(1), key(2), key(3));
        let mut table = GrantTable::new();
        grant(&mut table, &admin, Role::owner(), 9);
        let phone_grant = grant(&mut table, &phone, Role::owner(), 9);
        World {
            host,
            admin,
            phone,
            table,
            phone_grant,
        }
    }

    fn removal(w: &World, grant: GrantId, id: u8, issued_at: UnixTime) -> SignedRemoval {
        let r = Removal {
            signer: w.admin.public_key(),
            recipient: w.host.public_key(),
            removed: w.phone.public_key(),
            grant,
            id: RemovalId([id; 16]),
            issued_at,
        };
        let signed = SignedRemoval::sign(r, &w.admin).unwrap();
        SignedRemoval::decode(&signed.encode()).unwrap()
    }

    fn run(w: &World, r: &SignedRemoval, journaled: Option<Journaled>) -> Decision {
        decide(
            r,
            &w.host.public_key(),
            &w.table,
            journaled,
            NOW,
            MAX_AGE,
            SKEW,
        )
    }

    #[test]
    fn an_owner_removal_for_the_current_grant_is_applied() {
        let w = world();
        let r = removal(&w, w.phone_grant, 1, NOW);
        assert_eq!(
            run(&w, &r, None),
            Decision::Journal {
                result: RemovalResult::Applied,
                grant: Some(w.phone_grant)
            }
        );
    }

    #[test]
    fn a_signer_without_an_owner_grant_is_refused() {
        let mut w = world();
        let admin = w.admin.clone();
        grant(&mut w.table, &admin, Role::new("client").unwrap(), 9);
        let r = removal(&w, w.phone_grant, 1, NOW);
        assert_eq!(run(&w, &r, None), Decision::Refuse);
        // No grant at all.
        let stranger = key(7);
        let rec = Removal {
            signer: stranger.public_key(),
            ..r.removal().clone()
        };
        let signed = SignedRemoval::sign(rec, &stranger).unwrap();
        assert_eq!(run(&w, &signed, None), Decision::Refuse);
    }

    #[test]
    fn another_recipient_is_refused() {
        let w = world();
        let r = removal(&w, w.phone_grant, 1, NOW);
        let other = decide(&r, &key(8).public_key(), &w.table, None, NOW, MAX_AGE, SKEW);
        assert_eq!(other, Decision::Refuse);
    }

    #[test]
    fn a_stale_grant_id_leaves_the_newer_pairing() {
        let mut w = world();
        let old = w.phone_grant;
        let phone = w.phone.clone();
        let newer = grant(&mut w.table, &phone, Role::owner(), 9);
        assert_ne!(old, newer);
        let r = removal(&w, old, 1, NOW);
        assert_eq!(
            run(&w, &r, None),
            Decision::Journal {
                result: RemovalResult::Stale,
                grant: None
            }
        );
    }

    #[test]
    fn a_grant_another_owner_authorized_is_refused() {
        let mut w = world();
        let phone = w.phone.clone();
        let theirs = grant(&mut w.table, &phone, Role::owner(), 5);
        let r = removal(&w, theirs, 1, NOW);
        assert_eq!(
            run(&w, &r, None),
            Decision::Journal {
                result: RemovalResult::Refused,
                grant: None
            }
        );
    }

    #[test]
    fn a_resend_replays_and_a_reused_id_with_other_bytes_is_refused() {
        let w = world();
        let r = removal(&w, w.phone_grant, 1, NOW);
        let journaled = Journaled {
            record_hash: r.record_hash(),
            result: RemovalResult::Applied,
        };
        assert_eq!(
            run(&w, &r, Some(journaled)),
            Decision::Replay(RemovalResult::Applied)
        );
        let other = removal(&w, w.phone_grant, 1, NOW.plus(1));
        assert_eq!(run(&w, &other, Some(journaled)), Decision::RefuseReused);
    }

    #[test]
    fn too_old_or_from_the_future_is_refused() {
        let w = world();
        let old = removal(&w, w.phone_grant, 1, NOW.minus(MAX_AGE + SKEW + 1));
        assert_eq!(run(&w, &old, None).result(), RemovalResult::Refused);
        let edge = removal(&w, w.phone_grant, 2, NOW.minus(MAX_AGE + SKEW));
        assert_eq!(run(&w, &edge, None).result(), RemovalResult::Applied);
        let ahead = removal(&w, w.phone_grant, 3, NOW.plus(SKEW + 1));
        assert_eq!(run(&w, &ahead, None).result(), RemovalResult::Refused);
    }

    #[test]
    fn a_tampered_or_der_signature_is_rejected() {
        let w = world();
        let r = removal(&w, w.phone_grant, 1, NOW);
        let mut f = Fields::decode(&r.encode()).unwrap();
        let mut record = f.bytes(1).unwrap();
        let sig = f.bytes(2).unwrap();
        // Change the grant id inside the signed bytes.
        let pos = record.len() - 1;
        record[pos] ^= 1;
        let tampered = cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(record)),
            (2, Value::Bytes(sig.clone())),
        ]));
        assert!(SignedRemoval::decode(&tampered).is_err());
        let der = RawSignature::from_slice(&sig).unwrap().to_der();
        let der_env = cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(r.removal().to_cbor())),
            (2, Value::Bytes(der)),
        ]));
        assert_eq!(
            SignedRemoval::decode(&der_env),
            Err(RemovalError::BadSignature(SignatureError::NotRaw))
        );
    }

    #[test]
    fn only_the_records_signer_can_sign_it() {
        let w = world();
        let r = Removal {
            signer: w.admin.public_key(),
            recipient: w.host.public_key(),
            removed: w.phone.public_key(),
            grant: w.phone_grant,
            id: RemovalId([1; 16]),
            issued_at: NOW,
        };
        assert_eq!(
            SignedRemoval::sign(r, &w.phone),
            Err(SignError::WrongSigner)
        );
    }

    #[test]
    fn records_with_extra_or_missing_keys_are_rejected() {
        let w = world();
        let r = removal(&w, w.phone_grant, 1, NOW);
        let Value::Map(mut entries) = cbor::decode(&r.removal().to_cbor()).unwrap() else {
            panic!()
        };
        entries.push((8, Value::Uint(1)));
        assert_eq!(
            Removal::decode(&cbor::encode(&Value::Map(entries.clone()))),
            Err(RemovalError::Format(FieldError::Unknown(8)))
        );
        entries.truncate(6);
        assert_eq!(
            Removal::decode(&cbor::encode(&Value::Map(entries))),
            Err(RemovalError::Format(FieldError::Missing(7)))
        );
    }

    #[test]
    fn grant_lists_round_trip_and_reject_duplicates() {
        let w = world();
        let list = GrantList::of(w.table.grants());
        let back = GrantList::decode(&list.encode()).unwrap();
        assert_eq!(back, list);
        assert_eq!(back.grant_for(&w.phone.public_key()), Some(w.phone_grant));
        let mut dup = list.clone();
        dup.grants.push(dup.grants[0].clone());
        assert!(GrantList::decode(&dup.encode()).is_err());
    }

    #[test]
    fn answers_round_trip() {
        let a = RemovalAnswer {
            id: RemovalId([4; 16]),
            result: RemovalResult::Stale,
        };
        assert_eq!(RemovalAnswer::decode(&a.encode()), Ok(a));
        let bad = cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(vec![4; 16])),
            (2, Value::Uint(3)),
        ]));
        assert!(RemovalAnswer::decode(&bad).is_err());
    }
}
