//! The records a hosted relay exchanges with Plus (`docs/phase34-design.md`
//! §A.12 and §A.9): admission tokens and lease blocks it verifies, the boot
//! record and report parts it signs, and the answers it reads.
//!
//! Signed records are strict: a missing key, an unknown key, a wrong type or
//! a value out of range rejects the record. Answers are open: keys this
//! build does not know are ignored (§A.2).

use std::fmt;

use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::{PublicKey, RawSignature, SignatureError, SoftwareKey};

/// Domain string of an admission token.
pub const ADMIT_DOMAIN: &str = "mousse-relay-admit-v1";
/// Domain string of a lease block.
pub const LEASE_DOMAIN: &str = "mousse-lease-v1";
/// Domain string of a boot record.
pub const BOOT_DOMAIN: &str = "mousse-relay-boot-v1";
/// Domain string of a report part.
pub const REPORT_DOMAIN: &str = "mousse-relay-report-v1";
/// Prefix of the handle derivation (§A.7). Hashed as bytes, not CBOR.
pub const HANDLE_DOMAIN: &[u8] = b"mousse-relay-handle-v1";

/// Largest request body sent to Plus, except a report (§A.2, fixed).
pub const REQUEST_MAX: usize = 16_384;
/// Largest report body (§A.2, fixed).
pub const REPORT_MAX: usize = 65_536;
/// Most entries in one report part (§A.12, fixed).
pub const REPORT_ENTRIES_MAX: usize = 1_024;
/// Longest block window, `expires at − not before`, in seconds (§A.12, fixed).
pub const BLOCK_MAX_LIFETIME_SECS: u64 = 172_800;
/// After a lease's `expires at`, Plus time by which the relay has surely
/// stopped forwarding on it (§A.9 duty 12, fixed).
pub const FORWARD_MARGIN_SECS: u64 = 180;
/// The lowest rate cap a block may carry, bytes per second (§A.12, fixed).
pub const RATE_CAP_FLOOR: u64 = 65_536;
/// The largest WebSocket message, and so the smallest block (§A.9 duty 7).
pub const MESSAGE_MAX: u64 = 65_536;
/// Most lease ids in one `RELEASE` (§B.3).
pub const RELEASE_IDS_MAX: usize = 4;
/// Longest build id in a boot record, in bytes (§A.12).
pub const BUILD_ID_MAX: usize = 128;

/// A random 16-byte lease id.
pub type LeaseId = [u8; 16];
/// A relay handle: `SHA-256(HANDLE_DOMAIN ‖ relay id ‖ registration key)`.
pub type Handle = [u8; 32];
/// A relay id: SHA-256 of the relay's identity key.
pub type RelayId = [u8; 32];
/// A random 16-byte boot id, new on every relay start.
pub type BootId = [u8; 16];
/// A random 16-byte rate group, one per handle.
pub type RateGroup = [u8; 16];
/// The first 8 bytes of SHA-256 of an issuer key.
pub type IssuerKeyId = [u8; 8];

/// Relay id of a relay identity key (§A.7).
pub fn relay_id(identity: &PublicKey) -> RelayId {
    identity.fingerprint()
}

/// Handle of a registration key on a relay (§A.7); the relay protocol's
/// derivation.
pub fn handle(relay_id: &RelayId, registration_key: &PublicKey) -> Handle {
    crate::relay::proof::handle(&crate::relay::proof::RelayId(*relay_id), registration_key)
}

/// Issuer key id of an issuer key (§A.12).
pub fn issuer_key_id(key: &PublicKey) -> IssuerKeyId {
    let fp = key.fingerprint();
    let mut id = [0u8; 8];
    id.copy_from_slice(&fp[..8]);
    id
}

/// A lease class, the relay protocol's circuit class.
pub use crate::relay::msg::Class;

/// Both classes.
pub const CLASSES: [Class; 2] = [Class::Interactive, Class::Bulk];

/// The wire value of a class.
pub const fn class_to_u64(c: Class) -> u64 {
    match c {
        Class::Interactive => 0,
        Class::Bulk => 1,
    }
}

/// A class from its wire value.
pub const fn class_from_u64(v: u64) -> Option<Class> {
    match v {
        0 => Some(Class::Interactive),
        1 => Some(Class::Bulk),
        _ => None,
    }
}

/// Why a record or answer was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Not the expected canonical CBOR map, or a field broke its rule.
    Field(FieldError),
    /// Key 1 is not this record's domain string.
    Domain,
    /// The signature is not raw, or does not verify.
    Signature(SignatureError),
    /// No pinned issuer key has the record's key id.
    UnknownIssuer,
}

impl RecordError {
    /// Stable snake_case name.
    pub fn code(self) -> &'static str {
        match self {
            RecordError::Field(_) => "malformed",
            RecordError::Domain => "domain",
            RecordError::Signature(e) => e.code(),
            RecordError::UnknownIssuer => "unknown_issuer",
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Field(e) => write!(f, "{e}"),
            RecordError::Domain => f.write_str("record has the wrong domain string"),
            RecordError::Signature(e) => write!(f, "{e}"),
            RecordError::UnknownIssuer => f.write_str("record names no pinned issuer key"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<FieldError> for RecordError {
    fn from(e: FieldError) -> Self {
        RecordError::Field(e)
    }
}

impl From<SignatureError> for RecordError {
    fn from(e: SignatureError) -> Self {
        RecordError::Signature(e)
    }
}

/// `{1: record bytes, 2: raw signature}` (§A.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEnvelope {
    /// The canonical CBOR of the record. The signature is over these bytes.
    pub record: Vec<u8>,
    /// ECDSA P-256 / SHA-256, raw `r ‖ s`.
    pub signature: RawSignature,
}

impl SignedEnvelope {
    /// Sign `record` with `key` (deterministic, RFC 6979).
    pub fn sign(record: Vec<u8>, key: &SoftwareKey) -> Self {
        let signature = key.sign_raw(&record);
        Self { record, signature }
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(self.record.clone())),
            (2, Value::Bytes(self.signature.as_bytes().to_vec())),
        ]))
    }

    /// Decode strictly. A DER signature is `not_raw`.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode(bytes)?;
        let record = f.bytes(1)?;
        let sig = f.bytes(2)?;
        f.finish()?;
        let signature = RawSignature::from_slice(&sig)?;
        Ok(Self { record, signature })
    }

    /// Verify the signature with `key`.
    pub fn verify(&self, key: &PublicKey) -> Result<(), RecordError> {
        key.verify(&self.record, &self.signature)?;
        Ok(())
    }
}

/// The issuer public keys a hosted relay pins (§A.12). Two overlap during a
/// rotation; `mousse-relay reload` replaces the set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerKeys {
    keys: Vec<(IssuerKeyId, PublicKey)>,
}

impl IssuerKeys {
    /// A set of keys. Duplicates are dropped.
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        let mut out: Vec<(IssuerKeyId, PublicKey)> = Vec::new();
        for k in keys {
            if !out.iter().any(|(_, have)| *have == k) {
                out.push((issuer_key_id(&k), k));
            }
        }
        Self { keys: out }
    }

    /// The pinned key with this id.
    pub fn find(&self, id: &IssuerKeyId) -> Option<&PublicKey> {
        self.keys.iter().find(|(kid, _)| kid == id).map(|(_, k)| k)
    }

    /// How many keys are pinned.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is pinned.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn verify(&self, env: &SignedEnvelope, id: &IssuerKeyId) -> Result<(), RecordError> {
        let key = self.find(id).ok_or(RecordError::UnknownIssuer)?;
        env.verify(key)
    }
}

fn open_record(bytes: &[u8], domain: &str) -> Result<Fields, RecordError> {
    let mut f = Fields::decode(bytes)?;
    if f.text(1)? != domain {
        return Err(RecordError::Domain);
    }
    Ok(f)
}

fn class_field(f: &mut Fields, key: u64) -> Result<Class, RecordError> {
    let v = f.uint(key)?;
    class_from_u64(v).ok_or(RecordError::Field(FieldError::Invalid(key)))
}

/// An admission token (§A.12): lets one handle register on one relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionToken {
    /// Key 2.
    pub issuer_key_id: IssuerKeyId,
    /// Key 3.
    pub relay_id: RelayId,
    /// Key 4.
    pub handle: Handle,
    /// Key 5, Unix seconds.
    pub not_before: u64,
    /// Key 6, Unix seconds.
    pub not_after: u64,
}

impl AdmissionToken {
    /// The record's canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(ADMIT_DOMAIN.into())),
            (2, Value::Bytes(self.issuer_key_id.to_vec())),
            (3, Value::Bytes(self.relay_id.to_vec())),
            (4, Value::Bytes(self.handle.to_vec())),
            (5, Value::Uint(self.not_before)),
            (6, Value::Uint(self.not_after)),
        ]))
    }

    /// Decode the record bytes strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open_record(bytes, ADMIT_DOMAIN)?;
        let t = Self {
            issuer_key_id: f.fixed(2)?,
            relay_id: f.fixed(3)?,
            handle: f.fixed(4)?,
            not_before: f.uint(5)?,
            not_after: f.uint(6)?,
        };
        f.finish()?;
        Ok(t)
    }

    /// Decode an envelope and check its signature under `keys`. Nothing
    /// else (relay, handle, window) is checked here.
    pub fn open(envelope: &[u8], keys: &IssuerKeys) -> Result<Self, RecordError> {
        let env = SignedEnvelope::decode(envelope)?;
        let t = Self::decode(&env.record)?;
        keys.verify(&env, &t.issuer_key_id)?;
        Ok(t)
    }
}

/// A lease block (§A.12): lets one relay boot forward `bytes` of one class
/// for one handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseBlock {
    /// Key 2.
    pub issuer_key_id: IssuerKeyId,
    /// Key 3.
    pub lease_id: LeaseId,
    /// Key 4.
    pub relay_id: RelayId,
    /// Key 5.
    pub boot_id: BootId,
    /// Key 6.
    pub handle: Handle,
    /// Key 7.
    pub class: Class,
    /// Key 8, from 1 per handle, class and boot.
    pub sequence: u64,
    /// Key 9, bytes per second, both directions together.
    pub rate_cap: u64,
    /// Key 10, both directions together.
    pub bytes: u64,
    /// Key 11, Unix seconds.
    pub not_before: u64,
    /// Key 12, Unix seconds.
    pub expires_at: u64,
    /// Key 13.
    pub rate_group: RateGroup,
}

impl LeaseBlock {
    /// The record's canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(LEASE_DOMAIN.into())),
            (2, Value::Bytes(self.issuer_key_id.to_vec())),
            (3, Value::Bytes(self.lease_id.to_vec())),
            (4, Value::Bytes(self.relay_id.to_vec())),
            (5, Value::Bytes(self.boot_id.to_vec())),
            (6, Value::Bytes(self.handle.to_vec())),
            (7, Value::Uint(class_to_u64(self.class))),
            (8, Value::Uint(self.sequence)),
            (9, Value::Uint(self.rate_cap)),
            (10, Value::Uint(self.bytes)),
            (11, Value::Uint(self.not_before)),
            (12, Value::Uint(self.expires_at)),
            (13, Value::Bytes(self.rate_group.to_vec())),
        ]))
    }

    /// Decode the record bytes strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open_record(bytes, LEASE_DOMAIN)?;
        let b = Self {
            issuer_key_id: f.fixed(2)?,
            lease_id: f.fixed(3)?,
            relay_id: f.fixed(4)?,
            boot_id: f.fixed(5)?,
            handle: f.fixed(6)?,
            class: class_field(&mut f, 7)?,
            sequence: f.uint(8)?,
            rate_cap: f.uint(9)?,
            bytes: f.uint(10)?,
            not_before: f.uint(11)?,
            expires_at: f.uint(12)?,
            rate_group: f.fixed(13)?,
        };
        f.finish()?;
        if b.sequence == 0 {
            return Err(FieldError::Invalid(8).into());
        }
        Ok(b)
    }

    /// Decode an envelope and check its signature under `keys`. The relay's
    /// own checks are in [`super::Hosted::lease`].
    pub fn open(envelope: &[u8], keys: &IssuerKeys) -> Result<Self, RecordError> {
        let env = SignedEnvelope::decode(envelope)?;
        let b = Self::decode(&env.record)?;
        keys.verify(&env, &b.issuer_key_id)?;
        Ok(b)
    }

    /// Decode an envelope without checking the signature (to name the lease
    /// in a refusal).
    pub fn peek(envelope: &[u8]) -> Option<Self> {
        let env = SignedEnvelope::decode(envelope).ok()?;
        Self::decode(&env.record).ok()
    }
}

/// The boot record (§A.12), signed by the relay's report key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootRecord {
    /// Key 2.
    pub relay_id: RelayId,
    /// Key 3.
    pub boot_id: BootId,
    /// Key 4, Unix seconds, information only.
    pub started_at: u64,
    /// Key 5, 1 to 128 bytes.
    pub build_id: String,
    /// Key 6, at least 1 (§A.9 duty 1).
    pub generation: u64,
}

impl BootRecord {
    /// The record's canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(BOOT_DOMAIN.into())),
            (2, Value::Bytes(self.relay_id.to_vec())),
            (3, Value::Bytes(self.boot_id.to_vec())),
            (4, Value::Uint(self.started_at)),
            (5, Value::Text(self.build_id.clone())),
            (6, Value::Uint(self.generation)),
        ]))
    }

    /// Decode the record bytes strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open_record(bytes, BOOT_DOMAIN)?;
        let r = Self {
            relay_id: f.fixed(2)?,
            boot_id: f.fixed(3)?,
            started_at: f.uint(4)?,
            build_id: f.text(5)?,
            generation: f.uint(6)?,
        };
        f.finish()?;
        if r.build_id.is_empty() || r.build_id.len() > BUILD_ID_MAX {
            return Err(FieldError::Invalid(5).into());
        }
        if r.generation == 0 {
            return Err(FieldError::Invalid(6).into());
        }
        Ok(r)
    }
}

/// One lease's counters in a report part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportEntry {
    /// Key 1.
    pub lease_id: LeaseId,
    /// Key 2: bytes forwarded caller → target.
    pub to_target: u64,
    /// Key 3: bytes forwarded target → caller.
    pub to_caller: u64,
    /// Key 4: state 1, final. Its counters never change again.
    pub is_final: bool,
}

/// A relay boot's state in a report part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootState {
    /// 0.
    Running,
    /// 1: the relay is stopping; this is its last snapshot.
    Stopping,
}

/// One part of a snapshot (§A.12), signed by the relay's report key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportPart {
    /// Key 2.
    pub relay_id: RelayId,
    /// Key 3.
    pub boot_id: BootId,
    /// Key 4, from 1, one more per part in this boot.
    pub sequence: u64,
    /// Key 5, Unix seconds on the relay's Plus clock.
    pub sent_at: u64,
    /// Key 6.
    pub boot_state: BootState,
    /// Key 7: the sequence of the snapshot's first part.
    pub snapshot: u64,
    /// Key 8: parts in the snapshot.
    pub part_count: u64,
    /// Key 9, in lease-id order, at most [`REPORT_ENTRIES_MAX`].
    pub entries: Vec<ReportEntry>,
}

impl ReportPart {
    /// The record's canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .map(|e| {
                Value::Map(vec![
                    (1, Value::Bytes(e.lease_id.to_vec())),
                    (2, Value::Uint(e.to_target)),
                    (3, Value::Uint(e.to_caller)),
                    (4, Value::Uint(u64::from(e.is_final))),
                ])
            })
            .collect();
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(REPORT_DOMAIN.into())),
            (2, Value::Bytes(self.relay_id.to_vec())),
            (3, Value::Bytes(self.boot_id.to_vec())),
            (4, Value::Uint(self.sequence)),
            (5, Value::Uint(self.sent_at)),
            (
                6,
                Value::Uint(match self.boot_state {
                    BootState::Running => 0,
                    BootState::Stopping => 1,
                }),
            ),
            (7, Value::Uint(self.snapshot)),
            (8, Value::Uint(self.part_count)),
            (9, Value::Array(entries)),
        ]))
    }

    /// Decode the record bytes strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = open_record(bytes, REPORT_DOMAIN)?;
        let relay_id = f.fixed(2)?;
        let boot_id = f.fixed(3)?;
        let sequence = f.uint(4)?;
        let sent_at = f.uint(5)?;
        let boot_state = match f.uint(6)? {
            0 => BootState::Running,
            1 => BootState::Stopping,
            _ => return Err(FieldError::Invalid(6).into()),
        };
        let snapshot = f.uint(7)?;
        let part_count = f.uint(8)?;
        let raw = f.array(9)?;
        f.finish()?;
        if sequence == 0 {
            return Err(FieldError::Invalid(4).into());
        }
        if snapshot == 0 || snapshot > sequence {
            return Err(FieldError::Invalid(7).into());
        }
        if part_count == 0 || sequence - snapshot >= part_count {
            return Err(FieldError::Invalid(8).into());
        }
        if raw.len() > REPORT_ENTRIES_MAX {
            return Err(FieldError::Invalid(9).into());
        }
        let mut entries = Vec::with_capacity(raw.len());
        for item in raw {
            let mut e = Fields::from_value(item).map_err(|_| FieldError::Invalid(9))?;
            let lease_id = e.fixed(1).map_err(|_| FieldError::Invalid(9))?;
            let to_target = e.uint(2).map_err(|_| FieldError::Invalid(9))?;
            let to_caller = e.uint(3).map_err(|_| FieldError::Invalid(9))?;
            let is_final = match e.uint(4).map_err(|_| FieldError::Invalid(9))? {
                0 => false,
                1 => true,
                _ => return Err(FieldError::Invalid(9).into()),
            };
            e.finish().map_err(|_| FieldError::Invalid(9))?;
            if let Some(prev) = entries.last().map(|p: &ReportEntry| p.lease_id) {
                if prev >= lease_id {
                    return Err(FieldError::Invalid(9).into());
                }
            }
            entries.push(ReportEntry {
                lease_id,
                to_target,
                to_caller,
                is_final,
            });
        }
        Ok(Self {
            relay_id,
            boot_id,
            sequence,
            sent_at,
            boot_state,
            snapshot,
            part_count,
            entries,
        })
    }
}

/// Plus's answer to `POST /v1/relay/boot` (§A.9). Open: unknown keys are
/// ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootAnswer {
    /// Key 1: Plus time, Unix milliseconds, when the answer was built.
    pub plus_time_ms: u64,
}

impl BootAnswer {
    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![(1, Value::Uint(self.plus_time_ms))]))
    }

    /// Decode, ignoring unknown keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode(bytes)?;
        Ok(Self {
            plus_time_ms: f.uint(1)?,
        })
    }
}

/// Plus's answer to `POST /v1/relay/report` (§A.9). Open: unknown keys are
/// ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportAnswer {
    /// Key 1: the highest report sequence Plus has stored for this boot.
    pub highest_sequence: u64,
    /// Key 2: leases of this part that are settled.
    pub settled: Vec<LeaseId>,
    /// Key 3: leases to stop forwarding (reserved; empty in v1).
    pub stop: Vec<LeaseId>,
    /// Key 4: Plus time, Unix milliseconds, when the answer was built.
    pub plus_time_ms: u64,
}

fn id_list(f: &mut Fields, key: u64) -> Result<Vec<LeaseId>, RecordError> {
    f.array(key)?
        .into_iter()
        .map(|v| match v {
            Value::Bytes(b) => {
                <LeaseId>::try_from(b.as_slice()).map_err(|_| FieldError::Invalid(key).into())
            }
            _ => Err(FieldError::WrongType(key).into()),
        })
        .collect()
}

impl ReportAnswer {
    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let ids =
            |v: &[LeaseId]| Value::Array(v.iter().map(|i| Value::Bytes(i.to_vec())).collect());
        cbor::encode(&Value::Map(vec![
            (1, Value::Uint(self.highest_sequence)),
            (2, ids(&self.settled)),
            (3, ids(&self.stop)),
            (4, Value::Uint(self.plus_time_ms)),
        ]))
    }

    /// Decode, ignoring unknown keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode(bytes)?;
        Ok(Self {
            highest_sequence: f.uint(1)?,
            settled: id_list(&mut f, 2)?,
            stop: id_list(&mut f, 3)?,
            plus_time_ms: f.uint(4)?,
        })
    }
}

/// A Plus error body `{1: code, 2: retry after (optional)}` (§A.2). Open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorBody {
    /// Key 1, for example `stale_generation`.
    pub code: String,
    /// Key 2, seconds.
    pub retry_after_secs: Option<u64>,
}

impl ErrorBody {
    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = vec![(1, Value::Text(self.code.clone()))];
        if let Some(s) = self.retry_after_secs {
            m.push((2, Value::Uint(s)));
        }
        cbor::encode(&Value::Map(m))
    }

    /// Decode, ignoring unknown keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode(bytes)?;
        let code = f.text(1)?;
        let retry_after_secs = match f.optional(2) {
            None => None,
            Some(Value::Uint(s)) => Some(s),
            Some(_) => return Err(FieldError::WrongType(2).into()),
        };
        Ok(Self {
            code,
            retry_after_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha256};

    fn key(seed: u8) -> SoftwareKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn block(issuer: &SoftwareKey) -> LeaseBlock {
        LeaseBlock {
            issuer_key_id: issuer_key_id(&issuer.public_key()),
            lease_id: [1; 16],
            relay_id: [2; 32],
            boot_id: [3; 16],
            handle: [4; 32],
            class: Class::Bulk,
            sequence: 1,
            rate_cap: 65_536,
            bytes: 1 << 20,
            not_before: 1_000,
            expires_at: 2_000,
            rate_group: [5; 16],
        }
    }

    #[test]
    fn a_block_round_trips_and_verifies_under_its_issuer() {
        let issuer = key(1);
        let b = block(&issuer);
        let env = SignedEnvelope::sign(b.encode(), &issuer).encode();
        let keys = IssuerKeys::new([issuer.public_key()]);
        assert_eq!(LeaseBlock::open(&env, &keys), Ok(b.clone()));
        // Another issuer's key with the same id is never consulted: the id
        // comes from the key itself.
        let other = IssuerKeys::new([key(2).public_key()]);
        assert_eq!(
            LeaseBlock::open(&env, &other),
            Err(RecordError::UnknownIssuer)
        );
        // A forged signature.
        let forged = SignedEnvelope::sign(b.encode(), &key(2)).encode();
        assert_eq!(
            LeaseBlock::open(&forged, &keys),
            Err(RecordError::Signature(SignatureError::Invalid))
        );
    }

    #[test]
    fn a_der_signature_is_refused_as_not_raw() {
        let issuer = key(1);
        let b = block(&issuer);
        let env = SignedEnvelope::sign(b.encode(), &issuer);
        let der = cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(env.record.clone())),
            (2, Value::Bytes(env.signature.to_der())),
        ]));
        let keys = IssuerKeys::new([issuer.public_key()]);
        assert_eq!(
            LeaseBlock::open(&der, &keys).map_err(|e| e.code()),
            Err("not_raw")
        );
    }

    #[test]
    fn an_unknown_or_missing_key_rejects_a_record() {
        let issuer = key(1);
        let b = block(&issuer);
        let Value::Map(mut m) = cbor::decode(&b.encode()).unwrap() else {
            unreachable!()
        };
        m.push((14, Value::Uint(0)));
        let extra = cbor::encode(&Value::Map(m.clone()));
        assert_eq!(
            LeaseBlock::decode(&extra),
            Err(RecordError::Field(FieldError::Unknown(14)))
        );
        m.retain(|(k, _)| *k != 13 && *k != 14);
        let missing = cbor::encode(&Value::Map(m));
        assert_eq!(
            LeaseBlock::decode(&missing),
            Err(RecordError::Field(FieldError::Missing(13)))
        );
        // A token is not a block.
        let t = AdmissionToken {
            issuer_key_id: [0; 8],
            relay_id: [0; 32],
            handle: [0; 32],
            not_before: 0,
            not_after: 1,
        };
        assert_eq!(LeaseBlock::decode(&t.encode()), Err(RecordError::Domain));
    }

    #[test]
    fn handle_and_ids_follow_the_contract() {
        let reg = key(7).public_key();
        let rid = [9u8; 32];
        let mut h = Sha256::new();
        h.update(b"mousse-relay-handle-v1");
        h.update(rid);
        h.update(reg.as_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(handle(&rid, &reg), want);
        assert_eq!(relay_id(&reg), reg.fingerprint());
        assert_eq!(issuer_key_id(&reg), reg.fingerprint()[..8]);
    }

    #[test]
    fn a_full_report_part_at_the_largest_counters_fits_report_max() {
        let issuer = key(3);
        let entries = (0..REPORT_ENTRIES_MAX as u32)
            .map(|i| {
                let mut id = [0xff; 16];
                id[..4].copy_from_slice(&i.to_be_bytes());
                ReportEntry {
                    lease_id: id,
                    to_target: u64::MAX,
                    to_caller: u64::MAX,
                    is_final: true,
                }
            })
            .collect();
        let part = ReportPart {
            relay_id: [0xff; 32],
            boot_id: [0xff; 16],
            sequence: u64::MAX,
            sent_at: u64::MAX,
            boot_state: BootState::Stopping,
            snapshot: u64::MAX,
            part_count: u64::MAX,
            entries,
        };
        let env = SignedEnvelope::sign(part.encode(), &issuer).encode();
        assert!(env.len() <= REPORT_MAX, "{} bytes", env.len());
        // About 42 000 bytes, as §A.12 says.
        assert!((40_000..44_000).contains(&env.len()), "{} bytes", env.len());
        assert_eq!(ReportPart::decode(&part.encode()), Ok(part));
    }

    #[test]
    fn report_parts_reject_bad_numbering_and_unsorted_entries() {
        let mut part = ReportPart {
            relay_id: [0; 32],
            boot_id: [0; 16],
            sequence: 5,
            sent_at: 0,
            boot_state: BootState::Running,
            snapshot: 4,
            part_count: 2,
            entries: vec![],
        };
        assert!(ReportPart::decode(&part.encode()).is_ok());
        part.part_count = 1;
        assert!(ReportPart::decode(&part.encode()).is_err());
        part.part_count = 2;
        let e = |b| ReportEntry {
            lease_id: [b; 16],
            to_target: 0,
            to_caller: 0,
            is_final: false,
        };
        part.entries = vec![e(2), e(1)];
        assert!(ReportPart::decode(&part.encode()).is_err());
    }

    #[test]
    fn answers_ignore_keys_they_do_not_know() {
        let bytes = cbor::encode(&Value::Map(vec![
            (1, Value::Uint(7)),
            (2, Value::Array(vec![Value::Bytes(vec![1; 16])])),
            (3, Value::Array(vec![])),
            (4, Value::Uint(1_700_000_000_000)),
            (9, Value::Text("later".into())),
        ]));
        let a = ReportAnswer::decode(&bytes).unwrap();
        assert_eq!(a.highest_sequence, 7);
        assert_eq!(a.settled, vec![[1; 16]]);
        assert_eq!(a.plus_time_ms, 1_700_000_000_000);
        let boot = cbor::encode(&Value::Map(vec![(1, Value::Uint(5)), (2, Value::Uint(0))]));
        assert_eq!(
            BootAnswer::decode(&boot),
            Ok(BootAnswer { plus_time_ms: 5 })
        );
        let err = ErrorBody {
            code: "stale_generation".into(),
            retry_after_secs: Some(3),
        };
        assert_eq!(ErrorBody::decode(&err.encode()), Ok(err));
    }

    #[test]
    fn a_boot_record_needs_a_build_id_and_a_generation() {
        let mut r = BootRecord {
            relay_id: [0; 32],
            boot_id: [1; 16],
            started_at: 0,
            build_id: "mousse-relay 0.1.0".into(),
            generation: 1,
        };
        assert_eq!(BootRecord::decode(&r.encode()), Ok(r.clone()));
        r.generation = 0;
        assert!(BootRecord::decode(&r.encode()).is_err());
        r.generation = 1;
        r.build_id = "x".repeat(129);
        assert!(BootRecord::decode(&r.encode()).is_err());
        r.build_id = String::new();
        assert!(BootRecord::decode(&r.encode()).is_err());
    }
}
