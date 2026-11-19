//! The messages the helper exchanges with Plus (docs/phase34-design.md Part
//! A): canonical CBOR request bodies, open answers, the endpoint's signed
//! records and the Plus-signed records it carries to a relay.
//!
//! Requests are strict: each body is built here with exactly its keys.
//! Answers are open: keys this build does not know are ignored.

use mousse_net_core::cbor::{self, Value};
use mousse_net_core::identity::{PublicKey, RawSignature, SoftwareKey};

/// `mousse-plus-link-v1`, signed by the Plus key on every link poll.
pub const LINK_DOMAIN: &str = "mousse-plus-link-v1";
/// `mousse-plus-token-v1`, signed by the Plus key for an access token.
pub const TOKEN_DOMAIN: &str = "mousse-plus-token-v1";
/// `mousse-plus-handle-v1`, signed by a relay registration key.
#[allow(dead_code)] // the hosted relay client's
pub const HANDLE_DOMAIN: &str = "mousse-plus-handle-v1";
/// The admission token's domain (Plus-signed).
#[allow(dead_code)] // the hosted relay client's
pub const ADMIT_DOMAIN: &str = "mousse-relay-admit-v1";
/// The lease block's domain (Plus-signed).
pub const LEASE_DOMAIN: &str = "mousse-lease-v1";
/// The API minor version this build speaks.
pub const API_VERSION: &str = "1.0";
/// Largest request body (fixed, A.2).
pub const REQUEST_MAX: usize = 16_384;
/// Largest directory ciphertext (fixed, A.5).
pub const DIR_ENTRY_MAX: usize = 4096;
/// Largest mailbox envelope (fixed, A.6).
pub const MAIL_ENVELOPE_MAX: usize = 8192;
/// Most deposit tokens in an inbox (fixed, A.6).
pub const DEPOSIT_TOKENS_MAX: usize = 256;
/// Longest block lifetime (fixed, A.12).
pub const BLOCK_MAX_LIFETIME: u64 = 172_800;
/// The smallest block and rate cap (fixed, A.12).
pub const BLOCK_FLOOR: u64 = 65_536;

/// Why an answer could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BadAnswer(pub String);

impl std::fmt::Display for BadAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unexpected answer from Plus: {}", self.0)
    }
}

/// An open answer map: typed reads by key, unknown keys ignored.
pub struct Answer {
    entries: Vec<(u64, Value)>,
}

impl Answer {
    /// Decode a body that must be one canonical CBOR map.
    pub fn decode(bytes: &[u8]) -> Result<Self, BadAnswer> {
        match cbor::decode(bytes).map_err(|e| BadAnswer(e.to_string()))? {
            Value::Map(entries) => Ok(Self { entries }),
            _ => Err(BadAnswer("not a map".into())),
        }
    }

    fn from_value(value: Value) -> Result<Self, BadAnswer> {
        match value {
            Value::Map(entries) => Ok(Self { entries }),
            _ => Err(BadAnswer("not a map".into())),
        }
    }

    fn get(&self, key: u64) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// An optional unsigned integer.
    pub fn opt_uint(&self, key: u64) -> Option<u64> {
        match self.get(key) {
            Some(Value::Uint(n)) => Some(*n),
            _ => None,
        }
    }

    /// A required unsigned integer.
    pub fn uint(&self, key: u64) -> Result<u64, BadAnswer> {
        self.opt_uint(key)
            .ok_or_else(|| BadAnswer(format!("key {key} is not a number")))
    }

    /// A required byte string.
    pub fn bytes(&self, key: u64) -> Result<Vec<u8>, BadAnswer> {
        match self.get(key) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(BadAnswer(format!("key {key} is not bytes"))),
        }
    }

    /// A required byte string of exactly `N` bytes.
    pub fn fixed<const N: usize>(&self, key: u64) -> Result<[u8; N], BadAnswer> {
        self.bytes(key)?
            .try_into()
            .map_err(|_| BadAnswer(format!("key {key} is not {N} bytes")))
    }

    /// A required text string.
    pub fn text(&self, key: u64) -> Result<String, BadAnswer> {
        match self.get(key) {
            Some(Value::Text(t)) => Ok(t.clone()),
            _ => Err(BadAnswer(format!("key {key} is not text"))),
        }
    }

    /// A required array.
    pub fn array(&self, key: u64) -> Result<Vec<Value>, BadAnswer> {
        match self.get(key) {
            Some(Value::Array(a)) => Ok(a.clone()),
            _ => Err(BadAnswer(format!("key {key} is not an array"))),
        }
    }

    /// A required nested map.
    pub fn map(&self, key: u64) -> Result<Answer, BadAnswer> {
        match self.get(key) {
            Some(v @ Value::Map(_)) => Answer::from_value(v.clone()),
            _ => Err(BadAnswer(format!("key {key} is not a map"))),
        }
    }

    /// The items of an array of maps.
    pub fn maps(&self, key: u64) -> Result<Vec<Answer>, BadAnswer> {
        self.array(key)?
            .into_iter()
            .map(Answer::from_value)
            .collect()
    }
}

/// A Plus error answer: `{1: code, 2: retry after?}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlusError {
    /// The HTTP status.
    pub status: u16,
    /// The code (A.2), or empty when the body had none.
    pub code: String,
    /// Seconds to wait before retrying, when Plus said.
    pub retry_after: Option<u64>,
}

impl PlusError {
    /// Read an error body; a body without a code keeps only the status.
    pub fn from_body(status: u16, body: &[u8]) -> Self {
        let (code, retry_after) = match Answer::decode(body) {
            Ok(a) => (a.text(1).unwrap_or_default(), a.opt_uint(2)),
            Err(_) => (String::new(), None),
        };
        Self {
            status,
            code,
            retry_after,
        }
    }

    /// Whether the same request may succeed later without any change: a
    /// timeout-like or server-side condition.
    pub fn is_transient(&self) -> bool {
        matches!(
            self.code.as_str(),
            "rate_limited" | "issuer_not_ready" | "fleet_paused" | "internal" | "unknown_boot"
        ) || (self.code.is_empty() && (self.status >= 500 || self.status == 429))
    }
}

impl std::fmt::Display for PlusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code.is_empty() {
            write!(f, "Plus answered HTTP {}", self.status)
        } else {
            write!(f, "Plus answered {} ({})", self.code, self.status)
        }
    }
}

/// Canonical CBOR of a map.
pub fn map(entries: Vec<(u64, Value)>) -> Vec<u8> {
    cbor::encode(&Value::Map(entries))
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// A signed envelope `{1: record bytes, 2: raw signature}` over `record`.
pub fn envelope(record: &[u8], key: &SoftwareKey) -> Vec<u8> {
    let sig = key.sign_raw(record);
    map(vec![(1, bytes(record)), (2, bytes(sig.as_bytes()))])
}

/// The link poll record, signed by the Plus key.
pub fn link_poll(key: &SoftwareKey, link_id: &[u8; 16], issued_at: u64) -> Vec<u8> {
    let record = map(vec![
        (1, Value::Text(LINK_DOMAIN.into())),
        (2, bytes(link_id)),
        (3, Value::Uint(issued_at)),
    ]);
    envelope(&record, key)
}

/// The token request record, signed by the Plus key.
pub fn token_request(
    key: &SoftwareKey,
    endpoint_id: &[u8; 16],
    audience: &str,
    issued_at: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let record = map(vec![
        (1, Value::Text(TOKEN_DOMAIN.into())),
        (2, bytes(endpoint_id)),
        (3, Value::Text(audience.into())),
        (4, Value::Uint(issued_at)),
        (5, bytes(nonce)),
    ]);
    envelope(&record, key)
}

// Used by the hosted relay client, which registers handles; until it
// lands only tests reach this.
#[allow(dead_code)]
/// The handle proof: a raw signature by the registration key over
/// `{1: "mousse-plus-handle-v1", 2: relay id, 3: endpoint id}`.
pub fn handle_proof(
    registration: &SoftwareKey,
    relay_id: &[u8; 32],
    endpoint_id: &[u8; 16],
) -> RawSignature {
    let record = map(vec![
        (1, Value::Text(HANDLE_DOMAIN.into())),
        (2, bytes(relay_id)),
        (3, bytes(endpoint_id)),
    ]);
    registration.sign_raw(&record)
}

// Used by the hosted relay client, which registers handles; until it
// lands only tests reach this.
#[allow(dead_code)]
/// `H = SHA-256("mousse-relay-handle-v1" ‖ relay id ‖ registration key)`.
pub fn handle(relay_id: &[u8; 32], registration: &PublicKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"mousse-relay-handle-v1");
    h.update(relay_id);
    h.update(registration.as_bytes());
    h.finalize().into()
}

/// A traffic class on a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Typing and control.
    Interactive,
    /// Copies.
    Bulk,
}

impl Class {
    /// The wire value.
    pub const fn code(self) -> u64 {
        match self {
            Class::Interactive => 0,
            Class::Bulk => 1,
        }
    }

    /// From the wire value.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Class::Interactive),
            1 => Some(Class::Bulk),
            _ => None,
        }
    }

    /// Stable name.
    pub const fn name(self) -> &'static str {
        match self {
            Class::Interactive => "interactive",
            Class::Bulk => "bulk",
        }
    }
}

/// The fields of a Plus-signed lease block the helper keeps (A.12). The
/// relay checks the issuer signature; the helper only reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The signed envelope, as Plus sent it.
    pub envelope: Vec<u8>,
    /// Lease id (key 3).
    pub lease_id: [u8; 16],
    /// Relay id (key 4).
    pub relay_id: [u8; 32],
    /// Boot id (key 5).
    pub boot_id: [u8; 16],
    /// Handle (key 6).
    pub handle: [u8; 32],
    /// Class (key 7).
    pub class: Class,
    /// Block sequence (key 8).
    pub sequence: u64,
    /// Rate cap, bytes per second (key 9).
    pub rate_cap: u64,
    /// Bytes it lets the relay forward (key 10).
    pub bytes: u64,
    /// Not before (key 11).
    pub not_before: u64,
    /// Expires at (key 12).
    pub expires_at: u64,
}

impl Block {
    /// Read a block envelope. Exactly the A.12 keys; a block that breaks
    /// the fixed floors or lifetime is refused, since a relay would refuse
    /// it too.
    pub fn parse(envelope: &[u8]) -> Result<Self, BadAnswer> {
        let env =
            mousse_net_core::cbor::Fields::decode(envelope).map_err(|e| BadAnswer(e.to_string()));
        let mut env = env?;
        let record = env.bytes(1).map_err(|e| BadAnswer(e.to_string()))?;
        let sig = env.bytes(2).map_err(|e| BadAnswer(e.to_string()))?;
        env.finish().map_err(|e| BadAnswer(e.to_string()))?;
        RawSignature::from_slice(&sig).map_err(|e| BadAnswer(e.to_string()))?;
        let mut f =
            mousse_net_core::cbor::Fields::decode(&record).map_err(|e| BadAnswer(e.to_string()))?;
        let bad = |e: mousse_net_core::cbor::FieldError| BadAnswer(e.to_string());
        if f.text(1).map_err(bad)? != LEASE_DOMAIN {
            return Err(BadAnswer("not a lease block".into()));
        }
        let _issuer = f.fixed::<8>(2).map_err(bad)?;
        let block = Self {
            envelope: envelope.to_vec(),
            lease_id: f.fixed::<16>(3).map_err(bad)?,
            relay_id: f.fixed::<32>(4).map_err(bad)?,
            boot_id: f.fixed::<16>(5).map_err(bad)?,
            handle: f.fixed::<32>(6).map_err(bad)?,
            class: Class::from_code(f.uint(7).map_err(bad)?)
                .ok_or_else(|| BadAnswer("unknown class".into()))?,
            sequence: f.uint(8).map_err(bad)?,
            rate_cap: f.uint(9).map_err(bad)?,
            bytes: f.uint(10).map_err(bad)?,
            not_before: f.uint(11).map_err(bad)?,
            expires_at: f.uint(12).map_err(bad)?,
        };
        let _group = f.fixed::<16>(13).map_err(bad)?;
        f.finish().map_err(bad)?;
        if block.rate_cap < BLOCK_FLOOR
            || block.bytes < BLOCK_FLOOR
            || block.expires_at > block.not_before.saturating_add(BLOCK_MAX_LIFETIME)
        {
            return Err(BadAnswer("block outside the fixed bounds".into()));
        }
        Ok(block)
    }
}

// Used by the hosted relay client, which registers handles; until it
// lands only tests reach this.
#[allow(dead_code)]
/// The fields of a Plus-signed admission token the helper keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionToken {
    /// The signed envelope.
    pub envelope: Vec<u8>,
    /// Relay id (key 3).
    pub relay_id: [u8; 32],
    /// Handle (key 4).
    pub handle: [u8; 32],
    /// Not before (key 5).
    pub not_before: u64,
    /// Not after (key 6).
    pub not_after: u64,
}

// Used by the hosted relay client, which registers handles; until it
// lands only tests reach this.
#[allow(dead_code)]
impl AdmissionToken {
    /// Read an admission token envelope.
    pub fn parse(envelope: &[u8]) -> Result<Self, BadAnswer> {
        let bad = |e: mousse_net_core::cbor::FieldError| BadAnswer(e.to_string());
        let mut env = mousse_net_core::cbor::Fields::decode(envelope).map_err(bad)?;
        let record = env.bytes(1).map_err(bad)?;
        let _sig = env.bytes(2).map_err(bad)?;
        env.finish().map_err(bad)?;
        let mut f = mousse_net_core::cbor::Fields::decode(&record).map_err(bad)?;
        if f.text(1).map_err(bad)? != ADMIT_DOMAIN {
            return Err(BadAnswer("not an admission token".into()));
        }
        let _issuer = f.fixed::<8>(2).map_err(bad)?;
        let token = Self {
            envelope: envelope.to_vec(),
            relay_id: f.fixed::<32>(3).map_err(bad)?,
            handle: f.fixed::<32>(4).map_err(bad)?,
            not_before: f.uint(5).map_err(bad)?,
            not_after: f.uint(6).map_err(bad)?,
        };
        f.finish().map_err(bad)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousse_net_core::cbor::Fields;
    use mousse_net_io::rng::os_rng;

    #[test]
    fn signed_records_carry_their_domain_and_verify_under_the_plus_key() {
        let key = SoftwareKey::generate(&mut os_rng());
        let env = link_poll(&key, &[3; 16], 1_800_000_000);
        let mut f = Fields::decode(&env).unwrap();
        let record = f.bytes(1).unwrap();
        let sig = RawSignature::from_slice(&f.bytes(2).unwrap()).unwrap();
        f.finish().unwrap();
        key.public_key().verify(&record, &sig).unwrap();
        let mut r = Fields::decode(&record).unwrap();
        assert_eq!(r.text(1).unwrap(), LINK_DOMAIN);
        assert_eq!(r.fixed::<16>(2).unwrap(), [3; 16]);
        assert_eq!(r.uint(3).unwrap(), 1_800_000_000);
        r.finish().unwrap();

        let env = token_request(&key, &[4; 16], "https://plus.example", 7, &[5; 16]);
        let mut f = Fields::decode(&env).unwrap();
        let mut r = Fields::decode(&f.bytes(1).unwrap()).unwrap();
        assert_eq!(r.text(1).unwrap(), TOKEN_DOMAIN);
        assert_eq!(r.text(3).unwrap(), "https://plus.example");
        assert_eq!(r.fixed::<16>(5).unwrap(), [5; 16]);
    }

    #[test]
    fn answers_ignore_unknown_keys_and_errors_keep_the_status() {
        let body = map(vec![(1, Value::Uint(2)), (99, Value::Text("later".into()))]);
        let a = Answer::decode(&body).unwrap();
        assert_eq!(a.uint(1).unwrap(), 2);
        let e = PlusError::from_body(
            429,
            &map(vec![
                (1, Value::Text("rate_limited".into())),
                (2, Value::Uint(3)),
            ]),
        );
        assert_eq!(e.retry_after, Some(3));
        assert!(e.is_transient());
        let unknown = PlusError::from_body(503, b"not cbor");
        assert!(unknown.code.is_empty() && unknown.is_transient());
        assert!(
            !PlusError::from_body(402, &map(vec![(1, Value::Text("not_plus".into()))]))
                .is_transient()
        );
    }

    fn block_record(rate: u64, bytes: u64, nb: u64, exp: u64) -> Vec<u8> {
        let key = SoftwareKey::generate(&mut os_rng());
        let record = map(vec![
            (1, Value::Text(LEASE_DOMAIN.into())),
            (2, Value::Bytes(vec![1; 8])),
            (3, Value::Bytes(vec![2; 16])),
            (4, Value::Bytes(vec![3; 32])),
            (5, Value::Bytes(vec![4; 16])),
            (6, Value::Bytes(vec![5; 32])),
            (7, Value::Uint(1)),
            (8, Value::Uint(1)),
            (9, Value::Uint(rate)),
            (10, Value::Uint(bytes)),
            (11, Value::Uint(nb)),
            (12, Value::Uint(exp)),
            (13, Value::Bytes(vec![6; 16])),
        ]);
        envelope(&record, &key)
    }

    #[test]
    fn blocks_outside_the_fixed_bounds_are_refused() {
        let ok = Block::parse(&block_record(65_536, 1 << 20, 10, 10 + 3600)).unwrap();
        assert_eq!(ok.class, Class::Bulk);
        assert_eq!(ok.bytes, 1 << 20);
        assert!(Block::parse(&block_record(65_535, 1 << 20, 10, 3610)).is_err());
        assert!(Block::parse(&block_record(
            65_536,
            1 << 20,
            10,
            10 + BLOCK_MAX_LIFETIME + 1
        ))
        .is_err());
    }
}
