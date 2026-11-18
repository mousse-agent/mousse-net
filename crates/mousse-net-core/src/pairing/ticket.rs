//! Pairing tickets: what the QR code or link carries.
//!
//! Binary form: one canonical CBOR map
//! `{1: version, 2: kind, 3: host identity (65 B), 4: invitation id (16 B),
//!   5: secret (16 B), 6: expires_at (Unix s), 7: [route, ...]}`.
//! URL-fragment form: base64url of the binary form, no padding.

use std::fmt;

use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{InvitationId, InvitationKind};
use crate::base64url;
use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::IdentityPublicKey;
use crate::limits::Limits;
use crate::time::UnixTime;
use crate::PROTOCOL_VERSION;

/// Ticket format version. Equal to the major protocol version.
pub const TICKET_VERSION: u64 = PROTOCOL_VERSION;

/// Most route hints a ticket may carry.
pub const MAX_ROUTES: usize = 8;

/// Longest route hint, in bytes.
pub const MAX_ROUTE_LEN: usize = 255;

/// The 128-bit single-use ticket secret. Zeroized on drop; `Debug` hides it.
#[derive(Clone)]
pub struct TicketSecret(pub(crate) [u8; 16]);

impl TicketSecret {
    /// A fresh secret.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap known bytes (tests, restore from storage).
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The secret bytes.
    pub fn expose(&self) -> &[u8; 16] {
        &self.0
    }
}

impl PartialEq for TicketSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for TicketSecret {}

impl Drop for TicketSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for TicketSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TicketSecret(..)")
    }
}

/// Why a ticket was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketError {
    /// The fragment is not strict base64url without padding.
    Encoding,
    /// The bytes are not a valid ticket record.
    Field(FieldError),
    /// The ticket's version is not one this build supports.
    UnsupportedVersion(u64),
    /// The kind is not a known invitation kind.
    UnknownKind(u64),
    /// The ticket has expired (on the joiner: past expiry plus 10 min skew).
    Expired,
}

impl TicketError {
    /// Stable snake_case name, used in test vectors.
    pub fn code(&self) -> &'static str {
        match self {
            TicketError::Encoding => "encoding",
            TicketError::Field(FieldError::Cbor(_)) => "cbor",
            TicketError::Field(_) => "field",
            TicketError::UnsupportedVersion(_) => "unsupported_version",
            TicketError::UnknownKind(_) => "unknown_kind",
            TicketError::Expired => "expired",
        }
    }
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketError::Encoding => f.write_str("pairing link is not valid base64url"),
            TicketError::Field(e) => write!(f, "pairing ticket is malformed: {e}"),
            TicketError::UnsupportedVersion(v) => {
                write!(f, "pairing ticket version {v} is not supported")
            }
            TicketError::UnknownKind(k) => write!(f, "pairing ticket kind {k} is not known"),
            TicketError::Expired => f.write_str("pairing ticket has expired"),
        }
    }
}

impl std::error::Error for TicketError {}

impl From<FieldError> for TicketError {
    fn from(e: FieldError) -> Self {
        TicketError::Field(e)
    }
}

/// A decoded pairing ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// Ticket version ([`TICKET_VERSION`]).
    pub version: u64,
    /// Invitation kind, fixed by the host.
    pub kind: InvitationKind,
    /// The host's identity key. The joiner pins this on first contact.
    pub host_identity: IdentityPublicKey,
    /// The invitation id.
    pub invitation: InvitationId,
    /// The single-use secret.
    pub secret: TicketSecret,
    /// First second the invitation is no longer valid (host clock).
    pub expires_at: UnixTime,
    /// Route hints, in the host's order of preference. Each is a URI such as
    /// `tcp://192.168.1.20:7443`. Their meaning belongs to the I/O layer.
    pub routes: Vec<String>,
}

impl Ticket {
    /// Canonical CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Uint(self.version)),
            (2, Value::Uint(self.kind.as_u64())),
            (3, Value::Bytes(self.host_identity.as_bytes().to_vec())),
            (4, Value::Bytes(self.invitation.0.to_vec())),
            (5, Value::Bytes(self.secret.0.to_vec())),
            (6, Value::Uint(self.expires_at.secs())),
            (
                7,
                Value::Array(self.routes.iter().map(|r| Value::Text(r.clone())).collect()),
            ),
        ]))
    }

    /// Decode and validate the binary form. Does not check expiry.
    pub fn decode(bytes: &[u8]) -> Result<Self, TicketError> {
        let mut f = Fields::decode(bytes)?;
        // The version decides the layout, so it is checked before anything else.
        let version = f.uint(1)?;
        if version != TICKET_VERSION {
            return Err(TicketError::UnsupportedVersion(version));
        }
        let kind_value = f.uint(2)?;
        let kind =
            InvitationKind::from_u64(kind_value).ok_or(TicketError::UnknownKind(kind_value))?;
        let host_identity =
            IdentityPublicKey::from_sec1(&f.bytes(3)?).map_err(|_| FieldError::Invalid(3))?;
        let invitation = InvitationId(f.fixed::<16>(4)?);
        let secret = TicketSecret(f.fixed::<16>(5)?);
        let expires_at = UnixTime(f.uint(6)?);
        let route_values = f.array(7)?;
        if route_values.len() > MAX_ROUTES {
            return Err(FieldError::Invalid(7).into());
        }
        let mut routes = Vec::with_capacity(route_values.len());
        for value in route_values {
            match value {
                Value::Text(t) if !t.is_empty() && t.len() <= MAX_ROUTE_LEN => routes.push(t),
                _ => return Err(FieldError::Invalid(7).into()),
            }
        }
        f.finish()?;
        Ok(Self {
            version,
            kind,
            host_identity,
            invitation,
            secret,
            expires_at,
            routes,
        })
    }

    /// The URL-fragment form: base64url without padding (no leading `#`).
    pub fn to_fragment(&self) -> String {
        base64url::encode(&self.encode())
    }

    /// Parse the URL-fragment form (without the leading `#`).
    pub fn from_fragment(fragment: &str) -> Result<Self, TicketError> {
        let bytes = base64url::decode(fragment).map_err(|_| TicketError::Encoding)?;
        Self::decode(&bytes)
    }

    /// SHA-256 of the canonical binary form. Bound into the code exchange.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Joiner-side freshness: valid while `now < expires_at + 10 min` (the
    /// default skew). The host checks its own record without skew.
    pub fn check_fresh_for_joiner(&self, now: UnixTime) -> Result<(), TicketError> {
        self.check_fresh_for_joiner_with_skew(now, Limits::DEFAULT.clock_skew_secs)
    }

    /// Joiner-side freshness: valid while `now < expires_at + skew`.
    pub fn check_fresh_for_joiner_with_skew(
        &self,
        now: UnixTime,
        skew_secs: u64,
    ) -> Result<(), TicketError> {
        if now < self.expires_at.plus(skew_secs) {
            Ok(())
        } else {
            Err(TicketError::Expired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SoftwareKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn ticket() -> Ticket {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        Ticket {
            version: TICKET_VERSION,
            kind: InvitationKind::SendLink,
            host_identity: SoftwareKey::generate(&mut rng).public_key(),
            invitation: InvitationId([0x11; 16]),
            secret: TicketSecret::generate(&mut rng),
            expires_at: UnixTime(1_790_000_600),
            routes: vec!["tcp://192.168.1.20:7443".into()],
        }
    }

    #[test]
    fn binary_and_fragment_forms_round_trip() {
        let t = ticket();
        assert_eq!(Ticket::decode(&t.encode()), Ok(t.clone()));
        assert_eq!(Ticket::from_fragment(&t.to_fragment()), Ok(t.clone()));
        assert!(!t.to_fragment().contains(['=', '+', '/']));
    }

    #[test]
    fn version_is_checked_first() {
        let bytes = cbor::encode(&Value::Map(vec![(1, Value::Uint(2))]));
        assert_eq!(
            Ticket::decode(&bytes),
            Err(TicketError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn wrong_lengths_and_extra_fields_are_rejected() {
        let t = ticket();
        let mut value = cbor::decode(&t.encode()).unwrap();
        if let Value::Map(entries) = &mut value {
            entries[4].1 = Value::Bytes(vec![0; 15]);
        }
        assert_eq!(
            Ticket::decode(&cbor::encode(&value)),
            Err(TicketError::Field(FieldError::Invalid(5)))
        );
        let mut value = cbor::decode(&t.encode()).unwrap();
        if let Value::Map(entries) = &mut value {
            entries.push((8, Value::Uint(0)));
        }
        assert_eq!(
            Ticket::decode(&cbor::encode(&value)),
            Err(TicketError::Field(FieldError::Unknown(8)))
        );
    }

    #[test]
    fn joiner_freshness_allows_ten_minutes_of_skew() {
        let t = ticket();
        assert_eq!(t.check_fresh_for_joiner(t.expires_at.plus(599)), Ok(()));
        assert_eq!(
            t.check_fresh_for_joiner(t.expires_at.plus(600)),
            Err(TicketError::Expired)
        );
    }

    #[test]
    fn hash_changes_with_any_field() {
        let a = ticket();
        let mut b = a.clone();
        b.routes.push("tcp://10.0.0.2:7443".into());
        assert_ne!(a.hash(), b.hash());
    }
}
