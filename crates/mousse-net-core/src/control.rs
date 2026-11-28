//! Control-stream messages (stream 0, frame type `CONTROL`).
//!
//! Each message is one canonical CBOR map. Key 0 holds the message type;
//! the other keys are per type (spec `wire.md`, "Control messages").

use std::fmt;

use crate::cbor::{self, FieldError, Fields, Value};
use crate::grants::{validate_name, Role};
use crate::pairing::{AttemptId, DirectLookup, InvitationId};
use crate::{ErrorCode, PROTOCOL_MINOR_VERSION, PROTOCOL_VERSION};

/// The minor version that adds `JOIN_DIRECT` and `AUTHORIZED` keys 2 and 3
/// (Pair with IP). Neither is defined on a connection that agreed an older
/// minor version.
pub const DIRECT_MINOR_VERSION: u64 = 4;

/// Largest encoded control message, in bytes.
pub const MAX_CONTROL_MESSAGE: usize = 16_384;

/// Largest code-exchange payload, in bytes.
pub const MAX_EXCHANGE_PAYLOAD: usize = 1_024;

/// What step 2 decided, as the host tells the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizedState {
    /// A live grant: normal channels.
    Live = 1,
    /// Join-only: pairing messages only.
    JoinOnly = 2,
}

/// The recovery part of a `JOIN_DIRECT` (keys 3 and 4): a joiner that lost
/// its connection after the code passed asks by receipt, with no code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectRecovery {
    /// Key 3: the invitation id the host's confirmation authenticated.
    pub receipt: InvitationId,
    /// Key 4: the joiner cancels its request (or the grant it made).
    pub cancel: bool,
}

/// One control message.
#[derive(Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Type 1, both directions, first message on every connection.
    Hello {
        /// The sender's major protocol version.
        major_version: u64,
        /// The sender's minor protocol version (the newest it speaks).
        minor_version: u64,
    },
    /// Type 2, host to caller: the step 2 result.
    Authorized {
        /// Live or join-only.
        state: AuthorizedState,
    },
    /// Type 3, caller to host: proof of ticket possession bound to this TLS
    /// session.
    JoinProof {
        /// The ticket's invitation id.
        invitation: InvitationId,
        /// HMAC-SHA256 tag (spec "Join proof").
        mac: [u8; 32],
        /// The joining endpoint's display name (1 to 128 bytes), for example
        /// "<computer> (<profile>)".
        name: String,
    },
    /// Type 4, both directions: one code-exchange message.
    CodeExchange {
        /// The attempt this message belongs to.
        attempt: AttemptId,
        /// Opaque exchange bytes (at most 1024).
        payload: Vec<u8>,
    },
    /// Type 5, both directions: the sender ended an attempt.
    CodeAbort {
        /// The attempt.
        attempt: AttemptId,
        /// Why.
        code: ErrorCode,
    },
    /// Type 6, host to joiner: enrollment done; the connection is now live.
    Paired {
        /// The host endpoint's display name (1 to 128 bytes).
        host_name: String,
        /// The role the new grant carries.
        role: Role,
    },
    /// Type 7, caller to host (minor 4): look up a direct invitation
    /// (Pair with IP) by the code's first 4 characters.
    JoinDirect {
        /// Key 1: the lookup `L`.
        lookup: DirectLookup,
        /// Key 2: the joining computer's name (1 to 128 bytes).
        name: String,
        /// Keys 3 and 4, only when recovering.
        recovery: Option<DirectRecovery>,
    },
    /// Type 2 with key 2 (minor 4), host to caller: `AUTHORIZED {join_only}`
    /// in answer to `JOIN_DIRECT`, naming the direct invitation.
    AuthorizedDirect {
        /// Key 2: the invitation id `I`.
        invitation: InvitationId,
        /// Key 3: the host has no request from this identity (it never
        /// received the joiner's confirmation). Only in answer to a
        /// `JOIN_DIRECT` with a receipt.
        not_received: bool,
    },
}

impl fmt::Debug for ControlMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlMessage::Hello {
                major_version,
                minor_version,
            } => write!(f, "Hello({major_version}.{minor_version})"),
            ControlMessage::Authorized { state } => write!(f, "Authorized({state:?})"),
            ControlMessage::JoinProof {
                invitation, name, ..
            } => {
                write!(f, "JoinProof({invitation:?}, {name:?})")
            }
            ControlMessage::CodeExchange { attempt, payload } => {
                write!(f, "CodeExchange({attempt:?}, {} bytes)", payload.len())
            }
            ControlMessage::CodeAbort { attempt, code } => {
                write!(f, "CodeAbort({attempt:?}, {code:?})")
            }
            ControlMessage::Paired { host_name, role } => {
                write!(f, "Paired({host_name:?}, {role:?})")
            }
            ControlMessage::JoinDirect {
                lookup,
                name,
                recovery,
            } => write!(f, "JoinDirect({lookup:?}, {name:?}, {recovery:?})"),
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received,
            } => write!(
                f,
                "AuthorizedDirect({invitation:?}, not_received: {not_received})"
            ),
        }
    }
}

/// Why a control message was rejected. The receiver closes the connection
/// with `PROTOCOL_ERROR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// Larger than [`MAX_CONTROL_MESSAGE`].
    TooLarge,
    /// Not a valid record.
    Field(FieldError),
    /// Message type not defined in the negotiated version.
    UnknownType(u64),
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlError::TooLarge => f.write_str("control message too large"),
            ControlError::Field(e) => write!(f, "bad control message: {e}"),
            ControlError::UnknownType(t) => write!(f, "unknown control message type {t}"),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<FieldError> for ControlError {
    fn from(e: FieldError) -> Self {
        ControlError::Field(e)
    }
}

impl ControlMessage {
    /// The type number (key 0).
    pub fn type_number(&self) -> u64 {
        match self {
            ControlMessage::Hello { .. } => 1,
            ControlMessage::Authorized { .. } | ControlMessage::AuthorizedDirect { .. } => 2,
            ControlMessage::JoinProof { .. } => 3,
            ControlMessage::CodeExchange { .. } => 4,
            ControlMessage::CodeAbort { .. } => 5,
            ControlMessage::Paired { .. } => 6,
            ControlMessage::JoinDirect { .. } => 7,
        }
    }

    /// The oldest agreed minor version on which this message is defined.
    pub fn since_minor(&self) -> u64 {
        match self {
            ControlMessage::JoinDirect { .. } | ControlMessage::AuthorizedDirect { .. } => {
                DIRECT_MINOR_VERSION
            }
            _ => 0,
        }
    }

    /// Whether this message is defined on a connection that agreed minor
    /// version `agreed`. A receiver closes with `PROTOCOL_ERROR` otherwise.
    pub fn defined_at(&self, agreed: u64) -> bool {
        self.since_minor() <= agreed
    }

    /// Canonical CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![(0, Value::Uint(self.type_number()))];
        match self {
            ControlMessage::Hello {
                major_version,
                minor_version,
            } => {
                entries.push((1, Value::Uint(*major_version)));
                entries.push((2, Value::Uint(*minor_version)));
            }
            ControlMessage::Authorized { state } => entries.push((1, Value::Uint(*state as u64))),
            ControlMessage::JoinProof {
                invitation,
                mac,
                name,
            } => {
                entries.push((1, Value::Bytes(invitation.0.to_vec())));
                entries.push((2, Value::Bytes(mac.to_vec())));
                entries.push((3, Value::Text(name.clone())));
            }
            ControlMessage::CodeExchange { attempt, payload } => {
                entries.push((1, Value::Bytes(attempt.0.to_vec())));
                entries.push((2, Value::Bytes(payload.clone())));
            }
            ControlMessage::CodeAbort { attempt, code } => {
                entries.push((1, Value::Bytes(attempt.0.to_vec())));
                entries.push((2, Value::Uint(u64::from(code.as_u16()))));
            }
            ControlMessage::Paired { host_name, role } => {
                entries.push((1, Value::Text(host_name.clone())));
                entries.push((2, Value::Text(role.as_str().to_owned())));
            }
            ControlMessage::JoinDirect {
                lookup,
                name,
                recovery,
            } => {
                entries.push((1, Value::Text(lookup.as_str().to_owned())));
                entries.push((2, Value::Text(name.clone())));
                if let Some(recovery) = recovery {
                    entries.push((3, Value::Bytes(recovery.receipt.0.to_vec())));
                    if recovery.cancel {
                        entries.push((4, Value::Uint(1)));
                    }
                }
            }
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received,
            } => {
                entries.push((1, Value::Uint(AuthorizedState::JoinOnly as u64)));
                entries.push((2, Value::Bytes(invitation.0.to_vec())));
                if *not_received {
                    entries.push((3, Value::Uint(1)));
                }
            }
        }
        cbor::encode(&Value::Map(entries))
    }

    /// Decode and validate one message received on a connection that agreed
    /// minor version `agreed`. A message the agreed version does not define
    /// is rejected as a decoder of that version rejects it: `JOIN_DIRECT` as
    /// an unknown type, `AUTHORIZED` key 2 as an unknown field.
    pub fn decode_at(bytes: &[u8], agreed: u64) -> Result<Self, ControlError> {
        let message = Self::decode(bytes)?;
        if message.defined_at(agreed) {
            return Ok(message);
        }
        Err(match message {
            ControlMessage::AuthorizedDirect { .. } => FieldError::Unknown(2).into(),
            other => ControlError::UnknownType(other.type_number()),
        })
    }

    /// Decode and validate one message.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() > MAX_CONTROL_MESSAGE {
            return Err(ControlError::TooLarge);
        }
        let mut f = Fields::decode(bytes)?;
        let kind = f.uint(0)?;
        let message = match kind {
            1 => ControlMessage::Hello {
                major_version: f.uint(1)?,
                minor_version: f.uint(2)?,
            },
            2 => {
                let state = match f.uint(1)? {
                    1 => AuthorizedState::Live,
                    2 => AuthorizedState::JoinOnly,
                    _ => return Err(FieldError::Invalid(1).into()),
                };
                let invitation = optional_fixed::<16>(&mut f, 2)?;
                let not_received = optional_flag(&mut f, 3)?;
                match (invitation, state) {
                    (None, _) if not_received => return Err(FieldError::Invalid(3).into()),
                    (None, state) => ControlMessage::Authorized { state },
                    (Some(_), AuthorizedState::Live) => return Err(FieldError::Invalid(2).into()),
                    (Some(id), AuthorizedState::JoinOnly) => ControlMessage::AuthorizedDirect {
                        invitation: InvitationId(id),
                        not_received,
                    },
                }
            }
            3 => {
                let invitation = InvitationId(f.fixed::<16>(1)?);
                let mac = f.fixed::<32>(2)?;
                let name = f.text(3)?;
                validate_name(&name).map_err(|_| FieldError::Invalid(3))?;
                ControlMessage::JoinProof {
                    invitation,
                    mac,
                    name,
                }
            }
            4 => {
                let attempt = AttemptId(f.fixed::<16>(1)?);
                let payload = f.bytes(2)?;
                if payload.is_empty() || payload.len() > MAX_EXCHANGE_PAYLOAD {
                    return Err(FieldError::Invalid(2).into());
                }
                ControlMessage::CodeExchange { attempt, payload }
            }
            5 => {
                let attempt = AttemptId(f.fixed::<16>(1)?);
                let raw = u16::try_from(f.uint(2)?).map_err(|_| FieldError::Invalid(2))?;
                // Unknown codes are read as INTERNAL_ERROR, as in RESET and GOAWAY.
                let code = ErrorCode::from_u16(raw).unwrap_or(ErrorCode::InternalError);
                ControlMessage::CodeAbort { attempt, code }
            }
            6 => {
                let host_name = f.text(1)?;
                validate_name(&host_name).map_err(|_| FieldError::Invalid(1))?;
                let role = Role::new(&f.text(2)?).map_err(|_| FieldError::Invalid(2))?;
                ControlMessage::Paired { host_name, role }
            }
            7 => {
                let lookup =
                    DirectLookup::from_canonical(&f.text(1)?).ok_or(FieldError::Invalid(1))?;
                let name = f.text(2)?;
                validate_name(&name).map_err(|_| FieldError::Invalid(2))?;
                let receipt = optional_fixed::<16>(&mut f, 3)?;
                let cancel = optional_flag(&mut f, 4)?;
                let recovery = match receipt {
                    Some(id) => Some(DirectRecovery {
                        receipt: InvitationId(id),
                        cancel,
                    }),
                    None if cancel => return Err(FieldError::Invalid(4).into()),
                    None => None,
                };
                ControlMessage::JoinDirect {
                    lookup,
                    name,
                    recovery,
                }
            }
            other => return Err(ControlError::UnknownType(other)),
        };
        f.finish()?;
        Ok(message)
    }
}

/// An optional byte string of exactly `N` bytes.
fn optional_fixed<const N: usize>(f: &mut Fields, key: u64) -> Result<Option<[u8; N]>, FieldError> {
    match f.optional(key) {
        None => Ok(None),
        Some(Value::Bytes(b)) => b.try_into().map(Some).map_err(|_| FieldError::Invalid(key)),
        Some(_) => Err(FieldError::WrongType(key)),
    }
}

/// An optional flag: absent is false, `1` is true, anything else is
/// rejected (canonical CBOR has no `true`, wire.md 3).
fn optional_flag(f: &mut Fields, key: u64) -> Result<bool, FieldError> {
    match f.optional(key) {
        None => Ok(false),
        Some(Value::Uint(1)) => Ok(true),
        Some(Value::Uint(_)) => Err(FieldError::Invalid(key)),
        Some(_) => Err(FieldError::WrongType(key)),
    }
}

impl ControlMessage {
    /// The `HELLO` this build sends.
    pub fn hello() -> Self {
        ControlMessage::Hello {
            major_version: PROTOCOL_VERSION,
            minor_version: PROTOCOL_MINOR_VERSION,
        }
    }
}

/// The protocol versions one side speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionSupport {
    /// The major version (exactly one per build).
    pub major: u64,
    /// The newest minor version; sent in `HELLO`.
    pub minor: u64,
    /// The oldest minor version still spoken.
    pub oldest_minor: u64,
}

impl VersionSupport {
    /// What this build speaks: the current minor version and the one before.
    pub const LOCAL: VersionSupport = VersionSupport {
        major: PROTOCOL_VERSION,
        minor: PROTOCOL_MINOR_VERSION,
        oldest_minor: PROTOCOL_MINOR_VERSION.saturating_sub(1),
    };
}

/// Decide the minor version for a connection from the peer's `HELLO`.
///
/// Both sides use the lower of the two minor versions. The connection closes
/// with `UNSUPPORTED_VERSION` if the major versions differ or the lower minor
/// version is older than the oldest one `local` speaks. Each side decides on
/// its own; both reach the same minor version when both accept.
pub fn negotiate_version(
    local: VersionSupport,
    peer_major: u64,
    peer_minor: u64,
) -> Result<u64, ErrorCode> {
    if peer_major != local.major {
        return Err(ErrorCode::UnsupportedVersion);
    }
    let agreed = local.minor.min(peer_minor);
    if agreed < local.oldest_minor {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(agreed)
}

/// Whether a peer whose `HELLO` named `peer_minor` accepts `agreed`. A peer
/// speaks its newest minor and the one before it (wire.md 2), so it closes
/// with `UNSUPPORTED_VERSION` below that. A side that sees this may close
/// first: a caller then never goes live on a connection the host refuses
/// as soon as it reads the caller's `HELLO`.
pub fn peer_accepts(agreed: u64, peer_minor: u64) -> bool {
    agreed >= peer_minor.saturating_sub(1)
}

/// The decision a connection makes on the peer's first `HELLO`:
/// [`negotiate_version`], then `UNSUPPORTED_VERSION` too when the peer
/// would refuse the result ([`peer_accepts`]). What [`HelloState`] applies.
pub fn connection_version(
    local: VersionSupport,
    peer_major: u64,
    peer_minor: u64,
) -> Result<u64, ErrorCode> {
    let agreed = negotiate_version(local, peer_major, peer_minor)?;
    if !peer_accepts(agreed, peer_minor) {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(agreed)
}

/// What one received `HELLO` did to a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloOutcome {
    /// The peer's first `HELLO`: the connection uses this minor version.
    Agreed(u64),
    /// A later `HELLO`: it has no effect, whatever it holds.
    Ignored,
    /// No common version: close the connection with this code.
    Close(ErrorCode),
}

/// The version state of one connection. Only the peer's first `HELLO`
/// counts (spec `wire.md`, "Versions"): it fixes the minor version or closes
/// the connection ([`connection_version`]). Later ones are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloState {
    local: VersionSupport,
    decided: Option<Result<u64, ErrorCode>>,
}

impl HelloState {
    /// A connection that has not received the peer's `HELLO` yet.
    pub fn new(local: VersionSupport) -> Self {
        Self {
            local,
            decided: None,
        }
    }

    /// The agreed minor version, once the peer's first `HELLO` was accepted.
    pub fn agreed(&self) -> Option<u64> {
        self.decided.and_then(Result::ok)
    }

    /// A `HELLO` arrived from the peer.
    pub fn on_hello(&mut self, peer_major: u64, peer_minor: u64) -> HelloOutcome {
        if self.decided.is_some() {
            return HelloOutcome::Ignored;
        }
        let result = connection_version(self.local, peer_major, peer_minor);
        self.decided = Some(result);
        match result {
            Ok(minor) => HelloOutcome::Agreed(minor),
            Err(code) => HelloOutcome::Close(code),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn version_negotiation_takes_the_lower_minor_and_refuses_too_old() {
        let local = VersionSupport {
            major: 1,
            minor: 4,
            oldest_minor: 3,
        };
        assert_eq!(negotiate_version(local, 1, 4), Ok(4));
        assert_eq!(negotiate_version(local, 1, 9), Ok(4));
        assert_eq!(negotiate_version(local, 1, 3), Ok(3));
        assert_eq!(
            negotiate_version(local, 1, 2),
            Err(ErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            negotiate_version(local, 2, 4),
            Err(ErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            negotiate_version(local, 0, 4),
            Err(ErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn a_peer_accepts_its_newest_minor_and_the_one_before() {
        assert!(peer_accepts(3, 3));
        assert!(peer_accepts(2, 3));
        assert!(!peer_accepts(1, 3));
        assert!(peer_accepts(0, 0));
        assert!(peer_accepts(0, 1));
    }

    #[test]
    fn only_the_first_hello_counts() {
        let mut state = HelloState::new(VersionSupport::LOCAL);
        assert_eq!(state.agreed(), None);
        assert_eq!(
            state.on_hello(PROTOCOL_VERSION, PROTOCOL_MINOR_VERSION),
            HelloOutcome::Agreed(PROTOCOL_MINOR_VERSION)
        );
        assert_eq!(
            state.on_hello(PROTOCOL_VERSION + 1, 0),
            HelloOutcome::Ignored
        );
        assert_eq!(state.agreed(), Some(PROTOCOL_MINOR_VERSION));

        let mut refused = HelloState::new(VersionSupport::LOCAL);
        assert_eq!(
            refused.on_hello(PROTOCOL_VERSION + 1, 0),
            HelloOutcome::Close(ErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            refused.on_hello(PROTOCOL_VERSION, PROTOCOL_MINOR_VERSION),
            HelloOutcome::Ignored
        );
        assert_eq!(refused.agreed(), None);
    }

    fn all() -> Vec<ControlMessage> {
        vec![
            ControlMessage::hello(),
            ControlMessage::Authorized {
                state: AuthorizedState::JoinOnly,
            },
            ControlMessage::JoinProof {
                invitation: InvitationId([1; 16]),
                mac: [2; 32],
                name: "Laptop".into(),
            },
            ControlMessage::CodeExchange {
                attempt: AttemptId([3; 16]),
                payload: vec![4; 40],
            },
            ControlMessage::CodeAbort {
                attempt: AttemptId([3; 16]),
                code: ErrorCode::PairingFailed,
            },
            ControlMessage::Paired {
                host_name: "Desk".into(),
                role: Role::owner(),
            },
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for m in all() {
            assert_eq!(ControlMessage::decode(&m.encode()), Ok(m));
        }
    }

    #[test]
    fn unknown_types_extra_fields_and_bad_values_are_rejected() {
        let unknown = cbor::encode(&Value::Map(vec![(0, Value::Uint(99))]));
        assert_eq!(
            ControlMessage::decode(&unknown),
            Err(ControlError::UnknownType(99))
        );
        let extra = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(1)),
            (1, Value::Uint(1)),
            (2, Value::Uint(0)),
            (7, Value::Uint(0)),
        ]));
        assert_eq!(
            ControlMessage::decode(&extra),
            Err(ControlError::Field(FieldError::Unknown(7)))
        );
        let empty_payload = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(4)),
            (1, Value::Bytes(vec![0; 16])),
            (2, Value::Bytes(vec![])),
        ]));
        assert_eq!(
            ControlMessage::decode(&empty_payload),
            Err(ControlError::Field(FieldError::Invalid(2)))
        );
        let short_id = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(5)),
            (1, Value::Bytes(vec![0; 15])),
            (2, Value::Uint(10)),
        ]));
        assert_eq!(
            ControlMessage::decode(&short_id),
            Err(ControlError::Field(FieldError::Invalid(1)))
        );
    }

    #[test]
    fn abort_codes_unknown_are_internal_error_and_over_u16_are_rejected() {
        let abort = |code: u64| {
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(5)),
                (1, Value::Bytes(vec![0; 16])),
                (2, Value::Uint(code)),
            ]))
        };
        assert_eq!(
            ControlMessage::decode(&abort(999)),
            Ok(ControlMessage::CodeAbort {
                attempt: AttemptId([0; 16]),
                code: ErrorCode::InternalError
            })
        );
        assert_eq!(
            ControlMessage::decode(&abort(65_536)),
            Err(ControlError::Field(FieldError::Invalid(2)))
        );
    }
}
