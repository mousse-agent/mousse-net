//! Control-stream messages (stream 0, frame type `CONTROL`).
//!
//! Each message is one canonical CBOR map. Key 0 holds the message type;
//! the other keys are per type (spec `wire.md`, "Control messages").

use std::fmt;

use crate::cbor::{self, FieldError, Fields, Value};
use crate::grants::{validate_name, Role};
use crate::pairing::{AttemptId, InvitationId};
use crate::ErrorCode;

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

/// One control message.
#[derive(Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Type 1, both directions, first message on every connection.
    Hello {
        /// The sender's minor protocol version.
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
        /// The joining device's display name (1 to 64 bytes).
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
        /// The host's display name (1 to 64 bytes).
        host_name: String,
        /// The role the new grant carries.
        role: Role,
    },
}

impl fmt::Debug for ControlMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlMessage::Hello { minor_version } => write!(f, "Hello({minor_version})"),
            ControlMessage::Authorized { state } => write!(f, "Authorized({state:?})"),
            ControlMessage::JoinProof { invitation, name, .. } => {
                write!(f, "JoinProof({invitation:?}, {name:?})")
            }
            ControlMessage::CodeExchange { attempt, payload } => {
                write!(f, "CodeExchange({attempt:?}, {} bytes)", payload.len())
            }
            ControlMessage::CodeAbort { attempt, code } => write!(f, "CodeAbort({attempt:?}, {code:?})"),
            ControlMessage::Paired { host_name, role } => write!(f, "Paired({host_name:?}, {role:?})"),
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
            ControlMessage::Authorized { .. } => 2,
            ControlMessage::JoinProof { .. } => 3,
            ControlMessage::CodeExchange { .. } => 4,
            ControlMessage::CodeAbort { .. } => 5,
            ControlMessage::Paired { .. } => 6,
        }
    }

    /// Canonical CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![(0, Value::Uint(self.type_number()))];
        match self {
            ControlMessage::Hello { minor_version } => entries.push((1, Value::Uint(*minor_version))),
            ControlMessage::Authorized { state } => entries.push((1, Value::Uint(*state as u64))),
            ControlMessage::JoinProof { invitation, mac, name } => {
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
        }
        cbor::encode(&Value::Map(entries))
    }

    /// Decode and validate one message.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() > MAX_CONTROL_MESSAGE {
            return Err(ControlError::TooLarge);
        }
        let mut f = Fields::decode(bytes)?;
        let kind = f.uint(0)?;
        let message = match kind {
            1 => ControlMessage::Hello { minor_version: f.uint(1)? },
            2 => ControlMessage::Authorized {
                state: match f.uint(1)? {
                    1 => AuthorizedState::Live,
                    2 => AuthorizedState::JoinOnly,
                    _ => return Err(FieldError::Invalid(1).into()),
                },
            },
            3 => {
                let invitation = InvitationId(f.fixed::<16>(1)?);
                let mac = f.fixed::<32>(2)?;
                let name = f.text(3)?;
                validate_name(&name).map_err(|_| FieldError::Invalid(3))?;
                ControlMessage::JoinProof { invitation, mac, name }
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
                let code = u16::try_from(f.uint(2)?)
                    .ok()
                    .and_then(ErrorCode::from_u16)
                    .ok_or(FieldError::Invalid(2))?;
                ControlMessage::CodeAbort { attempt, code }
            }
            6 => {
                let host_name = f.text(1)?;
                validate_name(&host_name).map_err(|_| FieldError::Invalid(1))?;
                let role = Role::new(&f.text(2)?).map_err(|_| FieldError::Invalid(2))?;
                ControlMessage::Paired { host_name, role }
            }
            other => return Err(ControlError::UnknownType(other)),
        };
        f.finish()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<ControlMessage> {
        vec![
            ControlMessage::Hello { minor_version: 0 },
            ControlMessage::Authorized { state: AuthorizedState::JoinOnly },
            ControlMessage::JoinProof { invitation: InvitationId([1; 16]), mac: [2; 32], name: "Laptop".into() },
            ControlMessage::CodeExchange { attempt: AttemptId([3; 16]), payload: vec![4; 40] },
            ControlMessage::CodeAbort { attempt: AttemptId([3; 16]), code: ErrorCode::PairingFailed },
            ControlMessage::Paired { host_name: "Desk".into(), role: Role::owner() },
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
        assert_eq!(ControlMessage::decode(&unknown), Err(ControlError::UnknownType(99)));
        let extra = cbor::encode(&Value::Map(vec![(0, Value::Uint(1)), (1, Value::Uint(0)), (7, Value::Uint(0))]));
        assert_eq!(ControlMessage::decode(&extra), Err(ControlError::Field(FieldError::Unknown(7))));
        let empty_payload = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(4)),
            (1, Value::Bytes(vec![0; 16])),
            (2, Value::Bytes(vec![])),
        ]));
        assert_eq!(ControlMessage::decode(&empty_payload), Err(ControlError::Field(FieldError::Invalid(2))));
        let short_id = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(5)),
            (1, Value::Bytes(vec![0; 15])),
            (2, Value::Uint(10)),
        ]));
        assert_eq!(ControlMessage::decode(&short_id), Err(ControlError::Field(FieldError::Invalid(1))));
    }
}
