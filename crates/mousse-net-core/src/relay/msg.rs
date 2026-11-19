//! Relay messages (spec `relay.md` section 4): one canonical CBOR map per
//! WebSocket message before a connection is spliced, key 0 the type.

use std::fmt;

use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::{PublicKey, RawSignature};

/// Largest relay message before splicing, in bytes (fixed).
pub const RELAY_MESSAGE_MAX: usize = 16_384;

/// Largest WebSocket message on a relay connection, in bytes (fixed).
pub const WS_MESSAGE_MAX: usize = 65_536;

/// Most caller fingerprints in one allow-set (fixed).
pub const ALLOW_CALLERS_MAX: usize = 256;

/// Most invitations in one allow-set (fixed).
pub const ALLOW_INVITATIONS_MAX: usize = 8;

/// Most lease ids in one `RELEASE` (fixed).
pub const RELEASE_MAX: usize = 4;

/// The relay protocol version in `RELAY_HELLO`.
pub const RELAY_VERSION: u64 = 1;

/// Mode in `RELAY_HELLO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Mode 0: an operator's list of authorized targets, no leases.
    SelfHosted = 0,
    /// Mode 1: admission tokens and leases (Phase 4).
    Hosted = 1,
}

/// Circuit class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Class 0.
    Interactive = 0,
    /// Class 1.
    Bulk = 1,
}

impl Class {
    fn from_uint(n: u64) -> Option<Self> {
        match n {
            0 => Some(Self::Interactive),
            1 => Some(Self::Bulk),
            _ => None,
        }
    }
}

/// Why the relay refused a registration or an accept leg (`REFUSED`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason {
    /// The key did not prove itself or is not authorized.
    NotAuthorized,
    /// The enrollment code is unknown, used or expired.
    Enrollment,
    /// A local limit on registrations or accept legs.
    Limit,
    /// Hosted: no valid admission token.
    Admission,
}

impl RefuseReason {
    /// The text on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not_authorized",
            Self::Enrollment => "enrollment",
            Self::Limit => "limit",
            Self::Admission => "admission",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::NotAuthorized,
            Self::Enrollment,
            Self::Limit,
            Self::Admission,
        ]
        .into_iter()
        .find(|r| r.as_str() == text)
    }
}

/// One allow-set invitation entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationEntry {
    /// `H(invitation tag)`.
    pub tag_hash: [u8; 32],
    /// Unix seconds.
    pub expires_at: u64,
}

/// One `LEASE_STATUS` entry (hosted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseStatusEntry {
    /// Lease id.
    pub lease: [u8; 16],
    /// Class.
    pub class: Class,
    /// Bytes used.
    pub used: u64,
    /// Bytes in the block.
    pub bytes: u64,
    /// 0 pending, 1 current, 2 final, 3 refused.
    pub state: u8,
}

/// A relay message.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// 1, relay → client, first.
    Hello {
        /// Relay protocol version.
        version: u64,
        /// Fresh per connection.
        nonce: [u8; 32],
        /// This relay boot.
        boot_id: [u8; 16],
        /// The relay's mode.
        mode: Mode,
    },
    /// 2, target → relay.
    Register {
        /// Registration public key.
        key: PublicKey,
        /// Register proof.
        proof: RawSignature,
        /// Hosted only: admission token and status threshold percent.
        hosted: Option<(Vec<u8>, u8)>,
    },
    /// 3, target → relay (self).
    Enroll {
        /// Registration public key.
        key: PublicKey,
        /// Register proof.
        proof: RawSignature,
        /// Enrollment code.
        code: [u8; 16],
    },
    /// 4, relay → target.
    Registered {
        /// The derived handle.
        handle: [u8; 32],
    },
    /// 5, target → relay.
    AllowSet {
        /// Sequence.
        sequence: u64,
        /// Caller key fingerprints.
        callers: Vec<[u8; 32]>,
        /// Open invitations.
        invitations: Vec<InvitationEntry>,
    },
    /// 6, relay → target.
    AllowSetOk {
        /// The accepted sequence.
        sequence: u64,
    },
    /// 7, caller → relay.
    Call {
        /// Target handle.
        handle: [u8; 32],
        /// Caller public key.
        key: PublicKey,
        /// Call proof.
        proof: RawSignature,
        /// Class.
        class: Class,
    },
    /// 8, joiner → relay.
    Join {
        /// Target handle.
        handle: [u8; 32],
        /// Invitation tag.
        tag: [u8; 32],
    },
    /// 9, relay → target.
    Incoming {
        /// Circuit id.
        circuit: [u8; 16],
        /// Class.
        class: Class,
        /// The caller fingerprint for a call; `None` for a join.
        caller: Option<[u8; 32]>,
    },
    /// 10, target → relay, first on a new connection.
    Accept {
        /// Handle.
        handle: [u8; 32],
        /// Circuit id.
        circuit: [u8; 16],
        /// Accept proof.
        proof: RawSignature,
    },
    /// 11, relay → both legs.
    Spliced,
    /// 12, relay → caller or joiner.
    Unreachable,
    /// 13, target → relay.
    Promote {
        /// Circuit id.
        circuit: [u8; 16],
        /// Caller fingerprint.
        caller: [u8; 32],
    },
    /// 14, target → relay (hosted).
    Lease {
        /// A signed envelope.
        block: Vec<u8>,
    },
    /// 15, relay → target (hosted).
    LeaseStatus {
        /// Entries.
        entries: Vec<LeaseStatusEntry>,
    },
    /// 16, relay → target, then close.
    Refused {
        /// Why.
        reason: RefuseReason,
    },
    /// 17, target → relay (hosted).
    Admit {
        /// A renewed admission token.
        token: Vec<u8>,
    },
    /// 18, target → relay (self).
    Successor {
        /// New registration key.
        key: PublicKey,
        /// Successor proof by the new key.
        new_proof: RawSignature,
        /// Successor proof by the current key.
        current_proof: RawSignature,
    },
    /// 19.
    Ping {
        /// Opaque.
        data: [u8; 8],
    },
    /// 20.
    Pong {
        /// The `PING`'s bytes.
        data: [u8; 8],
    },
    /// 21, target → relay (hosted).
    Release {
        /// Lease ids.
        leases: Vec<[u8; 16]>,
    },
}

impl fmt::Debug for RelayMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Proofs, nonces and codes are not secret, but keep logs short.
        f.write_str(self.name())
    }
}

/// Why a relay message was rejected (a protocol error, close 1002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// More than [`RELAY_MESSAGE_MAX`] bytes.
    TooLarge,
    /// Not canonical CBOR, not a map, or a field rule failed.
    Field(FieldError),
    /// Key 0 names no type.
    UnknownType(u64),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "relay message over {RELAY_MESSAGE_MAX} bytes"),
            Self::Field(e) => write!(f, "relay message: {e}"),
            Self::UnknownType(t) => write!(f, "unknown relay message type {t}"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<FieldError> for MessageError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

fn key_field(fields: &mut Fields, key: u64) -> Result<PublicKey, FieldError> {
    let bytes = fields.bytes(key)?;
    PublicKey::from_sec1(&bytes).map_err(|_| FieldError::Invalid(key))
}

fn proof_field(fields: &mut Fields, key: u64) -> Result<RawSignature, FieldError> {
    let bytes = fields.bytes(key)?;
    RawSignature::from_slice(&bytes).map_err(|_| FieldError::Invalid(key))
}

fn class_field(fields: &mut Fields, key: u64) -> Result<Class, FieldError> {
    Class::from_uint(fields.uint(key)?).ok_or(FieldError::Invalid(key))
}

fn fixed_value<const N: usize>(value: &Value, key: u64) -> Result<[u8; N], FieldError> {
    match value {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).map_err(|_| FieldError::Invalid(key)),
        _ => Err(FieldError::WrongType(key)),
    }
}

fn distinct<T: Ord + Copy>(items: &[T]) -> bool {
    let mut sorted: Vec<T> = items.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).all(|w| w[0] != w[1])
}

impl RelayMessage {
    /// The type number.
    pub const fn kind(&self) -> u64 {
        match self {
            Self::Hello { .. } => 1,
            Self::Register { .. } => 2,
            Self::Enroll { .. } => 3,
            Self::Registered { .. } => 4,
            Self::AllowSet { .. } => 5,
            Self::AllowSetOk { .. } => 6,
            Self::Call { .. } => 7,
            Self::Join { .. } => 8,
            Self::Incoming { .. } => 9,
            Self::Accept { .. } => 10,
            Self::Spliced => 11,
            Self::Unreachable => 12,
            Self::Promote { .. } => 13,
            Self::Lease { .. } => 14,
            Self::LeaseStatus { .. } => 15,
            Self::Refused { .. } => 16,
            Self::Admit { .. } => 17,
            Self::Successor { .. } => 18,
            Self::Ping { .. } => 19,
            Self::Pong { .. } => 20,
            Self::Release { .. } => 21,
        }
    }

    /// The spec name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "RELAY_HELLO",
            Self::Register { .. } => "REGISTER",
            Self::Enroll { .. } => "ENROLL",
            Self::Registered { .. } => "REGISTERED",
            Self::AllowSet { .. } => "ALLOW_SET",
            Self::AllowSetOk { .. } => "ALLOW_SET_OK",
            Self::Call { .. } => "CALL",
            Self::Join { .. } => "JOIN",
            Self::Incoming { .. } => "INCOMING",
            Self::Accept { .. } => "ACCEPT",
            Self::Spliced => "SPLICED",
            Self::Unreachable => "UNREACHABLE",
            Self::Promote { .. } => "PROMOTE",
            Self::Lease { .. } => "LEASE",
            Self::LeaseStatus { .. } => "LEASE_STATUS",
            Self::Refused { .. } => "REFUSED",
            Self::Admit { .. } => "ADMIT",
            Self::Successor { .. } => "SUCCESSOR",
            Self::Ping { .. } => "PING",
            Self::Pong { .. } => "PONG",
            Self::Release { .. } => "RELEASE",
        }
    }

    /// Whether only the relay sends this type.
    pub const fn from_relay(&self) -> bool {
        matches!(
            self,
            Self::Hello { .. }
                | Self::Registered { .. }
                | Self::AllowSetOk { .. }
                | Self::Incoming { .. }
                | Self::Spliced
                | Self::Unreachable
                | Self::LeaseStatus { .. }
                | Self::Refused { .. }
        )
    }

    /// Canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let b = |bytes: &[u8]| Value::Bytes(bytes.to_vec());
        let u = Value::Uint;
        let mut entries: Vec<(u64, Value)> = vec![(0, u(self.kind()))];
        match self {
            Self::Hello {
                version,
                nonce,
                boot_id,
                mode,
            } => entries.extend([
                (1, u(*version)),
                (2, b(nonce)),
                (3, b(boot_id)),
                (4, u(*mode as u64)),
            ]),
            Self::Register { key, proof, hosted } => {
                entries.extend([(1, b(key.as_bytes())), (2, b(proof.as_bytes()))]);
                if let Some((token, threshold)) = hosted {
                    entries.extend([(3, b(token)), (4, u(u64::from(*threshold)))]);
                }
            }
            Self::Enroll { key, proof, code } => entries.extend([
                (1, b(key.as_bytes())),
                (2, b(proof.as_bytes())),
                (3, b(code)),
            ]),
            Self::Registered { handle } => entries.push((1, b(handle))),
            Self::AllowSet {
                sequence,
                callers,
                invitations,
            } => entries.extend([
                (1, u(*sequence)),
                (2, Value::Array(callers.iter().map(|c| b(c)).collect())),
                (
                    3,
                    Value::Array(
                        invitations
                            .iter()
                            .map(|i| Value::Map(vec![(1, b(&i.tag_hash)), (2, u(i.expires_at))]))
                            .collect(),
                    ),
                ),
            ]),
            Self::AllowSetOk { sequence } => entries.push((1, u(*sequence))),
            Self::Call {
                handle,
                key,
                proof,
                class,
            } => entries.extend([
                (1, b(handle)),
                (2, b(key.as_bytes())),
                (3, b(proof.as_bytes())),
                (4, u(*class as u64)),
            ]),
            Self::Join { handle, tag } => entries.extend([(1, b(handle)), (2, b(tag))]),
            Self::Incoming {
                circuit,
                class,
                caller,
            } => {
                entries.extend([
                    (1, b(circuit)),
                    (2, u(u64::from(caller.is_none()))),
                    (3, u(*class as u64)),
                ]);
                if let Some(fp) = caller {
                    entries.push((4, b(fp)));
                }
            }
            Self::Accept {
                handle,
                circuit,
                proof,
            } => entries.extend([(1, b(handle)), (2, b(circuit)), (3, b(proof.as_bytes()))]),
            Self::Spliced | Self::Unreachable => {}
            Self::Promote { circuit, caller } => entries.extend([(1, b(circuit)), (2, b(caller))]),
            Self::Lease { block } => entries.push((1, b(block))),
            Self::LeaseStatus { entries: list } => entries.push((
                1,
                Value::Array(
                    list.iter()
                        .map(|e| {
                            Value::Map(vec![
                                (1, b(&e.lease)),
                                (2, u(e.class as u64)),
                                (3, u(e.used)),
                                (4, u(e.bytes)),
                                (5, u(u64::from(e.state))),
                            ])
                        })
                        .collect(),
                ),
            )),
            Self::Refused { reason } => entries.push((1, Value::Text(reason.as_str().into()))),
            Self::Admit { token } => entries.push((1, b(token))),
            Self::Successor {
                key,
                new_proof,
                current_proof,
            } => entries.extend([
                (1, b(key.as_bytes())),
                (2, b(new_proof.as_bytes())),
                (3, b(current_proof.as_bytes())),
            ]),
            Self::Ping { data } | Self::Pong { data } => entries.push((1, b(data))),
            Self::Release { leases } => {
                entries.push((1, Value::Array(leases.iter().map(|l| b(l)).collect())))
            }
        }
        cbor::encode(&Value::Map(entries))
    }

    /// Decode and check every field rule of `relay.md` 4.2.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > RELAY_MESSAGE_MAX {
            return Err(MessageError::TooLarge);
        }
        let mut f = Fields::decode(bytes)?;
        let kind = f.uint(0)?;
        let msg = match kind {
            1 => {
                let version = f.uint(1)?;
                if version != RELAY_VERSION {
                    return Err(FieldError::Invalid(1).into());
                }
                Self::Hello {
                    version,
                    nonce: f.fixed(2)?,
                    boot_id: f.fixed(3)?,
                    mode: match f.uint(4)? {
                        0 => Mode::SelfHosted,
                        1 => Mode::Hosted,
                        _ => return Err(FieldError::Invalid(4).into()),
                    },
                }
            }
            2 => {
                let key = key_field(&mut f, 1)?;
                let proof = proof_field(&mut f, 2)?;
                let token = f.optional(3);
                let threshold = f.optional(4);
                let hosted = match (token, threshold) {
                    (None, None) => None,
                    (Some(Value::Bytes(token)), Some(Value::Uint(t))) => {
                        if !(10..=90).contains(&t) {
                            return Err(FieldError::Invalid(4).into());
                        }
                        Some((token, t as u8))
                    }
                    (Some(Value::Bytes(_)), Some(_)) => return Err(FieldError::WrongType(4).into()),
                    (Some(_), Some(_)) => return Err(FieldError::WrongType(3).into()),
                    (Some(_), None) => return Err(FieldError::Missing(4).into()),
                    (None, Some(_)) => return Err(FieldError::Missing(3).into()),
                };
                Self::Register { key, proof, hosted }
            }
            3 => Self::Enroll {
                key: key_field(&mut f, 1)?,
                proof: proof_field(&mut f, 2)?,
                code: f.fixed(3)?,
            },
            4 => Self::Registered {
                handle: f.fixed(1)?,
            },
            5 => {
                let sequence = f.uint(1)?;
                let caller_values = f.array(2)?;
                if caller_values.len() > ALLOW_CALLERS_MAX {
                    return Err(FieldError::Invalid(2).into());
                }
                let callers = caller_values
                    .iter()
                    .map(|v| fixed_value::<32>(v, 2))
                    .collect::<Result<Vec<_>, _>>()?;
                if !distinct(&callers) {
                    return Err(FieldError::Invalid(2).into());
                }
                let invitation_values = f.array(3)?;
                if invitation_values.len() > ALLOW_INVITATIONS_MAX {
                    return Err(FieldError::Invalid(3).into());
                }
                let mut invitations = Vec::with_capacity(invitation_values.len());
                for v in invitation_values {
                    let mut entry = Fields::from_value(v).map_err(|_| FieldError::WrongType(3))?;
                    let tag_hash = entry.fixed(1).map_err(|_| FieldError::Invalid(3))?;
                    let expires_at = entry.uint(2).map_err(|_| FieldError::Invalid(3))?;
                    entry.finish().map_err(|_| FieldError::Invalid(3))?;
                    invitations.push(InvitationEntry {
                        tag_hash,
                        expires_at,
                    });
                }
                let hashes: Vec<[u8; 32]> = invitations.iter().map(|i| i.tag_hash).collect();
                if !distinct(&hashes) {
                    return Err(FieldError::Invalid(3).into());
                }
                Self::AllowSet {
                    sequence,
                    callers,
                    invitations,
                }
            }
            6 => Self::AllowSetOk {
                sequence: f.uint(1)?,
            },
            7 => Self::Call {
                handle: f.fixed(1)?,
                key: key_field(&mut f, 2)?,
                proof: proof_field(&mut f, 3)?,
                class: class_field(&mut f, 4)?,
            },
            8 => Self::Join {
                handle: f.fixed(1)?,
                tag: f.fixed(2)?,
            },
            9 => {
                let circuit = f.fixed(1)?;
                let kind = f.uint(2)?;
                let class = class_field(&mut f, 3)?;
                let caller = match kind {
                    0 => Some(f.fixed(4)?),
                    1 => None,
                    _ => return Err(FieldError::Invalid(2).into()),
                };
                Self::Incoming {
                    circuit,
                    class,
                    caller,
                }
            }
            10 => Self::Accept {
                handle: f.fixed(1)?,
                circuit: f.fixed(2)?,
                proof: proof_field(&mut f, 3)?,
            },
            11 => Self::Spliced,
            12 => Self::Unreachable,
            13 => Self::Promote {
                circuit: f.fixed(1)?,
                caller: f.fixed(2)?,
            },
            14 => Self::Lease { block: f.bytes(1)? },
            15 => {
                let mut entries = Vec::new();
                for v in f.array(1)? {
                    let mut e = Fields::from_value(v).map_err(|_| FieldError::WrongType(1))?;
                    let lease = e.fixed(1).map_err(|_| FieldError::Invalid(1))?;
                    let class = class_field(&mut e, 2).map_err(|_| FieldError::Invalid(1))?;
                    let used = e.uint(3).map_err(|_| FieldError::Invalid(1))?;
                    let bytes = e.uint(4).map_err(|_| FieldError::Invalid(1))?;
                    let state = e.uint(5).map_err(|_| FieldError::Invalid(1))?;
                    e.finish().map_err(|_| FieldError::Invalid(1))?;
                    if state > 3 {
                        return Err(FieldError::Invalid(1).into());
                    }
                    entries.push(LeaseStatusEntry {
                        lease,
                        class,
                        used,
                        bytes,
                        state: state as u8,
                    });
                }
                Self::LeaseStatus { entries }
            }
            16 => Self::Refused {
                reason: RefuseReason::parse(&f.text(1)?).ok_or(FieldError::Invalid(1))?,
            },
            17 => Self::Admit { token: f.bytes(1)? },
            18 => Self::Successor {
                key: key_field(&mut f, 1)?,
                new_proof: proof_field(&mut f, 2)?,
                current_proof: proof_field(&mut f, 3)?,
            },
            19 => Self::Ping { data: f.fixed(1)? },
            20 => Self::Pong { data: f.fixed(1)? },
            21 => {
                let values = f.array(1)?;
                if values.is_empty() || values.len() > RELEASE_MAX {
                    return Err(FieldError::Invalid(1).into());
                }
                Self::Release {
                    leases: values
                        .iter()
                        .map(|v| fixed_value::<16>(v, 1))
                        .collect::<Result<Vec<_>, _>>()?,
                }
            }
            other => return Err(MessageError::UnknownType(other)),
        };
        f.finish()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::identity::SoftwareKey;

    fn key() -> SoftwareKey {
        SoftwareKey::from_secret_bytes(&[0x55; 32]).unwrap()
    }

    #[test]
    fn every_type_round_trips() {
        let k = key();
        let sig = k.sign_raw(b"x");
        let all = vec![
            RelayMessage::Hello {
                version: 1,
                nonce: [1; 32],
                boot_id: [2; 16],
                mode: Mode::SelfHosted,
            },
            RelayMessage::Register {
                key: k.public_key(),
                proof: sig,
                hosted: None,
            },
            RelayMessage::Register {
                key: k.public_key(),
                proof: sig,
                hosted: Some((vec![9, 9], 50)),
            },
            RelayMessage::Enroll {
                key: k.public_key(),
                proof: sig,
                code: [3; 16],
            },
            RelayMessage::Registered { handle: [4; 32] },
            RelayMessage::AllowSet {
                sequence: 7,
                callers: vec![[5; 32], [6; 32]],
                invitations: vec![InvitationEntry {
                    tag_hash: [7; 32],
                    expires_at: 1_790_000_600,
                }],
            },
            RelayMessage::AllowSetOk { sequence: 7 },
            RelayMessage::Call {
                handle: [4; 32],
                key: k.public_key(),
                proof: sig,
                class: Class::Bulk,
            },
            RelayMessage::Join {
                handle: [4; 32],
                tag: [8; 32],
            },
            RelayMessage::Incoming {
                circuit: [9; 16],
                class: Class::Interactive,
                caller: Some([5; 32]),
            },
            RelayMessage::Incoming {
                circuit: [9; 16],
                class: Class::Interactive,
                caller: None,
            },
            RelayMessage::Accept {
                handle: [4; 32],
                circuit: [9; 16],
                proof: sig,
            },
            RelayMessage::Spliced,
            RelayMessage::Unreachable,
            RelayMessage::Promote {
                circuit: [9; 16],
                caller: [5; 32],
            },
            RelayMessage::Lease { block: vec![1, 2] },
            RelayMessage::LeaseStatus {
                entries: vec![LeaseStatusEntry {
                    lease: [1; 16],
                    class: Class::Bulk,
                    used: 10,
                    bytes: 65_536,
                    state: 1,
                }],
            },
            RelayMessage::Refused {
                reason: RefuseReason::Enrollment,
            },
            RelayMessage::Admit { token: vec![3] },
            RelayMessage::Successor {
                key: k.public_key(),
                new_proof: sig,
                current_proof: sig,
            },
            RelayMessage::Ping { data: [1; 8] },
            RelayMessage::Pong { data: [1; 8] },
            RelayMessage::Release {
                leases: vec![[1; 16]],
            },
        ];
        for m in all {
            let bytes = m.encode();
            assert_eq!(RelayMessage::decode(&bytes).unwrap(), m, "{}", m.name());
        }
    }

    #[test]
    fn field_rules_are_enforced() {
        let k = key();
        let sig = k.sign_raw(b"x");
        // DER proof.
        let der = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(2)),
            (1, Value::Bytes(k.public_key().as_bytes().to_vec())),
            (2, Value::Bytes(sig.to_der())),
        ]));
        assert!(RelayMessage::decode(&der).is_err());
        // Hosted keys alone.
        let half = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(2)),
            (1, Value::Bytes(k.public_key().as_bytes().to_vec())),
            (2, Value::Bytes(sig.as_bytes().to_vec())),
            (4, Value::Uint(50)),
        ]));
        assert!(RelayMessage::decode(&half).is_err());
        // Duplicate fingerprints.
        let dup = RelayMessage::AllowSet {
            sequence: 1,
            callers: vec![[5; 32], [5; 32]],
            invitations: vec![],
        };
        assert!(RelayMessage::decode(&dup.encode()).is_err());
        // Join INCOMING with a fingerprint.
        let bad = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(9)),
            (1, Value::Bytes(vec![0; 16])),
            (2, Value::Uint(1)),
            (3, Value::Uint(0)),
            (4, Value::Bytes(vec![0; 32])),
        ]));
        assert!(RelayMessage::decode(&bad).is_err());
        assert_eq!(
            RelayMessage::decode(&cbor::encode(&Value::Map(vec![(0, Value::Uint(22))]))),
            Err(MessageError::UnknownType(22))
        );
        assert_eq!(
            RelayMessage::decode(&vec![0u8; RELAY_MESSAGE_MAX + 1]),
            Err(MessageError::TooLarge)
        );
    }
}
