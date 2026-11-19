//! The relay protocol as an endpoint speaks it (design `phase34-design.md`
//! §B.2 to §B.12): relay messages, the proofs an endpoint signs, handles,
//! the enrollment link, invitation tags, relay endpoints and the
//! `mousse-keys` records.
//!
//! Everything here is pure: encoding, decoding and the bytes to sign.
//! Signing keys are [`SoftwareKey`]s held by the I/O layer.

use core::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::asn1;
use crate::base64url;
use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::{PublicKey, RawSignature, SoftwareKey, PUBLIC_KEY_LEN};
use crate::pairing::{InvitationId, Route, RouteHost, TicketSecret};
use crate::session_cert::spki_der;

/// Relay protocol version in `RELAY_HELLO`.
pub const RELAY_VERSION: u64 = 1;
/// Largest relay message before a splice (fixed).
pub const RELAY_MESSAGE_MAX: usize = 16_384;
/// Largest WebSocket message on a relay connection (fixed).
pub const WS_MESSAGE_MAX: usize = 65_536;
/// Most caller fingerprints in one allow-set (fixed).
pub const ALLOW_CALLERS_MAX: usize = 256;
/// Most invitations in one allow-set (fixed).
pub const ALLOW_INVITATIONS_MAX: usize = 8;
/// The WebSocket path (fixed).
pub const RELAY_PATH: &str = "/mousse-relay/1";
/// The WebSocket subprotocol (fixed).
pub const RELAY_SUBPROTOCOL: &str = "mousse-relay.1";
/// The outer TLS ALPN.
pub const RELAY_ALPN: &[u8] = b"http/1.1";
/// Exporter label of the outer TLS connection (32 bytes, empty context).
pub const RELAY_EXPORTER_LABEL: &str = "EXPORTER-mousse-relay-v1";

/// Domain of the registration proof.
pub const REGISTER_DOMAIN: &str = "mousse-relay-register-v1";
/// Domain of the successor proofs.
pub const SUCCESSOR_DOMAIN: &str = "mousse-relay-successor-v1";
/// Domain of the call proof.
pub const CALL_DOMAIN: &str = "mousse-relay-call-v1";
/// Domain of the accept-leg proof.
pub const ACCEPT_DOMAIN: &str = "mousse-relay-accept-v1";
/// Prefix of the handle hash.
pub const HANDLE_DOMAIN: &str = "mousse-relay-handle-v1";
/// HKDF info of an invitation tag.
pub const INVITE_TAG_INFO: &str = "mousse-relay-invite-v1";
/// Scheme of an enrollment link.
pub const ENROLL_SCHEME: &str = "mousse-relay";
/// Scheme of a relay destination and of the `relay` route hint.
pub const RELAY_SCHEME: &str = "relay";
/// Most endpoints one relay route lists.
pub const RELAY_ENDPOINTS_MAX: usize = 4;

/// SHA-256 of a relay's identity key (SEC1).
pub type RelayId = [u8; 32];
/// A registration on one relay: SHA-256 of the handle domain, the relay id
/// and the registration key. Means nothing on another relay.
pub type Handle = [u8; 32];
/// A circuit waiting for its accept leg, or spliced.
pub type CircuitId = [u8; 16];
/// SHA-256 of a caller key (SEC1).
pub type Fingerprint = [u8; 32];

/// The relay id of `key`.
pub fn relay_id(key: &PublicKey) -> RelayId {
    key.fingerprint()
}

/// The handle of `registration_key` on the relay `relay`.
pub fn handle(relay: &RelayId, registration_key: &PublicKey) -> Handle {
    let mut h = Sha256::new();
    h.update(HANDLE_DOMAIN.as_bytes());
    h.update(relay);
    h.update(registration_key.as_bytes());
    h.finalize().into()
}

/// Relay mode in `RELAY_HELLO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Phase 3: an operator's list of targets, no leases.
    SelfHosted,
    /// Phase 4: Plus admission tokens and leases.
    Hosted,
}

impl Mode {
    fn as_u64(self) -> u64 {
        match self {
            Mode::SelfHosted => 0,
            Mode::Hosted => 1,
        }
    }

    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Mode::SelfHosted),
            1 => Some(Mode::Hosted),
            _ => None,
        }
    }
}

/// Traffic class of a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Typing, control, small messages.
    Interactive,
    /// Copies and other bulk transfers.
    Bulk,
}

impl Class {
    /// The wire value.
    pub fn as_u64(self) -> u64 {
        match self {
            Class::Interactive => 0,
            Class::Bulk => 1,
        }
    }

    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Class::Interactive),
            1 => Some(Class::Bulk),
            _ => None,
        }
    }
}

/// What an `INCOMING` circuit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingKind {
    /// A listed caller.
    Call,
    /// A joiner holding an invitation tag.
    Join,
}

/// The WebSocket close codes a relay sends (§B.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseCode {
    /// The caller left the allow-set, or the target was revoked.
    Removed,
    /// The lease ran out with no refill.
    LeaseExhausted,
    /// Nothing either way for too long.
    Idle,
    /// The relay is stopping.
    RelayStopping,
    /// The admission token expired with no usable block.
    AdmissionExpired,
    /// A newer registration of the same handle replaced this one.
    Replaced,
    /// A relay limit.
    Limit,
}

impl CloseCode {
    /// Every code, in order.
    pub const ALL: [CloseCode; 7] = [
        CloseCode::Removed,
        CloseCode::LeaseExhausted,
        CloseCode::Idle,
        CloseCode::RelayStopping,
        CloseCode::AdmissionExpired,
        CloseCode::Replaced,
        CloseCode::Limit,
    ];

    /// The WebSocket close code.
    pub fn code(self) -> u16 {
        match self {
            CloseCode::Removed => 4000,
            CloseCode::LeaseExhausted => 4001,
            CloseCode::Idle => 4002,
            CloseCode::RelayStopping => 4003,
            CloseCode::AdmissionExpired => 4004,
            CloseCode::Replaced => 4005,
            CloseCode::Limit => 4006,
        }
    }

    /// The code for a WebSocket close code, if it is one of ours.
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }

    /// The stable name.
    pub fn name(self) -> &'static str {
        match self {
            CloseCode::Removed => "removed",
            CloseCode::LeaseExhausted => "lease_exhausted",
            CloseCode::Idle => "idle",
            CloseCode::RelayStopping => "relay_stopping",
            CloseCode::AdmissionExpired => "admission_expired",
            CloseCode::Replaced => "replaced",
            CloseCode::Limit => "limit",
        }
    }

    /// One line for the app.
    pub fn reason(self) -> &'static str {
        match self {
            CloseCode::Removed => "The relay removed this connection",
            CloseCode::LeaseExhausted => "The relay allowance ran out",
            CloseCode::Idle => "The relay closed an idle connection",
            CloseCode::RelayStopping => "The relay is restarting",
            CloseCode::AdmissionExpired => "The relay admission expired",
            CloseCode::Replaced => "A newer registration replaced this one",
            CloseCode::Limit => "The relay is at a limit",
        }
    }
}

/// A signed envelope (§A.12): `{1: record bytes, 2: raw signature}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The canonical CBOR of the record.
    pub record: Vec<u8>,
    /// Raw P-256 signature over `record`.
    pub signature: RawSignature,
}

impl Envelope {
    /// The CBOR value.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (1, Value::Bytes(self.record.clone())),
            (2, Value::Bytes(self.signature.as_bytes().to_vec())),
        ])
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// From a decoded value. DER signatures are refused.
    pub fn from_value(value: Value) -> Result<Self, FieldError> {
        let mut f = Fields::from_value(value)?;
        let record = f.bytes(1)?;
        let signature =
            RawSignature::from_slice(&f.bytes(2)?).map_err(|_| FieldError::Invalid(2))?;
        f.finish()?;
        Ok(Self { record, signature })
    }

    /// Decode canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, FieldError> {
        Self::from_value(cbor::decode(bytes)?)
    }

    /// Whether `key` signed the record.
    pub fn verify(&self, key: &PublicKey) -> bool {
        key.verify(&self.record, &self.signature).is_ok()
    }
}

/// One invitation in an allow-set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedInvitation {
    /// SHA-256 of the invitation tag.
    pub tag_hash: [u8; 32],
    /// When the entry ends (Unix seconds).
    pub expires_at: u64,
}

/// One lease in `LEASE_STATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseState {
    /// The lease id.
    pub lease: [u8; 16],
    /// Its class.
    pub class: Class,
    /// Bytes forwarded against it.
    pub used: u64,
    /// Bytes it allows.
    pub bytes: u64,
    /// 0 pending, 1 current, 2 final, 3 refused.
    pub state: u64,
}

/// One relay message (§B.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayMessage {
    /// 1, relay → client, first.
    Hello {
        version: u64,
        nonce: [u8; 32],
        boot_id: [u8; 16],
        mode: Mode,
    },
    /// 2, target → relay.
    Register {
        key: PublicKey,
        proof: RawSignature,
        /// Hosted only.
        admission: Option<Envelope>,
        /// Hosted only, 10 to 90.
        threshold: Option<u64>,
    },
    /// 3, target → relay (self mode).
    Enroll {
        key: PublicKey,
        proof: RawSignature,
        code: [u8; 16],
    },
    /// 4, relay → target.
    Registered { handle: Handle },
    /// 5, target → relay.
    AllowSet {
        sequence: u64,
        callers: Vec<Fingerprint>,
        invitations: Vec<AllowedInvitation>,
    },
    /// 6, relay → target.
    AllowSetOk { sequence: u64 },
    /// 7, caller → relay.
    Call {
        handle: Handle,
        key: PublicKey,
        proof: RawSignature,
        class: Class,
    },
    /// 8, joiner → relay.
    Join { handle: Handle, tag: [u8; 32] },
    /// 9, relay → target.
    Incoming {
        circuit: CircuitId,
        kind: IncomingKind,
        class: Class,
        /// Calls only.
        caller: Option<Fingerprint>,
    },
    /// 10, target → relay, on a new connection.
    Accept {
        handle: Handle,
        circuit: CircuitId,
        proof: RawSignature,
    },
    /// 11, relay → both legs; then peer bytes.
    Spliced,
    /// 12, relay → caller or joiner; then close.
    Unreachable,
    /// 13, target → relay.
    Promote {
        circuit: CircuitId,
        caller: Fingerprint,
    },
    /// 14, target → relay (hosted).
    Lease { block: Envelope },
    /// 15, relay → target (hosted).
    LeaseStatus { leases: Vec<LeaseState> },
    /// 16, relay → target; then close.
    Refused { reason: String },
    /// 17, target → relay (hosted).
    Admit { token: Envelope },
    /// 18, target → relay (self).
    Successor {
        key: PublicKey,
        proof_new: RawSignature,
        proof_current: RawSignature,
    },
    /// 19.
    Ping([u8; 8]),
    /// 20.
    Pong([u8; 8]),
    /// 21, target → relay (hosted).
    Release { leases: Vec<[u8; 16]> },
}

/// Why a relay message was refused. Any of these closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayWireError {
    /// Over [`RELAY_MESSAGE_MAX`].
    TooLarge,
    /// Not canonical CBOR, missing or extra keys, wrong types or values.
    Field(FieldError),
    /// An unknown message type.
    UnknownType(u64),
}

impl fmt::Display for RelayWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayWireError::TooLarge => f.write_str("relay message too large"),
            RelayWireError::Field(e) => write!(f, "relay message: {e}"),
            RelayWireError::UnknownType(t) => write!(f, "unknown relay message type {t}"),
        }
    }
}

impl std::error::Error for RelayWireError {}

impl From<FieldError> for RelayWireError {
    fn from(e: FieldError) -> Self {
        RelayWireError::Field(e)
    }
}

impl From<cbor::CborError> for RelayWireError {
    fn from(e: cbor::CborError) -> Self {
        RelayWireError::Field(FieldError::Cbor(e))
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn key_field(f: &mut Fields, k: u64) -> Result<PublicKey, FieldError> {
    let b = f.fixed::<PUBLIC_KEY_LEN>(k)?;
    PublicKey::from_sec1(&b).map_err(|_| FieldError::Invalid(k))
}

fn sig_field(f: &mut Fields, k: u64) -> Result<RawSignature, FieldError> {
    RawSignature::from_slice(&f.bytes(k)?).map_err(|_| FieldError::Invalid(k))
}

fn fixed_value<const N: usize>(v: Value, k: u64) -> Result<[u8; N], FieldError> {
    match v {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).map_err(|_| FieldError::Invalid(k)),
        _ => Err(FieldError::WrongType(k)),
    }
}

fn class_field(f: &mut Fields, k: u64) -> Result<Class, FieldError> {
    Class::from_u64(f.uint(k)?).ok_or(FieldError::Invalid(k))
}

impl RelayMessage {
    /// The message type.
    pub fn kind(&self) -> u64 {
        match self {
            RelayMessage::Hello { .. } => 1,
            RelayMessage::Register { .. } => 2,
            RelayMessage::Enroll { .. } => 3,
            RelayMessage::Registered { .. } => 4,
            RelayMessage::AllowSet { .. } => 5,
            RelayMessage::AllowSetOk { .. } => 6,
            RelayMessage::Call { .. } => 7,
            RelayMessage::Join { .. } => 8,
            RelayMessage::Incoming { .. } => 9,
            RelayMessage::Accept { .. } => 10,
            RelayMessage::Spliced => 11,
            RelayMessage::Unreachable => 12,
            RelayMessage::Promote { .. } => 13,
            RelayMessage::Lease { .. } => 14,
            RelayMessage::LeaseStatus { .. } => 15,
            RelayMessage::Refused { .. } => 16,
            RelayMessage::Admit { .. } => 17,
            RelayMessage::Successor { .. } => 18,
            RelayMessage::Ping(_) => 19,
            RelayMessage::Pong(_) => 20,
            RelayMessage::Release { .. } => 21,
        }
    }

    /// Canonical CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut m: Vec<(u64, Value)> = vec![(0, Value::Uint(self.kind()))];
        match self {
            RelayMessage::Hello {
                version,
                nonce,
                boot_id,
                mode,
            } => {
                m.push((1, Value::Uint(*version)));
                m.push((2, bytes(nonce)));
                m.push((3, bytes(boot_id)));
                m.push((4, Value::Uint(mode.as_u64())));
            }
            RelayMessage::Register {
                key,
                proof,
                admission,
                threshold,
            } => {
                m.push((1, bytes(key.as_bytes())));
                m.push((2, bytes(proof.as_bytes())));
                if let Some(a) = admission {
                    m.push((3, a.to_value()));
                }
                if let Some(t) = threshold {
                    m.push((4, Value::Uint(*t)));
                }
            }
            RelayMessage::Enroll { key, proof, code } => {
                m.push((1, bytes(key.as_bytes())));
                m.push((2, bytes(proof.as_bytes())));
                m.push((3, bytes(code)));
            }
            RelayMessage::Registered { handle } => m.push((1, bytes(handle))),
            RelayMessage::AllowSet {
                sequence,
                callers,
                invitations,
            } => {
                m.push((1, Value::Uint(*sequence)));
                m.push((2, Value::Array(callers.iter().map(|c| bytes(c)).collect())));
                m.push((
                    3,
                    Value::Array(
                        invitations
                            .iter()
                            .map(|i| {
                                Value::Map(vec![
                                    (1, bytes(&i.tag_hash)),
                                    (2, Value::Uint(i.expires_at)),
                                ])
                            })
                            .collect(),
                    ),
                ));
            }
            RelayMessage::AllowSetOk { sequence } => m.push((1, Value::Uint(*sequence))),
            RelayMessage::Call {
                handle,
                key,
                proof,
                class,
            } => {
                m.push((1, bytes(handle)));
                m.push((2, bytes(key.as_bytes())));
                m.push((3, bytes(proof.as_bytes())));
                m.push((4, Value::Uint(class.as_u64())));
            }
            RelayMessage::Join { handle, tag } => {
                m.push((1, bytes(handle)));
                m.push((2, bytes(tag)));
            }
            RelayMessage::Incoming {
                circuit,
                kind,
                class,
                caller,
            } => {
                m.push((1, bytes(circuit)));
                m.push((
                    2,
                    Value::Uint(match kind {
                        IncomingKind::Call => 0,
                        IncomingKind::Join => 1,
                    }),
                ));
                m.push((3, Value::Uint(class.as_u64())));
                if let Some(c) = caller {
                    m.push((4, bytes(c)));
                }
            }
            RelayMessage::Accept {
                handle,
                circuit,
                proof,
            } => {
                m.push((1, bytes(handle)));
                m.push((2, bytes(circuit)));
                m.push((3, bytes(proof.as_bytes())));
            }
            RelayMessage::Spliced | RelayMessage::Unreachable => {}
            RelayMessage::Promote { circuit, caller } => {
                m.push((1, bytes(circuit)));
                m.push((2, bytes(caller)));
            }
            RelayMessage::Lease { block } => m.push((1, block.to_value())),
            RelayMessage::LeaseStatus { leases } => m.push((
                1,
                Value::Array(
                    leases
                        .iter()
                        .map(|l| {
                            Value::Map(vec![
                                (1, bytes(&l.lease)),
                                (2, Value::Uint(l.class.as_u64())),
                                (3, Value::Uint(l.used)),
                                (4, Value::Uint(l.bytes)),
                                (5, Value::Uint(l.state)),
                            ])
                        })
                        .collect(),
                ),
            )),
            RelayMessage::Refused { reason } => m.push((1, Value::Text(reason.clone()))),
            RelayMessage::Admit { token } => m.push((1, token.to_value())),
            RelayMessage::Successor {
                key,
                proof_new,
                proof_current,
            } => {
                m.push((1, bytes(key.as_bytes())));
                m.push((2, bytes(proof_new.as_bytes())));
                m.push((3, bytes(proof_current.as_bytes())));
            }
            RelayMessage::Ping(b) | RelayMessage::Pong(b) => m.push((1, bytes(b))),
            RelayMessage::Release { leases } => {
                m.push((1, Value::Array(leases.iter().map(|l| bytes(l)).collect())))
            }
        }
        cbor::encode(&Value::Map(m))
    }

    /// Decode one message strictly: canonical CBOR, a known type, exactly
    /// its keys.
    pub fn decode(input: &[u8]) -> Result<Self, RelayWireError> {
        if input.len() > RELAY_MESSAGE_MAX {
            return Err(RelayWireError::TooLarge);
        }
        let mut f = Fields::decode(input)?;
        let kind = f.uint(0)?;
        let msg = match kind {
            1 => {
                let version = f.uint(1)?;
                let nonce = f.fixed::<32>(2)?;
                let boot_id = f.fixed::<16>(3)?;
                let mode = Mode::from_u64(f.uint(4)?).ok_or(FieldError::Invalid(4))?;
                RelayMessage::Hello {
                    version,
                    nonce,
                    boot_id,
                    mode,
                }
            }
            2 => {
                let key = key_field(&mut f, 1)?;
                let proof = sig_field(&mut f, 2)?;
                let admission = f.optional(3).map(Envelope::from_value).transpose()?;
                let threshold = match f.optional(4) {
                    None => None,
                    Some(Value::Uint(t)) if (10..=90).contains(&t) => Some(t),
                    Some(Value::Uint(_)) => return Err(FieldError::Invalid(4).into()),
                    Some(_) => return Err(FieldError::WrongType(4).into()),
                };
                RelayMessage::Register {
                    key,
                    proof,
                    admission,
                    threshold,
                }
            }
            3 => RelayMessage::Enroll {
                key: key_field(&mut f, 1)?,
                proof: sig_field(&mut f, 2)?,
                code: f.fixed::<16>(3)?,
            },
            4 => RelayMessage::Registered {
                handle: f.fixed::<32>(1)?,
            },
            5 => {
                let sequence = f.uint(1)?;
                let list = f.array(2)?;
                if list.len() > ALLOW_CALLERS_MAX {
                    return Err(FieldError::Invalid(2).into());
                }
                let callers = list
                    .into_iter()
                    .map(|v| fixed_value::<32>(v, 2))
                    .collect::<Result<Vec<_>, _>>()?;
                let list = f.array(3)?;
                if list.len() > ALLOW_INVITATIONS_MAX {
                    return Err(FieldError::Invalid(3).into());
                }
                let mut invitations = Vec::with_capacity(list.len());
                for v in list {
                    let mut i = Fields::from_value(v).map_err(|_| FieldError::Invalid(3))?;
                    let tag_hash = i.fixed::<32>(1).map_err(|_| FieldError::Invalid(3))?;
                    let expires_at = i.uint(2).map_err(|_| FieldError::Invalid(3))?;
                    i.finish().map_err(|_| FieldError::Invalid(3))?;
                    invitations.push(AllowedInvitation {
                        tag_hash,
                        expires_at,
                    });
                }
                RelayMessage::AllowSet {
                    sequence,
                    callers,
                    invitations,
                }
            }
            6 => RelayMessage::AllowSetOk {
                sequence: f.uint(1)?,
            },
            7 => RelayMessage::Call {
                handle: f.fixed::<32>(1)?,
                key: key_field(&mut f, 2)?,
                proof: sig_field(&mut f, 3)?,
                class: class_field(&mut f, 4)?,
            },
            8 => RelayMessage::Join {
                handle: f.fixed::<32>(1)?,
                tag: f.fixed::<32>(2)?,
            },
            9 => {
                let circuit = f.fixed::<16>(1)?;
                let kind = match f.uint(2)? {
                    0 => IncomingKind::Call,
                    1 => IncomingKind::Join,
                    _ => return Err(FieldError::Invalid(2).into()),
                };
                let class = class_field(&mut f, 3)?;
                let caller = match (kind, f.optional(4)) {
                    (IncomingKind::Call, Some(v)) => Some(fixed_value::<32>(v, 4)?),
                    (IncomingKind::Call, None) => return Err(FieldError::Missing(4).into()),
                    (IncomingKind::Join, Some(_)) => return Err(FieldError::Unknown(4).into()),
                    (IncomingKind::Join, None) => None,
                };
                RelayMessage::Incoming {
                    circuit,
                    kind,
                    class,
                    caller,
                }
            }
            10 => RelayMessage::Accept {
                handle: f.fixed::<32>(1)?,
                circuit: f.fixed::<16>(2)?,
                proof: sig_field(&mut f, 3)?,
            },
            11 => RelayMessage::Spliced,
            12 => RelayMessage::Unreachable,
            13 => RelayMessage::Promote {
                circuit: f.fixed::<16>(1)?,
                caller: f.fixed::<32>(2)?,
            },
            14 => RelayMessage::Lease {
                block: Envelope::from_value(f.required(1)?)?,
            },
            15 => {
                let mut leases = Vec::new();
                for v in f.array(1)? {
                    let mut l = Fields::from_value(v).map_err(|_| FieldError::Invalid(1))?;
                    let state = LeaseState {
                        lease: l.fixed::<16>(1).map_err(|_| FieldError::Invalid(1))?,
                        class: class_field(&mut l, 2).map_err(|_| FieldError::Invalid(1))?,
                        used: l.uint(3).map_err(|_| FieldError::Invalid(1))?,
                        bytes: l.uint(4).map_err(|_| FieldError::Invalid(1))?,
                        state: l.uint(5).map_err(|_| FieldError::Invalid(1))?,
                    };
                    l.finish().map_err(|_| FieldError::Invalid(1))?;
                    if state.state > 3 {
                        return Err(FieldError::Invalid(1).into());
                    }
                    leases.push(state);
                }
                RelayMessage::LeaseStatus { leases }
            }
            16 => RelayMessage::Refused { reason: f.text(1)? },
            17 => RelayMessage::Admit {
                token: Envelope::from_value(f.required(1)?)?,
            },
            18 => RelayMessage::Successor {
                key: key_field(&mut f, 1)?,
                proof_new: sig_field(&mut f, 2)?,
                proof_current: sig_field(&mut f, 3)?,
            },
            19 => RelayMessage::Ping(f.fixed::<8>(1)?),
            20 => RelayMessage::Pong(f.fixed::<8>(1)?),
            21 => {
                let list = f.array(1)?;
                if list.len() > 4 {
                    return Err(FieldError::Invalid(1).into());
                }
                RelayMessage::Release {
                    leases: list
                        .into_iter()
                        .map(|v| fixed_value::<16>(v, 1))
                        .collect::<Result<Vec<_>, _>>()?,
                }
            }
            other => return Err(RelayWireError::UnknownType(other)),
        };
        f.finish()?;
        Ok(msg)
    }
}

/// What one connection's proofs are bound to: the relay, its fresh nonce
/// and the outer exporter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The pinned relay id.
    pub relay: RelayId,
    /// The relay's nonce from this connection's `RELAY_HELLO`.
    pub nonce: [u8; 32],
    /// This connection's `EXPORTER-mousse-relay-v1`.
    pub exporter: [u8; 32],
}

fn register_shape(domain: &str, b: &Binding, handle: &Handle) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, Value::Text(domain.to_owned())),
        (2, bytes(&b.relay)),
        (3, bytes(handle)),
        (4, bytes(&b.nonce)),
        (5, bytes(&b.exporter)),
    ]))
}

/// The registration proof record (also signed for `ENROLL`).
pub fn register_record(b: &Binding, handle: &Handle) -> Vec<u8> {
    register_shape(REGISTER_DOMAIN, b, handle)
}

/// The successor record. Both the new key and the current key sign it; the
/// handle is the new key's.
pub fn successor_record(b: &Binding, new_handle: &Handle) -> Vec<u8> {
    register_shape(SUCCESSOR_DOMAIN, b, new_handle)
}

/// The call proof record.
pub fn call_record(b: &Binding, handle: &Handle, class: Class) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, Value::Text(CALL_DOMAIN.to_owned())),
        (2, bytes(&b.relay)),
        (3, bytes(handle)),
        (4, bytes(&b.nonce)),
        (5, bytes(&b.exporter)),
        (6, Value::Uint(class.as_u64())),
    ]))
}

/// The accept-leg proof record.
pub fn accept_record(b: &Binding, handle: &Handle, circuit: &CircuitId) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (1, Value::Text(ACCEPT_DOMAIN.to_owned())),
        (2, bytes(&b.relay)),
        (3, bytes(handle)),
        (4, bytes(circuit)),
        (5, bytes(&b.nonce)),
        (6, bytes(&b.exporter)),
    ]))
}

/// `REGISTER` for a self-hosted relay, signed by `key`.
pub fn register(b: &Binding, key: &SoftwareKey) -> RelayMessage {
    let public = key.public_key();
    let h = handle(&b.relay, &public);
    RelayMessage::Register {
        key: public,
        proof: key.sign_raw(&register_record(b, &h)),
        admission: None,
        threshold: None,
    }
}

/// `ENROLL` with a code from an enrollment link, signed by `key`.
pub fn enroll(b: &Binding, key: &SoftwareKey, code: [u8; 16]) -> RelayMessage {
    let public = key.public_key();
    let h = handle(&b.relay, &public);
    RelayMessage::Enroll {
        key: public,
        proof: key.sign_raw(&register_record(b, &h)),
        code,
    }
}

/// `SUCCESSOR`: `new` vouched for by the registered `current` key.
pub fn successor(b: &Binding, current: &SoftwareKey, new: &SoftwareKey) -> RelayMessage {
    let public = new.public_key();
    let record = successor_record(b, &handle(&b.relay, &public));
    RelayMessage::Successor {
        key: public,
        proof_new: new.sign_raw(&record),
        proof_current: current.sign_raw(&record),
    }
}

/// `CALL` to `handle` with the caller key `key`.
pub fn call(b: &Binding, handle: &Handle, key: &SoftwareKey, class: Class) -> RelayMessage {
    RelayMessage::Call {
        handle: *handle,
        key: key.public_key(),
        proof: key.sign_raw(&call_record(b, handle, class)),
        class,
    }
}

/// `ACCEPT` for `circuit`, signed by the registration key.
pub fn accept(b: &Binding, registration: &SoftwareKey, circuit: &CircuitId) -> RelayMessage {
    let h = handle(&b.relay, &registration.public_key());
    RelayMessage::Accept {
        handle: h,
        circuit: *circuit,
        proof: registration.sign_raw(&accept_record(b, &h, circuit)),
    }
}

/// The invitation tag a ticket holder presents in `JOIN` (§B.7).
pub fn invitation_tag(invitation: &InvitationId, secret: &TicketSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&invitation.0), secret.expose());
    let mut out = [0u8; 32];
    hk.expand(INVITE_TAG_INFO.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// What the allow-set lists for a tag.
pub fn tag_hash(tag: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(tag).into()
}

/// Where a relay listens: `host:port`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayEndpoint {
    /// IP literal or lower-case DNS name.
    pub host: EndpointHost,
    /// TCP port.
    pub port: u16,
}

/// The host of a [`RelayEndpoint`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EndpointHost {
    /// IPv4.
    Ipv4(core::net::Ipv4Addr),
    /// IPv6, written in brackets.
    Ipv6(core::net::Ipv6Addr),
    /// Lower-case DNS name.
    Dns(String),
}

impl RelayEndpoint {
    /// Parse `host:port` with the `tcp` hint rules (wire.md 10.2.1). Host
    /// names are lower-cased.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > 255 {
            return None;
        }
        match Route::parse(&format!("tcp://{text}")) {
            Ok(Route::Tcp { host, port }) => Some(Self {
                host: match host {
                    RouteHost::Ipv4(ip) => EndpointHost::Ipv4(ip),
                    RouteHost::Ipv6(ip) => EndpointHost::Ipv6(ip),
                    RouteHost::Dns(name) => EndpointHost::Dns(name),
                },
                port,
            }),
            _ => None,
        }
    }

    /// The host as dialled (no brackets).
    pub fn host_text(&self) -> String {
        match &self.host {
            EndpointHost::Ipv4(ip) => ip.to_string(),
            EndpointHost::Ipv6(ip) => ip.to_string(),
            EndpointHost::Dns(name) => name.clone(),
        }
    }

    /// The approved destination: `relay://<lower-case host>:<port>`.
    pub fn destination(&self) -> String {
        format!("{RELAY_SCHEME}://{self}")
    }

    /// Parse a destination written by [`RelayEndpoint::destination`].
    pub fn from_destination(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("relay://")?;
        let ep = Self::parse(rest)?;
        (ep.destination() == text).then_some(ep)
    }
}

impl fmt::Display for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            EndpointHost::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            EndpointHost::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
            EndpointHost::Dns(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

/// An enrollment link: `mousse-relay://<host:port>/#<relay id>.<code>`,
/// both parts base64url without padding (§B.9).
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentLink {
    /// Where the relay listens.
    pub endpoint: RelayEndpoint,
    /// The relay id to pin.
    pub relay: RelayId,
    /// The single-use code.
    pub code: [u8; 16],
}

impl fmt::Debug for EnrollmentLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code is a secret until it is used.
        write!(f, "EnrollmentLink({}, ..)", self.endpoint)
    }
}

impl EnrollmentLink {
    /// Parse a pasted link. Surrounding white space is ignored.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let rest = text.strip_prefix("mousse-relay://")?;
        let (authority, fragment) = rest.split_once("/#")?;
        let endpoint = RelayEndpoint::parse(authority)?;
        let (id, code) = fragment.split_once('.')?;
        let relay = <[u8; 32]>::try_from(base64url::decode(id).ok()?.as_slice()).ok()?;
        let code = <[u8; 16]>::try_from(base64url::decode(code).ok()?.as_slice()).ok()?;
        Some(Self {
            endpoint,
            relay,
            code,
        })
    }

    /// The link text.
    pub fn to_text(&self) -> String {
        format!(
            "{ENROLL_SCHEME}://{}/#{}.{}",
            self.endpoint,
            base64url::encode(&self.relay),
            base64url::encode(&self.code)
        )
    }
}

/// A relay route: a relay to dial, pinned to its id, and the target's
/// handle on it. The `relay` hint form (§B.11) is
/// `relay://<host>:<port>/<relay id>/<handle>`, base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayRoute {
    /// Where the relay listens.
    pub endpoint: RelayEndpoint,
    /// The relay id to pin.
    pub relay: RelayId,
    /// The target's handle there.
    pub handle: Handle,
}

impl RelayRoute {
    /// The hint text.
    pub fn to_hint(&self) -> String {
        format!(
            "{RELAY_SCHEME}://{}/{}/{}",
            self.endpoint,
            base64url::encode(&self.relay),
            base64url::encode(&self.handle)
        )
    }

    /// Parse the hint text.
    pub fn parse_hint(text: &str) -> Option<Self> {
        if text.len() > 255 {
            return None;
        }
        let rest = text.strip_prefix("relay://")?;
        let mut parts = rest.split('/');
        let endpoint = RelayEndpoint::parse(parts.next()?)?;
        let relay = <[u8; 32]>::try_from(base64url::decode(parts.next()?).ok()?.as_slice()).ok()?;
        let handle =
            <[u8; 32]>::try_from(base64url::decode(parts.next()?).ok()?.as_slice()).ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            endpoint,
            relay,
            handle,
        })
    }
}

/// `mousse-keys`, caller → host: `{1: caller relay public key}`.
pub fn encode_keys_request(caller_key: &PublicKey) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(1, bytes(caller_key.as_bytes()))]))
}

/// Read a `mousse-keys` request.
pub fn decode_keys_request(input: &[u8]) -> Result<PublicKey, FieldError> {
    let mut f = Fields::decode(input)?;
    let key = key_field(&mut f, 1)?;
    f.finish()?;
    Ok(key)
}

/// `mousse-keys`, host → caller: `{1: pair secret}`.
pub fn encode_keys_answer(pair_secret: &[u8; 32]) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(1, bytes(pair_secret))]))
}

/// Read a `mousse-keys` answer.
pub fn decode_keys_answer(input: &[u8]) -> Result<[u8; 32], FieldError> {
    let mut f = Fields::decode(input)?;
    let secret = f.fixed::<32>(1)?;
    f.finish()?;
    Ok(secret)
}

const ECDSA_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// A self-signed certificate on a relay's identity key: what a relay
/// presents in its outer TLS. Clients ignore everything in it but the key.
pub fn relay_certificate(key: &SoftwareKey) -> Vec<u8> {
    let spki = spki_der(&key.public_key());
    let alg = asn1::tlv(asn1::SEQUENCE, &ECDSA_SHA256);
    let cn = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::OID, &[0x55, 0x04, 0x03]),
            &asn1::tlv(asn1::UTF8_STRING, b"mousse-relay"),
        ],
    );
    let name = asn1::tlv(asn1::SEQUENCE, &asn1::tlv(asn1::SET, &cn));
    let validity = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::UTC_TIME, b"000101000000Z"),
            &asn1::tlv(asn1::GENERALIZED_TIME, b"99991231235959Z"),
        ],
    );
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&Sha256::digest(&spki)[..16]);
    serial[0] = (serial[0] & 0x3f) | 0x40;
    let tbs = asn1::wrap(
        asn1::SEQUENCE,
        &[
            &asn1::tlv(asn1::CONTEXT_0, &asn1::tlv(asn1::INTEGER, &[2])),
            &asn1::tlv(asn1::INTEGER, &serial),
            &alg,
            &name,
            &validity,
            &name,
            &spki,
        ],
    );
    let sig = key.sign_raw(&tbs).to_der();
    let mut bit = Vec::with_capacity(sig.len() + 1);
    bit.push(0);
    bit.extend_from_slice(&sig);
    asn1::wrap(
        asn1::SEQUENCE,
        &[&tbs, &alg, &asn1::tlv(asn1::BIT_STRING, &bit)],
    )
}

/// The P-256 key in an X.509 certificate's subject public key info. The
/// client pins its hash and checks the TLS signature with it; nothing else
/// in the certificate counts.
pub fn certificate_key(der: &[u8]) -> Option<PublicKey> {
    let cert = asn1::single(der, asn1::SEQUENCE).ok()?;
    let mut outer = asn1::Reader::new(cert);
    let tbs = outer.read(asn1::SEQUENCE).ok()?;
    let mut r = asn1::Reader::new(tbs);
    let (tag, _, _) = r.read_any().ok()?;
    if tag == asn1::CONTEXT_0 {
        r.read(asn1::INTEGER).ok()?;
    } else if tag != asn1::INTEGER {
        return None;
    }
    r.read(asn1::SEQUENCE).ok()?; // signature algorithm
    r.read(asn1::SEQUENCE).ok()?; // issuer
    r.read(asn1::SEQUENCE).ok()?; // validity
    r.read(asn1::SEQUENCE).ok()?; // subject
    let spki = r.read_raw(asn1::SEQUENCE).ok()?;
    if spki.len() != 91 {
        return None;
    }
    let key = PublicKey::from_sec1(&spki[26..]).ok()?;
    (spki_der(&key) == spki).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn key(seed: u8) -> SoftwareKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn binding() -> Binding {
        Binding {
            relay: relay_id(&key(9).public_key()),
            nonce: [1; 32],
            exporter: [2; 32],
        }
    }

    fn sample_messages() -> Vec<RelayMessage> {
        let b = binding();
        let k = key(1);
        let env = Envelope {
            record: vec![0xa0],
            signature: k.sign_raw(b"x"),
        };
        vec![
            RelayMessage::Hello {
                version: 1,
                nonce: [3; 32],
                boot_id: [4; 16],
                mode: Mode::SelfHosted,
            },
            register(&b, &k),
            RelayMessage::Register {
                key: k.public_key(),
                proof: k.sign_raw(b"y"),
                admission: Some(env.clone()),
                threshold: Some(50),
            },
            enroll(&b, &k, [5; 16]),
            RelayMessage::Registered { handle: [6; 32] },
            RelayMessage::AllowSet {
                sequence: 7,
                callers: vec![[8; 32], [9; 32]],
                invitations: vec![AllowedInvitation {
                    tag_hash: [10; 32],
                    expires_at: 11,
                }],
            },
            RelayMessage::AllowSetOk { sequence: 7 },
            call(&b, &[12; 32], &k, Class::Bulk),
            RelayMessage::Join {
                handle: [13; 32],
                tag: [14; 32],
            },
            RelayMessage::Incoming {
                circuit: [15; 16],
                kind: IncomingKind::Call,
                class: Class::Interactive,
                caller: Some([16; 32]),
            },
            RelayMessage::Incoming {
                circuit: [15; 16],
                kind: IncomingKind::Join,
                class: Class::Interactive,
                caller: None,
            },
            accept(&b, &k, &[17; 16]),
            RelayMessage::Spliced,
            RelayMessage::Unreachable,
            RelayMessage::Promote {
                circuit: [18; 16],
                caller: [19; 32],
            },
            RelayMessage::Lease { block: env.clone() },
            RelayMessage::LeaseStatus {
                leases: vec![LeaseState {
                    lease: [20; 16],
                    class: Class::Bulk,
                    used: 1,
                    bytes: 2,
                    state: 3,
                }],
            },
            RelayMessage::Refused {
                reason: "not_authorized".into(),
            },
            RelayMessage::Admit { token: env },
            successor(&b, &k, &key(2)),
            RelayMessage::Ping([21; 8]),
            RelayMessage::Pong([22; 8]),
            RelayMessage::Release {
                leases: vec![[23; 16]],
            },
        ]
    }

    #[test]
    fn every_message_round_trips() {
        let messages = sample_messages();
        let kinds: Vec<u64> = messages.iter().map(RelayMessage::kind).collect();
        for kind in 1..=21 {
            assert!(kinds.contains(&kind), "type {kind} is not covered");
        }
        for m in messages {
            assert_eq!(RelayMessage::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn extra_missing_and_unknown_are_refused() {
        let extra = cbor::encode(&Value::Map(vec![(0, Value::Uint(11)), (1, Value::Uint(0))]));
        assert_eq!(
            RelayMessage::decode(&extra),
            Err(RelayWireError::Field(FieldError::Unknown(1)))
        );
        let missing = cbor::encode(&Value::Map(vec![(0, Value::Uint(4))]));
        assert_eq!(
            RelayMessage::decode(&missing),
            Err(RelayWireError::Field(FieldError::Missing(1)))
        );
        let unknown = cbor::encode(&Value::Map(vec![(0, Value::Uint(99))]));
        assert_eq!(
            RelayMessage::decode(&unknown),
            Err(RelayWireError::UnknownType(99))
        );
        assert_eq!(
            RelayMessage::decode(&vec![0; RELAY_MESSAGE_MAX + 1]),
            Err(RelayWireError::TooLarge)
        );
        // A join INCOMING never names a caller; a call always does.
        let join_with_caller = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(9)),
            (1, bytes(&[0; 16])),
            (2, Value::Uint(1)),
            (3, Value::Uint(0)),
            (4, bytes(&[0; 32])),
        ]));
        assert!(RelayMessage::decode(&join_with_caller).is_err());
    }

    #[test]
    fn der_proofs_and_oversized_allow_sets_are_refused() {
        let b = binding();
        let k = key(1);
        let der = k.sign_raw(b"x").to_der();
        let msg = cbor::encode(&Value::Map(vec![
            (0, Value::Uint(7)),
            (1, bytes(&[0; 32])),
            (2, bytes(k.public_key().as_bytes())),
            (3, bytes(&der)),
            (4, Value::Uint(0)),
        ]));
        assert!(RelayMessage::decode(&msg).is_err());
        let _ = b;
        let too_many = RelayMessage::AllowSet {
            sequence: 1,
            callers: vec![[0; 32]; ALLOW_CALLERS_MAX + 1],
            invitations: vec![],
        };
        assert!(RelayMessage::decode(&too_many.encode()).is_err());
    }

    #[test]
    fn proofs_bind_relay_nonce_exporter_handle_and_purpose() {
        let b = binding();
        let k = key(1);
        let RelayMessage::Register { key, proof, .. } = register(&b, &k) else {
            unreachable!()
        };
        let h = handle(&b.relay, &key);
        key.verify(&register_record(&b, &h), &proof).unwrap();
        let mut other = b;
        other.nonce = [9; 32];
        assert!(key.verify(&register_record(&other, &h), &proof).is_err());
        let mut other = b;
        other.exporter = [9; 32];
        assert!(key.verify(&register_record(&other, &h), &proof).is_err());
        let mut other = b;
        other.relay = [9; 32];
        assert!(key.verify(&register_record(&other, &h), &proof).is_err());
        // Another purpose with the same fields does not verify.
        assert!(key.verify(&successor_record(&b, &h), &proof).is_err());
        // The call proof covers its class.
        let RelayMessage::Call { proof, .. } = call(&b, &h, &k, Class::Interactive) else {
            unreachable!()
        };
        assert!(key
            .verify(&call_record(&b, &h, Class::Bulk), &proof)
            .is_err());
        key.verify(&call_record(&b, &h, Class::Interactive), &proof)
            .unwrap();
    }

    #[test]
    fn handles_differ_per_relay_and_key() {
        let a = key(1).public_key();
        let c = key(2).public_key();
        assert_ne!(handle(&[1; 32], &a), handle(&[2; 32], &a));
        assert_ne!(handle(&[1; 32], &a), handle(&[1; 32], &c));
    }

    #[test]
    fn enrollment_links_round_trip_and_reject_garbage() {
        let link = EnrollmentLink {
            endpoint: RelayEndpoint::parse("203.0.113.5:443").unwrap(),
            relay: [7; 32],
            code: [8; 16],
        };
        let text = link.to_text();
        assert!(text.starts_with("mousse-relay://203.0.113.5:443/#"));
        assert_eq!(EnrollmentLink::parse(&format!("  {text}\n")), Some(link));
        for bad in [
            "mousse-relay://203.0.113.5:443/#abc",
            "mousse-relay://203.0.113.5/#AAAA.AAAA",
            "https://203.0.113.5:443/#x.y",
            "",
        ] {
            assert_eq!(EnrollmentLink::parse(bad), None, "{bad}");
        }
        let v6 = RelayEndpoint::parse("[2001:db8::5]:8443").unwrap();
        assert_eq!(v6.destination(), "relay://[2001:db8::5]:8443");
        let name = RelayEndpoint::parse("Relay.Example.COM:443").unwrap();
        assert_eq!(name.destination(), "relay://relay.example.com:443");
        assert_eq!(
            RelayEndpoint::from_destination("relay://relay.example.com:443"),
            Some(name)
        );
        assert_eq!(
            RelayEndpoint::from_destination("relay://Relay.example.com:443"),
            None
        );
    }

    #[test]
    fn relay_hints_round_trip() {
        let route = RelayRoute {
            endpoint: RelayEndpoint::parse("203.0.113.5:443").unwrap(),
            relay: [1; 32],
            handle: [2; 32],
        };
        assert_eq!(RelayRoute::parse_hint(&route.to_hint()), Some(route));
        assert_eq!(
            RelayRoute::parse_hint("relay://203.0.113.5:443/AA/BB"),
            None
        );
    }

    #[test]
    fn invitation_tags_depend_on_both_id_and_secret() {
        let a = invitation_tag(&InvitationId([1; 16]), &TicketSecret([2; 16]));
        let b = invitation_tag(&InvitationId([3; 16]), &TicketSecret([2; 16]));
        let c = invitation_tag(&InvitationId([1; 16]), &TicketSecret([4; 16]));
        assert!(a != b && a != c);
        assert_ne!(tag_hash(&a), a);
    }

    #[test]
    fn the_certificate_key_is_the_relay_key() {
        let k = key(3);
        let cert = relay_certificate(&k);
        assert_eq!(certificate_key(&cert), Some(k.public_key()));
        assert_eq!(certificate_key(&cert[..cert.len() - 1]), None);
    }

    #[test]
    fn keys_records_round_trip() {
        let k = key(4).public_key();
        assert_eq!(decode_keys_request(&encode_keys_request(&k)).unwrap(), k);
        assert_eq!(
            decode_keys_answer(&encode_keys_answer(&[5; 32])).unwrap(),
            [5; 32]
        );
        assert!(decode_keys_answer(&encode_keys_request(&k)).is_err());
    }

    #[test]
    fn close_codes_are_4000_to_4006() {
        for (i, c) in CloseCode::ALL.iter().enumerate() {
            assert_eq!(c.code(), 4000 + i as u16);
            assert_eq!(CloseCode::from_code(c.code()), Some(*c));
        }
        assert_eq!(CloseCode::from_code(1000), None);
    }
}
