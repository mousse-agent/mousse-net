//! The joining side of Pair with IP (spec `wire.md` 10.9): one value is one
//! Connect, or one recovery of an earlier Connect whose outcome is pending.
//!
//! The person types the host's address and the 12-character code. The
//! joiner dials that address with no pin, waits for the host's `HELLO`,
//! looks the invitation up with `JOIN_DIRECT`, and runs one code attempt.
//! Once the host's confirmation verified, the host's identity key and the
//! invitation id `I` are authenticated, and the joiner waits for the host
//! owner's Allow (`PAIRED`).
//!
//! Two durable records, kept by the I/O layer under the typed lookup:
//! - the **ledger** ([`DirectLedger`]) counts this profile's attempts per
//!   typed lookup for 24 h, whatever key the far end shows;
//! - the **pending record** ([`DirectPending`]) remembers a code that passed
//!   until the host has said how it ended, so a dropped connection, a
//!   cancel while away or a crash never loses the outcome.
//!
//! Writes come out as [`DirectJoinerAction::PersistLedger`] and
//! [`DirectJoinerAction::PersistPending`], compare-and-swap writes the I/O
//! layer acknowledges with [`DirectJoinerPairing::on_persisted`]. What
//! depends on a write (the first share after a debit, the confirmation after
//! the pending record) is held until then.

use std::fmt;
use std::net::IpAddr;

use rand_core::CryptoRng;

use super::direct_code::{DirectCode, DirectCodeError, DirectLookup};
use super::exchange::{CodeExchange, CodeExchangeFactory, ExchangeRole};
use super::proof::{attempt_sid, direct_binding_transcript, EXPORTER_LEN};
use super::route::{parse_host, parse_port, RouteHost};
use super::{AttemptId, InvitationId};
use crate::cbor::{self, Fields, Value};
use crate::control::{AuthorizedState, ControlMessage, DirectRecovery, DIRECT_MINOR_VERSION};
use crate::grants::{validate_name, Role};
use crate::identity::IdentityPublicKey;
use crate::limits::Limits;
use crate::time::UnixTime;
use crate::ErrorCode;

/// The most attempts a stored [`DirectLedger`] may hold. A record format
/// bound: [`Limits::direct_joiner_attempts`] can only be lower.
pub const DIRECT_JOINER_ATTEMPTS: u8 = 5;

/// How long a ledger entry lives after its first debit. Fixed: a longer one
/// protects nothing once the invitation, at most 600 s, is gone.
pub const DIRECT_LEDGER_LIFE_SECS: u64 = 86_400;

/// Domain string at key 1 of a stored [`DirectLedger`].
pub const DIRECT_LEDGER_DOMAIN: &str = "mousse-direct-joiner-v1";

/// Domain string at key 1 of a stored [`DirectPending`].
pub const DIRECT_PENDING_DOMAIN: &str = "mousse-direct-pending-v1";

/// The address the person typed: `<IPv4>:<port>` or `[<IPv6>]:<port>`, as
/// the route grammar reads them (wire.md 10.2.1). No DNS names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DirectAddress {
    /// The host's IP address.
    pub ip: IpAddr,
    /// TCP port, 1 to 65535.
    pub port: u16,
}

impl DirectAddress {
    /// Read a typed address. Leading and trailing ASCII spaces are dropped;
    /// anything else that is not an IP address and a port is refused.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim_matches(' ');
        let (host, port) = text.rsplit_once(':')?;
        let port = parse_port(port)?;
        let ip = match parse_host(host)? {
            RouteHost::Ipv4(v4) => IpAddr::V4(v4),
            RouteHost::Ipv6(v6) => IpAddr::V6(v6),
            RouteHost::Dns(_) => return None,
        };
        Some(Self { ip, port })
    }

    /// The canonical text form, as stored in a [`DirectPending`].
    pub fn to_text(&self) -> String {
        match self.ip {
            IpAddr::V4(v4) => format!("{v4}:{}", self.port),
            IpAddr::V6(v6) => format!("[{v6}]:{}", self.port),
        }
    }
}

impl fmt::Display for DirectAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// The joiner's attempt ledger for one typed lookup (wire.md 10.9,
/// "Joiner records"): `{1: "mousse-direct-joiner-v1", 2: L, 3: attempts left,
/// 4: first debit time}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectLedger {
    /// The typed lookup it counts for.
    pub lookup: DirectLookup,
    /// Attempts left, 0 to [`DIRECT_JOINER_ATTEMPTS`].
    pub attempts_left: u8,
    /// When the first attempt was debited; the entry is gone 24 h later.
    pub first_debit: UnixTime,
}

impl DirectLedger {
    /// Canonical CBOR.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(DIRECT_LEDGER_DOMAIN.to_owned())),
            (2, Value::Text(self.lookup.as_str().to_owned())),
            (3, Value::Uint(u64::from(self.attempts_left))),
            (4, Value::Uint(self.first_debit.0)),
        ]))
    }

    /// Parse [`DirectLedger::to_bytes`] output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DirectJoinError> {
        let bad = |_| DirectJoinError::BadRecord;
        let mut f = Fields::decode(bytes).map_err(bad)?;
        if f.text(1).map_err(bad)? != DIRECT_LEDGER_DOMAIN {
            return Err(DirectJoinError::BadRecord);
        }
        let lookup = DirectLookup::from_canonical(&f.text(2).map_err(bad)?)
            .ok_or(DirectJoinError::BadRecord)?;
        let attempts_left = match f.uint(3).map_err(bad)? {
            n if n <= u64::from(DIRECT_JOINER_ATTEMPTS) => n as u8,
            _ => return Err(DirectJoinError::BadRecord),
        };
        let first_debit = UnixTime(f.uint(4).map_err(bad)?);
        f.finish().map_err(bad)?;
        Ok(Self {
            lookup,
            attempts_left,
            first_debit,
        })
    }

    /// Whether the entry still counts at `now`.
    pub fn is_live(&self, now: UnixTime) -> bool {
        now < self.first_debit.plus(DIRECT_LEDGER_LIFE_SECS)
    }
}

/// A code that passed and whose outcome the joiner has not learned
/// (wire.md 10.9, "Joiner records"): `{1: "mousse-direct-pending-v1", 2: L,
/// 3: host key, 4: I, 5: address, 6: time the host's confirmation verified,
/// 7: cancelled (0 or 1)}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectPending {
    /// The typed lookup.
    pub lookup: DirectLookup,
    /// The host's identity key, authenticated by its confirmation.
    pub host: IdentityPublicKey,
    /// The invitation id `I`, authenticated the same way.
    pub invitation: InvitationId,
    /// The typed address.
    pub address: DirectAddress,
    /// When the host's confirmation verified.
    pub verified_at: UnixTime,
    /// The joiner cancelled; the next connection delivers the cancel.
    pub cancelled: bool,
}

impl DirectPending {
    /// Canonical CBOR.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(DIRECT_PENDING_DOMAIN.to_owned())),
            (2, Value::Text(self.lookup.as_str().to_owned())),
            (3, Value::Bytes(self.host.as_bytes().to_vec())),
            (4, Value::Bytes(self.invitation.0.to_vec())),
            (5, Value::Text(self.address.to_text())),
            (6, Value::Uint(self.verified_at.0)),
            (7, Value::Uint(u64::from(self.cancelled))),
        ]))
    }

    /// Parse [`DirectPending::to_bytes`] output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DirectJoinError> {
        let bad = |_| DirectJoinError::BadRecord;
        let mut f = Fields::decode(bytes).map_err(bad)?;
        if f.text(1).map_err(bad)? != DIRECT_PENDING_DOMAIN {
            return Err(DirectJoinError::BadRecord);
        }
        let lookup = DirectLookup::from_canonical(&f.text(2).map_err(bad)?)
            .ok_or(DirectJoinError::BadRecord)?;
        let host = IdentityPublicKey::from_sec1(&f.bytes(3).map_err(bad)?)
            .map_err(|_| DirectJoinError::BadRecord)?;
        let invitation = InvitationId(f.fixed::<16>(4).map_err(bad)?);
        let address_text = f.text(5).map_err(bad)?;
        let address = DirectAddress::parse(&address_text)
            .filter(|a| a.to_text() == address_text)
            .ok_or(DirectJoinError::BadRecord)?;
        let verified_at = UnixTime(f.uint(6).map_err(bad)?);
        let cancelled = match f.uint(7).map_err(bad)? {
            0 => false,
            1 => true,
            _ => return Err(DirectJoinError::BadRecord),
        };
        f.finish().map_err(bad)?;
        Ok(Self {
            lookup,
            host,
            invitation,
            address,
            verified_at,
            cancelled,
        })
    }
}

/// Why a joiner call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectJoinError {
    /// The address is not `<IPv4>:<port>` or `[<IPv6>]:<port>`. Nothing is
    /// dialled.
    BadAddress,
    /// The code is not a code. Nothing is dialled and no attempt is spent.
    BadCode(DirectCodeError),
    /// This profile has no attempts left for the typed lookup. Nothing is
    /// dialled.
    AttemptsExhausted,
    /// The device name is empty or longer than 128 bytes.
    InvalidName,
    /// A stored record is for another lookup, or does not parse.
    BadRecord,
    /// The call does not fit the current state.
    WrongState,
}

impl DirectJoinError {
    /// Stable snake_case name, used in test vectors and helper errors.
    pub fn name(&self) -> &'static str {
        match self {
            DirectJoinError::BadAddress => "bad_address",
            DirectJoinError::BadCode(_) => "bad_code",
            DirectJoinError::AttemptsExhausted => "attempts_exhausted",
            DirectJoinError::InvalidName => "invalid_name",
            DirectJoinError::BadRecord => "bad_record",
            DirectJoinError::WrongState => "wrong_state",
        }
    }
}

impl fmt::Display for DirectJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DirectJoinError::BadAddress => "the address is not an IP address and a port",
            DirectJoinError::BadCode(_) => "the code is not a 12-character code",
            DirectJoinError::AttemptsExhausted => "no attempts left for this code",
            DirectJoinError::InvalidName => "invalid device name",
            DirectJoinError::BadRecord => "the stored record does not fit",
            DirectJoinError::WrongState => "not possible in the current state",
        })
    }
}

impl std::error::Error for DirectJoinError {}

/// How a flow ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectEnd {
    /// Paired: the pin is stored and the pending record cleared.
    Paired,
    /// The host speaks an older Mousse (agreed minor below 4).
    NeedsUpdate,
    /// The far end showed this device's own identity key.
    OwnDevice,
    /// The code did not pass. `attempts_left` is this profile's count for
    /// the typed lookup.
    CodeFailed {
        /// Attempts left.
        attempts_left: u8,
    },
    /// No attempts are left for the typed lookup.
    AttemptsExhausted,
    /// The connection dropped before the host had this device's
    /// confirmation: connect again and type the code again.
    NotReceived {
        /// Attempts left.
        attempts_left: u8,
    },
    /// This device cancelled before its code passed.
    Cancelled,
    /// The host closed with this code (`INVITATION_INVALID`,
    /// `PAIRING_DECLINED`, `CANCELLED`, `ATTEMPTS_EXHAUSTED`, a busy host's
    /// `INTERNAL_ERROR`, ...), or the connection broke (`None`). Any pending
    /// record is settled.
    Closed(Option<ErrorCode>),
}

/// Where the flow stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectJoinerState {
    /// Not connected (yet).
    Connecting,
    /// Connected; waiting for the host's `HELLO`.
    AwaitingHello,
    /// `JOIN_DIRECT` sent; waiting for the host's answer.
    AwaitingAnswer,
    /// The code attempt runs.
    Exchanging,
    /// The code passed (or a recovery found the request): waiting for the
    /// owner's Allow.
    AwaitingAllow,
    /// A pending record waits for a recovery connection.
    Away,
    /// `PAIRED` accepted; waiting for the pin to be stored.
    Paired,
    /// Done.
    Ended(DirectEnd),
}

/// The paired host, to store: pin, owner route and completion record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectPaired {
    /// The host's identity key, authenticated by its confirmation.
    pub identity: IdentityPublicKey,
    /// Its display name.
    pub name: String,
    /// The role it granted.
    pub role: Role,
    /// The invitation id, the completion record's key.
    pub invitation: InvitationId,
    /// The typed address, to keep as an owner route.
    pub address: DirectAddress,
}

/// Something the I/O layer or UI must do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectJoinerAction {
    /// Send this control message on the connection.
    Send(ControlMessage),
    /// Send `GOAWAY(code)` and close the connection.
    Close(ErrorCode),
    /// Store `record` under its lookup, atomically and only if the stored
    /// ledger is still `expected` (`None`: none stored). Then call
    /// [`DirectJoinerPairing::on_persisted`], or
    /// [`DirectJoinerPairing::on_persist_failed`] if the write failed or
    /// the stored record changed. Pass the flow no other event before.
    PersistLedger {
        /// The ledger this flow loaded or last wrote.
        expected: Option<DirectLedger>,
        /// The ledger to store.
        record: DirectLedger,
    },
    /// Store (`Some`) or delete (`None`) the pending record under its
    /// lookup, the same way.
    PersistPending {
        /// The pending record this flow loaded or last wrote.
        expected: Option<DirectPending>,
        /// The record to store, or `None` to delete it.
        record: Option<DirectPending>,
    },
    /// The code passed: show "Waiting for Allow" with this device's short
    /// id.
    CodePassed,
    /// The host allowed this device. Store the pin, the typed address as an
    /// owner route and the completion record keyed by the invitation, set
    /// the connection's pairing-only gate live, then call
    /// [`DirectJoinerPairing::on_pin_stored`].
    Paired(DirectPaired),
    /// The pending record stays: connect again later, pinned to
    /// [`DirectJoinerPairing::pinned_host`] at the typed address, to learn
    /// the outcome (or deliver the cancel).
    Away,
    /// The flow ended.
    Ended(DirectEnd),
}

/// A write the I/O layer has not acknowledged.
#[derive(Clone, Debug)]
enum Write {
    Ledger(DirectLedger),
    Pending(Option<DirectPending>),
}

struct Attempt<E> {
    id: AttemptId,
    exchange: Option<E>,
}

/// The joiner side of Pair with IP.
pub struct DirectJoinerPairing<F: CodeExchangeFactory> {
    address: DirectAddress,
    lookup: DirectLookup,
    /// The typed code; `None` for a recovery, which needs none.
    code: Option<DirectCode>,
    joiner: IdentityPublicKey,
    name: String,
    factory: F,
    state: DirectJoinerState,
    attempts_left: u8,
    /// The ledger as stored, as far as this flow knows.
    ledger_saved: Option<DirectLedger>,
    /// The first debit time of the ledger entry that still counts.
    first_debit: Option<UnixTime>,
    /// The pending record in memory, and as stored.
    pending: Option<DirectPending>,
    pending_saved: Option<DirectPending>,
    /// This connection is a recovery: `JOIN_DIRECT` carries the receipt.
    /// Set on each connection: true exactly when a pending record exists.
    recovering: bool,
    /// The far end's key on this connection (a candidate until its
    /// confirmation verifies, on a first contact).
    host: Option<IdentityPublicKey>,
    pair_exporter: Option<[u8; EXPORTER_LEN]>,
    /// From `AUTHORIZED {join_only, I}` (authenticated by the confirmation).
    invitation: Option<InvitationId>,
    attempt: Option<Attempt<F::Exchange>>,
    /// Step 2's `AUTHORIZED {live}` notice came on this connection.
    live_notice: bool,
    in_flight: Option<Write>,
    held: Vec<DirectJoinerAction>,
}

impl<F: CodeExchangeFactory> DirectJoinerPairing<F> {
    /// Start a Connect from what the person typed. `ledger` and `pending`
    /// are the records stored under the typed lookup, if any. A pending
    /// record for the same lookup and address resumes that flow (a
    /// recovery, no attempt); otherwise a new flow starts. Every refusal
    /// here happens before dialing. Uses the default limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: &str,
        code: &str,
        joiner: IdentityPublicKey,
        name: &str,
        factory: F,
        ledger: Option<&DirectLedger>,
        pending: Option<&DirectPending>,
        now: UnixTime,
    ) -> Result<Self, DirectJoinError> {
        Self::with_limits(
            address,
            code,
            joiner,
            name,
            factory,
            ledger,
            pending,
            now,
            &Limits::DEFAULT,
        )
    }

    /// [`DirectJoinerPairing::new`] with other limits
    /// ([`Limits::direct_joiner_attempts`], cut to the record's bound).
    #[allow(clippy::too_many_arguments)]
    pub fn with_limits(
        address: &str,
        code: &str,
        joiner: IdentityPublicKey,
        name: &str,
        factory: F,
        ledger: Option<&DirectLedger>,
        pending: Option<&DirectPending>,
        now: UnixTime,
        limits: &Limits,
    ) -> Result<Self, DirectJoinError> {
        let address = DirectAddress::parse(address).ok_or(DirectJoinError::BadAddress)?;
        let code = DirectCode::parse(code).map_err(DirectJoinError::BadCode)?;
        let lookup = code.lookup();
        let resumes = pending.is_some_and(|p| p.lookup == lookup && p.address == address);
        let mut flow = Self::build(
            address, lookup, joiner, name, factory, ledger, pending, now, limits,
        )?;
        if !resumes {
            if flow.attempts_left == 0 {
                return Err(DirectJoinError::AttemptsExhausted);
            }
            flow.code = Some(code);
            // A pending record for this lookup at another address belongs
            // to another flow; this one starts afresh.
            flow.pending = None;
        }
        Ok(flow)
    }

    /// Resume the flow of a stored pending record, with no code: a start-up
    /// or background recovery. `ledger` is the ledger stored under the same
    /// lookup, if any.
    pub fn resume(
        pending: &DirectPending,
        joiner: IdentityPublicKey,
        name: &str,
        factory: F,
        ledger: Option<&DirectLedger>,
        now: UnixTime,
        limits: &Limits,
    ) -> Result<Self, DirectJoinError> {
        let mut flow = Self::build(
            pending.address,
            pending.lookup.clone(),
            joiner,
            name,
            factory,
            ledger,
            Some(pending),
            now,
            limits,
        )?;
        flow.recovering = true;
        Ok(flow)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        address: DirectAddress,
        lookup: DirectLookup,
        joiner: IdentityPublicKey,
        name: &str,
        factory: F,
        ledger: Option<&DirectLedger>,
        pending: Option<&DirectPending>,
        now: UnixTime,
        limits: &Limits,
    ) -> Result<Self, DirectJoinError> {
        validate_name(name).map_err(|_| DirectJoinError::InvalidName)?;
        if ledger.is_some_and(|l| l.lookup != lookup) || pending.is_some_and(|p| p.lookup != lookup)
        {
            return Err(DirectJoinError::BadRecord);
        }
        let attempts_per_lookup = u8::try_from(limits.direct_joiner_attempts())
            .unwrap_or(u8::MAX)
            .min(DIRECT_JOINER_ATTEMPTS);
        // Must-fail control (tests only): the stored count is not read, as
        // with a ledger keyed by the far end's key when the far end shows a
        // new key on every Connect.
        let counted = ledger
            .filter(|l| l.is_live(now))
            .filter(|_| !cfg!(mousse_control = "direct-ledger-by-key"));
        let (attempts_left, first_debit) = match counted {
            Some(l) => (
                l.attempts_left.min(attempts_per_lookup),
                Some(l.first_debit),
            ),
            None => (attempts_per_lookup, None),
        };
        Ok(Self {
            address,
            lookup,
            code: None,
            joiner,
            name: name.to_owned(),
            factory,
            state: DirectJoinerState::Connecting,
            attempts_left,
            ledger_saved: ledger.cloned(),
            first_debit,
            pending: pending.cloned(),
            pending_saved: pending.cloned(),
            recovering: false,
            host: None,
            pair_exporter: None,
            invitation: None,
            attempt: None,
            live_notice: false,
            in_flight: None,
            held: Vec::new(),
        })
    }

    /// Current state.
    pub fn state(&self) -> DirectJoinerState {
        self.state
    }

    /// The typed address to dial.
    pub fn address(&self) -> DirectAddress {
        self.address
    }

    /// The typed lookup: the key of both records.
    pub fn lookup(&self) -> &DirectLookup {
        &self.lookup
    }

    /// Attempts left for the typed lookup.
    pub fn attempts_left(&self) -> u8 {
        self.attempts_left
    }

    /// The host key a recovery dial is pinned to; `None` for a first
    /// contact, which is dialled with no pin (wire.md 5.4).
    pub fn pinned_host(&self) -> Option<IdentityPublicKey> {
        self.pending.as_ref().map(|p| p.host)
    }

    /// The pending record as it stands in memory.
    pub fn pending(&self) -> Option<&DirectPending> {
        self.pending.as_ref()
    }

    /// The last persist action is durable. Returns what waited for it.
    pub fn on_persisted(&mut self) -> Vec<DirectJoinerAction> {
        match self.in_flight.take() {
            Some(Write::Ledger(l)) => self.ledger_saved = Some(l),
            Some(Write::Pending(p)) => self.pending_saved = p,
            None => return Vec::new(),
        }
        std::mem::take(&mut self.held)
    }

    /// The last persist action did not happen (the write failed, or another
    /// flow changed the stored record first). Nothing that waited for it is
    /// sent; the connection closes with `INTERNAL_ERROR` and the flow ends.
    /// What is stored stays as it was.
    pub fn on_persist_failed(&mut self) -> Vec<DirectJoinerAction> {
        if self.in_flight.take().is_none() {
            return Vec::new();
        }
        self.held.clear();
        self.attempt = None;
        let connected = !matches!(
            self.state,
            DirectJoinerState::Away | DirectJoinerState::Connecting
        );
        self.state = DirectJoinerState::Ended(DirectEnd::Closed(Some(ErrorCode::InternalError)));
        let mut actions = Vec::new();
        if connected {
            actions.push(DirectJoinerAction::Close(ErrorCode::InternalError));
        }
        actions.push(DirectJoinerAction::Ended(DirectEnd::Closed(Some(
            ErrorCode::InternalError,
        ))));
        actions
    }

    /// TLS is up with `host`, the key the far end showed (pinned on a
    /// recovery, a candidate on a first contact). Nothing is sent yet: the
    /// joiner waits for the host's `HELLO` ([`Self::on_hello`]).
    pub fn on_connected(
        &mut self,
        host: IdentityPublicKey,
        pair_exporter: [u8; EXPORTER_LEN],
    ) -> Vec<DirectJoinerAction> {
        if !matches!(
            self.state,
            DirectJoinerState::Connecting | DirectJoinerState::Away
        ) {
            return Vec::new();
        }
        // A device never pairs with itself (the I/O layer's verifier
        // refuses this key first, before its own certificate goes out).
        if host == self.joiner {
            return self.end_connected(ErrorCode::PairingFailed, DirectEnd::OwnDevice);
        }
        // A code that passed is pending: every later connection is a
        // pinned recovery.
        self.recovering = self.pending.is_some();
        if self.recovering && self.pinned_host() != Some(host) {
            return self.broken(Some(ErrorCode::NotAuthorized), true);
        }
        self.host = Some(host);
        self.pair_exporter = Some(pair_exporter);
        self.invitation = None;
        self.attempt = None;
        self.live_notice = false;
        self.state = DirectJoinerState::AwaitingHello;
        Vec::new()
    }

    /// The host's `HELLO` agreed on `agreed`. Below minor 4 the host cannot
    /// pair this way: close with `UNSUPPORTED_VERSION` (needs update).
    /// Otherwise send `JOIN_DIRECT`.
    pub fn on_hello(&mut self, agreed: u64) -> Vec<DirectJoinerAction> {
        if self.state != DirectJoinerState::AwaitingHello {
            return Vec::new();
        }
        if agreed < DIRECT_MINOR_VERSION {
            // A pending record stays: only the host's answer settles it.
            return self.end_connected(ErrorCode::UnsupportedVersion, DirectEnd::NeedsUpdate);
        }
        let recovery = if self.recovering {
            self.pending.as_ref().map(|p| DirectRecovery {
                receipt: p.invitation,
                cancel: p.cancelled,
            })
        } else {
            None
        };
        self.state = DirectJoinerState::AwaitingAnswer;
        vec![DirectJoinerAction::Send(ControlMessage::JoinDirect {
            lookup: self.lookup.clone(),
            name: self.name.clone(),
            recovery,
        })]
    }

    /// The host sent `AUTHORIZED` with key 1 only. A first `live` is step
    /// 2's notice (the host grants this device); it is not the answer.
    pub fn on_authorized(&mut self, state: AuthorizedState) -> Vec<DirectJoinerAction> {
        if self.state == DirectJoinerState::AwaitingAnswer
            && state == AuthorizedState::Live
            && !self.live_notice
        {
            self.live_notice = true;
            return Vec::new();
        }
        self.protocol_error()
    }

    /// The host answered `JOIN_DIRECT` with `AUTHORIZED {join_only, I,
    /// not_received}`. On a first contact this starts the one attempt of
    /// this connection: the debit is stored, then `msg_a` goes out.
    pub fn on_authorized_direct<R: CryptoRng + ?Sized>(
        &mut self,
        invitation: InvitationId,
        not_received: bool,
        now: UnixTime,
        rng: &mut R,
    ) -> Vec<DirectJoinerAction> {
        if self.state != DirectJoinerState::AwaitingAnswer {
            return self.protocol_error();
        }
        if self.recovering {
            let Some(pending) = self.pending.clone() else {
                return self.protocol_error();
            };
            if invitation != pending.invitation || pending.cancelled {
                return self.protocol_error();
            }
            if not_received {
                // The host never had this device's confirmation: settled.
                // The code is typed again; it is never stored.
                self.pending = None;
                let end = DirectEnd::NotReceived {
                    attempts_left: self.attempts_left,
                };
                self.state = DirectJoinerState::Ended(end);
                return self.commit_pending(vec![
                    DirectJoinerAction::Close(ErrorCode::NoError),
                    DirectJoinerAction::Ended(end),
                ]);
            }
            self.invitation = Some(invitation);
            self.state = DirectJoinerState::AwaitingAllow;
            return vec![DirectJoinerAction::CodePassed];
        }
        if not_received {
            return self.protocol_error();
        }
        self.invitation = Some(invitation);
        self.start_attempt(now, rng)
    }

    fn start_attempt<R: CryptoRng + ?Sized>(
        &mut self,
        now: UnixTime,
        rng: &mut R,
    ) -> Vec<DirectJoinerAction> {
        let (Some(code), Some(host), Some(exporter), Some(invitation)) = (
            self.code.clone(),
            self.host,
            self.pair_exporter,
            self.invitation,
        ) else {
            return self.protocol_error();
        };
        if self.attempts_left == 0 {
            return self.end_connected(ErrorCode::AttemptsExhausted, DirectEnd::AttemptsExhausted);
        }
        // Debit first. Nothing below runs on an undebited attempt.
        self.attempts_left -= 1;
        let first_debit = *self.first_debit.get_or_insert(now);
        let ledger = DirectLedger {
            lookup: self.lookup.clone(),
            attempts_left: self.attempts_left,
            first_debit,
        };
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let attempt = AttemptId(id);
        let binding =
            direct_binding_transcript(&self.lookup, &invitation, &host, &self.joiner, &exporter);
        let sid = attempt_sid(&attempt, &exporter);
        let secret = code.secret();
        let mut exchange = self.factory.start(
            ExchangeRole::Initiator,
            secret.as_bytes(),
            &binding,
            &sid,
            rng,
        );
        let then = match exchange.step(None) {
            Ok(step) => match step.send {
                Some(payload) => {
                    self.attempt = Some(Attempt {
                        id: attempt,
                        exchange: Some(exchange),
                    });
                    self.state = DirectJoinerState::Exchanging;
                    vec![DirectJoinerAction::Send(ControlMessage::CodeExchange {
                        attempt,
                        payload,
                    })]
                }
                None => self.code_failed(Some(attempt)),
            },
            Err(_) => self.code_failed(Some(attempt)),
        };
        // The debit is durable before the first share goes out.
        self.persist(Write::Ledger(ledger), then)
    }

    /// The host sent `CODE_EXCHANGE`. `msg_b` is checked: a wrong
    /// confirmation fails the attempt and ends the flow (the next try is a
    /// new Connect); a right one authenticates the host key and `I`, which
    /// are stored as the pending record before `msg_c` goes out.
    pub fn on_code_exchange(
        &mut self,
        attempt: AttemptId,
        payload: &[u8],
        now: UnixTime,
    ) -> Vec<DirectJoinerAction> {
        if self.state != DirectJoinerState::Exchanging {
            return Vec::new();
        }
        let Some(current) = self.attempt.as_mut() else {
            return Vec::new();
        };
        if current.id != attempt {
            return Vec::new();
        }
        let Some(exchange) = current.exchange.as_mut() else {
            return Vec::new();
        };
        match exchange.step(Some(payload)) {
            Ok(step) if step.peer_confirmed => {
                current.exchange = None;
                let (Some(host), Some(invitation)) = (self.host, self.invitation) else {
                    return self.protocol_error();
                };
                self.pending = Some(DirectPending {
                    lookup: self.lookup.clone(),
                    host,
                    invitation,
                    address: self.address,
                    verified_at: now,
                    cancelled: false,
                });
                self.state = DirectJoinerState::AwaitingAllow;
                let mut then = vec![DirectJoinerAction::CodePassed];
                then.extend(step.send.map(|payload| {
                    DirectJoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })
                }));
                // Must-fail control (tests only): the host is pinned as soon
                // as its confirmation verifies, before the owner allowed.
                if cfg!(mousse_control = "direct-pin-before-paired") {
                    then.push(DirectJoinerAction::Paired(DirectPaired {
                        identity: host,
                        name: String::new(),
                        role: Role::owner(),
                        invitation,
                        address: self.address,
                    }));
                }
                // The pending record is durable before `msg_c` goes out: from
                // then on the host may enroll this device.
                self.commit_pending(then)
            }
            Ok(_) => self.code_failed(Some(attempt)),
            Err(_) => self.code_failed(Some(attempt)),
        }
    }

    /// The host sent `CODE_ABORT` for this connection's attempt: it did not
    /// accept the attempt, so nothing is pending. The debit stays.
    pub fn on_code_abort(&mut self, attempt: AttemptId) -> Vec<DirectJoinerAction> {
        if self.attempt.as_ref().map(|a| a.id) != Some(attempt)
            || !matches!(
                self.state,
                DirectJoinerState::Exchanging | DirectJoinerState::AwaitingAllow
            )
        {
            return Vec::new();
        }
        let had_pending = self.pending.take().is_some();
        let actions = self.code_failed(None);
        if had_pending {
            self.commit_pending(actions)
        } else {
            actions
        }
    }

    /// The host sent `PAIRED`. Accepted only after this flow verified the
    /// host's confirmation (or, on a recovery, as the host's answer by
    /// receipt), and never after this device cancelled: a `PAIRED` that
    /// crosses the cancel pins nothing.
    pub fn on_paired(&mut self, host_name: String, role: Role) -> Vec<DirectJoinerAction> {
        let Some(pending) = self.pending.clone() else {
            return self.protocol_error();
        };
        if pending.cancelled {
            return Vec::new();
        }
        let ok = match self.state {
            DirectJoinerState::AwaitingAllow => true,
            // A recovery answered from the grant's receipt, after step 2's
            // notice.
            DirectJoinerState::AwaitingAnswer => self.recovering && self.live_notice,
            _ => false,
        };
        if !ok {
            return self.protocol_error();
        }
        self.state = DirectJoinerState::Paired;
        self.attempt = None;
        vec![DirectJoinerAction::Paired(DirectPaired {
            identity: pending.host,
            name: host_name,
            role,
            invitation: pending.invitation,
            address: self.address,
        })]
    }

    /// The pin, route and completion record from
    /// [`DirectJoinerAction::Paired`] are durable: the pending record goes.
    pub fn on_pin_stored(&mut self) -> Vec<DirectJoinerAction> {
        if self.state != DirectJoinerState::Paired {
            return Vec::new();
        }
        self.pending = None;
        self.state = DirectJoinerState::Ended(DirectEnd::Paired);
        self.commit_pending(vec![DirectJoinerAction::Ended(DirectEnd::Paired)])
    }

    /// The person cancelled. Before the code passed this ends the flow (an
    /// attempt in progress is aborted; its debit stays). After it passed the
    /// pending record is marked cancelled first; a connected device then
    /// aborts and closes with `CANCELLED`, and the record stays until a
    /// recovery hears the host's answer (the cancel wins over a crossing
    /// Allow).
    pub fn cancel(&mut self) -> Result<Vec<DirectJoinerAction>, DirectJoinError> {
        let connected = matches!(
            self.state,
            DirectJoinerState::AwaitingHello
                | DirectJoinerState::AwaitingAnswer
                | DirectJoinerState::Exchanging
                | DirectJoinerState::AwaitingAllow
        );
        match (self.state, self.pending.clone()) {
            (DirectJoinerState::Paired | DirectJoinerState::Ended(_), _) => {
                Err(DirectJoinError::WrongState)
            }
            (_, Some(pending)) => {
                let mut then = Vec::new();
                if connected {
                    if let Some(attempt) = self.attempt.take() {
                        then.push(DirectJoinerAction::Send(ControlMessage::CodeAbort {
                            attempt: attempt.id,
                            code: ErrorCode::Cancelled,
                        }));
                    }
                    then.push(DirectJoinerAction::Close(ErrorCode::Cancelled));
                }
                then.push(DirectJoinerAction::Away);
                self.state = DirectJoinerState::Away;
                self.pending = Some(DirectPending {
                    cancelled: true,
                    ..pending
                });
                Ok(self.commit_pending(then))
            }
            (_, None) => {
                let mut actions = Vec::new();
                if let Some(attempt) = self.attempt.take() {
                    actions.push(DirectJoinerAction::Send(ControlMessage::CodeAbort {
                        attempt: attempt.id,
                        code: ErrorCode::Cancelled,
                    }));
                }
                if connected {
                    actions.push(DirectJoinerAction::Close(ErrorCode::Cancelled));
                }
                self.state = DirectJoinerState::Ended(DirectEnd::Cancelled);
                actions.push(DirectJoinerAction::Ended(DirectEnd::Cancelled));
                Ok(actions)
            }
        }
    }

    /// The host's answer to `JOIN_DIRECT` did not come in time (wire.md
    /// 8.2): close with `NOT_AUTHORIZED`. A pending record stays.
    pub fn on_answer_timeout(&mut self) -> Vec<DirectJoinerAction> {
        if self.state != DirectJoinerState::AwaitingAnswer {
            return Vec::new();
        }
        let mut actions = vec![DirectJoinerAction::Close(ErrorCode::NotAuthorized)];
        actions.extend(self.broken(Some(ErrorCode::NotAuthorized), false));
        actions
    }

    /// The connection closed, with the host's `GOAWAY` code if it sent one.
    /// A pending record is cleared only by an answer that settles it
    /// (`PAIRING_DECLINED`, `CANCELLED`, `INVITATION_INVALID`,
    /// `ATTEMPTS_EXHAUSTED`); any other end keeps it ([`DirectJoinerAction::Away`]).
    pub fn on_closed(&mut self, code: Option<ErrorCode>) -> Vec<DirectJoinerAction> {
        if matches!(
            self.state,
            DirectJoinerState::Ended(_) | DirectJoinerState::Away | DirectJoinerState::Connecting
        ) {
            return Vec::new();
        }
        if self.state == DirectJoinerState::Paired {
            // The pin is being stored; the connection's end changes nothing.
            return Vec::new();
        }
        self.broken(code, false)
    }

    /// The connection ended with `code`. With a pending record: a settling
    /// answer clears it, anything else keeps it. Without: the flow ends.
    fn broken(&mut self, code: Option<ErrorCode>, close: bool) -> Vec<DirectJoinerAction> {
        self.attempt = None;
        self.held.clear();
        let mut actions = Vec::new();
        if close {
            if let Some(code) = code {
                actions.push(DirectJoinerAction::Close(code));
            }
        }
        let settles = matches!(
            code,
            Some(
                ErrorCode::PairingDeclined
                    | ErrorCode::Cancelled
                    | ErrorCode::InvitationInvalid
                    | ErrorCode::AttemptsExhausted
            )
        );
        match (&self.pending, settles) {
            (Some(_), false) => {
                self.state = DirectJoinerState::Away;
                actions.push(DirectJoinerAction::Away);
                actions
            }
            (Some(_), true) => {
                self.pending = None;
                let end = DirectEnd::Closed(code);
                self.state = DirectJoinerState::Ended(end);
                actions.push(DirectJoinerAction::Ended(end));
                self.commit_pending(actions)
            }
            (None, _) => {
                let end = DirectEnd::Closed(code);
                self.state = DirectJoinerState::Ended(end);
                actions.push(DirectJoinerAction::Ended(end));
                actions
            }
        }
    }

    fn protocol_error(&mut self) -> Vec<DirectJoinerAction> {
        self.broken(Some(ErrorCode::ProtocolError), true)
    }

    /// Close this connection with `code` and end with `end`; a pending
    /// record stays stored.
    fn end_connected(&mut self, code: ErrorCode, end: DirectEnd) -> Vec<DirectJoinerAction> {
        self.attempt = None;
        self.state = DirectJoinerState::Ended(end);
        vec![
            DirectJoinerAction::Close(code),
            DirectJoinerAction::Ended(end),
        ]
    }

    /// The attempt failed at this side (`attempt`: tell the host) or at the
    /// host. The connection closes; the next try is a new Connect.
    fn code_failed(&mut self, attempt: Option<AttemptId>) -> Vec<DirectJoinerAction> {
        self.attempt = None;
        let mut actions = Vec::new();
        if let Some(attempt) = attempt {
            actions.push(DirectJoinerAction::Send(ControlMessage::CodeAbort {
                attempt,
                code: ErrorCode::PairingFailed,
            }));
        }
        let (code, end) = if self.attempts_left == 0 {
            (ErrorCode::AttemptsExhausted, DirectEnd::AttemptsExhausted)
        } else {
            (
                ErrorCode::PairingFailed,
                DirectEnd::CodeFailed {
                    attempts_left: self.attempts_left,
                },
            )
        };
        self.state = DirectJoinerState::Ended(end);
        actions.push(DirectJoinerAction::Close(code));
        actions.push(DirectJoinerAction::Ended(end));
        actions
    }

    /// Ask for the pending record's write if it changed; `then` waits.
    fn commit_pending(&mut self, then: Vec<DirectJoinerAction>) -> Vec<DirectJoinerAction> {
        if self.pending == self.pending_saved {
            return then;
        }
        let record = self.pending.clone();
        self.persist(Write::Pending(record), then)
    }

    fn persist(&mut self, write: Write, then: Vec<DirectJoinerAction>) -> Vec<DirectJoinerAction> {
        let action = match &write {
            Write::Ledger(record) => DirectJoinerAction::PersistLedger {
                expected: self.ledger_saved.clone(),
                record: record.clone(),
            },
            Write::Pending(record) => DirectJoinerAction::PersistPending {
                expected: self.pending_saved.clone(),
                record: record.clone(),
            },
        };
        self.in_flight = Some(write);
        self.held = then;
        vec![action]
    }
}

#[cfg(test)]
#[path = "direct_joiner_tests.rs"]
mod tests;
