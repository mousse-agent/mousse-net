//! The joining device's pairing state machine. One value is one local
//! code-entry flow: it allows [`JOINER_ATTEMPTS_PER_FLOW`] code attempts,
//! across reconnects, so a fake host cannot make it try codes forever.
//!
//! The flow's durable part is a [`JoinerRecord`], keyed by the ticket hash.
//! The I/O layer stores it and passes it back when the same ticket is opened
//! again, so neither killing the app nor reopening the link resets the
//! attempt count or forgets a pending outcome.
//!
//! Writes that must land before the flow goes on come out as
//! [`JoinerAction::Persist`]: a compare-and-swap of the stored record. The
//! actions that depend on it, such as the first exchange message after a
//! debit, or the joiner's confirmation after the outcome-pending mark, are
//! held inside the flow and handed out only by
//! [`JoinerPairing::on_persisted`], so the I/O layer cannot send them first
//! (wire.md 10.7).

use std::fmt;

use rand_core::CryptoRng;

use super::exchange::{CodeExchange, CodeExchangeFactory, ExchangeRole, PairingCode};
use super::proof::{attempt_sid, binding_transcript, join_proof_mac, SessionExporters};
use super::ticket::Ticket;
use super::{AttemptId, InvitationKind};
use crate::cbor::{self, Fields, Value};
use crate::control::{AuthorizedState, ControlMessage};
use crate::grants::{validate_name, Role};
use crate::identity::IdentityPublicKey;
use crate::time::UnixTime;
use crate::ErrorCode;

/// Code attempts the joiner allows per ticket, by default (wire.md 10.7).
/// Also the most a stored [`JoinerRecord`] may hold.
pub const JOINER_ATTEMPTS_PER_FLOW: u8 = 3;

/// The joiner's limits. [`Default`] gives the protocol's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinerLimits {
    /// Code attempts per ticket, across every time it is opened. A stored
    /// record holds at most [`JOINER_ATTEMPTS_PER_FLOW`], so a larger value
    /// is cut to that.
    pub attempts_per_flow: u8,
}

impl Default for JoinerLimits {
    fn default() -> Self {
        Self {
            attempts_per_flow: JOINER_ATTEMPTS_PER_FLOW,
        }
    }
}

/// What the joiner shows when a code attempt fails. The joiner cannot tell
/// a mistyped code from a swapped link, so it names both.
pub const CODE_FAILED_MESSAGE: &str = "That code didn't work. If you typed it exactly as shown on the other device, the link may have been swapped; get a new one another way.";

/// Domain string at key 1 of a stored [`JoinerRecord`].
pub const JOINER_RECORD_DOMAIN: &str = "mousse-joiner-flow-v1";

/// How the ticket reached this device. The joiner believes a ticket's kind
/// only as far as its arrival supports it: an "in person" ticket skips the
/// code, so it is accepted only from the app's own scanner, pointed at the
/// host's screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// Scanned with Mousse's own in-app scanner.
    InAppScan,
    /// Any other way: a URL opened from another app or the browser, a
    /// paste, or a QR code opened by the system camera. Anyone along the
    /// way may have swapped it.
    Link,
}

/// Where the joiner stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinerState {
    /// Not connected to the host (yet, or again).
    Connecting,
    /// Proof sent; waiting for `AUTHORIZED`.
    AwaitingAdmission,
    /// In person: waiting for the owner's tap on the host.
    AwaitingApproval,
    /// Send link: waiting for the owner to type the code.
    AwaitingCode,
    /// A code attempt is in progress.
    Exchanging,
    /// This side verified the host's confirmation; waiting for `PAIRED`.
    AwaitingPaired,
    /// Done.
    Paired,
    /// The host already has a live grant for this device: paired.
    AlreadyPaired,
    /// The flow ended.
    Failed(ErrorCode),
}

/// How this device names itself to the host in `JOIN_PROOF` (wire.md
/// 10.3). The flow composes the name it sends from the ticket's kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinerName {
    /// The computer's name, such as `Phone`.
    pub computer: String,
    /// The profile label, such as `Work`. Sent only with an in-person
    /// ticket (which comes from the in-app scanner), as
    /// `<computer> (<profile>)`; a "Send link" proof carries the computer
    /// name alone.
    pub profile: Option<String>,
}

impl JoinerName {
    /// The `JOIN_PROOF` name for a ticket of `kind`.
    pub fn for_kind(&self, kind: InvitationKind) -> String {
        match (kind, &self.profile) {
            (InvitationKind::InPerson, Some(profile)) => {
                format!("{} ({profile})", self.computer)
            }
            _ => self.computer.clone(),
        }
    }
}

/// The paired host, to store as a pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedHost {
    /// Host identity (from the ticket, proven by TLS).
    pub identity: IdentityPublicKey,
    /// Host display name.
    pub name: String,
    /// The role the host granted.
    pub role: Role,
}

/// Something the I/O layer or UI must do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinerAction {
    /// Send this control message to the host.
    Send(ControlMessage),
    /// Store `record` durably under its ticket hash, atomically and only
    /// if the stored record is still `expected` (`None`: no record yet).
    /// Then call [`JoinerPairing::on_persisted`], which hands out the
    /// actions that were waiting for this write; if the stored record has
    /// changed (another flow on the same ticket wrote it) or the write
    /// fails, call [`JoinerPairing::on_persist_failed`]. Pass the flow no
    /// other event before one of the two.
    Persist {
        /// The record this flow last stored or loaded.
        expected: Option<JoinerRecord>,
        /// The record to store.
        record: JoinerRecord,
    },
    /// Pairing finished: this invitation enrolled the device with `role`.
    /// Store the pin, then call [`JoinerPairing::on_pin_stored`]. Also how
    /// a joiner whose `PAIRED` was lost learns, on a later connection, that
    /// it was enrolled: the host answers its proof with `PAIRED` again.
    Paired(PairedHost),
    /// The host grants this device, but not through this flow's
    /// invitation: the device keeps the access it had, and the role this
    /// invitation offered is not in effect. Pin
    /// [`JoinerPairing::expected_host`], then call
    /// [`JoinerPairing::on_pin_stored`]. With a "Send link" ticket this
    /// happens only for a host pinned before the flow
    /// ([`JoinerPairing::set_host_pinned`]) or after this flow's own
    /// exchange verified the host; otherwise the flow fails with
    /// `PAIRING_FAILED`.
    AlreadyPaired,
    /// The code was wrong (or the attempt failed); the owner may retype.
    CodeRejected {
        /// Attempts left in this flow.
        attempts_left: u8,
    },
    /// The flow ended for good.
    Failed(ErrorCode),
}

/// Why a joiner call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinerError {
    /// The call does not fit the current state.
    WrongState,
    /// No code attempts are left in this flow.
    AttemptsExhausted,
    /// The ticket expired.
    Expired,
    /// The device name is empty or too long (the computer name or the
    /// profile label is empty, or the name the proof would send is over
    /// 128 bytes).
    InvalidName,
    /// An "in person" ticket that did not come from the in-app scanner
    /// ([`Arrival::Link`]). Refused before dialing: `PAIRING_FAILED`.
    InPersonFromLink,
    /// The ticket names this device's own identity as the host.
    OwnTicket,
    /// The stored record is for another ticket, or does not parse.
    BadRecord,
}

impl JoinerError {
    /// The error code the app reports when this error ends the flow.
    pub fn code(self) -> Option<ErrorCode> {
        match self {
            JoinerError::InPersonFromLink | JoinerError::OwnTicket => {
                Some(ErrorCode::PairingFailed)
            }
            JoinerError::AttemptsExhausted => Some(ErrorCode::AttemptsExhausted),
            JoinerError::Expired => Some(ErrorCode::InvitationInvalid),
            JoinerError::WrongState | JoinerError::InvalidName | JoinerError::BadRecord => None,
        }
    }
}

impl fmt::Display for JoinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JoinerError::WrongState => "not possible in the current pairing state",
            JoinerError::AttemptsExhausted => "no code attempts left",
            JoinerError::Expired => "pairing ticket has expired",
            JoinerError::InvalidName => "invalid device name",
            JoinerError::InPersonFromLink => {
                "an in-person ticket must be scanned with the app's own scanner"
            }
            JoinerError::OwnTicket => "this ticket is this device's own invitation",
            JoinerError::BadRecord => "the stored pairing record is not for this ticket",
        })
    }
}

impl std::error::Error for JoinerError {}

/// The durable part of a flow: what must survive the app being killed and
/// the link being opened again. Keyed by the ticket hash; the storage is
/// local, and [`JoinerRecord::to_bytes`] is one way to keep it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinerRecord {
    /// The ticket hash (wire.md 10.2) this record belongs to.
    pub ticket_hash: [u8; 32],
    /// Code attempts left.
    pub attempts_left: u8,
    /// This side sent its confirmation and has not learned the outcome.
    pub outcome_pending: bool,
}

impl JoinerRecord {
    /// Canonical CBOR: `{1: "mousse-joiner-flow-v1", 2: ticket hash,
    /// 3: attempts left, 4: 1 if an outcome is pending else 0}`.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (1, Value::Text(JOINER_RECORD_DOMAIN.to_owned())),
            (2, Value::Bytes(self.ticket_hash.to_vec())),
            (3, Value::Uint(u64::from(self.attempts_left))),
            (4, Value::Uint(u64::from(self.outcome_pending))),
        ]))
    }

    /// Parse [`JoinerRecord::to_bytes`] output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JoinerError> {
        let bad = |_| JoinerError::BadRecord;
        let mut f = Fields::decode(bytes).map_err(bad)?;
        if f.text(1).map_err(bad)? != JOINER_RECORD_DOMAIN {
            return Err(JoinerError::BadRecord);
        }
        let ticket_hash = f.fixed::<32>(2).map_err(bad)?;
        let attempts_left = match f.uint(3).map_err(bad)? {
            n if n <= u64::from(JOINER_ATTEMPTS_PER_FLOW) => n as u8,
            _ => return Err(JoinerError::BadRecord),
        };
        let outcome_pending = match f.uint(4).map_err(bad)? {
            0 => false,
            1 => true,
            _ => return Err(JoinerError::BadRecord),
        };
        f.finish().map_err(bad)?;
        Ok(Self {
            ticket_hash,
            attempts_left,
            outcome_pending,
        })
    }
}

impl JoinerRecord {
    /// The record of a flow that has stored nothing yet, with
    /// `attempts` code attempts.
    pub fn fresh(ticket_hash: [u8; 32], attempts: u8) -> Self {
        Self {
            ticket_hash,
            attempts_left: attempts,
            outcome_pending: false,
        }
    }
}

struct JoinerAttempt<E> {
    id: AttemptId,
    exchange: Option<E>,
}

/// The joiner side of pairing.
pub struct JoinerPairing<F: CodeExchangeFactory> {
    ticket: Ticket,
    ticket_hash: [u8; 32],
    joiner: IdentityPublicKey,
    name: String,
    factory: F,
    state: JoinerState,
    /// Attempts a flow with nothing stored starts with.
    attempts_per_flow: u8,
    attempts_left: u8,
    attempt: Option<JoinerAttempt<F::Exchange>>,
    exporters: Option<SessionExporters>,
    /// The joiner sent its confirmation but the connection closed before
    /// `PAIRED`: the host may have enrolled it. The next connection learns
    /// the outcome, even with no attempts or ticket time left.
    outcome_pending: bool,
    /// This device already held a pin for the ticket's host before the
    /// flow started (it paired with that host earlier, not through this
    /// ticket).
    host_pinned: bool,
    /// On this connection the host has already said `AUTHORIZED {live}`
    /// once, from step 2 before it read the proof. The answer to the proof
    /// is the next `AUTHORIZED`, or `PAIRED`.
    live_before_answer: bool,
    /// The record as stored, as far as this flow knows: loaded at start or
    /// last written. `None`: nothing stored yet.
    saved: Option<JoinerRecord>,
    /// A [`JoinerAction::Persist`] the I/O layer has not finished.
    in_flight: Option<JoinerRecord>,
    /// Actions waiting for `in_flight` to be durable.
    held: Vec<JoinerAction>,
    /// The outcome was reported; clear the pending mark once the pin is
    /// stored ([`JoinerPairing::on_pin_stored`]).
    clear_after_pin: bool,
}

impl<F: CodeExchangeFactory> JoinerPairing<F> {
    /// Start a flow from a ticket that arrived by `arrival`. `stored` is
    /// the [`JoinerRecord`] kept for this ticket hash by an earlier start,
    /// if any: the flow then goes on with its attempt count and pending
    /// outcome. Every refusal here happens before dialing. Uses the default
    /// [`JoinerLimits`]; see [`JoinerPairing::with_limits`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket: Ticket,
        arrival: Arrival,
        joiner: IdentityPublicKey,
        name: JoinerName,
        factory: F,
        stored: Option<&JoinerRecord>,
        now: UnixTime,
    ) -> Result<Self, JoinerError> {
        Self::with_limits(
            ticket,
            arrival,
            joiner,
            name,
            factory,
            stored,
            now,
            JoinerLimits::default(),
        )
    }

    /// [`JoinerPairing::new`] with other limits.
    #[allow(clippy::too_many_arguments)]
    pub fn with_limits(
        ticket: Ticket,
        arrival: Arrival,
        joiner: IdentityPublicKey,
        name: JoinerName,
        factory: F,
        stored: Option<&JoinerRecord>,
        now: UnixTime,
        limits: JoinerLimits,
    ) -> Result<Self, JoinerError> {
        let attempts_per_flow = limits.attempts_per_flow.min(JOINER_ATTEMPTS_PER_FLOW);
        if ticket.host_identity == joiner {
            return Err(JoinerError::OwnTicket);
        }
        // The kind is believed only as far as the arrival supports it: a
        // swapped link must not skip the code by claiming "in person".
        if ticket.kind == InvitationKind::InPerson && arrival != Arrival::InAppScan {
            return Err(JoinerError::InPersonFromLink);
        }
        validate_name(&name.computer).map_err(|_| JoinerError::InvalidName)?;
        if name.profile.as_deref() == Some("") {
            return Err(JoinerError::InvalidName);
        }
        let name = name.for_kind(ticket.kind);
        validate_name(&name).map_err(|_| JoinerError::InvalidName)?;
        let ticket_hash = ticket.hash();
        let (attempts_left, outcome_pending) = match stored {
            Some(record) if record.ticket_hash != ticket_hash => {
                return Err(JoinerError::BadRecord)
            }
            Some(record) => (
                record.attempts_left.min(attempts_per_flow),
                record.outcome_pending,
            ),
            None => (attempts_per_flow, false),
        };
        // A pending outcome is learned from step 2, which needs no fresh
        // ticket: a grant outlives its invitation.
        if !outcome_pending {
            ticket
                .check_fresh_for_joiner(now)
                .map_err(|_| JoinerError::Expired)?;
            if ticket.kind == InvitationKind::SendLink && attempts_left == 0 {
                return Err(JoinerError::AttemptsExhausted);
            }
        }
        Ok(Self {
            ticket_hash,
            ticket,
            joiner,
            name,
            factory,
            state: JoinerState::Connecting,
            attempts_per_flow,
            attempts_left,
            attempt: None,
            exporters: None,
            outcome_pending,
            host_pinned: false,
            live_before_answer: false,
            saved: stored.copied(),
            in_flight: None,
            held: Vec::new(),
            clear_after_pin: false,
        })
    }

    /// The flow's durable part as it stands in memory. The flow asks for
    /// each write itself, with [`JoinerAction::Persist`].
    pub fn record(&self) -> JoinerRecord {
        JoinerRecord {
            ticket_hash: self.ticket_hash,
            attempts_left: self.attempts_left,
            outcome_pending: self.outcome_pending,
        }
    }

    /// Say whether this device already holds a pin for the ticket's host
    /// from an earlier pairing. Only then may a "Send link" flow end
    /// "already paired" on a first `AUTHORIZED {live}`: a link can be
    /// swapped in transit, and a swapped link that names another host's
    /// key must not be pinned without the code exchange.
    pub fn set_host_pinned(&mut self, pinned: bool) {
        self.host_pinned = pinned;
    }

    /// The host identity to pin for step 1 on every connection of this flow.
    pub fn expected_host(&self) -> &IdentityPublicKey {
        &self.ticket.host_identity
    }

    /// The ticket.
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    /// Current state.
    pub fn state(&self) -> JoinerState {
        self.state
    }

    /// Code attempts left in this flow.
    pub fn attempts_left(&self) -> u8 {
        self.attempts_left
    }

    /// This side verified the host's confirmation and released its own,
    /// and has not learned whether the host enrolled it. A new connection
    /// learns it from the answer to the join proof: `PAIRED` means it did.
    pub fn outcome_pending(&self) -> bool {
        self.outcome_pending
    }

    /// The last [`JoinerAction::Persist`] is durable. Returns the actions
    /// that were waiting for it.
    pub fn on_persisted(&mut self) -> Vec<JoinerAction> {
        match self.in_flight.take() {
            Some(record) => {
                self.saved = Some(record);
                std::mem::take(&mut self.held)
            }
            None => Vec::new(),
        }
    }

    /// The last [`JoinerAction::Persist`] did not happen: the write failed,
    /// or another flow on the same ticket changed the stored record first.
    /// Nothing that was waiting for it is sent. The flow ends with
    /// `INTERNAL_ERROR`, unless it had already reached its outcome (then
    /// the pending mark stays stored and a later start learns the outcome
    /// again); opening the ticket again starts from the stored record.
    pub fn on_persist_failed(&mut self) -> Vec<JoinerAction> {
        if self.in_flight.take().is_none() {
            return Vec::new();
        }
        self.held.clear();
        if matches!(self.state, JoinerState::Paired | JoinerState::AlreadyPaired) {
            return Vec::new();
        }
        self.fail(ErrorCode::InternalError)
    }

    /// The pin from [`JoinerAction::Paired`] or
    /// [`JoinerAction::AlreadyPaired`] is durable. Clears the
    /// outcome-pending mark, which may go only once the result is stored.
    pub fn on_pin_stored(&mut self) -> Vec<JoinerAction> {
        if !std::mem::take(&mut self.clear_after_pin) {
            return Vec::new();
        }
        self.outcome_pending = false;
        self.commit(Vec::new())
    }

    /// The host's answer to the join proof did not arrive in time (the
    /// caller's wait, 10 s by default, wire.md 8.2): the I/O layer closes
    /// the connection with `NOT_AUTHORIZED`. The flow ends and does
    /// not reconnect on its own, also while it is learning a pending
    /// outcome; the pending mark stays stored, so opening the same ticket
    /// again asks again (wire.md 10.6 rule 7).
    pub fn on_proof_timeout(&mut self) -> Vec<JoinerAction> {
        if self.state != JoinerState::AwaitingAdmission {
            return Vec::new();
        }
        self.fail(ErrorCode::NotAuthorized)
    }

    /// A new TLS connection to the pinned host is up. Returns the
    /// `JOIN_PROOF` to send after `HELLO`. Any attempt in progress on an
    /// older connection is abandoned; its debit stays.
    pub fn on_connected(
        &mut self,
        exporters: SessionExporters,
        now: UnixTime,
    ) -> Result<ControlMessage, JoinerError> {
        if matches!(
            self.state,
            JoinerState::Paired | JoinerState::AlreadyPaired | JoinerState::Failed(_)
        ) {
            return Err(JoinerError::WrongState);
        }
        // A pending outcome is learned from step 2, which needs no fresh
        // ticket: a grant outlives its invitation.
        if !self.outcome_pending && self.ticket.check_fresh_for_joiner(now).is_err() {
            self.state = JoinerState::Failed(ErrorCode::InvitationInvalid);
            return Err(JoinerError::Expired);
        }
        self.attempt = None;
        self.held.clear();
        self.exporters = Some(exporters);
        self.live_before_answer = false;
        self.state = JoinerState::AwaitingAdmission;
        let mac = join_proof_mac(
            &self.ticket.secret,
            &self.ticket.invitation,
            &self.ticket.host_identity,
            &self.joiner,
            &exporters.join,
        );
        Ok(ControlMessage::JoinProof {
            invitation: self.ticket.invitation,
            mac,
            name: self.name.clone(),
        })
    }

    /// The host sent `AUTHORIZED`.
    ///
    /// A host whose grant table already holds this device says
    /// `AUTHORIZED {live}` from step 2, before it reads the proof, and then
    /// answers the proof: `AUTHORIZED {join_only}` when the proof opens a
    /// pairing (which will replace the grant), `PAIRED` when this ticket's
    /// invitation made the grant ([`JoinerPairing::on_paired`]), and
    /// `AUTHORIZED {live}` otherwise. The first `live` is therefore only a
    /// notice; the flow acts on the answer.
    pub fn on_authorized(&mut self, state: AuthorizedState) -> Vec<JoinerAction> {
        if self.state != JoinerState::AwaitingAdmission {
            return self.fail(ErrorCode::ProtocolError);
        }
        if state == AuthorizedState::Live && !self.live_before_answer {
            self.live_before_answer = true;
            return Vec::new();
        }
        match state {
            AuthorizedState::JoinOnly => {
                // Not enrolled: a pending outcome is settled.
                self.outcome_pending = false;
                let actions =
                    if self.ticket.kind == InvitationKind::SendLink && self.attempts_left == 0 {
                        // No attempts left to try again.
                        self.fail(ErrorCode::AttemptsExhausted)
                    } else {
                        self.state = match self.ticket.kind {
                            InvitationKind::InPerson => JoinerState::AwaitingApproval,
                            InvitationKind::SendLink => JoinerState::AwaitingCode,
                        };
                        Vec::new()
                    };
                self.commit(actions)
            }
            AuthorizedState::Live => {
                if !self.answer_is_believed() {
                    return self.fail(ErrorCode::PairingFailed);
                }
                // Access exists, but not from this invitation: the role it
                // offered is not in effect. A pending outcome is settled
                // the same way, once the pin is stored.
                self.clear_after_pin = self.outcome_pending;
                self.state = JoinerState::AlreadyPaired;
                vec![JoinerAction::AlreadyPaired]
            }
        }
    }

    /// Whether a live host's answer that ends the flow paired (`AUTHORIZED
    /// {live}`, or `PAIRED` for a receipt) can be believed. A send link
    /// proves the host only through the code exchange, so the answer is
    /// believed only for a host this device pinned before the flow, or once
    /// this flow's own exchange verified the host (a pending outcome). An
    /// in-person ticket came from the in-app scanner.
    fn answer_is_believed(&self) -> bool {
        self.ticket.kind == InvitationKind::InPerson || self.host_pinned || self.outcome_pending
    }

    /// Send link: the owner typed a code. Debits one attempt before any
    /// exchange work, then returns the first exchange message.
    pub fn submit_code<R: CryptoRng + ?Sized>(
        &mut self,
        code: &PairingCode,
        rng: &mut R,
    ) -> Result<Vec<JoinerAction>, JoinerError> {
        if self.state != JoinerState::AwaitingCode {
            return Err(JoinerError::WrongState);
        }
        if self.attempts_left == 0 {
            return Err(JoinerError::AttemptsExhausted);
        }
        let exporters = self.exporters.ok_or(JoinerError::WrongState)?;
        // Debit first. Nothing below runs on an undebited attempt.
        self.attempts_left -= 1;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let attempt = AttemptId(id);
        let binding = binding_transcript(
            &self.ticket_hash,
            self.ticket.kind,
            self.ticket.version,
            &self.ticket.host_identity,
            &self.joiner,
            &exporters.pair,
        );
        let sid = attempt_sid(&attempt, &exporters.pair);
        let mut exchange = self
            .factory
            .start(ExchangeRole::Initiator, code, &binding, &sid, rng);
        let actions = match exchange.step(None) {
            Ok(step) => match step.send {
                Some(payload) => {
                    let message = ControlMessage::CodeExchange { attempt, payload };
                    self.attempt = Some(JoinerAttempt {
                        id: attempt,
                        exchange: Some(exchange),
                    });
                    self.state = JoinerState::Exchanging;
                    vec![JoinerAction::Send(message)]
                }
                None => self.attempt_failed(attempt, true),
            },
            Err(_) => self.attempt_failed(attempt, true),
        };
        // The debit is durable before the first share goes out.
        Ok(self.commit(actions))
    }

    /// The host sent `CODE_EXCHANGE`. A message that does not fit the
    /// attempt's next step, including a repeat, fails the attempt.
    pub fn on_code_exchange(&mut self, attempt: AttemptId, payload: &[u8]) -> Vec<JoinerAction> {
        if self.state != JoinerState::Exchanging {
            return Vec::new();
        }
        let Some(current) = self.attempt.as_mut() else {
            return Vec::new();
        };
        if current.id != attempt {
            return Vec::new(); // a late message for an abandoned attempt
        }
        let Some(exchange) = current.exchange.as_mut() else {
            return Vec::new();
        };
        match exchange.step(Some(payload)) {
            Ok(step) => {
                let mut actions = Vec::new();
                if let Some(payload) = step.send {
                    actions.push(JoinerAction::Send(ControlMessage::CodeExchange {
                        attempt,
                        payload,
                    }));
                }
                if step.peer_confirmed {
                    current.exchange = None;
                    self.state = JoinerState::AwaitingPaired;
                    // From here the host may enroll this device. The
                    // outcome is marked pending durably before this side's
                    // confirmation goes out, so a crash right after sending
                    // it cannot forget it.
                    self.outcome_pending = true;
                    return self.commit(actions);
                }
                actions
            }
            Err(_) => self.attempt_failed(attempt, true),
        }
    }

    /// The host sent `CODE_ABORT` for an attempt. Its debit stays.
    pub fn on_code_abort(&mut self, attempt: AttemptId) -> Vec<JoinerAction> {
        let current = self.attempt.as_ref().map(|a| a.id);
        if current != Some(attempt)
            || !matches!(
                self.state,
                JoinerState::Exchanging | JoinerState::AwaitingPaired
            )
        {
            return Vec::new();
        }
        // The host refused this side's confirmation: not enrolled.
        self.outcome_pending = false;
        let actions = self.attempt_failed(attempt, false);
        self.commit(actions)
    }

    /// The host sent `PAIRED`: after enrolling this device on this
    /// connection, or as its answer to the join proof on a connection that
    /// was live from step 2, because this ticket's invitation made the
    /// grant (its enrollment receipt, wire.md 10.6 rule 7).
    pub fn on_paired(&mut self, host_name: String, role: Role) -> Vec<JoinerAction> {
        let ok = match self.state {
            // The answer to the proof.
            JoinerState::AwaitingAdmission if self.live_before_answer => {
                if !self.answer_is_believed() {
                    return self.fail(ErrorCode::PairingFailed);
                }
                true
            }
            JoinerState::AwaitingApproval => self.ticket.kind == InvitationKind::InPerson,
            // Only after this side verified the host's confirmation.
            JoinerState::AwaitingPaired => self.ticket.kind == InvitationKind::SendLink,
            _ => false,
        };
        if !ok {
            return self.fail(ErrorCode::ProtocolError);
        }
        self.state = JoinerState::Paired;
        self.attempt = None;
        self.clear_after_pin = self.outcome_pending;
        vec![JoinerAction::Paired(PairedHost {
            identity: self.ticket.host_identity,
            name: host_name,
            role,
        })]
    }

    /// The connection closed, with the peer's `GOAWAY` code if there was one.
    pub fn on_closed(&mut self, code: Option<ErrorCode>) -> Vec<JoinerAction> {
        if matches!(
            self.state,
            JoinerState::Paired | JoinerState::AlreadyPaired | JoinerState::Failed(_)
        ) {
            return Vec::new();
        }
        self.attempt = None;
        self.exporters = None;
        self.held.clear();
        match code {
            Some(c @ (ErrorCode::AttemptsExhausted | ErrorCode::InvitationInvalid)) => {
                // A host that holds a grant for this device never closes a
                // proof this way: not enrolled.
                self.outcome_pending = false;
                let actions = self.fail(c);
                self.commit(actions)
            }
            Some(
                c @ (ErrorCode::PairingDeclined | ErrorCode::Cancelled | ErrorCode::NotAuthorized),
            ) => self.fail(c),
            _ => {
                self.state = if self.attempts_left == 0 && !self.outcome_pending {
                    JoinerState::Failed(ErrorCode::AttemptsExhausted)
                } else {
                    JoinerState::Connecting
                };
                Vec::new()
            }
        }
    }

    /// Ask for a write if the record changed since it was last stored;
    /// `then` waits for it.
    fn commit(&mut self, then: Vec<JoinerAction>) -> Vec<JoinerAction> {
        let record = self.record();
        let stored = self
            .saved
            .unwrap_or_else(|| JoinerRecord::fresh(self.ticket_hash, self.attempts_per_flow));
        if record == stored {
            return then;
        }
        self.in_flight = Some(record);
        self.held = then;
        vec![JoinerAction::Persist {
            expected: self.saved,
            record,
        }]
    }

    fn attempt_failed(&mut self, attempt: AttemptId, tell_host: bool) -> Vec<JoinerAction> {
        self.attempt = None;
        let mut actions = Vec::new();
        if tell_host {
            actions.push(JoinerAction::Send(ControlMessage::CodeAbort {
                attempt,
                code: ErrorCode::PairingFailed,
            }));
        }
        if self.attempts_left == 0 {
            self.state = JoinerState::Failed(ErrorCode::AttemptsExhausted);
            actions.push(JoinerAction::Failed(ErrorCode::AttemptsExhausted));
        } else {
            self.state = JoinerState::AwaitingCode;
            actions.push(JoinerAction::CodeRejected {
                attempts_left: self.attempts_left,
            });
        }
        actions
    }

    fn fail(&mut self, code: ErrorCode) -> Vec<JoinerAction> {
        self.state = JoinerState::Failed(code);
        self.attempt = None;
        vec![JoinerAction::Failed(code)]
    }
}
