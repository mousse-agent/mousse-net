//! The joining device's pairing state machine. One value is one local
//! code-entry flow: it allows [`JOINER_ATTEMPTS_PER_FLOW`] code attempts,
//! across reconnects, so a fake host cannot make it try codes forever.
//!
//! The flow's durable part is a [`JoinerRecord`], keyed by the ticket hash.
//! The I/O layer stores it and passes it back when the same ticket is opened
//! again, so neither killing the app nor reopening the link resets the
//! attempt count or forgets a pending outcome.

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

/// Code attempts the joiner allows per local code-entry flow.
pub const JOINER_ATTEMPTS_PER_FLOW: u8 = 3;

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

/// Something the I/O layer or UI must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinerAction {
    /// Send this control message to the host.
    Send(ControlMessage),
    /// Pairing finished. Store the pin.
    Paired(PairedHost),
    /// The host already grants this device (step 2 said live). The device
    /// is paired: pin [`JoinerPairing::expected_host`]. This is also how a
    /// joiner whose `PAIRED` was lost learns that it was enrolled. With a
    /// "Send link" ticket it happens only for a host pinned before the flow
    /// ([`JoinerPairing::set_host_pinned`]) or after this flow's own lost
    /// `PAIRED`; otherwise the flow fails with `PAIRING_FAILED`.
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
    /// The device name is empty or too long.
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
    /// is the next `AUTHORIZED`.
    live_before_answer: bool,
}

impl<F: CodeExchangeFactory> JoinerPairing<F> {
    /// Start a flow from a ticket that arrived by `arrival`. `stored` is
    /// the [`JoinerRecord`] kept for this ticket hash by an earlier start,
    /// if any: the flow then goes on with its attempt count and pending
    /// outcome. Every refusal here happens before dialing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket: Ticket,
        arrival: Arrival,
        joiner: IdentityPublicKey,
        name: String,
        factory: F,
        stored: Option<&JoinerRecord>,
        now: UnixTime,
    ) -> Result<Self, JoinerError> {
        if ticket.host_identity == joiner {
            return Err(JoinerError::OwnTicket);
        }
        // The kind is believed only as far as the arrival supports it: a
        // swapped link must not skip the code by claiming "in person".
        if ticket.kind == InvitationKind::InPerson && arrival != Arrival::InAppScan {
            return Err(JoinerError::InPersonFromLink);
        }
        validate_name(&name).map_err(|_| JoinerError::InvalidName)?;
        let ticket_hash = ticket.hash();
        let (attempts_left, outcome_pending) = match stored {
            Some(record) if record.ticket_hash != ticket_hash => {
                return Err(JoinerError::BadRecord)
            }
            Some(record) => (
                record.attempts_left.min(JOINER_ATTEMPTS_PER_FLOW),
                record.outcome_pending,
            ),
            None => (JOINER_ATTEMPTS_PER_FLOW, false),
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
            attempts_left,
            attempt: None,
            exporters: None,
            outcome_pending,
            host_pinned: false,
            live_before_answer: false,
        })
    }

    /// The flow's durable part. Store it, keyed by the ticket hash,
    /// whenever it changes: before sending the first message of an attempt
    /// ([`JoinerPairing::submit_code`] debits first), and after
    /// [`JoinerPairing::on_closed`] or any call that ends the flow.
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

    /// The connection closed after this side sent its confirmation and
    /// before `PAIRED` arrived. Reconnect to learn whether the host enrolled
    /// this device: `AUTHORIZED {live}` means it did.
    pub fn outcome_pending(&self) -> bool {
        self.outcome_pending
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
    /// answers the proof with a second `AUTHORIZED`: `join_only` when the
    /// proof opens a pairing (which will replace the grant), `live` when it
    /// does not. The first `live` is therefore only a notice; the flow acts
    /// on the answer.
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
                // Not enrolled, and no attempts left to try again.
                if self.ticket.kind == InvitationKind::SendLink && self.attempts_left == 0 {
                    return self.fail(ErrorCode::AttemptsExhausted);
                }
                self.state = match self.ticket.kind {
                    InvitationKind::InPerson => JoinerState::AwaitingApproval,
                    InvitationKind::SendLink => JoinerState::AwaitingCode,
                };
                Vec::new()
            }
            AuthorizedState::Live => {
                // A send link proves the host only through the code
                // exchange. "Already paired" is believed only for a host
                // this device pinned before, or as the outcome of this
                // flow's own exchange (a lost `PAIRED`).
                if self.ticket.kind == InvitationKind::SendLink
                    && !self.host_pinned
                    && !self.outcome_pending
                {
                    return self.fail(ErrorCode::PairingFailed);
                }
                // Also how a pending outcome resolves: the host enrolled us.
                self.outcome_pending = false;
                self.state = JoinerState::AlreadyPaired;
                vec![JoinerAction::AlreadyPaired]
            }
        }
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
        match exchange.step(None) {
            Ok(step) => {
                let Some(payload) = step.send else {
                    return Ok(self.attempt_failed(attempt, true));
                };
                let message = ControlMessage::CodeExchange { attempt, payload };
                self.attempt = Some(JoinerAttempt {
                    id: attempt,
                    exchange: Some(exchange),
                });
                self.state = JoinerState::Exchanging;
                Ok(vec![JoinerAction::Send(message)])
            }
            Err(_) => Ok(self.attempt_failed(attempt, true)),
        }
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
        self.attempt_failed(attempt, false)
    }

    /// The host sent `PAIRED`.
    pub fn on_paired(&mut self, host_name: String, role: Role) -> Vec<JoinerAction> {
        let ok = match self.ticket.kind {
            InvitationKind::InPerson => self.state == JoinerState::AwaitingApproval,
            // Only after this side verified the host's confirmation.
            InvitationKind::SendLink => self.state == JoinerState::AwaitingPaired,
        };
        if !ok {
            return self.fail(ErrorCode::ProtocolError);
        }
        self.state = JoinerState::Paired;
        self.attempt = None;
        self.outcome_pending = false;
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
        if self.state == JoinerState::AwaitingPaired {
            self.outcome_pending = true;
        }
        match code {
            Some(
                c @ (ErrorCode::AttemptsExhausted
                | ErrorCode::InvitationInvalid
                | ErrorCode::PairingDeclined
                | ErrorCode::Cancelled
                | ErrorCode::NotAuthorized),
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
