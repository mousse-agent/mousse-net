//! The joining device's pairing state machine. One value is one local
//! code-entry flow: it allows [`JOINER_ATTEMPTS_PER_FLOW`] code attempts,
//! across reconnects, so a fake host cannot make it try codes forever.

use std::fmt;

use rand_core::CryptoRng;

use super::exchange::{CodeExchange, CodeExchangeFactory, ExchangeRole, PairingCode};
use super::proof::{binding_transcript, join_proof_mac, SessionExporters};
use super::ticket::Ticket;
use super::{AttemptId, InvitationKind};
use crate::control::{AuthorizedState, ControlMessage};
use crate::grants::{validate_name, Role};
use crate::identity::IdentityPublicKey;
use crate::time::UnixTime;
use crate::ErrorCode;

/// Code attempts the joiner allows per local code-entry flow.
pub const JOINER_ATTEMPTS_PER_FLOW: u8 = 3;

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
    /// The host already has a live grant for this device.
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
    /// The host already grants this device.
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
}

impl fmt::Display for JoinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JoinerError::WrongState => "not possible in the current pairing state",
            JoinerError::AttemptsExhausted => "no code attempts left",
            JoinerError::Expired => "pairing ticket has expired",
            JoinerError::InvalidName => "invalid device name",
        })
    }
}

impl std::error::Error for JoinerError {}

struct JoinerAttempt<E> {
    id: AttemptId,
    exchange: Option<E>,
    last_sent: ControlMessage,
    last_received: Option<Vec<u8>>,
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
}

impl<F: CodeExchangeFactory> JoinerPairing<F> {
    /// Start a flow from a scanned or opened ticket.
    pub fn new(
        ticket: Ticket,
        joiner: IdentityPublicKey,
        name: String,
        factory: F,
        now: UnixTime,
    ) -> Result<Self, JoinerError> {
        ticket
            .check_fresh_for_joiner(now)
            .map_err(|_| JoinerError::Expired)?;
        validate_name(&name).map_err(|_| JoinerError::InvalidName)?;
        Ok(Self {
            ticket_hash: ticket.hash(),
            ticket,
            joiner,
            name,
            factory,
            state: JoinerState::Connecting,
            attempts_left: JOINER_ATTEMPTS_PER_FLOW,
            attempt: None,
            exporters: None,
        })
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
        if self.ticket.check_fresh_for_joiner(now).is_err() {
            self.state = JoinerState::Failed(ErrorCode::InvitationInvalid);
            return Err(JoinerError::Expired);
        }
        self.attempt = None;
        self.exporters = Some(exporters);
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
    pub fn on_authorized(&mut self, state: AuthorizedState) -> Vec<JoinerAction> {
        if self.state != JoinerState::AwaitingAdmission {
            return self.fail(ErrorCode::ProtocolError);
        }
        match state {
            AuthorizedState::JoinOnly => {
                self.state = match self.ticket.kind {
                    InvitationKind::InPerson => JoinerState::AwaitingApproval,
                    InvitationKind::SendLink => JoinerState::AwaitingCode,
                };
                Vec::new()
            }
            AuthorizedState::Live => {
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
        let mut exchange = self
            .factory
            .start(ExchangeRole::Initiator, code, &binding, rng);
        match exchange.step(None) {
            Ok(step) => {
                let Some(payload) = step.send else {
                    return Ok(self.attempt_failed(attempt, true));
                };
                let message = ControlMessage::CodeExchange { attempt, payload };
                self.attempt = Some(JoinerAttempt {
                    id: attempt,
                    exchange: Some(exchange),
                    last_sent: message.clone(),
                    last_received: None,
                });
                self.state = JoinerState::Exchanging;
                Ok(vec![JoinerAction::Send(message)])
            }
            Err(_) => Ok(self.attempt_failed(attempt, true)),
        }
    }

    /// The last message of the current attempt, byte-identical, for a resend
    /// on the same connection.
    pub fn resend(&self) -> Option<ControlMessage> {
        match self.state {
            JoinerState::Exchanging | JoinerState::AwaitingPaired => {
                self.attempt.as_ref().map(|a| a.last_sent.clone())
            }
            _ => None,
        }
    }

    /// The host sent `CODE_EXCHANGE`.
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
        if current.last_received.as_deref() == Some(payload) {
            return Vec::new(); // the host repeated itself; we already answered
        }
        current.last_received = Some(payload.to_vec());
        let Some(exchange) = current.exchange.as_mut() else {
            return Vec::new();
        };
        match exchange.step(Some(payload)) {
            Ok(step) => {
                let mut actions = Vec::new();
                if let Some(payload) = step.send {
                    let message = ControlMessage::CodeExchange { attempt, payload };
                    current.last_sent = message.clone();
                    actions.push(JoinerAction::Send(message));
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
        match code {
            Some(
                c @ (ErrorCode::AttemptsExhausted
                | ErrorCode::InvitationInvalid
                | ErrorCode::PairingDeclined
                | ErrorCode::Cancelled
                | ErrorCode::NotAuthorized),
            ) => self.fail(c),
            _ => {
                self.state = if self.attempts_left == 0 {
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
