//! Pairing: tickets, join proofs, the code exchange seam, and the host and
//! joiner state machines.
//!
//! Two invitation kinds, chosen by the host and fixed in its pending record:
//! - **In person** (QR scanned next to the host): the joiner proves it holds
//!   the ticket, then the host owner taps once to approve. No code.
//! - **Send link**: the joiner proves it holds the ticket, then both sides run
//!   a code exchange (a PAKE over the 6-digit code shown on the host). Both
//!   confirmations are needed before the host enrolls the device.
//!
//! A third kind, **direct** (Pair with IP, kind 3), has no ticket: the joiner
//! types the host's address and a 12-character code ([`DirectCode`]). It has
//! its own host machine, [`DirectHostPairing`].
//!
//! The code exchange itself sits behind [`CodeExchange`]; the real one is
//! CPace ([`CpaceExchangeFactory`]), with the joiner as initiator and the host
//! as responder. This module owns the binding transcript and session id it
//! must use, attempt limits and atomic one-enrollment consumption.

mod direct_code;
mod direct_host;
mod exchange;
mod host;
mod joiner;
mod proof;
mod route;
mod ticket;

use std::fmt;

pub use direct_code::{
    DirectCode, DirectCodeError, DirectLookup, DirectSecret, DIRECT_CODE_ALPHABET, DIRECT_CODE_LEN,
    DIRECT_LOOKUP_LEN, DIRECT_SECRET_LEN,
};
pub use direct_host::{
    ApprovalEnd, CreatedDirectInvitation, DirectApproval, DirectHostAction, DirectHostError,
    DirectHostPairing, DirectInvitationParams, DirectInvitationStatus, DirectRequestId,
    RequestDecision, RequestPresence,
};
#[cfg(feature = "insecure-test-exchange")]
pub use exchange::insecure;
pub use exchange::{
    CodeExchange, CodeExchangeFactory, CpaceExchange, CpaceExchangeFactory, ExchangeError,
    ExchangeRole, ExchangeStep, PairingCode,
};
pub use host::{
    CreatedInvitation, HostAction, HostPairing, HostPairingError, InvitationParams,
    InvitationStatus,
};
pub use joiner::{
    Arrival, JoinerAction, JoinerError, JoinerName, JoinerPairing, JoinerRecord, JoinerState,
    PairedHost, CODE_FAILED_MESSAGE, JOINER_ATTEMPTS_PER_FLOW, JOINER_RECORD_DOMAIN,
};
pub use proof::{
    attempt_sid, binding_transcript, direct_binding_transcript, direct_invite_digest,
    join_proof_input, join_proof_mac, verify_join_proof, BindingTranscript, SessionExporters,
    DIRECT_CEREMONY_VERSION, DIRECT_INVITE_DOMAIN, DIRECT_KIND, DIRECT_PAIR_DOMAIN, EXPORTER_LEN,
    JOIN_EXPORTER_LABEL, JOIN_PROOF_DOMAIN, JOIN_PROOF_KEY_INFO, PAIR_EXPORTER_LABEL,
    PAIR_TRANSCRIPT_DOMAIN, SID_DOMAIN, SID_LEN,
};
pub use route::{
    parse_host, parse_port, parse_wss_path, Route, RouteHost, RouteSkip, MAX_DNS_NAME_LEN,
    MAX_MDNS_INSTANCE_LEN, MAX_WSS_PATH_LEN, RESERVED_SCHEMES, WSS_DEFAULT_PORT, WSS_PATH_SUFFIX,
};
pub use ticket::{Ticket, TicketError, TicketSecret, MAX_ROUTES, MAX_ROUTE_LEN, TICKET_VERSION};

/// A 16-byte random invitation id, chosen by the host.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvitationId(pub [u8; 16]);

impl fmt::Debug for InvitationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InvitationId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// A 16-byte random code-exchange attempt id, chosen by the joiner for each
/// attempt.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(pub [u8; 16]);

impl fmt::Debug for AttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AttemptId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// The invitation kind. Wire values are fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvitationKind {
    /// "Scan in person": proof of ticket, then one approval tap. No code.
    InPerson = 1,
    /// "Send link": proof of ticket, then the code exchange.
    SendLink = 2,
}

impl InvitationKind {
    /// Wire value.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// Parse a wire value.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(InvitationKind::InPerson),
            2 => Some(InvitationKind::SendLink),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
