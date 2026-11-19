//! Invariants and the record of the first violation.

use std::collections::BTreeMap;
use std::fmt;

/// A property every run must keep. Checked after every step (and some at the
/// exact moment the observed action happens).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Invariant {
    /// At most one enrollment per invitation, across all routes.
    SingleEnrollment,
    /// Every code-exchange start (code work) is preceded by an attempt debit,
    /// on the host (per invitation) and on the joiner (per state machine).
    DebitBeforeWork,
    /// At most 3 attempts per invitation on the host and per code-entry flow
    /// on the joiner; a debit is never returned.
    AttemptCap,
    /// The host's application only accepts stream traffic (RPC, terminal) on
    /// a connection bound to a live grant.
    NoTrafficWithoutGrant,
    /// After the step that removes, denies, replaces or expires a grant, no
    /// connection bound to it is still open.
    RemovedGrantClosed,
    /// No frame other than the closing `GOAWAY` is sent or processed on a
    /// connection after its effective certificate deadline, by either
    /// device's own clock.
    NoFlowPastDeadline,
    /// A joiner that completes pairing has a matching enrollment on the host,
    /// and a joiner the host enrolled does not end its flow as failed.
    PairingAgreement,
    /// A caller only ever authenticates the identity it pinned.
    PinMatch,
    /// Step 1 accepts exactly when the spec's window and pin rules say so.
    Step1Spec,
    /// Grant ids are never reused on a host whose grant store survives.
    GrantIdsUnique,
    /// Endpoints that share a computer are independent: a deny or removal on
    /// one never changes another's grants or closes its channels.
    EndpointIsolation,
    /// A dial that reaches the wrong endpoint fails the pin and moves no
    /// data.
    WrongEndpointNoData,
    /// The relay admits a call only for a caller in the target's current
    /// allow-set with a valid proof, and a join only with a live invitation
    /// tag.
    RelayAllowSetOnly,
    /// Every refused call or join is answered exactly at its refusal
    /// deadline; an admitted one never before it.
    RelayOneAnswer,
    /// Once the relay accepts an allow-set, no call circuit of a caller it
    /// no longer lists is open.
    RelayRemovalCloses,
    /// An unpromoted join circuit forwards at most the pre-accept budget
    /// each way.
    RelayPreacceptBudget,
    /// The relay registers only keys on the operator's list.
    RelayRegisterAuthorized,
}

impl Invariant {
    /// Every invariant.
    pub const ALL: [Invariant; 17] = [
        Invariant::SingleEnrollment,
        Invariant::DebitBeforeWork,
        Invariant::AttemptCap,
        Invariant::NoTrafficWithoutGrant,
        Invariant::RemovedGrantClosed,
        Invariant::NoFlowPastDeadline,
        Invariant::PairingAgreement,
        Invariant::PinMatch,
        Invariant::Step1Spec,
        Invariant::GrantIdsUnique,
        Invariant::EndpointIsolation,
        Invariant::WrongEndpointNoData,
        Invariant::RelayAllowSetOnly,
        Invariant::RelayOneAnswer,
        Invariant::RelayRemovalCloses,
        Invariant::RelayPreacceptBudget,
        Invariant::RelayRegisterAuthorized,
    ];

    /// Short kebab-case name.
    pub fn name(self) -> &'static str {
        match self {
            Invariant::SingleEnrollment => "single-enrollment",
            Invariant::DebitBeforeWork => "debit-before-work",
            Invariant::AttemptCap => "attempt-cap",
            Invariant::NoTrafficWithoutGrant => "no-traffic-without-grant",
            Invariant::RemovedGrantClosed => "removed-grant-closed",
            Invariant::NoFlowPastDeadline => "no-flow-past-deadline",
            Invariant::PairingAgreement => "pairing-agreement",
            Invariant::PinMatch => "pin-match",
            Invariant::Step1Spec => "step1-spec",
            Invariant::GrantIdsUnique => "grant-ids-unique",
            Invariant::EndpointIsolation => "endpoint-isolation",
            Invariant::WrongEndpointNoData => "wrong-endpoint-no-data",
            Invariant::RelayAllowSetOnly => "relay-allow-set-only",
            Invariant::RelayOneAnswer => "relay-one-answer",
            Invariant::RelayRemovalCloses => "relay-removal-closes",
            Invariant::RelayPreacceptBudget => "relay-preaccept-budget",
            Invariant::RelayRegisterAuthorized => "relay-register-authorized",
        }
    }
}

impl fmt::Display for Invariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One broken invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Which one.
    pub invariant: Invariant,
    /// Virtual time, in milliseconds.
    pub at_ms: u64,
    /// What was seen.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {}.{:03}s: {}",
            self.invariant,
            self.at_ms / 1000,
            self.at_ms % 1000,
            self.detail
        )
    }
}

/// Run-wide observations the invariants need.
#[derive(Default)]
pub(crate) struct Checker {
    pub violation: Option<Violation>,
    /// Enrollments per (host device, pairing instance, invitation id).
    pub enrollments: BTreeMap<(usize, u64, [u8; 16]), u32>,
}

impl Checker {
    /// Record a violation. Only the first one is kept; the run stops after it.
    pub(crate) fn fail(&mut self, invariant: Invariant, at_ms: u64, detail: String) {
        if self.violation.is_none() {
            self.violation = Some(Violation {
                invariant,
                at_ms,
                detail,
            });
        }
    }

    /// An enrollment happened. Returns how many there now are for that
    /// invitation.
    pub(crate) fn enrolled(&mut self, host: usize, instance: u64, invitation: [u8; 16]) -> u32 {
        let n = self
            .enrollments
            .entry((host, instance, invitation))
            .or_insert(0);
        *n += 1;
        *n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_first_violation_is_kept() {
        let mut c = Checker::default();
        c.fail(Invariant::PinMatch, 5, "first".into());
        c.fail(Invariant::AttemptCap, 6, "second".into());
        let v = c.violation.unwrap();
        assert_eq!(v.invariant, Invariant::PinMatch);
        assert_eq!(v.detail, "first");
    }

    #[test]
    fn a_second_enrollment_for_one_invitation_is_counted() {
        let mut c = Checker::default();
        assert_eq!(c.enrolled(0, 1, [7; 16]), 1);
        assert_eq!(c.enrolled(0, 1, [8; 16]), 1);
        assert_eq!(c.enrolled(0, 1, [7; 16]), 2);
    }
}
