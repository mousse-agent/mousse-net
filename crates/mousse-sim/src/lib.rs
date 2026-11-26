//! Seeded, deterministic simulator for the mousse-net core.
//!
//! One run is one `(drill, seed)` pair. The seed feeds a single ChaCha20 RNG,
//! the only source of randomness. Time is virtual: a monotonic clock in
//! milliseconds, and per device a wall clock (`T0 + skew + elapsed`). There
//! are no threads, no sockets and no wall clock, so the same seed always
//! produces the same event log, byte for byte.
//!
//! Simulated devices drive the real core state machines: [`HostPairing`],
//! [`JoinerPairing`], [`ConnectionGate`], [`GrantTable`], [`Mux`] and
//! [`PeerSession`], over a virtual network of reliable byte pipes with
//! injected faults. TLS is abstracted as an authenticated pipe; see
//! [`certs`] for exactly what is and is not modelled.
//!
//! After every step the run checks the invariants in [`Invariant`]. The first
//! violation ends the run and is reported with a replay command.
//!
//! [`HostPairing`]: mousse_net_core::pairing::HostPairing
//! [`JoinerPairing`]: mousse_net_core::pairing::JoinerPairing
//! [`ConnectionGate`]: mousse_net_core::authz::ConnectionGate
//! [`GrantTable`]: mousse_net_core::grants::GrantTable
//! [`Mux`]: mousse_net_core::mux::Mux
//! [`PeerSession`]: mousse_net_core::session::PeerSession
#![forbid(unsafe_code)]

mod caller;
pub mod certs;
mod check;
mod drills;
mod exchange;
mod host;
mod log;
mod relay;
mod sim;
mod world;

use std::fmt;
use std::str::FromStr;

pub use check::{Invariant, Violation};
pub use exchange::ExchangeImpl;

/// A named set of scenarios. Each seed picks one variant and its faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Drill {
    /// Certificate windows, clock skew, wrong pin on reconnect, expiry
    /// mid-channel, renewal, path switch, grant removal, host restart.
    Handshake,
    /// Wrong codes, aborts, reconnects between attempts, two joiners racing
    /// across two routes, ticket expiry, host restart mid-pairing, a fake host.
    PairingLimits,
    /// Two endpoints (profiles) on one computer, one identity granted on
    /// both: deny or removal on one endpoint, dials that reach the other
    /// endpoint's port, both restarting.
    SharedEndpoints,
    /// One self-hosted relay: registrations, allow-set pushes and removals,
    /// listed, unlisted and bad-proof calls, joins and promotion, accept
    /// legs, revocation, reboots and key rotation.
    RelayAdmission,
}

impl Drill {
    /// Every drill.
    pub const ALL: [Drill; 4] = [
        Drill::Handshake,
        Drill::PairingLimits,
        Drill::SharedEndpoints,
        Drill::RelayAdmission,
    ];

    /// The CLI name.
    pub fn name(self) -> &'static str {
        match self {
            Drill::Handshake => "handshake",
            Drill::PairingLimits => "pairing-limits",
            Drill::SharedEndpoints => "shared-endpoints",
            Drill::RelayAdmission => "relay-admission",
        }
    }

    /// The variants this drill picks from.
    pub fn variants(self) -> &'static [&'static str] {
        match self {
            Drill::Handshake => drills::HANDSHAKE_ALL,
            Drill::PairingLimits => drills::PAIRING_VARIANTS,
            Drill::SharedEndpoints => drills::SHARED_VARIANTS,
            Drill::RelayAdmission => relay::RELAY_VARIANTS,
        }
    }
}

impl fmt::Display for Drill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Drill {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Drill::ALL
            .into_iter()
            .find(|d| d.name() == s)
            .ok_or_else(|| {
                let names: Vec<&str> = Drill::ALL.iter().map(|d| d.name()).collect();
                format!("unknown drill {s:?}; known: {}", names.join(", "))
            })
    }
}

/// A deliberately planted bug in the simulated devices' I/O layer. Each one
/// must make its drill report a violation of [`Bug::expected`]. These are the
/// must-fail controls: they prove the invariant checks can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bug {
    /// The host ignores the grant table's "close these channels" event, so a
    /// removed grant keeps its connections.
    KeepChannelAfterRemoval,
    /// The host pre-computes its exchange share as soon as a joiner is
    /// admitted, before any attempt is debited.
    HostWorkBeforeDebit,
    /// The joiner pre-computes its first exchange message before the code is
    /// submitted (so before the debit).
    JoinerWorkBeforeDebit,
    /// The joiner starts a fresh pairing state machine on every reconnect and
    /// ignores its stored record, so its 3-attempt limit for the ticket resets.
    JoinerNewFlowOnReconnect,
    /// Devices never run the session deadline, so traffic continues past the
    /// certificate's effective deadline.
    SkipDeadline,
    /// The host hands stream frames to the application without asking the
    /// connection gate.
    HostIgnoreGate,
    /// A paired device verifies the host's certificate without its pin on
    /// reconnects and path switches.
    NoPinOnReconnect,
    /// The endpoints on one computer share one grant table, so a deny or
    /// removal on one endpoint also applies on the other.
    SharedGrantTable,
    /// The verifier ignores the session certificate's validity window.
    AcceptExpiredCert,
    /// The relay's timer runs on a clock ahead of the rest of the relay, so
    /// refused calls are answered before their deadline.
    RelayEarlyAnswer,
    /// After a reboot the relay reapplies a target's old allow-set when it
    /// registers again, before the target pushes a fresh one.
    RelayStaleAllowSet,
}

impl Bug {
    /// Every planted bug.
    pub const ALL: [Bug; 11] = [
        Bug::KeepChannelAfterRemoval,
        Bug::HostWorkBeforeDebit,
        Bug::JoinerWorkBeforeDebit,
        Bug::JoinerNewFlowOnReconnect,
        Bug::SkipDeadline,
        Bug::HostIgnoreGate,
        Bug::NoPinOnReconnect,
        Bug::SharedGrantTable,
        Bug::AcceptExpiredCert,
        Bug::RelayEarlyAnswer,
        Bug::RelayStaleAllowSet,
    ];

    /// The CLI name.
    pub fn name(self) -> &'static str {
        match self {
            Bug::KeepChannelAfterRemoval => "keep-channel-after-removal",
            Bug::HostWorkBeforeDebit => "host-work-before-debit",
            Bug::JoinerWorkBeforeDebit => "joiner-work-before-debit",
            Bug::JoinerNewFlowOnReconnect => "joiner-new-flow-on-reconnect",
            Bug::SkipDeadline => "skip-deadline",
            Bug::HostIgnoreGate => "host-ignore-gate",
            Bug::NoPinOnReconnect => "no-pin-on-reconnect",
            Bug::SharedGrantTable => "shared-grant-table",
            Bug::AcceptExpiredCert => "accept-expired-cert",
            Bug::RelayEarlyAnswer => "relay-early-answer",
            Bug::RelayStaleAllowSet => "relay-stale-allow-set",
        }
    }

    /// The drill that exercises this bug.
    pub fn drill(self) -> Drill {
        match self {
            Bug::KeepChannelAfterRemoval
            | Bug::SkipDeadline
            | Bug::HostIgnoreGate
            | Bug::NoPinOnReconnect
            | Bug::AcceptExpiredCert => Drill::Handshake,
            Bug::HostWorkBeforeDebit
            | Bug::JoinerWorkBeforeDebit
            | Bug::JoinerNewFlowOnReconnect => Drill::PairingLimits,
            Bug::SharedGrantTable => Drill::SharedEndpoints,
            Bug::RelayEarlyAnswer | Bug::RelayStaleAllowSet => Drill::RelayAdmission,
        }
    }

    /// The invariant the drill must report when this bug is planted.
    pub fn expected(self) -> Invariant {
        match self {
            Bug::KeepChannelAfterRemoval => Invariant::RemovedGrantClosed,
            Bug::HostWorkBeforeDebit | Bug::JoinerWorkBeforeDebit => Invariant::DebitBeforeWork,
            Bug::JoinerNewFlowOnReconnect => Invariant::AttemptCap,
            Bug::SkipDeadline => Invariant::NoFlowPastDeadline,
            Bug::HostIgnoreGate => Invariant::NoTrafficWithoutGrant,
            Bug::NoPinOnReconnect => Invariant::PinMatch,
            Bug::SharedGrantTable => Invariant::EndpointIsolation,
            Bug::AcceptExpiredCert => Invariant::Step1Spec,
            Bug::RelayEarlyAnswer => Invariant::RelayOneAnswer,
            Bug::RelayStaleAllowSet => Invariant::RelayAllowSetOnly,
        }
    }
}

impl fmt::Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Bug {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Bug::ALL.into_iter().find(|b| b.name() == s).ok_or_else(|| {
            let names: Vec<&str> = Bug::ALL.iter().map(|b| b.name()).collect();
            format!("unknown bug {s:?}; known: {}", names.join(", "))
        })
    }
}

/// What to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    /// The drill.
    pub drill: Drill,
    /// The seed.
    pub seed: u64,
    /// A planted bug, for must-fail controls.
    pub bug: Option<Bug>,
    /// Run core's full certificate verification on every handshake instead
    /// of the cached crypto (see [`certs`]). Slower; same results.
    pub full_verify: bool,
    /// Keep the event log lines (for replay). The hash is always computed.
    pub keep_log: bool,
}

impl RunConfig {
    /// A run of `drill` with `seed`, no bug, cached verification, no log kept.
    pub fn new(drill: Drill, seed: u64) -> Self {
        Self {
            drill,
            seed,
            bug: None,
            full_verify: false,
            keep_log: false,
        }
    }

    /// The command that replays this run and prints its event log.
    pub fn replay_command(&self) -> String {
        let mut cmd = format!(
            "mousse-sim replay --drill {} --seed {}",
            self.drill.name(),
            self.seed
        );
        if let Some(bug) = self.bug {
            cmd.push_str(&format!(" --bug {}", bug.name()));
        }
        if self.full_verify {
            cmd.push_str(" --full-verify");
        }
        cmd
    }
}

/// The result of one run.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    /// What ran.
    pub config: RunConfig,
    /// The scenario variant the seed picked.
    pub variant: &'static str,
    /// SHA-256 over the event log (each line plus `\n`).
    pub log_hash: [u8; 32],
    /// Number of log lines.
    pub log_lines: u64,
    /// The log, if [`RunConfig::keep_log`] was set.
    pub log: Vec<String>,
    /// The first invariant violation, if any.
    pub violation: Option<Violation>,
    /// Events processed.
    pub events: u64,
    /// Virtual time at the end, in milliseconds.
    pub end_ms: u64,
}

impl RunOutcome {
    /// The log hash as lowercase hex.
    pub fn log_hash_hex(&self) -> String {
        self.log_hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Run one seed.
pub fn run(config: &RunConfig) -> RunOutcome {
    drills::run(config)
}

/// Run `seeds` of `drill` (optionally with a planted bug) and return the
/// outcomes that have a violation, plus the number of runs.
pub fn run_many(
    drill: Drill,
    seeds: std::ops::Range<u64>,
    bug: Option<Bug>,
) -> (u64, Vec<RunOutcome>) {
    let mut failures = Vec::new();
    let mut count = 0;
    for seed in seeds {
        let config = RunConfig {
            bug,
            ..RunConfig::new(drill, seed)
        };
        let outcome = run(&config);
        count += 1;
        if outcome.violation.is_some() {
            failures.push(outcome);
        }
    }
    (count, failures)
}
