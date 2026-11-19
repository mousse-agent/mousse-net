//! Every limit the I/O layer uses: the core's ([`CoreLimits`]) and its own
//! ([`IoLimits`]), with their defaults and allowed ranges.
//!
//! [`HostConfig`](crate::HostConfig) and [`Caller::new`](crate::Caller::new)
//! take a [`Limits`]; the helper fills it from `MOUSSE_NET_<NAME>` at
//! startup (`docs/limits.md`). Like the core's, a [`Limits`] is always
//! valid: it changes only through [`Limits::with_overrides`], which checks
//! every range and the limits that must agree.

use std::time::Duration;

pub use mousse_net_core::limits::{LimitError, LimitSpec};
pub use mousse_net_core::Limits as CoreLimits;

mousse_net_core::define_limits! {
    /// The I/O layer's own limits. [`IoLimits::DEFAULT`] holds the spec's
    /// values where the spec gives one.
    pub struct IoLimits {
        /// Caller: how long it waits for the answer to its JOIN_PROOF (wire.md 8.2; tighten only).
        proof_answer_wait_ms = "PROOF_ANSWER_WAIT_MS": 10_000, [1_000, 10_000];
        /// Reconnects a join makes to learn an outcome a dropped connection left pending.
        outcome_retries = "OUTCOME_RETRIES": 4, [0, 20];
        /// Wait before the first of those reconnects; each next wait doubles.
        outcome_retry_first_ms = "OUTCOME_RETRY_FIRST_MS": 250, [10, 10_000];
        /// Longest wait between those reconnects; not below the first wait.
        outcome_retry_max_ms = "OUTCOME_RETRY_MAX_MS": 2_000, [10, 60_000];
        /// Longest time between readings of both clocks for connection deadlines, renewal and the host's step 2 timers (wire.md 6 closes in the second after the deadline; tighten only).
        clock_recheck_ms = "CLOCK_RECHECK_MS": 1_000, [10, 1_000];
        /// How often a write still pending checks the connection deadline.
        deadline_poll_ms = "DEADLINE_POLL_MS": 50, [1, 1_000];
        /// How long a closing connection may take to send its last frame and shut the pipe down, reading and dropping what the peer still sends meanwhile.
        close_linger_ms = "CLOSE_LINGER_MS": 2_000, [100, 30_000];
        /// Queued bytes per stream above which a write waits.
        write_high_water_bytes = "WRITE_HIGH_WATER_BYTES": 262_144, [16_384, 67_108_864];
        /// Bytes read from the pipe at a time.
        read_buffer_bytes = "READ_BUFFER_BYTES": 32_768, [1_024, 1_048_576];
        /// Size of the buffers received DATA frames share until read: a peer's tiny frames fill one buffer instead of an allocation each.
        rx_chunk_bytes = "RX_CHUNK_BYTES": 16_384, [1_024, 65_536];
        /// How long a TLS handshake may take.
        handshake_timeout_ms = "HANDSHAKE_TIMEOUT_MS": 10_000, [1_000, 60_000];
        /// How long a TCP connect may take.
        connect_timeout_ms = "CONNECT_TIMEOUT_MS": 5_000, [100, 60_000];
        /// Lifetime of the session certificates this device issues; above RENEW_LEAD_SECS (wire.md 5.2: verifiers reject more than 24 h).
        cert_lifetime_secs = "CERT_LIFETIME_SECS": 86_400, [3_600, 86_400];
        /// How often the mDNS instance name changes while running (privacy.md; tighten only).
        mdns_rotate_ms = "MDNS_ROTATE_MS": 900_000, [60_000, 900_000];
        /// How often the advertiser checks whether the name is due to change.
        mdns_rotate_check_ms = "MDNS_ROTATE_CHECK_MS": 5_000, [100, 30_000];
        /// Streams one connection may have open, both directions counted; a peer's open beyond it is refused with REFUSED_STREAM. Each holds up to 256 KiB of received data before it is read (wire.md 9.2; at most the spec's 1 024).
        streams_per_connection = "STREAMS_PER_CONNECTION": 32, [1, 1_024];
        /// Streams all connections of one endpoint (one helper) may have open together, both directions counted; a peer's open beyond it is refused with REFUSED_STREAM.
        streams_per_endpoint = "STREAMS_PER_ENDPOINT": 128, [1, 1_024];
        /// Caller: candidate addresses for one host dialled at once (Phase 1a §6).
        dial_parallel = "DIAL_PARALLEL": 4, [1, 64];
        /// Caller: how long one candidate address may take to connect and pass step 1 before the next is tried (Phase 1a §6).
        dial_timeout_ms = "DIAL_TIMEOUT_MS": 2_000, [100, 60_000];
        /// How long an mDNS browse listens for answers (Phase 1a §6).
        browse_wait_ms = "BROWSE_WAIT_MS": 1_500, [100, 30_000];
        /// How long browse results are reused before the next browse (Phase 1a §6; 0 browses every time).
        browse_cache_ms = "BROWSE_CACHE_MS": 60_000, [0, 3_600_000];
        /// How often the network watcher lists the interfaces and reads the monotonic clock (Phase 1a §6 and §8).
        iface_poll_ms = "IFACE_POLL_MS": 5_000, [100, 60_000];
        /// How far the monotonic clock may run past one watcher poll before the gap counts as a sleep and wake (Phase 1a §8).
        wake_jump_ms = "WAKE_JUMP_MS": 10_000, [1_000, 600_000];
        /// After a wake or an interface change, how long each connection has to answer a PING before it is closed as dead (Phase 1a §8).
        wake_ping_ms = "WAKE_PING_MS": 2_000, [100, 30_000];
        /// Host: TCP connections not yet live (from accept, before any read, until live or closed), per endpoint; one more is closed at accept (Phase 1b §6.2; tighten only).
        preauth_tcp = "PREAUTH_TCP": 48, [1, 48];
        /// Host: `ws` connections not yet live, per endpoint (Phase 1b §6.2; tighten only).
        preauth_ws = "PREAUTH_WS": 16, [1, 16];
        /// Host: pipe connections (an SSH login's `mousse-helper pipe`) not yet live, per endpoint (Phase 1b §6.2; tighten only).
        preauth_pipe = "PREAUTH_PIPE": 4, [1, 4];
        /// Host: of the TCP ones, connections from one IPv4 address or one IPv6 /64 (Phase 1b §6.2; tighten only).
        preauth_per_source = "PREAUTH_PER_SOURCE": 8, [1, 8];
    }
    agree(io) {
        if io.outcome_retry_max_ms < io.outcome_retry_first_ms {
            return Err(LimitError::Conflict(format!(
                "OUTCOME_RETRY_MAX_MS ({}) is below OUTCOME_RETRY_FIRST_MS ({})",
                io.outcome_retry_max_ms, io.outcome_retry_first_ms
            )));
        }
    }
}

/// The core's limits and the I/O layer's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    core: CoreLimits,
    io: IoLimits,
}

impl Limits {
    /// The defaults.
    pub const DEFAULT: Self = Self {
        core: CoreLimits::DEFAULT,
        io: IoLimits::DEFAULT,
    };

    /// The state machines' limits.
    pub const fn core(&self) -> &CoreLimits {
        &self.core
    }

    /// The I/O layer's own.
    pub const fn io(&self) -> &IoLimits {
        &self.io
    }

    /// Every limit: the core's, then the I/O layer's.
    pub fn specs() -> impl Iterator<Item = &'static LimitSpec> {
        CoreLimits::SPECS.iter().chain(IoLimits::SPECS)
    }

    /// The value of the limit called `name`.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.core.get(name).or_else(|| self.io.get(name))
    }

    /// These limits with `overrides` (name, value) applied, all at once,
    /// to the core's set or the I/O layer's. Every value must be within its
    /// range and the result's limits must agree; otherwise the error names
    /// the first problem.
    pub fn with_overrides(&self, overrides: &[(&str, u64)]) -> Result<Self, LimitError> {
        let (core, io): (Vec<_>, Vec<_>) = overrides
            .iter()
            .copied()
            .partition(|(name, _)| CoreLimits::SPECS.iter().any(|s| s.name == *name));
        let out = Self {
            core: self.core.with_overrides(&core)?,
            io: self.io.with_overrides(&io)?,
        };
        if out.core.renew_lead_secs() >= out.io.cert_lifetime_secs() {
            return Err(LimitError::Conflict(format!(
                "RENEW_LEAD_SECS ({}) must be below CERT_LIFETIME_SECS ({}), or every new \
                 certificate would be due for renewal at once",
                out.core.renew_lead_secs(),
                out.io.cert_lifetime_secs()
            )));
        }
        Ok(out)
    }

    /// The waits before each reconnect that learns a pending join outcome.
    pub fn outcome_retry_waits(&self) -> Vec<Duration> {
        let io = &self.io;
        let mut wait = io.outcome_retry_first_ms();
        (0..io.outcome_retries())
            .map(|_| {
                let this = wait.min(io.outcome_retry_max_ms());
                wait = wait.saturating_mul(2);
                Duration::from_millis(this)
            })
            .collect()
    }
}

/// `ms` milliseconds.
pub(crate) fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_spec_values() {
        let d = IoLimits::DEFAULT;
        // wire.md 8.2: the caller waits 10 s for the answer to its proof.
        assert_eq!(d.proof_answer_wait_ms(), 10_000);
        // wire.md 5.2: 24 h certificates.
        assert_eq!(d.cert_lifetime_secs(), 86_400);
        // privacy.md: the mDNS name changes every 15 minutes.
        assert_eq!(d.mdns_rotate_ms(), 15 * 60 * 1_000);
        // wire.md 6: a connection closes in the first second after its
        // deadline, so the clocks are read at least once a second.
        assert_eq!(d.clock_recheck_ms(), 1_000);
        // Phase 1a §2.2: 32 streams a connection and 128 an endpoint keep
        // initial credit at 8 MiB a connection and 32 MiB an endpoint.
        assert_eq!(d.streams_per_connection(), 32);
        assert_eq!(d.streams_per_endpoint(), 128);
        assert_eq!(Limits::DEFAULT.with_overrides(&[]), Ok(Limits::DEFAULT));
        assert_eq!(Limits::default(), Limits::DEFAULT);
    }

    #[test]
    fn spec_bound_limits_can_only_be_tightened() {
        for name in [
            "PROOF_ANSWER_WAIT_MS",
            "CLOCK_RECHECK_MS",
            "CERT_LIFETIME_SECS",
            "MDNS_ROTATE_MS",
        ] {
            let spec = IoLimits::SPECS.iter().find(|s| s.name == name).unwrap();
            assert_eq!(spec.max, spec.default, "{name}");
        }
        assert_eq!(
            IoLimits::SPECS
                .iter()
                .find(|s| s.name == "CERT_LIFETIME_SECS")
                .unwrap()
                .max,
            mousse_net_core::session_cert::MAX_LIFETIME_SECS
        );
    }

    #[test]
    fn names_are_unique_across_core_and_io() {
        let mut names: Vec<&str> = Limits::specs().map(|s| s.name).collect();
        let all = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all);
    }

    #[test]
    fn overrides_reach_both_sets() {
        let l = Limits::DEFAULT
            .with_overrides(&[("CLOCK_SKEW_SECS", 300), ("CONNECT_TIMEOUT_MS", 2_000)])
            .unwrap();
        assert_eq!(l.core().clock_skew_secs(), 300);
        assert_eq!(l.io().connect_timeout_ms(), 2_000);
        assert!(matches!(
            l.with_overrides(&[("CERT_LIFETIME_SECS", 86_401)]),
            Err(LimitError::OutOfRange { .. })
        ));
        // A core limit is checked against the spec too: no wider proof
        // wait or clock skew can be built.
        assert!(matches!(
            l.with_overrides(&[("CLOCK_SKEW_SECS", 601)]),
            Err(LimitError::OutOfRange { .. })
        ));
        assert!(matches!(
            l.with_overrides(&[("PROOF_ANSWER_WAIT_MS", 10_001)]),
            Err(LimitError::OutOfRange { .. })
        ));
        assert!(matches!(
            l.with_overrides(&[("NOPE", 1)]),
            Err(LimitError::Unknown(_))
        ));
    }

    #[test]
    fn limits_that_must_agree_are_checked() {
        assert!(matches!(
            Limits::DEFAULT
                .with_overrides(&[("RENEW_LEAD_SECS", 7_200), ("CERT_LIFETIME_SECS", 3_600)]),
            Err(LimitError::Conflict(_))
        ));
        assert!(matches!(
            Limits::DEFAULT.with_overrides(&[
                ("OUTCOME_RETRY_FIRST_MS", 500),
                ("OUTCOME_RETRY_MAX_MS", 100)
            ]),
            Err(LimitError::Conflict(_))
        ));
        // Checked once all are in: a first wait above the default cap is
        // fine with a larger cap.
        let l = Limits::DEFAULT
            .with_overrides(&[
                ("OUTCOME_RETRY_FIRST_MS", 5_000),
                ("OUTCOME_RETRY_MAX_MS", 8_000),
            ])
            .unwrap();
        assert_eq!(l.io().outcome_retry_first_ms(), 5_000);
    }

    #[test]
    fn outcome_retry_waits_double_up_to_the_cap() {
        let waits: Vec<u64> = Limits::DEFAULT
            .outcome_retry_waits()
            .iter()
            .copied()
            .map(|d| d.as_millis() as u64)
            .collect();
        assert_eq!(waits, [250, 500, 1_000, 2_000]);
    }
}
