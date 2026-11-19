//! Relay limits (`docs/limits.md`, "Relay"). `mousse-relay` reads each from
//! `MOUSSE_NET_<NAME>`; every name here starts with `RELAY_`.
//!
//! Defaults marked † in `phase34-design.md` H.1 come from the E-R0
//! measurements recorded in that file.

use crate::limits::LimitError;

crate::define_limits! {
    /// Every limit of the relay.
    pub struct RelayLimits {
        /// Open outer connections (capacity; about 52 KB each, plus queued bytes).
        max_connections = "RELAY_MAX_CONNECTIONS": 1_024, [1, 65_536];
        /// Open connections per IPv4 address or IPv6 /64, except accept legs once their ACCEPT is accepted (tighten only).
        connections_per_ip = "RELAY_CONNECTIONS_PER_IP": 256, [1, 256];
        /// Open accept legs per handle (tighten only).
        accept_legs_per_handle = "RELAY_ACCEPT_LEGS_PER_HANDLE": 64, [1, 64];
        /// Open circuits per caller fingerprint and handle (tighten only).
        circuits_per_caller = "RELAY_CIRCUITS_PER_CALLER": 8, [2, 8];
        /// Live registrations (capacity).
        max_registrations = "RELAY_MAX_REGISTRATIONS": 1_024, [1, 65_536];
        /// Wait for the first client message after RELAY_HELLO (tighten only).
        hello_wait_ms = "RELAY_HELLO_WAIT_MS": 5_000, [500, 5_000];
        /// Whole TLS and WebSocket upgrade (tighten only).
        upgrade_wait_ms = "RELAY_UPGRADE_WAIT_MS": 5_000, [100, 5_000];
        /// Largest upgrade request (tighten only).
        header_max_bytes = "RELAY_HEADER_MAX_BYTES": 8_192, [1_024, 8_192];
        /// Wait for the target's accept leg after INCOMING.
        accept_wait_ms = "RELAY_ACCEPT_WAIT_MS": 10_000, [1_000, 30_000];
        /// Constant refusal deadline from a CALL or JOIN; below the accept wait.
        refuse_ms = "RELAY_REFUSE_MS": 500, [500, 5_000];
        /// Peer bytes per join circuit and direction before promotion (tighten only).
        preaccept_bytes = "RELAY_PREACCEPT_BYTES": 65_536, [16_384, 65_536];
        /// Join circuits per handle (tighten only).
        preaccept_per_target = "RELAY_PREACCEPT_PER_TARGET": 4, [1, 4];
        /// PING on a registration connection after this long without sending.
        keepalive_ms = "RELAY_KEEPALIVE_MS": 15_000, [1_000, 15_000];
        /// Registration closed after this long without receiving (tighten only).
        registration_idle_ms = "RELAY_REGISTRATION_IDLE_MS": 45_000, [30_000, 45_000];
        /// Spliced circuit closed after this long with no bytes either way; above the peer idle timeout.
        circuit_idle_ms = "RELAY_CIRCUIT_IDLE_MS": 60_000, [46_000, 600_000];
        /// Bytes buffered per circuit and direction before the relay stops reading that leg (tighten only).
        queue_bytes = "RELAY_QUEUE_BYTES": 262_144, [16_384, 262_144];
        /// Shared egress ceiling in bytes per second (capacity).
        egress_bps = "RELAY_EGRESS_BPS": 12_500_000, [125_000, 12_500_000_000_u64];
        /// Enrollment code lifetime; single use (tighten only).
        enroll_secs = "RELAY_ENROLL_SECS": 3_600, [60, 3_600];
        /// After a SUCCESSOR, how long the superseded registration key stays authorized.
        successor_overlap_secs = "RELAY_SUCCESSOR_OVERLAP_SECS": 604_800, [86_400, 2_592_000];
        /// How often the running relay re-reads its authorized list and enrollment codes, so `revoke` and `enroll` take effect.
        state_poll_ms = "RELAY_STATE_POLL_MS": 1_000, [100, 60_000];
    }
    agree(l) {
        if l.refuse_ms >= l.accept_wait_ms {
            return Err(LimitError::Conflict(format!(
                "RELAY_REFUSE_MS ({}) must be below RELAY_ACCEPT_WAIT_MS ({})",
                l.refuse_ms, l.accept_wait_ms
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn names_carry_the_relay_prefix_and_tighten_only_ranges_end_at_the_default() {
        for spec in RelayLimits::SPECS {
            assert!(spec.name.starts_with("RELAY_"), "{}", spec.name);
        }
        for name in [
            "RELAY_CONNECTIONS_PER_IP",
            "RELAY_ACCEPT_LEGS_PER_HANDLE",
            "RELAY_CIRCUITS_PER_CALLER",
            "RELAY_HELLO_WAIT_MS",
            "RELAY_PREACCEPT_BYTES",
            "RELAY_PREACCEPT_PER_TARGET",
            "RELAY_REGISTRATION_IDLE_MS",
            "RELAY_QUEUE_BYTES",
            "RELAY_ENROLL_SECS",
        ] {
            let spec = RelayLimits::SPECS.iter().find(|s| s.name == name).unwrap();
            assert_eq!(spec.max, spec.default, "{name} must only tighten");
            assert!(RelayLimits::DEFAULT
                .with_overrides(&[(name, spec.default + 1)])
                .is_err());
        }
        assert!(RelayLimits::DEFAULT
            .with_overrides(&[("RELAY_REFUSE_MS", 5_000), ("RELAY_ACCEPT_WAIT_MS", 4_000)])
            .is_err());
    }
}
