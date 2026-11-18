//! Every tunable limit of the core, with its default and allowed range.
//!
//! Core reads no environment and no clock: the state machines take a
//! [`Limits`] as a parameter, and their plain constructors use
//! [`Limits::DEFAULT`]. The I/O crate and the helper add their own sets
//! with [`define_limits!`](crate::define_limits), and the helper overrides any of them from
//! `MOUSSE_NET_<NAME>` at startup (`docs/limits.md`).
//!
//! A limit the peer or a security bound depends on may only be tightened:
//! its range ends at the value the spec gives.
//!
//! A limits value is always valid: its fields are private, and the only
//! way to change them is [`Limits::with_overrides`], which checks every
//! range and the limits that must agree, so a value outside the spec can
//! never reach a state machine.

use core::fmt;

/// One settable limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitSpec {
    /// The name, ending in its unit (`_MS`, `_SECS`, `_BYTES`, or none for a
    /// count). The helper reads it from `MOUSSE_NET_<name>`.
    pub name: &'static str,
    /// The default.
    pub default: u64,
    /// The smallest allowed value.
    pub min: u64,
    /// The largest allowed value.
    pub max: u64,
    /// What it limits.
    pub what: &'static str,
}

impl LimitSpec {
    /// Check `value` against the range.
    pub fn check(&self, value: u64) -> Result<(), LimitError> {
        if (self.min..=self.max).contains(&value) {
            Ok(())
        } else {
            Err(LimitError::OutOfRange {
                name: self.name,
                value,
                min: self.min,
                max: self.max,
            })
        }
    }
}

/// A limit value that cannot be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitError {
    /// No limit has this name.
    Unknown(String),
    /// The value is outside the allowed range.
    OutOfRange {
        /// The limit.
        name: &'static str,
        /// The value given.
        value: u64,
        /// The smallest allowed value.
        min: u64,
        /// The largest allowed value.
        max: u64,
    },
    /// Two limits that must agree do not.
    Conflict(String),
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(f, "{name} is not a known limit"),
            Self::OutOfRange {
                name,
                value,
                min,
                max,
            } => write!(f, "{name} is {value}; allowed range is {min} to {max}"),
            Self::Conflict(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for LimitError {}

/// Define a set of limits: a `Copy` struct of private `u64` fields with a
/// read accessor each, a `DEFAULT` constant, a `SPECS` table (name,
/// default, range, what), `get` by name, and `with_overrides`, the one way
/// to change values. Each default is checked against its range at compile
/// time. An optional `agree(v) { ... }` block returns
/// [`LimitError::Conflict`] when limits that must agree do not.
///
/// ```
/// mousse_net_core::define_limits! {
///     /// Example limits.
///     pub struct Example {
///         /// How long to wait.
///         wait_ms = "WAIT_MS": 1_000, [10, 5_000];
///     }
/// }
/// assert_eq!(Example::DEFAULT.wait_ms(), 1_000);
/// let tighter = Example::DEFAULT.with_overrides(&[("WAIT_MS", 50)]).unwrap();
/// assert_eq!(tighter.wait_ms(), 50);
/// assert!(Example::DEFAULT.with_overrides(&[("WAIT_MS", 9_000)]).is_err());
/// ```
#[macro_export]
macro_rules! define_limits {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $(
                #[doc = $doc:literal]
                $field:ident = $env:literal: $default:expr, [$min:expr, $max:expr];
            )+
        }
        $( agree($v:ident) $agree:block )?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            $( $field: u64, )+
        }

        const _: () = {
            $(
                assert!($min <= $default && $default <= $max, concat!($env, ": default outside its range"));
            )+
        };

        impl $name {
            /// The defaults.
            pub const DEFAULT: Self = Self {
                $( $field: $default, )+
            };

            /// Every limit in this set.
            pub const SPECS: &'static [$crate::limits::LimitSpec] = &[
                $(
                    $crate::limits::LimitSpec {
                        name: $env,
                        default: $default,
                        min: $min,
                        max: $max,
                        what: $doc,
                    },
                )+
            ];

            $(
                #[doc = $doc]
                pub const fn $field(&self) -> u64 {
                    self.$field
                }
            )+

            /// The value of the limit called `name`.
            pub fn get(&self, name: &str) -> Option<u64> {
                match name {
                    $( $env => Some(self.$field), )+
                    _ => None,
                }
            }

            /// These limits with `overrides` (name, value) applied, all at
            /// once. Every value must be within its range and the result's
            /// limits must agree; otherwise the error names the first
            /// problem and nothing is returned.
            pub fn with_overrides(
                &self,
                overrides: &[(&str, u64)],
            ) -> Result<Self, $crate::limits::LimitError> {
                let mut out = *self;
                for &(name, value) in overrides {
                    let spec = Self::SPECS
                        .iter()
                        .find(|s| s.name == name)
                        .ok_or_else(|| $crate::limits::LimitError::Unknown(name.to_owned()))?;
                    spec.check(value)?;
                    match name {
                        $( $env => out.$field = value, )+
                        _ => {}
                    }
                }
                out.agree()?;
                Ok(out)
            }

            /// Whether the limits that must agree do.
            fn agree(&self) -> Result<(), $crate::limits::LimitError> {
                $( let $v = self; $agree )?
                Ok(())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::DEFAULT
            }
        }
    };
}

define_limits! {
    /// The core's limits. [`Limits::DEFAULT`] holds the spec's values.
    pub struct Limits {
        /// Host: how long a connection with no grant may take to send its JOIN_PROOF (wire.md 8, step 2; tighten only).
        join_proof_wait_ms = "JOIN_PROOF_WAIT_MS": 10_000, [1_000, 10_000];
        /// Send a PING after this long without sending (wire.md 9.4; the peer's idle timeout needs it, so tighten only).
        keepalive_ms = "KEEPALIVE_MS": 15_000, [1_000, 15_000];
        /// Close after this long without receiving (wire.md 9.4; at least two of the peer's keepalives, tighten only).
        idle_timeout_ms = "IDLE_TIMEOUT_MS": 45_000, [30_000, 45_000];
        /// Streams the peer may have open at once; more are refused (wire.md 9.2; tighten only).
        max_peer_streams = "MAX_PEER_STREAMS": 1_024, [1, 1_024];
        /// Largest DATA payload this side sends (wire.md 9.4; tighten only).
        send_chunk_bytes = "SEND_CHUNK_BYTES": 16_384, [1_024, 16_384];
        /// Return credit once this many consumed bytes are unreturned (wire.md 9.3; tighten only).
        credit_return_bytes = "CREDIT_RETURN_BYTES": 65_536, [1_024, 65_536];
        /// Clock difference allowed on every peer-signed time (wire.md 1; tighten only).
        clock_skew_secs = "CLOCK_SKEW_SECS": 600, [0, 600];
        /// Start renewal this long before the earlier certificate's not_after (wire.md 6; earlier only).
        renew_lead_secs = "RENEW_LEAD_SECS": 1_800, [1_800, 7_200];
        /// First wait before asking again for a renewal (wire.md 6; tighten only).
        renew_retry_first_secs = "RENEW_RETRY_FIRST_SECS": 30, [1, 30];
        /// Longest wait between renewal requests; not below the first wait (wire.md 6; tighten only).
        renew_retry_max_secs = "RENEW_RETRY_MAX_SECS": 300, [1, 300];
        /// How long a new pairing ticket is valid (wire.md 10.2; tighten only).
        ticket_lifetime_secs = "TICKET_LIFETIME_SECS": 600, [60, 600];
        /// Code attempts the host allows per invitation (wire.md 10.7; tighten only).
        host_attempts_per_invitation = "HOST_ATTEMPTS_PER_INVITATION": 3, [1, 3];
        /// Code attempts the joiner allows per ticket; a stored flow record holds at most 3 (wire.md 10.7; tighten only).
        joiner_attempts_per_flow = "JOINER_ATTEMPTS_PER_FLOW": 3, [1, 3];
    }
    agree(l) {
        if l.renew_retry_max_secs < l.renew_retry_first_secs {
            return Err(LimitError::Conflict(format!(
                "RENEW_RETRY_MAX_SECS ({}) is below RENEW_RETRY_FIRST_SECS ({})",
                l.renew_retry_max_secs, l.renew_retry_first_secs
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
    fn the_defaults_are_the_spec_values() {
        let d = Limits::DEFAULT;
        // wire.md 8, step 2.
        assert_eq!(d.join_proof_wait_ms(), 10_000);
        // wire.md 9.2 to 9.4.
        assert_eq!(d.keepalive_ms(), 15_000);
        assert_eq!(d.idle_timeout_ms(), 45_000);
        assert_eq!(d.max_peer_streams(), 1_024);
        assert_eq!(d.send_chunk_bytes(), 16_384);
        assert_eq!(d.credit_return_bytes(), 65_536);
        // wire.md 1.
        assert_eq!(d.clock_skew_secs(), 600);
        // wire.md 6: renew 30 min before; retry after 30 s, at most 300 s.
        assert_eq!(d.renew_lead_secs(), 1_800);
        assert_eq!(d.renew_retry_first_secs(), 30);
        assert_eq!(d.renew_retry_max_secs(), 300);
        // wire.md 10.2 and 10.7.
        assert_eq!(d.ticket_lifetime_secs(), 600);
        assert_eq!(d.host_attempts_per_invitation(), 3);
        assert_eq!(d.joiner_attempts_per_flow(), 3);
        assert_eq!(d.with_overrides(&[]), Ok(d));
        assert_eq!(Limits::default(), d);
    }

    #[test]
    fn a_spec_bound_limit_can_only_be_tightened() {
        let wire_bound = [
            "JOIN_PROOF_WAIT_MS",
            "KEEPALIVE_MS",
            "IDLE_TIMEOUT_MS",
            "MAX_PEER_STREAMS",
            "SEND_CHUNK_BYTES",
            "CREDIT_RETURN_BYTES",
            "CLOCK_SKEW_SECS",
            "RENEW_RETRY_FIRST_SECS",
            "RENEW_RETRY_MAX_SECS",
            "TICKET_LIFETIME_SECS",
            "HOST_ATTEMPTS_PER_INVITATION",
            "JOINER_ATTEMPTS_PER_FLOW",
        ];
        for spec in Limits::SPECS {
            if wire_bound.contains(&spec.name) {
                assert_eq!(spec.max, spec.default, "{}", spec.name);
            }
        }
        // Renewal may only start earlier.
        let lead = Limits::SPECS
            .iter()
            .find(|s| s.name == "RENEW_LEAD_SECS")
            .unwrap();
        assert_eq!(lead.min, lead.default);
        // The record format holds at most three attempts.
        assert_eq!(
            Limits::SPECS
                .iter()
                .find(|s| s.name == "JOINER_ATTEMPTS_PER_FLOW")
                .unwrap()
                .max,
            u64::from(crate::pairing::JOINER_ATTEMPTS_PER_FLOW)
        );
    }

    #[test]
    fn overrides_check_the_range_and_the_name() {
        let l = Limits::DEFAULT
            .with_overrides(&[("CLOCK_SKEW_SECS", 120)])
            .unwrap();
        assert_eq!(l.clock_skew_secs(), 120);
        assert_eq!(l.get("CLOCK_SKEW_SECS"), Some(120));
        assert_eq!(
            l.with_overrides(&[("CLOCK_SKEW_SECS", 601)]),
            Err(LimitError::OutOfRange {
                name: "CLOCK_SKEW_SECS",
                value: 601,
                min: 0,
                max: 600
            })
        );
        assert_eq!(
            l.with_overrides(&[("JOINER_ATTEMPTS_PER_FLOW", 4)]),
            Err(LimitError::OutOfRange {
                name: "JOINER_ATTEMPTS_PER_FLOW",
                value: 4,
                min: 1,
                max: 3
            })
        );
        assert!(matches!(
            l.with_overrides(&[("NO_SUCH", 1)]),
            Err(LimitError::Unknown(_))
        ));
    }

    #[test]
    fn retry_waits_must_agree() {
        // Checked once all overrides are in, so their order does not matter.
        let l = Limits::DEFAULT
            .with_overrides(&[("RENEW_RETRY_MAX_SECS", 10), ("RENEW_RETRY_FIRST_SECS", 5)])
            .unwrap();
        assert_eq!(l.renew_retry_max_secs(), 10);
        assert!(matches!(
            Limits::DEFAULT
                .with_overrides(&[("RENEW_RETRY_FIRST_SECS", 20), ("RENEW_RETRY_MAX_SECS", 10)]),
            Err(LimitError::Conflict(_))
        ));
    }
}
