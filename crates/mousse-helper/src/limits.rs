//! Every limit the helper runs with: the network crates' and its own. They
//! are read once at startup from `MOUSSE_NET_<NAME>` (`docs/limits.md`); a
//! value that is not a whole number or is outside its range stops startup.

use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use mousse_net_core::limits::{LimitError, LimitSpec};

/// The prefix of every limit variable.
pub const ENV_PREFIX: &str = "MOUSSE_NET_";

mousse_net_core::define_limits! {
    /// The helper's own limits.
    pub struct HelperLimits {
        /// Bytes read from the terminal's PTY at a time (one DATA frame, well under the 1 MiB frame maximum).
        term_pty_read_bytes = "TERM_PTY_READ_BYTES": 16_384, [1_024, 65_536];
        /// Bytes read from local input at a time when using a remote terminal.
        term_stdin_read_bytes = "TERM_STDIN_READ_BYTES": 4_096, [64, 65_536];
        /// Terminal output chunks queued for the network before the PTY reader waits.
        term_output_queue = "TERM_OUTPUT_QUEUE": 64, [1, 4_096];
        /// Largest terminal width or height a peer may ask for.
        term_max_dimension = "TERM_MAX_DIMENSION": 1_000, [80, 4_000];
        /// After the command exits, how long its last output may take before the PTY is closed.
        term_close_delay_ms = "TERM_CLOSE_DELAY_MS": 300, [0, 10_000];
        /// After the command exits, how long to wait for the output to end before sending EXIT anyway.
        term_exit_grace_ms = "TERM_EXIT_GRACE_MS": 3_000, [0, 60_000];
        /// How often a remote terminal checks the local window size.
        term_resize_poll_ms = "TERM_RESIZE_POLL_MS": 500, [50, 10_000];
        /// Host: how long a helper-info requester has to finish its empty request.
        info_request_wait_ms = "INFO_REQUEST_WAIT_MS": 5_000, [100, 60_000];
        /// Longest helper-info answer accepted.
        info_answer_max_bytes = "INFO_ANSWER_MAX_BYTES": 4_096, [256, 65_536];
        /// How long to wait for a helper-info answer.
        info_answer_wait_ms = "INFO_ANSWER_WAIT_MS": 10_000, [100, 120_000];
        /// How long the slice check waits for its command to finish.
        capture_wait_ms = "CAPTURE_WAIT_MS": 30_000, [100, 600_000];
        /// Slice check: default wait for the host to remove this device (--removal-timeout overrides it).
        removal_wait_secs = "REMOVAL_WAIT_SECS": 300, [1, 86_400];
        /// After `stop`, how long closing connections get before the host exits.
        stop_linger_ms = "STOP_LINGER_MS": 200, [0, 10_000];
        /// Windows: how long to retry a busy control pipe.
        pipe_busy_wait_ms = "PIPE_BUSY_WAIT_MS": 2_000, [0, 60_000];
        /// Windows: wait between tries on a busy control pipe.
        pipe_busy_retry_ms = "PIPE_BUSY_RETRY_MS": 20, [1, 1_000];
        /// How long to retry an endpoint lock a process that just exited may still hold.
        endpoint_lock_wait_ms = "ENDPOINT_LOCK_WAIT_MS": 2_000, [0, 60_000];
        /// Wait between tries on a held endpoint lock.
        endpoint_lock_retry_ms = "ENDPOINT_LOCK_RETRY_MS": 100, [1, 1_000];
        /// Longest default device name taken from the computer name (names are at most 64 bytes in PAIRED).
        computer_name_max_bytes = "COMPUTER_NAME_MAX_BYTES": 64, [1, 64];
    }
}

/// The network crates' limits and the helper's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Core and I/O.
    pub net: mousse_net_io::Limits,
    /// The helper's own.
    pub helper: HelperLimits,
}

impl Limits {
    /// The defaults.
    pub const DEFAULT: Self = Self {
        net: mousse_net_io::Limits::DEFAULT,
        helper: HelperLimits::DEFAULT,
    };

    /// Every limit, in table order.
    pub fn specs() -> impl Iterator<Item = &'static LimitSpec> {
        mousse_net_io::Limits::specs().chain(HelperLimits::SPECS)
    }

    fn set(&mut self, name: &str, value: u64) -> Result<(), LimitError> {
        if HelperLimits::SPECS.iter().any(|s| s.name == name) {
            self.helper.set(name, value)
        } else {
            self.net.set(name, value)
        }
    }

    /// Defaults overridden by the `MOUSSE_NET_<NAME>` variables `var`
    /// returns. Errors name the variable and its allowed range.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        let mut limits = Self::DEFAULT;
        for spec in Self::specs() {
            let key = format!("{ENV_PREFIX}{}", spec.name);
            let Some(raw) = var(&key) else {
                continue;
            };
            let range = format!("allowed range is {} to {}", spec.min, spec.max);
            let text = raw
                .to_str()
                .ok_or_else(|| format!("{key} is not valid text; {range}"))?;
            let value = parse_whole(text)
                .ok_or_else(|| format!("{key}={text:?} is not a whole number; {range}"))?;
            limits.set(spec.name, value).map_err(|e| match e {
                LimitError::OutOfRange { value, .. } => {
                    format!("{key}={value} is out of range; {range}")
                }
                other => format!("{key}: {other}"),
            })?;
        }
        limits
            .net
            .validate()
            .map_err(|e| format!("{ENV_PREFIX}* limits do not agree: {e}"))?;
        Ok(limits)
    }

    /// Unknown `MOUSSE_NET_*` names among `names`, most likely typos.
    pub fn unknown_names(names: impl Iterator<Item = OsString>) -> Vec<String> {
        names
            .filter_map(|n| n.into_string().ok())
            .filter(|n| {
                n.strip_prefix(ENV_PREFIX)
                    .is_some_and(|rest| !Self::specs().any(|s| s.name == rest))
            })
            .collect()
    }
}

/// Digits only: no sign, spaces, units or underscores.
fn parse_whole(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

/// Read the limits from the environment. Called once, at startup; an
/// error stops startup.
pub fn init_from_env() -> Result<(), String> {
    let unknown = Limits::unknown_names(std::env::vars_os().map(|(k, _)| k));
    if let Some(name) = unknown.first() {
        return Err(format!(
            "{name} is not a known limit (see docs/limits.md for the {ENV_PREFIX}* names)"
        ));
    }
    let limits = Limits::from_vars(|key| std::env::var_os(key))?;
    let _ = LIMITS.set(limits);
    Ok(())
}

/// The limits read at startup (the defaults before that, as in unit tests).
pub fn get() -> &'static Limits {
    LIMITS.get_or_init(|| Limits::DEFAULT)
}

/// The helper's own limits.
pub fn helper() -> &'static HelperLimits {
    &get().helper
}

/// `ms` milliseconds.
pub fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// A duration for messages: whole seconds when it is one, else
/// milliseconds.
pub fn describe(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1_000) {
        format!("{} s", ms / 1_000)
    } else {
        format!("{ms} ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(*v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn no_variables_give_the_defaults() {
        assert_eq!(Limits::from_vars(vars(&[])), Ok(Limits::DEFAULT));
    }

    #[test]
    fn variables_override_core_io_and_helper_limits() {
        let l = Limits::from_vars(vars(&[
            ("MOUSSE_NET_CLOCK_SKEW_SECS", "120"),
            ("MOUSSE_NET_CONNECT_TIMEOUT_MS", "2500"),
            ("MOUSSE_NET_CAPTURE_WAIT_MS", "60000"),
        ]))
        .unwrap();
        assert_eq!(l.net.core.clock_skew_secs, 120);
        assert_eq!(l.net.io.connect_timeout_ms, 2_500);
        assert_eq!(l.helper.capture_wait_ms, 60_000);
        assert_eq!(l.net.core.join_proof_wait_ms, 10_000);
    }

    #[test]
    fn a_value_that_is_not_a_whole_number_names_the_variable_and_range() {
        for bad in [
            "",
            "ten",
            "-5",
            "+5",
            " 5",
            "5 ",
            "5ms",
            "1_000",
            "1.5",
            "99999999999999999999",
        ] {
            let err = Limits::from_vars(vars(&[("MOUSSE_NET_KEEPALIVE_MS", bad)])).unwrap_err();
            assert!(
                err.starts_with("MOUSSE_NET_KEEPALIVE_MS=")
                    && err.ends_with("is not a whole number; allowed range is 1000 to 15000"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn an_out_of_range_value_names_the_variable_and_range() {
        let err =
            Limits::from_vars(vars(&[("MOUSSE_NET_JOINER_ATTEMPTS_PER_FLOW", "4")])).unwrap_err();
        assert_eq!(
            err,
            "MOUSSE_NET_JOINER_ATTEMPTS_PER_FLOW=4 is out of range; allowed range is 1 to 3"
        );
        let err = Limits::from_vars(vars(&[("MOUSSE_NET_CLOCK_SKEW_SECS", "601")])).unwrap_err();
        assert_eq!(
            err,
            "MOUSSE_NET_CLOCK_SKEW_SECS=601 is out of range; allowed range is 0 to 600"
        );
        let err = Limits::from_vars(vars(&[("MOUSSE_NET_TERM_OUTPUT_QUEUE", "0")])).unwrap_err();
        assert_eq!(
            err,
            "MOUSSE_NET_TERM_OUTPUT_QUEUE=0 is out of range; allowed range is 1 to 4096"
        );
    }

    #[test]
    fn limits_that_must_agree_are_checked() {
        let err = Limits::from_vars(vars(&[
            ("MOUSSE_NET_RENEW_LEAD_SECS", "7200"),
            ("MOUSSE_NET_CERT_LIFETIME_SECS", "3600"),
        ]))
        .unwrap_err();
        assert!(err.contains("RENEW_LEAD_SECS"), "{err}");
    }

    #[test]
    fn unknown_names_are_reported() {
        let names = [
            "MOUSSE_NET_KEEPALIVE_MS",
            "MOUSSE_NET_KEEPALIVE",
            "MOUSSE_HELPER_STATE",
            "PATH",
        ]
        .map(OsString::from);
        assert_eq!(
            Limits::unknown_names(names.into_iter()),
            ["MOUSSE_NET_KEEPALIVE"]
        );
    }

    #[test]
    fn names_are_unique_and_carry_a_unit_or_are_counts() {
        let mut names: Vec<&str> = Limits::specs().map(|s| s.name).collect();
        let all = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all);
        for spec in Limits::specs() {
            assert!(
                spec.min <= spec.default && spec.default <= spec.max,
                "{}",
                spec.name
            );
        }
    }

    #[test]
    fn the_helper_defaults_are_the_values_it_used_before() {
        let h = HelperLimits::DEFAULT;
        assert_eq!(h.term_pty_read_bytes, 16 * 1024);
        assert_eq!(h.term_max_dimension, 1_000);
        assert_eq!(h.info_answer_wait_ms, 10_000);
        assert_eq!(h.removal_wait_secs, 300);
        assert_eq!(h.computer_name_max_bytes, 64);
    }

    #[test]
    fn docs_list_every_limit_with_its_default_and_range() {
        let doc = include_str!("../../../docs/limits.md");
        for spec in Limits::specs() {
            let row = format!(
                "| `{ENV_PREFIX}{}` | {} | {} to {} |",
                spec.name, spec.default, spec.min, spec.max
            );
            assert!(
                doc.contains(&row),
                "docs/limits.md has no row starting {row}"
            );
        }
    }

    #[test]
    fn durations_read_as_seconds_or_milliseconds() {
        assert_eq!(describe(Duration::from_secs(10)), "10 s");
        assert_eq!(describe(Duration::from_millis(2_500)), "2500 ms");
    }
}
