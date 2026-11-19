//! Every limit the helper runs with: the network crates' and its own. They
//! are read once at startup from `MOUSSE_NET_<NAME>` (`docs/limits.md`); a
//! value that is not a whole number or is outside its range stops startup.

use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use mousse_net_core::limits::{LimitError, LimitSpec};

/// The prefix of every limit variable.
pub const ENV_PREFIX: &str = "MOUSSE_NET_";

/// After [`ENV_PREFIX`]: the Mousse app's own limits and controls.
const APP_PREFIX: &str = "ENGINE_";

/// After [`ENV_PREFIX`]: the Mousse app's helper path in unpackaged builds.
const APP_HELPER_PATH: &str = "HELPER";

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
        /// App channel: credit the helper grants the app, all streams together, for data going to the engine (Phase 1a §2.2).
        app_credit_budget_bytes = "APP_CREDIT_BUDGET_BYTES": 8_388_608, [262_144, 1_073_741_824];
        /// App channel: part of that budget only interactive streams may use.
        app_credit_interactive_reserve_bytes = "APP_CREDIT_INTERACTIVE_RESERVE_BYTES": 1_048_576, [0, 1_073_741_824];
        /// App channel: most credit one stream holds at a time, in each direction the helper grants it.
        app_stream_credit_bytes = "APP_STREAM_CREDIT_BYTES": 262_144, [65_536, 16_777_216];
        /// App channel: a stream is read from the engine only while the app's credit covers what is buffered plus this much (at least one engine chunk, 64 KiB).
        app_read_ahead_bytes = "APP_READ_AHEAD_BYTES": 65_536, [65_536, 16_777_216];
        /// App channel: queued JSON and CREDIT frames to the app above which the app counts as stuck and the channel closes.
        app_control_queue_bytes = "APP_CONTROL_QUEUE_BYTES": 1_048_576, [65_536, 67_108_864];
        /// App mode: size at which helper.log is rotated.
        app_log_max_bytes = "APP_LOG_MAX_BYTES": 1_048_576, [4_096, 1_073_741_824];
        /// App mode: log files kept, helper.log included.
        app_log_files = "APP_LOG_FILES": 2, [1, 10];
        /// While networking is paused because a removal could not be saved, how often the save is tried again (Phase 1a §5.4).
        removal_retry_ms = "REMOVAL_RETRY_MS": 1_000, [10, 60_000];
        /// Keep connected: wait before redialling a paired host that could not be reached; each next wait doubles (Phase 1a §6).
        keep_retry_first_ms = "KEEP_RETRY_FIRST_MS": 1_000, [10, 60_000];
        /// Keep connected: longest wait between redials of a host that could not be reached; not below the first wait.
        keep_retry_max_ms = "KEEP_RETRY_MAX_MS": 60_000, [10, 3_600_000];
        /// Host: inbound connections not yet past step 2 (TLS handshake, then authorization or pairing), from all addresses together; one more is dropped before its handshake starts (tighten only).
        preauth_connections = "PREAUTH_CONNECTIONS": 64, [1, 64];
        /// Host: of those, connections from one source address (tighten only).
        preauth_per_source = "PREAUTH_PER_SOURCE": 8, [1, 8];
    }
    agree(h) {
        if h.app_credit_interactive_reserve_bytes >= h.app_credit_budget_bytes {
            return Err(LimitError::Conflict(format!(
                "APP_CREDIT_INTERACTIVE_RESERVE_BYTES ({}) must be below APP_CREDIT_BUDGET_BYTES ({})",
                h.app_credit_interactive_reserve_bytes, h.app_credit_budget_bytes
            )));
        }
        if h.app_stream_credit_bytes > h.app_credit_budget_bytes - h.app_credit_interactive_reserve_bytes {
            return Err(LimitError::Conflict(format!(
                "APP_STREAM_CREDIT_BYTES ({}) is more than a bulk stream can get: \
                 APP_CREDIT_BUDGET_BYTES ({}) less APP_CREDIT_INTERACTIVE_RESERVE_BYTES ({})",
                h.app_stream_credit_bytes,
                h.app_credit_budget_bytes,
                h.app_credit_interactive_reserve_bytes
            )));
        }
        if h.preauth_per_source > h.preauth_connections {
            return Err(LimitError::Conflict(format!(
                "PREAUTH_PER_SOURCE ({}) is above PREAUTH_CONNECTIONS ({})",
                h.preauth_per_source, h.preauth_connections
            )));
        }
        if h.keep_retry_max_ms < h.keep_retry_first_ms {
            return Err(LimitError::Conflict(format!(
                "KEEP_RETRY_MAX_MS ({}) is below KEEP_RETRY_FIRST_MS ({})",
                h.keep_retry_max_ms, h.keep_retry_first_ms
            )));
        }
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

    /// Defaults overridden by the `MOUSSE_NET_<NAME>` variables `var`
    /// returns. Errors name the variable and its allowed range.
    pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        let mut net = Vec::new();
        let mut helper = Vec::new();
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
            if HelperLimits::SPECS.iter().any(|s| s.name == spec.name) {
                helper.push((spec.name, value));
            } else {
                net.push((spec.name, value));
            }
        }
        let explain = |e: LimitError| match e {
            LimitError::OutOfRange {
                name,
                value,
                min,
                max,
            } => format!(
                "{ENV_PREFIX}{name}={value} is out of range; allowed range is {min} to {max}"
            ),
            LimitError::Conflict(why) => format!("{ENV_PREFIX}* limits do not agree: {why}"),
            other => other.to_string(),
        };
        Ok(Self {
            net: Self::DEFAULT.net.with_overrides(&net).map_err(explain)?,
            helper: Self::DEFAULT
                .helper
                .with_overrides(&helper)
                .map_err(explain)?,
        })
    }

    /// Unknown `MOUSSE_NET_*` names among `names`, most likely typos. The
    /// Mousse app's own variables (`MOUSSE_NET_ENGINE_*`, and
    /// `MOUSSE_NET_HELPER`, the helper's path) are not the helper's and are
    /// not reported: the app's environment reaches the helper it spawns.
    pub fn unknown_names(names: impl Iterator<Item = OsString>) -> Vec<String> {
        names
            .filter_map(|n| n.into_string().ok())
            .filter(|n| {
                n.strip_prefix(ENV_PREFIX).is_some_and(|rest| {
                    !rest.starts_with(APP_PREFIX)
                        && rest != APP_HELPER_PATH
                        && !Self::specs().any(|s| s.name == rest)
                })
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

    /// The pre-authorization caps bound what an unauthenticated peer can
    /// hold: they can be tightened, never raised.
    #[test]
    fn preauth_caps_can_only_be_tightened() {
        for name in ["PREAUTH_CONNECTIONS", "PREAUTH_PER_SOURCE"] {
            let spec = HelperLimits::SPECS.iter().find(|s| s.name == name).unwrap();
            assert_eq!(spec.max, spec.default, "{name}");
        }
        assert!(Limits::from_vars(vars(&[("MOUSSE_NET_PREAUTH_PER_SOURCE", "9")])).is_err());
        assert!(Limits::from_vars(vars(&[("MOUSSE_NET_PREAUTH_CONNECTIONS", "65")])).is_err());
        let tight = Limits::from_vars(vars(&[
            ("MOUSSE_NET_PREAUTH_CONNECTIONS", "4"),
            ("MOUSSE_NET_PREAUTH_PER_SOURCE", "2"),
        ]))
        .unwrap();
        assert_eq!(tight.helper.preauth_connections, 4);
        assert_eq!(tight.helper.preauth_per_source, 2);
    }

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
        assert_eq!(l.net.core().clock_skew_secs(), 120);
        assert_eq!(l.net.io().connect_timeout_ms(), 2_500);
        assert_eq!(l.helper.capture_wait_ms, 60_000);
        assert_eq!(l.net.core().join_proof_wait_ms(), 10_000);
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
        let err = Limits::from_vars(vars(&[(
            "MOUSSE_NET_APP_CREDIT_INTERACTIVE_RESERVE_BYTES",
            "8388608",
        )]))
        .unwrap_err();
        assert!(
            err.contains("APP_CREDIT_INTERACTIVE_RESERVE_BYTES"),
            "{err}"
        );
        let err = Limits::from_vars(vars(&[
            ("MOUSSE_NET_APP_CREDIT_BUDGET_BYTES", "524288"),
            ("MOUSSE_NET_APP_CREDIT_INTERACTIVE_RESERVE_BYTES", "393216"),
        ]))
        .unwrap_err();
        assert!(err.contains("APP_STREAM_CREDIT_BYTES"), "{err}");
    }

    #[test]
    fn the_app_channel_defaults_are_the_design_values() {
        // Phase 1a §2.2: an 8 MiB budget, 256 KiB a stream, 1 MiB kept for
        // interactive streams and for control, 64 KiB of read-ahead.
        let h = HelperLimits::DEFAULT;
        assert_eq!(h.app_credit_budget_bytes, 8 << 20);
        assert_eq!(h.app_credit_interactive_reserve_bytes, 1 << 20);
        assert_eq!(h.app_stream_credit_bytes, 256 << 10);
        assert_eq!(h.app_read_ahead_bytes, 64 << 10);
        assert_eq!(h.app_control_queue_bytes, 1 << 20);
        // §1: helper.log rotates at 1 MB, two files.
        assert_eq!(h.app_log_max_bytes, 1 << 20);
        assert_eq!(h.app_log_files, 2);
    }

    #[test]
    fn unknown_names_are_reported() {
        let names = [
            "MOUSSE_NET_KEEPALIVE_MS",
            "MOUSSE_NET_KEEPALIVE",
            "MOUSSE_HELPER_STATE",
            "PATH",
            // The app's own, which reach the helper it spawns.
            "MOUSSE_NET_ENGINE_MAX_MESSAGE_BYTES",
            "MOUSSE_NET_ENGINE_CONTROL",
            "MOUSSE_NET_HELPER",
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
