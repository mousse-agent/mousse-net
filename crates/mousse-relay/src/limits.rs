//! The relay's limits from the environment (`docs/limits.md`, "Relay"):
//! `MOUSSE_NET_RELAY_*`, read once at startup. A bad value or an unknown
//! `MOUSSE_NET_*` name stops startup with a message naming the variable.

use std::ffi::OsString;

use mousse_net_core::limits::LimitError;
use mousse_net_core::relay::RelayLimits;

/// Prefix of every limit variable.
pub const ENV_PREFIX: &str = "MOUSSE_NET_";

/// A test hook, not a limit: debug builds keep the process dumpable when it
/// is `1` (`phase3.marker` samples the relay's memory). Release builds
/// ignore it. Never refused as an unknown name.
pub const TEST_KEEP_DUMPABLE: &str = "MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE";

/// Digits only: no sign, spaces, units or underscores.
fn parse_whole(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The limits from `vars` (name, value). Every `MOUSSE_NET_*` name must be
/// a relay limit.
pub fn from_vars(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<RelayLimits, String> {
    let mut overrides = Vec::new();
    for (key, raw) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        let Some(name) = key.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        if key == TEST_KEEP_DUMPABLE {
            continue;
        }
        // Hosted mode's limits and settings are read with its settings.
        if mousse_relay_plus::settings::is_known(key) {
            continue;
        }
        let spec = RelayLimits::SPECS
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("{key} is not a relay limit (see docs/limits.md, \"Relay\")"))?;
        let range = format!("allowed range is {} to {}", spec.min, spec.max);
        let text = raw
            .to_str()
            .ok_or_else(|| format!("{key} is not valid text; {range}"))?;
        let value = parse_whole(text)
            .ok_or_else(|| format!("{key}={text:?} is not a whole number; {range}"))?;
        overrides.push((spec.name, value));
    }
    RelayLimits::DEFAULT
        .with_overrides(&overrides)
        .map_err(|e| match e {
            LimitError::OutOfRange {
                name,
                value,
                min,
                max,
            } => format!(
                "{ENV_PREFIX}{name}={value} is out of range; allowed range is {min} to {max}"
            ),
            LimitError::Conflict(why) => format!("{ENV_PREFIX}RELAY_* limits do not agree: {why}"),
            other => other.to_string(),
        })
}

/// The limits from this process's environment.
pub fn from_env() -> Result<RelayLimits, String> {
    from_vars(std::env::vars_os())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        list.iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn overrides_apply_and_bad_values_stop_startup() {
        let l = from_vars(vars(&[
            ("MOUSSE_NET_RELAY_REFUSE_MS", "700"),
            ("PATH", "x"),
        ]))
        .unwrap();
        assert_eq!(l.refuse_ms(), 700);
        // Hosted names belong to the hosted settings.
        assert!(from_vars(vars(&[
            ("MOUSSE_NET_RELAY_REPORT_MS", "5000"),
            ("MOUSSE_NET_RELAY_PLUS_URL", "https://plus.example"),
        ]))
        .is_ok());
        for (bad, says) in [
            (
                ("MOUSSE_NET_RELAY_CONNECTIONS_PER_IP", "257"),
                "out of range",
            ),
            (
                ("MOUSSE_NET_RELAY_PREACCEPT_BYTES", "65537"),
                "out of range",
            ),
            (("MOUSSE_NET_RELAY_REFUSE_MS", "5_00"), "whole number"),
            (("MOUSSE_NET_RELAY_NO_SUCH", "1"), "not a relay limit"),
            (("MOUSSE_NET_KEEPALIVE_MS", "1000"), "not a relay limit"),
            (("MOUSSE_NET_RELAY_REPORT", "1000"), "not a relay limit"),
        ] {
            let err = from_vars(vars(&[bad])).unwrap_err();
            assert!(err.contains(says), "{bad:?}: {err}");
        }
        let err = from_vars(vars(&[
            ("MOUSSE_NET_RELAY_REFUSE_MS", "5000"),
            ("MOUSSE_NET_RELAY_ACCEPT_WAIT_MS", "4000"),
        ]))
        .unwrap_err();
        assert!(err.contains("do not agree"), "{err}");
    }

    #[test]
    fn docs_list_every_relay_limit_with_its_default_and_range() {
        let doc = include_str!("../../../docs/limits.md");
        for spec in RelayLimits::SPECS {
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
}
