//! The hosted relay's settings and limits from the environment
//! (`docs/limits.md`, "Relay").
//!
//! `MOUSSE_NET_RELAY_PLUS_URL` is a setting, not a limit: the Plus base URL.
//! Limits are `MOUSSE_NET_<NAME>` for every row of [`HostedLimits::SPECS`];
//! each name starts with `RELAY_`, as the relay's other limits do. Both are read once at startup; a bad value stops
//! startup with a message naming the variable.

use std::ffi::OsString;
use std::net::IpAddr;

use mousse_net_core::limits::LimitError;
use mousse_net_core::relay_hosted::HostedLimits;

/// The prefix of every limit variable; the relay's names then start with
/// `RELAY_`.
pub const ENV_PREFIX: &str = "MOUSSE_NET_";

/// The Plus base URL setting.
pub const PLUS_URL_VAR: &str = "MOUSSE_NET_RELAY_PLUS_URL";

/// Every relay setting that is not a limit.
pub const SETTINGS: &[&str] = &[PLUS_URL_VAR];

/// Where Plus is: `https://host[:port][/base]`, or, for tests on one
/// machine only, `http://` to a loopback address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlusUrl {
    /// TLS 1.3 with the platform verifier; false only for loopback.
    pub tls: bool,
    /// Host name or IP address, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Path prefix without a trailing slash; empty for the root.
    pub base_path: String,
}

impl PlusUrl {
    /// Parse a base URL. No user, query or fragment.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (tls, rest) = if let Some(r) = text.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = text.strip_prefix("http://") {
            (false, r)
        } else {
            return Err("must start with https://".into());
        };
        if rest.contains(['?', '#', '@']) || rest.chars().any(|c| c.is_whitespace()) {
            return Err("must not have a user, query, fragment or spaces".into());
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let end = after
                .find(']')
                .ok_or("an IPv6 address needs its closing ]")?;
            let host = &after[..end];
            let tail = &after[end + 1..];
            let port = match tail.strip_prefix(':') {
                Some(p) => Some(p),
                None if tail.is_empty() => None,
                None => return Err("unexpected text after the IPv6 address".into()),
            };
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err("not an IPv6 address in [ ]".into());
            }
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err("has no host".into());
        }
        let port = match port {
            None => {
                if tls {
                    443
                } else {
                    80
                }
            }
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n > 0 && p.bytes().all(|b| b.is_ascii_digit()) => n,
                _ => return Err(format!("port {p:?} is not 1 to 65535")),
            },
        };
        if !tls {
            let loopback = host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if !loopback {
                return Err(
                    "http:// is allowed only to a loopback address (tests); use https://".into(),
                );
            }
        }
        let base_path = path.trim_end_matches('/').to_owned();
        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            base_path,
        })
    }

    /// The `Host` header value.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The request target for an API path such as `/v1/relay/boot`.
    pub fn target(&self, path: &str) -> String {
        format!("{}{path}", self.base_path)
    }
}

/// The hosted relay's settings and limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedSettings {
    /// `MOUSSE_NET_RELAY_PLUS_URL`.
    pub plus_url: PlusUrl,
    /// The `MOUSSE_NET_RELAY_*` limits of [`HostedLimits`].
    pub limits: HostedLimits,
}

/// Digits only: no sign, spaces, units or underscores.
fn parse_whole(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The hosted limits from the `MOUSSE_NET_RELAY_*` variables that `var`
/// returns. Errors name the variable and its range.
pub fn limits_from_vars(var: &impl Fn(&str) -> Option<OsString>) -> Result<HostedLimits, String> {
    let mut overrides = Vec::new();
    for spec in HostedLimits::SPECS {
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
        overrides.push((spec.name, value));
    }
    HostedLimits::DEFAULT
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
            LimitError::Conflict(why) => format!("{ENV_PREFIX}* limits do not agree: {why}"),
            other => other.to_string(),
        })
}

/// The hosted settings from the variables `var` returns. The Plus URL is
/// required in hosted mode.
pub fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Result<HostedSettings, String> {
    let raw = var(PLUS_URL_VAR)
        .ok_or_else(|| format!("{PLUS_URL_VAR} is not set; hosted mode needs the Plus base URL"))?;
    let text = raw
        .to_str()
        .ok_or_else(|| format!("{PLUS_URL_VAR} is not valid text"))?;
    let plus_url = PlusUrl::parse(text).map_err(|why| format!("{PLUS_URL_VAR}={text:?} {why}"))?;
    Ok(HostedSettings {
        plus_url,
        limits: limits_from_vars(&var)?,
    })
}

/// Whether the variable `name` is a hosted limit or setting, for the
/// relay's unknown-variable check.
pub fn is_known(name: &str) -> bool {
    SETTINGS.contains(&name)
        || name
            .strip_prefix(ENV_PREFIX)
            .is_some_and(|rest| HostedLimits::SPECS.iter().any(|s| s.name == rest))
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
    fn https_urls_parse_with_their_defaults() {
        let u = PlusUrl::parse("https://plus.example").unwrap();
        assert_eq!(
            u,
            PlusUrl {
                tls: true,
                host: "plus.example".into(),
                port: 443,
                base_path: String::new()
            }
        );
        assert_eq!(u.target("/v1/relay/boot"), "/v1/relay/boot");
        assert_eq!(u.authority(), "plus.example");
        let u = PlusUrl::parse("https://[2001:db8::1]:8443/api/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 8443));
        assert_eq!(u.target("/v1/relay/report"), "/api/v1/relay/report");
        assert_eq!(u.authority(), "[2001:db8::1]:8443");
    }

    #[test]
    fn plain_http_only_to_loopback() {
        assert!(PlusUrl::parse("http://127.0.0.1:9000").is_ok());
        assert!(PlusUrl::parse("http://[::1]:9000").is_ok());
        assert!(PlusUrl::parse("http://plus.example").is_err());
        assert!(PlusUrl::parse("http://10.0.0.1:9000").is_err());
        assert!(PlusUrl::parse("http://localhost:9000").is_err());
    }

    #[test]
    fn bad_urls_are_refused() {
        for bad in [
            "ftp://x",
            "plus.example",
            "https://",
            "https://u@plus.example",
            "https://plus.example/?a=1",
            "https://plus.example:0",
            "https://plus.example:70000",
            "https://plus.example:+5",
            "https://[nope]:1",
        ] {
            assert!(PlusUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_url_is_required_and_errors_name_the_variable() {
        let e = from_vars(vars(&[])).unwrap_err();
        assert!(e.contains(PLUS_URL_VAR), "{e}");
        let e = from_vars(vars(&[(PLUS_URL_VAR, "http://plus.example")])).unwrap_err();
        assert!(e.contains(PLUS_URL_VAR), "{e}");
        let ok = from_vars(vars(&[(PLUS_URL_VAR, "https://plus.example")])).unwrap();
        assert_eq!(ok.limits, HostedLimits::DEFAULT);
    }

    #[test]
    fn limits_are_read_with_the_relay_prefix_and_checked() {
        let url = (PLUS_URL_VAR, "https://plus.example");
        let s = from_vars(vars(&[url, ("MOUSSE_NET_RELAY_REPORT_MS", "5000")])).unwrap();
        assert_eq!(s.limits.report_ms(), 5_000);
        // The refill wait can only be shortened.
        let e = from_vars(vars(&[url, ("MOUSSE_NET_RELAY_REFILL_WAIT_MS", "10001")])).unwrap_err();
        assert!(e.contains("MOUSSE_NET_RELAY_REFILL_WAIT_MS"), "{e}");
        let e = from_vars(vars(&[url, ("MOUSSE_NET_RELAY_REPORT_MS", "5s")])).unwrap_err();
        assert!(e.contains("not a whole number"), "{e}");
        let e = from_vars(vars(&[
            url,
            ("MOUSSE_NET_RELAY_REPORT_MS", "1000"),
            ("MOUSSE_NET_RELAY_REPORT_MIN_MS", "1000"),
        ]))
        .unwrap_err();
        assert!(e.contains("do not agree"), "{e}");
    }

    #[test]
    fn known_names() {
        assert!(is_known("MOUSSE_NET_RELAY_PLUS_URL"));
        assert!(is_known("MOUSSE_NET_RELAY_CLOCK_RTT_MS"));
        assert!(!is_known("MOUSSE_NET_RELAY_CLOCK_RTT"));
    }
}
