//! The check kit's egress fence for the helper (Phase 1b §14, "Plus and
//! egress"). Debug builds only: when `MOUSSE_NET_TEST_EGRESS` is set, a
//! dial to anything but loopback and the IP literals it lists (the Mac's
//! address in cross-machine cells) is refused, and a name other than
//! `localhost` is never resolved. Each refusal appends one JSON line to
//! `MOUSSE_NET_TEST_EGRESS_LOG`, which the kit reads to fail the run with
//! `egress_attempted`. Release builds never read either variable.

use std::io::Write as _;
use std::net::IpAddr;

use crate::error::NetError;

/// Comma-separated IP literals a check allows besides loopback.
pub const TEST_EGRESS_VAR: &str = "MOUSSE_NET_TEST_EGRESS";
/// Where refused dials are logged.
pub const TEST_EGRESS_LOG_VAR: &str = "MOUSSE_NET_TEST_EGRESS_LOG";

/// The fence in force: `None` when there is none (release builds, or the
/// variable unset), else the allowed addresses besides loopback.
fn fence() -> Option<Vec<IpAddr>> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let list = std::env::var(TEST_EGRESS_VAR).ok()?;
    Some(parse(&list))
}

fn parse(list: &str) -> Vec<IpAddr> {
    list.split(',')
        .map(|s| s.trim().trim_start_matches('[').trim_end_matches(']'))
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn allows(allowed: &[IpAddr], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    ip.is_loopback() || allowed.contains(&ip)
}

fn refuse(target: &str) -> NetError {
    if let Some(path) = std::env::var_os(TEST_EGRESS_LOG_VAR) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let line =
                serde_json::json!({"kind": "helper", "target": target, "pid": std::process::id()});
            let _ = writeln!(f, "{line}");
        }
    }
    NetError::Refused(format!(
        "{target} is outside {TEST_EGRESS_VAR} (a check's egress fence)"
    ))
}

/// Before dialling `ip`.
pub fn check_ip(ip: IpAddr, port: u16) -> Result<(), NetError> {
    match fence() {
        Some(allowed) if !allows(&allowed, ip) => Err(refuse(&format!("{ip}:{port}"))),
        _ => Ok(()),
    }
}

/// Before resolving `name`: under the fence only `localhost` resolves.
pub fn check_name(name: &str, port: u16) -> Result<(), NetError> {
    match fence() {
        Some(_) if !name.eq_ignore_ascii_case("localhost") => {
            Err(refuse(&format!("{name}:{port}")))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_listed_addresses_pass_and_nothing_else_does() {
        let allowed = parse(" 192.168.0.59 , [fd00::1],junk");
        assert_eq!(allowed.len(), 2);
        assert!(allows(&allowed, "127.0.0.1".parse().unwrap()));
        assert!(allows(&allowed, "::1".parse().unwrap()));
        assert!(allows(&allowed, "::ffff:127.0.0.1".parse().unwrap()));
        assert!(allows(&allowed, "192.168.0.59".parse().unwrap()));
        assert!(allows(&allowed, "fd00::1".parse().unwrap()));
        assert!(!allows(&allowed, "192.168.0.60".parse().unwrap()));
        assert!(!allows(&allowed, "8.8.8.8".parse().unwrap()));
        assert!(!allows(&[], "10.0.0.1".parse().unwrap()));
    }
}
