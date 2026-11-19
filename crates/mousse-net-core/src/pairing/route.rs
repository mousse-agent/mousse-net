//! Route hints: where a joiner can reach the host (spec `wire.md`, "Route
//! hints").
//!
//! A ticket carries up to 8 hints as plain text. The ticket accepts any text
//! of 1 to 255 bytes; this module reads one hint. A hint that cannot be used
//! is skipped, never an error: the joiner tries the next one.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

/// Schemes kept for transports that are not defined on the wire. Hints with
/// them are skipped: `ssh` and plain `ws` are owner-entered only (Phase 1b
/// §1.1), never read from a ticket.
pub const RESERVED_SCHEMES: [&str; 3] = ["ssh", "ws", "relay"];

/// Every `wss` path ends with this.
pub const WSS_PATH_SUFFIX: &str = "/mousse-net/1";

/// Longest `wss` path, in bytes.
pub const MAX_WSS_PATH_LEN: usize = 200;

/// The port a `wss` hint without one uses.
pub const WSS_DEFAULT_PORT: u16 = 443;

/// Longest DNS name in a `tcp` hint, in bytes.
pub const MAX_DNS_NAME_LEN: usize = 253;

/// Longest mDNS instance name, in bytes.
pub const MAX_MDNS_INSTANCE_LEN: usize = 63;

/// The host part of a `tcp` hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteHost {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address (written in brackets in the hint).
    Ipv6(Ipv6Addr),
    /// A DNS name, lowercased.
    Dns(String),
}

/// A usable route hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `tcp://<host>:<port>`: a direct TLS connection.
    Tcp {
        /// Where to connect.
        host: RouteHost,
        /// TCP port, 1 to 65535.
        port: u16,
    },
    /// `wss://<host>[:<port>]<path>`: TLS 1.3 inside a WebSocket over TLS,
    /// through a tunnel the host's owner runs.
    Wss {
        /// Where to connect (also the name for SNI and `Host`).
        host: RouteHost,
        /// TCP port, 1 to 65535 (443 when the hint gives none).
        port: u16,
        /// The request path: `/`, ASCII `[A-Za-z0-9._~/-]`, at most 200
        /// bytes, ending in `/mousse-net/1`.
        path: String,
    },
    /// `mdns:<instance>`: browse for this service instance on the local
    /// network.
    Mdns {
        /// The service instance name (1 to 63 bytes).
        instance: String,
    },
}

/// Why a hint was skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteSkip {
    /// A reserved scheme ([`RESERVED_SCHEMES`]).
    Reserved,
    /// A scheme this version does not know, or no scheme at all.
    UnknownScheme,
    /// A known scheme whose rest does not follow the grammar.
    Malformed,
}

impl RouteSkip {
    /// The name used in test vectors.
    pub fn name(self) -> &'static str {
        match self {
            RouteSkip::Reserved => "reserved",
            RouteSkip::UnknownScheme => "unknown_scheme",
            RouteSkip::Malformed => "malformed",
        }
    }
}

impl fmt::Display for RouteSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Route {
    /// Read one hint. The scheme is everything before the first `:` and is
    /// matched exactly (lowercase).
    pub fn parse(hint: &str) -> Result<Route, RouteSkip> {
        let Some((scheme, rest)) = hint.split_once(':') else {
            return Err(RouteSkip::UnknownScheme);
        };
        match scheme {
            "tcp" => parse_tcp(rest).ok_or(RouteSkip::Malformed),
            "wss" => parse_wss(rest).ok_or(RouteSkip::Malformed),
            "mdns" => parse_mdns(rest).ok_or(RouteSkip::Malformed),
            s if RESERVED_SCHEMES.contains(&s) => Err(RouteSkip::Reserved),
            _ => Err(RouteSkip::UnknownScheme),
        }
    }
}

fn parse_tcp(rest: &str) -> Option<Route> {
    let authority = rest.strip_prefix("//")?;
    let (host, port) = authority.rsplit_once(':')?;
    let port = parse_port(port)?;
    let host = parse_host(host)?;
    Some(Route::Tcp { host, port })
}

/// `//<host>[:<port>]<path>`.
fn parse_wss(rest: &str) -> Option<Route> {
    let rest = rest.strip_prefix("//")?;
    let slash = rest.find('/')?;
    let (authority, path) = rest.split_at(slash);
    let (host, port) = split_host_port(authority)?;
    let port = match port {
        Some(port) => parse_port(port)?,
        None => WSS_DEFAULT_PORT,
    };
    Some(Route::Wss {
        host: parse_host(host)?,
        port,
        path: parse_wss_path(path)?,
    })
}

/// `<host>` or `<host>:<port>`, with an IPv6 host in brackets.
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, after) = authority.split_at(end + 1);
        match after {
            "" => Some((host, None)),
            _ => Some((host, Some(after.strip_prefix(':')?))),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => Some((host, Some(port))),
            None => Some((authority, None)),
        }
    }
}

/// A path the `wss` grammar allows (Phase 1b §1.1).
pub fn parse_wss_path(path: &str) -> Option<String> {
    let ok = path.starts_with('/')
        && path.len() <= MAX_WSS_PATH_LEN
        && path.ends_with(WSS_PATH_SUFFIX)
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-'));
    ok.then(|| path.to_owned())
}

/// The host of a `tcp` or `wss` hint, read by its shape.
pub fn parse_host(host: &str) -> Option<RouteHost> {
    Some(if let Some(inner) = host.strip_prefix('[') {
        let addr = inner.strip_suffix(']')?;
        // Rust's parser takes the RFC 4291 text forms and no zone id.
        RouteHost::Ipv6(Ipv6Addr::from_str(addr).ok()?)
    } else if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        RouteHost::Ipv4(parse_ipv4(host)?)
    } else {
        RouteHost::Dns(parse_dns(host)?)
    })
}

/// Decimal 1 to 65535, no sign, no leading zero.
pub fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty()
        || text.len() > 5
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    u16::try_from(text.parse::<u32>().ok()?).ok()
}

/// Four decimal parts 0 to 255, no leading zeros.
fn parse_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

/// Labels of 1 to 63 letters, digits and hyphens, not starting or ending
/// with a hyphen, joined by dots; at most 253 bytes; the last label is not
/// all digits. No trailing dot.
fn parse_dns(text: &str) -> Option<String> {
    if text.is_empty() || text.len() > MAX_DNS_NAME_LEN {
        return None;
    }
    let mut last_all_digits = false;
    for label in text.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return None;
        }
        last_all_digits = label.bytes().all(|b| b.is_ascii_digit());
    }
    if last_all_digits {
        return None;
    }
    Some(text.to_ascii_lowercase())
}

/// 1 to 63 bytes of UTF-8 with no control characters.
fn parse_mdns(rest: &str) -> Option<Route> {
    if rest.is_empty() || rest.len() > MAX_MDNS_INSTANCE_LEN || rest.chars().any(char::is_control) {
        return None;
    }
    Some(Route::Mdns {
        instance: rest.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn tcp(host: RouteHost, port: u16) -> Result<Route, RouteSkip> {
        Ok(Route::Tcp { host, port })
    }

    #[test]
    fn tcp_hints_take_ipv4_bracketed_ipv6_and_dns_names() {
        assert_eq!(
            Route::parse("tcp://192.168.1.20:7443"),
            tcp(RouteHost::Ipv4(Ipv4Addr::new(192, 168, 1, 20)), 7443)
        );
        assert_eq!(
            Route::parse("tcp://[fd00::20]:1"),
            tcp(RouteHost::Ipv6("fd00::20".parse().unwrap()), 1)
        );
        assert_eq!(
            Route::parse("tcp://Desk-1.Local:65535"),
            tcp(RouteHost::Dns("desk-1.local".into()), 65535)
        );
        for bad in [
            "tcp://192.168.1.20",
            "tcp://192.168.1.20:0",
            "tcp://192.168.1.20:65536",
            "tcp://192.168.1.20:07443",
            "tcp://192.168.01.20:7443",
            "tcp://192.168.1.256:7443",
            "tcp://1.2.3:7443",
            "tcp://fd00::20:7443",
            "tcp://[fe80::1%eth0]:7443",
            "tcp://[::ffff:192.168.01.20]:7443",
            "tcp://-desk.local:7443",
            "tcp://desk..local:7443",
            "tcp://desk.local.:7443",
            "tcp://desk_1.local:7443",
            "tcp://desk.123:7443",
            "tcp://user@desk.local:7443",
            "tcp://desk.local:7443/path",
            "tcp:desk.local:7443",
        ] {
            assert_eq!(Route::parse(bad), Err(RouteSkip::Malformed), "{bad}");
        }
        let long = format!("tcp://{}.local:1", "a".repeat(64));
        assert_eq!(Route::parse(&long), Err(RouteSkip::Malformed));
    }

    #[test]
    fn wss_hints_take_a_host_an_optional_port_and_the_mousse_path() {
        let wss = |host, port, path: &str| {
            Ok(Route::Wss {
                host,
                port,
                path: path.into(),
            })
        };
        assert_eq!(
            Route::parse("wss://X.Example/mousse-net/1"),
            wss(RouteHost::Dns("x.example".into()), 443, "/mousse-net/1")
        );
        assert_eq!(
            Route::parse("wss://[fd00::1]:8443/a_b.c~d/mousse-net/1"),
            wss(
                RouteHost::Ipv6("fd00::1".parse().unwrap()),
                8443,
                "/a_b.c~d/mousse-net/1"
            )
        );
        assert_eq!(
            Route::parse("wss://203.0.113.7:7443/t/mousse-net/1"),
            wss(
                RouteHost::Ipv4(Ipv4Addr::new(203, 0, 113, 7)),
                7443,
                "/t/mousse-net/1"
            )
        );
        let long = format!("wss://x.example/{}/mousse-net/1", "a".repeat(186));
        assert_eq!(Route::parse(&long).map(|_| ()), Ok(()));
        let too_long = format!("wss://x.example/{}/mousse-net/1", "a".repeat(187));
        for bad in [
            too_long.as_str(),
            "wss://x.example",
            "wss://x.example/",
            "wss://x.example/mousse-net/2",
            "wss://x.example/mousse-net/1/",
            "wss://x.example/mousse-net/1?a=b",
            "wss://x.example/mousse-net/1#f",
            "wss://x.example/a%20b/mousse-net/1",
            "wss://user@x.example/mousse-net/1",
            "wss://x.example:0/mousse-net/1",
            "wss://x.example:/mousse-net/1",
            "wss://[fd00::1/mousse-net/1",
            "wss://fd00::1/mousse-net/1",
            "wss:x.example/mousse-net/1",
        ] {
            assert_eq!(Route::parse(bad), Err(RouteSkip::Malformed), "{bad}");
        }
    }

    #[test]
    fn mdns_reserved_and_unknown_schemes() {
        assert_eq!(
            Route::parse("mdns:Desk"),
            Ok(Route::Mdns {
                instance: "Desk".into()
            })
        );
        assert_eq!(Route::parse("mdns:"), Err(RouteSkip::Malformed));
        assert_eq!(
            Route::parse(&format!("mdns:{}", "a".repeat(64))),
            Err(RouteSkip::Malformed)
        );
        assert_eq!(Route::parse("mdns:a\nb"), Err(RouteSkip::Malformed));
        for reserved in ["ssh://h", "ws://h", "relay:x"] {
            assert_eq!(Route::parse(reserved), Err(RouteSkip::Reserved));
        }
        for unknown in ["quic://h:1", "TCP://h:1", "no-scheme", ""] {
            assert_eq!(Route::parse(unknown), Err(RouteSkip::UnknownScheme));
        }
    }
}
