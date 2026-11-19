//! Routes this device may dial (Phase 1b §1.1): the wire's `tcp` and `wss`
//! routes, plus two that never travel on the wire: a plain `ws` to a
//! loopback address (the local hop of the owner's tunnel client) and `ssh`.
//! Core never sees the last two, so they live here.

use std::fmt;
use std::net::IpAddr;

use mousse_net_core::pairing::{parse_host, parse_port, parse_wss_path, Route, RouteHost};

use crate::error::NetError;

/// Longest `ssh` user, in bytes.
pub const MAX_SSH_USER_LEN: usize = 64;

/// Longest `ssh` target name, in bytes.
pub const MAX_SSH_TARGET_LEN: usize = 253;

/// Which tier of the dial a route is in (§1.4), and which pipe it yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// A TCP connection.
    Tcp,
    /// A WebSocket, `ws` or `wss`.
    Ws,
    /// `ssh` stdio.
    Ssh,
}

impl RouteKind {
    /// The name `conn.up` uses.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Ssh => "ssh",
        }
    }
}

/// A route this device may dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalRoute {
    /// `tcp://<host>:<port>` (wire 10.2.1).
    Tcp {
        /// Where to connect.
        host: RouteHost,
        /// TCP port.
        port: u16,
    },
    /// `wss://<host>[:<port>]<path>` (wire 10.2.1).
    Wss {
        /// Where to connect; a name is also sent for SNI and `Host`.
        host: RouteHost,
        /// TCP port (443 by default).
        port: u16,
        /// The request path, ending in `/mousse-net/1`.
        path: String,
    },
    /// `ws://<loopback>:<port><path>`: owner-entered only, loopback only.
    Ws {
        /// A loopback address (`127.0.0.0/8` or `::1`).
        host: IpAddr,
        /// TCP port; always given.
        port: u16,
        /// The request path, ending in `/mousse-net/1`.
        path: String,
    },
    /// `ssh://[<user>@]<target>[:<port>]`: owner-entered only, never on
    /// the wire. The target is resolved by `ssh -G`, never here.
    Ssh {
        /// The login, if given.
        user: Option<String>,
        /// An IP literal or a name (an `~/.ssh/config` alias may hold `_`),
        /// lowercased.
        target: String,
        /// The port, if given; otherwise `ssh -G` decides.
        port: Option<u16>,
    },
}

impl LocalRoute {
    /// Read an owner-entered route of any kind. A `wss` or `tcp` route
    /// follows core's grammar; `mdns` is not a route the owner enters.
    pub fn parse(text: &str) -> Result<Self, NetError> {
        let bad = || NetError::Refused(format!("not a route: {text:?}"));
        let (scheme, rest) = text.split_once(':').ok_or_else(bad)?;
        match scheme {
            "tcp" | "wss" => Route::parse(text)
                .ok()
                .and_then(Self::from_route)
                .ok_or_else(bad),
            "ws" => parse_ws(rest).ok_or_else(bad),
            "ssh" => parse_ssh(rest).ok_or_else(bad),
            _ => Err(bad()),
        }
    }

    /// The route for a wire route; `None` for `mdns`, which needs a browse.
    pub fn from_route(route: Route) -> Option<Self> {
        match route {
            Route::Tcp { host, port } => Some(Self::Tcp { host, port }),
            Route::Wss { host, port, path } => Some(Self::Wss { host, port, path }),
            Route::Mdns { .. } => None,
        }
    }

    /// The wire route, for `tcp` and `wss`.
    pub fn to_route(&self) -> Option<Route> {
        match self {
            Self::Tcp { host, port } => Some(Route::Tcp {
                host: host.clone(),
                port: *port,
            }),
            Self::Wss { host, port, path } => Some(Route::Wss {
                host: host.clone(),
                port: *port,
                path: path.clone(),
            }),
            _ => None,
        }
    }

    /// A `tcp://` route to `addr`.
    pub fn tcp(addr: std::net::SocketAddr) -> Self {
        Self::Tcp {
            host: host_of(addr.ip()),
            port: addr.port(),
        }
    }

    /// The tier this route is dialled in.
    pub fn kind(&self) -> RouteKind {
        match self {
            Self::Tcp { .. } => RouteKind::Tcp,
            Self::Wss { .. } | Self::Ws { .. } => RouteKind::Ws,
            Self::Ssh { .. } => RouteKind::Ssh,
        }
    }

    /// The IP address the route names, if it names one: a `tcp`, `wss` or
    /// `ws` host given as a literal. An `ssh` target is the client's.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Tcp { host, .. } | Self::Wss { host, .. } => host_ip(host),
            Self::Ws { host, .. } => Some(*host),
            Self::Ssh { .. } => None,
        }
    }

    /// The port to dial, where this side resolves the host.
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Tcp { port, .. } | Self::Wss { port, .. } | Self::Ws { port, .. } => Some(*port),
            Self::Ssh { port, .. } => *port,
        }
    }

    /// The ws client's destination for a `ws` or `wss` route.
    pub fn ws_target(&self) -> Option<super::ws::WsTarget> {
        match self {
            Self::Wss { host, port, path } => Some(super::ws::WsTarget {
                secure: true,
                host: host.clone(),
                port: *port,
                path: path.clone(),
            }),
            Self::Ws { host, port, path } => Some(super::ws::WsTarget {
                secure: false,
                host: host_of(*host),
                port: *port,
                path: path.clone(),
            }),
            _ => None,
        }
    }

    /// The canonical form: scheme, lower-case host, explicit port and path
    /// (§1.3), as stored in `approvals.json`. An `ssh` route keeps the port
    /// only when given, since `~/.ssh/config` may set it.
    pub fn uri(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp://{}:{port}", host_text(host)),
            Self::Wss { host, port, path } => format!("wss://{}:{port}{path}", host_text(host)),
            Self::Ws { host, port, path } => {
                format!("ws://{}:{port}{path}", host_text(&host_of(*host)))
            }
            Self::Ssh { user, target, port } => {
                let mut out = String::from("ssh://");
                if let Some(user) = user {
                    out.push_str(user);
                    out.push('@');
                }
                if target.contains(':') {
                    out.push_str(&format!("[{target}]"));
                } else {
                    out.push_str(target);
                }
                if let Some(port) = port {
                    out.push_str(&format!(":{port}"));
                }
                out
            }
        }
    }
}

impl fmt::Display for LocalRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri())
    }
}

fn host_of(ip: IpAddr) -> RouteHost {
    match ip {
        IpAddr::V4(ip) => RouteHost::Ipv4(ip),
        IpAddr::V6(ip) => RouteHost::Ipv6(ip),
    }
}

fn host_ip(host: &RouteHost) -> Option<IpAddr> {
    match host {
        RouteHost::Ipv4(ip) => Some(IpAddr::V4(*ip)),
        RouteHost::Ipv6(ip) => Some(IpAddr::V6(*ip)),
        RouteHost::Dns(_) => None,
    }
}

fn host_text(host: &RouteHost) -> String {
    match host {
        RouteHost::Ipv4(ip) => ip.to_string(),
        RouteHost::Ipv6(ip) => format!("[{ip}]"),
        RouteHost::Dns(name) => name.clone(),
    }
}

/// `//<loopback literal>:<port><path>`.
fn parse_ws(rest: &str) -> Option<LocalRoute> {
    let rest = rest.strip_prefix("//")?;
    let slash = rest.find('/')?;
    let (authority, path) = rest.split_at(slash);
    let (host, port) = authority.rsplit_once(':')?;
    let host = host_ip(&parse_host(host)?)?;
    if !host.is_loopback() {
        return None;
    }
    Some(LocalRoute::Ws {
        host,
        port: parse_port(port)?,
        path: parse_wss_path(path)?,
    })
}

/// `//[<user>@]<target>[:<port>]`.
fn parse_ssh(rest: &str) -> Option<LocalRoute> {
    let rest = rest.strip_prefix("//")?;
    let (user, authority) = match rest.split_once('@') {
        Some((user, authority)) => (Some(user), authority),
        None => (None, rest),
    };
    if let Some(user) = user {
        if !name_ok(user, MAX_SSH_USER_LEN) {
            return None;
        }
    }
    let (target, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (addr, after) = inner.split_once(']')?;
        let ip: std::net::Ipv6Addr = addr.parse().ok()?;
        let port = match after {
            "" => None,
            p => Some(parse_port(p.strip_prefix(':')?)?),
        };
        (ip.to_string(), port)
    } else {
        let (target, port) = match authority.rsplit_once(':') {
            Some((t, p)) => (t, Some(parse_port(p)?)),
            None => (authority, None),
        };
        if !name_ok(target, MAX_SSH_TARGET_LEN) {
            return None;
        }
        (target.to_ascii_lowercase(), port)
    };
    Some(LocalRoute::Ssh {
        user: user.map(str::to_owned),
        target,
        port,
    })
}

/// 1 to `max` bytes of `[A-Za-z0-9._-]`, not starting with `-` (§1.1).
fn name_ok(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && !text.starts_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_parses_to_its_canonical_form() {
        for (text, uri) in [
            ("tcp://Mac.Local:7443", "tcp://mac.local:7443"),
            (
                "wss://X.example/mousse-net/1",
                "wss://x.example:443/mousse-net/1",
            ),
            (
                "ws://127.0.0.1:8080/t/mousse-net/1",
                "ws://127.0.0.1:8080/t/mousse-net/1",
            ),
            ("ws://[::1]:9/mousse-net/1", "ws://[::1]:9/mousse-net/1"),
            ("ssh://me@Box_1:2222", "ssh://me@box_1:2222"),
            ("ssh://[fd00::1]", "ssh://[fd00::1]"),
            ("ssh://host", "ssh://host"),
        ] {
            let route = LocalRoute::parse(text).unwrap();
            assert_eq!(route.uri(), uri, "{text}");
            assert_eq!(LocalRoute::parse(&route.uri()).unwrap(), route, "{text}");
        }
    }

    #[test]
    fn plain_ws_is_loopback_only_and_ssh_names_are_checked() {
        for bad in [
            "ws://192.168.1.2:80/mousse-net/1",
            "ws://localhost:80/mousse-net/1",
            "ws://127.0.0.1/mousse-net/1",
            "ws://127.0.0.1:80/other",
            "ssh://-oProxyCommand=x",
            "ssh://me@-x",
            "ssh://-me@x",
            "ssh://a b",
            "ssh://",
            "mdns:x",
            "relay://x",
        ] {
            assert!(LocalRoute::parse(bad).is_err(), "{bad}");
        }
    }
}
