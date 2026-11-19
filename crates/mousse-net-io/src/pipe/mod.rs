//! Pipes: any reliable, ordered byte stream the session can run over.
//!
//! The session needs nothing else from a pipe: TLS, the mux and step 2 run
//! on top. A route is a pipe kind plus an address (Phase 1b §1): `tcp`
//! (LAN, tailnet, port forward), `ws`/`wss` through a user tunnel and
//! `ssh` stdio. No pipe adds an authentication path of its own.
//!
//! [`classify`] is the one address classifier (§1.2).

mod classify;
pub mod ssh;
pub mod test_egress;
pub mod ws;

pub use classify::{classify, AddrClass};

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;
use crate::limits::{ms, Limits};

/// A reliable byte stream.
pub trait Pipe: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Pipe for T {}

pub use mousse_net_core::pairing::{Route, RouteHost};

/// Parse a route hint with core's grammar ([`Route::parse`]).
pub fn parse_route(hint: &str) -> Result<Route, NetError> {
    Route::parse(hint).map_err(|skip| NetError::Refused(format!("route {hint:?}: {skip}")))
}

/// The `tcp://` route for a socket address.
pub fn route_from_addr(addr: SocketAddr) -> Route {
    Route::Tcp {
        host: match addr.ip() {
            IpAddr::V4(ip) => RouteHost::Ipv4(ip),
            IpAddr::V6(ip) => RouteHost::Ipv6(ip),
        },
        port: addr.port(),
    }
}

/// The hint form of a route, as written into tickets.
pub fn route_uri(route: &Route) -> String {
    match route {
        Route::Tcp { host, port } => match host {
            RouteHost::Ipv4(ip) => format!("tcp://{ip}:{port}"),
            RouteHost::Ipv6(ip) => format!("tcp://[{ip}]:{port}"),
            RouteHost::Dns(name) => format!("tcp://{name}:{port}"),
        },
        Route::Wss { host, port, path } => match host {
            RouteHost::Ipv4(ip) => format!("wss://{ip}:{port}{path}"),
            RouteHost::Ipv6(ip) => format!("wss://[{ip}]:{port}{path}"),
            RouteHost::Dns(name) => format!("wss://{name}:{port}{path}"),
        },
        Route::Mdns { instance } => format!("mdns:{instance}"),
    }
}

/// Dial a `tcp://` route within the default connect timeout. Other routes
/// need discovery first.
pub async fn connect_tcp(route: &Route) -> Result<TcpStream, NetError> {
    connect_tcp_within(route, ms(Limits::DEFAULT.io().connect_timeout_ms())).await
}

/// Whether `ip` is in a private range: the `lan` class of [`classify`]
/// (RFC 1918, IPv4 link-local, IPv6 unique local outside the tailnet
/// range). An IPv4-mapped IPv6 address counts as its IPv4 address.
pub fn is_private_ip(ip: IpAddr) -> bool {
    classify(ip) == AddrClass::Lan
}

/// The address of a `tcp://` route given as an IP literal; `None` for a DNS
/// name or an mDNS route.
pub fn route_ip(route: &Route) -> Option<IpAddr> {
    match route {
        Route::Tcp {
            host: RouteHost::Ipv4(ip),
            ..
        } => Some(IpAddr::V4(*ip)),
        Route::Tcp {
            host: RouteHost::Ipv6(ip),
            ..
        } => Some(IpAddr::V6(*ip)),
        _ => None,
    }
}

/// Whether a peer-supplied route may be dialled (Phase 1a §5.3): a
/// `tcp://` route to an IP literal in a private range. Names are refused,
/// since they could resolve anywhere.
pub fn is_private_route(route: &Route) -> bool {
    route_ip(route).is_some_and(is_private_ip)
}

/// Dial a `tcp://` route, giving up after `timeout`
/// ([`IoLimits::connect_timeout_ms`](crate::limits::IoLimits::connect_timeout_ms)).
pub async fn connect_tcp_within(route: &Route, timeout: Duration) -> Result<TcpStream, NetError> {
    let Route::Tcp { host, port } = route else {
        return Err(NetError::Refused(format!(
            "{} is not a TCP route",
            route_uri(route)
        )));
    };
    let target = match host {
        RouteHost::Ipv4(ip) => {
            test_egress::check_ip(IpAddr::V4(*ip), *port)?;
            IpAddr::V4(*ip).to_string()
        }
        RouteHost::Ipv6(ip) => {
            test_egress::check_ip(IpAddr::V6(*ip), *port)?;
            IpAddr::V6(*ip).to_string()
        }
        RouteHost::Dns(name) => {
            test_egress::check_name(name, *port)?;
            name.clone()
        }
    };
    let stream = tokio::time::timeout(timeout, TcpStream::connect((target.as_str(), *port)))
        .await
        .map_err(|_| NetError::Timeout("TCP connect"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Accept one TCP connection, with Nagle off.
pub async fn accept_tcp(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), NetError> {
    let (stream, addr) = listener.accept().await?;
    stream.set_nodelay(true)?;
    Ok((stream, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_hints_parse_back_to_the_same_route() {
        for addr in ["192.168.1.20:7443", "[fe80::1]:9"] {
            let route = route_from_addr(addr.parse().unwrap());
            assert_eq!(parse_route(&route_uri(&route)).unwrap(), route);
        }
        let named = parse_route("tcp://mac.local:1").unwrap();
        assert_eq!(route_uri(&named), "tcp://mac.local:1");
        assert!(parse_route("ws://x:1").is_err());
        let tunnel = parse_route("wss://X.example/mousse-net/1").unwrap();
        assert_eq!(route_uri(&tunnel), "wss://x.example:443/mousse-net/1");
        assert_eq!(parse_route(&route_uri(&tunnel)).unwrap(), tunnel);
    }

    #[test]
    fn private_ranges_are_rfc1918_link_local_and_ula_only() {
        for ok in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.20",
            "169.254.3.4",
            "fc00::1",
            "fd12:3456::9",
            "::ffff:192.168.0.2",
        ] {
            assert!(is_private_ip(ok.parse().unwrap()), "{ok}");
        }
        for no in [
            "8.8.8.8",
            "172.32.0.1",
            "172.15.255.255",
            "100.64.0.1",
            "100.100.100.100",
            "127.0.0.1",
            "0.0.0.0",
            "203.0.113.9",
            "fe80::1",
            "::1",
            "2001:db8::1",
            "fe00::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_private_ip(no.parse().unwrap()), "{no}");
        }
        assert!(is_private_route(
            &parse_route("tcp://192.168.1.2:7443").unwrap()
        ));
        assert!(is_private_route(
            &parse_route("tcp://[fd00::2]:7443").unwrap()
        ));
        assert!(!is_private_route(
            &parse_route("tcp://mac.local:7443").unwrap()
        ));
        assert!(!is_private_route(
            &parse_route("tcp://8.8.8.8:7443").unwrap()
        ));
    }
}
