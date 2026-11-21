//! Pipes: any reliable, ordered byte stream the session can run over.
//!
//! The session needs nothing else from a pipe: TLS, the mux and step 2 run
//! on top. A route is a pipe kind plus an address (Phase 1b §1): `tcp`
//! (LAN, tailnet, port forward), `ws`/`wss` through a user tunnel and
//! `ssh` stdio. No pipe adds an authentication path of its own.
//!
//! [`classify`] is the one address classifier (§1.2); [`AddrPolicy`] adds
//! the build's loopback rule, and [`resolve`] turns a route into the exact
//! addresses to dial. [`LocalRoute`] is every route kind this device dials,
//! the two that never travel on the wire included.
//!
//! **Dialers for other pipes.** The caller dials `tcp` itself, and `ws`/`wss`
//! with [`ws::dial`] unless it was given another [`RouteDialer`]
//! ([`Caller::use_ws_dialer`](crate::Caller::use_ws_dialer)). An `ssh` route
//! is opened by the dialer given with
//! [`Caller::use_ssh_dialer`](crate::Caller::use_ssh_dialer). A dialer gets
//! the route, the classified address for `ws`/`wss` (`None` for `ssh`, which
//! `ssh -G` resolves) and the try's time, and returns the pipe, a
//! [`BoxPipe`]. TLS and step 1 run on top as for TCP. A `wss` dialer keeps
//! the name for SNI and `Host` only and connects to the address given.

mod classify;
mod local;
mod policy;
pub mod ssh;
pub mod test_egress;
pub mod ws;

pub use classify::{classify, AddrClass};
pub use local::{LocalRoute, RouteKind, MAX_SSH_TARGET_LEN, MAX_SSH_USER_LEN};
pub use policy::{
    resolve, AddrPolicy, ResolveFuture, Resolver, SystemResolver, TEST_CLASS_MAP_VAR,
};

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;
use crate::limits::{ms, Limits};

/// A reliable byte stream.
pub trait Pipe: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Pipe for T {}

/// A pipe of any kind.
pub type BoxPipe = Box<dyn Pipe>;

/// What a [`RouteDialer`] returns.
pub type DialFuture = Pin<Box<dyn Future<Output = Result<BoxPipe, NetError>> + Send>>;

/// Opens the pipe for one route kind other than `tcp` (see the module
/// docs).
pub trait RouteDialer: Send + Sync {
    /// Open a pipe for `route`: to `addr` for `ws`/`wss`, the classified
    /// address the caller resolved once; `None` for `ssh`. The caller gives
    /// up after `within` (`WS_DIAL_TIMEOUT_MS`, `SSH_DIAL_TIMEOUT_MS`),
    /// which also covers step 1 on the pipe.
    fn dial(&self, route: &LocalRoute, addr: Option<SocketAddr>, within: Duration) -> DialFuture;
}

impl<F> RouteDialer for F
where
    F: Fn(&LocalRoute, Option<SocketAddr>, Duration) -> DialFuture + Send + Sync,
{
    fn dial(&self, route: &LocalRoute, addr: Option<SocketAddr>, within: Duration) -> DialFuture {
        self(route, addr, within)
    }
}

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

/// Connect to exactly `addr`, giving up after `within`, with Nagle off.
pub async fn connect_addr(addr: SocketAddr, within: Duration) -> Result<TcpStream, NetError> {
    let stream = tokio::time::timeout(within, TcpStream::connect(addr))
        .await
        .map_err(|_| NetError::Timeout("TCP connect"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
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
}
