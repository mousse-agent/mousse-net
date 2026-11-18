//! Pipes: any reliable, ordered byte stream the session can run over.
//!
//! The session needs nothing else from a pipe: TLS, the mux and step 2 run
//! on top. TCP (LAN, tailnet, port forward) is the first implementation; SSH
//! stdio and WebSocket pipes plug in the same way.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;

/// A reliable byte stream.
pub trait Pipe: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Pipe for T {}

/// How long a TCP connect may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
        Route::Mdns { instance } => format!("mdns:{instance}"),
    }
}

/// Dial a `tcp://` route. Other routes need discovery first.
pub async fn connect_tcp(route: &Route) -> Result<TcpStream, NetError> {
    let Route::Tcp { host, port } = route else {
        return Err(NetError::Refused(format!(
            "{} is not a TCP route",
            route_uri(route)
        )));
    };
    let target = match host {
        RouteHost::Ipv4(ip) => IpAddr::V4(*ip).to_string(),
        RouteHost::Ipv6(ip) => IpAddr::V6(*ip).to_string(),
        RouteHost::Dns(name) => name.clone(),
    };
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.as_str(), *port)),
    )
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
    }
}
