//! Pipes: any reliable, ordered byte stream the session can run over.
//!
//! The session needs nothing else from a pipe: TLS, the mux and step 2 run
//! on top. TCP (LAN, tailnet, port forward) is the first implementation; SSH
//! stdio and WebSocket pipes plug in the same way.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::error::NetError;

/// A reliable byte stream.
pub trait Pipe: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Pipe for T {}

/// How long a TCP connect may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A parsed route hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `tcp://host:port`.
    Tcp {
        /// Host name or address literal (IPv6 without brackets).
        host: String,
        /// Port.
        port: u16,
    },
}

impl Route {
    /// Parse a route hint URI. Only `tcp://` is defined so far.
    pub fn parse(uri: &str) -> Result<Self, NetError> {
        let rest = uri
            .strip_prefix("tcp://")
            .ok_or_else(|| NetError::Refused(format!("unsupported route {uri:?}")))?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
            let (host, tail) = inner
                .split_once(']')
                .ok_or_else(|| NetError::Refused(format!("bad route {uri:?}")))?;
            let port = tail
                .strip_prefix(':')
                .ok_or_else(|| NetError::Refused(format!("route {uri:?} has no port")))?;
            (host, port)
        } else {
            rest.rsplit_once(':')
                .ok_or_else(|| NetError::Refused(format!("route {uri:?} has no port")))?
        };
        if host.is_empty() {
            return Err(NetError::Refused(format!("route {uri:?} has no host")));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| NetError::Refused(format!("bad port in route {uri:?}")))?;
        Ok(Route::Tcp {
            host: host.to_owned(),
            port,
        })
    }

    /// The route for a socket address.
    pub fn from_addr(addr: SocketAddr) -> Self {
        Route::Tcp {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    /// The URI form, as written into tickets.
    pub fn to_uri(&self) -> String {
        match self {
            Route::Tcp { host, port } if host.contains(':') => format!("tcp://[{host}]:{port}"),
            Route::Tcp { host, port } => format!("tcp://{host}:{port}"),
        }
    }
}

/// Dial a TCP route.
pub async fn connect_tcp(route: &Route) -> Result<TcpStream, NetError> {
    let Route::Tcp { host, port } = route;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), *port)))
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
    fn routes_parse_and_round_trip() {
        let r = Route::parse("tcp://192.168.1.20:7443").unwrap();
        assert_eq!(
            r,
            Route::Tcp {
                host: "192.168.1.20".into(),
                port: 7443
            }
        );
        assert_eq!(r.to_uri(), "tcp://192.168.1.20:7443");
        let v6 = Route::parse("tcp://[fe80::1]:9").unwrap();
        assert_eq!(v6.to_uri(), "tcp://[fe80::1]:9");
        assert_eq!(
            Route::parse("tcp://mac.local:1").unwrap(),
            Route::Tcp {
                host: "mac.local".into(),
                port: 1
            }
        );
    }

    #[test]
    fn bad_routes_are_refused() {
        for bad in [
            "ws://x:1",
            "tcp://x",
            "tcp://:1",
            "tcp://x:99999",
            "tcp://[::1]1",
            "",
        ] {
            assert!(Route::parse(bad).is_err(), "{bad}");
        }
    }
}
