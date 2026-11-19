//! A native relay client connection (spec `relay.md` 2): pinned TLS with
//! the hybrid group, the WebSocket upgrade, and `RELAY_HELLO`. Used by the
//! tests and the E-R0 measurements; the helper's client builds on the same
//! rules.

use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use mousse_net_core::relay::msg::Mode;
use mousse_net_core::relay::proof::Binding;
use mousse_net_core::relay::{RelayId, RelayMessage};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{tls, upgrade};

/// What arrived on a relay connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A relay message (before `SPLICED`).
    Relay(RelayMessage),
    /// A peer message (after `SPLICED`).
    Peer(Vec<u8>),
    /// The relay closed the connection with this WebSocket code.
    Closed(Option<u16>),
}

/// One outer connection to a relay.
pub struct RelayConn {
    ws: WebSocketStream<Box<dyn crate::Io>>,
    /// The connection's nonce and outer exporter, for proofs.
    pub binding: Binding,
    /// The relay's boot id.
    pub boot_id: [u8; 16],
    /// The relay's mode.
    pub mode: Mode,
    spliced: bool,
}

impl std::fmt::Debug for RelayConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayConn(..)")
    }
}

/// Why a dial failed.
#[derive(Debug)]
pub enum DialError {
    /// TCP connect failed.
    Connect(std::io::Error),
    /// The TLS handshake failed: a wrong relay key ends here.
    Tls(std::io::Error),
    /// The handshake finished without ALPN `http/1.1` or the hybrid group.
    Policy(String),
    /// The WebSocket upgrade failed.
    Upgrade(String),
    /// The relay closed the connection before `RELAY_HELLO`.
    ClosedBeforeHello(Option<u16>),
    /// The first message was not a `RELAY_HELLO`.
    NoHello,
}

/// The native client's outer TLS, and its exporter.
#[cfg(not(mousse_control = "marker-in-splice"))]
async fn outer_tls(
    addr: SocketAddr,
    host: &str,
    pin: RelayId,
    tcp: TcpStream,
) -> Result<(Box<dyn crate::Io>, [u8; 32]), DialError> {
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .unwrap_or_else(|_| ServerName::IpAddress(addr.ip().into()));
    let stream: TlsStream<TcpStream> = TlsConnector::from(tls::client_config(pin))
        .connect(name, tcp)
        .await
        .map_err(DialError::Tls)?;
    tls::check(stream.get_ref().1, true).map_err(DialError::Policy)?;
    let exporter =
        tls::exporter(stream.get_ref().1).map_err(|e| DialError::Policy(e.to_string()))?;
    Ok((Box::new(stream), exporter))
}

/// `marker-in-splice`: no outer TLS (the relay runs without it too).
#[cfg(mousse_control = "marker-in-splice")]
async fn outer_tls(
    _addr: SocketAddr,
    _host: &str,
    _pin: RelayId,
    tcp: TcpStream,
) -> Result<(Box<dyn crate::Io>, [u8; 32]), DialError> {
    Ok((Box::new(tcp), [0; 32]))
}

impl RelayConn {
    /// Dial the relay at `addr`, pinned to `pin`. `host` is the name in the
    /// enrollment link (an IP address sends no server name).
    pub async fn dial(addr: SocketAddr, host: &str, pin: RelayId) -> Result<Self, DialError> {
        let tcp = TcpStream::connect(addr).await.map_err(DialError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let (stream, exporter) = outer_tls(addr, host, pin, tcp).await?;
        let mut request = format!("ws://{host}{}", upgrade::PATH)
            .into_client_request()
            .map_err(|e| DialError::Upgrade(e.to_string()))?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(upgrade::SUBPROTOCOL),
        );
        let (ws, response) = tokio_tungstenite::client_async_with_config(
            request,
            stream,
            Some(upgrade::ws_config()),
        )
        .await
        .map_err(|e| DialError::Upgrade(e.to_string()))?;
        if response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            != Some(upgrade::SUBPROTOCOL)
        {
            return Err(DialError::Upgrade("no mousse-relay.1 subprotocol".into()));
        }
        let mut conn = Self {
            ws,
            binding: Binding {
                nonce: [0; 32],
                exporter,
            },
            boot_id: [0; 16],
            mode: Mode::SelfHosted,
            spliced: false,
        };
        match conn.recv().await {
            Received::Relay(RelayMessage::Hello {
                nonce,
                boot_id,
                mode,
                ..
            }) => {
                conn.binding.nonce = nonce;
                conn.boot_id = boot_id;
                conn.mode = mode;
                Ok(conn)
            }
            Received::Closed(code) => Err(DialError::ClosedBeforeHello(code)),
            _ => Err(DialError::NoHello),
        }
    }

    /// Send a relay message.
    pub async fn send(&mut self, message: &RelayMessage) -> Result<(), String> {
        self.send_raw(message.encode()).await
    }

    /// Send one binary WebSocket message as it is (a relay message before
    /// splicing, peer bytes after).
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        self.ws
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| e.to_string())
    }

    /// Wait for the next message or the close.
    pub async fn recv(&mut self) -> Received {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    if self.spliced {
                        return Received::Peer(bytes.to_vec());
                    }
                    return match RelayMessage::decode(&bytes) {
                        Ok(m) => {
                            if m == RelayMessage::Spliced {
                                self.spliced = true;
                            }
                            Received::Relay(m)
                        }
                        Err(_) => Received::Peer(bytes.to_vec()),
                    };
                }
                Some(Ok(Message::Close(frame))) => {
                    return Received::Closed(frame.map(|f| u16::from(f.code)))
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return Received::Closed(None),
            }
        }
    }

    /// Close the connection.
    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
