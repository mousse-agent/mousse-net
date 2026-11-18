use std::fmt;

use mousse_net_core::session_cert::CertError;

use crate::conn::CloseReason;

/// Errors from the I/O layer.
#[derive(Debug)]
pub enum NetError {
    /// The pipe failed.
    Io(std::io::Error),
    /// Our step 1 check refused the peer's session certificate.
    PeerCertificate(CertError),
    /// The TLS handshake failed for another reason (the peer refused our
    /// certificate, no common protocol, a wrong ALPN or key exchange group).
    Tls(String),
    /// The connection was closed before it reached the expected state.
    Closed(CloseReason),
    /// A step took too long.
    Timeout(&'static str),
    /// The pairing ticket cannot be used (expired, wrong kind, bad form).
    Ticket(String),
    /// Our identity signer failed.
    Signer(String),
    /// A local state file or the keystore failed.
    Store(String),
    /// The peer reset the stream with this code.
    StreamReset(mousse_net_core::ErrorCode),
    /// A local call was refused (unknown stream, wrong state).
    Refused(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "connection failed: {e}"),
            NetError::PeerCertificate(e) => write!(f, "peer certificate refused: {e}"),
            NetError::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            NetError::Closed(reason) => write!(f, "connection closed: {reason}"),
            NetError::Timeout(what) => write!(f, "timed out: {what}"),
            NetError::Ticket(e) => write!(f, "pairing ticket: {e}"),
            NetError::Signer(e) => write!(f, "identity signer: {e}"),
            NetError::Store(e) => write!(f, "local state: {e}"),
            NetError::StreamReset(c) => write!(f, "stream reset ({})", c.name()),
            NetError::Refused(e) => write!(f, "refused: {e}"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}
