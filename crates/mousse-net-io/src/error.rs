use std::fmt;

use mousse_net_core::pairing::JoinerError;
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
    /// The pairing ticket cannot be used (bad form).
    Ticket(String),
    /// The pairing flow refused to start or go on. `JoinerError::code` is
    /// the error code to report, when it has one.
    Join(JoinerError),
    /// Our identity signer failed.
    Signer(String),
    /// A local state file or the keystore failed.
    Store(String),
    /// The peer reset the stream with this code.
    StreamReset(mousse_net_core::ErrorCode),
    /// A local call was refused (unknown stream, wrong state).
    Refused(String),
    /// No place for another stream: the connection or the endpoint has as
    /// many open as its limit allows. Open it once one ends.
    StreamLimit,
    /// An `ssh` call or pipe failed before the pipe carried anything
    /// (Phase 1b §3.1). `detail` is the kept stderr, for a tooltip only.
    Ssh {
        /// What the app shows.
        reason: crate::pipe::ssh::SshReason,
        /// The stderr text or what was missing; never shown raw.
        detail: String,
    },
    /// The route names, or resolved only to, addresses that are never
    /// dialled (Phase 1b §1.2), or it is not approved for this peer.
    Forbidden(String),
}

impl NetError {
    /// The failure came before step 1 completed: the address was not
    /// reached, or the TLS handshake or its certificate check failed. Such
    /// a failure says nothing about the host, so another of its addresses
    /// may still pass.
    pub fn is_step1(&self) -> bool {
        matches!(
            self,
            NetError::Io(_)
                | NetError::Tls(_)
                | NetError::Timeout(_)
                | NetError::PeerCertificate(_)
                | NetError::Ssh { .. }
                | NetError::Forbidden(_)
        )
    }
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
            NetError::Join(e) => match e.code() {
                Some(code) => write!(f, "pairing: {e} ({})", code.name()),
                None => write!(f, "pairing: {e}"),
            },
            NetError::Signer(e) => write!(f, "identity signer: {e}"),
            NetError::Store(e) => write!(f, "local state: {e}"),
            NetError::StreamReset(c) => write!(f, "stream reset ({})", c.name()),
            NetError::Refused(e) => write!(f, "refused: {e}"),
            NetError::StreamLimit => f.write_str("too many open streams"),
            NetError::Ssh { reason, detail } if detail.is_empty() => write!(f, "ssh: {reason}"),
            NetError::Ssh { reason, detail } => write!(f, "ssh: {reason} ({detail})"),
            NetError::Forbidden(e) => write!(f, "forbidden address: {e}"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}
