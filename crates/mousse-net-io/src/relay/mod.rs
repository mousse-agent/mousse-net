//! The endpoint side of a relay (spec `relay.md`, design
//! `phase34-design.md` §B): calling a host through a relay, joining
//! through one, and a target's registration with its accept legs. The
//! messages, proofs and pin check are `mousse_net_core::relay`'s.
//!
//! A relay only joins two outgoing connections. The peer TLS (step 1 with
//! the host's pin, then step 2) runs end to end inside the spliced
//! connection, so a relay that admits wrongly reaches a host that refuses.
//!
//! - [`outer`]: the pinned outer TLS and the WebSocket, and [`WsPipe`], the
//!   spliced connection as a byte pipe.
//! - [`target`]: one registration connection: `REGISTER` or `ENROLL`,
//!   allow-set pushes, keepalive, `INCOMING` and accept legs.

pub mod outer;
pub mod target;

use std::fmt;
use std::io;
use std::time::Duration;

use mousse_net_core::relay::{close, Class, RefuseReason, RelayClientKey, RelayId, RelayMessage};

pub use outer::{CloseWatch, RelayAddr, RelayLink, WsPipe};
pub use target::{AllowSet, Proof, TargetCommand, TargetEvent, TargetLink};

/// Why a relay connection failed or ended.
#[derive(Debug)]
pub enum RelayError {
    /// The address was not reached, or the connection broke.
    Io(io::Error),
    /// The relay's key is not the pinned relay id.
    WrongRelay,
    /// The outer TLS failed for another reason.
    Tls(String),
    /// The WebSocket upgrade failed.
    Upgrade(String),
    /// A step took too long.
    Timeout,
    /// A malformed or unexpected relay message.
    Protocol(String),
    /// `UNREACHABLE`: an unlisted caller, an unknown handle, an offline or
    /// unfunded target. The relay does not say which.
    Unreachable,
    /// `REFUSED` with the relay's reason.
    Refused(RefuseReason),
    /// The relay closed the connection, with its close code if it sent one.
    Closed(Option<u16>),
}

impl RelayError {
    /// A short stable word for the app.
    pub fn word(&self) -> &'static str {
        match self {
            RelayError::Io(_) => "relay_unreachable",
            RelayError::WrongRelay => "relay_key",
            RelayError::Tls(_) | RelayError::Upgrade(_) => "relay_tls",
            RelayError::Timeout => "relay_timeout",
            RelayError::Protocol(_) => "relay_protocol",
            RelayError::Unreachable => "relay_refused",
            RelayError::Refused(RefuseReason::Limit) => "relay_limit",
            RelayError::Refused(_) => "relay_not_authorized",
            RelayError::Closed(code) => match *code {
                Some(close::REMOVED) => "relay_removed",
                Some(close::REPLACED) => "relay_replaced",
                Some(close::RELAY_STOPPING) => "relay_stopping",
                Some(close::LIMIT) => "relay_limit",
                Some(close::IDLE) => "relay_idle",
                _ => "relay_closed",
            },
        }
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::Io(e) => write!(f, "relay connection failed: {e}"),
            RelayError::WrongRelay => f.write_str("the relay's key is not the one pinned"),
            RelayError::Tls(e) => write!(f, "relay TLS failed: {e}"),
            RelayError::Upgrade(e) => write!(f, "relay upgrade failed: {e}"),
            RelayError::Timeout => f.write_str("the relay did not answer in time"),
            RelayError::Protocol(e) => write!(f, "relay protocol error: {e}"),
            RelayError::Unreachable => f.write_str("not reachable through the relay"),
            RelayError::Refused(r) => write!(f, "the relay refused: {}", r.as_str()),
            RelayError::Closed(Some(code)) => write!(f, "the relay closed the connection ({code})"),
            RelayError::Closed(None) => f.write_str("the relay closed the connection"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Dial `handle` through the relay pinned as `relay` with the caller key
/// `key`, and wait for the splice. On success the pipe carries the peer
/// TLS; the caller starts it as the TLS client with the host's pin.
pub async fn dial_call(
    addr: &RelayAddr,
    relay: RelayId,
    handle: [u8; 32],
    key: &RelayClientKey,
    class: Class,
    within: Duration,
) -> Result<WsPipe, RelayError> {
    let started = tokio::time::Instant::now();
    let mut link = RelayLink::connect(addr, relay, within).await?;
    let msg = RelayMessage::Call {
        handle,
        key: key.public_key(),
        proof: key.call_proof(&relay, &handle, &link.binding(), class),
        class,
    };
    let left = within.saturating_sub(started.elapsed());
    tokio::time::timeout(left, async {
        link.send(&msg).await?;
        wait_spliced(&mut link).await
    })
    .await
    .map_err(|_| RelayError::Timeout)??;
    Ok(link.into_pipe())
}

/// Join through the relay with an invitation tag (§B.7). On success the
/// pipe carries the peer TLS of a join.
pub async fn dial_join(
    addr: &RelayAddr,
    relay: RelayId,
    handle: [u8; 32],
    tag: [u8; 32],
    within: Duration,
) -> Result<WsPipe, RelayError> {
    let started = tokio::time::Instant::now();
    let mut link = RelayLink::connect(addr, relay, within).await?;
    let left = within.saturating_sub(started.elapsed());
    tokio::time::timeout(left, async {
        link.send(&RelayMessage::Join { handle, tag }).await?;
        wait_spliced(&mut link).await
    })
    .await
    .map_err(|_| RelayError::Timeout)??;
    Ok(link.into_pipe())
}

async fn wait_spliced<S>(link: &mut RelayLink<S>) -> Result<(), RelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match link.recv().await? {
        RelayMessage::Spliced => Ok(()),
        RelayMessage::Unreachable => Err(RelayError::Unreachable),
        RelayMessage::Refused { reason } => Err(RelayError::Refused(reason)),
        other => Err(RelayError::Protocol(format!(
            "expected SPLICED, got {}",
            other.name()
        ))),
    }
}
