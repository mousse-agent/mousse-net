//! tokio adapters for `mousse-net-core`: TLS sessions, pipes, the session
//! driver, keystores and discovery.
//!
//! - [`tls`]: mutual TLS 1.3 on session certificates. The verifiers call
//!   [`mousse_net_core::session_cert::verify`]; the caller pins the host on
//!   every connection.
//! - [`certs`]: issues and renews our own session certificate from an
//!   [`IdentitySigner`](mousse_net_core::identity::IdentitySigner).
//! - [`pipe`]: any reliable byte stream; TCP is the first one.
//! - [`conn`]: the session driver. It runs the mux, the control stream and
//!   the step 2 gate over one TLS connection, and hands out streams.
//! - [`host`]: the host side: accepts connections, runs step 2 and pairing,
//!   owns the grant table.
//! - [`caller`]: the caller side: dials known hosts and joins with a ticket.
//! - [`endpoint`]: one profile's helper on a device: its state directory,
//!   locks, kept port and profile id.
//! - [`keystore`] and [`store`]: the identity key and the local state files.
//! - [`discovery`]: mDNS with a rotating random instance name.
//! - [`limits`]: every limit, its default and allowed range.
// Only `private` (the Windows security calls) may use unsafe code.
#![deny(unsafe_code)]

pub mod admission;
pub mod caller;
pub mod certs;
pub mod clock;
pub mod conn;
pub mod discovery;
pub mod endpoint;
mod error;
pub mod host;
pub mod keystore;
pub mod limits;
pub mod pipe;
pub mod private;
pub mod rng;
pub mod store;
pub mod tls;

pub use admission::StreamAdmission;
pub use caller::{Caller, CodeEntry, JoinOutcome, NoCode, PathEvent, Step1Failures};
pub use clock::{Clock, ManualClock, SystemClock};
pub use conn::{CloseReason, ConnStatus, Connection, MuxStream, StreamReader, StreamWriter};
pub use endpoint::{Endpoint, PortChoice};
pub use error::NetError;
pub use host::{ApprovalRequest, Host, HostConfig, HostEvent};
pub use limits::Limits;
pub use tls::TlsPolicy;

use std::sync::Arc;

use mousse_net_core::identity::IdentitySigner;

/// An identity signer that can be shared across tasks.
pub type SharedSigner = Arc<dyn IdentitySigner + Send + Sync>;

#[cfg(all(
    not(debug_assertions),
    any(
        mousse_control = "skip-pin-check",
        mousse_control = "keep-removed-grant",
        mousse_control = "shared-endpoint-state",
        mousse_control = "allow-break-env",
        mousse_control = "no-stream-cap"
    )
))]
compile_error!("a mousse_control build has a deliberate defect and is for tests only; build it without --release");

// The same controls in a release-profile build, even with debug assertions
// on. `build.rs` passes the profile in `MOUSSE_BUILD_PROFILE`.
#[cfg(any(
    mousse_control = "skip-pin-check",
    mousse_control = "keep-removed-grant",
    mousse_control = "shared-endpoint-state",
    mousse_control = "allow-break-env",
    mousse_control = "no-stream-cap"
))]
const _: () = {
    let profile = env!("MOUSSE_BUILD_PROFILE").as_bytes();
    let release = b"release";
    let mut same = profile.len() == release.len();
    let mut i = 0;
    while same && i < profile.len() {
        same = profile[i] == release[i];
        i += 1;
    }
    assert!(!same, "a mousse_control build has a deliberate defect and is for tests only; build it without --release");
};

/// The must-fail control compiled into this build, if any. Control builds
/// carry one deliberate defect so a test kit can check that the tests
/// catch it. Release builds never have one.
pub const CONTROL: Option<&str> = if cfg!(mousse_control = "skip-pin-check") {
    Some("skip-pin-check")
} else if cfg!(mousse_control = "keep-removed-grant") {
    Some("keep-removed-grant")
} else if cfg!(mousse_control = "shared-endpoint-state") {
    Some("shared-endpoint-state")
} else if cfg!(mousse_control = "allow-break-env") {
    Some("allow-break-env")
} else if cfg!(mousse_control = "no-stream-cap") {
    Some("no-stream-cap")
} else {
    None
};
