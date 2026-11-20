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
//! - [`watch`]: interface changes and wakes, for the caller to redial.
//! - [`limits`]: every limit, its default and allowed range.
//! - [`relay`]: calling, joining and registering through a relay.
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
pub mod preauth;
pub mod private;
pub mod relay;
pub mod rng;
pub mod routes;
pub mod store;
pub mod tls;
pub mod watch;

pub use admission::StreamAdmission;
pub use caller::{
    Caller, CandidateSource, CodeEntry, JoinOutcome, LaterCandidates, NoCode, PathEvent, Reached,
    RouteClass, Search, Step1Failures,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use conn::{CloseReason, ConnStatus, Connection, MuxStream, StreamReader, StreamWriter};
pub use endpoint::{Endpoint, PortChoice};
pub use error::NetError;
pub use host::{AppliedRemoval, ApprovalRequest, Host, HostConfig, HostEvent, Refusal};
pub use limits::Limits;
pub use preauth::{ListenerKind, PreAuthSlot, PreAuthStats};
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
        mousse_control = "no-stream-cap",
        mousse_control = "stop-on-mismatch",
        mousse_control = "no-preauth-budget",
        mousse_control = "shared-preauth-pool",
        mousse_control = "join-only-frees-slot",
        mousse_control = "join-only-outlives-invitation",
        mousse_control = "fence-at-accept-only",
        mousse_control = "fence-tcp-only",
        mousse_control = "enroll-while-paused",
        mousse_control = "repair-skips-slot",
        mousse_control = "repair-skips-fence",
        mousse_control = "no-endpoint-lock",
        mousse_control = "no-pin-relay",
        mousse_control = "shared-caller-key",
        mousse_control = "close-all-on-removal",
        mousse_control = "manifest-unapproved",
        mousse_control = "blanket-approval",
        mousse_control = "no-pairing-recovery",
        mousse_control = "recovery-makes-grant",
        mousse_control = "no-overlap",
        mousse_control = "relay-overlap-ignored",
        mousse_control = "chain-full-ignored",
        mousse_control = "stale-manifest-dropped",
        mousse_control = "prompt-on-key-change",
        mousse_control = "disallow-keeps-paths",
        mousse_control = "remove-keeps-sessions",
        mousse_control = "accept-legs-unbounded",
        mousse_control = "ws-allow-origin",
        mousse_control = "plain-ws-off-loopback",
        mousse_control = "release-test-root",
        mousse_control = "loopback-routes",
        mousse_control = "resolve-again",
        mousse_control = "unlisted-allowed",
        mousse_control = "stale-renewal-routes",
        mousse_control = "unbounded-candidates",
        mousse_control = "ssh-races-lan",
        mousse_control = "bind-all-lan-off",
        mousse_control = "pin-stored-memory-only"
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
    mousse_control = "no-stream-cap",
    mousse_control = "stop-on-mismatch",
    mousse_control = "no-preauth-budget",
    mousse_control = "shared-preauth-pool",
    mousse_control = "join-only-frees-slot",
    mousse_control = "join-only-outlives-invitation",
    mousse_control = "fence-at-accept-only",
    mousse_control = "fence-tcp-only",
    mousse_control = "enroll-while-paused",
    mousse_control = "repair-skips-slot",
    mousse_control = "repair-skips-fence",
    mousse_control = "no-endpoint-lock",
    mousse_control = "no-pin-relay",
    mousse_control = "shared-caller-key",
    mousse_control = "close-all-on-removal",
    mousse_control = "manifest-unapproved",
    mousse_control = "blanket-approval",
    mousse_control = "no-pairing-recovery",
    mousse_control = "recovery-makes-grant",
    mousse_control = "no-overlap",
    mousse_control = "relay-overlap-ignored",
    mousse_control = "chain-full-ignored",
    mousse_control = "stale-manifest-dropped",
    mousse_control = "prompt-on-key-change",
    mousse_control = "disallow-keeps-paths",
    mousse_control = "remove-keeps-sessions",
    mousse_control = "accept-legs-unbounded",
    mousse_control = "ws-allow-origin",
    mousse_control = "plain-ws-off-loopback",
    mousse_control = "release-test-root",
    mousse_control = "loopback-routes",
    mousse_control = "resolve-again",
    mousse_control = "unlisted-allowed",
    mousse_control = "stale-renewal-routes",
    mousse_control = "unbounded-candidates",
    mousse_control = "ssh-races-lan",
    mousse_control = "bind-all-lan-off",
    mousse_control = "pin-stored-memory-only"
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
} else if cfg!(mousse_control = "no-preauth-budget") {
    Some("no-preauth-budget")
} else if cfg!(mousse_control = "shared-preauth-pool") {
    Some("shared-preauth-pool")
} else if cfg!(mousse_control = "join-only-frees-slot") {
    Some("join-only-frees-slot")
} else if cfg!(mousse_control = "join-only-outlives-invitation") {
    Some("join-only-outlives-invitation")
} else if cfg!(mousse_control = "fence-at-accept-only") {
    Some("fence-at-accept-only")
} else if cfg!(mousse_control = "fence-tcp-only") {
    Some("fence-tcp-only")
} else if cfg!(mousse_control = "no-endpoint-lock") {
    Some("no-endpoint-lock")
} else if cfg!(mousse_control = "enroll-while-paused") {
    Some("enroll-while-paused")
} else if cfg!(mousse_control = "repair-skips-slot") {
    Some("repair-skips-slot")
} else if cfg!(mousse_control = "repair-skips-fence") {
    Some("repair-skips-fence")
} else if cfg!(mousse_control = "no-pin-relay") {
    Some("no-pin-relay")
} else if cfg!(mousse_control = "shared-caller-key") {
    Some("shared-caller-key")
} else if cfg!(mousse_control = "close-all-on-removal") {
    Some("close-all-on-removal")
} else if cfg!(mousse_control = "manifest-unapproved") {
    Some("manifest-unapproved")
} else if cfg!(mousse_control = "blanket-approval") {
    Some("blanket-approval")
} else if cfg!(mousse_control = "no-pairing-recovery") {
    Some("no-pairing-recovery")
} else if cfg!(mousse_control = "recovery-makes-grant") {
    Some("recovery-makes-grant")
} else if cfg!(mousse_control = "no-overlap") {
    Some("no-overlap")
} else if cfg!(mousse_control = "relay-overlap-ignored") {
    Some("relay-overlap-ignored")
} else if cfg!(mousse_control = "chain-full-ignored") {
    Some("chain-full-ignored")
} else if cfg!(mousse_control = "stale-manifest-dropped") {
    Some("stale-manifest-dropped")
} else if cfg!(mousse_control = "prompt-on-key-change") {
    Some("prompt-on-key-change")
} else if cfg!(mousse_control = "disallow-keeps-paths") {
    Some("disallow-keeps-paths")
} else if cfg!(mousse_control = "remove-keeps-sessions") {
    Some("remove-keeps-sessions")
} else if cfg!(mousse_control = "accept-legs-unbounded") {
    Some("accept-legs-unbounded")
} else if cfg!(mousse_control = "ws-allow-origin") {
    Some("ws-allow-origin")
} else if cfg!(mousse_control = "plain-ws-off-loopback") {
    Some("plain-ws-off-loopback")
} else if cfg!(mousse_control = "release-test-root") {
    Some("release-test-root")
} else if cfg!(mousse_control = "loopback-routes") {
    Some("loopback-routes")
} else if cfg!(mousse_control = "resolve-again") {
    Some("resolve-again")
} else if cfg!(mousse_control = "unlisted-allowed") {
    Some("unlisted-allowed")
} else if cfg!(mousse_control = "stale-renewal-routes") {
    Some("stale-renewal-routes")
} else if cfg!(mousse_control = "unbounded-candidates") {
    Some("unbounded-candidates")
} else if cfg!(mousse_control = "ssh-races-lan") {
    Some("ssh-races-lan")
} else if cfg!(mousse_control = "bind-all-lan-off") {
    Some("bind-all-lan-off")
} else {
    None
};
