//! Mousse networking core: pure state machines with no I/O.
//!
//! Nothing in this crate opens sockets, reads clocks or draws randomness on
//! its own. Time is passed in as explicit values ([`UnixTime`] for wall-clock
//! checks, [`Millis`] for timers) and randomness comes from a caller-supplied
//! [`rand_core::CryptoRng`], so a seeded simulator can replay every run.
//!
//! The wire format is specified in `spec/wire.md`; the design is in
//! `docs/PLAN.md`.
//!
//! Modules, bottom-up:
//! - [`cbor`]: the small canonical CBOR subset our records use.
//! - [`identity`]: P-256 identity keys and fixed-width raw signatures.
//! - [`session_cert`]: building and verifying session certificates (step 1).
//! - [`grants`]: the host grant table and channel bindings.
//! - [`authz`]: the step 2 decision and the per-connection traffic gate.
//! - [`control`]: control-stream messages.
//! - [`pairing`]: tickets, join proofs, host and joiner pairing state machines.
//! - [`mux`]: frame codec, per-stream credit, priority scheduler, keepalive.
//! - [`session`]: certificate-driven session lifetime and path switching.
//! - [`relay`]: the relay protocol and the relay's admission state machine.
//! - [`relay_hosted`]: the relay's hosted mode: admission tokens, leases,
//!   the Plus clock and reports.
//! - [`manifest`]: the host-signed list of relay routes.
//! - [`relay_wire`]: the relay protocol as an endpoint speaks it.
//! - [`limits`]: every tunable limit, its default and allowed range.
#![forbid(unsafe_code)]

// Must-fail controls (spec/vectors/README.md, "Must-fail controls") plant a
// bug so the vector tests can be shown to fail. They are for debug test runs
// only and never compile into a release build: this stops builds without
// debug assertions, and the check below stops the release profile (and
// profiles that inherit it) even when debug assertions are on.
#[cfg(all(
    any(
        mousse_control = "break-session-cert",
        mousse_control = "break-authz",
        mousse_control = "break-raw-signature",
        mousse_control = "break-cpace-confirm",
        mousse_control = "break-cpace-sid",
        mousse_control = "limits-raise",
        mousse_control = "no-pin-relay",
        mousse_control = "relay-skip-allow-set",
        mousse_control = "relay-refuse-early",
        mousse_control = "relay-successor-unchecked",
        mousse_control = "relay-no-preaccept-budget",
        mousse_control = "per-socket-rate",
        mousse_control = "accept-replayed-lease",
        mousse_control = "ignore-admission-expiry",
        mousse_control = "close-funded-at-expiry",
        mousse_control = "refuse-expired-reregister",
        mousse_control = "expiry-on-relay-wall-clock"
    ),
    not(debug_assertions)
))]
compile_error!("mousse_control plants a bug for tests; it is not allowed in release builds");

// The same controls in a release-profile build, even with debug assertions
// on. `build.rs` passes the profile in `MOUSSE_BUILD_PROFILE`.
#[cfg(any(
    mousse_control = "break-session-cert",
    mousse_control = "break-authz",
    mousse_control = "break-raw-signature",
    mousse_control = "break-cpace-confirm",
    mousse_control = "break-cpace-sid",
    mousse_control = "limits-raise",
    mousse_control = "no-pin-relay",
    mousse_control = "relay-skip-allow-set",
    mousse_control = "relay-refuse-early",
    mousse_control = "relay-successor-unchecked",
    mousse_control = "relay-no-preaccept-budget",
    mousse_control = "per-socket-rate",
    mousse_control = "accept-replayed-lease",
    mousse_control = "ignore-admission-expiry",
    mousse_control = "close-funded-at-expiry",
    mousse_control = "refuse-expired-reregister",
    mousse_control = "expiry-on-relay-wall-clock"
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
    assert!(
        !same,
        "mousse_control plants a bug for tests; it is not allowed in release builds"
    );
};

mod asn1;
mod base64url;

pub mod authz;
pub mod cbor;
pub mod codes;
pub mod control;
pub mod cpace;
pub mod grants;
pub mod identity;
pub mod limits;
pub mod manifest;
pub mod mux;
pub mod pairing;
pub mod relay;
pub mod relay_hosted;
pub mod relay_wire;
pub mod session;
pub mod session_cert;
pub mod time;

#[cfg(test)]
mod vectors;

pub use codes::ErrorCode;
pub use limits::Limits;
pub use time::{Millis, UnixTime};

/// Major protocol version. It is signed into every session certificate and
/// carried in every pairing ticket. A new major version means re-pairing.
pub const PROTOCOL_VERSION: u64 = 1;

/// Minor protocol version this build speaks. Peers exchange it in `HELLO`
/// and use the lower of the two. The current and previous minor versions are
/// supported.
pub const PROTOCOL_MINOR_VERSION: u64 = 1;

/// TLS ALPN protocol identifier for peer sessions. It carries the major
/// version only.
pub const ALPN: &[u8] = b"mousse/1";

/// A local handle for one TLS connection (one peer session on one path).
///
/// The I/O layer assigns these; they never go on the wire. A "channel" in the
/// grant table is a connection that step 2 authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(pub u64);
