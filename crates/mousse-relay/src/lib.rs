//! `mousse-relay`: the self-hosted Mousse relay (spec `relay.md`, self
//! mode).
//!
//! The relay admits a call only when the target's own allow-set lists the
//! caller, answers every refused call the same way at the same deadline,
//! and then forwards WebSocket messages between two legs whose peer TLS it
//! cannot read. Admission itself is `mousse_net_core::relay::Relay`; this
//! crate is its I/O: TLS and WebSocket, timers, splicing, the egress
//! ceiling, and the state directory.
#![forbid(unsafe_code)]

// Must-fail controls plant a bug for tests and never compile into a release
// build (spec/vectors/README.md, "Must-fail controls").
#[cfg(all(
    any(
        mousse_control = "relay-persist-allow-set",
        mousse_control = "marker-in-splice",
        mousse_control = "marker-in-relay-memory"
    ),
    not(debug_assertions)
))]
compile_error!("mousse_control plants a bug for tests; it is not allowed in release builds");

#[cfg(any(
    mousse_control = "relay-persist-allow-set",
    mousse_control = "marker-in-splice",
    mousse_control = "marker-in-relay-memory"
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

pub mod client;
mod control;
mod egress;
pub mod limits;
pub mod server;
pub mod state;
pub mod tls;
pub mod upgrade;

use getrandom::SysRng;
use rand_core::UnwrapErr;

/// A byte stream under a relay WebSocket: the outer TLS stream.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Io for T {}

/// The OS random source.
pub type OsRng = UnwrapErr<SysRng>;

/// The OS random source as a `rand_core` `CryptoRng`.
pub fn os_rng() -> OsRng {
    UnwrapErr(SysRng)
}
