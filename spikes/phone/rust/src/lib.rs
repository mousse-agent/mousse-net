//! Phase 0 phone spikes, shared by the iOS and Android host apps through UniFFI.
//!
//! - Spike 4, lifecycle ([`Engine`]): Rust owns a tokio runtime. `start`, `stop`,
//!   `dial` (TCP connect plus a tiny echo protocol), `cancel(id)`, waiting on a dial
//!   from Swift async or Kotlin suspend, and bounded batches of events.
//! - Spike 3, byte path ([`Engine::start_byte_path`]): a WebSocket server on
//!   127.0.0.1 with strict Host and Origin checks and a per-launch token. A WebView
//!   in the app pushes terminal-like and file-like traffic through it.
//! - [`Report`] turns the steps a host app ran into one result JSON.
//!
//! Must-fail controls (`EngineConfig::break_mode`): `"cancel"` makes cancellation a
//! no-op; `"token"` turns the byte-path token check off. Both runs must end in FAIL.

mod bytepath;
mod engine;
mod fds;
mod report;

pub use bytepath::{BytePathConfig, BytePathInfo, ProbeResult};
pub use engine::{
    DialState, EchoResult, Engine, EngineConfig, EngineStatus, Event, EventBatch, EventKind,
    NetError,
};
pub use fds::{open_socket_fds, socket_fd_list};
pub use report::Report;

uniffi::setup_scaffolding!();

/// `<git short sha>[-dirty]+<profile>`, stamped at build time.
pub const BUILD_ID: &str = env!("PHONE_SPIKE_BUILD_ID");
/// The Rust target triple this library was built for.
pub const TARGET_TRIPLE: &str = env!("PHONE_SPIKE_TARGET");

/// The build id that goes into every result file.
#[uniffi::export]
pub fn build_id() -> String {
    BUILD_ID.to_string()
}

/// The Rust target triple, e.g. `aarch64-linux-android`.
#[uniffi::export]
pub fn target_triple() -> String {
    TARGET_TRIPLE.to_string()
}

/// The Android ABI name for this build (`arm64-v8a`, `x86_64`, ...), or the arch.
#[uniffi::export]
pub fn abi_name() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86" => "x86",
        other => other,
    }
    .to_string()
}
