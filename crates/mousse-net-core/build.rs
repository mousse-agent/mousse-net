//! Refuses a release build with a must-fail control (spec/vectors/README.md,
//! "Must-fail controls"). The `compile_error!` in the crate only sees
//! `debug_assertions`, which a release profile can turn on; this sees the
//! profile itself. Profiles that inherit from `release` report `release`.
//!
//! It stops a build early when the control is in the global `RUSTFLAGS`, and
//! always passes the profile to the crate as `MOUSSE_BUILD_PROFILE`. The
//! crate refuses `release` at compile time itself, which also catches flags
//! given to that crate alone (`cargo rustc -- --cfg ...`).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let from_cfg = std::env::var("CARGO_CFG_MOUSSE_CONTROL").ok();
    let from_flags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .contains("mousse_control");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    println!("cargo:rustc-env=MOUSSE_BUILD_PROFILE={profile}");
    if profile == "release" && (from_cfg.is_some() || from_flags) {
        eprintln!(
            "error: mousse_control ({}) plants a bug for tests; it is not allowed in release builds",
            from_cfg.as_deref().unwrap_or("set in RUSTFLAGS")
        );
        std::process::exit(1);
    }
}
