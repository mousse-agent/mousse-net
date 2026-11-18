//! Refuses a release build with a must-fail control (spec/vectors/README.md,
//! "Must-fail controls"). The `compile_error!` in the crate only sees
//! `debug_assertions`, which a release profile can turn on; this sees the
//! profile itself. Profiles that inherit from `release` report `release`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let from_cfg = std::env::var("CARGO_CFG_MOUSSE_CONTROL").ok();
    let from_flags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .contains("mousse_control");
    let release = std::env::var("PROFILE").is_ok_and(|p| p == "release");
    if release && (from_cfg.is_some() || from_flags) {
        eprintln!(
            "error: mousse_control ({}) plants a bug for tests; it is not allowed in release builds",
            from_cfg.as_deref().unwrap_or("set in RUSTFLAGS")
        );
        std::process::exit(1);
    }
}
