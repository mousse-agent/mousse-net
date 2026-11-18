//! Declares the must-fail control cfgs. A control build is a test build
//! with one deliberate defect, set through RUSTFLAGS, for example
//! `--cfg mousse_control="skip-pin-check"`.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!(
        "cargo::rustc-check-cfg=cfg(mousse_control, values(\"skip-pin-check\", \"keep-removed-grant\", \"shared-endpoint-state\", \"allow-break-env\"))"
    );
}
