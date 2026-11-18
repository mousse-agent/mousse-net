//! Two jobs at compile time:
//!
//! - Refuses a release build with a must-fail control (spec/vectors/README.md,
//!   "Must-fail controls"). The `compile_error!` in the crate only sees
//!   `debug_assertions`, which a release profile can turn on; this sees the
//!   profile itself. Profiles that inherit from `release` report `release`.
//!   It stops a build early when the control is in the global `RUSTFLAGS`,
//!   and always passes the profile to the crate as `MOUSSE_BUILD_PROFILE`;
//!   the crate refuses `release` at compile time itself, which also catches
//!   flags given to it alone (`cargo rustc -- --cfg ...`).
//! - Fixes this build's id, `<commit>[-dirty]+<profile>`, in
//!   `MOUSSE_HELPER_BUILD`, so a result names the build that ran, not the
//!   checkout it happens to run in. `MOUSSE_BUILD_ID` overrides it (the test
//!   kit sets it). Dirty means any uncommitted change, untracked files
//!   included, except the kit's own `checks/results` and `checks/runs`.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=MOUSSE_BUILD_ID");
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
    let build = match std::env::var("MOUSSE_BUILD_ID") {
        Ok(id) if !id.trim().is_empty() => id.trim().to_owned(),
        _ => from_git(&profile),
    };
    println!("cargo:rustc-env=MOUSSE_HELPER_BUILD={build}");
}

fn git(args: &[&str]) -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .current_dir(manifest)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn from_git(profile: &str) -> String {
    let Some(commit) = git(&["rev-parse", "HEAD"]) else {
        return format!("unknown+{profile}");
    };
    let Some(root) = git(&["rev-parse", "--show-toplevel"]) else {
        return format!("unknown+{profile}");
    };
    // Build again when the commit, the index or any source changes.
    for dir in ["--git-dir", "--git-common-dir"] {
        if let Some(d) = git(&["rev-parse", "--path-format=absolute", dir]) {
            let d = Path::new(&d);
            println!("cargo:rerun-if-changed={}", d.join("HEAD").display());
            println!("cargo:rerun-if-changed={}", d.join("index").display());
            println!("cargo:rerun-if-changed={}", d.join("refs").display());
        }
    }
    let root = Path::new(&root);
    for item in ["crates", "spec", "checks", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={}", root.join(item).display());
    }
    let status = git(&[
        "-C",
        &root.display().to_string(),
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ".",
        ":(exclude)checks/results",
        ":(exclude)checks/runs",
    ]);
    let dirty = match status {
        Some(s) => !s.is_empty(),
        // Unknown state: never claim a clean build.
        None => true,
    };
    format!("{commit}{}+{profile}", if dirty { "-dirty" } else { "" })
}
