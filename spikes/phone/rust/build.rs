// Stamps the build id into the library: phones have no git and no build environment.
// MOUSSE_BUILD_ID wins; otherwise the git short sha (with -dirty when spikes/phone has
// local changes) plus the cargo profile.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(["-C", &dir])
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let id = std::env::var("MOUSSE_BUILD_ID").ok().unwrap_or_else(|| {
        let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "nogit".into());
        // Result files written by earlier runs don't make the code dirty.
        let dirty = git(&["status", "--porcelain", "--", "..", ":(exclude)../results"])
            .is_some_and(|s| !s.is_empty());
        format!("{sha}{}+{profile}", if dirty { "-dirty" } else { "" })
    });
    println!("cargo:rustc-env=PHONE_SPIKE_BUILD_ID={id}");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=PHONE_SPIKE_TARGET={target}");
    println!("cargo:rerun-if-env-changed=MOUSSE_BUILD_ID");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    // A new commit or a staged change must re-stamp the id.
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={dir}/{r}");
        }
    }
}
