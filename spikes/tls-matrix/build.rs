// Records the target triple so each result names the target it ran on.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=MATRIX_TARGET={target}");
    // A build id given at build time travels with the binary, for devices
    // where neither git nor the environment of the build host is available.
    if let Ok(id) = std::env::var("MOUSSE_BUILD_ID") {
        println!("cargo:rustc-env=MATRIX_BUILD_ID={id}");
    }
    println!("cargo:rerun-if-env-changed=MOUSSE_BUILD_ID");
    println!("cargo:rerun-if-changed=build.rs");
}
