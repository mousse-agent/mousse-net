// Records the target triple so each result names the target it ran on.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=MATRIX_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
