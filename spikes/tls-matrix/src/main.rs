//! Native runner for the crypto matrix.
//!
//! Usage: `tls-matrix [--out DIR] [--same-only] [--pipe-only]`
//!
//! Prints one line per provider pair and one JSON result per pair. With
//! `--out`, writes each result to `DIR/<target>__<client>__<server>.json`.
//! `MOUSSE_MATRIX_BREAK=1` swaps the pinned server key, so the run must FAIL.
//! `MOUSSE_BUILD_ID` overrides the build id (default: git short sha + profile).
//! Exits non-zero if any pair fails.

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use tls_matrix::handshake::Params;
use tls_matrix::matrix::{self, Transport};
use tls_matrix::TARGET;

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR")])
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn build_id() -> String {
    if let Ok(id) = std::env::var("MOUSSE_BUILD_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // Dirty only if the spike's own sources changed since that commit.
    let dirty = git(&[
        "status",
        "--porcelain",
        "--",
        "src",
        "Cargo.toml",
        "build.rs",
    ])
    .map(|s| !s.is_empty())
    .unwrap_or(false);
    format!("{sha}{}+{}", if dirty { "-dirty" } else { "" }, profile())
}

fn main() -> ExitCode {
    let mut out_dir: Option<PathBuf> = None;
    let mut include_cross = true;
    let mut transports = Transport::available();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_dir = args.next().map(PathBuf::from),
            "--same-only" => include_cross = false,
            "--pipe-only" => transports = vec![Transport::Pipe],
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let break_pin = std::env::var("MOUSSE_MATRIX_BREAK").is_ok_and(|v| v == "1");
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let build = build_id();

    let mut all_pass = true;
    for (client, server) in matrix::pairs(include_cross) {
        let params = Params {
            client,
            server,
            now_unix_secs,
            break_pin,
        };
        let (result, _) = matrix::run(params, &transports, TARGET, &build);
        all_pass &= result.outcome == "PASS";
        println!(
            "{:<4} {:<26} {:<24} kx={:<16} suite={}",
            result.outcome, result.target, result.provider, result.kx_group, result.suite
        );
        let json = match serde_json::to_string_pretty(&result) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("cannot encode result: {e}");
                return ExitCode::FAILURE;
            }
        };
        if result.outcome != "PASS" {
            println!("{json}");
        }
        if let Some(dir) = &out_dir {
            let path = dir.join(matrix::result_file_name(TARGET, client, server));
            if let Err(e) =
                std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&path, json + "\n"))
            {
                eprintln!("cannot write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }
    if all_pass {
        println!("PASS {}", matrix::CHECK);
        ExitCode::SUCCESS
    } else {
        println!("FAIL {}", matrix::CHECK);
        ExitCode::FAILURE
    }
}
