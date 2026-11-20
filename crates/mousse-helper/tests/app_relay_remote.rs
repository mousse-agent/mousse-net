//! E-R3 and E-R4 across machines: the cases of `app_relay.rs` and
//! `app_relay_rotation.rs` against a `mousse-relay` on another machine
//! (Phase 3 Part G: the relay on the Mac, both endpoints on the PC dialling
//! out). The check cells `phase3.relay-routes-cross` and
//! `phase3.relay-rotation-cross` run `routes_cross` and `rotation_cross`.
//!
//! The relay comes from enrollment links (`common/relay_remote.rs`,
//! docs/limits.md "Relay tests"):
//!
//! - `MOUSSE_RELAY_TEST_LINKS`: the links, each used once. `routes_cross`
//!   needs seven, six of one relay and one of a second; `rotation_cross`
//!   needs three.
//! - `MOUSSE_RELAY_TEST_HOST_BUILD`: the relay's build, written as the
//!   result's `host_build`.
//! - `MOUSSE_RELAY_TEST_RESULT`: a file to write the unsigned result to,
//!   for `mousse-check sign` (`{check}` is replaced by the check id).
//!
//! Both tests are ignored in an ordinary `cargo test`, as needing a remote
//! relay. Run with `--ignored`, each runs every case one by one, prints a
//! line per case and ends with `PASS <check>`, or `FAIL <check>
//! reason=<word>` and a failed test. Without links it prints `FAIL <check>
//! reason=not_configured`, fails, and writes no result.

mod common;
#[path = "common/relay_remote.rs"]
mod relay_fixture;
#[path = "common/relay_rotation.rs"]
mod rotation;
#[path = "common/relay_routes.rs"]
mod routes;

use std::sync::Mutex;

use serde_json::json;

/// The cell both checks have.
const TARGET: &str = "pc-to-mac-lan";

/// One check at a time: each may hold every configured relay.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "needs a relay on another machine: MOUSSE_RELAY_TEST_LINKS"]
fn routes_cross() {
    run_cross("phase3.relay-routes-cross", routes::CASES);
}

#[test]
#[ignore = "needs a relay on another machine: MOUSSE_RELAY_TEST_LINKS"]
fn rotation_cross() {
    run_cross("phase3.relay-rotation-cross", rotation::CASES);
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panicked".into())
}

/// The build this test and its helpers were compiled as, and the control
/// compiled in (`none` normally).
const BUILD: &str = env!("MOUSSE_HELPER_BUILD");
const CONTROL: &str = env!("MOUSSE_HELPER_CONTROL");

fn run_cross(check: &str, cases: &[(&str, fn())]) {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let result_file = std::env::var("MOUSSE_RELAY_TEST_RESULT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.replace("{check}", check));
    let host_build = std::env::var("MOUSSE_RELAY_TEST_HOST_BUILD")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut setup = relay_fixture::configured();
    if result_file.is_some() && host_build.is_none() {
        setup = Err("MOUSSE_RELAY_TEST_HOST_BUILD (the relay's build) is not set".into());
    }
    let relays = match setup {
        Ok(relays) => relays,
        Err(why) => {
            println!("FAIL {check} reason=not_configured ({why})");
            panic!("{check}: {}: {why}", relay_fixture::NOT_CONFIGURED);
        }
    };
    println!("{check}: build {BUILD}, control {CONTROL}, relay {relays}");

    let mut failed = Vec::new();
    let mut not_configured = false;
    for (name, case) in cases {
        println!("case {name}: running");
        match std::panic::catch_unwind(case) {
            Ok(()) => println!("case {name}: ok"),
            Err(payload) => {
                let why = panic_text(payload.as_ref());
                not_configured |= why.contains(relay_fixture::NOT_CONFIGURED);
                println!("case {name}: FAILED: {why}");
                failed.push(*name);
            }
        }
    }
    let (verdict, reason) = if not_configured {
        (
            format!("FAIL {check} reason=not_configured"),
            Some("not_configured"),
        )
    } else if failed.is_empty() {
        (format!("PASS {check}"), None)
    } else {
        (
            format!("FAIL {check} reason=case_failed ({})", failed.join(", ")),
            Some("case_failed"),
        )
    };
    println!("{verdict}");

    // A run that was not configured proves nothing either way: no result,
    // not even for a control.
    if let (Some(file), false) = (&result_file, not_configured) {
        let outcome = match (CONTROL, failed.is_empty()) {
            ("none", true) => "PASS",
            ("none", false) => "FAIL",
            (_, false) => "FAIL",
            (_, true) => "DID_NOT_FAIL",
        };
        let mut result = json!({
            "check": check,
            "target": TARGET,
            "outcome": outcome,
            "details": verdict,
            // Both endpoints are this build; the relay is the host.
            "build": BUILD,
            "caller_build": BUILD,
            "host_build": host_build,
        });
        if let Some(r) = reason {
            result["reason"] = json!(r);
        }
        if CONTROL != "none" {
            result["control"] = json!(CONTROL);
        }
        std::fs::write(file, serde_json::to_string_pretty(&result).unwrap() + "\n").unwrap();
        println!("result written to {file}");
    }
    assert!(failed.is_empty() && !not_configured, "{verdict}");
}
