//! The relay process's own hardening (design §B.15 and §B.16, check
//! `phase3.relay-hardening`): every command starts with core dumps off (hard
//! limit 0) and the process non-dumpable, so a crash writes nothing to disk
//! and other processes of the same user cannot read its memory. Only a debug
//! build honours the test hook that keeps it dumpable for `phase3.marker`.
//!
//! The release image and the systemd unit are checked the same way, through
//! `status --json`, by `phase3.install`.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("relay-hardening-{tag}-{}-{n}", std::process::id()))
}

fn relay(state: &PathBuf, args: &[&str], keep_dumpable: bool) -> serde_json::Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mousse-relay"));
    cmd.arg("--state").arg(state).args(args);
    cmd.env_remove("MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE");
    if keep_dumpable {
        cmd.env("MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE", "1");
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

fn initialized(tag: &str) -> PathBuf {
    let state = temp_dir(tag);
    relay(&state, &["init", "--public", "127.0.0.1:443"], false);
    state
}

#[test]
fn the_relay_has_core_dumps_off_and_is_not_dumpable() {
    let state = initialized("off");
    let status = relay(&state, &["status", "--json"], false);
    let p = &status["process"];
    assert_eq!(p["core_limit"], 0, "{status:#}");
    assert_eq!(p["core_limit_max"], 0, "{status:#}");
    assert_eq!(
        p["dumpable"], false,
        "the relay process is dumpable: {status:#}"
    );
    let _ = std::fs::remove_dir_all(&state);
}

#[cfg(debug_assertions)]
#[test]
fn the_test_hook_keeps_only_a_debug_build_dumpable_and_core_dumps_stay_off() {
    let state = initialized("hook");
    // Not refused as an unknown MOUSSE_NET_RELAY_ limit.
    let status = relay(&state, &["status", "--json"], true);
    let p = &status["process"];
    assert_eq!(p["dumpable"], true, "{status:#}");
    assert_eq!(p["core_limit"], 0, "{status:#}");
    let _ = std::fs::remove_dir_all(&state);
}
