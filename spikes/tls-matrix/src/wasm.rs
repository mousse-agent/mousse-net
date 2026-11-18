//! Entry point for wasm32-unknown-unknown hosts (Node, or a browser Worker).
//!
//! Time comes from the host (`Date.now()`), entropy from
//! `crypto.getRandomValues` through `getrandom`.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::handshake::Params;
use crate::matrix::{self, MatrixResult, Transport};

/// Marker for result lines printed by tests, collected by `scripts/run-wasm.mjs --stdin`.
pub const RESULT_LINE_PREFIX: &str = "MATRIX_RESULT ";

#[derive(Serialize)]
struct Entry {
    file: String,
    result: MatrixResult,
}

/// Target label: the triple plus the JS host, e.g. `wasm32-unknown-unknown@node`.
pub fn target_label(host: &str) -> String {
    if host.is_empty() {
        crate::TARGET.to_string()
    } else {
        format!("{}@{}", crate::TARGET, host)
    }
}

/// Runs every compiled provider pair over the in-memory pipe.
pub fn run_all(
    now_unix_ms: f64,
    break_pin: bool,
    build: &str,
    host: &str,
) -> Vec<(String, MatrixResult)> {
    let now_unix_secs = if now_unix_ms.is_finite() && now_unix_ms > 0.0 {
        (now_unix_ms / 1000.0) as u64
    } else {
        0
    };
    let target = target_label(host);
    let ua = user_agent();
    matrix::pairs(true)
        .into_iter()
        .map(|(client, server)| {
            let params = Params {
                client,
                server,
                now_unix_secs,
                break_pin,
            };
            let (mut result, _) = matrix::run(params, &[Transport::Pipe], &target, build);
            result
                .details
                .push_str(&format!(" | host clock {now_unix_ms} ms; user agent: {ua}"));
            (matrix::result_file_name(&target, client, server), result)
        })
        .collect()
}

/// One line per result, `MATRIX_RESULT <json {file, result}>`, for log collection.
pub fn result_lines(results: &[(String, MatrixResult)]) -> Vec<String> {
    results
        .iter()
        .map(|(file, result)| {
            let entry = Entry {
                file: file.clone(),
                result: result.clone(),
            };
            format!(
                "{RESULT_LINE_PREFIX}{}",
                serde_json::to_string(&entry).unwrap_or_default()
            )
        })
        .collect()
}

/// JSON array of `{ file, result }`, one per provider pair.
#[wasm_bindgen]
pub fn run_matrix(now_unix_ms: f64, break_pin: bool, build: String, host: String) -> String {
    let entries: Vec<Entry> = run_all(now_unix_ms, break_pin, &build, &host)
        .into_iter()
        .map(|(file, result)| Entry { file, result })
        .collect();
    serde_json::to_string(&entries).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// The host clock, in milliseconds since the Unix epoch.
pub fn host_now_ms() -> f64 {
    js_sys::Date::now()
}

/// `navigator.userAgent` of the host, or "" when there is none.
pub fn user_agent() -> String {
    let global = js_sys::global();
    js_sys::Reflect::get(&global, &JsValue::from_str("navigator"))
        .ok()
        .filter(|n| n.is_object())
        .and_then(|n| js_sys::Reflect::get(&n, &JsValue::from_str("userAgent")).ok())
        .and_then(|ua| ua.as_string())
        .unwrap_or_default()
}

/// Short browser family from a user agent: chromium, firefox, safari or unknown.
pub fn browser_family(ua: &str) -> &'static str {
    if ua.contains("Firefox/") {
        "firefox"
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        "chromium"
    } else if ua.contains("Safari/") {
        "safari"
    } else {
        "unknown"
    }
}
