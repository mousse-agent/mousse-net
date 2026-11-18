//! The same handshakes inside a browser dedicated Worker. Needs a browser and
//! its WebDriver, so it only builds with the `browser-worker` feature. Run
//! with `--nocapture` to print one `MATRIX_RESULT` line per provider pair;
//! `scripts/run-wasm.mjs --stdin --out <dir>` turns them into result files.
//! Commands per browser: spec/matrix/targets.md.
#![cfg(all(target_arch = "wasm32", feature = "browser-worker"))]

use tls_matrix::wasm::{browser_family, host_now_ms, result_lines, run_all, user_agent};
use wasm_bindgen_test::{console_log, wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn build_id() -> &'static str {
    option_env!("MOUSSE_BUILD_ID").unwrap_or("unknown")
}

#[wasm_bindgen_test]
fn every_pair_passes_in_a_worker() {
    let now = host_now_ms();
    assert!(now > 1.7e12, "Worker clock looks wrong: {now}");
    let host = format!("worker-{}", browser_family(&user_agent()));
    let results = run_all(now, false, build_id(), &host);
    assert!(!results.is_empty(), "no provider compiled in");
    for line in result_lines(&results) {
        console_log!("{line}");
    }
    for (file, r) in &results {
        assert_eq!(r.outcome, "PASS", "{file}: {}", r.details);
    }
}

#[wasm_bindgen_test]
fn broken_mode_fails_in_a_worker() {
    for (file, r) in run_all(host_now_ms(), true, build_id(), "worker") {
        assert_eq!(r.outcome, "FAIL", "{file} passed in broken mode");
    }
}
