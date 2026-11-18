//! wasm32 handshakes under Node (the default wasm-bindgen-test host).
//!
//! Run (ring needs clang for wasm32; see spec/matrix/crypto.md):
//! `cargo test -p tls-matrix --target wasm32-unknown-unknown --no-default-features --features ring,rustcrypto,pq-pure,wasm`
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use tls_matrix::wasm::{host_now_ms, run_all};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn every_pair_passes_with_host_clock_and_entropy() {
    let now = host_now_ms();
    assert!(now > 1.7e12, "host clock looks wrong: {now}");
    let results = run_all(now, false, "test", "node");
    assert!(!results.is_empty(), "no provider compiled in");
    for (file, r) in &results {
        assert_eq!(r.outcome, "PASS", "{file}: {}", r.details);
        // ring and rustcrypto alone are classical; the hybrid needs `pq-pure`
        // on both ends (the judge checks that per pair).
        if !cfg!(feature = "pq-pure") {
            assert_eq!(r.kx_group, "X25519", "{file}");
        }
        assert_eq!(r.target, "wasm32-unknown-unknown@node");
    }
}

#[wasm_bindgen_test]
fn broken_mode_fails() {
    for (file, r) in run_all(host_now_ms(), true, "test", "node") {
        assert_eq!(r.outcome, "FAIL", "{file} passed in broken mode");
    }
}
