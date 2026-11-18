// Dedicated Worker for the crypto matrix (Phase 0 spike 1, browser cells):
// runs every provider pair of spikes/tls-matrix (wasm32, built with
// wasm-bindgen --target no-modules into matrix-pkg/) over the in-memory pipe,
// with the Worker's clock and crypto.getRandomValues.
//
// Message in:  { breakPin, build }
// Message out: { ok: true, host, entries: [{ file, result }], ms } or { ok: false, error }

/* global wasm_bindgen */
importScripts('matrix-pkg/tls_matrix.js');
const ready = wasm_bindgen({ module_or_path: 'matrix-pkg/tls_matrix_bg.wasm' });

// The same families as tls-matrix's browser_family().
function family(ua) {
  if (ua.includes('Firefox/')) return 'firefox';
  if (ua.includes('Chrome/') || ua.includes('Chromium/')) return 'chromium';
  if (ua.includes('Safari/')) return 'safari';
  return 'unknown';
}

self.onmessage = async ({ data }) => {
  try {
    await ready;
    const host = `worker-${family(navigator.userAgent)}`;
    const started = performance.now();
    const entries = JSON.parse(wasm_bindgen.run_matrix(Date.now(), data.breakPin, data.build, host));
    self.postMessage({ ok: true, host, entries, ms: Math.round(performance.now() - started) });
  } catch (e) {
    self.postMessage({ ok: false, error: String((e && e.stack) || e) });
  }
};
