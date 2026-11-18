// The page side: asks for persistent storage (Window-only API) and starts
// one dedicated Worker per step. The runner drives these through
// window.spike; a person can call them from the console too.

const log = (line) => {
  document.getElementById('log').textContent += line + '\n';
};

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(label), ms)),
  ]);
}

async function requestPersist() {
  const storage = navigator.storage;
  if (!storage || typeof storage.persist !== 'function') {
    return { persist: 'unsupported', persisted_before: null, persisted_after: null };
  }
  const before = typeof storage.persisted === 'function' ? await storage.persisted() : null;
  // Firefox asks the user; headless there is nobody to answer.
  const answer = await withTimeout(storage.persist(), 5000, 'no-answer-in-5s');
  const after = typeof storage.persisted === 'function' ? await storage.persisted() : null;
  log(`persist() = ${answer} (persisted before ${before}, after ${after})`);
  return { persist: answer, persisted_before: before, persisted_after: after };
}

// Start a new Worker, run one step, terminate it.
function runWorker(phase, breakMode) {
  return new Promise((resolve) => {
    const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    const done = (value) => {
      worker.terminate();
      log(`${phase}: ${value.ok ? 'certificate issued' : 'failed: ' + value.error}`);
      resolve(value);
    };
    const timer = setTimeout(() => done({ phase, ok: false, error: 'Worker timed out' }), 30000);
    worker.onmessage = (e) => {
      clearTimeout(timer);
      done(e.data);
    };
    worker.onerror = (e) => {
      clearTimeout(timer);
      done({ phase, ok: false, error: `Worker error: ${e.message || e.type}` });
    };
    worker.postMessage({ phase, break: breakMode });
  });
}

// Ask the server to clear this origin's storage (the Clear-Site-Data header,
// the same thing a user's "clear site data" does).
async function clearSiteData() {
  const res = await fetch('/clear-site-data', { cache: 'no-store' });
  return res.ok;
}

window.spike = { requestPersist, runWorker, clearSiteData };
window.spikeReady = true;
