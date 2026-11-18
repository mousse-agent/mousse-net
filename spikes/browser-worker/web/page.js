// Drives the spike: a Worker makes a session certificate, the native runner
// checks it, the Worker is terminated and a new one makes another, and the
// runner checks that the same identity key signed it.

const log = (line) => {
  document.getElementById('log').textContent += `\n${line}`;
  console.log(line);
};

const post = async (path, body) => {
  const res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
};

function deleteDb(name) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve('deleted');
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve('blocked');
  });
}

function runWorker(message) {
  return new Promise((resolve) => {
    const worker = new Worker('worker.js');
    const finish = (result) => {
      worker.terminate();
      resolve(result);
    };
    worker.onmessage = ({ data }) => finish(data);
    worker.onerror = (e) => finish({ ok: false, step: message.step, error: `worker error: ${e.message}` });
    worker.postMessage(message);
  });
}

(async () => {
  const run = new URLSearchParams(location.search).get('run');
  const page = { userAgent: navigator.userAgent, errors: [] };
  try {
    const config = await (await fetch(`config?run=${run}`)).json();
    page.breakMode = config.breakMode;
    page.clearedDb = await deleteDb('mousse-browser-spike');
    log(`cleared stored key: ${page.clearedDb}`);
    // Firefox asks the user before persisting; headless, nobody answers.
    page.persist = navigator.storage && navigator.storage.persist
      ? await Promise.race([navigator.storage.persist(), new Promise((r) => setTimeout(() => r('no answer in 2 s'), 2000))])
      : 'unavailable';
    for (const step of [1, 2]) {
      // Each step is a new Worker; the previous one was terminated.
      const result = await runWorker({ step, breakMode: config.breakMode });
      const verdict = await post(`step?run=${run}`, result);
      log(`step ${step}: ${verdict.verdict}`);
    }
  } catch (e) {
    page.errors.push(String((e && e.stack) || e));
    log(`error: ${e}`);
  }
  await post(`done?run=${run}`, page).catch(() => {});
  log('done');
})();
