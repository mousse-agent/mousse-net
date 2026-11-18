// Dedicated Worker: holds the identity key and makes session certificates.
//
// The identity key is a non-extractable WebCrypto ECDSA P-256 key kept in
// IndexedDB, so it survives the Worker (and the page) going away. The
// session record and the certificate come from mousse-net-core compiled to
// wasm32 (pkg/, built by wasm-pack --target no-modules).
//
// Message in:  { step, breakMode, startedAt }
// Message out: { ok: true, ... } or { ok: false, error }

/* global wasm_bindgen */
importScripts('pkg/mousse_browser_worker.js');
const { SessionDraft, verify_in_worker } = wasm_bindgen;
const ready = wasm_bindgen({ module_or_path: 'pkg/mousse_browser_worker_bg.wasm' });

const DB = 'mousse-browser-spike';
const STORE = 'keys';
const SLOT = 'identity';
const LIFETIME = 86400;
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };

const hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function openDb() {
  const req = indexedDB.open(DB, 1);
  req.onupgradeneeded = () => req.result.createObjectStore(STORE);
  return request(req);
}

async function withStore(mode, fn) {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, mode);
    const done = new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    const result = await request(fn(tx.objectStore(STORE)));
    await done;
    return result;
  } finally {
    db.close();
  }
}

async function makeKey() {
  const pair = await crypto.subtle.generateKey(ECDSA, false, ['sign', 'verify']);
  await withStore('readwrite', (s) => s.put({ privateKey: pair.privateKey, publicKey: pair.publicKey }, SLOT));
  return pair;
}

// The stored key, or a new one if there is none. Control `fresh-key` makes a
// new key after the restart instead of loading the stored one.
async function identityKey(step, breakMode) {
  const stored = await withStore('readonly', (s) => s.get(SLOT));
  if (stored && !(breakMode === 'fresh-key' && step === 2)) return { pair: stored, created: false };
  return { pair: await makeKey(), created: true };
}

async function refusesExport(key) {
  const tried = {};
  for (const format of ['pkcs8', 'jwk']) {
    try {
      await crypto.subtle.exportKey(format, key);
      tried[format] = 'exported';
    } catch (e) {
      tried[format] = `refused: ${e && e.name}`;
    }
  }
  return tried;
}

async function draft(nb) {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  try {
    return new SessionDraft(secret, BigInt(nb), BigInt(nb + LIFETIME));
  } finally {
    secret.fill(0);
  }
}

async function sign(privateKey, record) {
  return new Uint8Array(await crypto.subtle.sign(SIGN, privateKey, record));
}

async function issue({ step, breakMode }) {
  await ready;
  const { pair, created } = await identityKey(step, breakMode);
  const identity = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const nb = Math.floor(Date.now() / 1000);
  const session = await draft(nb);
  const record = session.record();
  const spki = session.spki();
  const signature = await sign(pair.privateKey, record);
  let certificate;
  let foreignSpki = null;
  if (breakMode === 'tampered-cert') {
    // Sign a record for another session key, and put that signature in
    // this certificate.
    const other = await draft(nb);
    foreignSpki = hex(other.spki());
    const foreign = await sign(pair.privateKey, other.record());
    other.free();
    certificate = session.finish_with_foreign_signature(identity, signature, foreign);
  } else {
    certificate = session.finish(identity, signature);
  }
  return {
    ok: true,
    step,
    created,
    identity: hex(identity),
    certificate: hex(certificate),
    spki: hex(spki),
    foreignSpki,
    record: hex(record),
    identitySignature: hex(signature),
    signatureLength: signature.length,
    notBefore: nb,
    notAfter: nb + LIFETIME,
    privateKey: {
      type: pair.privateKey.type,
      extractable: pair.privateKey.extractable,
      algorithm: pair.privateKey.algorithm,
      usages: pair.privateKey.usages,
      export: await refusesExport(pair.privateKey),
    },
    verifyInWorker: verify_in_worker(certificate, BigInt(nb + 60), identity),
    workerTime: Date.now(),
  };
}

self.onmessage = async ({ data }) => {
  try {
    self.postMessage(await issue(data));
  } catch (e) {
    self.postMessage({ ok: false, step: data && data.step, error: String((e && e.stack) || e) });
  }
};
