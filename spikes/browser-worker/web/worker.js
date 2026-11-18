// The dedicated Worker: loads the identity key from IndexedDB (or makes a
// non-extractable one), has the wasm engine make a session key and the
// record to sign, signs it with WebCrypto, and finishes the certificate.
//
// Breaks (must-fail controls):
//   tampered-cert  the certificate's identity signature is over another SPKI
//   der-signature  the certificate carries the DER form of the signature
//   fresh-key      every Worker after the first ignores the stored key

import init, { Pending, rawToDer } from './pkg/browser_worker.js';

const DB_NAME = 'mousse-identity';
const STORE = 'keys';
const KEY_ID = 'identity';
const LIFETIME_SECS = 86400;
const ECDSA = { name: 'ECDSA', hash: 'SHA-256' };

const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function openDb() {
  const req = indexedDB.open(DB_NAME, 1);
  req.onupgradeneeded = () => req.result.createObjectStore(STORE);
  return request(req);
}

async function loadKey(db) {
  const tx = db.transaction(STORE, 'readonly');
  return (await request(tx.objectStore(STORE).get(KEY_ID))) ?? null;
}

async function saveKey(db, pair) {
  const tx = db.transaction(STORE, 'readwrite');
  tx.objectStore(STORE).put({ privateKey: pair.privateKey, publicKey: pair.publicKey }, KEY_ID);
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function sign(privateKey, record) {
  return new Uint8Array(await crypto.subtle.sign(ECDSA, privateKey, record));
}

async function step(phase, breakMode) {
  await init();
  const db = await openDb();
  let pair = await loadKey(db);
  if (pair && breakMode === 'fresh-key') pair = null;
  const loadedFromStore = pair !== null;
  if (!pair) {
    // Private key non-extractable; the public half is always exportable.
    pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await saveKey(db, pair);
  }
  db.close();

  const identity = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  let exportRefused = false;
  try {
    await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  } catch {
    exportRefused = true;
  }

  const now = Math.floor(Date.now() / 1000);
  const pending = new Pending(now, LIFETIME_SECS);
  const notBefore = pending.notBefore;
  const notAfter = pending.notAfter;
  const signature = await sign(pair.privateKey, pending.record());
  const cert = pending.finish(identity, signature);

  // Negative cases, made with this certificate's own session key.
  const other = new Pending(now, LIFETIME_SECS);
  const otherSignature = await sign(pair.privateKey, other.record());
  const otherSpkiCert = cert.withIdentitySignature(otherSignature);
  const derCert = cert.withIdentitySignature(rawToDer(signature));
  other.free();

  // finish() itself must refuse a DER signature.
  const third = new Pending(now, LIFETIME_SECS);
  let finishDerError = null;
  try {
    third.finish(identity, rawToDer(await sign(pair.privateKey, third.record()))).free();
  } catch (e) {
    finishDerError = String(e && e.message ? e.message : e);
  }
  third.free();

  let main = cert.der();
  if (breakMode === 'tampered-cert') main = otherSpkiCert;
  if (breakMode === 'der-signature') main = derCert;
  cert.free();
  pending.free();

  const persisted = navigator.storage && navigator.storage.persisted
    ? await navigator.storage.persisted().catch(() => null)
    : null;

  return {
    phase,
    ok: true,
    loaded_from_store: loadedFromStore,
    identity_key: hex(identity),
    certificate: hex(main),
    other_spki_certificate: hex(otherSpkiCert),
    der_certificate: hex(derCert),
    extractable: pair.privateKey.extractable,
    export_refused: exportRefused,
    webcrypto_signature_len: signature.length,
    finish_refuses_der: finishDerError !== null,
    finish_der_error: finishDerError,
    not_before: notBefore,
    not_after: notAfter,
    persisted_in_worker: persisted,
  };
}

self.onmessage = async (e) => {
  const { phase, break: breakMode } = e.data;
  try {
    self.postMessage(await step(phase, breakMode));
  } catch (err) {
    self.postMessage({ phase, ok: false, error: String(err && err.message ? err.message : err) });
  }
};
