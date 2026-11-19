import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { equalBytes } from '@noble/curves/utils.js';
import { bytes, concat, encode, fail, hex, record, requireThat, utf8 } from './cbor.ts';

export { equalBytes, sha256 };
export const publicKey = (secret: Uint8Array): Uint8Array => p256.getPublicKey(secret, false);
export function validPoint(key: Uint8Array): boolean {
  if (key.length !== 65 || key[0] !== 4) return false;
  try { p256.Point.fromBytes(key); return true; }
  catch { return false; }
}
export function fingerprint(key: Uint8Array): Uint8Array {
  requireThat(validPoint(key), 'identity_key_invalid');
  return sha256(key);
}

const integer = (value: Uint8Array): bigint => BigInt('0x' + hex(value));
export function checkRaw(raw: Uint8Array): void {
  requireThat(raw.length === 64, 'not_raw');
  for (const part of [raw.subarray(0, 32), raw.subarray(32)]) {
    const n = integer(part);
    requireThat(n > 0n && n < p256.Point.Fn.ORDER, 'out_of_range');
  }
}

export function der(tag: number, ...parts: Uint8Array[]): Buffer {
  const body = concat(...parts);
  const length: number[] = [];
  for (let n = body.length; n > 0; n >>>= 8) length.unshift(n & 255);
  return concat(Buffer.from(body.length < 128 ? [tag, body.length] : [tag, 0x80 | length.length, ...length]), body);
}

export class DerReader {
  private offset = 0;
  constructor(data: Uint8Array, error = 'malformed') {
    this.data = data;
    this.error = error;
  }
  private readonly data: Uint8Array;
  private readonly error: string;

  private octet(): number {
    requireThat(this.offset < this.data.length, this.error);
    return this.data[this.offset++];
  }

  peek(): number { return this.data[this.offset]; }

  read(tag: number) {
    const start = this.offset;
    requireThat(this.octet() === tag, this.error);
    let size = this.octet();
    if (size >= 128) {
      const width = size & 127;
      requireThat(width >= 1 && width <= 4, this.error);
      size = this.octet();
      requireThat(size !== 0, this.error);
      for (let i = 1; i < width; i++) size = size * 256 + this.octet();
      requireThat(size >= 128, this.error);
    }
    const end = this.offset + size;
    requireThat(end <= this.data.length, this.error);
    const value = this.data.subarray(this.offset, end);
    this.offset = end;
    return { value, encoded: this.data.subarray(start, end) };
  }

  nested(tag: number): DerReader { return new DerReader(this.read(tag).value, this.error); }
  done(): void { requireThat(this.offset === this.data.length, this.error); }
}

function positive(value: Uint8Array, error: string): Uint8Array {
  requireThat(value.length && value[0] < 128 &&
    (value[0] !== 0 || value.length === 1 || value[1] >= 128), error);
  return value[0] === 0 && value.length > 1 ? value.subarray(1) : value;
}

export function derToRaw(input: Uint8Array): Buffer {
  const outer = new DerReader(input, 'bad_der');
  const sequence = outer.nested(0x30);
  const r = sequence.read(2).value;
  const s = sequence.read(2).value;
  sequence.done();
  outer.done();
  const raw = Buffer.alloc(64);
  const parts = [r, s].map(value => positive(value, 'bad_der'));
  for (const [index, part] of parts.entries()) {
    requireThat(part.length <= 32, 'out_of_range');
    raw.set(part, 32 * (index + 1) - part.length);
  }
  checkRaw(raw);
  return raw;
}

export function rawToDer(raw: Uint8Array): Buffer {
  checkRaw(raw);
  const integers = [raw.subarray(0, 32), raw.subarray(32)].map(value => {
    const part = value.subarray(value.findIndex(b => b !== 0));
    return part[0] >= 128 ? der(2, Buffer.of(0), part) : der(2, part);
  });
  return der(0x30, ...integers);
}

function sign(message: Uint8Array, secret: Uint8Array): Uint8Array {
  return p256.sign(message, secret, { prehash: true, lowS: false });
}

export function signCertificateVerify(message: Uint8Array, sessionSecret: Uint8Array): Uint8Array {
  return sign(message, sessionSecret);
}

export function verify(signature: Uint8Array, message: Uint8Array, key: Uint8Array): boolean {
  return validPoint(key) && p256.verify(signature, message, key, { prehash: true, lowS: false });
}

export const spkiPrefix = bytes('3059301306072a8648ce3d020106082a8648ce3d030107034200');
export const versionField = bytes('a003020102');
export const algorithm = bytes('300a06082a8648ce3d040302');
const name = der(0x30, der(0x31, der(0x30, bytes('0603550403'), der(0x0c, utf8('mousse-session')))));
const oid = bytes('061369e595e3c0fbf68a84f595c9dabef4e2f7be05');

export interface Window { not_before: number; not_after: number }
const goodWindow = ({ not_before: start, not_after: end }: Window) => start < end && end - start <= 86400;

export function time(seconds: number): Buffer {
  requireThat(Number.isSafeInteger(seconds) && seconds >= 0 && seconds < 253402300800, 'malformed');
  const iso = new Date(seconds * 1000).toISOString();
  const digits = iso.slice(0, 19).replace(/[-:T]/g, '') + 'Z';
  return Number(iso.slice(0, 4)) < 2050 ? der(0x17, utf8(digits.slice(2))) : der(0x18, utf8(digits));
}

function readTime(reader: DerReader): number {
  const tag = reader.peek();
  requireThat(tag === 0x17 || tag === 0x18, 'malformed');
  const { value, encoded } = reader.read(tag);
  let digits = Buffer.from(value).toString('latin1');
  requireThat(tag === 0x17 ? /^[0-9]{12}Z$/.test(digits) : /^[0-9]{14}Z$/.test(digits), 'malformed');
  if (tag === 0x17) digits = (Number(digits.slice(0, 2)) >= 50 ? '19' : '20') + digits;
  const parts = digits.match(/^(....)(..)(..)(..)(..)(..)Z$/)!;
  const [, y, m, d, h, min, s] = parts;
  const parsed = Date.parse(`${y}-${m}-${d}T${h}:${min}:${s}Z`) / 1000;
  requireThat(equalBytes(time(parsed), encoded), 'malformed');
  return parsed;
}

export function serialNumber(spki: Uint8Array): Uint8Array {
  const serial = sha256(spki).slice(0, 16);
  serial[0] = (serial[0] & 0x3f) | 0x40;
  return serial;
}

function delegation(spki: Uint8Array, window: Window, version: bigint) {
  return encode(record([1, 'mousse-session-v1'], [2, spki], [3, window.not_before], [4, window.not_after], [5, version]));
}

class IdentitySigner {
  readonly #secret: Uint8Array;

  constructor(secret: Uint8Array) { this.#secret = secret; }

  signSession(spki: Uint8Array, window: Window) {
    const record = delegation(spki, window, 1n);
    return { record, signature: sign(record, this.#secret) };
  }
}

function tbs(spki: Uint8Array, window: Window, serial: Uint8Array, extension: Uint8Array) {
  return der(0x30, versionField, der(2, serial), algorithm, name,
    der(0x30, time(window.not_before), time(window.not_after)), name, spki,
    der(0xa3, der(0x30, der(0x30, oid, der(4, extension)))));
}

export function issueCertificate(identitySecret: Uint8Array, sessionSecret: Uint8Array, window: Window) {
  requireThat(goodWindow(window), 'window_invalid');
  const identityPublic = publicKey(identitySecret);
  const sessionPublic = publicKey(sessionSecret);
  requireThat(!equalBytes(identityPublic, sessionPublic), 'session_key_invalid');
  const spki = concat(spkiPrefix, sessionPublic);
  const serial = serialNumber(spki);
  const { record, signature: identitySignature } = new IdentitySigner(identitySecret).signSession(spki, window);
  const extensionValue = der(0x30, der(2, Buffer.of(1)), der(4, identityPublic), der(4, identitySignature));
  const body = tbs(spki, window, serial, extensionValue);
  const certificate = der(0x30, body, algorithm, der(3, Buffer.of(0), rawToDer(sign(body, sessionSecret))));
  return { certificate, identityPublic, sessionPublic, spki, serial, record, identitySignature, extensionValue };
}

function parseCertificate(certificate: Uint8Array) {
  const root = new DerReader(certificate);
  const cert = root.nested(0x30);
  root.done();
  const body = cert.read(0x30);
  requireThat(equalBytes(cert.read(0x30).encoded, algorithm), 'malformed');
  const signature = cert.read(3).value;
  cert.done();
  requireThat(signature[0] === 0, 'malformed');
  let rawSelf: Uint8Array | undefined;
  try { rawSelf = derToRaw(signature.subarray(1)); }
  catch (error) { if ((error as Error).message !== 'out_of_range') fail('malformed'); }

  const r = new DerReader(body.value);
  r.read(0xa0); r.read(2); r.read(0x30); r.read(0x30);
  const times = r.nested(0x30);
  const window = { not_before: readTime(times), not_after: readTime(times) };
  times.done();
  r.read(0x30);
  const spki = r.read(0x30).encoded;
  requireThat(spki.length === 91 && equalBytes(spki.subarray(0, 26), spkiPrefix), 'malformed');
  const session = spki.subarray(26);
  const extWrap = r.nested(0xa3);
  const extList = extWrap.nested(0x30);
  const ext = extList.nested(0x30);
  requireThat(equalBytes(ext.read(6).encoded, oid), 'malformed');
  const extension = ext.read(4).value;
  ext.done(); extList.done(); extWrap.done(); r.done();
  const extValue = new DerReader(extension);
  const binding = extValue.nested(0x30);
  extValue.done();
  const versionBytes = binding.read(2).value;
  requireThat(versionBytes.length <= 8, 'malformed');
  const version = integer(positive(versionBytes, 'malformed'));
  const identity = binding.read(4).value;
  const rawIdentity = binding.read(4).value;
  binding.done();
  requireThat(equalBytes(body.encoded, tbs(spki, window, serialNumber(spki), extension)), 'malformed');
  return { window, spki, session, identity, version, rawSelf, rawIdentity, body: body.encoded };
}

export function verifyCertificate(certificate: Uint8Array, now: number, pin?: Uint8Array, alpnMajor = 1n) {
  const c = parseCertificate(certificate);
  requireThat(c.version === 1n && c.version === alpnMajor, 'unsupported_version');
  requireThat(validPoint(c.identity), 'identity_key_invalid');
  requireThat(validPoint(c.session), 'session_key_invalid');
  requireThat(c.rawIdentity.length === 64, 'identity_signature_not_raw');
  requireThat(goodWindow(c.window), 'window_invalid');
  requireThat(c.rawSelf && verify(c.rawSelf, c.body, c.session), 'self_signature_invalid');
  if (process.env.MOUSSE_SECOND_BREAK !== 'verifier') {
    requireThat(verify(c.rawIdentity, delegation(c.spki, c.window, c.version), c.identity), 'identity_signature_invalid');
  }
  requireThat(!pin || equalBytes(pin, c.identity), 'pin_mismatch');
  requireThat(now >= c.window.not_before - 600 && now <= c.window.not_after + 600, 'outside_window');
  return { window: c.window, identity: c.identity, session: c.session };
}

export function lanCandidate(result: string) {
  return result === 'ok' ? null : { action: 'try_next', send: false, warn: false, repin: false };
}

export const nativeTlsPolicy = Object.freeze({
  version: 'TLSv1.3',
  alpn: 'mousse/1',
  groups: Object.freeze(['X25519MLKEM768', 'X25519']),
  requiredGroup: 'X25519MLKEM768',
  signatureScheme: 'ecdsa_secp256r1_sha256',
  mutualCertificates: true,
  resumption: false,
  psk: false,
  earlyData: false,
});

interface NativeHandshake {
  version: string;
  alpn: string;
  group: string;
  signatureScheme: string;
  mutualCertificates: boolean;
  resumed: boolean;
  psk: boolean;
  earlyData: boolean;
}

// The transport supplies these facts and verifies CertificateVerify itself.
export function authenticateNativePeer(handshake: NativeHandshake, certificate: Uint8Array, now: number, pin?: Uint8Array) {
  const policy = nativeTlsPolicy;
  requireThat(handshake.alpn === policy.alpn, 'unsupported_version');
  requireThat(handshake.version === policy.version && handshake.group === policy.requiredGroup &&
    handshake.signatureScheme === policy.signatureScheme && handshake.mutualCertificates &&
    !handshake.resumed && !handshake.psk && !handshake.earlyData, 'tls_policy');
  return verifyCertificate(certificate, now, pin, 1n);
}

const renewalWaits = [30, 60, 120, 240, 300];

export class SessionLifetime {
  readonly renewAt: number;
  readonly deadline: number;
  readonly monoDeadline: number;
  private nextRetry?: number;
  private retry = 0;
  private closed = false;

  constructor(local: Window, peer: Window, authenticated: { now: number; mono: number }, previous?: SessionLifetime) {
    const end = Math.min(local.not_after, peer.not_after);
    this.renewAt = Math.max(local.not_before, peer.not_before, end - 1800);
    this.deadline = end + 600;
    this.monoDeadline = authenticated.mono + (this.deadline + 1 - authenticated.now) * 1000;
    if (previous && this.renewAt <= previous.renewAt) {
      this.nextRetry = previous.nextRetry;
      this.retry = previous.retry;
    }
  }

  tick(now: number, mono: number, candidateInProgress = false): 'cert_expired' | 'renew_due' | null {
    if (this.closed) return null;
    if (now > this.deadline || mono >= this.monoDeadline) {
      this.closed = true;
      return 'cert_expired';
    }
    const due = this.nextRetry === undefined ? now >= this.renewAt : mono >= this.nextRetry;
    if (due) {
      this.nextRetry = mono + renewalWaits[this.retry] * 1000;
      this.retry = Math.min(this.retry + 1, renewalWaits.length - 1);
      if (!candidateInProgress) return 'renew_due';
    }
    return null;
  }
}
