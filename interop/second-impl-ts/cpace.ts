import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { concat, fail, requireThat, utf8 } from './cbor.ts';
import { equalBytes } from './certificate.ts';

const Point = ristretto255.Point;
export const DSI = utf8('CPaceRistretto255');
export const DSI_ISK = utf8('CPaceRistretto255_ISK');
export const hashBlockSize = 128;
export const hashTranscript = sha512;
const identity = new Uint8Array(32);

export function prependLen(input: Uint8Array): Buffer {
  const digits: number[] = [];
  let n = input.length;
  while (n >= 128) {
    digits.push((n % 128) | 128);
    n = Math.floor(n / 128);
  }
  return concat(Buffer.from([...digits, n]), input);
}

export const lvCat = (...parts: Uint8Array[]) => concat(...parts.map(prependLen));
export const lexLarger = (a: Uint8Array, b: Uint8Array) => Buffer.compare(a, b) > 0;
export const orderedCat = (a: Uint8Array, b: Uint8Array) => lexLarger(a, b)
  ? concat(utf8('oc'), a, b) : concat(utf8('oc'), b, a);
export const transcriptIR = (ya: Uint8Array, ada: Uint8Array, yb: Uint8Array, adb: Uint8Array) =>
  lvCat(ya, ada, yb, adb);
export const transcriptOC = (ya: Uint8Array, ada: Uint8Array, yb: Uint8Array, adb: Uint8Array) =>
  orderedCat(lvCat(ya, ada), lvCat(yb, adb));
export const sidOutput = (transcript: Uint8Array) => sha512(concat(utf8('CPaceSidOutput'), transcript));

export interface Inputs { prs: Uint8Array; ci: Uint8Array; sid: Uint8Array; ad: Uint8Array }
export function generator(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array) {
  const zpad = Math.max(0, hashBlockSize - 1 - prependLen(prs).length - prependLen(DSI).length);
  const input = lvCat(DSI, prs, new Uint8Array(zpad), ci, sid);
  const hash = sha512(input);
  const point = ristretto255_hasher.deriveToCurve!(hash);
  return { zpad, input, hash, point };
}

function littleEndian(input: Uint8Array): bigint {
  let result = 0n;
  for (let i = input.length - 1; i >= 0; i--) result = (result << 8n) | BigInt(input[i]);
  return result;
}

export type DrawBytes = (length: number) => Uint8Array;
export function sampleScalar(draw: DrawBytes): Uint8Array {
  for (;;) {
    const scalar = Uint8Array.from(draw(32));
    requireThat(scalar.length === 32, 'BadRandomDraw');
    scalar[31] &= 0x0f;
    if (scalar.some(x => x !== 0)) return scalar;
  }
}

export function scalarMult(scalar: Uint8Array, encoded: Uint8Array): Uint8Array {
  return Point.fromBytes(encoded).multiply(littleEndian(scalar)).toBytes();
}

export function scalarMultVerified(scalar: Uint8Array, encoded: Uint8Array): Uint8Array {
  let point;
  try { point = Point.fromBytes(encoded); }
  catch { return identity.slice(); }
  return point.multiply(littleEndian(scalar)).toBytes();
}

function checkInputs({ prs, sid, ad }: Inputs): void {
  requireThat(prs.length !== 0, 'EmptyPassword');
  requireThat(sid.length >= 16, 'SidTooShort');
  requireThat(ad.length <= 4096, 'AdTooLong');
}

function share(input: Inputs, scalar: Uint8Array): Buffer {
  const { point } = generator(input.prs, input.ci, input.sid);
  return lvCat(point.multiply(littleEndian(scalar)).toBytes(), input.ad);
}

function parseShare(message: Uint8Array, tagLength: number) {
  requireThat(message[0] === 32 && message.length >= 34, 'Malformed');
  let length = message[33];
  let start = 34;
  if (length & 128) {
    const next = message[start++];
    requireThat(next >= 1 && next <= 32, 'Malformed');
    length = (length & 127) + next * 128;
  }
  const end = start + length;
  requireThat(length <= 4096 && message.length === end + tagLength, 'Malformed');
  return {
    encoded: message.subarray(1, 33),
    ad: message.subarray(start, end),
    body: message.subarray(0, end),
    tag: message.subarray(end),
  };
}

export const iskInput = (sid: Uint8Array, shared: Uint8Array, transcript: Uint8Array) =>
  concat(lvCat(DSI_ISK, sid, shared), transcript);

export function confirmationKey(sid: Uint8Array, isk: Uint8Array) {
  const input = concat(utf8('CPaceMac'), sid, isk);
  const key = sha512(input);
  input.fill(0);
  return key;
}

function confirmation(sid: Uint8Array, scalar: Uint8Array, point: Uint8Array, a: Uint8Array, b: Uint8Array) {
  const shared = scalarMultVerified(scalar, point);
  requireThat(!equalBytes(shared, identity), 'InvalidPoint');
  const input = iskInput(sid, shared, concat(a, b));
  const isk = hashTranscript(input);
  input.fill(0);
  shared.fill(0);
  const key = confirmationKey(sid, isk);
  const ta = hmac(sha512, key, a);
  const tb = hmac(sha512, key, b);
  key.fill(0);
  return { isk, ta, tb };
}

export function initiate(inputs: Inputs, draw: DrawBytes) {
  checkInputs(inputs);
  const scalar = sampleScalar(draw);
  const message = share(inputs, scalar);
  let pending = true;

  function dispose() {
    pending = false;
    scalar.fill(0);
  }

  return {
    message,
    dispose,
    finish(reply: Uint8Array) {
      requireThat(pending, 'WrongState');
      try {
        const peer = parseShare(reply, 64);
        const { isk, ta, tb } = confirmation(inputs.sid, scalar, peer.encoded, message, peer.body);
        if (!equalBytes(peer.tag, tb)) {
          isk.fill(0); ta.fill(0); tb.fill(0);
          fail('ConfirmationFailed');
        }
        tb.fill(0);
        return { message: ta, isk, ad: peer.ad };
      } finally {
        dispose();
      }
    },
  };
}

export function respond(inputs: Inputs, received: Uint8Array, draw: DrawBytes) {
  checkInputs(inputs);
  const peer = parseShare(received, 0);
  requireThat(!equalBytes(peer.encoded, identity), 'InvalidPoint');
  try { Point.fromBytes(peer.encoded); }
  catch { fail('InvalidPoint'); }
  const scalar = sampleScalar(draw);
  let result;
  try {
    const body = share(inputs, scalar);
    result = { body, ...confirmation(inputs.sid, scalar, peer.encoded, peer.body, body) };
  } finally {
    scalar.fill(0);
  }
  const { body, isk, ta, tb } = result;
  const message = concat(body, tb);
  tb.fill(0);
  let pending = true;

  function dispose() {
    pending = false;
    isk.fill(0);
    ta.fill(0);
  }

  return {
    message,
    dispose,
    finish(reply: Uint8Array) {
      requireThat(pending, 'WrongState');
      try {
        requireThat(reply.length === 64, 'Malformed');
        requireThat(equalBytes(ta, reply), 'ConfirmationFailed');
        return { isk: isk.slice(), ad: peer.ad };
      } finally {
        dispose();
      }
    },
  };
}
