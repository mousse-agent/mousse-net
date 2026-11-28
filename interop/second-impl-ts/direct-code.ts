// The direct code of wire.md 10.9: 12 characters of Crockford base32, the
// first 4 the lookup, the last 8 the secret (the exchange password).

import { encode, record, requireThat } from './cbor.ts';
import { sha256 } from './certificate.ts';
import { attemptSession } from './wire.ts';
import type { PeerBinding } from './wire.ts';

export const DIRECT_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LENGTH = 12;
const LOOKUP_LENGTH = 4;

export interface DirectCode {
  code: string;
  lookup: string;
  secret: Uint8Array;
}

function parts(code: string): DirectCode {
  return {
    code,
    lookup: code.slice(0, LOOKUP_LENGTH),
    secret: new TextEncoder().encode(code.slice(LOOKUP_LENGTH)),
  };
}

export function directCodeFromDraw(draw: Uint8Array): DirectCode {
  if (draw.length !== LENGTH) throw new Error('draw_length');
  return parts([...draw].map(b => DIRECT_CODE_ALPHABET[b & 0x1f]).join(''));
}

export function displayDirectCode(code: string): string {
  return [code.slice(0, 4), code.slice(4, 8), code.slice(8)].join('-');
}

// What a person typed: spaces and dashes dropped, ASCII letters uppercased,
// O read as 0 and I, L as 1. A bad character is reported before a wrong
// length.
export function parseDirectCode(text: string): DirectCode {
  // Keep at most 12 characters, but read every one so a later bad character
  // is still bad_character.
  let code = '';
  let length = 0;
  for (const unit of text) {
    if (unit === ' ' || unit === '-') continue;
    const c = unit.length === 1 && unit.charCodeAt(0) < 0x80 ? unit.toUpperCase() : '';
    const folded = c === 'O' ? '0' : c === 'I' || c === 'L' ? '1' : c;
    if (folded === '' || !DIRECT_CODE_ALPHABET.includes(folded)) throw new Error('bad_character');
    if (length < LENGTH) code += folded;
    length += 1;
  }
  if (length !== LENGTH) throw new Error('wrong_length');
  return parts(code);
}

// The kind-3 binding (wire.md 10.9 "Binding").
export const DIRECT_KIND = 3;
export const DIRECT_CEREMONY_VERSION = 1;

/** D = H(CBOR {1: "mousse-direct-invite-v1", 2: L, 3: I}). */
export function directInviteDigest(lookup: string, invitation: Uint8Array): Uint8Array {
  requireThat(/^[0-9A-HJKMNP-TV-Z]{4}$/.test(lookup) && invitation.length === 16, 'direct_binding');
  return sha256(encode(record([1, 'mousse-direct-invite-v1'], [2, lookup], [3, invitation])));
}

/** CI: the direct binding transcript, with the joiner (initiator) first. */
export const directTranscript = (digest: Uint8Array, binding: PeerBinding): Uint8Array =>
  encode(record([1, 'mousse-direct-pair-v1'], [2, digest], [3, DIRECT_KIND], [4, DIRECT_CEREMONY_VERSION],
    [5, [[1, binding.joiner], [2, binding.host]]], [6, binding.exporter]));

/** The CPace inputs of one Pair with IP attempt: PRS is the secret's 8 ASCII bytes. */
export function directCpaceInputs(code: DirectCode, invitation: Uint8Array, binding: PeerBinding, attempt: Uint8Array) {
  const digest = directInviteDigest(code.lookup, invitation);
  const ci = directTranscript(digest, binding);
  const { sid } = attemptSession(attempt, binding.exporter);
  return { digest, ci, sid, prs: Uint8Array.from(code.secret), ad: new Uint8Array(), requireEmptyPeerAd: true };
}

/** A code from its 12 characters (no folding: the host's own or a parsed one). */
export function directCode(code: string): DirectCode {
  requireThat(code.length === LENGTH && [...code].every(c => DIRECT_CODE_ALPHABET.includes(c)), 'bad_character');
  return parts(code);
}
