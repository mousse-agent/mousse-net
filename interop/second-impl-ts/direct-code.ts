// The direct code of wire.md 10.9: 12 characters of Crockford base32, the
// first 4 the lookup, the last 8 the secret (the exchange password).

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
