export type UInt = number | bigint;
export type Value = UInt | Uint8Array | string | Value[] | Map<bigint, Value>;

export const bytes = (hex: string): Buffer => Buffer.from(hex, 'hex');
export const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex');
export const utf8 = (s: string): Buffer => Buffer.from(s, 'utf8');
export const concat = (...parts: Uint8Array[]): Buffer => Buffer.concat(parts);
export const record = (...fields: [UInt, Value][]): Map<bigint, Value> =>
  new Map(fields.map(([key, value]) => [BigInt(key), value]));

export function fail(code: string): never { throw new Error(code); }
export function requireThat(condition: unknown, code: string): asserts condition {
  if (!condition) fail(code);
}

const maximum = 0xffffffffffffffffn;
export function uint(value: Value | undefined, max = maximum): value is UInt {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) return false;
  return (typeof value === 'number' || typeof value === 'bigint') && value >= 0 && value <= max;
}
export const byteString = (value: Value | undefined, min: number, max = min): value is Uint8Array =>
  value instanceof Uint8Array && value.length >= min && value.length <= max;
export const textString = (value: Value | undefined, min: number, max: number): value is string =>
  typeof value === 'string' && value.isWellFormed() && utf8(value).length >= min && utf8(value).length <= max;
export const fields = (value: Value, ...keys: number[]): value is Map<bigint, Value> =>
  value instanceof Map && value.size === keys.length && keys.every(key => value.has(BigInt(key)));

function head(major: number, n: bigint): Buffer {
  requireThat(uint(n), 'unsupported');
  if (n < 24n) return Buffer.of((major << 5) | Number(n));
  const width = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 0xffffffffn ? 4 : 8;
  const out = Buffer.alloc(width + 1);
  out[0] = (major << 5) | (23 + Math.log2(width) + 1);
  for (let i = width; i > 0; i--, n >>= 8n) out[i] = Number(n & 255n);
  return out;
}

export function encode(value: Value, depth = 0): Buffer {
  requireThat(depth <= 8, 'too_deep');
  if (uint(value)) return head(0, BigInt(value));
  if (value instanceof Uint8Array) return concat(head(2, BigInt(value.length)), value);
  if (typeof value === 'string') {
    requireThat(value.isWellFormed(), 'invalid_utf8');
    const b = utf8(value);
    return concat(head(3, BigInt(b.length)), b);
  }
  if (Array.isArray(value)) return concat(head(4, BigInt(value.length)), ...value.map(v => encode(v, depth + 1)));
  if (value instanceof Map) {
    const entries = [...value].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return concat(head(5, BigInt(entries.length)),
      ...entries.flatMap(([k, v]) => {
        requireThat(uint(k), 'non_integer_key');
        return [encode(k, depth + 1), encode(v, depth + 1)];
      }));
  }
  return fail('unsupported');
}

export function decode(input: Uint8Array): Value {
  let cursor = 0;
  const take = (size: bigint): Uint8Array => {
    requireThat(size <= input.length - cursor, 'truncated');
    const start = cursor;
    cursor += Number(size);
    return input.subarray(start, cursor);
  };

  function item(depth: number, key = false): Value {
    requireThat(depth <= 8, 'too_deep');
    const initial = take(1n)[0];
    const major = initial >> 5;
    const extra = initial & 31;
    if (key) requireThat(major === 0, 'non_integer_key');
    requireThat([0, 2, 3, 4, 5].includes(major), 'unsupported');
    requireThat(extra !== 31, 'non_canonical');
    requireThat(extra <= 27, 'unsupported');
    let size = BigInt(extra);
    if (extra >= 24) {
      size = 0n;
      for (const octet of take(1n << BigInt(extra - 24))) size = (size << 8n) | BigInt(octet);
      requireThat(size >= [24n, 256n, 65536n, 0x100000000n][extra - 24], 'non_canonical');
    }
    if (major === 0) return size;
    if (major === 2) return Buffer.from(take(size));
    if (major === 3) {
      const data = take(size);
      try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data); }
      catch { return fail('invalid_utf8'); }
    }
    const minimumItemBytes = major === 4 ? 1n : 2n;
    requireThat(size * minimumItemBytes <= input.length - cursor, 'truncated');
    const array: Value[] = [];
    const map = new Map<bigint, Value>();
    let last = -1n;
    for (let i = 0n; i < size; i++) {
      if (major === 4) {
        array.push(item(depth + 1));
      } else {
        const k = item(depth + 1, true) as bigint;
        requireThat(k > last, 'unsorted_keys');
        last = k;
        map.set(k, item(depth + 1));
      }
    }
    return major === 4 ? array : map;
  }

  const result = item(0);
  requireThat(cursor === input.length, 'trailing_bytes');
  return result;
}
