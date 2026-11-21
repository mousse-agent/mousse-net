import { isIP } from 'node:net';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { byteString, bytes, concat, decode, encode, fail, fields, hex, record, requireThat, textString, uint, utf8 } from './cbor.ts';
import type { UInt, Value } from './cbor.ts';
import { sha256, validPoint } from './certificate.ts';

export const errorNames = [
  'no_error', 'protocol_error', 'frame_too_large', 'flow_control', 'stream_closed',
  'idle_timeout', 'not_authorized', 'grant_revoked', 'cert_expired', 'unsupported_version',
  'pairing_failed', 'invitation_invalid', 'attempts_exhausted', 'pairing_declined',
  'path_replaced', 'refused_stream', 'cancelled', 'internal_error',
] as const;
export type ErrorName = typeof errorNames[number];
export const errorNumber = (name: ErrorName) => errorNames.indexOf(name);
export const readError = (value: number) => errorNames[value] ?? 'internal_error';
const wireError = (value: number) => errorNumber(readError(value));

export type Control =
  | { type: 'HELLO'; major: UInt; minor: UInt }
  | { type: 'AUTHORIZED'; state: 'live' | 'join_only' }
  | { type: 'JOIN_PROOF'; invitation: Uint8Array; mac: Uint8Array; name: string }
  | { type: 'CODE_EXCHANGE'; attempt: Uint8Array; payload: Uint8Array }
  | { type: 'CODE_ABORT'; attempt: Uint8Array; code: number }
  | { type: 'PAIRED'; name: string; role: string };

export type Version = { major: UInt; minor: UInt };
export const hello = { type: 'HELLO', major: 1, minor: 3 } as const;
export function negotiate(local: Version, peer: Version): UInt {
  const agreed = BigInt(local.minor) < BigInt(peer.minor) ? local.minor : peer.minor;
  requireThat(BigInt(local.major) === BigInt(peer.major) && BigInt(agreed) >= BigInt(local.minor) - 1n,
    'unsupported_version');
  return agreed;
}

function decodeControlRecord(value: Value): Control {
  requireThat(fields(value, 0, 1, 2) || fields(value, 0, 1) || fields(value, 0, 1, 2, 3), 'protocol_error');
  const type = value.get(0n);
  const first = value.get(1n);
  const second = value.get(2n);
  const third = value.get(3n);
  switch (type) {
    case 1n:
      requireThat(value.size === 3 && uint(first) && uint(second), 'protocol_error');
      return { type: 'HELLO', major: first, minor: second };
    case 2n:
      requireThat(value.size === 2 && (first === 1n || first === 2n), 'protocol_error');
      return { type: 'AUTHORIZED', state: first === 1n ? 'live' : 'join_only' };
    case 3n:
      requireThat(value.size === 4 && byteString(first, 16) && byteString(second, 32) &&
        textString(third, 1, 128), 'protocol_error');
      return { type: 'JOIN_PROOF', invitation: first, mac: second, name: third };
    case 4n:
      requireThat(value.size === 3 && byteString(first, 16) && byteString(second, 1, 1024), 'protocol_error');
      return { type: 'CODE_EXCHANGE', attempt: first, payload: second };
    case 5n:
      requireThat(value.size === 3 && byteString(first, 16) && uint(second, 65535n), 'protocol_error');
      return { type: 'CODE_ABORT', attempt: first, code: wireError(Number(second)) };
    case 6n:
      requireThat(value.size === 3 && textString(first, 1, 128) && typeof second === 'string' &&
        /^[a-z0-9-]{1,32}$/.test(second) && !/\s/.test(second), 'protocol_error');
      return { type: 'PAIRED', name: first, role: second };
    default: return fail('protocol_error');
  }
}

export function decodeControl(data: Uint8Array): Control {
  requireThat(data.length <= 16384, 'protocol_error');
  try { return decodeControlRecord(decode(data)); }
  catch { return fail('protocol_error'); }
}

export function encodeControl(message: Control): Buffer {
  let value: Value;
  switch (message.type) {
    case 'HELLO': value = record([0, 1], [1, message.major], [2, message.minor]); break;
    case 'AUTHORIZED': value = record([0, 2], [1, message.state === 'live' ? 1 : 2]); break;
    case 'JOIN_PROOF': value = record([0, 3], [1, message.invitation], [2, message.mac], [3, message.name]); break;
    case 'CODE_EXCHANGE': value = record([0, 4], [1, message.attempt], [2, message.payload]); break;
    case 'CODE_ABORT': value = record([0, 5], [1, message.attempt], [2, message.code]); break;
    case 'PAIRED': value = record([0, 6], [1, message.name], [2, message.role]); break;
  }
  const encoded = encode(value);
  decodeControl(encoded);
  return encoded;
}

export interface Ticket {
  version: UInt;
  kind: 1 | 2;
  hostIdentity: Uint8Array;
  invitation: Uint8Array;
  secret: Uint8Array;
  expiresAt: UInt;
  routes: string[];
}

export function decodeTicket(data: Uint8Array): Ticket {
  let value;
  try { value = decode(data); }
  catch { return fail('cbor'); }
  requireThat(value instanceof Map, 'field');
  const version = value.get(1n);
  requireThat(uint(version), 'field');
  requireThat(version === 1n, 'unsupported_version');
  const kind = value.get(2n);
  requireThat(uint(kind), 'field');
  requireThat(kind === 1n || kind === 2n, 'unknown_kind');
  requireThat(fields(value, 1, 2, 3, 4, 5, 6, 7), 'field');
  const hostIdentity = value.get(3n);
  const invitation = value.get(4n);
  const secret = value.get(5n);
  const expiresAt = value.get(6n);
  const routes = value.get(7n);
  requireThat(byteString(hostIdentity, 65) && validPoint(hostIdentity) && byteString(invitation, 16) &&
    byteString(secret, 16) && uint(expiresAt) && Array.isArray(routes) && routes.length <= 8 &&
    routes.every(route => textString(route, 1, 255)), 'field');
  return { version, kind: kind === 1n ? 1 : 2, hostIdentity, invitation, secret, expiresAt, routes };
}

export function encodeTicket(ticket: Ticket): Buffer {
  const data = encode(record([1, ticket.version], [2, ticket.kind], [3, ticket.hostIdentity],
    [4, ticket.invitation], [5, ticket.secret], [6, ticket.expiresAt], [7, ticket.routes]));
  decodeTicket(data);
  return data;
}

export const encodeFragment = (data: Uint8Array): string => Buffer.from(data).toString('base64url');
export function decodeBase64url(text: string): Buffer {
  requireThat(text.length > 0 && !/[^A-Za-z0-9_-]/.test(text), 'encoding');
  const data = Buffer.from(text, 'base64url');
  requireThat(encodeFragment(data) === text, 'encoding');
  return data;
}
export const decodeFragment = (fragment: string): Ticket => decodeTicket(decodeBase64url(fragment));

export const checkJoinerExpiry = (expires: UInt, now: UInt) => {
  requireThat(BigInt(now) < BigInt(expires) + 600n, 'expired');
};

type Host = { ipv4: string } | { ipv6: string } | { dns: string };
type Route = { skip: 'malformed' | 'unknown_scheme' | 'reserved' } | { mdns: string } |
  { tcp: { host: Host; port: number } } | { wss: { host: Host; port: number; path: string } };

function ipv6Hex(address: string): string {
  // The URL parser serializes a validated IPv6 host with hex groups, including IPv4 tails.
  const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const [left, right] = canonical.split('::');
  const groups = left ? left.split(':') : [];
  if (right !== undefined) {
    const suffix = right ? right.split(':') : [];
    groups.push(...Array<string>(8 - groups.length - suffix.length).fill('0'), ...suffix);
  }
  return groups.map(group => group.padStart(4, '0')).join('');
}

// `<host>` by its shape (wire.md 10.2.1), or null when it breaks the grammar.
function routeHost(host: string): Host | null {
  if (/\s/.test(host)) return null;
  if (host.startsWith('[') && host.endsWith(']')) {
    const ipv6 = host.slice(1, -1);
    if (ipv6.includes('%') || isIP(ipv6) !== 6) return null;
    return { ipv6: ipv6Hex(ipv6) };
  }
  if (/^[0-9.]+$/.test(host)) return isIP(host) === 4 ? { ipv4: host } : null;
  const labels = host.split('.');
  if (host.length > 253 || /^\d+$/.test(labels.at(-1)!) ||
      !labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) return null;
  return { dns: host.toLowerCase() };
}

// `<port>`: decimal 1 to 65535, no sign, no leading zero.
const routePort = (digits: string): number | null =>
  /^[1-9][0-9]{0,4}$/.test(digits) && Number(digits) <= 65535 ? Number(digits) : null;

export function routeHint(hint: string): Route {
  const colon = hint.indexOf(':');
  const scheme = colon < 0 ? '' : hint.slice(0, colon);
  const tail = hint.slice(colon + 1);
  const malformed = { skip: 'malformed' } as const;
  if (['ssh', 'ws', 'relay'].includes(scheme)) return { skip: 'reserved' };
  if (scheme === 'mdns') return textString(tail, 1, 63) && !/\p{Cc}/u.test(tail) ? { mdns: tail } : malformed;
  if (scheme === 'wss') {
    // The host and port end at the path's first `/`; no host form holds one.
    if (!tail.startsWith('//')) return malformed;
    const slash = tail.indexOf('/', 2);
    if (slash < 0) return malformed;
    const authority = tail.slice(2, slash);
    const path = tail.slice(slash);
    if (path.length > 200 || !/^\/[A-Za-z0-9._~\/-]*$/.test(path) || !path.endsWith('/mousse-net/1')) {
      return malformed;
    }
    // A port follows the host's last `:` outside the IPv6 brackets.
    const close = authority.lastIndexOf(']');
    const portColon = authority.lastIndexOf(':');
    let hostText = authority;
    let port: number | null = 443;
    if (portColon > close) {
      hostText = authority.slice(0, portColon);
      port = routePort(authority.slice(portColon + 1));
    }
    const host = routeHost(hostText);
    return host && port ? { wss: { host, port, path } } : malformed;
  }
  if (scheme !== 'tcp') return { skip: 'unknown_scheme' };
  const match = tail.match(/^\/\/(\[[^\[\]]+\]|[^:]+):([^:]*)$/);
  if (!match) return malformed;
  const host = routeHost(match[1]);
  const port = routePort(match[2]);
  return host && port ? { tcp: { host, port } } : malformed;
}

export interface PeerBinding { host: Uint8Array; joiner: Uint8Array; exporter: Uint8Array }
export function joinProof(invitation: Uint8Array, secret: Uint8Array, binding: PeerBinding) {
  const key = hkdf(sha256, secret, invitation, utf8('mousse-join-proof-v1'), 32);
  const input = encode(record([1, 'mousse-join-v1'], [2, invitation], [3, binding.host],
    [4, binding.joiner], [5, binding.exporter]));
  return { key, input, mac: hmac(sha256, key, input) };
}
export const bindingTranscript = (ticketHash: Uint8Array, kind: number, version: UInt, binding: PeerBinding) =>
  encode(record([1, 'mousse-pair-v1'], [2, ticketHash], [3, kind], [4, version],
    [5, [[1, binding.joiner], [2, binding.host]]], [6, binding.exporter]));
export function attemptSession(attempt: Uint8Array, exporter: Uint8Array) {
  const input = encode(record([1, 'mousse-pair-sid-v1'], [2, attempt], [3, exporter]));
  return { input, sid: sha256(input) };
}

export type Frame =
  | { type: 'data'; stream: number; payload: Uint8Array }
  | { type: 'open'; stream: number; class: 0 | 1; label: string }
  | { type: 'credit'; stream: number; increment: number }
  | { type: 'fin'; stream: number }
  | { type: 'reset'; stream: number; code: number }
  | { type: 'ping' | 'pong'; opaque: Uint8Array }
  | { type: 'control'; payload: Uint8Array }
  | { type: 'goaway'; code: number };

const frameTypes = ['data', 'open', 'credit', 'fin', 'reset', 'ping', 'pong', 'control', 'goaway'] as const;
export function decodeFrame(input: Uint8Array): { frame: Frame; read: number } {
  requireThat(input.length >= 9, 'need_more');
  const header = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const stream = header.getUint32(0);
  const type = frameTypes[header.getUint8(4)];
  const size = header.getUint32(5);
  requireThat(type, 'unknown_type');
  requireThat(size <= (type === 'control' ? 16384 : type === 'open' ? 256 : 65536), 'too_large');
  requireThat((stream !== 0) === (header.getUint8(4) < 5), 'bad_stream');
  requireThat(input.length >= 9 + size, 'need_more');
  const payload = Buffer.from(input.subarray(9, 9 + size));
  let frame: Frame;
  switch (type) {
    case 'data':
    case 'control':
      requireThat(size > 0, 'bad_payload');
      frame = type === 'data' ? { type, stream, payload } : { type, payload }; break;
    case 'open': {
      let value;
      try { value = decode(payload); }
      catch { return fail('bad_payload'); }
      requireThat(fields(value, 1, 2), 'bad_payload');
      const kind = value.get(1n);
      const label = value.get(2n);
      requireThat((kind === 0n || kind === 1n) && textString(label, 1, 64), 'bad_payload');
      frame = { type, stream, class: kind === 0n ? 0 : 1, label }; break;
    }
    case 'credit':
      requireThat(size === 4, 'bad_payload');
      frame = { type, stream, increment: payload.readUInt32BE() };
      requireThat(frame.increment > 0, 'bad_payload'); break;
    case 'fin':
      requireThat(size === 0, 'bad_payload');
      frame = { type, stream }; break;
    case 'reset':
    case 'goaway': {
      requireThat(size === 2, 'bad_payload');
      const code = wireError(payload.readUInt16BE());
      frame = type === 'reset' ? { type, stream, code } : { type, code }; break;
    }
    case 'ping':
    case 'pong':
      requireThat(size === 8, 'bad_payload');
      frame = { type, opaque: payload }; break;
  }
  return { frame, read: 9 + size };
}

export function encodeFrame(frame: Frame): Buffer {
  let payload: Uint8Array;
  switch (frame.type) {
    case 'data':
    case 'control': payload = frame.payload; break;
    case 'open': payload = encode(record([1, frame.class], [2, frame.label])); break;
    case 'credit': {
      const increment = Buffer.alloc(4);
      increment.writeUInt32BE(frame.increment);
      payload = increment; break;
    }
    case 'fin': payload = Buffer.alloc(0); break;
    case 'reset':
    case 'goaway': {
      const code = Buffer.alloc(2);
      code.writeUInt16BE(frame.code);
      payload = code; break;
    }
    case 'ping':
    case 'pong': payload = frame.opaque; break;
  }
  const header = Buffer.alloc(9);
  if ('stream' in frame) header.writeUInt32BE(frame.stream);
  header[4] = frameTypes.indexOf(frame.type);
  header.writeUInt32BE(payload.length, 5);
  const data = concat(header, payload);
  decodeFrame(data);
  return data;
}

export function frameResult(frame: Frame) {
  if (frame.type === 'data' || frame.type === 'control') return { ...frame, payload: hex(frame.payload) };
  if (frame.type === 'ping' || frame.type === 'pong') return { ...frame, opaque: hex(frame.opaque) };
  return frame;
}
