import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { byteString, bytes, concat, decode, encode, fail, fields, hex, record, requireThat, uint, utf8 } from './cbor.ts';
import type { Value } from './cbor.ts';
import { algorithm, checkRaw, der, DerReader, equalBytes, rawToDer, serialNumber, sha256, spkiPrefix, time,
  validPoint, verify, versionField } from './certificate.ts';
import { decodeBase64url, encodeFragment, routeHint } from './wire.ts';

// relay.md section 3: identifiers.
export const relayId = (relayKey: Uint8Array): Uint8Array => sha256(relayKey);
export const handleOf = (relay: Uint8Array, registrationKey: Uint8Array): Uint8Array =>
  sha256(concat(utf8('mousse-relay-handle-v1'), relay, registrationKey));
export const invitationTag = (invitation: Uint8Array, secret: Uint8Array): Uint8Array =>
  hkdf(sha256, secret, invitation, utf8('mousse-relay-invite-v1'), 32);

// relay.md section 5: proof records.
export const registerRecord = (relay: Uint8Array, handle: Uint8Array, nonce: Uint8Array, exporter: Uint8Array) =>
  encode(record([1, 'mousse-relay-register-v1'], [2, relay], [3, handle], [4, nonce], [5, exporter]));
export const successorRecord = (relay: Uint8Array, newHandle: Uint8Array, nonce: Uint8Array, exporter: Uint8Array) =>
  encode(record([1, 'mousse-relay-successor-v1'], [2, relay], [3, newHandle], [4, nonce], [5, exporter]));
export const callRecord = (relay: Uint8Array, handle: Uint8Array, nonce: Uint8Array, exporter: Uint8Array,
  callClass: bigint) =>
  encode(record([1, 'mousse-relay-call-v1'], [2, relay], [3, handle], [4, nonce], [5, exporter], [6, callClass]));
export const acceptRecord = (relay: Uint8Array, handle: Uint8Array, circuit: Uint8Array, nonce: Uint8Array,
  exporter: Uint8Array) =>
  encode(record([1, 'mousse-relay-accept-v1'], [2, relay], [3, handle], [4, circuit], [5, nonce], [6, exporter]));

// relay.md 2.1: the relay certificate and the native pin check.
const relayName = der(0x30, der(0x31, der(0x30, bytes('0603550403'), der(0x0c, utf8('mousse-relay')))));
export function relayTbs(relayKey: Uint8Array): Buffer {
  const spki = concat(spkiPrefix, relayKey);
  return der(0x30, versionField, der(2, serialNumber(spki)), algorithm, relayName,
    der(0x30, time(0), time(253402300799)), relayName, spki);
}
export function relayCertificate(relaySecret: Uint8Array): Buffer {
  const tbs = relayTbs(p256.getPublicKey(relaySecret, false));
  const signature = p256.sign(tbs, relaySecret, { prehash: true, lowS: false });
  return der(0x30, tbs, algorithm, der(3, Buffer.of(0), rawToDer(signature)));
}

// The native client reads the leaf's subjectPublicKeyInfo and judges nothing else in the certificate.
export function relayCertificateKey(certificate: Uint8Array): Uint8Array {
  const root = new DerReader(certificate, 'pin_mismatch');
  const tbs = root.nested(0x30).nested(0x30);
  if (tbs.peek() === 0xa0) tbs.read(0xa0);
  for (const tag of [0x02, 0x30, 0x30, 0x30, 0x30]) tbs.read(tag);
  const spki = tbs.read(0x30).encoded;
  requireThat(spki.length === 91 && equalBytes(spki.subarray(0, 26), spkiPrefix), 'pin_mismatch');
  const key = spki.subarray(26);
  requireThat(validPoint(key), 'pin_mismatch');
  return key;
}
export function relayPinKey(certificate: Uint8Array, pin: Uint8Array): Uint8Array {
  const key = relayCertificateKey(certificate);
  requireThat(equalBytes(sha256(key), pin), 'pin_mismatch');
  return key;
}

// relay.md section 11: enrollment links.
export type LinkHost = { ipv4: string } | { ipv6: string } | { dns: string };
export interface EnrollmentLink { host: LinkHost; port: number; relayId: Uint8Array; code: Uint8Array }

const linkScheme = 'mousse-relay://';
export function parseEnrollmentLink(text: string): EnrollmentLink {
  requireThat(text.startsWith(linkScheme), 'link');
  const rest = text.slice(linkScheme.length);
  const marker = rest.indexOf('/#');
  requireThat(marker > 0, 'link');
  const route = routeHint(`tcp://${rest.slice(0, marker)}`);
  requireThat('tcp' in route, 'link');
  const parts = rest.slice(marker + 2).split('.');
  requireThat(parts.length === 2, 'link');
  let id: Uint8Array, code: Uint8Array;
  try { [id, code] = parts.map(decodeBase64url); }
  catch { return fail('link'); }
  requireThat(id.length === 32 && code.length === 16, 'link');
  return { host: route.tcp.host, port: route.tcp.port, relayId: id, code };
}

// RFC 5952 text for 16 address bytes given as hex.
export function ipv6Text(addressHex: string): string {
  const groups = addressHex.match(/.{4}/g)!.map(group => parseInt(group, 16).toString(16));
  let best = { start: -1, length: 1 };
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > best.length) best = { start: i, length: j - i };
    i = j;
  }
  if (best.start < 0) return groups.join(':');
  return `${groups.slice(0, best.start).join(':')}::${groups.slice(best.start + best.length).join(':')}`;
}

export function hostText(host: LinkHost): string {
  if ('ipv6' in host) return `[${ipv6Text(host.ipv6)}]`;
  return 'ipv4' in host ? host.ipv4 : host.dns;
}

export function printEnrollmentLink(link: EnrollmentLink): string {
  const text = `${linkScheme}${hostText(link.host)}:${link.port}/#${encodeFragment(link.relayId)}.${encodeFragment(link.code)}`;
  parseEnrollmentLink(text);
  return text;
}

// relay.md section 4: messages.
export const relayTypes = [
  'RELAY_HELLO', 'REGISTER', 'ENROLL', 'REGISTERED', 'ALLOW_SET', 'ALLOW_SET_OK', 'CALL', 'JOIN', 'INCOMING',
  'ACCEPT', 'SPLICED', 'UNREACHABLE', 'PROMOTE', 'LEASE', 'LEASE_STATUS', 'REFUSED', 'ADMIT', 'SUCCESSOR', 'PING',
  'PONG', 'RELEASE',
] as const;
export type RelayType = typeof relayTypes[number];
const typeNumber = (type: RelayType) => BigInt(relayTypes.indexOf(type) + 1);

export const refusalReasons = ['not_authorized', 'enrollment', 'limit', 'admission', 'chain_full'] as const;
export type RefusalReason = typeof refusalReasons[number];

export interface Invitation { tagHash: Uint8Array; expiresAt: bigint }
export interface LeaseStatus { lease: Uint8Array; class: bigint; used: bigint; bytes: bigint; state: bigint }
export interface RelayMessage {
  type: RelayType;
  version?: bigint; nonce?: Uint8Array; bootId?: Uint8Array; mode?: bigint;
  key?: Uint8Array; proof?: Uint8Array; currentProof?: Uint8Array; token?: Uint8Array; threshold?: bigint;
  code?: Uint8Array; handle?: Uint8Array; sequence?: bigint; callers?: Uint8Array[]; invitations?: Invitation[];
  class?: bigint; tag?: Uint8Array; circuit?: Uint8Array; kind?: bigint; fingerprint?: Uint8Array;
  block?: Uint8Array; leases?: LeaseStatus[]; reason?: RefusalReason; opaque?: Uint8Array; leaseIds?: Uint8Array[];
  successorOverlap?: bigint;
}
type FieldName = Exclude<keyof RelayMessage, 'type'>;

type Rule = (value: Value) => boolean;
const sized = (size: number): Rule => value => byteString(value, size);
const opaque: Rule = value => value instanceof Uint8Array;
const among = (...allowed: bigint[]): Rule => value => uint(value) && allowed.includes(BigInt(value));
const key: Rule = value => byteString(value, 65) && validPoint(value);
const proof: Rule = value => {
  if (!byteString(value, 64)) return false;
  try { checkRaw(value); return true; }
  catch { return false; }
};
const distinct = (items: Uint8Array[]) => new Set(items.map(hex)).size === items.length;
const callers: Rule = value => Array.isArray(value) && value.length <= 256 &&
  value.every(item => byteString(item, 32)) && distinct(value as Uint8Array[]);
const invitations: Rule = value => Array.isArray(value) && value.length <= 8 &&
  value.every(item => fields(item, 1, 2) && byteString(item.get(1n), 32) && uint(item.get(2n))) &&
  distinct(value.map(item => (item as Map<bigint, Value>).get(1n) as Uint8Array));
const leases: Rule = value => Array.isArray(value) && value.every(item => fields(item, 1, 2, 3, 4, 5) &&
  byteString(item.get(1n), 16) && among(0n, 1n)(item.get(2n)!) && uint(item.get(3n)) && uint(item.get(4n)) &&
  among(0n, 1n, 2n, 3n)(item.get(5n)!));
const leaseIds: Rule = value => Array.isArray(value) && value.length >= 1 && value.length <= 4 &&
  value.every(item => byteString(item, 16));
const reason: Rule = value => typeof value === 'string' && (refusalReasons as readonly string[]).includes(value);
const anyUint: Rule = value => uint(value);

type Schema = [key: number, name: FieldName, rule: Rule, optional?: boolean][];
const schemas: Record<RelayType, Schema> = {
  RELAY_HELLO: [[1, 'version', among(1n)], [2, 'nonce', sized(32)], [3, 'bootId', sized(16)], [4, 'mode', among(0n, 1n)]],
  REGISTER: [[1, 'key', key], [2, 'proof', proof], [3, 'token', opaque, true],
    [4, 'threshold', value => uint(value) && value >= 10 && value <= 90, true]],
  ENROLL: [[1, 'key', key], [2, 'proof', proof], [3, 'code', sized(16)]],
  REGISTERED: [[1, 'handle', sized(32)], [2, 'successorOverlap', anyUint, true]],
  ALLOW_SET: [[1, 'sequence', anyUint], [2, 'callers', callers], [3, 'invitations', invitations]],
  ALLOW_SET_OK: [[1, 'sequence', anyUint]],
  CALL: [[1, 'handle', sized(32)], [2, 'key', key], [3, 'proof', proof], [4, 'class', among(0n, 1n)]],
  JOIN: [[1, 'handle', sized(32)], [2, 'tag', sized(32)]],
  INCOMING: [[1, 'circuit', sized(16)], [2, 'kind', among(0n, 1n)], [3, 'class', among(0n, 1n)],
    [4, 'fingerprint', sized(32), true]],
  ACCEPT: [[1, 'handle', sized(32)], [2, 'circuit', sized(16)], [3, 'proof', proof]],
  SPLICED: [],
  UNREACHABLE: [],
  PROMOTE: [[1, 'circuit', sized(16)], [2, 'fingerprint', sized(32)]],
  LEASE: [[1, 'block', opaque]],
  LEASE_STATUS: [[1, 'leases', leases]],
  REFUSED: [[1, 'reason', reason]],
  ADMIT: [[1, 'token', opaque]],
  SUCCESSOR: [[1, 'key', key], [2, 'proof', proof], [3, 'currentProof', proof]],
  PING: [[1, 'opaque', sized(8)]],
  PONG: [[1, 'opaque', sized(8)]],
  RELEASE: [[1, 'leaseIds', leaseIds]],
};

export const RELAY_MESSAGE_MAX = 16384;

function readField(name: FieldName, value: Value): unknown {
  if (name === 'invitations') {
    return (value as Map<bigint, Value>[]).map(item => ({ tagHash: item.get(1n), expiresAt: item.get(2n) }));
  }
  if (name === 'leases') {
    return (value as Map<bigint, Value>[]).map(item =>
      ({ lease: item.get(1n), class: item.get(2n), used: item.get(3n), bytes: item.get(4n), state: item.get(5n) }));
  }
  return value;
}

function writeField(name: FieldName, value: unknown): Value {
  if (name === 'invitations') {
    return (value as Invitation[]).map(item => record([1, item.tagHash], [2, item.expiresAt]));
  }
  if (name === 'leases') {
    return (value as LeaseStatus[]).map(item =>
      record([1, item.lease], [2, item.class], [3, item.used], [4, item.bytes], [5, item.state]));
  }
  return value as Value;
}

function decodeRelayRecord(value: Value): RelayMessage {
  requireThat(value instanceof Map, 'malformed');
  const number = value.get(0n);
  requireThat(typeof number === 'bigint' && number >= 1n && number <= BigInt(relayTypes.length), 'malformed');
  const type = relayTypes[Number(number) - 1];
  const message: RelayMessage = { type };
  let seen = 1;
  for (const [k, name, rule, optional] of schemas[type]) {
    const field = value.get(BigInt(k));
    if (field === undefined) {
      requireThat(optional, 'malformed');
      continue;
    }
    requireThat(rule(field), 'malformed');
    (message as unknown as Record<string, unknown>)[name] = readField(name, field);
    seen++;
  }
  requireThat(value.size === seen, 'malformed');
  if (type === 'REGISTER') requireThat((message.token === undefined) === (message.threshold === undefined), 'malformed');
  if (type === 'INCOMING') requireThat((message.fingerprint !== undefined) === (message.kind === 0n), 'malformed');
  return message;
}

export function decodeRelay(data: Uint8Array): RelayMessage {
  requireThat(data.length <= RELAY_MESSAGE_MAX, 'malformed');
  let value: Value;
  try { value = decode(data); }
  catch { return fail('malformed'); }
  return decodeRelayRecord(value);
}

export function encodeRelay(message: RelayMessage): Buffer {
  const entries: [number, Value][] = [[0, typeNumber(message.type)]];
  for (const [k, name] of schemas[message.type]) {
    const value = message[name];
    if (value !== undefined) entries.push([k, writeField(name, value)]);
  }
  const data = encode(record(...entries));
  decodeRelay(data);
  return data;
}

const clientToRelay = new Set<RelayType>(['REGISTER', 'ENROLL', 'ALLOW_SET', 'CALL', 'JOIN', 'ACCEPT', 'PROMOTE',
  'LEASE', 'ADMIT', 'SUCCESSOR', 'PING', 'PONG', 'RELEASE']);
const registrationTypes = new Set<RelayType>(['ALLOW_SET', 'PROMOTE', 'SUCCESSOR', 'PING', 'PONG']);

// relay.md sections 6-14: a self-mode relay driven by the replay model of section 14.
export const relayDefaults = {
  RELAY_HELLO_WAIT_MS: 5000,
  RELAY_REFUSE_MS: 500,
  RELAY_ACCEPT_WAIT_MS: 10000,
  RELAY_REGISTRATION_IDLE_MS: 45000,
  RELAY_KEEPALIVE_MS: 15000,
  RELAY_CIRCUIT_IDLE_MS: 60000,
  RELAY_PREACCEPT_BYTES: 65536,
  RELAY_PREACCEPT_PER_TARGET: 4,
  RELAY_SUCCESSOR_OVERLAP_SECS: 604800,
  RELAY_CHAIN_KEYS_MAX: 4,
  RELAY_MAX_CONNECTIONS: 1024,
  RELAY_CONNECTIONS_PER_IP: 256,
  RELAY_ACCEPT_LEGS_PER_HANDLE: 64,
  RELAY_CIRCUITS_PER_CALLER: 8,
  RELAY_MAX_REGISTRATIONS: 1024,
};
export type RelayLimits = typeof relayDefaults;

export type RelayOutput =
  | { send: number; message: RelayType; hex: string }
  | { close: number; code: number }
  | { splice: [number, number]; circuit: string; class: number }
  | { forward: [number, number]; len: number }
  | { authorize: string; chain: string }
  | { supersede: string; drop_at: number }
  | { drop: string }
  | { consume_code: string };

export type RelayEvent =
  | { event: 'open'; at: number; conn: number; ip: string; exporter: Uint8Array }
  | { event: 'recv'; at: number; conn: number; data: Uint8Array }
  | { event: 'data'; at: number; conn: number; len: number }
  | { event: 'closed'; at: number; conn: number }
  | { event: 'tick'; at: number }
  | { event: 'revoke'; at: number; fingerprint: Uint8Array };

export interface RelaySetup {
  relayKey: Uint8Array;
  bootId: Uint8Array;
  wallBase: number;
  authorized: { fingerprint: Uint8Array; dropAt?: number; chain?: Uint8Array }[];
  codes: { hash: Uint8Array; expiresAt: number }[];
  limits?: Partial<RelayLimits>;
  draw: (size: number) => Uint8Array;
}

interface AllowSet { sequence: bigint; callers: Set<string>; invitations: Map<string, bigint> }
interface Registration { handle: string; key: Uint8Array; conn: Conn; allow?: AllowSet }
interface Conn {
  id: number;
  ip: string;
  exporter: Uint8Array;
  nonce: Uint8Array;
  open: boolean;
  role: 'new' | 'registration' | 'call' | 'join' | 'accept';
  accepted: boolean;
  helloAt?: number;
  refuseAt?: number;
  idleAt?: number;
  keepaliveAt?: number;
  registration?: Registration;
  circuit?: Circuit;
}
interface Circuit {
  id: Uint8Array;
  handle: string;
  key: Uint8Array;
  kind: 'call' | 'join';
  class: number;
  caller: Conn;
  accept?: Conn;
  fingerprint?: string;
  promoted: boolean;
  ended: boolean;
  acceptAt?: number;
  idleAt?: number;
  expiresAt?: bigint;
  sent: [number, number];
}
interface Wait { at: number; row: number; order: number; fire: () => void }

export class SelfRelay {
  readonly relayKey: Uint8Array;
  readonly relayId: Uint8Array;
  readonly bootId: Uint8Array;
  readonly limits: RelayLimits;
  // Each key's SUCCESSOR chain: the fingerprint it started from (section 7.4).
  readonly authorized = new Map<string, { dropAt?: number; chain: string }>();
  readonly codes = new Map<string, number>();
  private readonly wallBase: number;
  private readonly draw: (size: number) => Uint8Array;
  private readonly conns = new Map<number, Conn>();
  private readonly registrations = new Map<string, Registration>();
  private circuits: Circuit[] = [];
  private out: RelayOutput[] = [];
  private now = 0;

  constructor(setup: RelaySetup) {
    requireThat(validPoint(setup.relayKey), 'relay_key');
    this.relayKey = setup.relayKey;
    this.relayId = relayId(setup.relayKey);
    this.bootId = setup.bootId;
    this.wallBase = setup.wallBase;
    this.draw = setup.draw;
    this.limits = { ...relayDefaults, ...setup.limits };
    for (const entry of setup.authorized) {
      const fingerprint = hex(entry.fingerprint);
      this.authorized.set(fingerprint, { dropAt: entry.dropAt, chain: entry.chain ? hex(entry.chain) : fingerprint });
    }
    for (const code of setup.codes) this.codes.set(hex(code.hash), code.expiresAt);
  }

  private wall(at = this.now) { return this.wallBase + Math.floor(at / 1000); }

  handle(event: RelayEvent): RelayOutput[] {
    this.out = [];
    this.fireDue(event.at);
    this.now = event.at;
    switch (event.event) {
      case 'open': this.opened(event.conn, event.ip, event.exporter); break;
      case 'recv': this.received(event.conn, event.data); break;
      case 'data': this.peerData(event.conn, event.len); break;
      case 'closed': {
        const conn = this.conns.get(event.conn);
        if (conn?.open) { conn.open = false; this.afterClose(conn); }
        break;
      }
      case 'revoke': {
        // The whole chain of the revoked key, in fingerprint order.
        const fingerprint = hex(event.fingerprint);
        const chain = this.authorized.get(fingerprint)?.chain ?? fingerprint;
        const gone = new Set([fingerprint, ...this.chainMembers(chain)]);
        for (const member of [...gone].sort()) {
          this.authorized.delete(member);
          this.closeKey(member);
        }
        break;
      }
      case 'tick': break;
    }
    return this.out;
  }

  // Section 6: monotonic waits in time, row and connection order; then wall-clock times.
  private dueWaits(): Wait[] {
    const waits: Wait[] = [];
    for (const conn of this.conns.values()) {
      if (!conn.open) continue;
      if (conn.helloAt !== undefined) waits.push({ at: conn.helloAt, row: 0, order: conn.id, fire: () => this.close(conn, 4002) });
      if (conn.refuseAt !== undefined) waits.push({ at: conn.refuseAt, row: 1, order: conn.id, fire: () => {
        this.send(conn, { type: 'UNREACHABLE' });
        this.close(conn, 1000);
      } });
      if (conn.idleAt !== undefined) waits.push({ at: conn.idleAt, row: 3, order: conn.id, fire: () => this.close(conn, 4002) });
      if (conn.keepaliveAt !== undefined) waits.push({ at: conn.keepaliveAt, row: 4, order: conn.id, fire: () =>
        this.send(conn, { type: 'PING', opaque: this.take(8) }) });
    }
    for (const circuit of this.circuits) {
      if (circuit.acceptAt !== undefined) waits.push({ at: circuit.acceptAt, row: 2, order: circuit.caller.id, fire: () => {
        this.endCircuit(circuit);
        this.send(circuit.caller, { type: 'UNREACHABLE' });
        this.close(circuit.caller, 1000);
      } });
      if (circuit.idleAt !== undefined) {
        waits.push({ at: circuit.idleAt, row: 5, order: circuit.caller.id, fire: () => this.closeCircuit(circuit, 4002) });
      }
    }
    return waits;
  }

  private fireDue(at: number) {
    for (;;) {
      const next = this.dueWaits().filter(wait => wait.at <= at)
        .sort((a, b) => a.at - b.at || a.row - b.row || a.order - b.order)[0];
      if (!next) break;
      this.now = next.at;
      next.fire();
    }
    this.now = at;
    const wall = BigInt(this.wall(at));
    const expired = this.circuits.filter(c => c.expiresAt !== undefined && !c.promoted && c.expiresAt <= wall)
      .sort((a, b) => a.caller.id - b.caller.id);
    for (const circuit of expired) this.closeCircuit(circuit, 4006);
    const drops = [...this.authorized].filter(([, entry]) => entry.dropAt !== undefined && entry.dropAt <= wall)
      .map(([fingerprint]) => fingerprint).sort();
    for (const fingerprint of drops) {
      this.authorized.delete(fingerprint);
      this.out.push({ drop: fingerprint });
      this.closeKey(fingerprint);
    }
  }

  private chainMembers(chain: string): string[] {
    return [...this.authorized].filter(([, entry]) => entry.chain === chain).map(([fingerprint]) => fingerprint);
  }

  private take(size: number): Uint8Array {
    const value = this.draw(size);
    requireThat(value.length === size, 'draw_size');
    return value;
  }

  private send(conn: Conn, message: RelayMessage) {
    if (!conn.open) return;
    this.out.push({ send: conn.id, message: message.type, hex: hex(encodeRelay(message)) });
    if (conn.role === 'registration') conn.keepaliveAt = this.now + this.limits.RELAY_KEEPALIVE_MS;
  }

  private close(conn: Conn, code: number) {
    if (!conn.open) return;
    this.out.push({ close: conn.id, code });
    conn.open = false;
    this.afterClose(conn);
  }

  // Section 10.3: what a closed connection ends.
  private afterClose(conn: Conn) {
    const registration = conn.registration;
    if (registration && this.registrations.get(registration.handle) === registration) {
      this.registrations.delete(registration.handle);
    }
    const circuit = conn.circuit;
    if (circuit && !circuit.ended) {
      this.endCircuit(circuit);
      const other = conn === circuit.caller ? circuit.accept : circuit.caller;
      if (other) this.close(other, 1000);
    }
  }

  private endCircuit(circuit: Circuit) {
    circuit.ended = true;
    this.circuits = this.circuits.filter(c => c !== circuit);
  }

  private closeCircuit(circuit: Circuit, code: number) {
    this.endCircuit(circuit);
    this.close(circuit.caller, code);
    if (circuit.accept) this.close(circuit.accept, code);
  }

  private circuitsOf(handle: string) {
    return this.circuits.filter(c => c.handle === handle).sort((a, b) => a.caller.id - b.caller.id);
  }

  // A revoked or dropped key: its registration, then every circuit of its handle, with 4000.
  private closeKey(fingerprint: string) {
    for (const registration of [...this.registrations.values()]) {
      if (hex(sha256(registration.key)) === fingerprint) this.close(registration.conn, 4000);
    }
    for (const circuit of this.circuits.filter(c => hex(sha256(c.key)) === fingerprint)
      .sort((a, b) => a.caller.id - b.caller.id)) this.closeCircuit(circuit, 4000);
  }

  private opened(id: number, ip: string, exporter: Uint8Array) {
    // Section 13: every open connection counts; an accepted accept leg leaves its address key's count.
    const open = [...this.conns.values()].filter(c => c.open);
    const sameAddress = open.filter(c => c.ip === ip && !c.accepted).length;
    const conn: Conn = { id, ip, exporter, nonce: new Uint8Array(), open: true, role: 'new', accepted: false };
    this.conns.set(id, conn);
    if (open.length >= this.limits.RELAY_MAX_CONNECTIONS || sameAddress >= this.limits.RELAY_CONNECTIONS_PER_IP) {
      this.close(conn, 4006);
      return;
    }
    conn.nonce = this.take(32);
    conn.helloAt = this.now + this.limits.RELAY_HELLO_WAIT_MS;
    this.send(conn, { type: 'RELAY_HELLO', version: 1n, nonce: conn.nonce, bootId: this.bootId, mode: 0n });
  }

  private protocolError(conn: Conn) { this.close(conn, 1002); }

  private refuse(conn: Conn, reason: RefusalReason) {
    this.send(conn, { type: 'REFUSED', reason });
    this.close(conn, 1000);
  }

  private received(id: number, data: Uint8Array) {
    const conn = this.conns.get(id);
    if (!conn?.open) return;
    if (conn.circuit?.accept && !conn.circuit.ended) return this.peerData(id, data.length);
    let message: RelayMessage;
    try { message = decodeRelay(data); }
    catch { return this.protocolError(conn); }
    if (!clientToRelay.has(message.type)) return this.protocolError(conn);
    if (conn.role === 'new') {
      conn.helloAt = undefined;
      switch (message.type) {
        case 'REGISTER':
          if (message.token !== undefined) return this.protocolError(conn);
          return this.register(conn, message);
        case 'ENROLL': return this.enroll(conn, message);
        case 'CALL': return this.call(conn, message);
        case 'JOIN': return this.join(conn, message);
        case 'ACCEPT': return this.accept(conn, message);
        default: return this.protocolError(conn);
      }
    }
    if (conn.role !== 'registration' || !registrationTypes.has(message.type)) return this.protocolError(conn);
    conn.idleAt = this.now + this.limits.RELAY_REGISTRATION_IDLE_MS;
    const registration = conn.registration!;
    switch (message.type) {
      case 'ALLOW_SET': return this.allowSet(registration, message);
      case 'PROMOTE': return this.promote(registration, message);
      case 'SUCCESSOR': return this.successor(conn, registration, message);
      case 'PING': return this.send(conn, { type: 'PONG', opaque: message.opaque });
      default: return;
    }
  }

  private isAuthorized(fingerprint: string) {
    const entry = this.authorized.get(fingerprint);
    return entry !== undefined && (entry.dropAt === undefined || this.wall() < entry.dropAt);
  }

  private liveRegistrationsBesides(handle: string) {
    return [...this.registrations.keys()].filter(other => other !== handle).length;
  }

  private proved(conn: Conn, message: RelayMessage) {
    const handle = handleOf(this.relayId, message.key!);
    const ok = verify(message.proof!, registerRecord(this.relayId, handle, conn.nonce, conn.exporter), message.key!);
    return { handle, ok };
  }

  // Section 7.1.
  private register(conn: Conn, message: RelayMessage) {
    const { handle, ok } = this.proved(conn, message);
    if (!ok || !this.isAuthorized(hex(sha256(message.key!)))) return this.refuse(conn, 'not_authorized');
    if (this.liveRegistrationsBesides(hex(handle)) >= this.limits.RELAY_MAX_REGISTRATIONS) {
      return this.refuse(conn, 'limit');
    }
    this.becomeRegistration(conn, handle, message.key!);
  }

  // Section 11.
  private enroll(conn: Conn, message: RelayMessage) {
    const { handle, ok } = this.proved(conn, message);
    if (!ok) return this.refuse(conn, 'not_authorized');
    const codeHash = hex(sha256(message.code!));
    const expiresAt = this.codes.get(codeHash);
    if (expiresAt === undefined || !(expiresAt > this.wall())) return this.refuse(conn, 'enrollment');
    if (this.liveRegistrationsBesides(hex(handle)) >= this.limits.RELAY_MAX_REGISTRATIONS) {
      return this.refuse(conn, 'limit');
    }
    this.codes.delete(codeHash);
    this.out.push({ consume_code: codeHash });
    const fingerprint = hex(sha256(message.key!));
    this.authorized.set(fingerprint, { chain: fingerprint });
    this.out.push({ authorize: fingerprint, chain: fingerprint });
    this.becomeRegistration(conn, handle, message.key!);
  }

  private becomeRegistration(conn: Conn, handle: Uint8Array, key: Uint8Array) {
    const previous = this.registrations.get(hex(handle));
    if (previous) this.close(previous.conn, 4005);
    const registration: Registration = { handle: hex(handle), key, conn };
    this.registrations.set(registration.handle, registration);
    conn.role = 'registration';
    conn.registration = registration;
    conn.idleAt = this.now + this.limits.RELAY_REGISTRATION_IDLE_MS;
    // Self mode: REGISTERED carries RELAY_SUCCESSOR_OVERLAP_SECS.
    this.send(conn, { type: 'REGISTERED', handle, successorOverlap: BigInt(this.limits.RELAY_SUCCESSOR_OVERLAP_SECS) });
  }

  // Section 7.4.
  private successor(conn: Conn, registration: Registration, message: RelayMessage) {
    const newKey = message.key!;
    const signed = successorRecord(this.relayId, handleOf(this.relayId, newKey), conn.nonce, conn.exporter);
    const current = this.authorized.get(hex(sha256(registration.key)));
    // A chain holds at most RELAY_CHAIN_KEYS_MAX keys at once.
    const room = current !== undefined && this.chainMembers(current.chain).length < this.limits.RELAY_CHAIN_KEYS_MAX;
    if (!verify(message.proof!, signed, newKey) || !verify(message.currentProof!, signed, registration.key) ||
        !current || current.dropAt !== undefined || this.authorized.has(hex(sha256(newKey)))) {
      return this.refuse(conn, 'not_authorized');
    }
    // A full chain keeps the registration open.
    if (!room) return this.send(conn, { type: 'REFUSED', reason: 'chain_full' });
    const fingerprint = hex(sha256(newKey));
    this.authorized.set(fingerprint, { chain: current.chain });
    this.out.push({ authorize: fingerprint, chain: current.chain });
    current.dropAt = this.wall() + this.limits.RELAY_SUCCESSOR_OVERLAP_SECS;
    this.out.push({ supersede: hex(sha256(registration.key)), drop_at: current.dropAt });
  }

  // Section 8.
  private allowSet(registration: Registration, message: RelayMessage) {
    if (registration.allow && message.sequence! <= registration.allow.sequence) return;
    const allow: AllowSet = {
      sequence: message.sequence!,
      callers: new Set(message.callers!.map(hex)),
      invitations: new Map(message.invitations!.map(item => [hex(item.tagHash), item.expiresAt])),
    };
    for (const circuit of this.circuitsOf(registration.handle)) {
      if ((circuit.kind === 'call' || circuit.promoted) && !allow.callers.has(circuit.fingerprint!)) {
        this.closeCircuit(circuit, 4000);
      }
    }
    registration.allow = allow;
    this.send(registration.conn, { type: 'ALLOW_SET_OK', sequence: allow.sequence });
  }

  // Section 9.4.
  private promote(registration: Registration, message: RelayMessage) {
    const fingerprint = hex(message.fingerprint!);
    const circuit = this.circuits.find(c => equalBytes(c.id, message.circuit!) && c.handle === registration.handle &&
      c.kind === 'join' && c.accept && !c.promoted);
    if (!circuit || !registration.allow?.callers.has(fingerprint)) return;
    circuit.promoted = true;
    circuit.fingerprint = fingerprint;
  }

  private isCallerCircuit(circuit: Circuit) { return circuit.kind === 'call' || circuit.promoted; }

  private admit(conn: Conn, registration: Registration, circuit: Omit<Circuit, 'id' | 'caller' | 'ended' | 'sent' | 'promoted'>) {
    const admitted: Circuit = { ...circuit, id: this.take(16), caller: conn, promoted: false, ended: false, sent: [0, 0],
      acceptAt: this.now + this.limits.RELAY_ACCEPT_WAIT_MS };
    this.circuits.push(admitted);
    conn.circuit = admitted;
    this.send(registration.conn, admitted.kind === 'call'
      ? { type: 'INCOMING', circuit: admitted.id, kind: 0n, class: BigInt(admitted.class), fingerprint: bytes(admitted.fingerprint!) }
      : { type: 'INCOMING', circuit: admitted.id, kind: 1n, class: 0n });
  }

  // Section 9.1.
  private call(conn: Conn, message: RelayMessage) {
    conn.role = 'call';
    const deadline = this.now + this.limits.RELAY_REFUSE_MS;
    const handle = hex(message.handle!);
    const fingerprint = hex(sha256(message.key!));
    const registration = this.registrations.get(handle);
    const proofOk = verify(message.proof!, callRecord(this.relayId, message.handle!, conn.nonce, conn.exporter,
      message.class!), message.key!);
    const open = this.circuits.filter(c => c.handle === handle && this.isCallerCircuit(c) && c.fingerprint === fingerprint);
    // Must-fail control (MOUSSE_SECOND_BREAK=relay-allow-set): any caller of a
    // handle with an allow-set is admitted.
    const listed = process.env.MOUSSE_SECOND_BREAK === 'relay-allow-set' || registration?.allow?.callers.has(fingerprint);
    if (!proofOk || !registration?.allow || !listed ||
        open.length >= this.limits.RELAY_CIRCUITS_PER_CALLER) {
      conn.refuseAt = deadline;
      return;
    }
    this.admit(conn, registration, { handle, key: registration.key, kind: 'call', class: Number(message.class), fingerprint });
  }

  // Section 9.2.
  private join(conn: Conn, message: RelayMessage) {
    conn.role = 'join';
    const deadline = this.now + this.limits.RELAY_REFUSE_MS;
    const handle = hex(message.handle!);
    const registration = this.registrations.get(handle);
    const expiresAt = registration?.allow?.invitations.get(hex(sha256(message.tag!)));
    const joins = this.circuits.filter(c => c.handle === handle && c.kind === 'join' && !c.promoted);
    if (!registration?.allow || expiresAt === undefined || !(expiresAt > BigInt(this.wall())) ||
        joins.length >= this.limits.RELAY_PREACCEPT_PER_TARGET) {
      conn.refuseAt = deadline;
      return;
    }
    this.admit(conn, registration, { handle, key: registration.key, kind: 'join', class: 0, expiresAt });
  }

  // Section 10.1.
  private accept(conn: Conn, message: RelayMessage) {
    conn.role = 'accept';
    const handle = hex(message.handle!);
    const circuit = this.circuits.find(c => c.handle === handle && equalBytes(c.id, message.circuit!) && !c.accept);
    if (!circuit || !verify(message.proof!, acceptRecord(this.relayId, message.handle!, message.circuit!, conn.nonce,
      conn.exporter), circuit.key)) return this.refuse(conn, 'not_authorized');
    const legs = this.circuits.filter(c => c.handle === handle && c.accept).length;
    if (legs >= this.limits.RELAY_ACCEPT_LEGS_PER_HANDLE) return this.refuse(conn, 'limit');
    circuit.accept = conn;
    circuit.acceptAt = undefined;
    conn.accepted = true;
    conn.circuit = circuit;
    this.send(circuit.caller, { type: 'SPLICED' });
    this.send(conn, { type: 'SPLICED' });
    this.out.push({ splice: [circuit.caller.id, conn.id], circuit: hex(circuit.id), class: circuit.class });
    circuit.idleAt = this.now + this.limits.RELAY_CIRCUIT_IDLE_MS;
  }

  // Sections 9.3 and 10.2.
  private peerData(id: number, len: number) {
    const conn = this.conns.get(id);
    if (!conn?.open) return;
    const circuit = conn.circuit;
    if (!circuit || circuit.ended || !circuit.accept) return this.protocolError(conn);
    const direction = conn === circuit.caller ? 0 : 1;
    const to = direction === 0 ? circuit.accept : circuit.caller;
    if (circuit.kind === 'join' && !circuit.promoted &&
        circuit.sent[direction] + len > this.limits.RELAY_PREACCEPT_BYTES) {
      return this.closeCircuit(circuit, 4006);
    }
    circuit.sent[direction] += len;
    this.out.push({ forward: [conn.id, to.id], len });
    circuit.idleAt = this.now + this.limits.RELAY_CIRCUIT_IDLE_MS;
  }
}
