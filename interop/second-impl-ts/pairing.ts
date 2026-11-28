import { equalBytes, sha256 } from './certificate.ts';
import { byteString, decode, encode, fields, hex, record, requireThat, uint, utf8 } from './cbor.ts';
import { initiate, respond } from './cpace.ts';
import { Gate, step2, Streams } from './session.ts';
import type { Grant, Traffic } from './session.ts';
import { attemptSession, bindingTranscript, checkJoinerExpiry, decodeTicket, encodeTicket, errorNumber, hello, joinProof } from './wire.ts';
import type { Control, ErrorName, Ticket } from './wire.ts';

export interface RandomDraws {
  bytes(length: number, purpose: string): Uint8Array;
  u32(purpose: string): number;
}

interface Exporters { join: Uint8Array; pair: Uint8Array }
interface Endpoint { identity: Uint8Array; name: string }
interface InvitationPolicy { authorizingOwner: string; grantExpiresAt: number | null; role: string; routes: string[] }

export type Effect =
  | { send: Control; conn: number }
  | { close: ErrorName; conn: number }
  | { version: number }
  | { show_code: string }
  | { ask_approval: { conn: number; name: string } }
  | { admitted_join_only: number }
  | { enrolled: { conn: number } }
  | { role_set: { changed: boolean; role: string } }
  | { invitation_ended: ErrorName }
  | { paired: { host_identity: string; host_name: string; role: string } }
  | { already_paired: true }
  | { code_rejected: { attempts_left: number } }
  | { failed: ErrorName }
  | { attempt: { id: string; ci: string; sid: string } }
  | { persist: { expected: string | null; record: string } }
  | { error: string }
  | { ignored: true };

function send(conn: number, message: Control): Effect { return { conn, send: message }; }
function close(conn: number, gate: Gate, code: ErrorName): Effect {
  gate.close(code);
  return { conn, close: code };
}

/** The gate class of a control message received from the peer. */
export function trafficOf(message: Control): Traffic {
  switch (message.type) {
    case 'HELLO': return 'hello';
    case 'AUTHORIZED': return message.state === 'live' ? 'authorized_live' : 'authorized_join_only';
    case 'JOIN_PROOF': return 'join_proof';
    case 'JOIN_DIRECT': return 'join_direct';
    case 'CODE_EXCHANGE':
    case 'CODE_ABORT': return 'pairing';
    case 'PAIRED': return 'paired';
  }
}

function checked(gate: Gate, conn: number, msg: Control): Effect[] | undefined {
  const verdict = gate.check(trafficOf(msg));
  if (verdict === 'allow') return;
  if (verdict === 'ignore') return [{ ignored: true }];
  return [{ conn, close: verdict.slice(6) as ErrorName }];
}

function receiveHello(gate: Gate, conn: number, message: Extract<Control, { type: 'HELLO' }>): Effect[] {
  const result = gate.receiveHello(message);
  if (result === 'ignored') return [{ ignored: true }];
  if (result === 'close:unsupported_version') return [{ conn, close: 'unsupported_version' }];
  return [{ version: Number(result) }];
}

function drawCode(random: RandomDraws, purpose: string): string {
  let value;
  do {
    value = random.u32(purpose);
    requireThat(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, 'BadRandomDraw');
  } while (value >= 4294000000);
  return String(value % 1000000).padStart(6, '0');
}

function proof(ticket: Ticket, joiner: Uint8Array, exporter: Uint8Array) {
  const result = joinProof(ticket.invitation, ticket.secret, { host: ticket.hostIdentity, joiner, exporter });
  result.key.fill(0);
  return result.mac;
}

function cpaceInputs(ticket: Ticket, binary: Uint8Array, joiner: Uint8Array, pair: Uint8Array,
  attempt: Uint8Array, code: string) {
  requireThat(code.length === 6 && /^[0-9]{6}$/.test(code), 'invalid_code');
  const ci = bindingTranscript(sha256(binary), ticket.kind, ticket.version,
    { host: ticket.hostIdentity, joiner, exporter: pair });
  const { sid } = attemptSession(attempt, pair);
  return { ci, sid, prs: utf8(code), ad: new Uint8Array(), requireEmptyPeerAd: true };
}

function exchange(conn: number, attempt: Uint8Array, payload: Uint8Array): Effect {
  return send(conn, { type: 'CODE_EXCHANGE', attempt, payload });
}
function abort(conn: number, attempt: Uint8Array): Effect {
  return send(conn, { type: 'CODE_ABORT', attempt, code: errorNumber('pairing_failed') });
}

interface HostConnection {
  gate: Gate;
  streams: Streams;
  peer: Uint8Array;
  exporters: Exporters;
  attempts: Map<string, ReturnType<typeof respond> | undefined>;
  name?: string;
}

interface Enrollment extends Grant {
  authorizing_owner: string;
  bound_connections: number[];
  granted_at: number;
  name: string;
}

interface HostGrantStore {
  get(identity: string): Enrollment | undefined;
  values(): Iterable<Enrollment>;
  // A persistent implementation commits the complete grant, including its receipt, in this call.
  set(identity: string, enrollment: Enrollment): void;
}

export class PairingHost {
  readonly ticket: Ticket;
  readonly binary: Buffer;
  readonly grants: HostGrantStore;
  readonly denials = new Set<string>();
  private readonly connections = new Map<number, HostConnection>();
  attemptsLeft = 3;
  status: 'open' | 'consumed' | `ended:${ErrorName}` = 'open';
  shownCode: string | null;

  private readonly endpoint: Endpoint;
  private readonly policy: InvitationPolicy;
  private readonly random: RandomDraws;
  constructor(endpoint: Endpoint, policy: InvitationPolicy, kind: 1 | 2, random: RandomDraws, now: number,
    grants: HostGrantStore = new Map()) {
    this.endpoint = endpoint;
    this.policy = policy;
    this.random = random;
    this.grants = grants;
    this.ticket = { version: 1, kind, hostIdentity: endpoint.identity,
      invitation: random.bytes(16, 'invitation_id'), secret: random.bytes(16, 'ticket_secret'),
      expiresAt: now + 600, routes: policy.routes };
    this.binary = encodeTicket(this.ticket);
    this.shownCode = kind === 2 ? drawCode(random, 'code') : null;
  }

  connect(conn: number, peer: Uint8Array, exporters: Exporters, now: number, mono = 0): Effect[] {
    requireThat(!this.connections.has(conn), 'connection_reused');
    const identity = hex(peer);
    const decision = step2(identity, this.grants.values(), this.denials, now);
    const gate = new Gate('host', decision, mono);
    this.connections.set(conn, { gate, streams: new Streams('host', gate), peer, exporters, attempts: new Map() });
    const output = [send(conn, hello)];
    if (decision === 'close:not_authorized') output.push(close(conn, gate, 'not_authorized'));
    if (decision === 'live') {
      this.grants.get(identity)!.bound_connections.push(conn);
      output.push(send(conn, { type: 'AUTHORIZED', state: 'live' }));
    }
    return output;
  }

  streams(conn: number) { return this.connections.get(conn)?.streams; }

  private stopAttempts(connection: HostConnection) {
    for (const [id, attempt] of connection.attempts) {
      attempt?.dispose();
      connection.attempts.set(id, undefined);
    }
  }

  private end(code: ErrorName): Effect[] {
    if (this.status !== 'open') return [];
    this.status = `ended:${code}`;
    this.shownCode = null;
    const output: Effect[] = [];
    for (const [id, connection] of this.connections) {
      this.stopAttempts(connection);
      if (connection.gate.state === 'join_only') output.push(close(id, connection.gate, code));
    }
    return [...output, { invitation_ended: code }];
  }

  private checkExhausted(): Effect[] {
    if (this.attemptsLeft > 0) return [];
    for (const connection of this.connections.values()) {
      if ([...connection.attempts.values()].some(attempt => attempt !== undefined)) return [];
    }
    return this.end('attempts_exhausted');
  }

  drop(conn: number): Effect[] {
    const connection = this.connections.get(conn);
    if (!connection) return [];
    this.stopAttempts(connection);
    this.connections.delete(conn);
    const grant = this.grants.get(hex(connection.peer));
    if (grant) grant.bound_connections = grant.bound_connections.filter(id => id !== conn);
    return this.checkExhausted();
  }

  tick(now: number, mono: number): Effect[] {
    const output = now >= Number(this.ticket.expiresAt) ? this.end('invitation_invalid') : [];
    for (const [conn, connection] of this.connections) {
      const error = connection.gate.timeout(mono);
      if (error) output.push({ conn, close: error });
    }
    return output;
  }

  // `role`: the owner chose the role of this enrollment's grant with the approval; the invitation keeps its own.
  approve(conn: number, now: number, role?: string): Effect[] {
    const connection = this.connections.get(conn);
    if (this.status !== 'open' || !connection || connection.gate.state !== 'join_only' || this.ticket.kind !== 1) {
      return [{ error: 'not_open' }];
    }
    return this.enroll(conn, connection, now, role ?? this.policy.role);
  }

  // Edit a grant's role in place (wire.md 7): its channels close with CANCELLED and authorize again.
  setRole(identity: string, role: string): Effect[] {
    const grant = this.grants.get(identity);
    requireThat(grant !== undefined, 'no_grant');
    const changed = grant.role !== role;
    const output: Effect[] = [{ role_set: { changed, role } }];
    if (!changed) return output;
    this.grants.set(identity, { ...grant, role, bound_connections: [] });
    for (const id of grant.bound_connections) {
      const connection = this.connections.get(id);
      if (connection) output.push(close(id, connection.gate, 'cancelled'));
    }
    return output;
  }

  private enroll(conn: number, connection: HostConnection, now: number, role = this.policy.role): Effect[] {
    if (this.status !== 'open' || now >= Number(this.ticket.expiresAt)) {
      return [close(conn, connection.gate, 'invitation_invalid')];
    }
    const identity = hex(connection.peer);
    if (this.denials.has(identity)) return [close(conn, connection.gate, 'not_authorized')];
    requireThat(connection.name !== undefined, 'protocol_error');
    const oldGrant = this.grants.get(identity);
    try {
      this.grants.set(identity, { authorizing_owner: this.policy.authorizingOwner, bound_connections: [conn],
        enrolled_by: hex(this.ticket.invitation), expires_at: this.policy.grantExpiresAt, granted_at: now,
        identity, name: connection.name, role });
    } catch {
      return [close(conn, connection.gate, 'internal_error'), ...this.checkExhausted()];
    }
    this.status = 'consumed';
    this.shownCode = null;
    connection.gate.promote();
    const output: Effect[] = [{ enrolled: { conn } },
      send(conn, { type: 'PAIRED', name: this.endpoint.name, role })];
    for (const [id, other] of this.connections) {
      this.stopAttempts(other);
      if (id === conn) continue;
      if (oldGrant?.bound_connections.includes(id)) output.push(close(id, other.gate, 'grant_revoked'));
      else if (other.gate.state === 'join_only') output.push(close(id, other.gate, 'invitation_invalid'));
    }
    return output;
  }

  receive(conn: number, msg: Control, now: number): Effect[] {
    const connection = this.connections.get(conn);
    if (!connection) return [{ ignored: true }];
    const { gate } = connection;
    if (!gate.state.startsWith('closed:') && gate.version === undefined && msg.type !== 'HELLO') {
      return [close(conn, gate, 'protocol_error')];
    }
    const rejected = checked(gate, conn, msg);
    if (rejected) {
      if (rejected.some(effect => 'close' in effect)) {
        this.stopAttempts(connection);
        return [...rejected, ...this.checkExhausted()];
      }
      return rejected;
    }
    switch (msg.type) {
      case 'HELLO': return receiveHello(gate, conn, msg);
      case 'JOIN_PROOF': {
        if (equalBytes(connection.peer, this.endpoint.identity) || this.denials.has(hex(connection.peer))) {
          return [close(conn, gate, 'not_authorized')];
        }
        if (this.status !== 'open' || now >= Number(this.ticket.expiresAt) ||
            !equalBytes(msg.invitation, this.ticket.invitation) ||
            !equalBytes(msg.mac, proof(this.ticket, connection.peer, connection.exporters.join))) {
          if (gate.state !== 'live') return [close(conn, gate, 'invitation_invalid')];
          const grant = this.grants.get(hex(connection.peer));
          if (!grant || (grant.expires_at !== null && grant.expires_at <= now)) return [close(conn, gate, 'grant_revoked')];
          if (grant.enrolled_by === hex(msg.invitation)) {
            return [send(conn, { type: 'PAIRED', name: this.endpoint.name, role: grant.role })];
          }
          return [send(conn, { type: 'AUTHORIZED', state: 'live' })];
        }
        gate.admit();
        connection.name = msg.name;
        const output: Effect[] = [{ admitted_join_only: conn }, send(conn, { type: 'AUTHORIZED', state: 'join_only' })];
        if (this.ticket.kind === 1) output.push({ ask_approval: { conn, name: msg.name } });
        else if (this.shownCode !== null) output.push({ show_code: this.shownCode });
        return output;
      }
      case 'CODE_EXCHANGE': return this.codeExchange(conn, connection, msg, now);
      case 'CODE_ABORT': {
        const key = hex(msg.attempt);
        const attempt = connection.attempts.get(key);
        if (!attempt) return [];
        attempt.dispose();
        connection.attempts.set(key, undefined);
        return this.checkExhausted();
      }
      default: return [close(conn, gate, 'protocol_error')];
    }
  }

  private codeExchange(conn: number, connection: HostConnection, msg: Extract<Control, { type: 'CODE_EXCHANGE' }>,
    now: number): Effect[] {
    if (this.ticket.kind !== 2) return [abort(conn, msg.attempt)];
    if (now >= Number(this.ticket.expiresAt)) return this.end('invitation_invalid');
    const key = hex(msg.attempt);
    if (connection.attempts.has(key)) {
      const responder = connection.attempts.get(key);
      if (!responder) return [abort(conn, msg.attempt)];
      connection.attempts.set(key, undefined);
      try {
        responder.finish(msg.payload).isk.fill(0);
      } catch {
        return [abort(conn, msg.attempt), ...this.checkExhausted()];
      }
      return this.enroll(conn, connection, now);
    }
    if (this.attemptsLeft === 0) {
      this.stopAttempts(connection);
      return [close(conn, connection.gate, 'attempts_exhausted'), ...this.checkExhausted()];
    }
    this.attemptsLeft--;
    const code = this.shownCode!;
    this.shownCode = this.attemptsLeft > 0 ? drawCode(this.random, 'next_code') : null;
    const shown: Effect[] = this.shownCode === null ? [] : [{ show_code: this.shownCode }];
    connection.attempts.set(key, undefined);
    let reply: Effect;
    const inputs = cpaceInputs(this.ticket, this.binary, connection.peer, connection.exporters.pair, msg.attempt, code);
    try {
      const responder = respond(inputs, msg.payload, size => this.random.bytes(size, 'cpace_scalar_yb'));
      connection.attempts.set(key, responder);
      reply = exchange(conn, msg.attempt, responder.message);
    } catch (error) {
      if (!['Malformed', 'InvalidPoint'].includes((error as Error).message)) throw error;
      reply = abort(conn, msg.attempt);
    } finally { inputs.prs.fill(0); }
    return [...shown, reply, ...this.checkExhausted()];
  }

  snapshot() { return { attempts_left: this.attemptsLeft, shown_code: this.shownCode, status: this.status }; }
}

type JoinerState = 'connecting' | 'awaiting_code' | 'awaiting_approval' | 'exchanging' |
  'awaiting_paired' | 'paired' | 'already_paired' | `failed:${ErrorName}`;

export interface JoinerFlowStore {
  load(ticketHash: string): Uint8Array | undefined;
  // Atomically and durably replace the record only if its previous bytes match.
  save(ticketHash: string, record: Uint8Array, previous: Uint8Array | undefined): boolean;
  // Return only once the pin is durable. Throw if it could not be stored.
  savePin(hostIdentity: Uint8Array): void;
}

interface JoinerEndpoint {
  identity: Uint8Array;
  computerName: string;
  profileName?: string;
}

interface JoinerOptions {
  arrival: 'in_app_scan' | 'link';
  store: JoinerFlowStore;
  pinnedHost?: Uint8Array;
}

const flowDomain = 'mousse-joiner-flow-v1';

export class PairingJoiner {
  readonly ticket: Ticket;
  state: JoinerState = 'connecting';
  private connection?: { id: number; exporters: Exporters; gate: Gate; streams: Streams };
  private pending?: { id: Uint8Array; initiator: ReturnType<typeof initiate> };
  private remaining = 3;
  private outcomePending = false;
  private savedRecord?: Uint8Array;

  private readonly endpoint: JoinerEndpoint;
  private readonly binary: Uint8Array;
  private readonly random: RandomDraws;
  private readonly hostPinned: boolean;
  private readonly ticketHash: Uint8Array;
  private readonly store: JoinerFlowStore;
  private readonly name: string;

  constructor(endpoint: JoinerEndpoint, binary: Uint8Array, random: RandomDraws, now: number, options: JoinerOptions) {
    this.endpoint = endpoint;
    this.binary = Uint8Array.from(binary);
    this.random = random;
    this.ticket = decodeTicket(this.binary);
    requireThat(this.ticket.kind !== 1 || options.arrival === 'in_app_scan', 'in_person_from_link');
    requireThat(!equalBytes(endpoint.identity, this.ticket.hostIdentity), 'own_ticket');
    const { pinnedHost, store } = options;
    this.hostPinned = pinnedHost !== undefined && equalBytes(pinnedHost, this.ticket.hostIdentity);
    this.name = this.ticket.kind === 1 && endpoint.profileName !== undefined ?
      `${endpoint.computerName} (${endpoint.profileName})` : endpoint.computerName;
    this.ticketHash = sha256(this.binary);
    this.store = store;
    const saved = store.load(hex(this.ticketHash));
    if (saved !== undefined) {
      const value = decode(saved);
      requireThat(fields(value, 1, 2, 3, 4) && value.get(1n) === flowDomain, 'invalid_flow_record');
      const hash = value.get(2n);
      const count = value.get(3n);
      const pending = value.get(4n);
      requireThat(byteString(hash, 32) && equalBytes(hash, this.ticketHash), 'flow_ticket_mismatch');
      requireThat(uint(count, 3n) && uint(pending, 1n), 'invalid_flow_record');
      this.remaining = Number(count);
      this.outcomePending = pending === 1n;
      this.savedRecord = Uint8Array.from(saved);
    }
    requireThat(this.attemptsLeft > 0 || this.outcomePending, 'attempts_exhausted');
    if (!this.outcomePending) checkJoinerExpiry(this.ticket.expiresAt, now);
  }

  get attemptsLeft() { return this.remaining; }
  get streams() { return this.connection?.streams; }

  hostStreamRole(localGrants: Iterable<Grant>, denied: Iterable<string>, now: number) {
    return this.connection?.gate.hostStreamRole(hex(this.ticket.hostIdentity), localGrants, denied, now);
  }

  flowRecord(): Uint8Array {
    return this.encodeProgress(this.remaining, this.outcomePending);
  }

  private encodeProgress(count: number, pending: boolean) {
    return encode(record([1, flowDomain], [2, this.ticketHash], [3, count], [4, Number(pending)]));
  }

  private saveProgress(count: number, pending: boolean, effects: Effect[]): boolean {
    if (count === this.remaining && pending === this.outcomePending) return true;
    const previous = this.savedRecord;
    const next = this.encodeProgress(count, pending);
    try {
      if (!this.store.save(hex(this.ticketHash), next, previous)) return false;
    } catch {
      return false;
    }
    this.savedRecord = Uint8Array.from(next);
    this.remaining = count;
    this.outcomePending = pending;
    effects.push({ persist: { expected: previous ? hex(previous) : null, record: hex(next) } });
    return true;
  }

  connect(id: number, exporters: Exporters, now: number, mono = 0): Effect[] {
    requireThat(this.state === 'connecting' && !this.connection, 'wrong_state');
    if (!this.outcomePending) checkJoinerExpiry(this.ticket.expiresAt, now);
    const gate = new Gate('caller');
    this.connection = { id, exporters, gate, streams: new Streams('caller', gate) };
    const joinProof = send(id, { type: 'JOIN_PROOF', invitation: this.ticket.invitation,
      mac: proof(this.ticket, this.endpoint.identity, exporters.join), name: this.name });
    gate.sentJoinProof(mono);
    return [send(id, hello), joinProof];
  }

  tick(mono: number): Effect[] {
    const code = this.connection?.gate.timeout(mono);
    return code ? this.fail(code) : [];
  }

  drop() {
    this.clearAttempt();
    this.connection = undefined;
    if (this.state !== 'paired' && this.state !== 'already_paired' && !this.state.startsWith('failed:')) {
      this.state = this.attemptsLeft === 0 && !this.outcomePending ? 'failed:attempts_exhausted' : 'connecting';
    }
  }

  private clearAttempt() {
    this.pending?.initiator.dispose();
    this.pending = undefined;
  }

  submit(code: string): Effect[] {
    if (this.state !== 'awaiting_code') return [{ error: 'wrong_state' }];
    if (code.length !== 6 || !/^[0-9]{6}$/.test(code)) return [{ error: 'invalid_code' }];
    const conn = this.connection!;
    const effects: Effect[] = [];
    if (!this.saveProgress(this.attemptsLeft - 1, false, effects)) return this.fail('internal_error');
    const id = this.random.bytes(16, 'attempt_id');
    const inputs = cpaceInputs(this.ticket, this.binary, this.endpoint.identity, conn.exporters.pair, id, code);
    let initiator;
    try { initiator = initiate(inputs, size => this.random.bytes(size, 'cpace_scalar_ya')); }
    finally { inputs.prs.fill(0); }
    this.pending = { id, initiator };
    this.state = 'exchanging';
    return [{ attempt: { id: hex(id), ci: hex(inputs.ci), sid: hex(inputs.sid) } }, ...effects,
      exchange(conn.id, id, initiator.message)];
  }

  goaway(code: ErrorName): Effect[] {
    if (this.state.startsWith('failed:')) return [];
    if (code === 'invitation_invalid' || code === 'attempts_exhausted') {
      const effects: Effect[] = [];
      if (!this.saveProgress(this.attemptsLeft, false, effects)) return this.fail('internal_error', false);
      return [...effects, ...this.fail(code, false)];
    }
    if (this.state === 'awaiting_paired') {
      this.drop();
      return [];
    }
    return this.fail(code, false);
  }

  private fail(code: ErrorName, notifyPeer = true): Effect[] {
    if (this.state.startsWith('failed:')) return [];
    this.clearAttempt();
    this.state = `failed:${code}`;
    const effects: Effect[] = [{ failed: code }];
    const conn = this.connection;
    if (conn) {
      const closing = close(conn.id, conn.gate, code);
      if (notifyPeer) effects.push(closing);
    }
    return effects;
  }

  receive(msg: Control): Effect[] {
    const conn = this.connection!;
    if (conn.gate.state === 'awaiting_authorization' && conn.gate.version === undefined && msg.type !== 'HELLO') {
      return [close(conn.id, conn.gate, 'protocol_error')];
    }
    const proofAnswer = conn.gate.state === 'awaiting_proof_answer';
    const result = checked(conn.gate, conn.id, msg);
    if (result) {
      if (result.some(effect => 'close' in effect)) this.clearAttempt();
      return result;
    }
    switch (msg.type) {
      case 'HELLO': return receiveHello(conn.gate, conn.id, msg);
      case 'AUTHORIZED': {
        if (conn.gate.state === 'awaiting_proof_answer') return [];
        if (msg.state === 'live') {
          if (!this.trustsProofAnswer()) return this.fail('pairing_failed');
          return this.completePairing({ already_paired: true });
        }
        const effects: Effect[] = [];
        if (!this.saveProgress(this.attemptsLeft, false, effects)) return this.fail('internal_error');
        if (this.attemptsLeft === 0) return [...effects, ...this.fail('attempts_exhausted')];
        this.state = this.ticket.kind === 1 ? 'awaiting_approval' : 'awaiting_code';
        return effects;
      }
      case 'PAIRED':
        if (proofAnswer) {
          if (!this.trustsProofAnswer()) return this.fail('pairing_failed');
        } else if (this.state !== 'awaiting_approval' && this.state !== 'awaiting_paired') {
          this.clearAttempt();
          return [close(conn.id, conn.gate, 'protocol_error')];
        }
        return this.completePairing({ paired: {
          host_identity: hex(this.ticket.hostIdentity), host_name: msg.name, role: msg.role,
        } });
      case 'CODE_ABORT':
        return this.pending && equalBytes(this.pending.id, msg.attempt) ?
          this.rejectCode() : [{ ignored: true }];
      case 'CODE_EXCHANGE': return this.confirm(conn.id, msg);
      default: return [close(conn.id, conn.gate, 'protocol_error')];
    }
  }

  private trustsProofAnswer() {
    return this.ticket.kind === 1 || this.hostPinned || this.outcomePending;
  }

  private completePairing(outcome: Extract<Effect, { paired: unknown } | { already_paired: true }>): Effect[] {
    const effects: Effect[] = [outcome];
    try {
      this.store.savePin(this.ticket.hostIdentity);
    } catch {
      return this.fail('internal_error');
    }
    if (!this.saveProgress(this.attemptsLeft, false, effects)) return this.fail('internal_error');
    this.clearAttempt();
    const gate = this.connection!.gate;
    if (gate.state === 'join_only') gate.promote();
    this.state = 'paired' in outcome ? 'paired' : 'already_paired';
    return effects;
  }

  private rejectCode(reply?: Effect): Effect[] {
    const effects: Effect[] = [];
    if (!this.saveProgress(this.attemptsLeft, false, effects)) return this.fail('internal_error');
    if (reply) effects.push(reply);
    if (this.attemptsLeft === 0) return [...effects, ...this.fail('attempts_exhausted')];
    this.clearAttempt();
    this.state = 'awaiting_code';
    return [...effects, { code_rejected: { attempts_left: this.attemptsLeft } }];
  }

  private confirm(conn: number, msg: Extract<Control, { type: 'CODE_EXCHANGE' }>): Effect[] {
    const pending = this.pending;
    if (!pending || !equalBytes(pending.id, msg.attempt)) return [{ ignored: true }];
    if (this.state !== 'exchanging') return this.rejectCode(abort(conn, msg.attempt));
    let confirmation;
    try {
      confirmation = pending.initiator.finish(msg.payload);
    } catch {
      return this.rejectCode(abort(conn, msg.attempt));
    }
    confirmation.isk.fill(0);
    const effects: Effect[] = [];
    if (!this.saveProgress(this.attemptsLeft, true, effects)) return this.fail('internal_error');
    this.state = 'awaiting_paired';
    return [...effects, exchange(conn, msg.attempt, confirmation.message)];
  }

  snapshot() {
    const stored = this.store.load(hex(this.ticketHash));
    return { attempts_left: this.attemptsLeft, live: this.connection?.gate.state === 'live',
      outcome_pending: this.outcomePending, state: this.state, stored: stored ? hex(stored) : null };
  }
}
