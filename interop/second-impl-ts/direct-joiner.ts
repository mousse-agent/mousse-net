// The joiner side of Pair with IP (wire.md 10.9 "Joiner"): the typed address
// and code, the lookup's hold, the attempt ledger (stored under the typed
// lookup L) and the pending records (under L and the typed address), both
// written by compare and swap under the hold, first contact, the ends that
// settle a pending record, recovery and cancel.

import { equalBytes, validPoint } from './certificate.ts';
import { byteString, decode, encode, fail, fields, hex, record, requireThat, textString, uint } from './cbor.ts';
import { initiate } from './cpace.ts';
import { directCpaceInputs, parseDirectCode } from './direct-code.ts';
import type { DirectCode } from './direct-code.ts';
import { directHello } from './direct-host.ts';
import { trafficOf } from './pairing.ts';
import type { RandomDraws } from './pairing.ts';
import { hostText } from './relay.ts';
import { Gate } from './session.ts';
import { directMinor, errorNumber, routeHint } from './wire.ts';
import type { Control, ErrorName } from './wire.ts';

/** DIRECT_JOINER_ATTEMPTS, the attempts a start has when no ledger record counts. */
export const directJoinerAttempts = 5;
/** A ledger record counts for this long after its first debit (fixed). */
export const ledgerWindowSecs = 86400;
/** The wait for the answer to JOIN_DIRECT (8.2). */
export const answerWaitSecs = 10;
const ledgerDomain = 'mousse-direct-joiner-v1';
const pendingDomain = 'mousse-direct-pending-v1';

/**
 * The typed address in its canonical text: `<IPv4>:<port>` or `[<IPv6>]:<port>`
 * read with the route grammar (10.2.1), leading and trailing spaces dropped, no
 * DNS names and no IPv4-mapped IPv6 address. IPv4 stays dotted; IPv6 is written
 * in RFC 5952 form (hex groups only).
 */
export function parseDirectAddress(text: string): string {
  const route = routeHint(`tcp://${text.replace(/^ +| +$/g, '')}`);
  if (!('tcp' in route) || 'dns' in route.tcp.host) return fail('bad_address');
  // No IPv4-mapped IPv6 address (::ffff:0:0/96): the IPv4 form is typed instead.
  if ('ipv6' in route.tcp.host && route.tcp.host.ipv6.startsWith(`${'0'.repeat(20)}ffff`)) return fail('bad_address');
  return `${hostText(route.tcp.host)}:${route.tcp.port}`;
}

// Times in both records are uints up to 2^64 - 1, kept whole as bigint.
const isUint = (value: unknown, max?: bigint): value is bigint => typeof value === 'bigint' && uint(value, max);

export interface DirectLedger { lookup: string; left: number; firstDebit: bigint }

export const encodeLedger = (ledger: DirectLedger): Buffer =>
  encode(record([1, ledgerDomain], [2, ledger.lookup], [3, ledger.left], [4, ledger.firstDebit]));

/** A stored ledger record; one stored for another lookup is refused. */
export function decodeLedger(data: Uint8Array, lookup: string): DirectLedger {
  const value = decode(data);
  requireThat(fields(value, 1, 2, 3, 4) && value.get(1n) === ledgerDomain, 'invalid_ledger');
  const left = value.get(3n);
  const firstDebit = value.get(4n);
  requireThat(isUint(left, BigInt(directJoinerAttempts)) && isUint(firstDebit), 'invalid_ledger');
  requireThat(value.get(2n) === lookup, 'ledger_lookup');
  return { lookup, left: Number(left), firstDebit };
}

export interface DirectPending {
  lookup: string;
  host: Uint8Array;
  invitation: Uint8Array;
  address: string;
  verifiedAt: bigint;
  cancelled: boolean;
}

export const encodePending = (pending: DirectPending): Buffer =>
  encode(record([1, pendingDomain], [2, pending.lookup], [3, pending.host], [4, pending.invitation],
    [5, pending.address], [6, pending.verifiedAt], [7, pending.cancelled ? 1 : 0]));

/** A stored pending record; one for another lookup or with a non-canonical address is refused. */
export function decodePending(data: Uint8Array, lookup: string): DirectPending {
  const value = decode(data);
  requireThat(fields(value, 1, 2, 3, 4, 5, 6, 7) && value.get(1n) === pendingDomain, 'invalid_pending');
  const host = value.get(3n);
  const invitation = value.get(4n);
  const address = value.get(5n);
  const verifiedAt = value.get(6n);
  const cancelled = value.get(7n);
  requireThat(byteString(host, 65) && validPoint(host) && byteString(invitation, 16) &&
    textString(address, 1, 255) && isUint(verifiedAt) && isUint(cancelled, 1n), 'invalid_pending');
  let canonical: string | undefined;
  try { canonical = parseDirectAddress(address); } catch { /* refused below */ }
  requireThat(canonical === address, 'invalid_pending');
  requireThat(value.get(2n) === lookup, 'pending_lookup');
  return { lookup, host, invitation, address, verifiedAt, cancelled: cancelled === 1n };
}

export type DirectRecordKind = 'ledger' | 'pending';

export interface DirectPairing {
  host: Uint8Array;
  address: string;
  invitation: Uint8Array;
  name: string;
  role: string;
}

export interface DirectJoinerStore {
  /**
   * Take the lookup's hold: one flow at a time works on a typed lookup. The
   * operating system releases it if the app dies. False when another flow has it.
   */
  acquire(lookup: string): boolean;
  /** Give the lookup's hold back. */
  release(lookup: string): void;
  /**
   * The ledger stored under `lookup`, or the pending record stored under
   * `lookup` and the typed address `address`. Read under the hold.
   */
  load(kind: DirectRecordKind, lookup: string, address: string): Uint8Array | undefined;
  /**
   * Durably replace the record (`null` deletes it) only if the caller holds the
   * lookup's hold and the stored bytes are still `previous` (`undefined`: no
   * record). Return false otherwise.
   */
  save(kind: DirectRecordKind, lookup: string, address: string, next: Uint8Array | null,
    previous: Uint8Array | undefined): boolean;
  /**
   * Durably store the pin, the typed address as an owner route and a completion
   * record keyed by the invitation id. Return only once durable; throw if not.
   */
  savePairing(pairing: DirectPairing): void;
}

export interface DirectJoinerContext {
  identity: Uint8Array;
  /** The computer name, sent in JOIN_DIRECT. */
  name: string;
  store: DirectJoinerStore;
  random: RandomDraws;
}

export type DirectJoinerEvent =
  | 'code_passed'
  | 'away'
  | { paired: { address: string; host: string; invitation: string; name: string; role: string } }
  | { ended: string };

export type DirectJoinerEffect =
  | { send: Control; conn: number }
  | { close: ErrorName; conn: number }
  | { persist_ledger: { expected: string | null; record: string | null } }
  | { persist_pending: { expected: string | null; record: string | null } }
  | { write_failed: true }
  | { hold: string }
  | { hold_refused: string }
  | { release: string }
  | { joiner: DirectJoinerEvent }
  // The app's first stream on the paired connection (it commits the host's provisional grant).
  | { stream: number };

export type DirectJoinerState = 'ready' | 'hello' | 'joining' | 'exchanging' | 'recovering' |
  'awaiting_allow' | 'away' | `ended:${string}`;

export type DirectStart =
  | { result: 'ok'; flow: DirectJoiner; effects: DirectJoinerEffect[] }
  | { result: 'bad_address' | 'bad_code' | 'busy' | 'attempts_exhausted' | 'no_pending' | 'internal_error';
      effects: DirectJoinerEffect[] };

interface Connection {
  id: number;
  gate: Gate;
  peer: Uint8Array;
  exporter: Uint8Array;
  open: boolean;
  recovery: boolean;
  // A recovery whose JOIN_DIRECT carried the cancel flag.
  cancelling?: boolean;
  // The deadline for the answer to JOIN_DIRECT, while it is awaited.
  answerBy?: number;
  // The attempt this connection ran: its id stays for a cancel after the code passed.
  attempt?: { id: Uint8Array; initiator?: ReturnType<typeof initiate> };
}

// Host closes that settle a pending record.
const settling: readonly ErrorName[] = ['pairing_declined', 'cancelled', 'invitation_invalid', 'attempts_exhausted'];

// The records under a lookup's hold, loaded and decoded.
function loadRecords(store: DirectJoinerStore, lookup: string, address: string) {
  const ledgerBytes = store.load('ledger', lookup, address);
  const pendingBytes = store.load('pending', lookup, address);
  const ledger = ledgerBytes && decodeLedger(ledgerBytes, lookup);
  const pending = pendingBytes && decodePending(pendingBytes, lookup);
  if (pending) requireThat(pending.address === address, 'invalid_pending');
  return { ledgerBytes, pendingBytes, ledger, pending };
}

/** One Pair with IP flow: one Connect, at most one attempt, then recovery while a pending record exists. */
export class DirectJoiner {
  state: DirectJoinerState = 'ready';
  readonly lookup: string;
  readonly address: string;
  private readonly context: DirectJoinerContext;
  private readonly code?: DirectCode;
  // Each record's bytes as this flow last read or wrote them.
  private ledgerBytes?: Uint8Array;
  private pendingBytes?: Uint8Array;
  private pending?: DirectPending;
  private invitation?: Uint8Array;
  private connection?: Connection;
  // Whether this flow has the lookup's hold.
  private holding = true;
  // The connection the flow ended paired on, live, until the app opens its first stream there.
  private paired_?: Connection;

  private constructor(context: DirectJoinerContext, lookup: string, address: string, code: DirectCode | undefined,
    records: ReturnType<typeof loadRecords>) {
    this.context = context;
    this.lookup = lookup;
    this.address = address;
    this.code = code;
    this.ledgerBytes = records.ledgerBytes;
    this.pendingBytes = records.pendingBytes;
    this.pending = records.pending;
  }

  // Take the lookup's hold and load the records under it; `undefined` when another flow has it.
  private static hold(context: DirectJoinerContext, lookup: string, address: string, effects: DirectJoinerEffect[]) {
    if (!context.store.acquire(lookup)) {
      effects.push({ hold_refused: lookup });
      return undefined;
    }
    effects.push({ hold: lookup });
    try { return loadRecords(context.store, lookup, address); } catch {
      context.store.release(lookup);
      effects.push({ joiner: { ended: 'failed:internal_error' } }, { release: lookup });
      return null;
    }
  }

  /** What the person typed. Nothing is dialled and no attempt is spent unless the result is `ok`. */
  static start(context: DirectJoinerContext, typed: { address: string; code: string }, now: number): DirectStart {
    let address: string;
    let code: DirectCode;
    try { address = parseDirectAddress(typed.address); } catch { return { result: 'bad_address', effects: [] }; }
    try { code = parseDirectCode(typed.code); } catch { return { result: 'bad_code', effects: [] }; }
    const effects: DirectJoinerEffect[] = [];
    const records = DirectJoiner.hold(context, code.lookup, address, effects);
    if (records === undefined) return { result: 'busy', effects: [...effects, { joiner: { ended: 'busy' } }] };
    if (records === null) return { result: 'internal_error', effects };
    // The same typed address and lookup as a stored pending record: its recovery.
    if (records.pending) {
      return { result: 'ok', flow: new DirectJoiner(context, code.lookup, address, undefined, records), effects };
    }
    if (DirectJoiner.left(records.ledger, now) === 0) {
      context.store.release(code.lookup);
      return { result: 'attempts_exhausted',
        effects: [...effects, { joiner: { ended: 'attempts_exhausted' } }, { release: code.lookup }] };
    }
    return { result: 'ok', flow: new DirectJoiner(context, code.lookup, address, code, records), effects };
  }

  /** A new flow from the pending record stored under `lookup` at `address` (no code). */
  static resume(context: DirectJoinerContext, lookup: string, address: string): DirectStart {
    const effects: DirectJoinerEffect[] = [];
    const records = DirectJoiner.hold(context, lookup, address, effects);
    if (records === undefined) return { result: 'busy', effects: [...effects, { joiner: { ended: 'busy' } }] };
    if (records === null) return { result: 'internal_error', effects };
    if (!records.pending) {
      context.store.release(lookup);
      return { result: 'no_pending', effects: [...effects, { release: lookup }] };
    }
    return { result: 'ok', flow: new DirectJoiner(context, lookup, address, undefined, records), effects };
  }

  private static left(ledger: DirectLedger | undefined, now: number) {
    return ledger && BigInt(now) < ledger.firstDebit + BigInt(ledgerWindowSecs) ? ledger.left : directJoinerAttempts;
  }

  private ledger() { return this.ledgerBytes && decodeLedger(this.ledgerBytes, this.lookup); }

  /** The attempts left for this lookup. */
  attemptsLeft(now: number) { return DirectJoiner.left(this.ledger(), now); }

  private get ended() { return this.state.startsWith('ended:'); }

  /** Whether this flow has the lookup's hold. */
  get held() { return this.holding; }

  private write(kind: DirectRecordKind, next: Uint8Array | null, effects: DirectJoinerEffect[]): boolean {
    const previous = kind === 'ledger' ? this.ledgerBytes : this.pendingBytes;
    let saved = false;
    // Every write needs the hold.
    if (this.holding) {
      try { saved = this.context.store.save(kind, this.lookup, this.address, next, previous); } catch { saved = false; }
    }
    if (!saved) {
      effects.push({ write_failed: true });
      return false;
    }
    const stored = next === null ? undefined : Uint8Array.from(next);
    if (kind === 'ledger') this.ledgerBytes = stored;
    else this.pendingBytes = stored;
    const persisted = { expected: previous ? hex(previous) : null, record: next === null ? null : hex(next) };
    effects.push(kind === 'ledger' ? { persist_ledger: persisted } : { persist_pending: persisted });
    return true;
  }

  // The hold goes back after the flow's last write, when it ends or goes away.
  private release(): DirectJoinerEffect[] {
    if (!this.holding) return [];
    this.holding = false;
    this.context.store.release(this.lookup);
    return [{ release: this.lookup }];
  }

  // Going on from away: take the hold again and reload the records. A refused hold leaves the flow away;
  // a recovery whose own record is gone ends as settled.
  private retake(): DirectJoinerEffect[] | undefined {
    if (this.holding) return undefined;
    const effects: DirectJoinerEffect[] = [];
    const records = DirectJoiner.hold(this.context, this.lookup, this.address, effects);
    if (records === undefined) return [...effects, { joiner: 'away' }];
    if (records === null) {
      this.state = 'ended:failed:internal_error';
      return effects;
    }
    this.holding = true;
    this.ledgerBytes = records.ledgerBytes;
    this.pendingBytes = records.pendingBytes;
    this.pending = records.pending;
    if (!this.pending) return [...effects, ...this.end('settled')];
    return effects.length ? effects : undefined;
  }

  private end(outcome: string): DirectJoinerEffect[] {
    this.state = `ended:${outcome}`;
    return [{ joiner: { ended: outcome } }, ...this.release()];
  }

  // The connection ends here. A kept pending record leaves the flow away, to recover later.
  private closed(): DirectJoinerEffect[] {
    const connection = this.connection;
    if (connection) {
      connection.open = false;
      connection.answerBy = undefined;
      connection.attempt?.initiator?.dispose();
      if (connection.attempt) connection.attempt.initiator = undefined;
    }
    return [];
  }

  private away(): DirectJoinerEffect[] {
    this.state = 'away';
    return [{ joiner: 'away' }, ...this.release()];
  }

  // The joiner closes the connection; the flow ends, or waits away while a pending record is kept.
  private fail(code: ErrorName, outcome: string = `failed:${code}`, keepFlow = true): DirectJoinerEffect[] {
    const connection = this.connection;
    const effects: DirectJoinerEffect[] = [];
    if (connection?.open) {
      connection.gate.close(code);
      effects.push({ conn: connection.id, close: code });
    }
    this.closed();
    return [...effects, ...(this.pending && keepFlow ? this.away() : this.end(outcome))];
  }

  // A write failed or found the record changed: nothing that waited for it goes out; the joiner closes
  // with INTERNAL_ERROR (a connection that was to close after the write is still up) and the flow ends.
  private failedWrite(effects: DirectJoinerEffect[] = []) {
    return [...effects, ...this.fail('internal_error', 'closed:internal_error', false)];
  }

  /** TLS is up and the joiner sees the far end's identity key. */
  connect(id: number, peer: Uint8Array, exporters: { pair: Uint8Array }): DirectJoinerEffect[] {
    requireThat(this.state === 'ready' || this.state === 'away', 'wrong_state');
    const held = this.retake();
    if (held && (!this.holding || this.ended)) return held;
    const effects = held ?? [];
    const recovery = this.pending !== undefined;
    // A recovery is dialled pinned to the record's host key: another key never connects.
    if (recovery && !equalBytes(peer, this.pending!.host)) return [...effects, ...this.away()];
    if (!recovery && equalBytes(peer, this.context.identity)) {
      return [...effects, { conn: id, close: 'pairing_failed' }, ...this.end('own_device')];
    }
    const gate = recovery ? new Gate('caller') : Gate.pairingOnly();
    this.connection = { id, gate, peer: Uint8Array.from(peer), exporter: Uint8Array.from(exporters.pair), open: true,
      recovery };
    this.state = 'hello';
    return [...effects, { conn: id, send: directHello }];
  }

  /** A control message from the host on connection `id`. */
  receive(id: number, msg: Control, now: number): DirectJoinerEffect[] {
    const connection = this.connection;
    if (!connection || connection.id !== id || !connection.open || this.ended) return [];
    const { gate } = connection;
    if (gate.version === undefined && msg.type !== 'HELLO') return this.fail('protocol_error');
    const verdict = gate.check(trafficOf(msg));
    if (verdict === 'ignore') return [];
    if (verdict !== 'allow') return this.fail(verdict.slice(6) as ErrorName);
    switch (msg.type) {
      case 'HELLO': return this.hello(connection, msg, now);
      case 'AUTHORIZED':
        if (msg.state === 'live') return [];
        connection.answerBy = undefined;
        return connection.recovery ? this.recoveryAnswer(msg, now) : this.answer(connection, msg, now);
      case 'CODE_EXCHANGE': return this.confirm(connection, msg, now);
      case 'CODE_ABORT': return this.hostAbort(connection, msg, now);
      case 'PAIRED':
        connection.answerBy = undefined;
        return this.paired(connection, msg);
      default: return this.fail('protocol_error');
    }
  }

  /** The joiner's timer: no answer to JOIN_DIRECT within 10 s closes with NOT_AUTHORIZED (8.2). */
  timeout(id: number, now: number): DirectJoinerEffect[] {
    const connection = this.connection;
    if (!connection || connection.id !== id || !connection.open || this.ended) return [];
    if (connection.answerBy === undefined || now < connection.answerBy) return [];
    return this.fail('not_authorized', 'closed:not_authorized');
  }

  private hello(connection: Connection, msg: Extract<Control, { type: 'HELLO' }>, now: number): DirectJoinerEffect[] {
    const result = connection.gate.receiveHello(msg, directHello);
    if (result === 'ignored') return [];
    // The host needs an update; a recovery keeps its record.
    if (result === 'close:unsupported_version' || Number(result) < directMinor) {
      return this.fail('unsupported_version', 'needs_update');
    }
    const { name } = this.context;
    // Either form of JOIN_DIRECT arms the wait for its answer.
    connection.answerBy = now + answerWaitSecs;
    if (!connection.recovery) {
      this.state = 'joining';
      return [{ conn: connection.id, send: { type: 'JOIN_DIRECT', lookup: this.lookup, name } }];
    }
    const pending = this.pending!;
    // On a pinned recovery, JOIN_DIRECT counts as the proof (8.2).
    connection.gate.sentJoinProof(now * 1000);
    connection.cancelling = pending.cancelled;
    this.state = 'recovering';
    return [{ conn: connection.id, send: { type: 'JOIN_DIRECT', lookup: this.lookup, name,
      receipt: pending.invitation, ...(pending.cancelled ? { cancel: true } : {}) } }];
  }

  // First contact, step 4: the answer AUTHORIZED {join_only, I}. Debit, then msg_a.
  private answer(connection: Connection, msg: Extract<Control, { type: 'AUTHORIZED' }>, now: number): DirectJoinerEffect[] {
    if (this.state !== 'joining' || !msg.invitation || msg.notReceived) return this.fail('protocol_error');
    this.invitation = Uint8Array.from(msg.invitation);
    // The ledger as loaded, read again now: when its 24 hours ended after the start, the debit begins a new record.
    const ledger = this.ledger();
    const counts = ledger !== undefined && BigInt(now) < ledger.firstDebit + BigInt(ledgerWindowSecs);
    const left = counts ? ledger.left : directJoinerAttempts;
    if (left === 0) return this.fail('attempts_exhausted', 'attempts_exhausted');
    const effects: DirectJoinerEffect[] = [];
    const next = encodeLedger({ lookup: this.lookup, left: left - 1, firstDebit: counts ? ledger.firstDebit : BigInt(now) });
    if (!this.write('ledger', next, effects)) return this.failedWrite(effects);
    const { random } = this.context;
    const attempt = random.bytes(16, 'attempt_id');
    const inputs = directCpaceInputs(this.code!, this.invitation,
      { host: connection.peer, joiner: this.context.identity, exporter: connection.exporter }, attempt);
    let initiator;
    try { initiator = initiate(inputs, size => random.bytes(size, 'cpace_scalar_ya')); }
    finally { inputs.prs.fill(0); }
    connection.attempt = { id: attempt, initiator };
    this.state = 'exchanging';
    return [...effects, { conn: connection.id, send: { type: 'CODE_EXCHANGE', attempt, payload: initiator.message } }];
  }

  // Steps 5 and 6: check Tb, then store the pending record before msg_c.
  private confirm(connection: Connection, msg: Extract<Control, { type: 'CODE_EXCHANGE' }>, now: number): DirectJoinerEffect[] {
    const attempt = connection.attempt;
    if (!attempt || !equalBytes(attempt.id, msg.attempt) || this.state !== 'exchanging' || !attempt.initiator) return [];
    let confirmation;
    try {
      confirmation = attempt.initiator.finish(msg.payload);
    } catch {
      attempt.initiator = undefined;
      return this.codeFailed(connection, true, now);
    }
    attempt.initiator = undefined;
    confirmation.isk.fill(0);
    const pending: DirectPending = { lookup: this.lookup, host: connection.peer, invitation: this.invitation!,
      address: this.address, verifiedAt: BigInt(now), cancelled: false };
    const effects: DirectJoinerEffect[] = [];
    if (!this.write('pending', encodePending(pending), effects)) {
      confirmation.message.fill(0);
      return this.failedWrite(effects);
    }
    this.pending = pending;
    this.state = 'awaiting_allow';
    return [...effects, { joiner: 'code_passed' },
      { conn: connection.id, send: { type: 'CODE_EXCHANGE', attempt: attempt.id, payload: confirmation.message } }];
  }

  private codeFailed(connection: Connection, abort: boolean, now: number): DirectJoinerEffect[] {
    const left = this.attemptsLeft(now);
    const effects: DirectJoinerEffect[] = abort ? [{ conn: connection.id,
      send: { type: 'CODE_ABORT', attempt: connection.attempt!.id, code: errorNumber('pairing_failed') } }] : [];
    if (left === 0) return [...effects, ...this.fail('attempts_exhausted', 'attempts_exhausted')];
    return [...effects, ...this.fail('pairing_failed', `code_failed:${left}`)];
  }

  private hostAbort(connection: Connection, msg: Extract<Control, { type: 'CODE_ABORT' }>, now: number): DirectJoinerEffect[] {
    if (!connection.attempt || !equalBytes(connection.attempt.id, msg.attempt)) return [];
    if (this.state === 'exchanging') return this.codeFailed(connection, false, now);
    // After the code passed: the connection ends and the record is kept.
    return this.fail('pairing_failed');
  }

  // A recovery's answer AUTHORIZED {join_only, I[, not_received]}.
  private recoveryAnswer(msg: Extract<Control, { type: 'AUTHORIZED' }>, now: number): DirectJoinerEffect[] {
    const pending = this.pending!;
    if (this.state !== 'recovering' || !msg.invitation || !equalBytes(msg.invitation, pending.invitation)) {
      return this.fail('protocol_error');
    }
    if (msg.notReceived) {
      const effects: DirectJoinerEffect[] = [];
      if (!this.write('pending', null, effects)) return this.failedWrite(effects);
      this.pending = undefined;
      const left = this.attemptsLeft(now);
      return [...effects, ...this.fail('no_error', `not_received:${left}`)];
    }
    this.state = 'awaiting_allow';
    return [{ joiner: 'code_passed' }];
  }

  // Step 7: PAIRED, only after the host's confirmation verified (or on a recovery), never once cancelled,
  // except as the settling answer to the recovery that carries the cancel flag (the grant committed first).
  private paired(connection: Connection, msg: Extract<Control, { type: 'PAIRED' }>): DirectJoinerEffect[] {
    const pending = this.pending;
    if (pending?.cancelled && !(connection.recovery && connection.cancelling)) return [];
    const expected = connection.recovery ? this.state === 'recovering' || this.state === 'awaiting_allow'
      : this.state === 'awaiting_allow';
    if (!pending || !expected) return this.fail('protocol_error');
    const pairing = { host: pending.host, address: pending.address, invitation: pending.invitation, name: msg.name,
      role: msg.role };
    try { this.context.store.savePairing(pairing); } catch { return this.failedWrite([{ write_failed: true }]); }
    const effects: DirectJoinerEffect[] = [{ joiner: { paired: { address: pairing.address, host: hex(pairing.host),
      invitation: hex(pairing.invitation), name: pairing.name, role: pairing.role } } }];
    const { gate } = connection;
    if (gate.state === 'join_only') gate.promote();
    else gate.promoteDirect();
    if (!this.write('pending', null, effects)) return this.failedWrite(effects);
    this.pending = undefined;
    // The connection is live and stays up; the flow is done with it.
    this.connection = undefined;
    this.paired_ = connection;
    return [...effects, ...this.end('paired')];
  }

  /** Once paired, the app may open its first stream on that connection, only when its gate is live. */
  openStream(): DirectJoinerEffect[] {
    const connection = this.paired_;
    if (!connection?.open || !connection.gate.canOpenStream('caller')) return [];
    connection.gate.openedStream('caller');
    this.paired_ = undefined;
    return [{ stream: connection.id }];
  }

  // The paired connection ended before the app opened a stream on it.
  private pairedGone(id: number) {
    if (this.paired_?.id !== id) return;
    this.paired_.open = false;
    this.paired_ = undefined;
  }

  /** The host closed connection `id` (its GOAWAY). */
  hostClosed(id: number, code: ErrorName): DirectJoinerEffect[] {
    this.pairedGone(id);
    const connection = this.connection;
    if (!connection || connection.id !== id || !connection.open || this.ended) return [];
    connection.gate.close(code);
    this.closed();
    if (!this.pending) return this.end(`closed:${code}`);
    if (!settling.includes(code)) return this.away();
    const effects: DirectJoinerEffect[] = [];
    if (!this.write('pending', null, effects)) return [...effects, ...this.end('closed:internal_error')];
    this.pending = undefined;
    return [...effects, ...this.end(`closed:${code}`)];
  }

  /** Connection `id` broke. */
  broken(id: number): DirectJoinerEffect[] {
    this.pairedGone(id);
    const connection = this.connection;
    if (!connection || connection.id !== id || !connection.open || this.ended) return [];
    connection.gate.close('no_error');
    this.closed();
    return this.pending ? this.away() : this.end('broken');
  }

  /** The person cancels. */
  cancel(): DirectJoinerEffect[] {
    if (this.ended) return [];
    // From away, the cancel takes the hold again and reloads; refused, the flow stays away.
    const held = this.retake();
    if (held && (!this.holding || this.ended)) return held;
    const connection = this.connection?.open ? this.connection : undefined;
    const effects: DirectJoinerEffect[] = held ?? [];
    const abort = (attempt: Uint8Array) => effects.push({ conn: connection!.id,
      send: { type: 'CODE_ABORT', attempt, code: errorNumber('cancelled') } });
    if (!this.pending) {
      // Before the code passed: a running attempt is aborted (its debit stays).
      if (connection?.attempt && this.state === 'exchanging') abort(connection.attempt.id);
      if (connection) {
        connection.gate.close('cancelled');
        effects.push({ conn: connection.id, close: 'cancelled' });
      }
      this.closed();
      return [...effects, ...this.end('cancelled')];
    }
    // After it passed: mark the record cancelled first; the record stays for a recovery.
    if (!this.pending.cancelled) {
      const next = { ...this.pending, cancelled: true };
      if (!this.write('pending', encodePending(next), effects)) return this.failedWrite(effects);
      this.pending = next;
    }
    if (connection) {
      if (connection.attempt) abort(connection.attempt.id);
      connection.gate.close('cancelled');
      effects.push({ conn: connection.id, close: 'cancelled' });
    }
    this.closed();
    return [...effects, ...this.away()];
  }

  /** The app stopped: the operating system releases the hold. */
  crashed() {
    this.holding = false;
  }
}
