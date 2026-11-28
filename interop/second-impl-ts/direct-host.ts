// The host side of Pair with IP (wire.md 10.9): direct invitations in memory,
// the lookup, one attempt per connection, approval requests keyed by
// (invitation, joiner identity), and recovery.

import { equalBytes } from './certificate.ts';
import { hex, requireThat } from './cbor.ts';
import { respond } from './cpace.ts';
import { directCodeFromDraw, directCpaceInputs } from './direct-code.ts';
import type { DirectCode } from './direct-code.ts';
import { trafficOf } from './pairing.ts';
import type { RandomDraws } from './pairing.ts';
import { Gate, step2 } from './session.ts';
import type { Grant } from './session.ts';
import { directMinor, errorNumber } from './wire.ts';
import type { Control, ErrorName } from './wire.ts';

export interface DirectLimits {
  lifetimeSecs: number;
  hostAttempts: number;
  allowWindowSecs: number;
  maxOpen: number;
  missHoldMs: number;
}
export const directDefaults: DirectLimits = Object.freeze({
  lifetimeSecs: 600, hostAttempts: 5, allowWindowSecs: 300, maxOpen: 4, missHoldMs: 1000,
});

export const directHello = { type: 'HELLO', major: 1, minor: directMinor } as const;

interface Endpoint { identity: Uint8Array; name: string }
export interface DirectPolicy { authorizingOwner: string; grantExpiresAt: number | null; role: string }
interface Exporters { join?: Uint8Array; pair: Uint8Array }

type Presence = 'connected' | 'away';
type Decision = 'pending' | 'allowed';
export type DirectStatus = 'open' | 'allowed' | 'consumed' | `ended:${ErrorName}` | 'gone';

export interface ApprovalPrompt {
  invitation: string;
  request: number;
  identity: string;
  name: string;
  role: string;
  presence: Presence;
  decision: Decision;
  answer_by: number;
}

export type DirectEffect =
  | { send: Control; conn: number }
  | { close: ErrorName; conn: number }
  | { version: number }
  | { ignored: true }
  | { admitted: number }
  | { miss_hold: { conn: number; hold_ms: number } }
  | { attempts_left: { invitation: string; left: number } }
  | { approval: ApprovalPrompt }
  | { approval_ended: { invitation: string; request: number; identity: string;
      reason: 'enrolled' | 'declined' | 'cancelled' | 'dismissed' | 'window_ended' } }
  | { enrolled: { conn: number; grant: number; identity: string; role: string } }
  | { enrollment_undone: { grant: number; identity: string } }
  | { invitation_ended: { invitation: string; code: ErrorName } };

export interface DirectGrant extends Grant {
  id: number;
  authorizing_owner: string;
  bound_connections: number[];
  granted_at: number;
  name: string;
}

interface Request {
  id: number;
  identity: string;
  name: string;
  role: string;
  firstPassed: number;
  conn?: number;
  decision: Decision;
}

interface Invitation {
  id: Uint8Array;
  key: string;
  code: DirectCode;
  expiresAt: number;
  attemptsLeft: number;
  policy: DirectPolicy;
  status: DirectStatus;
  requests: Map<string, Request>;
  // Declined or cancelled requests, kept for their recovery until their Allow window ends.
  outcomes: Map<string, { code: 'pairing_declined' | 'cancelled'; until: number }>;
}

interface Attempt { id: Uint8Array; responder?: ReturnType<typeof respond> }

interface Connection {
  gate: Gate;
  peer: Uint8Array;
  identity: string;
  exporters: Exporters;
  tcp: boolean;
  closed: boolean;
  held: boolean;
  sentJoin: boolean;
  invitation?: string;
  name?: string;
  attempt?: Attempt;
  // The grant enrolled on this connection, until it carries a stream frame.
  enrolledGrant?: number;
}

const send = (conn: number, message: Control): DirectEffect => ({ conn, send: message });

export class DirectHost {
  readonly grants = new Map<string, DirectGrant>();
  readonly denials = new Set<string>();
  readonly invitations = new Map<string, Invitation>();
  private readonly connections = new Map<number, Connection>();
  private nextRequest = 0;
  private nextGrant = 0;

  private readonly endpoint: Endpoint;
  private readonly policy: DirectPolicy;
  private readonly random: RandomDraws;
  private readonly limits: DirectLimits;
  constructor(endpoint: Endpoint, policy: DirectPolicy, random: RandomDraws, limits: DirectLimits = directDefaults) {
    this.endpoint = endpoint;
    this.policy = policy;
    this.random = random;
    this.limits = limits;
  }

  private isOpen(invitation: Invitation) { return invitation.status === 'open' || invitation.status === 'allowed'; }

  /** Create a direct invitation: draw I, then the code (again while its lookup is another open invitation's). */
  invite(now: number, policy: DirectPolicy = this.policy) {
    const open = [...this.invitations.values()].filter(invitation => this.isOpen(invitation));
    if (open.length >= this.limits.maxOpen) return { error: 'too_many_open' } as const;
    const id = this.random.bytes(16, 'invitation_id');
    let code: DirectCode;
    do code = directCodeFromDraw(this.random.bytes(12, 'direct_code'));
    while (open.some(invitation => invitation.code.lookup === code.lookup));
    const key = hex(id);
    requireThat(!this.invitations.has(key), 'invitation_reused');
    this.invitations.set(key, { id, key, code, expiresAt: now + this.limits.lifetimeSecs,
      attemptsLeft: this.limits.hostAttempts, policy, status: 'open', requests: new Map(), outcomes: new Map() });
    return { invitation: id, code: code.code };
  }

  /** An invitation takes lookups and new attempts while open and before expires_at. */
  private takesAttempts(invitation: Invitation, now: number) {
    return invitation.status === 'open' && now < invitation.expiresAt;
  }

  // Whether the invitation still takes anything: lookups, attempts, or a request's Allow or recovery.
  private takesAnything(invitation: Invitation, now: number) {
    return invitation.status === 'allowed' ||
      (invitation.status === 'open' && (now < invitation.expiresAt || invitation.requests.size > 0));
  }

  connect(conn: number, peer: Uint8Array, exporters: Exporters, now: number, transport: 'tcp' | 'other' = 'tcp'): DirectEffect[] {
    requireThat(!this.connections.has(conn), 'connection_reused');
    const identity = hex(peer);
    const decision = step2(identity, this.grants.values(), this.denials, now);
    const gate = new Gate('host', decision, now * 1000);
    const connection: Connection = { gate, peer, identity, exporters, tcp: transport === 'tcp',
      closed: false, held: false, sentJoin: false };
    this.connections.set(conn, connection);
    const output: DirectEffect[] = [send(conn, directHello)];
    if (decision === 'close:not_authorized') {
      connection.closed = true;
      output.push({ conn, close: 'not_authorized' });
    }
    if (decision === 'live') {
      this.grants.get(identity)!.bound_connections.push(conn);
      output.push(send(conn, { type: 'AUTHORIZED', state: 'live' }));
    }
    return output;
  }

  private close(id: number, code: ErrorName): DirectEffect[] {
    const connection = this.connections.get(id);
    if (!connection || connection.closed) return [];
    connection.closed = true;
    connection.gate.close(code);
    this.stopAttempt(connection);
    const output: DirectEffect[] = [{ conn: id, close: code }];
    // A request that still points here (not ended by the caller) is now away.
    const invitation = connection.invitation ? this.invitations.get(connection.invitation) : undefined;
    const request = invitation && [...invitation.requests.values()].find(r => r.conn === id);
    if (invitation && request) {
      request.conn = undefined;
      output.push(this.prompt(invitation, request));
    }
    return output;
  }

  private stopAttempt(connection: Connection) {
    connection.attempt?.responder?.dispose();
    if (connection.attempt) connection.attempt.responder = undefined;
  }

  private prompt(invitation: Invitation, request: Request): DirectEffect {
    return { approval: { invitation: invitation.key, request: request.id, identity: request.identity, name: request.name,
      role: request.role, presence: request.conn === undefined ? 'away' : 'connected', decision: request.decision,
      answer_by: request.firstPassed + this.limits.allowWindowSecs } };
  }

  private ended(invitation: Invitation, request: Request,
    reason: 'enrolled' | 'declined' | 'cancelled' | 'dismissed' | 'window_ended'): DirectEffect {
    invitation.requests.delete(request.identity);
    return { approval_ended: { invitation: invitation.key, request: request.id, identity: request.identity, reason } };
  }

  // End every request but `keep` (dismissed) and close the invitation's other join-only connections.
  private dismissOthers(invitation: Invitation, code: ErrorName, keep?: Request): DirectEffect[] {
    const output: DirectEffect[] = [];
    for (const request of [...invitation.requests.values()]) {
      if (request === keep) continue;
      output.push(this.ended(invitation, request, 'dismissed'));
      if (request.conn !== undefined) output.push(...this.close(request.conn, code));
    }
    for (const [id, connection] of this.connections) {
      if (connection.invitation !== invitation.key || connection.closed || id === keep?.conn) continue;
      if (connection.gate.state === 'join_only') output.push(...this.close(id, code));
    }
    return output;
  }

  private end(invitation: Invitation, code: ErrorName, others: ErrorName = code): DirectEffect[] {
    if (!this.isOpen(invitation)) return [];
    invitation.status = `ended:${code}`;
    const output = this.dismissOthers(invitation, others);
    for (const connection of this.connections.values()) {
      if (connection.invitation === invitation.key) this.stopAttempt(connection);
    }
    return [...output, { invitation_ended: { invitation: invitation.key, code } }];
  }

  private running(invitation: Invitation) {
    for (const connection of this.connections.values()) {
      if (connection.invitation === invitation.key && !connection.closed && connection.attempt?.responder) return true;
    }
    return false;
  }

  // No attempts left, none running and no request inside its Allow window: the invitation ends.
  private settle(invitation: Invitation): DirectEffect[] {
    if (invitation.status !== 'open' || invitation.attemptsLeft > 0 || this.running(invitation) ||
        invitation.requests.size > 0) return [];
    return this.end(invitation, 'attempts_exhausted');
  }

  private enroll(invitation: Invitation, request: Request, conn: number, now: number, role: string): DirectEffect[] {
    const connection = this.connections.get(conn)!;
    const old = this.grants.get(request.identity);
    const grant: DirectGrant = { id: this.nextGrant++, identity: request.identity, role,
      expires_at: invitation.policy.grantExpiresAt, enrolled_by: invitation.key,
      authorizing_owner: invitation.policy.authorizingOwner, bound_connections: [conn], granted_at: now,
      name: request.name };
    this.grants.set(request.identity, grant);
    invitation.status = 'consumed';
    // The caller ends the other requests (10.8 step 5); the enrolled one has already ended.
    connection.gate.promote();
    connection.enrolledGrant = grant.id;
    this.stopAttempt(connection);
    const output: DirectEffect[] = [{ enrolled: { conn, grant: grant.id, identity: request.identity, role } },
      send(conn, { type: 'PAIRED', name: this.endpoint.name, role })];
    for (const id of old?.bound_connections ?? []) if (id !== conn) output.push(...this.close(id, 'grant_revoked'));
    return output;
  }

  // Remove a grant with receipt I (the joiner's cancel); its other connections close.
  private undo(grant: DirectGrant, conn: number | undefined): DirectEffect[] {
    this.grants.delete(grant.identity);
    const output: DirectEffect[] = [{ enrollment_undone: { grant: grant.id, identity: grant.identity } }];
    if (conn !== undefined) output.push(...this.close(conn, 'cancelled'));
    for (const id of grant.bound_connections) if (id !== conn) output.push(...this.close(id, 'grant_revoked'));
    return output;
  }

  private undoable(connection: Connection) {
    if (connection.enrolledGrant === undefined || connection.gate.carriedStream) return undefined;
    const grant = this.grants.get(connection.identity);
    return grant?.id === connection.enrolledGrant ? grant : undefined;
  }

  private cancelRequest(invitation: Invitation, request: Request): DirectEffect[] {
    invitation.outcomes.set(request.identity,
      { code: 'cancelled', until: request.firstPassed + this.limits.allowWindowSecs });
    const allowed = request.decision === 'allowed';
    const output = [this.ended(invitation, request, 'cancelled')];
    if (allowed) output.push(...this.end(invitation, 'cancelled'));
    return output;
  }

  /** The peer's GOAWAY (`code`) or a broken connection (no code). */
  lost(conn: number, now: number, code?: ErrorName): DirectEffect[] {
    const connection = this.connections.get(conn);
    if (!connection) return [];
    this.connections.delete(conn);
    for (const grant of this.grants.values()) {
      grant.bound_connections = grant.bound_connections.filter(id => id !== conn);
    }
    if (connection.closed) return [];
    connection.closed = true;
    this.stopAttempt(connection);
    if (code === 'cancelled') {
      const grant = this.undoable(connection);
      if (grant) return this.undo(grant, undefined);
    }
    const invitation = connection.invitation ? this.invitations.get(connection.invitation) : undefined;
    if (!invitation) return [];
    const output: DirectEffect[] = [];
    const request = [...invitation.requests.values()].find(r => r.conn === conn);
    if (request && code === 'cancelled') output.push(...this.cancelRequest(invitation, request));
    else if (request) {
      request.conn = undefined;
      output.push(this.prompt(invitation, request));
    }
    return [...output, ...this.settle(invitation)];
  }

  drop(conn: number, now: number): DirectEffect[] { return this.lost(conn, now); }

  tick(now: number): DirectEffect[] {
    const output: DirectEffect[] = [];
    for (const [id, connection] of this.connections) {
      if (connection.closed || connection.sentJoin) continue;
      const code = connection.gate.timeout(now * 1000);
      if (code) {
        connection.closed = true;
        output.push({ conn: id, close: code });
      }
    }
    for (const invitation of this.invitations.values()) {
      for (const [identity, outcome] of invitation.outcomes) if (now >= outcome.until) invitation.outcomes.delete(identity);
      for (const request of [...invitation.requests.values()]) {
        if (now < request.firstPassed + this.limits.allowWindowSecs) continue;
        output.push(this.ended(invitation, request, 'window_ended'));
        if (request.conn !== undefined) output.push(...this.close(request.conn, 'invitation_invalid'));
      }
      const expired = now >= invitation.expiresAt;
      if (invitation.status === 'open' && expired) {
        for (const [id, connection] of this.connections) {
          if (connection.invitation !== invitation.key || connection.closed || connection.gate.state !== 'join_only') continue;
          if (![...invitation.requests.values()].some(r => r.conn === id)) output.push(...this.close(id, 'invitation_invalid'));
        }
        if (invitation.requests.size === 0) output.push(...this.end(invitation, 'invitation_invalid'));
      } else if (invitation.status === 'open') {
        output.push(...this.settle(invitation));
      } else if (invitation.status === 'allowed' && invitation.requests.size === 0) {
        output.push(...this.end(invitation, 'invitation_invalid'));
      }
      // An ended invitation that keeps no outcome is forgotten.
      if (!this.isOpen(invitation) && invitation.outcomes.size === 0) invitation.status = 'gone';
    }
    return output;
  }

  private request(invitationId: Uint8Array, identity: Uint8Array) {
    const invitation = this.invitations.get(hex(invitationId));
    if (!invitation || invitation.status !== 'open') return { error: 'not_open' } as const;
    const request = invitation.requests.get(hex(identity));
    if (!request) return { error: 'unknown_request' } as const;
    return { invitation, request };
  }

  /** The owner allows a request; `role` goes to this enrollment only. */
  allow(invitationId: Uint8Array, identity: Uint8Array, now: number, role?: string) {
    const found = this.request(invitationId, identity);
    if ('error' in found) return { result: found.error, effects: [] as DirectEffect[] };
    const { invitation, request } = found;
    if (request.conn === undefined) {
      request.decision = 'allowed';
      if (role !== undefined) request.role = role;
      invitation.status = 'allowed';
      const effects = [this.prompt(invitation, request), ...this.dismissOthers(invitation, 'invitation_invalid', request)];
      return { result: 'ok', effects };
    }
    // 10.8: enroll and send PAIRED, then end the other requests and close the other connections.
    const conn = request.conn;
    const effects = [this.ended(invitation, request, 'enrolled'),
      ...this.enroll(invitation, request, conn, now, role ?? request.role),
      ...this.dismissOthers(invitation, 'invitation_invalid', request)];
    return { result: 'ok', effects };
  }

  decline(invitationId: Uint8Array, identity: Uint8Array, now: number) {
    const found = this.request(invitationId, identity);
    if ('error' in found) return { result: found.error, effects: [] as DirectEffect[] };
    const { invitation, request } = found;
    invitation.outcomes.set(request.identity,
      { code: 'pairing_declined', until: request.firstPassed + this.limits.allowWindowSecs });
    const effects = [this.ended(invitation, request, 'declined')];
    if (request.conn !== undefined) {
      const conn = request.conn;
      request.conn = undefined;
      effects.push(...this.close(conn, 'pairing_declined'));
    }
    effects.push(...this.end(invitation, 'pairing_declined', 'invitation_invalid'));
    return { result: 'ok', effects };
  }

  /** The owner cancels the invitation. */
  cancel(invitationId: Uint8Array, now: number): DirectEffect[] {
    const invitation = this.invitations.get(hex(invitationId));
    return invitation ? this.end(invitation, 'cancelled') : [];
  }

  receive(conn: number, msg: Control, now: number): DirectEffect[] {
    const connection = this.connections.get(conn);
    if (!connection || connection.closed || connection.held) return [{ ignored: true }];
    const { gate } = connection;
    if (gate.version === undefined && msg.type !== 'HELLO') return this.close(conn, 'protocol_error');
    // A cancel crossing Allow: the just-enrolled connection is live, so this precedes the gate.
    if (msg.type === 'CODE_ABORT' && msg.code === errorNumber('cancelled') && connection.attempt &&
        equalBytes(connection.attempt.id, msg.attempt)) {
      const grant = this.undoable(connection);
      if (grant) return this.undo(grant, conn);
    }
    const verdict = gate.check(trafficOf(msg));
    if (verdict === 'ignore') return [{ ignored: true }];
    if (verdict !== 'allow') return this.close(conn, verdict.slice(6) as ErrorName);
    switch (msg.type) {
      case 'HELLO': {
        const result = gate.receiveHello(msg, directHello);
        if (result === 'ignored') return [{ ignored: true }];
        if (result === 'close:unsupported_version') {
          connection.closed = true;
          return [{ conn, close: 'unsupported_version' }];
        }
        return [{ version: Number(result) }];
      }
      case 'JOIN_DIRECT': return this.joinDirect(conn, connection, msg, now);
      case 'CODE_EXCHANGE': return this.codeExchange(conn, connection, msg, now);
      case 'CODE_ABORT': return this.codeAbort(conn, connection, msg);
      default: return this.close(conn, 'protocol_error');
    }
  }

  private missHold(conn: number, connection: Connection): DirectEffect[] {
    connection.held = true;
    return [{ miss_hold: { conn, hold_ms: this.limits.missHoldMs } }];
  }

  private admit(conn: number, connection: Connection, invitation: Invitation, name: string, notReceived = false) {
    connection.gate.admit();
    connection.invitation = invitation.key;
    connection.name = name;
    return [{ admitted: conn }, send(conn, { type: 'AUTHORIZED', state: 'join_only', invitation: invitation.id,
      ...(notReceived ? { notReceived: true } : {}) })] as DirectEffect[];
  }

  private joinDirect(conn: number, connection: Connection, msg: Extract<Control, { type: 'JOIN_DIRECT' }>,
    now: number): DirectEffect[] {
    connection.sentJoin = true;
    if (!connection.tcp) return this.close(conn, 'invitation_invalid');
    if (equalBytes(connection.peer, this.endpoint.identity) || this.denials.has(connection.identity)) {
      return this.close(conn, 'not_authorized');
    }
    if (msg.receipt) return this.recover(conn, connection, { ...msg, receipt: msg.receipt }, now);
    const invitation = [...this.invitations.values()]
      .find(candidate => candidate.code.lookup === msg.lookup && this.takesAttempts(candidate, now));
    if (!invitation) return this.missHold(conn, connection);
    return this.admit(conn, connection, invitation, msg.name);
  }

  private recover(conn: number, connection: Connection,
    msg: Extract<Control, { type: 'JOIN_DIRECT' }> & { receipt: Uint8Array }, now: number): DirectEffect[] {
    const key = hex(msg.receipt);
    // 1. A live grant for this identity with receipt I.
    const grant = this.grants.get(connection.identity);
    if (grant && grant.enrolled_by === key && (grant.expires_at === null || grant.expires_at > now)) {
      if (msg.cancel) return this.undo(grant, conn);
      return [send(conn, { type: 'PAIRED', name: this.endpoint.name, role: grant.role })];
    }
    // 2. No direct invitation I with this L.
    const invitation = this.invitations.get(key);
    if (!invitation || invitation.status === 'gone' || invitation.code.lookup !== msg.lookup) {
      return this.missHold(conn, connection);
    }
    // 3. A kept outcome for this identity.
    const outcome = invitation.outcomes.get(connection.identity);
    if (outcome && now < outcome.until) return this.close(conn, outcome.code);
    const request = invitation.requests.get(connection.identity);
    // 4. The cancel flag.
    if (msg.cancel) {
      if (!this.takesAnything(invitation, now)) return this.missHold(conn, connection);
      const output: DirectEffect[] = [];
      if (request) {
        if (request.conn !== undefined) {
          const old = request.conn;
          request.conn = undefined;
          output.push(...this.close(old, 'cancelled'));
        }
        output.unshift(...this.cancelRequest(invitation, request));
      }
      return [...output, ...this.close(conn, 'cancelled')];
    }
    // 5. Its request is allowed: enroll on this connection.
    if (request && request.decision === 'allowed' && invitation.status === 'allowed') {
      return [...this.admit(conn, connection, invitation, msg.name), this.ended(invitation, request, 'enrolled'),
        ...this.enroll(invitation, request, conn, now, request.role),
        ...this.dismissOthers(invitation, 'invitation_invalid', request)];
    }
    // 6. Its request waits: it now points at this connection.
    if (request && invitation.status === 'open') {
      const output = this.admit(conn, connection, invitation, msg.name);
      const old = request.conn;
      request.conn = conn;
      if (old !== undefined) output.push(...this.close(old, 'path_replaced'));
      return [...output, this.prompt(invitation, request)];
    }
    // 7. The invitation takes attempts and the host never had this identity's msg_c.
    if (!request && this.takesAttempts(invitation, now)) {
      return this.admit(conn, connection, invitation, msg.name, true);
    }
    // 8. Anything else.
    return this.missHold(conn, connection);
  }

  private codeExchange(conn: number, connection: Connection, msg: Extract<Control, { type: 'CODE_EXCHANGE' }>,
    now: number): DirectEffect[] {
    const invitation = this.invitations.get(connection.invitation!)!;
    const abort = send(conn, { type: 'CODE_ABORT', attempt: msg.attempt, code: errorNumber('pairing_failed') });
    const attempt = connection.attempt;
    if (attempt && equalBytes(attempt.id, msg.attempt)) {
      // 10.7 "No resends": an ended attempt gets CODE_ABORT; a running one takes its next message.
      const responder = attempt.responder;
      if (!responder) return [abort];
      attempt.responder = undefined;
      if (now >= invitation.expiresAt || invitation.status !== 'open') {
        responder.dispose();
        return this.close(conn, 'invitation_invalid');
      }
      try {
        responder.finish(msg.payload).isk.fill(0);
      } catch {
        return [abort, ...this.settle(invitation)];
      }
      return this.passed(conn, connection, invitation, now);
    }
    if (!this.takesAttempts(invitation, now)) return this.close(conn, 'invitation_invalid');
    if (attempt) return this.close(conn, 'protocol_error');
    if (invitation.attemptsLeft === 0) return [...this.close(conn, 'attempts_exhausted'), ...this.settle(invitation)];
    invitation.attemptsLeft--;
    const output: DirectEffect[] = [{ attempts_left: { invitation: invitation.key, left: invitation.attemptsLeft } }];
    connection.attempt = { id: Uint8Array.from(msg.attempt) };
    const inputs = directCpaceInputs(invitation.code, invitation.id,
      { host: this.endpoint.identity, joiner: connection.peer, exporter: connection.exporters.pair }, msg.attempt);
    try {
      const responder = respond(inputs, msg.payload, size => this.random.bytes(size, 'cpace_scalar_yb'));
      connection.attempt.responder = responder;
      output.push(send(conn, { type: 'CODE_EXCHANGE', attempt: msg.attempt, payload: responder.message }));
    } catch (error) {
      if (!['Malformed', 'InvalidPoint'].includes((error as Error).message)) throw error;
      output.push(abort, ...this.settle(invitation));
    } finally { inputs.prs.fill(0); }
    return output;
  }

  // The joiner's confirmation verified: the device passed the code.
  private passed(conn: number, connection: Connection, invitation: Invitation, now: number): DirectEffect[] {
    const output: DirectEffect[] = [];
    const existing = invitation.requests.get(connection.identity);
    if (existing) {
      const old = existing.conn;
      existing.conn = conn;
      if (old !== undefined && old !== conn) output.push(...this.close(old, 'path_replaced'));
      if (old === undefined) output.push(this.prompt(invitation, existing));
      return output;
    }
    invitation.outcomes.delete(connection.identity);
    const request: Request = { id: this.nextRequest++, identity: connection.identity, name: connection.name!,
      role: invitation.policy.role, firstPassed: now, conn, decision: 'pending' };
    invitation.requests.set(request.identity, request);
    return [this.prompt(invitation, request)];
  }

  private codeAbort(conn: number, connection: Connection, msg: Extract<Control, { type: 'CODE_ABORT' }>): DirectEffect[] {
    const attempt = connection.attempt;
    if (!attempt || !equalBytes(attempt.id, msg.attempt)) return [];
    const invitation = this.invitations.get(connection.invitation!)!;
    const request = [...invitation.requests.values()].find(r => r.conn === conn);
    if (msg.code === errorNumber('cancelled') && request) {
      request.conn = undefined;
      return [...this.cancelRequest(invitation, request), ...this.close(conn, 'cancelled')];
    }
    if (!attempt.responder) return [];
    this.stopAttempt(connection);
    return this.settle(invitation);
  }

  snapshot(invitationId: Uint8Array) {
    const invitation = this.invitations.get(hex(invitationId));
    requireThat(invitation !== undefined, 'unknown_invitation');
    return {
      status: invitation.status,
      attempts_left: invitation.attemptsLeft,
      code: invitation.code.code,
      requests: [...invitation.requests.values()].map(request =>
        [request.identity, request.conn === undefined ? 'away' : 'connected', request.decision]),
      granted: [...this.grants.values()].filter(grant => grant.enrolled_by === invitation.key).map(grant => grant.identity),
    };
  }
}
