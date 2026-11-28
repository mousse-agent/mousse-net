// The host side of Pair with IP (wire.md 10.9): direct invitations in memory,
// the lookup, one attempt per connection, approval requests keyed by
// (invitation, joiner identity), provisional grants and recovery.

import { equalBytes } from './certificate.ts';
import { hex, requireThat } from './cbor.ts';
import { respond } from './cpace.ts';
import { directCodeFromDraw, directCpaceInputs } from './direct-code.ts';
import type { DirectCode } from './direct-code.ts';
import { trafficOf } from './pairing.ts';
import type { RandomDraws } from './pairing.ts';
import { Gate } from './session.ts';
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
  | { gate: { conn: number; verdict: 'ignore' } }
  | { stream: { conn: number; verdict: 'allow' | 'commit' | 'ignore' } }
  | { admitted: number }
  | { miss_hold: { conn: number; hold_ms: number } }
  | { attempts_left: { invitation: string; left: number } }
  | { approval: ApprovalPrompt }
  | { approval_ended: { invitation: string; request: number; identity: string;
      reason: 'enrolled' | 'declined' | 'cancelled' | 'dismissed' | 'window_ended' } }
  | { enrolled: { conn: number; grant: number; identity: string; role: string } }
  | { bound: { conn: number; grant: number; provisional: boolean } }
  | { committed: { conn: number; grant: number; identity: string; bound: number[] } }
  | { enrollment_undone: { grant: number; identity: string } }
  | { grant_closes: { grant: number; code: ErrorName; conns: number[] } }
  | { invitation_ended: { invitation: string; code: ErrorName } }
  | { proof_timeout: number };

/** A grant-table entry: a committed grant, or a provisional one (wire.md 10.9). */
export interface DirectGrant extends Grant {
  id: number;
  authorizing_owner: string;
  bound_connections: number[];
  granted_at: number;
  name: string;
  // Made by a direct invitation (its receipt answers a direct recovery).
  direct: boolean;
}
export type GrantKind = 'provisional' | 'direct' | 'ticket';

interface Request {
  id: number;
  identity: string;
  name: string;
  role: string;
  firstPassed: number;
  // The attempt that passed; a recovery that moves the request keeps it.
  passed?: Uint8Array;
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
  // Identities that passed the code, kept until the invitation is forgotten.
  passed: Set<string>;
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
  // When the gate opened, in ms: its join-proof timer counts from here.
  openedAt: number;
  invitation?: string;
  name?: string;
  attempt?: Attempt;
  // The grant (provisional or committed) the connection is bound to.
  grant?: number;
  // Enrollment happened on this connection (10.8): a GOAWAY with CANCELLED removes its provisional grant.
  enrolled?: number;
  // The attempt that passed on this connection, when it was enrolled after a code exchange.
  enrolledAttempt?: Uint8Array;
}

const send = (conn: number, message: Control): DirectEffect => ({ conn, send: message });
const live = (grant: DirectGrant | undefined, now: number) =>
  grant && (grant.expires_at === null || grant.expires_at > now) ? grant : undefined;

export class DirectHost {
  // The grant table: each identity's grant, and beside it at most one provisional grant.
  readonly grants = new Map<string, DirectGrant>();
  readonly provisional = new Map<string, DirectGrant>();
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
      attemptsLeft: this.limits.hostAttempts, policy, status: 'open', requests: new Map(), outcomes: new Map(),
      passed: new Set() });
    return { invitation: id, code: code.code };
  }

  /** A grant made by a ticket pairing (10.8), stored as any grant is. */
  addTicketGrant(identity: Uint8Array, name: string, role: string, receipt: Uint8Array, now: number) {
    const key = hex(identity);
    requireThat(!this.grants.has(key), 'grant_exists');
    this.grants.set(key, { id: this.nextGrant++, identity: key, role, expires_at: null, enrolled_by: hex(receipt),
      authorizing_owner: this.policy.authorizingOwner, bound_connections: [], granted_at: now, name, direct: false });
  }

  /** The host restarts: invitations and connections are gone; the grant table, provisional grants included, stays. */
  restart() {
    this.invitations.clear();
    this.connections.clear();
    for (const grant of [...this.grants.values(), ...this.provisional.values()]) grant.bound_connections = [];
  }

  /** Every grant in the table with its kind. */
  grantTable(): Array<{ identity: string; name: string; role: string; kind: GrantKind }> {
    return [
      ...[...this.grants.values()].map(grant =>
        ({ identity: grant.identity, name: grant.name, role: grant.role, kind: grant.direct ? 'direct' : 'ticket' } as const)),
      ...[...this.provisional.values()].map(grant =>
        ({ identity: grant.identity, name: grant.name, role: grant.role, kind: 'provisional' } as const)),
    ];
  }

  /** An invitation takes lookups and new attempts while open and before expires_at. */
  private takesAttempts(invitation: Invitation, now: number) {
    return invitation.status === 'open' && now < invitation.expiresAt;
  }

  // Whether the invitation still takes anything: lookups, attempts, or a request's Allow or recovery.
  private takesAnything(invitation: Invitation, now: number) {
    return invitation.status === 'allowed' ||
      (invitation.status === 'open' && (now < invitation.expiresAt || this.waiting(invitation, now)));
  }

  // A request may be answered and claimed until its Allow window ends, whether or not the timer has run.
  private inWindow(request: Request, now: number) {
    return now < request.firstPassed + this.limits.allowWindowSecs;
  }

  private grantById(id: number | undefined) {
    if (id === undefined) return undefined;
    for (const grant of [...this.provisional.values(), ...this.grants.values()]) if (grant.id === id) return grant;
    return undefined;
  }

  private isProvisional(grant: DirectGrant | undefined) {
    return grant !== undefined && this.provisional.get(grant.identity) === grant;
  }

  private bind(conn: number, connection: Connection, grant: DirectGrant) {
    this.unbind(conn, connection);
    connection.grant = grant.id;
    grant.bound_connections.push(conn);
  }

  private unbind(conn: number, connection: Connection) {
    const grant = this.grantById(connection.grant);
    if (grant) grant.bound_connections = grant.bound_connections.filter(id => id !== conn);
    connection.grant = undefined;
  }

  /** Step 2 (section 8) and the HELLO the host sends. */
  connect(conn: number, peer: Uint8Array, exporters: Exporters, now: number, transport: 'tcp' | 'other' = 'tcp'): DirectEffect[] {
    requireThat(!this.connections.has(conn), 'connection_reused');
    const identity = hex(peer);
    const denied = this.denials.has(identity);
    const grant = denied ? undefined : live(this.provisional.get(identity), now) ?? live(this.grants.get(identity), now);
    const gate = new Gate('host', denied ? 'close:not_authorized' : grant ? 'live' : 'await_join_proof', now * 1000);
    const connection: Connection = { gate, peer, identity, exporters, tcp: transport === 'tcp',
      closed: false, held: false, sentJoin: false, openedAt: now * 1000 };
    this.connections.set(conn, connection);
    const output: DirectEffect[] = [send(conn, directHello)];
    if (denied) {
      connection.closed = true;
      output.push({ conn, close: 'not_authorized' });
    }
    if (grant) {
      this.bind(conn, connection, grant);
      output.push(send(conn, { type: 'AUTHORIZED', state: 'live' }));
    }
    return output;
  }

  private close(id: number, code: ErrorName): DirectEffect[] {
    const connection = this.connections.get(id);
    if (!connection || connection.closed) return [];
    this.shut(id, connection, code);
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

  private shut(id: number, connection: Connection, code: ErrorName) {
    connection.closed = true;
    connection.gate.close(code);
    this.stopAttempt(connection);
    this.unbind(id, connection);
  }

  // A grant-table change closes every connection still bound to `grant` (but `except`).
  private grantCloses(grant: DirectGrant, code: ErrorName, except?: number): DirectEffect[] {
    const conns = grant.bound_connections.filter(id => id !== except && !this.connections.get(id)?.closed);
    for (const id of conns) this.shut(id, this.connections.get(id)!, code);
    return conns.length ? [{ grant_closes: { grant: grant.id, code, conns } }] : [];
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

  // A request inside its Allow window, whether or not the timer has run.
  private waiting(invitation: Invitation, now: number) {
    return [...invitation.requests.values()].some(request => this.inWindow(request, now));
  }

  // No attempts left, none running and no request inside its Allow window: the invitation ends.
  private settle(invitation: Invitation, now: number): DirectEffect[] {
    if (invitation.status !== 'open' || invitation.attemptsLeft > 0 || this.running(invitation) ||
        this.waiting(invitation, now)) return [];
    return this.end(invitation, 'attempts_exhausted');
  }

  // What can fail before a provisional grant is made: a denied identity, a grant expiry not ahead.
  private refusal(identity: string, invitation: Invitation, now: number): 'denied' | 'grant_expired' | undefined {
    if (this.denials.has(identity)) return 'denied';
    const expiry = invitation.policy.grantExpiresAt;
    return expiry !== null && expiry <= now ? 'grant_expired' : undefined;
  }

  // Enrollment (10.8) with receipt I: a provisional grant beside the identity's grant, if any.
  private enroll(invitation: Invitation, request: Request, conn: number, now: number, role: string): DirectEffect[] {
    const connection = this.connections.get(conn)!;
    const output: DirectEffect[] = [];
    const grant: DirectGrant = { id: this.nextGrant++, identity: request.identity, role,
      expires_at: invitation.policy.grantExpiresAt, enrolled_by: invitation.key,
      authorizing_owner: invitation.policy.authorizingOwner, bound_connections: [], granted_at: now,
      name: request.name, direct: true };
    this.provisional.set(request.identity, grant);
    invitation.status = 'consumed';
    // The caller ends the other requests (10.8 step 5); the enrolled one has already ended.
    connection.gate.promote();
    this.bind(conn, connection, grant);
    connection.enrolled = grant.id;
    // The cancel exception holds for the attempt that passed, when it passed on this connection.
    if (connection.attempt && !connection.attempt.responder && request.passed &&
        equalBytes(connection.attempt.id, request.passed)) connection.enrolledAttempt = connection.attempt.id;
    this.stopAttempt(connection);
    output.push({ enrolled: { conn, grant: grant.id, identity: request.identity, role } },
      send(conn, { type: 'PAIRED', name: this.endpoint.name, role }));
    return output;
  }

  // Before a new provisional grant is made: detach the connection it is made on from any grant (it is never
  // closed), then remove an older provisional grant of the identity: its connections close, then the removal is
  // reported, also when no connection was bound.
  private replaceProvisional(identity: string, conn: number): DirectEffect[] {
    this.unbind(conn, this.connections.get(conn)!);
    const replaced = this.provisional.get(identity);
    if (!replaced) return [];
    this.provisional.delete(identity);
    return [...this.grantCloses(replaced, 'grant_revoked'),
      { enrollment_undone: { grant: replaced.id, identity: replaced.identity } }];
  }

  // Remove a provisional grant (the joiner's cancel): the cancelling connection closes with CANCELLED.
  private undo(grant: DirectGrant, conn: number | undefined): DirectEffect[] {
    this.provisional.delete(grant.identity);
    // Its other connections close before the removal is reported (10.9).
    const output: DirectEffect[] = [...this.grantCloses(grant, 'grant_revoked', conn),
      { enrollment_undone: { grant: grant.id, identity: grant.identity } }];
    if (conn !== undefined) output.push(...this.close(conn, 'cancelled'));
    return output;
  }

  // The provisional grant enrolled on this connection, while it is provisional.
  private enrolledProvisional(connection: Connection) {
    const grant = this.grantById(connection.enrolled);
    return this.isProvisional(grant) ? grant : undefined;
  }

  // The provisional grant this connection is bound to, while it is provisional.
  private boundProvisional(connection: Connection) {
    const grant = this.grantById(connection.grant);
    return this.isProvisional(grant) ? grant : undefined;
  }

  /** Commit a provisional grant (10.9 "Provisional grant"); the first stream frame waits for it. */
  private commit(conn: number, grant: DirectGrant, now: number): DirectEffect[] {
    if (this.denials.has(grant.identity) || !live(grant, now)) {
      // The grant's other connections close first, then the committing one, with GRANT_REVOKED (8.1).
      this.provisional.delete(grant.identity);
      return [...this.grantCloses(grant, 'grant_revoked', conn),
        { enrollment_undone: { grant: grant.id, identity: grant.identity } }, ...this.close(conn, 'grant_revoked')];
    }
    const output: DirectEffect[] = [];
    const old = this.grants.get(grant.identity);
    if (old) {
      this.grants.delete(grant.identity);
      output.push(...this.grantCloses(old, 'grant_revoked'));
    }
    this.provisional.delete(grant.identity);
    this.grants.set(grant.identity, grant);
    // Every connection bound to it is now live as any other (8.1).
    output.push({ committed: { conn, grant: grant.id, identity: grant.identity, bound: [...grant.bound_connections] } });
    return output;
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
    this.unbind(conn, connection);
    if (connection.closed) return [];
    connection.closed = true;
    this.stopAttempt(connection);
    if (code === 'cancelled') {
      const grant = this.enrolledProvisional(connection);
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
    return [...output, ...this.settle(invitation, now)];
  }

  drop(conn: number, now: number): DirectEffect[] { return this.lost(conn, now); }

  tick(now: number): DirectEffect[] {
    const output: DirectEffect[] = [];
    for (const invitation of this.invitations.values()) {
      for (const [identity, outcome] of invitation.outcomes) if (now >= outcome.until) invitation.outcomes.delete(identity);
      for (const request of [...invitation.requests.values()]) {
        if (this.inWindow(request, now)) continue;
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
        output.push(...this.settle(invitation, now));
      } else if (invitation.status === 'allowed' && invitation.requests.size === 0) {
        output.push(...this.end(invitation, 'invitation_invalid'));
      }
      // An ended invitation that keeps no outcome is forgotten, and with it who passed the code.
      if (!this.isOpen(invitation) && invitation.outcomes.size === 0) {
        invitation.status = 'gone';
        invitation.passed.clear();
      }
    }
    // Then the grant table: committed grants, then provisional ones, each in grant id order, are removed at
    // their expiry, their connections closing; then each expired provisional grant's removal is reported.
    const removed: DirectGrant[] = [];
    for (const table of [this.grants, this.provisional]) {
      for (const grant of [...table.values()].sort((x, y) => x.id - y.id)) {
        if (live(grant, now)) continue;
        table.delete(grant.identity);
        output.push(...this.grantCloses(grant, 'grant_revoked'));
        if (table === this.provisional) removed.push(grant);
      }
    }
    for (const grant of removed) output.push({ enrollment_undone: { grant: grant.id, identity: grant.identity } });
    return output;
  }

  // The 10 s wait for a JOIN_PROOF (section 8, step 2); it stops for a connection in the miss hold.
  private proofTimers(elapsed: (connection: Connection) => number): DirectEffect[] {
    const output: DirectEffect[] = [];
    for (const [id, connection] of this.connections) {
      if (connection.closed || connection.held) continue;
      const code = connection.gate.timeout(connection.openedAt + elapsed(connection));
      if (code) output.push({ proof_timeout: id }, ...this.close(id, code));
    }
    return output;
  }

  /** Every gate's join-proof timer runs `ms` milliseconds after its gate opened. */
  gateTimer(ms: number): DirectEffect[] {
    return this.proofTimers(() => ms);
  }

  private request(invitationId: Uint8Array, identity: Uint8Array, now: number) {
    const invitation = this.invitations.get(hex(invitationId));
    if (!invitation || invitation.status !== 'open') return { error: 'not_open' } as const;
    const request = invitation.requests.get(hex(identity));
    if (!request || !this.inWindow(request, now)) return { error: 'unknown_request' } as const;
    return { invitation, request };
  }

  /** The owner allows a request; `role` goes to this enrollment only. */
  allow(invitationId: Uint8Array, identity: Uint8Array, now: number, role?: string) {
    const found = this.request(invitationId, identity, now);
    if ('error' in found) return { result: found.error, effects: [] as DirectEffect[] };
    const { invitation, request } = found;
    const refused = this.refusal(request.identity, invitation, now);
    if (refused) return { result: refused, effects: [] as DirectEffect[] };
    if (request.conn === undefined) {
      request.decision = 'allowed';
      if (role !== undefined) request.role = role;
      invitation.status = 'allowed';
      const effects = [this.prompt(invitation, request), ...this.dismissOthers(invitation, 'invitation_invalid', request)];
      return { result: 'ok', effects };
    }
    // 10.8: enroll and send PAIRED, then end the other requests and close the other connections.
    const conn = request.conn;
    const effects = [...this.replaceProvisional(request.identity, conn), this.ended(invitation, request, 'enrolled'),
      ...this.enroll(invitation, request, conn, now, role ?? request.role),
      ...this.dismissOthers(invitation, 'invitation_invalid', request)];
    return { result: 'ok', effects };
  }

  decline(invitationId: Uint8Array, identity: Uint8Array, now: number) {
    const found = this.request(invitationId, identity, now);
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

  // The host's gate (8.1), with the two differences of a connection bound to a provisional grant.
  private gateCheck(connection: Connection, msg: Control | 'stream') {
    const { gate } = connection;
    if (gate.state === 'live' && this.boundProvisional(connection)) {
      if (msg === 'stream') return 'commit' as const;
      if (msg.type === 'CODE_ABORT' && connection.enrolledAttempt && this.enrolledProvisional(connection) &&
          equalBytes(connection.enrolledAttempt, msg.attempt)) return 'allow' as const;
    }
    return gate.check(msg === 'stream' ? 'stream' : trafficOf(msg));
  }

  /** The joiner opens a stream on conn: the gate's verdict, and "commit first" while provisional. */
  stream(conn: number, now: number): DirectEffect[] {
    const connection = this.connections.get(conn);
    // A closed connection, or one in the miss hold, lets no stream frame through and commits nothing.
    if (!connection || connection.closed || connection.held) return [{ stream: { conn, verdict: 'ignore' } }];
    const verdict = this.gateCheck(connection, 'stream');
    if (verdict === 'commit') {
      const output: DirectEffect[] = [{ stream: { conn, verdict } },
        ...this.commit(conn, this.boundProvisional(connection)!, now)];
      // Committed: the I/O layer releases the frame.
      if (!connection.closed) connection.gate.check('stream');
      return output;
    }
    if (verdict === 'allow' || verdict === 'ignore') return [{ stream: { conn, verdict } }];
    return this.close(conn, verdict.slice(6) as ErrorName);
  }

  receive(conn: number, msg: Control, now: number): DirectEffect[] {
    const connection = this.connections.get(conn);
    if (!connection || connection.closed || connection.held) return [{ ignored: true }];
    const { gate } = connection;
    if (gate.version === undefined && msg.type !== 'HELLO') return this.close(conn, 'protocol_error');
    const verdict = this.gateCheck(connection, msg);
    if (verdict === 'ignore') return [{ gate: { conn, verdict } }];
    if (verdict === 'commit') return [];
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
      case 'CODE_ABORT': return this.codeAbort(conn, connection, msg, now);
      default: return this.close(conn, 'protocol_error');
    }
  }

  private missHold(conn: number, connection: Connection): DirectEffect[] {
    connection.held = true;
    return [{ miss_hold: { conn, hold_ms: this.limits.missHoldMs } }];
  }

  private admit(conn: number, connection: Connection, invitation: Invitation, name: string, notReceived = false) {
    connection.gate.admit();
    // A join-only connection is bound to no grant.
    this.unbind(conn, connection);
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

  // Rule 1: a provisional or committed grant of this identity, made by a direct invitation, with receipt I.
  private receiptGrant(identity: string, receipt: string, now: number) {
    for (const grant of [this.provisional.get(identity), this.grants.get(identity)]) {
      if (live(grant, now) && grant!.direct && grant!.enrolled_by === receipt) return grant;
    }
    return undefined;
  }

  private recover(conn: number, connection: Connection,
    msg: Extract<Control, { type: 'JOIN_DIRECT' }> & { receipt: Uint8Array }, now: number): DirectEffect[] {
    const key = hex(msg.receipt);
    // 1. A grant from this direct invitation (also after a restart).
    const grant = this.receiptGrant(connection.identity, key, now);
    if (grant) {
      const provisional = this.isProvisional(grant);
      if (msg.cancel && provisional) return this.undo(grant, conn);
      const output: DirectEffect[] = [];
      if (connection.grant !== grant.id) {
        const notice = connection.gate.state !== 'live';
        this.bind(conn, connection, grant);
        output.push({ bound: { conn, grant: grant.id, provisional } });
        if (notice) {
          connection.gate.state = 'live';
          output.push(send(conn, { type: 'AUTHORIZED', state: 'live' }));
        }
      }
      return [...output, send(conn, { type: 'PAIRED', name: this.endpoint.name, role: grant.role })];
    }
    // 2. No direct invitation I with this L.
    const invitation = this.invitations.get(key);
    if (!invitation || invitation.status === 'gone' || invitation.code.lookup !== msg.lookup) {
      return this.missHold(conn, connection);
    }
    const found = invitation.requests.get(connection.identity);
    const request = found && this.inWindow(found, now) ? found : undefined;
    // From here on, with the cancel flag: retire this identity's attempts and pairing connections first,
    // whatever the answer, so a confirmation on its way opens nothing.
    const retired: DirectEffect[] = [];
    if (msg.cancel) {
      for (const [id, other] of this.connections) {
        if (id === conn || other.closed || other.identity !== connection.identity ||
            other.invitation !== invitation.key || other.gate.state !== 'join_only') continue;
        if (found?.conn === id) found.conn = undefined;
        retired.push(...this.close(id, 'cancelled'));
      }
    }
    // 3. A kept outcome for this identity.
    const outcome = invitation.outcomes.get(connection.identity);
    if (outcome && now < outcome.until) {
      // With the cancel flag, an invitation its retirements leave with nothing to take then ends, as in 4.
      return [...retired, ...this.close(conn, outcome.code), ...(msg.cancel ? this.settle(invitation, now) : [])];
    }
    // 4. The cancel flag.
    if (msg.cancel) {
      if (!this.takesAnything(invitation, now)) return [...retired, ...this.missHold(conn, connection)];
      const output = retired;
      if (request) output.push(...this.cancelRequest(invitation, request));
      return [...output, ...this.close(conn, 'cancelled'), ...this.settle(invitation, now)];
    }
    // 5. Its request is allowed: enroll on this connection (the claim checks what can fail first).
    if (request && request.decision === 'allowed' && invitation.status === 'allowed') {
      if (this.refusal(request.identity, invitation, now)) {
        // Nothing is sent before the close; then the invitation ends.
        return [...this.close(conn, 'invitation_invalid'), ...this.end(invitation, 'invitation_invalid')];
      }
      return [...this.admit(conn, connection, invitation, msg.name),
        ...this.replaceProvisional(request.identity, conn), this.ended(invitation, request, 'enrolled'),
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
    // 7. The invitation takes attempts and this identity never passed the code on it.
    if (!invitation.passed.has(connection.identity) && this.takesAttempts(invitation, now)) {
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
        return [abort, ...this.settle(invitation, now)];
      }
      return this.passed(conn, connection, invitation, now);
    }
    if (!this.takesAttempts(invitation, now)) return this.close(conn, 'invitation_invalid');
    if (attempt) return this.close(conn, 'protocol_error');
    if (invitation.attemptsLeft === 0) return [...this.close(conn, 'attempts_exhausted'), ...this.settle(invitation, now)];
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
      output.push(abort, ...this.settle(invitation, now));
    } finally { inputs.prs.fill(0); }
    return output;
  }

  // The joiner's confirmation verified: the device passed the code.
  private passed(conn: number, connection: Connection, invitation: Invitation, now: number): DirectEffect[] {
    invitation.passed.add(connection.identity);
    const output: DirectEffect[] = [];
    const attempt = Uint8Array.from(connection.attempt!.id);
    const existing = invitation.requests.get(connection.identity);
    if (existing) {
      existing.passed = attempt;
      const old = existing.conn;
      existing.conn = conn;
      if (old !== undefined && old !== conn) output.push(...this.close(old, 'path_replaced'));
      if (old === undefined) output.push(this.prompt(invitation, existing));
      return output;
    }
    invitation.outcomes.delete(connection.identity);
    const request: Request = { id: this.nextRequest++, identity: connection.identity, name: connection.name!,
      role: invitation.policy.role, firstPassed: now, passed: attempt, conn, decision: 'pending' };
    invitation.requests.set(request.identity, request);
    return [this.prompt(invitation, request)];
  }

  private codeAbort(conn: number, connection: Connection, msg: Extract<Control, { type: 'CODE_ABORT' }>,
    now: number): DirectEffect[] {
    // Cancel crossing Allow: the provisional grant enrolled here after this attempt passed.
    const enrolled = this.enrolledProvisional(connection);
    if (enrolled) return msg.code === errorNumber('cancelled') ? this.undo(enrolled, conn) : [];
    const invitation = this.invitations.get(connection.invitation!)!;
    // Only the attempt that passed, the one the request remembers, ends a waiting request.
    const request = [...invitation.requests.values()].find(r => r.conn === conn);
    if (msg.code === errorNumber('cancelled') && request?.passed && equalBytes(request.passed, msg.attempt)) {
      request.conn = undefined;
      return [...this.cancelRequest(invitation, request), ...this.close(conn, 'cancelled')];
    }
    // An abort of an attempt merely running here stops that attempt and nothing else.
    const attempt = connection.attempt;
    if (!attempt || !equalBytes(attempt.id, msg.attempt) || !attempt.responder) return [];
    this.stopAttempt(connection);
    return this.settle(invitation, now);
  }

  snapshot(invitationId: Uint8Array) {
    const invitation = this.invitations.get(hex(invitationId));
    if (!invitation) return { status: 'gone' as DirectStatus, attempts_left: undefined, requests: [] };
    return {
      status: invitation.status,
      attempts_left: invitation.attemptsLeft,
      code: invitation.code.code,
      requests: [...invitation.requests.values()].map(request =>
        [request.identity, request.conn === undefined ? 'away' : 'connected', request.decision]),
    };
  }
}
