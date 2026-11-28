import { requireThat } from './cbor.ts';
import type { UInt } from './cbor.ts';
import { errorNumber, hello, negotiate } from './wire.ts';
import type { ErrorName, Frame, Version } from './wire.ts';

export interface Grant { identity: string; expires_at: number | null; role: string; enrolled_by?: string }
type Verdict = 'allow' | 'ignore' | `close:${ErrorName}`;
// A Pair with IP first contact (unpinned): pairing only until promoteDirect.
type PairingOnlyStep = 'awaiting_answer' | 'notice_seen' | 'join_only' | 'paired';
type GateState = 'await_join_proof' | 'awaiting_authorization' | 'awaiting_proof_answer' |
  'join_only' | 'live' | `pairing_only:${PairingOnlyStep}` | `closed:${ErrorName}`;
// `join_direct` is a JOIN_DIRECT received by the host: the JOIN_PROOF rows.
export type Traffic = 'hello' | 'keepalive' | 'goaway' | 'stream' | 'paired' | 'pairing' |
  'join_proof' | 'join_direct' | 'authorized_live' | 'authorized_join_only' | 'host_only' | 'caller_only';

function liveGrant(peer: string, grants: Iterable<Grant>, now: number) {
  const grant = new Map(Array.from(grants, grant => [grant.identity, grant])).get(peer);
  return grant && (grant.expires_at === null || grant.expires_at > now) ? grant : undefined;
}

export function step2(peer: string, grants: Iterable<Grant>, denied: Iterable<string>, now: number) {
  if (new Set(denied).has(peer)) return 'close:not_authorized';
  return liveGrant(peer, grants, now) ? 'live' : 'await_join_proof';
}

export class Gate {
  state: GateState;
  readonly side: 'host' | 'caller';
  private readonly start: number;
  private agreed?: UInt;
  private proofUsed = false;
  private proofSentAt?: number;
  private streamSeen = false;
  private callerOpened = false;
  constructor(side: 'host' | 'caller', initial?: ReturnType<typeof step2>, start = 0) {
    this.side = side;
    this.start = start;
    this.state = side === 'caller' ? 'awaiting_authorization' :
      initial === 'close:not_authorized' ? 'closed:not_authorized' : initial ?? 'await_join_proof';
  }

  close(code: ErrorName): Verdict {
    this.state = `closed:${code}`;
    return `close:${code}`;
  }

  get version() { return this.agreed; }

  /** Whether the connection has carried any stream frame. */
  get carriedStream() { return this.streamSeen; }

  receiveHello(peer: Version, local: Version = hello): UInt | 'ignored' | 'close:unsupported_version' {
    if (this.agreed !== undefined || this.state.startsWith('closed:')) return 'ignored';
    try {
      this.agreed = negotiate(local, peer);
      return this.agreed;
    } catch {
      this.close('unsupported_version');
      return 'close:unsupported_version';
    }
  }

  admit() {
    requireThat(this.state === 'await_join_proof' || (this.state === 'live' && this.proofUsed), 'protocol_error');
    this.proofUsed = true;
    this.state = 'join_only';
  }

  promote() {
    requireThat(this.state === 'join_only', 'protocol_error');
    this.state = 'live';
  }

  /** A caller gate for an unpinned Pair with IP connection. */
  static pairingOnly(): Gate {
    const gate = new Gate('caller');
    gate.state = 'pairing_only:awaiting_answer';
    gate.proofUsed = true;
    return gate;
  }

  /** The pairing layer verified the host's confirmation and accepted PAIRED. */
  promoteDirect() {
    if (this.state === 'pairing_only:paired') this.state = 'live';
  }

  timeout(now: number): ErrorName | null {
    const since = this.state === 'await_join_proof' ? this.start : this.proofSentAt;
    if (this.state.startsWith('closed:') || since === undefined || now - since < 10000) return null;
    this.close('not_authorized');
    return 'not_authorized';
  }

  sentJoinProof(now: number) {
    requireThat(this.side === 'caller' && !this.proofUsed && !this.streamSeen &&
      (this.state === 'awaiting_authorization' || this.state === 'live'), 'protocol_error');
    this.proofUsed = true;
    this.proofSentAt = now;
    if (this.state === 'live') this.state = 'awaiting_proof_answer';
  }

  canOpenStream(side: 'host' | 'caller') {
    return this.state === 'live' && (side === 'caller' || this.callerOpened);
  }

  hostStreamRole(host: string, localGrants: Iterable<Grant>, denied: Iterable<string>, now: number) {
    if (this.side !== 'caller' || this.state !== 'live' || new Set(denied).has(host)) return undefined;
    return liveGrant(host, localGrants, now)?.role;
  }

  openedStream(side: 'host' | 'caller') {
    this.streamSeen = true;
    if (side === 'caller') this.callerOpened = true;
  }

  check(traffic: Traffic): Verdict {
    if (this.state.startsWith('closed:')) return 'ignore';
    if (traffic === 'keepalive' || traffic === 'hello' || traffic === 'goaway') return 'allow';

    if (this.side === 'host') {
      switch (traffic === 'join_direct' ? 'join_proof' : traffic) {
        case 'stream':
          if (this.state !== 'live') return this.close('not_authorized');
          this.streamSeen = true;
          return 'allow';
        case 'join_proof':
          if (this.proofUsed || this.streamSeen || (this.state !== 'await_join_proof' && this.state !== 'live')) {
            return this.close('protocol_error');
          }
          this.proofUsed = true;
          return 'allow';
        case 'pairing':
          if (this.state === 'join_only') return 'allow';
          return this.state === 'live' ? 'ignore' : this.close('not_authorized');
        default: return this.close('protocol_error');
      }
    }

    if (this.state.startsWith('pairing_only:')) {
      const step = this.state.slice('pairing_only:'.length) as PairingOnlyStep;
      const next: Partial<Record<Traffic, PairingOnlyStep>> = {
        awaiting_answer: { authorized_live: 'notice_seen', authorized_join_only: 'join_only' },
        notice_seen: { authorized_join_only: 'join_only' },
        join_only: { pairing: 'join_only', paired: 'paired' },
        paired: {},
      }[step] as Partial<Record<Traffic, PairingOnlyStep>>;
      // A late code-exchange message after PAIRED means nothing.
      if (step === 'paired' && traffic === 'pairing') return 'ignore';
      const to = next[traffic];
      if (to === undefined) return this.close('protocol_error');
      this.state = `pairing_only:${to}`;
      return 'allow';
    }

    switch (traffic) {
      case 'authorized_live':
      case 'authorized_join_only':
        if (this.state === 'awaiting_authorization' && traffic === 'authorized_live' && this.proofSentAt !== undefined) {
          this.state = 'awaiting_proof_answer';
          return 'allow';
        }
        if (this.state !== 'awaiting_authorization' && this.state !== 'awaiting_proof_answer') {
          return this.close('protocol_error');
        }
        this.proofSentAt = undefined;
        this.state = traffic === 'authorized_live' ? 'live' : 'join_only';
        return 'allow';
      case 'stream':
        if (this.state !== 'live') return this.close('protocol_error');
        this.streamSeen = true;
        return 'allow';
      case 'paired':
        if (this.state === 'awaiting_proof_answer') {
          this.proofSentAt = undefined;
          this.state = 'live';
          return 'allow';
        }
        return this.state === 'join_only' ? 'allow' : this.close('protocol_error');
      case 'pairing':
        if (this.state === 'join_only') return 'allow';
        return this.state === 'live' ? 'ignore' : this.close('protocol_error');
      default: return this.close('protocol_error');
    }
  }
}

const initialCredit = 262144;
const creditThreshold = 65536;
const maximumCredit = 2 ** 30;
type Direction = { remaining: number; finished: boolean };
interface Stream {
  peerOpened: boolean;
  send: Direction;
  receive: Direction;
  unread: number;
  consumed: number;
}

type StreamEvent = Extract<Frame, { type: 'open' | 'data' | 'fin' | 'reset' }>;
type Receipt = { event?: StreamEvent; reply?: Frame };
type StreamResult = Receipt | { close: ErrorName };

export class Streams {
  private readonly active = new Map<number, Stream>();
  private highestPeer = 0;
  private highestLocal = 0;
  private peerCount = 0;
  private closed = false;
  private readonly side: 'host' | 'caller';
  private readonly gate?: Gate;
  constructor(side: 'host' | 'caller', gate?: Gate) {
    requireThat(gate === undefined || gate.side === side, 'protocol_error');
    this.side = side;
    this.gate = gate;
  }

  private forget(id: number, stream: Stream) {
    if (stream.peerOpened) this.peerCount--;
    this.active.delete(id);
  }

  private open(frame: Extract<Frame, { type: 'open' }>, peer: boolean): StreamResult {
    const id = frame.stream;
    const first = (this.side === 'caller') !== peer ? 1 : 2;
    const highest = peer ? this.highestPeer : this.highestLocal;
    const expected = highest === 0 ? first : highest + 2;
    if (id !== expected || id > 0xffffffff) {
      return { close: 'protocol_error' };
    }
    if (peer) this.highestPeer = id;
    else this.highestLocal = id;
    if (peer && this.peerCount === 1024) {
      return { reply: { type: 'reset', stream: id, code: errorNumber('refused_stream') } };
    }
    if (peer) this.peerCount++;
    this.active.set(id, {
      peerOpened: peer,
      send: { remaining: initialCredit, finished: false },
      receive: { remaining: initialCredit, finished: false },
      unread: 0, consumed: 0,
    });
    return { event: frame };
  }

  private streamFrame(frame: Extract<Frame, { stream: number }>, incoming: boolean): StreamResult {
    if (frame.type === 'open') return this.open(frame, incoming);
    const stream = this.active.get(frame.stream);
    if (!stream) {
      const openedByCaller = frame.stream % 2 === 1;
      const highest = openedByCaller === (this.side === 'caller') ? this.highestLocal : this.highestPeer;
      return frame.stream > 0 && frame.stream <= highest ? {} : { close: 'protocol_error' };
    }
    const same = incoming ? stream.receive : stream.send;
    const opposite = incoming ? stream.send : stream.receive;
    switch (frame.type) {
      case 'data':
        if (same.finished) return { close: 'stream_closed' };
        if (frame.payload.length > same.remaining) return { close: 'flow_control' };
        same.remaining -= frame.payload.length;
        if (incoming) stream.unread += frame.payload.length;
        return { event: frame };
      case 'fin':
        if (same.finished) return { close: 'stream_closed' };
        same.finished = true;
        if (opposite.finished) this.forget(frame.stream, stream);
        return { event: frame };
      case 'reset':
        this.forget(frame.stream, stream);
        return { event: frame };
      case 'credit':
        if (opposite.remaining + frame.increment > maximumCredit) return { close: 'flow_control' };
        opposite.remaining += frame.increment;
        return {};
    }
  }

  receive(frame: Frame): Receipt {
    if (this.closed) return {};
    if ('stream' in frame) {
      const peer = this.side === 'host' ? 'caller' : 'host';
      if (this.gate) {
        const verdict = this.gate.check('stream');
        if (verdict === 'ignore') return {};
        if (verdict !== 'allow') return this.protocolClose(verdict.slice(6) as ErrorName);
        if (frame.type === 'open' && !this.gate.canOpenStream(peer)) return this.protocolClose('protocol_error');
      }
      const result = this.streamFrame(frame, true);
      if ('close' in result) return this.protocolClose(result.close);
      if (result.event?.type === 'open') this.gate?.openedStream(peer);
      return result;
    }
    if (frame.type === 'ping') return { reply: { type: 'pong', opaque: frame.opaque } };
    if (frame.type === 'goaway') this.end();
    return {};
  }

  sent(frame: Frame): void {
    if (this.closed) return;
    if ('stream' in frame) {
      requireThat(!this.gate || this.gate.state === 'live', 'not_authorized');
      if (frame.type === 'open') requireThat(!this.gate || this.gate.canOpenStream(this.side), 'protocol_error');
      const result = this.streamFrame(frame, false);
      if ('close' in result) throw new Error(result.close);
      if (result.event?.type === 'open') this.gate?.openedStream(this.side);
    }
    if (frame.type === 'goaway') this.end();
  }

  private protocolClose(code: ErrorName): Receipt {
    this.gate?.close(code);
    this.end();
    return { reply: { type: 'goaway', code: errorNumber(code) } };
  }

  private end() {
    this.closed = true;
    this.active.clear();
  }

  consume(id: number, count: number): Frame | undefined {
    const stream = this.active.get(id);
    if (!stream) return;
    requireThat(Number.isSafeInteger(count) && count >= 0 && count <= stream.unread, 'flow_control');
    stream.unread -= count;
    stream.consumed += count;
    if (!stream.receive.finished && stream.consumed >= creditThreshold) {
      const frame = { type: 'credit', stream: id, increment: stream.consumed } as const;
      this.sent(frame);
      stream.consumed = 0;
      return frame;
    }
  }
}
