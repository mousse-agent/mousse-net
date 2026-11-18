import { requireThat } from './cbor.ts';
import { errorNumber } from './wire.ts';
import type { ErrorName, Frame } from './wire.ts';

export interface Grant { identity: string; expires_at: number | null; role: string }
type Verdict = 'allow' | 'ignore' | `close:${ErrorName}`;
type GateState = 'await_join_proof' | 'awaiting_authorization' | 'join_only' | 'live' | `closed:${ErrorName}`;
export type Traffic = 'hello' | 'keepalive' | 'goaway' | 'stream' | 'paired' | 'pairing' |
  'join_proof' | 'authorized_live' | 'authorized_join_only' | 'host_only' | 'caller_only';

export function step2(peer: string, grants: Iterable<Grant>, denied: Iterable<string>, now: number) {
  if (new Set(denied).has(peer)) return 'close:not_authorized';
  const grant = new Map(Array.from(grants, grant => [grant.identity, grant])).get(peer);
  return grant && (grant.expires_at === null || grant.expires_at > now) ? 'live' : 'await_join_proof';
}

export class Gate {
  state: GateState;
  readonly side: 'host' | 'caller';
  private readonly start: number;
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

  admit() {
    requireThat(this.state === 'await_join_proof', 'protocol_error');
    this.state = 'join_only';
  }

  promote() {
    requireThat(this.state === 'join_only', 'protocol_error');
    this.state = 'live';
  }

  timeout(now: number): ErrorName | null {
    if (this.state !== 'await_join_proof' || now - this.start < 10000) return null;
    this.close('not_authorized');
    return 'not_authorized';
  }

  check(traffic: Traffic): Verdict {
    if (this.state.startsWith('closed:')) return 'ignore';
    if (traffic === 'keepalive' || traffic === 'hello' || traffic === 'goaway') return 'allow';

    if (this.side === 'host') {
      switch (traffic) {
        case 'stream': return this.state === 'live' ? 'allow' : this.close('not_authorized');
        case 'join_proof':
          if (this.state === 'await_join_proof') return 'allow';
          return this.state === 'live' ? 'ignore' : this.close('protocol_error');
        case 'pairing':
          if (this.state === 'join_only') return 'allow';
          return this.state === 'live' ? 'ignore' : this.close('not_authorized');
        default: return this.close('protocol_error');
      }
    }

    switch (traffic) {
      case 'authorized_live':
      case 'authorized_join_only':
        if (this.state !== 'awaiting_authorization') return this.close('protocol_error');
        this.state = traffic === 'authorized_live' ? 'live' : 'join_only';
        return 'allow';
      case 'stream': return this.state === 'live' ? 'allow' : this.close('protocol_error');
      case 'paired': return this.state === 'join_only' ? 'allow' : this.close('protocol_error');
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

export class Streams {
  private readonly active = new Map<number, Stream>();
  private readonly opened = new Set<number>();
  private highestPeer = 0;
  private highestLocal = 0;
  private peerCount = 0;
  private readonly side: 'host' | 'caller';
  constructor(side: 'host' | 'caller') { this.side = side; }

  private forget(id: number, stream: Stream) {
    if (stream.peerOpened) this.peerCount--;
    this.active.delete(id);
  }

  private open(id: number, peer: boolean): Frame | undefined {
    const parity = (this.side === 'caller') !== peer ? 1 : 0;
    requireThat(id > (peer ? this.highestPeer : this.highestLocal) && id % 2 === parity, 'protocol_error');
    if (peer) this.highestPeer = id;
    else this.highestLocal = id;
    this.opened.add(id);
    if (peer && this.peerCount === 1024) return { type: 'reset', stream: id, code: errorNumber('refused_stream') };
    if (peer) this.peerCount++;
    this.active.set(id, {
      peerOpened: peer,
      send: { remaining: initialCredit, finished: false },
      receive: { remaining: initialCredit, finished: false },
      unread: 0, consumed: 0,
    });
  }

  private streamFrame(frame: Extract<Frame, { stream: number }>, incoming: boolean): Frame | undefined {
    if (frame.type === 'open') return this.open(frame.stream, incoming);
    requireThat(this.opened.has(frame.stream), 'protocol_error');
    const stream = this.active.get(frame.stream);
    if (!stream) return;
    const same = incoming ? stream.receive : stream.send;
    const opposite = incoming ? stream.send : stream.receive;
    switch (frame.type) {
      case 'data':
        requireThat(!same.finished, 'stream_closed');
        requireThat(frame.payload.length <= same.remaining, 'flow_control');
        same.remaining -= frame.payload.length;
        if (incoming) stream.unread += frame.payload.length;
        break;
      case 'fin':
        requireThat(!same.finished, 'stream_closed');
        same.finished = true;
        if (opposite.finished) this.forget(frame.stream, stream);
        break;
      case 'reset':
        this.forget(frame.stream, stream);
        break;
      case 'credit':
        requireThat(opposite.remaining + frame.increment <= maximumCredit, 'flow_control');
        opposite.remaining += frame.increment;
        break;
    }
  }

  receive(frame: Frame): Frame | undefined {
    if ('stream' in frame) return this.streamFrame(frame, true);
    if (frame.type === 'ping') return { type: 'pong', opaque: frame.opaque };
  }

  sent(frame: Frame): void {
    if ('stream' in frame) this.streamFrame(frame, false);
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
