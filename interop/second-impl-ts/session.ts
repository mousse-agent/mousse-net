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
  constructor(side: 'host' | 'caller') { this.side = side; }

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
      const result = this.streamFrame(frame, true);
      if (!('close' in result)) return result;
      this.end();
      return { reply: { type: 'goaway', code: errorNumber(result.close) } };
    }
    if (frame.type === 'ping') return { reply: { type: 'pong', opaque: frame.opaque } };
    if (frame.type === 'goaway') this.end();
    return {};
  }

  sent(frame: Frame): void {
    if (this.closed) return;
    if ('stream' in frame) {
      const result = this.streamFrame(frame, false);
      if ('close' in result) throw new Error(result.close);
    }
    if (frame.type === 'goaway') this.end();
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
