import assert from 'node:assert/strict';
import { bytes, hex } from './cbor.ts';
import { publicKey, sha256 } from './certificate.ts';
import { PairingHost, PairingJoiner } from './pairing.ts';
import { decodeControl, decodeFrame, decodeTicket, encodeControl, encodeFragment, encodeFrame, errorNumber,
  readError } from './wire.ts';

class ScriptedDraws {
  #offset = 0;
  constructor(draws) { this.draws = draws; }
  take(purpose) {
    const draw = this.draws[this.#offset++];
    assert.ok(draw, `unexpected random draw for ${purpose}`);
    if (draw.use !== undefined) assert.equal(draw.use, purpose, 'random draw order');
    return draw;
  }
  bytes(length, purpose) {
    const draw = this.take(purpose);
    assert.equal(typeof draw.bytes, 'string');
    const value = bytes(draw.bytes);
    assert.equal(value.length, length);
    return value;
  }
  u32(purpose) {
    const draw = this.take(purpose);
    assert.equal(typeof draw.u32, 'number');
    return draw.u32;
  }
  done() { assert.equal(this.#offset, this.draws.length, 'unused random draws'); }
}

const parseExporters = ({ join, pair }) => ({ join: bytes(join), pair: bytes(pair) });

function incoming(frame) {
  const { frame: decoded, read } = decodeFrame(frame);
  assert.equal(read, frame.length);
  return decoded;
}

function onWire(control) {
  const encoded = encodeControl(control);
  return decodeControl(incoming(encodeFrame({ type: 'control', payload: encoded })).payload);
}

export function replayEndToEnd(flow, input) {
  const { time: now, host: hostInput, joiner: joinerInput, invitation } = input;
  const hostEndpoint = { identity: publicKey(bytes(hostInput.identity_secret)), name: hostInput.name };
  const joinerEndpoint = { identity: publicKey(bytes(joinerInput.identity_secret)), name: joinerInput.name };
  assert.equal(hex(hostEndpoint.identity), hostInput.identity);
  assert.equal(hex(joinerEndpoint.identity), joinerInput.identity);
  const policy = { authorizingOwner: invitation.authorizing_owner, grantExpiresAt: invitation.grant_expires_at,
    role: invitation.role, routes: invitation.routes };
  const hostDraws = new ScriptedDraws(flow.draws.host);
  const joinerDraws = new Map(Object.entries(flow.draws.joiners).map(([name, draws]) => [name, new ScriptedDraws(draws)]));
  const joiners = new Map();
  const routes = new Map();
  const parties = new Map();
  const frames = new Map();
  let host;

  function queue(from, conn, frame) {
    const route = routes.get(conn);
    if (!route.real) return;
    const to = from === 'host' ? route.party : 'host';
    const key = `${conn}/${to}`;
    const list = frames.get(key) ?? [];
    list.push(frame);
    frames.set(key, list);
  }

  function project(effects, from) {
    return effects.map(effect => {
      if ('send' in effect) {
        const { conn, send } = effect;
        const payload = encodeControl(send);
        const frame = encodeFrame({ type: 'control', payload });
        queue(from, conn, frame);
        return { send: { conn, control: hex(payload), frame: hex(frame), from, type: send.type } };
      }
      if ('close' in effect) {
        const { close: code, conn } = effect;
        const frame = encodeFrame({ type: 'goaway', code: errorNumber(code) });
        queue(from, conn, frame);
        return { close: { code, conn, frame: hex(frame), from } };
      }
      return effect;
    });
  }

  function receive(party, conn, provided) {
    if (!routes.get(conn).real) return decodeControl(bytes(provided));
    const frame = frames.get(`${conn}/${party}`)?.shift();
    assert.ok(frame, 'no matching outbound frame');
    const message = incoming(frame);
    assert.equal(message.type, 'control');
    assert.equal(hex(message.payload), provided, 'inbound fixture bytes');
    return decodeControl(message.payload);
  }

  function run(step) {
    const { party, event } = step;
    const joiner = joiners.get(party);
    const conn = step.conn ?? parties.get(party);
    switch (event) {
      case 'create': {
        assert.equal(step.kind, flow.kind);
        host = new PairingHost(hostEndpoint, policy, step.kind, hostDraws, now);
        return [{ ticket: { binary: hex(host.binary), fragment: encodeFragment(host.binary),
          hash: hex(sha256(host.binary)), shown_code: host.shownCode } }];
      }
      case 'start': {
        assert.ok(step.host_pinned === undefined || typeof step.host_pinned === 'boolean');
        const ticket = bytes(step.ticket);
        const pinnedHost = step.host_pinned ? decodeTicket(ticket).hostIdentity : undefined;
        joiners.set(party, new PairingJoiner(joinerEndpoint, ticket, joinerDraws.get(party), now, pinnedHost));
        return [];
      }
      case 'connect': {
        const real = step.host !== false;
        routes.set(conn, { party, real });
        parties.set(party, conn);
        const exporters = parseExporters(step.exporters);
        const [hello, proof] = project(joiner.connect(conn, exporters, now), party);
        const peer = real ? project(
          host.connect(conn, joinerEndpoint.identity, parseExporters(step.host_exporters ?? step.exporters), now), 'host') : [];
        return [hello, ...peer, proof];
      }
      case 'receive': {
        const control = receive(party, conn, step.control);
        if (party === 'host') return project(host.receive(conn, control, now), party);
        return project(joiner.receive(control), party);
      }
      case 'drop':
        joiner.drop();
        frames.delete(`${conn}/${party}`);
        frames.delete(`${conn}/host`);
        return routes.get(conn).real ? project(host.drop(conn), 'host') : [];
      case 'submit_code':
        return project(joiner.submit(step.code), party);
      case 'approve':
        return project(host.approve(conn, now), party);
      case 'goaway': {
        const frame = frames.get(`${conn}/${party}`)?.shift();
        assert.ok(frame);
        const message = incoming(frame);
        assert.equal(message.type, 'goaway');
        assert.equal(readError(message.code), step.code);
        return project(joiner.goaway(readError(message.code)), party);
      }
      default:
        assert.fail(`unknown event ${event}`);
    }
  }

  for (const [index, step] of flow.steps.entries()) {
    const effects = run(step);
    const label = `step ${index + 1} ${step.party}/${step.event}`;
    assert.deepEqual(effects, step.out, label);
    if (effects.some(effect => 'failed' in effect)) {
      const message = onWire({ type: 'AUTHORIZED', state: 'live' });
      assert.deepEqual(joiners.get(step.party).receive(message), [{ ignored: true }], `${label}: gate after failure`);
    }
  }
  for (const pending of frames.values()) assert.equal(pending.length, 0, 'undelivered frame');
  hostDraws.done();
  for (const draws of joinerDraws.values()) draws.done();
  assert.deepEqual({
    host: host.snapshot(),
    joiners: Object.fromEntries([...joiners].map(([party, joiner]) => [party, joiner.snapshot()])),
    grants: [...host.grants.values()],
  }, flow.end);
}

export function replayAttemptSequence(sequence, input) {
  const { time: now, host: hostInput, invitation } = input;
  const hostEndpoint = { name: hostInput.name, identity: publicKey(bytes(hostInput.identity_secret)) };
  const draws = new Map(Object.entries(sequence.draws).map(([name, script]) => [name, new ScriptedDraws(script)]));
  const host = new PairingHost(hostEndpoint, { authorizingOwner: invitation.authorizing_owner,
    grantExpiresAt: invitation.grant_expires_at, routes: invitation.routes, role: invitation.role },
  sequence.kind === 'in_person' ? 1 : 2, draws.get('host'), now);
  assert.equal(hex(host.binary), sequence.ticket);
  const joiners = new Map();
  const connections = new Map();
  const firstMessages = new Map();
  let lastCode;

  function apply(step) {
    const { conn, joiner: label, op } = step;
    const out = [];
    const closed = [];
    let result;
    let reply;
    const recordSend = (from, id, message) => {
      out.push({ send: { conn: id, from, control: hex(encodeControl(message)) } });
    };

    function receiveAtHost(id, message, deliver = true) {
      const effects = host.receive(id, onWire(message), now);
      fromHost(effects, deliver);
      return effects.flatMap(effect => effect.send ? [hex(encodeControl(effect.send))] : []);
    }

    function toHost(from, id, message, deliver = true) {
      recordSend(from, id, message);
      return receiveAtHost(id, message, deliver);
    }

    function fromHost(effects, deliver = true) {
      for (const effect of effects) {
        if (effect.send) {
          const { conn: id, send } = effect;
          recordSend('host', id, send);
          if (deliver) {
            const { label, joiner } = connections.get(id);
            for (const response of joiner.receive(onWire(send))) {
              if (response.send) toHost(label, id, response.send);
            }
          }
        }
        if (effect.close) {
          closed.push([effect.conn, effect.close]);
          out.push({ close: { conn: effect.conn, code: effect.close, from: 'host' } });
          connections.get(effect.conn)?.joiner.goaway(effect.close);
        }
        if (effect.show_code) out.push({ show_code: effect.show_code });
        if (effect.error) result = effect.error;
        if (effect.enrolled) result = 'ok';
      }
    }

    switch (op) {
      case 'connect': {
        let endpoint = joiners.get(label)?.endpoint;
        if (!endpoint) {
          endpoint = { name: label, identity: publicKey(Buffer.alloc(32, 0x50 + joiners.size)) };
          const joiner = new PairingJoiner(endpoint, host.binary, draws.get(label), now);
          joiners.set(label, { endpoint, joiner });
        }
        const { joiner } = joiners.get(label);
        connections.set(conn, { label, joiner });
        const exporters = { join: Buffer.alloc(32, conn), pair: Buffer.alloc(32, conn + 100) };
        const [{ send: callerHello }, { send: proof }] = joiner.connect(conn, exporters, now);
        const [{ send: hostHello }, ...hostEffects] = host.connect(conn, endpoint.identity, exporters, now);
        // The attempt fixture starts its message log at JOIN_PROOF.
        assert.deepEqual(host.receive(conn, onWire(callerHello), now), [{ version: 0 }]);
        assert.deepEqual(joiner.receive(onWire(hostHello)), [{ version: 0 }]);
        recordSend(label, conn, proof);
        fromHost(hostEffects);
        receiveAtHost(conn, proof);
        break;
      }
      case 'submit':
      case 'submit_first': {
        const current = host.shownCode;
        const wrong = current === '000000' ? '000001' : '000000';
        const code = step.code === 'right' ? current ?? '000000' : step.code === 'stale' ? lastCode : wrong;
        const submitted = joiners.get(label).joiner.submit(code);
        const first = submitted.find(effect => effect.send)?.send;
        if (first) {
          lastCode = current;
          const response = toHost(label, conn, first, op === 'submit');
          firstMessages.set(label, { first, response });
        } else {
          result = submitted[0]?.error;
        }
        break;
      }
      case 'redeliver':
      case 'inject': {
        const previous = firstMessages.get(label);
        let message;
        if (op === 'redeliver') {
          message = previous.first;
        } else {
          const attempt = step.attempt === 'current' ? previous.first.attempt : bytes(step.attempt);
          if (step.message === 'code_exchange') {
            message = { type: 'CODE_EXCHANGE', attempt, payload: bytes(step.payload) };
          } else {
            assert.equal(step.message, 'code_abort');
            message = { type: 'CODE_ABORT', attempt, code: errorNumber('pairing_failed') };
          }
        }
        const response = toHost(label, conn, message, false);
        const abort = encodeControl({ type: 'CODE_ABORT', attempt: message.attempt, code: errorNumber('pairing_failed') });
        if (!response.length) reply = 'none';
        else if (op === 'redeliver' && response.length === previous.response.length &&
          response.every((payload, index) => payload === previous.response[index])) reply = 'first_reply';
        else if (response.length === 1 && response[0] === hex(abort)) reply = 'code_abort';
        break;
      }
      case 'drop':
        connections.get(conn).joiner.drop();
        connections.delete(conn);
        fromHost(host.drop(conn));
        break;
      case 'approve':
        fromHost(host.approve(conn, now));
        break;
      default:
        assert.fail(`unknown operation ${op}`);
    }

    return { out, closed, result, reply, new_code: out.some(effect => 'show_code' in effect) };
  }

  for (const [index, step] of sequence.steps.entries()) {
    const actual = apply(step);
    const joiner = joiners.get(step.joiner ?? 'a')?.joiner;
    Object.assign(actual, {
      host_attempts_left: host.attemptsLeft,
      host_status: host.status,
      joiner_attempts_left: joiner?.attemptsLeft,
      joiner_state: joiner?.state,
    });
    for (const [key, expected] of Object.entries(step)) {
      if (['op', 'conn', 'joiner', 'code', 'attempt', 'message', 'payload'].includes(key)) continue;
      assert.deepEqual(actual[key], expected, `step ${index + 1} ${step.op} ${key}`);
    }
  }
  for (const script of draws.values()) script.done();
}
