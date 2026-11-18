import assert from 'node:assert/strict';
import { bytes, hex, utf8 } from './cbor.ts';
import { publicKey, sha256 } from './certificate.ts';
import { PairingHost, PairingJoiner } from './pairing.ts';
import { decodeControl, decodeFrame, encodeControl, encodeFragment, encodeFrame, errorNumber,
  readError } from './wire.ts';

class ScriptedDraws {
  #offset = 0;
  constructor(draws) { this.draws = draws; }
  take(purpose) {
    const draw = this.draws[this.#offset++];
    assert.equal(draw?.use, purpose, 'random draw order');
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

function deterministicDraws(seed) {
  let counter = 0;
  let code = 111111;
  return {
    bytes: (length, use) => sha256(utf8(`${seed}/${++counter}/${use}`)).subarray(0, length),
    u32: () => code++,
  };
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
  const connectOutputs = new Map();
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
      case 'start':
        joiners.set(party, new PairingJoiner(joinerEndpoint, bytes(step.ticket), joinerDraws.get(party), now));
        return [];
      case 'connect': {
        const real = step.host !== false;
        routes.set(conn, { party, real });
        parties.set(party, conn);
        const exporters = parseExporters(step.exporters);
        const start = project(joiner.connect(conn, exporters, now), party);
        const peer = real ? project(
          host.connect(conn, joinerEndpoint.identity, parseExporters(step.host_exporters ?? step.exporters)), 'host') : [];
        const outgoing = [...start, ...peer];
        connectOutputs.set(conn, outgoing);
        return outgoing;
      }
      case 'receive': {
        const control = receive(party, conn, step.control);
        if (party === 'host') return project(host.receive(conn, control, now), party);
        const effects = joiner.receive(control);
        const immediate = [];
        for (const effect of effects) {
          // The fixture groups the proof with connect, before its HELLO delivery rows.
          if (effect.send?.type === 'JOIN_PROOF') connectOutputs.get(conn).push(...project([effect], party));
          else immediate.push(effect);
        }
        return project(immediate, party);
      }
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

  const deferred = [];
  for (const [index, step] of flow.steps.entries()) {
    const actual = run(step);
    const label = `step ${index + 1} ${step.party}/${step.event}`;
    if (step.event === 'connect') deferred.push(() => assert.deepEqual(actual, step.out, label));
    else assert.deepEqual(actual, step.out, label);
  }
  for (const check of deferred) check();
  for (const pending of frames.values()) assert.equal(pending.length, 0, 'undelivered frame');
  hostDraws.done();
  for (const draws of joinerDraws.values()) draws.done();
  assert.deepEqual({
    host: host.snapshot(),
    joiners: Object.fromEntries([...joiners].map(([party, joiner]) => [party, joiner.snapshot()])),
    grants: [...host.grants.values()],
  }, flow.end);
}

export function replayAttemptSequence(sequence) {
  const now = 1790000000;
  const hostEndpoint = { name: 'Desk', identity: publicKey(Buffer.alloc(32, 0x11)) };
  const host = new PairingHost(hostEndpoint, { authorizingOwner: '51'.repeat(16),
    grantExpiresAt: null, routes: [], role: 'owner' }, sequence.kind === 'in_person' ? 1 : 2,
  deterministicDraws('host'), now);
  const joiners = new Map();
  const connections = new Map();
  const firstMessages = new Map();
  let lastCode;

  function apply(step) {
    const { conn, joiner: label, op } = step;
    let joiner = joiners.get(label);
    const effects = [];
    let sameReply;
    if (op === 'connect') {
      const endpoint = { name: label, identity: publicKey(Buffer.alloc(32, 0x22 + joiners.size)) };
      joiner ??= new PairingJoiner(endpoint, host.binary, deterministicDraws(label), now);
      joiners.set(label, joiner);
      connections.set(conn, joiner);
      const exporters = { join: sha256(utf8(`join/${conn}`)), pair: sha256(utf8(`pair/${conn}`)) };
      const [{ send: callerHello }] = joiner.connect(conn, exporters, now);
      const [{ send: hostHello }] = host.connect(conn, endpoint.identity, exporters);
      assert.deepEqual(host.receive(conn, onWire(callerHello), now), [{ version: 0 }]);
      const [version, { send: proof }] = joiner.receive(onWire(hostHello));
      assert.deepEqual(version, { version: 0 });
      effects.push(...host.receive(conn, onWire(proof), now));
    } else if (op === 'submit' || op === 'submit_first') {
      const current = host.shownCode;
      const code = step.code === 'right' ? current ?? '000000' : step.code === 'stale' ? lastCode : '000000';
      const submitted = joiner.submit(code);
      const first = submitted.find(effect => effect.send);
      if (!first) return { result: submitted[0]?.error };
      lastCode = current;
      const replies = host.receive(conn, onWire(first.send), now);
      firstMessages.set(label, { first: first.send, reply: replies.find(effect => effect.send)?.send });
      if (op === 'submit_first') return { new_code: replies.some(effect => 'show_code' in effect) };
      effects.push(...replies);
    } else if (op === 'redeliver') {
      const { first, reply } = firstMessages.get(label);
      const outputs = host.receive(conn, onWire(first), now);
      sameReply = outputs.some(effect => effect.send &&
        hex(encodeControl(effect.send)) === hex(encodeControl(reply)));
      return { same_reply: sameReply, new_code: outputs.some(effect => 'show_code' in effect) };
    } else if (op === 'drop') {
      connections.get(conn).drop();
      effects.push(...host.drop(conn));
    } else if (op === 'approve') {
      effects.push(...host.approve(conn, now));
    } else {
      assert.fail(`unknown operation ${op}`);
    }

    const closed = [];
    let newCode = false;
    let result;
    for (const effect of effects) {
      if (effect.send) {
        const replies = connections.get(effect.conn).receive(onWire(effect.send));
        for (const reply of replies) {
          if (reply.send) effects.push(...host.receive(effect.conn, onWire(reply.send), now));
        }
      }
      if (effect.close) {
        closed.push([effect.conn, effect.close]);
        connections.get(effect.conn)?.goaway(effect.close);
      }
      if (effect.show_code) newCode = true;
      if (effect.error) result = effect.error;
      if (effect.enrolled) result = 'ok';
    }
    return { closed, result, new_code: newCode };
  }

  for (const [index, step] of sequence.steps.entries()) {
    const actual = apply(step);
    const joiner = joiners.get(step.joiner ?? 'a');
    Object.assign(actual, {
      host_attempts_left: host.attemptsLeft,
      host_status: host.status,
      joiner_attempts_left: joiner?.attemptsLeft,
      joiner_state: joiner?.state,
    });
    for (const [key, expected] of Object.entries(step)) {
      if (['op', 'conn', 'joiner', 'code'].includes(key)) continue;
      assert.deepEqual(actual[key], expected, `step ${index + 1} ${step.op} ${key}`);
    }
  }
}
