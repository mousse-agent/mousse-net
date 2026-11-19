import assert from 'node:assert/strict';
import { bytes, decode, hex } from './cbor.ts';
import { equalBytes, publicKey, sha256 } from './certificate.ts';
import { PairingHost, PairingJoiner } from './pairing.ts';
import { decodeControl, decodeFrame, decodeTicket, encodeControl, encodeFragment, encodeFrame, errorNumber,
  hello, joinProof, readError } from './wire.ts';

export function memoryFlowStore(onPersist = () => {}, onPin = () => {}) {
  const records = new Map();
  const pins = new Set();
  return {
    load(hash) { return records.get(hash); },
    save(hash, next, previous) {
      const current = records.get(hash);
      if (current === undefined ? previous !== undefined : !previous || !equalBytes(current, previous)) return false;
      records.set(hash, Uint8Array.from(next));
      onPersist({ persist: { expected: previous ? hex(previous) : null, record: hex(next) } });
      return true;
    },
    savePin(identity) {
      pins.add(hex(identity));
      onPin({ pin: hex(identity) });
    },
    hasPin(identity) { return pins.has(hex(identity)); },
  };
}

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
const goawayFrame = code => encodeFrame({ type: 'goaway', code: errorNumber(code) });

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
  const joinerEndpoint = { identity: publicKey(bytes(joinerInput.identity_secret)),
    computerName: joinerInput.computer, profileName: joinerInput.profile };
  assert.equal(hex(hostEndpoint.identity), hostInput.identity);
  assert.equal(hex(joinerEndpoint.identity), joinerInput.identity);
  const policy = { authorizingOwner: invitation.authorizing_owner, grantExpiresAt: invitation.grant_expires_at,
    role: invitation.role, routes: invitation.routes };
  const hostDraws = new ScriptedDraws(flow.draws.host);
  const joinerDraws = new Map(Object.entries(flow.draws.joiners).map(([name, draws]) => [name, new ScriptedDraws(draws)]));
  const writes = [];
  let crashAtPersist = false;
  const stores = new Map([...joinerDraws.keys()].map(name => [name, memoryFlowStore(
    write => {
      writes.push(write);
      if (crashAtPersist) throw new Error('simulated process exit after commit');
    },
    pin => writes.push(pin),
  )]));
  const joiners = new Map();
  const routes = new Map();
  const parties = new Map();
  const frames = new Map();
  let host;
  let hostNow = now;

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
    const failed = effects.some(effect => 'failed' in effect);
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
        const frame = goawayFrame(code);
        // The fixture implies the joiner's final GOAWAY and scripts no receipt of it.
        if (!failed) queue(from, conn, frame);
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

  function breakConnection(party, conn) {
    frames.delete(`${conn}/${party}`);
    frames.delete(`${conn}/host`);
    return routes.get(conn).real ? project(host.drop(conn), 'host') : [];
  }

  function run(step) {
    const { party, event } = step;
    const joiner = joiners.get(party);
    const conn = step.conn ?? parties.get(party);
    switch (event) {
      case 'create': {
        assert.equal(step.kind, flow.kind);
        host = new PairingHost(hostEndpoint, { ...policy, role: step.role ?? policy.role }, step.kind, hostDraws, hostNow);
        return [{ ticket: { binary: hex(host.binary), fragment: encodeFragment(host.binary),
          hash: hex(sha256(host.binary)), shown_code: host.shownCode } }];
      }
      case 'grant': {
        const identity = hex(joinerEndpoint.identity);
        host.grants.set(identity, { identity, name: step.name, role: step.role ?? policy.role,
          authorizing_owner: policy.authorizingOwner, expires_at: policy.grantExpiresAt,
          granted_at: hostNow, bound_connections: [] });
        return [];
      }
      case 'tick':
        assert.equal(party, 'host');
        hostNow = step.at;
        return project(host.tick(hostNow, (hostNow - now) * 1000), party);
      case 'start': {
        assert.ok(step.host_pinned === undefined || typeof step.host_pinned === 'boolean');
        assert.ok(step.identity === undefined || step.identity === 'host');
        assert.ok(step.arrival === 'in_app_scan' || step.arrival === 'link');
        const ticket = bytes(step.ticket);
        const hostIdentity = decodeTicket(ticket).hostIdentity;
        const endpoint = step.identity === 'host' ? { ...joinerEndpoint, identity: hostEndpoint.identity } : joinerEndpoint;
        const store = stores.get(party);
        const pinnedHost = step.host_pinned || store?.hasPin(hostIdentity) ? hostIdentity : undefined;
        if (step.record !== undefined) assert.equal(hex(store.load(hex(sha256(ticket)))), step.record);
        try {
          joiners.set(party, new PairingJoiner(endpoint, ticket, joinerDraws.get(party), now,
            { arrival: step.arrival, store, pinnedHost }));
        } catch (error) {
          if (!['in_person_from_link', 'own_ticket', 'attempts_exhausted'].includes(error.message)) throw error;
          return [{ error: error.message }];
        }
        return [];
      }
      case 'save': {
        const hash = hex(decode(joiner.flowRecord()).get(2n));
        const stored = stores.get(party).load(hash);
        return [{ record: stored ? hex(stored) : null }];
      }
      case 'connect': {
        const real = step.host !== false;
        routes.set(conn, { party, real });
        parties.set(party, conn);
        const exporters = parseExporters(step.exporters);
        const [hello, proof] = project(joiner.connect(conn, exporters, now), party);
        const peer = real ? project(
          host.connect(conn, joinerEndpoint.identity, parseExporters(step.host_exporters ?? step.exporters),
            hostNow, (hostNow - now) * 1000), 'host') : [];
        return [hello, ...peer, proof];
      }
      case 'receive': {
        const control = receive(party, conn, step.control);
        if (party === 'host') return project(host.receive(conn, control, hostNow), party);
        crashAtPersist = step.crash_at_persist === true;
        const effects = joiner.receive(control);
        if (!crashAtPersist) return project(effects, party);
        crashAtPersist = false;
        assert.equal(writes.length, 1, 'crash must follow the first write');
        assert.ok('persist' in writes[0], 'crash must follow a flow record commit');
        assert.deepEqual(effects, [{ failed: 'internal_error' }, { conn, close: 'internal_error' }]);
        joiners.delete(party);
        return [...writes, { crashed: true }, ...breakConnection(party, conn)];
      }
      case 'drop':
        joiner.drop();
        return breakConnection(party, conn);
      case 'proof_timeout':
        assert.deepEqual(joiner.tick(9999), []);
        return project(joiner.tick(10000), party);
      case 'submit_code':
        return project(joiner.submit(step.code), party);
      case 'approve':
        return project(host.approve(conn, hostNow), party);
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
    writes.length = 0;
    const effects = run(step);
    const label = `step ${index + 1} ${step.party}/${step.event}`;
    const failure = step.out.find(effect => 'failed' in effect);
    const expected = [...step.out];
    if (failure && step.event !== 'goaway' && step.event !== 'drop') {
      const code = failure.failed;
      const conn = step.conn ?? parties.get(step.party);
      expected.push({ close: { code, conn, frame: hex(goawayFrame(code)), from: step.party } });
    }
    assert.deepEqual(effects, expected, label);
    const paired = effects.find(effect => 'paired' in effect || 'already_paired' in effect);
    const pin = paired ? [{ pin: hex(hostEndpoint.identity) }] : [];
    assert.deepEqual(writes, [...pin, ...effects.filter(effect => 'persist' in effect)], `${label}: durable write order`);
    if (failure) {
      const message = onWire({ type: 'AUTHORIZED', state: 'live' });
      assert.deepEqual(joiners.get(step.party).receive(message), [{ ignored: true }], `${label}: gate after failure`);
    }
  }
  for (const pending of frames.values()) assert.equal(pending.length, 0, 'undelivered frame');
  hostDraws.done();
  for (const draws of joinerDraws.values()) draws.done();
  const enrolled = flow.steps.some(step => step.out.some(effect => 'enrolled' in effect));
  const grants = [...host.grants.values()].map(({ enrolled_by, ...grant }) => {
    assert.equal(enrolled_by, enrolled ? hex(host.ticket.invitation) : undefined);
    return grant;
  });
  assert.deepEqual({
    host: host.snapshot(),
    joiners: Object.fromEntries([...joiners].map(([party, joiner]) => [party, joiner.snapshot()])),
    grants,
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
    const joinerFailures = new Map();
    const recordSend = (from, id, message) => {
      out.push({ send: { conn: id, from, control: hex(encodeControl(message)) } });
    };

    function receiveAtHost(id, message, deliver = true) {
      const effects = host.receive(id, onWire(message), now);
      fromHost(effects, deliver);
      return effects.flatMap(effect => effect.send ? [effect.send] : []);
    }

    function toHost(from, id, message, deliver = true) {
      recordSend(from, id, message);
      return receiveAtHost(id, message, deliver);
    }

    function fromJoiner(id, effects, notifyPeer) {
      const { label } = connections.get(id);
      const failure = effects.find(effect => 'failed' in effect);
      const terminal = failure && notifyPeer ? [{ conn: id, close: failure.failed }] : [];
      assert.deepEqual(effects.filter(effect => 'close' in effect), terminal, 'joiner GOAWAY');
      if (terminal.length) assert.deepEqual(effects.at(-1), terminal[0], 'joiner GOAWAY must be last');
      if (failure) joinerFailures.set(label, failure.failed);

      for (const effect of effects) {
        if (effect.send) toHost(label, id, effect.send);
        if ('close' in effect) {
          const frame = incoming(goawayFrame(effect.close));
          assert.deepEqual(frame, { type: 'goaway', code: errorNumber(failure.failed) });
          if (!closed.some(([conn]) => conn === id)) fromHost(host.drop(id));
        }
      }
    }

    function fromHost(effects, deliver = true) {
      for (const effect of effects) {
        if (effect.send) {
          const { conn: id, send } = effect;
          recordSend('host', id, send);
          if (deliver) {
            const { joiner } = connections.get(id);
            fromJoiner(id, joiner.receive(onWire(send)), true);
          }
        }
        if (effect.close) {
          closed.push([effect.conn, effect.close]);
          out.push({ close: { conn: effect.conn, code: effect.close, from: 'host' } });
          const joiner = connections.get(effect.conn)?.joiner;
          if (joiner) fromJoiner(effect.conn, joiner.goaway(effect.close), false);
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
          endpoint = { computerName: label, profileName: 'Work', identity: publicKey(Buffer.alloc(32, 0x50 + joiners.size)) };
          const arrival = host.ticket.kind === 1 ? 'in_app_scan' : 'link';
          const joiner = new PairingJoiner(endpoint, host.binary, draws.get(label), now,
            { arrival, store: memoryFlowStore() });
          joiners.set(label, { endpoint, joiner });
        }
        const { joiner } = joiners.get(label);
        connections.set(conn, { label, joiner });
        const exporters = { join: Buffer.alloc(32, conn), pair: Buffer.alloc(32, conn + 100) };
        const [{ send: callerHello }, { send: proof }] = joiner.connect(conn, exporters, now);
        const [{ send: hostHello }, ...hostEffects] = host.connect(conn, endpoint.identity, exporters, now);
        // The attempt fixture starts its message log at JOIN_PROOF.
        assert.deepEqual(host.receive(conn, onWire(callerHello), now), [{ version: hello.minor }]);
        assert.deepEqual(joiner.receive(onWire(hostHello)), [{ version: hello.minor }]);
        recordSend(label, conn, proof);
        fromHost(hostEffects);
        receiveAtHost(conn, proof);
        break;
      }
      case 'connect_as_host': {
        const exporters = { join: Buffer.alloc(32, conn), pair: Buffer.alloc(32, conn + 100) };
        const [{ send: hostHello }, ...hostEffects] = host.connect(conn, hostEndpoint.identity, exporters, now);
        assert.deepEqual(hostHello, hello);
        assert.deepEqual(host.receive(conn, onWire(hello), now), [{ version: hello.minor }]);
        const { invitation, secret } = host.ticket;
        const { key, mac } = joinProof(invitation, secret, {
          host: hostEndpoint.identity, joiner: hostEndpoint.identity, exporter: exporters.join,
        });
        key.fill(0);
        const proof = { type: 'JOIN_PROOF', invitation, mac, name: label };
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
          toHost(label, conn, first, op === 'submit');
          firstMessages.set(label, first);
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
          message = previous;
        } else {
          const attempt = step.attempt === 'current' ? previous.attempt : bytes(step.attempt);
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
        else if (response.length === 1) {
          const [answer] = response;
          if (answer.type === 'CODE_EXCHANGE' && equalBytes(answer.attempt, message.attempt)) reply = 'code_exchange';
          if (equalBytes(encodeControl(answer), abort)) reply = 'code_abort';
        }
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

    const joinerFailure = joinerFailures.get(label ?? 'a');
    return { out, closed, result, reply, joinerFailure, new_code: out.some(effect => 'show_code' in effect) };
  }

  for (const [index, step] of sequence.steps.entries()) {
    const previousState = joiners.get(step.joiner ?? 'a')?.joiner.state;
    const actual = apply(step);
    const joiner = joiners.get(step.joiner ?? 'a')?.joiner;
    if (step.joiner_state?.startsWith('failed:') && step.joiner_state !== previousState && step.op !== 'drop') {
      assert.equal(actual.joinerFailure, step.joiner_state.slice('failed:'.length), `step ${index + 1} failure`);
    }
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
