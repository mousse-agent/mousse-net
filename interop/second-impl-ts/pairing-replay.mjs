import assert from 'node:assert/strict';
import { bytes, decode, hex } from './cbor.ts';
import { equalBytes, publicKey, sha256 } from './certificate.ts';
import { initiate } from './cpace.ts';
import { directCode, directCodeFromDraw, directCpaceInputs, displayDirectCode } from './direct-code.ts';
import { DirectHost, directHello } from './direct-host.ts';
import { PairingHost, PairingJoiner } from './pairing.ts';
import { decodeControl, decodeFrame, decodeTicket, directMinor, encodeControl, encodeFragment, encodeFrame, errorNumber,
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
        assert.ok(step.role === undefined || typeof step.role === 'string');
        return project(host.approve(conn, hostNow, step.role), party);
      case 'set_role':
        assert.equal(party, 'host');
        return project(host.setRole(hex(joinerEndpoint.identity), step.role), party);
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

// Pair with IP (wire.md 10.9), direct-host.json. The joiners are scripted here;
// the host is DirectHost.
const onWireDirect = control => decodeControl(
  incoming(encodeFrame({ type: 'control', payload: encodeControl(control) })).payload, directMinor);
// The fixture's wrong inputs: lookup `0000` (`0001` if that is the invitation's),
// secret `00000000` (`00000001` if that is the code's).
const wrongLookup = lookup => lookup === '0000' ? '0001' : '0000';
const wrongSecret = secret => secret === '00000000' ? '00000001' : '00000000';

function directParties(conventions, draws) {
  const hostKey = publicKey(bytes(conventions.host.identity_secret));
  const { invitation } = conventions;
  const policy = { authorizingOwner: invitation.authorizing_owner, grantExpiresAt: invitation.grant_expires_at,
    role: invitation.role };
  const hostDraws = new ScriptedDraws(draws.host);
  const host = new DirectHost({ identity: hostKey, name: conventions.host.name }, policy, hostDraws);
  const joiners = new Map();
  const labels = new Map([[hex(hostKey), 'host']]);
  const joinerOf = label => {
    if (!joiners.has(label)) {
      const count = [...joiners.keys()].filter(name => name !== 'host').length;
      const identity = label === 'host' ? hostKey : publicKey(Buffer.alloc(32, 0x50 + count));
      // A joiner with the host's own identity draws nothing; `draws.host` is the host's.
      joiners.set(label, { identity, draws: new ScriptedDraws(label === 'host' ? [] : draws[label] ?? []) });
      labels.set(hex(identity), label);
    }
    return joiners.get(label);
  };
  return { host, hostKey, hostDraws, joinerOf, joiners, labels };
}

// One step's I/O: every message each side sent (no HELLOs), host closes and host events.
function directWire(host, labels, now, conns) {
  const out = [];
  const closed = [];
  const held = [];
  const paired = [];
  for (const connection of conns.values()) connection.inbox = [];
  const label = identity => labels.get(identity) ?? identity;
  const record = (from, conn, message) => out.push({ send: { conn, control: hex(encodeControl(message)), from } });

  function fromHost(effects) {
    for (const effect of effects) {
      if ('send' in effect) {
        if (effect.send.type === 'HELLO') continue;
        record('host', effect.conn, effect.send);
        if (effect.send.type === 'PAIRED') paired.push([effect.conn, effect.send.role]);
        conns.get(effect.conn)?.inbox.push(onWireDirect(effect.send));
      } else if ('close' in effect) {
        closed.push([effect.conn, effect.close]);
        out.push({ close: { code: effect.close, conn: effect.conn, from: 'host' } });
        const connection = conns.get(effect.conn);
        if (connection) connection.closed = true;
      } else if ('admitted' in effect) out.push({ admitted: { conn: effect.admitted } });
      else if ('miss_hold' in effect) {
        held.push(effect.miss_hold.conn);
        out.push(effect);
      } else if ('attempts_left' in effect) out.push({ attempts_left: effect.attempts_left.left });
      else if ('approval' in effect) {
        const { answer_by, decision, identity, name, presence, role } = effect.approval;
        out.push({ approval: { answer_by, decision, joiner: label(identity), name, presence, role } });
      } else if ('approval_ended' in effect) {
        const { identity, reason } = effect.approval_ended;
        out.push({ approval_ended: { joiner: label(identity), reason } });
      } else if ('enrolled' in effect) {
        const { conn, grant, identity, role } = effect.enrolled;
        out.push({ enrolled: { conn, grant, joiner: label(identity), role } });
      } else if ('enrollment_undone' in effect) {
        const { grant, identity } = effect.enrollment_undone;
        out.push({ enrollment_undone: { grant, joiner: label(identity) } });
      } else if ('committed' in effect) {
        const { conn, grant, identity } = effect.committed;
        out.push({ committed: { conn, grant, joiner: label(identity) } });
      } else if ('grant_closes' in effect) {
        // Grant-table closes are listed as one event, not in `closed`.
        out.push(effect);
        for (const conn of effect.grant_closes.conns) {
          const connection = conns.get(conn);
          if (connection) connection.closed = true;
        }
      } else if ('invitation_ended' in effect) out.push({ invitation_ended: effect.invitation_ended.code });
      else if (!('version' in effect) && !('ignored' in effect)) out.push(effect);
    }
  }

  function toHost(from, conn, message) {
    record(from, conn, message);
    fromHost(host.receive(conn, onWireDirect(message), now()));
  }

  // Step 2 and both HELLOs; then the caller sends JOIN_DIRECT.
  function open(from, conn, joiner) {
    assert.ok(!conns.has(conn), `connection ${conn} reused`);
    const exporters = { pair: Buffer.alloc(32, conn + 100) };
    const connection = { from, joiner, exporters, inbox: [], closed: false };
    conns.set(conn, connection);
    fromHost(host.connect(conn, joiner.identity, exporters, now()));
    assert.ok(!connection.closed, 'closed at step 2');
    assert.deepEqual(host.receive(conn, onWireDirect(directHello), now()), [{ version: directMinor }]);
    return connection;
  }

  // `dial` unless the connection exists.
  const dialled = (from, conn, joiner) => conns.get(conn) ?? open(from, conn, joiner);

  return { host, now, out, closed, held, paired, conns, fromHost, toHost, open, dialled };
}

// The scripted joiner's attempt: msg_a, check msg_b, then msg_c (or CODE_ABORT and a close).
// `lose` msg_c: the connection breaks first; `hold` msg_c: it stays on its way until `deliver`.
function directAttempt(wire, conn, code, invitation, hostKey, lose, hold) {
  const connection = wire.conns.get(conn);
  const { joiner, from, exporters } = connection;
  const attempt = joiner.draws.bytes(16, 'attempt_id');
  const inputs = directCpaceInputs(code, invitation, { host: hostKey, joiner: joiner.identity, exporter: exporters.pair },
    attempt);
  let initiator;
  try { initiator = initiate(inputs, size => joiner.draws.bytes(size, 'cpace_scalar_ya')); }
  finally { inputs.prs.fill(0); }
  joiner.attempt = attempt;
  wire.toHost(from, conn, { type: 'CODE_EXCHANGE', attempt, payload: initiator.message });
  const reply = connection.inbox.find(m => m.type === 'CODE_EXCHANGE' && equalBytes(m.attempt, attempt));
  if (connection.closed || !reply) {
    initiator.dispose();
    return;
  }
  let confirmation;
  try {
    confirmation = initiator.finish(reply.payload);
  } catch {
    wire.toHost(from, conn, { type: 'CODE_ABORT', attempt, code: errorNumber('pairing_failed') });
    // Its close is listed, and reaches the host, only if the host has not closed the connection.
    if (!connection.closed) {
      connection.closed = true;
      wire.out.push({ close: { code: 'pairing_failed', conn, from } });
      wire.fromHost(wire.host.lost(conn, wire.now(), 'pairing_failed'));
    }
    return;
  }
  confirmation.isk.fill(0);
  if (lose === 'msg_c') {
    connection.closed = true;
    wire.fromHost(wire.host.drop(conn, wire.now()));
    return;
  }
  const msgC = { type: 'CODE_EXCHANGE', attempt, payload: confirmation.message };
  if (hold === 'msg_c') connection.heldMessage = msgC;
  else wire.toHost(from, conn, msgC);
}

export function replayDirectSequence(sequence, conventions) {
  const { host, hostKey, hostDraws, joinerOf, joiners, labels } = directParties(conventions, sequence.draws);
  const created = host.invite(conventions.time);
  assert.equal(hex(created.invitation), sequence.invitation);
  assert.equal(displayDirectCode(created.code), sequence.code);
  const code = directCode(created.code);
  const invitation = created.invitation;
  const conns = new Map();
  let now = conventions.time;
  const label = identity => labels.get(identity) ?? identity;

  for (const [index, step] of sequence.steps.entries()) {
    const name = `step ${index + 1} ${step.op}`;
    if (step.at !== undefined) {
      assert.ok(conventions.time + step.at >= now, `${name}: time goes back`);
      now = conventions.time + step.at;
    }
    const wire = directWire(host, labels, () => now, conns);
    const joiner = step.joiner === undefined ? undefined : joinerOf(step.joiner);
    let result;
    switch (step.op) {
      case 'dial':
        wire.open(step.joiner, step.conn, joiner);
        break;
      case 'connect':
      case 'recover': {
        assert.ok(step.lookup === undefined || step.lookup === 'wrong');
        wire.dialled(step.joiner, step.conn, joiner);
        const message = step.op === 'connect'
          ? { type: 'JOIN_DIRECT', lookup: step.lookup === 'wrong' ? wrongLookup(code.lookup) : code.lookup,
            name: step.joiner }
          : { type: 'JOIN_DIRECT', lookup: code.lookup, name: step.joiner, receipt: invitation,
            ...(step.cancel ? { cancel: true } : {}) };
        wire.toHost(step.joiner, step.conn, message);
        break;
      }
      case 'submit': {
        assert.ok(step.code === 'right' || step.code === 'wrong');
        assert.ok(step.lose === undefined || step.lose === 'msg_c');
        assert.ok(step.hold === undefined || step.hold === 'msg_c');
        const secret = step.code === 'right' ? code : directCode(code.lookup + wrongSecret(code.code.slice(4)));
        directAttempt(wire, step.conn, secret, invitation, hostKey, step.lose, step.hold);
        break;
      }
      case 'deliver': {
        const connection = conns.get(step.conn);
        const message = connection.heldMessage;
        assert.ok(message, `${name}: nothing held`);
        connection.heldMessage = undefined;
        if (connection.closed) wire.out.push({ undelivered: { conn: step.conn } });
        else wire.toHost(step.joiner, step.conn, message);
        break;
      }
      case 'inject': {
        const attempt = bytes(step.attempt);
        joiner.attempt = attempt;
        wire.toHost(step.joiner, step.conn, { type: 'CODE_EXCHANGE', attempt, payload: bytes(step.payload) });
        break;
      }
      case 'cancel': {
        assert.ok(step.abort === undefined || step.abort === 'lost');
        assert.ok(step.goaway === undefined || step.goaway === 'lost');
        const abort = { type: 'CODE_ABORT', attempt: joiner.attempt, code: errorNumber('cancelled') };
        if (step.abort === 'lost') {
          wire.out.push({ lost: { conn: step.conn, control: hex(encodeControl(abort)), from: step.joiner } });
        } else wire.toHost(step.joiner, step.conn, abort);
        // Its close is listed, and reaches the host, only if the host has not closed the connection.
        const connection = conns.get(step.conn);
        if (!connection.closed) {
          connection.closed = true;
          if (step.goaway === 'lost') wire.fromHost(host.drop(step.conn, now));
          else {
            wire.out.push({ close: { code: 'cancelled', conn: step.conn, from: step.joiner } });
            wire.fromHost(host.lost(step.conn, now, 'cancelled'));
          }
        }
        break;
      }
      case 'drop':
        wire.fromHost(host.drop(step.conn, now));
        break;
      case 'stream':
        wire.fromHost(host.stream(step.conn, now));
        break;
      case 'allow':
      case 'decline': {
        const answer = step.op === 'allow'
          ? host.allow(invitation, joiner.identity, now, step.role)
          : host.decline(invitation, joiner.identity, now);
        result = answer.result;
        wire.fromHost(answer.effects);
        break;
      }
      case 'owner_cancel':
        wire.fromHost(host.cancel(invitation, now));
        break;
      case 'tick':
        wire.fromHost(host.tick(now));
        break;
      case 'old_grant':
        // A ticket pairing whose invitation id has the bytes of I.
        host.addTicketGrant(joiner.identity, `${step.joiner} (old)`, 'owner', invitation, now);
        break;
      case 'restart':
        host.restart();
        wire.out.push({ restart: true });
        for (const connection of conns.values()) connection.closed = true;
        break;
      default:
        assert.fail(`unknown operation ${step.op}`);
    }
    assert.deepEqual(wire.out, step.out, `${name} out`);
    assert.deepEqual(wire.closed, step.closed ?? [], `${name} closed`);
    assert.deepEqual(wire.held, step.held ?? [], `${name} held`);
    const snapshot = host.snapshot(invitation);
    const order = (x, y) => {
      for (let i = 0; i < Math.max(x.length, y.length); i++) {
        if (x[i] !== y[i]) return (x[i] ?? '') < (y[i] ?? '') ? -1 : 1;
      }
      return 0;
    };
    const actual = {
      host_status: snapshot.status,
      host_attempts_left: snapshot.attempts_left,
      requests: snapshot.requests.map(([identity, presence, decision]) => [label(identity), presence, decision]),
      grants: host.grantTable().map(({ identity, name, role, kind }) => [label(identity), name, role, kind]).sort(order),
      paired: wire.paired,
      result,
    };
    for (const key of Object.keys(actual)) {
      if (key in step) assert.deepEqual(actual[key], step[key], `${name} ${key}`);
    }
  }
  for (const { draws } of joiners.values()) draws.done();
  hostDraws.done();
}

// Two invitations with the same id and lookup and different secrets: the same
// bytes up to AUTHORIZED {join_only, I}, then different msg_a.
export function replayBeforeMsgA(section, conventions) {
  const first = [];
  for (const [index, codeDraw] of section.codes.entries()) {
    const { host, hostKey, hostDraws, joinerOf, labels } = directParties(conventions,
      { host: [{ bytes: section.invitation }, { bytes: codeDraw }], a: section.joiner_draws });
    const created = host.invite(conventions.time);
    assert.equal(hex(created.invitation), section.invitation);
    assert.equal(created.code, directCodeFromDraw(bytes(codeDraw)).code);
    const wire = directWire(host, labels, () => conventions.time, new Map());
    const joiner = joinerOf('a');
    wire.open('a', 1, joiner);
    wire.toHost('a', 1, { type: 'JOIN_DIRECT', lookup: directCode(created.code).lookup, name: 'a' });
    assert.deepEqual(wire.out, section.out, `invitation ${index + 1} out`);
    // The joiner's first message, not delivered (the host would debit and draw).
    const attempt = joiner.draws.bytes(16, 'attempt_id');
    const inputs = directCpaceInputs(directCode(created.code), created.invitation,
      { host: hostKey, joiner: joiner.identity, exporter: wire.conns.get(1).exporters.pair }, attempt);
    const initiator = initiate(inputs, size => joiner.draws.bytes(size, 'cpace_scalar_ya'));
    initiator.dispose();
    assert.equal(hex(initiator.message), section.msg_a[index], `invitation ${index + 1} msg_a`);
    first.push(hex(initiator.message));
    joiner.draws.done();
    hostDraws.done();
  }
  assert.equal(first.length, 2);
  assert.notEqual(first[0], first[1]);
}
