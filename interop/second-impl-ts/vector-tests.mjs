import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { bytes, decode, encode, hex } from './cbor.ts';
import { authenticateNativePeer, checkRaw, DerReader, derToRaw, issueCertificate, lanCandidate, nativeTlsPolicy, publicKey,
  rawToDer, SessionLifetime, sha256, signCertificateVerify, verify, verifyCertificate } from './certificate.ts';
import * as cpace from './cpace.ts';
import { DIRECT_CODE_ALPHABET, directCode, directCodeFromDraw, directCpaceInputs, directInviteDigest, directTranscript,
  displayDirectCode, parseDirectCode } from './direct-code.ts';
import { PairingJoiner, trafficOf } from './pairing.ts';
import { Gate, step2, Streams } from './session.ts';
import * as relay from './relay.ts';
import * as wire from './wire.ts';
import { memoryFlowStore, replayAttemptSequence, replayBeforeMsgA, replayDirectSequence,
  replayEndToEnd } from './pairing-replay.mjs';

const directory = new URL('../../spec/vectors/', import.meta.url);
const fixtures = new Map(readdirSync(directory).filter(file => file.endsWith('.json'))
  .map(file => [file, JSON.parse(readFileSync(new URL(file, directory), 'utf8'))]));
const used = new Set();
function file(name) {
  used.add(name);
  assert.ok(fixtures.has(name), `missing fixture ${name}`);
  return [fixtures.get(name), (description, check) => test(`${name} / ${description}`, check)];
}
const matches = (actual, expected) => assert.equal(hex(actual), expected);
function outcome(expected, fn) {
  if (expected === 'ok') return fn();
  assert.throws(fn, { message: expected });
}

{
  const [v, add] = file('cbor.json');
  for (const item of v.valid) add(item.diagnostic, () => matches(encode(decode(bytes(item.hex))), item.hex));
  for (const item of v.invalid) add(item.description, () => outcome(item.error, () => decode(bytes(item.hex))));
}

{
  const [v, add] = file('der-raw.json');
  for (const item of v.der_to_raw) add(item.name, () => {
    if (item.error) outcome(item.error, () => derToRaw(bytes(item.der)));
    else {
      matches(derToRaw(bytes(item.der)), item.raw);
      matches(rawToDer(bytes(item.raw)), item.der);
    }
  });
  for (const item of v.raw_only) add(item.name, () => outcome(item.result, () => checkRaw(bytes(item.input))));
}

{
  const [v, add] = file('direct-code.json');
  const same = (code, item) => {
    assert.equal(code.code, item.code);
    assert.equal(code.lookup, item.lookup);
    matches(code.secret, item.secret);
  };
  add('alphabet', () => assert.equal(v.alphabet, DIRECT_CODE_ALPHABET));
  for (const item of v.draws) add(`draw ${item.name}`, () => {
    const code = directCodeFromDraw(bytes(item.draw));
    same(code, item);
    assert.equal(displayDirectCode(code.code), item.display);
    same(parseDirectCode(item.display), item);
  });
  for (const item of v.accepted) add(`accepted ${item.name}`, () => same(parseDirectCode(item.input), item));
  for (const item of v.rejected) add(`rejected ${item.name}`, () => outcome(item.error, () => parseDirectCode(item.input)));
}

{
  const [v, add] = file('session-cert.json');
  const sample = v.valid;
  add('issue certificate and compare all intermediate bytes', () => {
    const issued = issueCertificate(bytes(sample.identity_secret), bytes(sample.session_secret),
      { not_before: sample.not_before, not_after: sample.not_after });
    const output = {
      certificate: 'certificate', record: 'record', identityPublic: 'identity_public',
      sessionPublic: 'session_public', serial: 'serial', spki: 'spki',
      identitySignature: 'identity_signature', extensionValue: 'extension_value',
    };
    for (const [name, field] of Object.entries(output)) matches(issued[name], sample[field]);
    matches(verifyCertificate(issued.certificate, sample.not_before).identity, sample.identity_public);
    assert.equal(BigInt(decode(issued.record).get(5n)), BigInt(sample.version));
    matches(publicKey(Buffer.alloc(32, 0x22)), v.other_identity_public);
  });
  add('CertificateVerify-style signatures', () => {
    const { message, signature, wrong_key_signature } = sample.tls_signature;
    const proof = bytes(message);
    matches(rawToDer(signCertificateVerify(proof, bytes(sample.session_secret))), signature);
    matches(rawToDer(signCertificateVerify(proof, Buffer.alloc(32, 0x44))), wrong_key_signature);
    assert.ok(verify(derToRaw(bytes(signature)), proof, bytes(sample.session_public)));
    assert.equal(verify(derToRaw(bytes(wrong_key_signature)), proof, bytes(sample.session_public)), false);
  });
  for (const item of v.cases) add(item.name, () => {
    outcome(item.result, () => verifyCertificate(bytes(item.certificate), item.now,
      item.expected_identity === null ? undefined : bytes(item.expected_identity)));
    if (['another_endpoint_on_lan_address', 'precedence_pin_before_window', 'expired_with_no_pin'].includes(item.name)) {
      assert.deepEqual(lanCandidate(item.result), { action: 'try_next', send: false, warn: false, repin: false });
    }
  });
  assert.ok(v.browser_worker.length > 0);
  for (const item of v.browser_worker) add(`${item.name}: parts`, () => {
    const checked = verifyCertificate(bytes(item.certificate), item.not_before + 60, bytes(item.identity_public));
    assert.deepEqual(checked.window, { not_before: item.not_before, not_after: item.not_after });
    assert.ok(verify(bytes(item.identity_signature), bytes(item.record), bytes(item.identity_public)));
    const record = decode(bytes(item.record));
    matches(record.get(2n), item.spki);
    assert.equal(BigInt(record.get(3n)), BigInt(item.not_before));
    assert.equal(BigInt(record.get(4n)), BigInt(item.not_after));
    assert.ok(v.cases.some(c => c.name === item.name && c.result === 'ok'));
  });
}

{
  const [v, add] = file('session-lifecycle.json');
  const authenticate = (now = v.authenticated_at) => verifyCertificate(bytes(v.peer_certificate), now, bytes(v.pin));
  const mono = now => (now - v.authenticated_at) * 1000;
  const lifetime = (now = v.authenticated_at, previous) =>
    new SessionLifetime(v.local_window, authenticate(now).window, { now, mono: mono(now) }, previous);
  function checkTick(life, conn, item, candidateInProgress = false) {
    const event = life.tick(item.now, item.mono_ms ?? mono(item.now), candidateInProgress);
    const events = event === null ? [] : event === 'renew_due' ? [{ conn, event }] :
      [{ conn, event: 'close', code: event }];
    assert.deepEqual(events, item.events, `tick ${item.now}`);
  }
  add('renewal and expiration timeline', () => {
    const life = lifetime();
    assert.equal(life.deadline, v.deadline);
    assert.equal(life.renewAt, v.renew_at);
    for (const tick of v.ticks) checkTick(life, 1, tick);
  });
  add('switch without renewing keeps pending retries', () => {
    const life = lifetime();
    const switchAt = v.switch_without_renewal.switch_at;
    for (const tick of v.ticks.filter(tick => tick.now < switchAt)) checkTick(life, 1, tick);
    const replacement = lifetime(switchAt, life);
    for (const tick of v.switch_without_renewal.ticks) checkTick(replacement, 2, tick);
  });
  function checkCandidateSteps(life, steps) {
    let candidate;
    for (const step of steps) {
      switch (step.op) {
        case 'tick': checkTick(life, 1, step, candidate !== undefined); break;
        case 'begin_path':
          assert.equal(candidate, undefined);
          candidate = step.conn;
          break;
        case 'path_closed':
          assert.equal(candidate, step.conn);
          candidate = undefined;
          break;
        default: assert.fail(`unknown lifecycle step ${step.op}`);
      }
    }
  }
  add('retry_while_candidate', () => {
    const life = lifetime();
    for (const tick of v.ticks.filter(tick => tick.now <= v.renew_at)) checkTick(life, 1, tick);
    checkCandidateSteps(life, v.retry_while_candidate.steps);
  });
  add('candidate_at_first_renewal', () => {
    const life = lifetime();
    checkCandidateSteps(life, v.candidate_at_first_renewal.steps);
  });
  add('clock_rollback', () => {
    const life = lifetime();
    assert.equal(life.monoDeadline, v.clock_rollback.mono_deadline_ms);
    for (const tick of v.clock_rollback.ticks) checkTick(life, 1, tick);
  });
  add('handshake after expiration', () => {
    const item = v.new_connection_after_deadline;
    outcome(item.result, () => verifyCertificate(bytes(v.peer_certificate), item.now, bytes(v.pin)));
  });
}

{
  const [v, add] = file('authz.json');
  for (const item of v.cases) add(item.name, () => {
    const initial = step2(item.peer, item.grants, item.denied, item.now);
    assert.equal(initial, item.step2);
    const gate = new Gate('host', initial);
    for (const step of item.steps) {
      switch (step.op) {
        case 'check': assert.equal(gate.check(step.traffic), step.verdict); break;
        case 'admit_join_only': gate.admit(); break;
        case 'timeout': assert.equal(gate.timeout(step.mono_ms), step.result); break;
        default: assert.fail(`unknown host step ${step.op}`);
      }
    }
  });
  for (const item of v.caller_cases) add(item.name, () => {
    const gate = item.start === 'pairing_only' ? Gate.pairingOnly() : new Gate('caller');
    assert.ok(item.start === undefined || item.start === 'pairing_only', `unknown start ${item.start}`);
    for (const step of item.steps) {
      if (step.op === 'promote') gate.promote();
      else if (step.op === 'promote_direct') gate.promoteDirect();
      else if (step.op === 'sent_join_proof') gate.sentJoinProof(step.mono_ms ?? 0);
      else if (step.op === 'host_stream') {
        const localGrants = item.local_grants.map(grant => ({ ...grant, identity: v.identities[grant.identity] }));
        assert.equal(gate.hostStreamRole(v.identities[step.host], localGrants, [], item.now) ?? 'none', step.result);
      }
      else {
        assert.equal(step.op, 'check');
        assert.equal(gate.check(step.traffic), step.verdict);
      }
      assert.equal(gate.state, step.state);
    }
  });
}

{
  const [v, add] = file('hello.json');
  add('this build', () => {
    matches(wire.encodeControl(wire.hello), v.hello);
    assert.equal(wire.hello.major, v.this_build.major);
    assert.equal(wire.hello.minor, v.this_build.minor);
    assert.equal(Math.max(0, wire.hello.minor - 1), v.this_build.oldest_minor);
  });
  for (const item of v.cases) add(item.name, () => {
    assert.equal(Math.max(0, item.local.minor - 1), item.local.oldest_minor);
    if (typeof item.result === 'number') assert.equal(wire.negotiate(item.local, item.peer), item.result);
    else outcome(item.result.slice(6), () => wire.negotiate(item.local, item.peer));
  });
  for (const item of v.repeated) add(item.name, () => {
    assert.equal(Math.max(0, item.local.minor - 1), item.local.oldest_minor);
    for (const side of ['host', 'caller']) {
      const gate = new Gate(side);
      for (const step of item.hellos) {
        const message = wire.decodeControl(bytes(step.control));
        assert.equal(message.type, 'HELLO');
        const result = gate.receiveHello(message, item.local);
        assert.equal(typeof result === 'bigint' ? Number(result) : result, step.result, side);
      }
      assert.equal(gate.version === undefined ? null : Number(gate.version), item.agreed, side);
      if (item.agreed === null) assert.equal(gate.state, 'closed:unsupported_version', side);
    }
  });
}

{
  const [v, add] = file('ticket.json');
  for (const key of ['valid', 'valid_in_person']) add(key, () => {
    const ticket = v[key];
    const data = wire.encodeTicket({ version: ticket.version, kind: ticket.kind,
      hostIdentity: bytes(ticket.host_identity), invitation: bytes(ticket.invitation), secret: bytes(ticket.secret),
      expiresAt: ticket.expires_at, routes: ticket.routes });
    matches(data, ticket.binary);
    matches(sha256(data), ticket.hash);
    assert.equal(wire.encodeFragment(data), ticket.fragment);
    assert.deepEqual(wire.decodeFragment(ticket.fragment), wire.decodeTicket(data));
    matches(wire.encodeTicket(wire.decodeFragment(ticket.fragment)), ticket.binary);
  });
  for (const item of v.rejections) add(item.name, () => outcome(item.result, () =>
    item.binary === undefined ? wire.decodeFragment(item.fragment) : wire.decodeTicket(bytes(item.binary))));
  for (const item of v.joiner_freshness.cases) add(`freshness at ${item.now}`, () =>
    outcome(item.result, () => wire.checkJoinerExpiry(v.joiner_freshness.expires_at, item.now)));
  for (const item of v.route_hints.cases) add(JSON.stringify(item.hint), () =>
    assert.deepEqual(wire.routeHint(item.hint), item.result));
}

{
  const [v, add] = file('join-proof.json');
  const host = bytes(v.host_identity);
  const joiner = bytes(v.joiner_identity);
  add('join proof', () => {
    const p = v.join_proof;
    const answer = wire.joinProof(bytes(p.invitation), bytes(p.secret), { host, joiner, exporter: bytes(p.join_exporter) });
    for (const key of ['input', 'key', 'mac']) matches(answer[key], p[key]);
  });
  add('binding transcript', () => {
    const b = v.binding_transcript;
    const hash = sha256(wire.encodeTicket(wire.decodeTicket(bytes(v.ticket_binary))));
    matches(hash, v.ticket_hash);
    matches(wire.bindingTranscript(hash, b.kind, b.ticket_version, { host, joiner, exporter: bytes(b.pair_exporter) }),
      b.transcript);
  });
  add('attempt session id', () => {
    const s = v.sid;
    const result = wire.attemptSession(bytes(s.attempt), bytes(s.pair_exporter));
    matches(result.input, s.input);
    matches(result.sid, s.sid);
  });
}

{
  const [v, add] = file('control.json');
  const names = ['HELLO', 'AUTHORIZED', 'JOIN_PROOF', 'CODE_EXCHANGE', 'CODE_ABORT', 'PAIRED', 'JOIN_DIRECT'];
  const classes = { HELLO: 'hello', JOIN_PROOF: 'join_proof', CODE_EXCHANGE: 'pairing', CODE_ABORT: 'pairing',
    PAIRED: 'paired', JOIN_DIRECT: 'join_direct' };
  for (const [i, item] of v.valid.entries()) add(item.name ?? `valid ${i + 1}`, () => {
    const message = wire.decodeControl(bytes(item.hex), item.minor);
    assert.equal(message.type, names[item.type - 1]);
    matches(wire.encodeControl(message), item.hex);
    // The gate classifies every decoded message (wire.md 8).
    const expected = message.type === 'AUTHORIZED' ? `authorized_${message.state}` : classes[message.type];
    assert.equal(trafficOf(message), expected);
  });
  for (const item of v.invalid) add(item.name, () =>
    outcome('protocol_error', () => wire.decodeControl(bytes(item.hex), item.minor)));
  for (const item of v.before_minor_4) add(`before minor 4 / ${item.name}`, () => {
    wire.decodeControl(bytes(item.hex), wire.directMinor);
    outcome('protocol_error', () => wire.decodeControl(bytes(item.hex), wire.directMinor - 1));
  });
}

{
  const [v, add] = file('mux.json');
  for (const [i, item] of v.valid.entries()) add(`valid ${item.frame.type} ${i + 1}`, () => {
    const { frame, read } = wire.decodeFrame(bytes(item.hex));
    assert.equal(read, item.hex.length / 2);
    assert.deepEqual(wire.frameResult(frame), item.frame);
    matches(wire.encodeFrame(frame), item.hex);
  });
  for (const item of v.invalid) add(item.name, () => outcome(item.result, () => wire.decodeFrame(bytes(item.hex))));
  add('unknown RESET code', () => {
    const { frame } = wire.decodeFrame(bytes(v.unknown_error_code.hex));
    assert.deepEqual(frame, { type: 'reset', stream: 1, code: wire.errorNumber('internal_error') });
  });
  for (const item of v.streams.cases) add(item.name, () => {
    assert.ok(item.role === 'host' || item.role === 'caller');
    const streams = new Streams(item.role);
    for (const [index, step] of item.steps.entries()) {
      const { frame, read } = wire.decodeFrame(bytes(step.hex));
      assert.equal(read, step.hex.length / 2);
      assert.deepEqual(wire.frameResult(frame), step.frame);
      matches(wire.encodeFrame(frame), step.hex);

      const { event, reply } = streams.receive(frame);
      if (typeof step.result === 'string') {
        assert.equal(event, undefined);
        assert.equal(reply?.type, 'goaway');
        const { frame: goaway } = wire.decodeFrame(wire.encodeFrame(reply));
        assert.equal(`close:${wire.readError(goaway.code)}`, step.result);
        assert.equal(index, item.steps.length - 1, 'close must end the sequence');
        assert.deepEqual(streams.receive({ type: 'ping', opaque: Buffer.alloc(8) }), {});
        continue;
      }

      assert.equal(reply, undefined);
      const events = [];
      if (event) {
        const { stream } = event;
        switch (event.type) {
          case 'open': events.push(`opened:${stream}`); break;
          case 'data': events.push(`data:${stream}:${event.payload.length}`); break;
          case 'fin': events.push(`finished:${stream}`); break;
          case 'reset': events.push(`reset:${stream}:${wire.readError(event.code)}`); break;
          default: assert.fail(`unexpected mux event ${event.type}`);
        }
      }
      assert.deepEqual(events, step.result);
    }
  });
}

{
  const [v, add] = file('cpace-ristretto255-sha512.json');
  const parts = r => [r.Ya, r.ADa, r.Yb, r.ADb].map(bytes);
  for (const [i, r] of v.prepend_len.entries()) add(`prepend_len ${i + 1}`, () =>
    matches(cpace.prependLen(bytes(r.input)), r.output));
  for (const [i, r] of v.lv_cat.entries()) add(`lv_cat ${i + 1}`, () => matches(cpace.lvCat(...r.inputs.map(bytes)), r.output));
  for (const [i, r] of v.lexiographically_larger.entries()) add(`lexicographic order ${i + 1}`, () =>
    assert.equal(cpace.lexLarger(bytes(r.a), bytes(r.b)), r.larger));
  for (const [i, r] of v.o_cat.entries()) add(`ordered concatenation ${i + 1}`, () =>
    matches(cpace.orderedCat(bytes(r.a), bytes(r.b)), r.output));
  for (const [i, r] of v.transcript_ir.entries()) add(`initiator-responder transcript ${i + 1}`, () =>
    matches(cpace.transcriptIR(...parts(r)), r.output));
  for (const [i, r] of v.transcript_oc.entries()) add(`ordered transcript ${i + 1}`, () =>
    matches(cpace.transcriptOC(...parts(r)), r.output));
  add('B.3.1–B.3.7 full exchange', () => {
    const r = v.cpace;
    const sid = bytes(r.sid);
    const [ya, yb] = [r.ya, r.yb].map(x => cpace.sampleScalar(() => bytes(x)));
    matches(ya, r.ya);
    matches(yb, r.yb);
    matches(cpace.DSI, r.DSI);
    matches(cpace.DSI_ISK, r.DSI_ISK);
    assert.equal(cpace.hashBlockSize, r.s_in_bytes);
    const generator = cpace.generator(bytes(r.PRS), bytes(r.CI), sid);
    assert.equal(generator.zpad, r.zpad_len);
    matches(generator.input, r.generator_string);
    matches(generator.hash, r.generator_hash);
    const g = generator.point.toBytes();
    matches(g, r.g);
    const a = cpace.scalarMult(ya, g);
    const b = cpace.scalarMult(yb, g);
    matches(a, r.Ya);
    matches(b, r.Yb);
    const shared = cpace.scalarMultVerified(ya, b);
    matches(shared, r.K);
    matches(cpace.scalarMultVerified(yb, a), r.K);
    const ir = cpace.transcriptIR(a, bytes(r.ADa), b, bytes(r.ADb));
    const oc = cpace.transcriptOC(a, bytes(r.ADa), b, bytes(r.ADb));
    matches(ir, r.transcript_ir);
    matches(oc, r.transcript_oc);
    const irInput = cpace.iskInput(sid, shared, ir);
    const ocInput = cpace.iskInput(sid, shared, oc);
    matches(irInput, r.isk_input_ir);
    matches(ocInput, r.isk_input_oc);
    matches(cpace.hashTranscript(irInput), r.ISK_IR);
    matches(cpace.hashTranscript(ocInput), r.ISK_SY);
    matches(cpace.sidOutput(ir), r.sid_output_ir);
    matches(cpace.sidOutput(oc), r.sid_output_oc);
  });
  add('B.3.10 valid scalar multiplication', () => {
    const r = v.scalar_mult_valid;
    matches(cpace.scalarMult(bytes(r.s), bytes(r.X)), r.scalar_mult);
    matches(cpace.scalarMultVerified(bytes(r.s), bytes(r.X)), r.scalar_mult_vfy);
  });
  for (const [i, point] of v.scalar_mult_vfy_invalid.points.entries()) add(`B.3.11 invalid point ${i + 1}`, () =>
    matches(cpace.scalarMultVerified(bytes(v.scalar_mult_vfy_invalid.s), bytes(point)), v.scalar_mult_vfy_invalid.result));
}

{
  const [v, add] = file('cpace-ristretto255-sha512-mousse.json');
  const { common } = v;
  const inputs = ad => ({ prs: bytes(common.PRS), ci: bytes(common.CI), sid: bytes(common.sid), ad: bytes(ad) });
  const scalarA = () => bytes(common.ya);
  const scalarB = () => bytes(common.yb);
  for (const r of v.vectors) add(r.name, () => {
    const a = cpace.initiate(inputs(r.ADa), scalarA);
    matches(a.message, r.msg_a);
    matches(a.message.subarray(1, 33), common.Ya);
    const b = cpace.respond(inputs(r.ADb), a.message, scalarB);
    matches(b.message, r.msg_b);
    matches(b.message.subarray(1, 33), common.Yb);
    matches(cpace.scalarMultVerified(scalarA(), b.message.subarray(1, 33)), common.K);
    matches(b.message.subarray(-64), r.Tb);
    const outA = a.finish(b.message);
    matches(outA.isk, r.ISK);
    matches(outA.ad, r.ADb);
    matches(outA.message, r.msg_c);
    matches(outA.message, r.Ta);
    matches(cpace.confirmationKey(bytes(common.sid), outA.isk), r.mac_key);
    const outB = b.finish(outA.message);
    matches(outB.isk, r.ISK);
    matches(outB.ad, r.ADa);
  });
  const draft = v.vectors.find(r => r.name === 'draft-inputs');
  for (const r of v.rejections) add(`${r.stage} ${r.name}`, () => {
    const message = bytes(r.message);
    switch (r.stage) {
      case 'msg_a': return outcome(r.error, () => cpace.respond(inputs(draft.ADb), message, scalarB));
      case 'msg_b': {
        const a = cpace.initiate(inputs(draft.ADa), scalarA);
        return outcome(r.error, () => a.finish(message));
      }
      case 'msg_c': {
        const b = cpace.respond(inputs(draft.ADb), bytes(draft.msg_a), scalarB);
        return outcome(r.error, () => b.finish(message));
      }
      default: assert.fail(`unknown rejection stage ${r.stage}`);
    }
  });
  // Kind 3, Pair with IP (wire.md 10.9 "Binding"): every value rebuilt from the inputs.
  for (const r of v.pairing_runs) add(`pairing run ${r.name}`, () => {
    const prs = bytes(r.PRS);
    const code = directCode(r.lookup + prs.toString('latin1'));
    const binding = { host: bytes(r.host_identity), joiner: bytes(r.joiner_identity), exporter: bytes(r.pair_exporter) };
    const inputs = directCpaceInputs(code, bytes(r.invitation), binding, bytes(r.attempt));
    matches(directInviteDigest(r.lookup, bytes(r.invitation)), r.D);
    matches(inputs.digest, r.D);
    matches(inputs.ci, r.CI);
    matches(directTranscript(bytes(r.D), binding), r.CI);
    matches(inputs.sid, r.sid);
    matches(inputs.prs, r.PRS);
    const generator = cpace.generator(inputs.prs, inputs.ci, inputs.sid);
    assert.equal(generator.zpad, r.zpad_len);
    // The generator string: lv(DSI), lv(PRS), then the zero padding's length byte and the zeros.
    const at = cpace.prependLen(cpace.DSI).length + cpace.prependLen(inputs.prs).length;
    assert.equal(generator.input[at], r.zpad_len);
    assert.ok(generator.input.subarray(at + 1, at + 1 + r.zpad_len).every(x => x === 0));
    matches(cpace.prependLen(inputs.ci), hex(generator.input.subarray(at + 1 + r.zpad_len, at + 1 + r.zpad_len +
      cpace.prependLen(inputs.ci).length)));
    const g = generator.point.toBytes();
    matches(g, r.g);
    const [ya, yb] = [r.ya, r.yb].map(x => cpace.sampleScalar(() => bytes(x)));
    matches(cpace.scalarMult(ya, g), r.Ya);
    matches(cpace.scalarMult(yb, g), r.Yb);
    const a = cpace.initiate(inputs, () => bytes(r.ya));
    matches(a.message, r.msg_a);
    matches(a.message.subarray(1, 33), r.Ya);
    const b = cpace.respond(inputs, a.message, () => bytes(r.yb));
    matches(b.message, r.msg_b);
    matches(b.message.subarray(1, 33), r.Yb);
    matches(b.message.subarray(-64), r.Tb);
    matches(cpace.scalarMultVerified(ya, bytes(r.Yb)), r.K);
    matches(cpace.scalarMultVerified(yb, bytes(r.Ya)), r.K);
    const outA = a.finish(b.message);
    matches(outA.isk, r.ISK);
    matches(outA.message, r.Ta);
    matches(outA.message, r.msg_c);
    matches(cpace.confirmationKey(inputs.sid, outA.isk), r.mac_key);
    matches(b.finish(outA.message).isk, r.ISK);
  });
}

{
  const [v, add] = file('pairing-e2e.json');
  for (const flow of v.flows) add(flow.name, () => replayEndToEnd(flow, v.conventions));
}

{
  const [v, add] = file('pairing-attempts.json');
  for (const sequence of v.sequences) add(sequence.name, () => replayAttemptSequence(sequence, v.conventions));
}

{
  const [v, add] = file('direct-host.json');
  for (const sequence of v.sequences) add(sequence.name, () => replayDirectSequence(sequence, v.conventions));
  add('before_msg_a', () => replayBeforeMsgA(v.before_msg_a, v.conventions));
}

{
  const [v, add] = file('relay-admission.json');
  const d = v.derivations;
  add('derivations: relay id, handles and fingerprints', () => {
    matches(relay.relayId(bytes(d.relay_key)), d.relay_id);
    matches(publicKey(bytes(d.relay_secret)), d.relay_key);
    matches(relay.handleOf(bytes(d.relay_id), bytes(d.registration_key)), d.handle);
    matches(relay.handleOf(bytes(d.relay_id), bytes(d.new_key)), d.new_handle);
    matches(sha256(bytes(d.registration_key)), d.registration_fingerprint);
  });
  add('derivations: relay certificate and pin', () => {
    const certificate = bytes(d.relay_certificate);
    const tbs = relay.relayTbs(bytes(d.relay_key));
    matches(certificate.subarray(4, 4 + tbs.length), hex(tbs));
    const signature = new DerReader(certificate).nested(0x30);
    signature.read(0x30);
    signature.read(0x30);
    const bits = signature.read(3).value;
    assert.equal(bits[0], 0);
    assert.ok(verify(derToRaw(bits.subarray(1)), tbs, bytes(d.relay_key)));
    matches(relay.relayCertificate(bytes(d.relay_secret)), d.relay_certificate);
    matches(relay.relayPinKey(certificate, bytes(d.relay_id)), d.relay_key);
    outcome('pin_mismatch', () => relay.relayPinKey(bytes(d.other_relay_certificate), bytes(d.relay_id)));
    const otherKey = relay.relayCertificateKey(bytes(d.other_relay_certificate));
    assert.notEqual(hex(relay.relayId(otherKey)), d.relay_id);
    matches(relay.relayPinKey(bytes(d.other_relay_certificate), relay.relayId(otherKey)), hex(otherKey));
  });
  for (const item of d.proofs) add(`derivations: ${item.name} proof`, () => {
    const id = bytes(d.relay_id);
    const nonce = bytes(d.nonce);
    const exporter = bytes(d.exporter);
    const built = {
      register: () => relay.registerRecord(id, bytes(d.handle), nonce, exporter),
      successor_new: () => relay.successorRecord(id, bytes(d.new_handle), nonce, exporter),
      successor_current: () => relay.successorRecord(id, bytes(d.new_handle), nonce, exporter),
      call: () => relay.callRecord(id, bytes(d.handle), nonce, exporter, 1n),
      accept: () => relay.acceptRecord(id, bytes(d.handle), bytes(d.circuit), nonce, exporter),
    }[item.name];
    assert.ok(built, `unknown proof ${item.name}`);
    matches(built(), item.record);
    checkRaw(bytes(item.signature));
    assert.ok(verify(bytes(item.signature), bytes(item.record), bytes(item.key)));
    const signer = { register: d.registration_key, successor_new: d.new_key, successor_current: d.registration_key,
      accept: d.registration_key }[item.name];
    if (signer) assert.equal(item.key, signer);
  });
  add('derivations: invitation tag and enrollment code', () => {
    const tag = relay.invitationTag(bytes(d.invitation.id), bytes(d.invitation.secret));
    matches(tag, d.invitation.tag);
    matches(sha256(tag), d.invitation.tag_hash);
    matches(sha256(bytes(d.enrollment.code)), d.enrollment.code_hash);
  });
  for (const link of d.enrollment.links) add(`link ${link.text}`, () => {
    const parsed = relay.parseEnrollmentLink(link.text);
    assert.equal(relay.hostText(parsed.host), link.host);
    assert.equal(parsed.port, link.port);
    matches(parsed.relayId, d.relay_id);
    matches(parsed.code, link.code);
    assert.equal(relay.printEnrollmentLink(parsed), link.text);
  });
  for (const text of d.enrollment.rejected_links) add(`rejected link ${text}`,
    () => outcome('link', () => relay.parseEnrollmentLink(text)));
  for (const [index, item] of v.messages.valid.entries()) add(`valid message ${index} ${item.name}`, () => {
    const message = relay.decodeRelay(bytes(item.hex));
    assert.equal(message.type, item.name);
    matches(relay.encodeRelay(message), item.hex);
  });
  for (const item of v.messages.malformed) add(`malformed message: ${item.why}`,
    () => outcome('malformed', () => relay.decodeRelay(bytes(item.hex))));
  for (const scenario of v.scenarios) add(`scenario ${scenario.name}`, () => {
    let drawn = 0;
    const server = new relay.SelfRelay({
      relayKey: bytes(scenario.relay_key),
      bootId: bytes(scenario.boot_id),
      wallBase: scenario.wall_base,
      authorized: scenario.authorized.map(entry => ({
        fingerprint: bytes(entry.fingerprint),
        dropAt: entry.drop_at,
        chain: entry.chain === undefined ? undefined : bytes(entry.chain),
      })),
      codes: scenario.codes.map(code => ({ hash: bytes(code.hash), expiresAt: code.expires_at })),
      limits: scenario.limits,
      draw(size) {
        assert.ok(drawn < scenario.draws.length, 'ran out of draws');
        const value = bytes(scenario.draws[drawn++]);
        assert.equal(value.length, size, `draw ${drawn} size`);
        return value;
      },
    });
    let last = 0;
    for (const [index, item] of scenario.events.entries()) {
      assert.ok(item.at >= last, 'time goes back');
      last = item.at;
      const event = { ...item };
      if (item.exporter) event.exporter = bytes(item.exporter);
      if (item.hex) event.data = bytes(item.hex);
      if (item.fingerprint) event.fingerprint = bytes(item.fingerprint);
      assert.deepEqual(server.handle(event), item.out, `event ${index} (${item.event} at ${item.at})`);
    }
    assert.equal(drawn, scenario.draws.length, 'unused draws');
  });
}

test('lifecycle checks / a renewed path resets the backoff', () => {
  const window = { not_before: 1000, not_after: 5000 };
  const life = new SessionLifetime(window, window, { now: 1000, mono: 0 });
  assert.equal(life.tick(life.renewAt, 0, true), null);
  assert.equal(life.tick(life.renewAt + 30, 30000), 'renew_due');
  assert.equal(life.tick(life.renewAt + 90, 90000), 'renew_due');
  assert.equal(life.tick(life.renewAt + 99, 99000), null);

  const renewed = { ...window, not_after: 6000 };
  const replacement = new SessionLifetime(renewed, renewed, { now: life.renewAt + 100, mono: 100000 }, life);
  assert.equal(replacement.tick(life.renewAt + 210, 210000), null);
  assert.equal(replacement.tick(replacement.renewAt, 1000000), 'renew_due');
  assert.equal(replacement.tick(replacement.renewAt + 30, 1030000), 'renew_due');
});

test('lifecycle checks / losing PAIRED on the last attempt permits an expired-ticket reconnect', () => {
  const fixture = fixtures.get('pairing-e2e.json');
  const { time, joiner: endpoint } = fixture.conventions;
  const flow = fixture.flows.find(flow => flow.name === 'outcome_after_lost_paired');
  const ticket = bytes(flow.steps.find(step => step.event === 'start').ticket);
  let draw = 0;
  const store = memoryFlowStore();
  const options = { arrival: 'link', store };
  const local = { computerName: endpoint.computer, profileName: endpoint.profile, identity: bytes(endpoint.identity) };
  const draws = { bytes: length => Buffer.alloc(length, ++draw) };
  const joiner = new PairingJoiner(local, ticket, draws, time, options);
  const exporters = { join: Buffer.alloc(32, 1), pair: Buffer.alloc(32, 2) };
  joiner.connect(1, exporters, time);
  joiner.receive(wire.hello);
  joiner.receive({ type: 'AUTHORIZED', state: 'join_only' });

  const code = '012345';
  for (let i = 0; i < 2; i++) {
    const [, , { send }] = joiner.submit(code);
    joiner.receive({ type: 'CODE_ABORT', attempt: send.attempt, code: wire.errorNumber('pairing_failed') });
  }
  const [{ attempt: { ci, sid } }, , { send: first }] = joiner.submit(code);
  const ticketHash = hex(sha256(ticket));
  assert.deepEqual([...decode(store.load(ticketHash)).values()].slice(2), [0n, 0n]);
  const host = cpace.respond({ ci: bytes(ci), sid: bytes(sid), prs: Buffer.from(code), ad: Buffer.alloc(0) },
    first.payload, length => Buffer.alloc(length, 42));
  const [, { send: last }] = joiner.receive({ type: 'CODE_EXCHANGE', attempt: first.attempt, payload: host.message });
  host.finish(last.payload).isk.fill(0);
  assert.deepEqual([...decode(store.load(ticketHash)).values()].slice(2), [0n, 1n]);

  const retryExporters = { join: Buffer.alloc(32, 3), pair: Buffer.alloc(32, 4) };
  const reopenedAt = Number(joiner.ticket.expiresAt) + 600;
  const restored = new PairingJoiner(local, ticket, draws, reopenedAt, options);
  const messages = restored.connect(2, retryExporters, reopenedAt);
  assert.deepEqual(messages.map(effect => effect.send.type), ['HELLO', 'JOIN_PROOF']);
  restored.receive(wire.hello);
  const live = { type: 'AUTHORIZED', state: 'live' };
  assert.deepEqual(restored.receive(live), []);
  const [paired, persisted] = restored.receive({ type: 'PAIRED', name: 'Desk', role: 'owner' });
  assert.deepEqual(paired, { paired: { host_identity: hex(restored.ticket.hostIdentity), host_name: 'Desk', role: 'owner' } });
  assert.ok(store.hasPin(restored.ticket.hostIdentity));
  assert.deepEqual(restored.snapshot(), { attempts_left: 0, live: true, outcome_pending: false,
    state: 'paired', stored: persisted.persist.record });
  assert.throws(() => new PairingJoiner(local, ticket, draws, time, options), { message: 'attempts_exhausted' });
  const wrongRecord = encode(decode(store.load(ticketHash)).set(2n, Buffer.alloc(32)));
  const mismatchedStore = { ...store, load: () => wrongRecord };
  assert.throws(() => new PairingJoiner(local, ticket, draws, time, { ...options, store: mismatchedStore }),
    { message: 'flow_ticket_mismatch' });
});

test('pairing checks / a repeated host share fails the active attempt', () => {
  const { conventions, flows } = fixtures.get('pairing-e2e.json');
  const { time, joiner: endpoint } = conventions;
  const { ticket } = flows.find(flow => flow.name === 'send_link').steps.find(step => step.event === 'start');
  const local = { computerName: endpoint.computer, profileName: endpoint.profile, identity: bytes(endpoint.identity) };
  const joiner = new PairingJoiner(local, bytes(ticket), { bytes: length => Buffer.alloc(length, 3) }, time,
    { arrival: 'link', store: memoryFlowStore() });
  const exporters = { join: Buffer.alloc(32, 1), pair: Buffer.alloc(32, 2) };
  const [, { send: proof }] = joiner.connect(1, exporters, time);
  assert.equal(proof.name, local.computerName);
  joiner.receive(wire.hello);
  joiner.receive({ type: 'AUTHORIZED', state: 'join_only' });
  const code = '012345';
  const [{ attempt: { ci, sid } }, , { send: first }] = joiner.submit(code);
  const host = cpace.respond({ ci: bytes(ci), sid: bytes(sid), prs: Buffer.from(code), ad: Buffer.alloc(0) },
    first.payload, length => Buffer.alloc(length, 42));
  const share = { type: 'CODE_EXCHANGE', attempt: first.attempt, payload: host.message };
  const [, { send: last }] = joiner.receive(share);
  host.finish(last.payload).isk.fill(0);
  const [persist, ...effects] = joiner.receive(share);
  assert.equal(decode(bytes(persist.persist.record)).get(4n), 0n);
  assert.deepEqual(effects, [
    { conn: 1, send: { type: 'CODE_ABORT', attempt: first.attempt, code: wire.errorNumber('pairing_failed') } },
    { code_rejected: { attempts_left: 2 } },
  ]);
});

test('pairing checks / a stale flow cannot send an attempt', () => {
  const { conventions, flows } = fixtures.get('pairing-e2e.json');
  const { time, joiner: endpoint } = conventions;
  const { ticket } = flows.find(flow => flow.name === 'send_link').steps.find(step => step.event === 'start');
  const local = { computerName: endpoint.computer, identity: bytes(endpoint.identity) };
  const store = memoryFlowStore();
  const options = { arrival: 'link', store };
  const draws = { bytes: length => Buffer.alloc(length, 3) };
  const first = new PairingJoiner(local, bytes(ticket), draws, time, options);
  const second = new PairingJoiner(local, bytes(ticket), draws, time, options);
  const exporters = { join: Buffer.alloc(32, 1), pair: Buffer.alloc(32, 2) };
  for (const [index, joiner] of [first, second].entries()) {
    joiner.connect(index + 1, exporters, time);
    joiner.receive(wire.hello);
    joiner.receive({ type: 'AUTHORIZED', state: 'join_only' });
  }
  const [, { persist }, { send }] = first.submit('012345');
  assert.equal(send.type, 'CODE_EXCHANGE');
  assert.deepEqual(second.submit('012345'), [{ failed: 'internal_error' }, { conn: 2, close: 'internal_error' }]);
  assert.equal(second.snapshot().stored, persist.record);
});

test('coverage / all JSON files registered', () => assert.deepEqual([...used].sort(), [...fixtures.keys()].sort()));

test('TLS policy / native transport facts must describe a full hybrid handshake', () => {
  const { valid } = fixtures.get('session-cert.json');
  const certificate = bytes(valid.certificate);
  const pin = bytes(valid.identity_public);
  const handshake = {
    version: 'TLSv1.3', alpn: 'mousse/1', group: 'X25519MLKEM768', signatureScheme: 'ecdsa_secp256r1_sha256',
    mutualCertificates: true, resumed: false, psk: false, earlyData: false,
  };
  assert.deepEqual(nativeTlsPolicy.groups, ['X25519MLKEM768', 'X25519']);
  const authenticate = facts => authenticateNativePeer(facts, certificate, valid.not_before, pin);
  matches(authenticate(handshake).identity, valid.identity_public);
  for (const bad of [{ version: 'TLSv1.2' }, { group: 'X25519' }, { signatureScheme: 'ed25519' },
    { mutualCertificates: false }, { resumed: true }, { psk: true }, { earlyData: true }]) {
    outcome('tls_policy', () => authenticate({ ...handshake, ...bad }));
  }
  outcome('unsupported_version', () => authenticate({ ...handshake, alpn: 'mousse/2' }));
});

test('authorization checks / the proof timeout starts at send and survives the live notice', () => {
  const gate = new Gate('caller');
  gate.sentJoinProof(70);
  assert.equal(gate.timeout(10069), null);
  assert.equal(gate.check('authorized_live'), 'allow');
  assert.equal(gate.timeout(10070), 'not_authorized');
  assert.equal(gate.check('authorized_live'), 'ignore');
});

test('flow control / initial credit, replenishment and FIN', () => {
  const streams = new Streams('host');
  streams.receive({ type: 'open', stream: 1, class: 0, label: 'rpc' });
  const data = { type: 'data', stream: 1, payload: new Uint8Array(65536) };
  for (let i = 0; i < 4; i++) streams.receive(data);
  assert.equal(streams.consume(1, 65535), undefined);
  assert.deepEqual(streams.consume(1, 1), { type: 'credit', stream: 1, increment: 65536 });
  streams.receive(data);
  streams.receive({ type: 'fin', stream: 1 });
  assert.equal(streams.consume(1, 65536), undefined);
  streams.sent({ type: 'fin', stream: 1 });
  assert.deepEqual(streams.receive(data), {});
});

test('flow control / exceeding receive credit closes the mux', () => {
  const streams = new Streams('host');
  streams.receive({ type: 'open', stream: 1, class: 0, label: 'rpc' });
  const data = { type: 'data', stream: 1, payload: new Uint8Array(65536) };
  for (let i = 0; i < 4; i++) streams.receive(data);
  assert.deepEqual(streams.receive(data), { reply: { type: 'goaway', code: wire.errorNumber('flow_control') } });
});

test('flow control / peer stream cap and send-credit cap', () => {
  const streams = new Streams('caller');
  for (let i = 1; i <= 1024; i++) streams.receive({ type: 'open', stream: i * 2, class: 0, label: 'rpc' });
  const refused = { type: 'open', stream: 2050, class: 0, label: 'rpc' };
  assert.deepEqual(streams.receive(refused),
    { reply: { type: 'reset', stream: 2050, code: wire.errorNumber('refused_stream') } });
  streams.receive({ type: 'reset', stream: 2, code: wire.errorNumber('cancelled') });
  const next = { ...refused, stream: 2052 };
  assert.deepEqual(streams.receive(next), { event: next });
  streams.receive({ type: 'credit', stream: 4, increment: 2 ** 30 - 262144 });
  assert.deepEqual(streams.receive({ type: 'credit', stream: 4, increment: 1 }),
    { reply: { type: 'goaway', code: wire.errorNumber('flow_control') } });
});

test('flow control / only the caller can open the first stream', () => {
  const host = new Streams('host', new Gate('host', 'live'));
  const callerGate = new Gate('caller');
  assert.equal(callerGate.check('authorized_live'), 'allow');
  const caller = new Streams('caller', callerGate);
  const hostOpen = { type: 'open', stream: 2, class: 0, label: 'rpc' };
  const callerOpen = { ...hostOpen, stream: 1 };
  outcome('protocol_error', () => host.sent(hostOpen));
  caller.sent(callerOpen);
  assert.deepEqual(host.receive(callerOpen), { event: callerOpen });
  host.sent(hostOpen);
  assert.deepEqual(caller.receive(hostOpen), { event: hostOpen });
});
