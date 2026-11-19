// Self-tests of the relay, the chat page and the Plus recorder, on loopback.
// Run: node --test tools/app-check/test/
import assert from 'node:assert/strict'
import net from 'node:net'
import { test } from 'node:test'

import { allowedLink, page, serve as servePage } from '../chat-page.mjs'
import { selfTest, sortRequests, startRecorder } from '../recorder.mjs'
import { dial, limits, MAGIC, serve } from '../relay.mjs'

const TOKEN = 'a'.repeat(32)
const env = {}

function echoServer() {
  const server = net.createServer((s) => s.pipe(s))
  return new Promise((done) => server.listen(0, '127.0.0.1', () => done(server)))
}

function roundTrip(port, text) {
  return new Promise((done) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(text))
    let got = ''
    s.on('data', (d) => {
      got += d
      if (got.length >= text.length) {
        s.end()
        done(got)
      }
    })
    // A refused connection may reset: what arrived so far is the answer.
    s.on('error', () => done(got))
    s.on('close', () => done(got))
  })
}

test('the relay carries a Mac connection to the PC loopback listener over one dialled connection', async () => {
  const echo = await echoServer()
  const relay = await serve({ listen: '127.0.0.1:0', control: '127.0.0.1:0', token: TOKEN, env })
  const pc = await dial({
    relay: `127.0.0.1:${relay.control.port}`,
    to: `127.0.0.1:${echo.address().port}`,
    token: TOKEN,
    env
  })
  await new Promise((r) => setTimeout(r, 100))
  const big = 'x'.repeat(200_000)
  assert.equal(await roundTrip(relay.listen.port, 'hello through the relay'), 'hello through the relay')
  assert.equal((await roundTrip(relay.listen.port, big)).length, big.length)
  pc.close()
  await relay.close()
  echo.close()
})

test('a wrong token gets no control connection, and with no PC a relayed connection is closed', async () => {
  const relay = await serve({ listen: '127.0.0.1:0', control: '127.0.0.1:0', token: TOKEN, env })
  const closed = await new Promise((done) => {
    const s = net.connect(relay.control.port, '127.0.0.1', () => s.write(`${MAGIC} ${'b'.repeat(32)}\n`))
    s.on('close', () => done(true))
    s.on('error', () => {})
  })
  assert.ok(closed)
  assert.equal(await roundTrip(relay.listen.port, 'nobody'), '')
  await relay.close()
})

test('relay limits only tighten', () => {
  assert.equal(limits({}).MAX_STREAMS, 16)
  assert.equal(limits({ MOUSSE_NET_RELAY_MAX_STREAMS: '4' }).MAX_STREAMS, 4)
  assert.throws(() => limits({ MOUSSE_NET_RELAY_MAX_STREAMS: '17' }))
  assert.throws(() => limits({ MOUSSE_NET_RELAY_FRAME_MAX_BYTES: '70000' }))
})

test('the chat page shows the link as its one anchor and refuses other schemes', async () => {
  const link = 'mousse://pair#ab"c<d>'
  assert.ok(page(link).includes('href="mousse://pair#ab&quot;c&lt;d&gt;"'))
  assert.equal(allowedLink('javascript:alert(1)'), false)
  assert.throws(() => page('javascript:alert(1)'))
  const s = await servePage('mousse://pair#xyz')
  const body = await (await fetch(s.url)).text()
  assert.ok(body.includes('href="mousse://pair#xyz"'))
  assert.equal((await fetch(`${s.url}other`)).status, 404)
  await s.close()
})

test('the Plus recorder records every request, answers 403, and sorts update checks apart', async () => {
  const r = await startRecorder()
  await selfTest(r)
  assert.equal(r.requests().length, 0)
  assert.equal((await fetch(`${r.url}/v1/session`, { method: 'POST', body: 'x' })).status, 403)
  assert.equal((await fetch(`${r.url}/update-feed/latest.yml`)).status, 403)
  const { plus, updates } = sortRequests(r.requests())
  assert.deepEqual(plus.map((x) => x.url), ['/v1/session'])
  assert.deepEqual(updates.map((x) => x.url), ['/update-feed/latest.yml'])
  await r.close()
})
