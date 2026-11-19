#!/usr/bin/env node
/**
 * The kit relay for the attested chat-link check (Phase 1b §14, "Reverse
 * direction"): the Mac must reach the PC, but the PC listens only on
 * loopback. The relay runs on the Mac; the PC dials it once and carries the
 * Mac's connections back to its own loopback listener.
 *
 *   # Mac (listens; the only side that does)
 *   node relay.mjs serve --listen <mac LAN ip>:<port> --control <mac LAN ip>:<port> --token-file <file>
 *   # PC (dials one outbound connection)
 *   node relay.mjs dial --relay <mac LAN ip>:<control port> --to 127.0.0.1:<helper port> --token-file <file>
 *
 * The PC shares the `--listen` address in pairback; the Mac's helper dials
 * it, and the relay hands each such connection to the PC over the one
 * control connection, where it is spliced to `--to`. Bytes are carried as
 * they are: the peer TLS runs end to end, so the relay sees no content.
 *
 * The control connection starts with `mousse-relay/1 <token>\n`; the token
 * (32 hex digits or more, from the token file, the same on both sides) is
 * compared in constant time, and a wrong one closes the connection. One
 * control connection at a time. Then frames: u32 BE stream id, u8 type
 * (1 open, 2 data, 3 close), u32 BE length, payload.
 *
 * Limits (relay: MOUSSE_NET_RELAY_*, each a named default; the stream and
 * frame caps can only be tightened):
 * - MOUSSE_NET_RELAY_MAX_STREAMS (16, 1 to 16): relayed connections at once;
 * - MOUSSE_NET_RELAY_FRAME_MAX_BYTES (65536, 1024 to 65536): one frame;
 * - MOUSSE_NET_RELAY_HELLO_WAIT_MS (5000, 100 to 60000): for the first line.
 */
import { timingSafeEqual } from 'node:crypto'
import { readFileSync } from 'node:fs'
import net from 'node:net'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const MAGIC = 'mousse-relay/1'
const OPEN = 1
const DATA = 2
const CLOSE = 3

const LIMITS = [
  ['MAX_STREAMS', 16, 1, 16],
  ['FRAME_MAX_BYTES', 65536, 1024, 65536],
  ['HELLO_WAIT_MS', 5000, 100, 60000]
]

/** The relay's limits from `env` (MOUSSE_NET_RELAY_*), or an error. */
export function limits(env = process.env) {
  const out = {}
  for (const [name, def, min, max] of LIMITS) {
    const raw = env[`MOUSSE_NET_RELAY_${name}`]
    const v = raw === undefined ? def : Number(raw)
    if (!Number.isInteger(v) || v < min || v > max) {
      throw new Error(`MOUSSE_NET_RELAY_${name}=${raw} is outside ${min} to ${max}`)
    }
    out[name] = v
  }
  return out
}

function frame(id, type, payload = Buffer.alloc(0)) {
  const h = Buffer.alloc(9)
  h.writeUInt32BE(id, 0)
  h.writeUInt8(type, 4)
  h.writeUInt32BE(payload.length, 5)
  return Buffer.concat([h, payload])
}

/** Reads frames from a socket; calls `on(id, type, payload)`; errors close. */
function frameReader(sock, max, on) {
  let buf = Buffer.alloc(0)
  return (d) => {
    buf = buf.length ? Buffer.concat([buf, d]) : d
    while (buf.length >= 9) {
      const len = buf.readUInt32BE(5)
      if (len > max) {
        sock.destroy(new Error(`relay frame of ${len} bytes is over MOUSSE_NET_RELAY_FRAME_MAX_BYTES`))
        return
      }
      if (buf.length < 9 + len) return
      on(buf.readUInt32BE(0), buf.readUInt8(4), buf.subarray(9, 9 + len))
      buf = buf.subarray(9 + len)
    }
  }
}

function addr(text) {
  const m = /^\[?([^\]]+)\]?:(\d+)$/.exec(text ?? '')
  if (!m) throw new Error(`${text} is not <ip>:<port>`)
  if (net.isIP(m[1]) === 0) throw new Error(`${text}: an IP literal, not a name`)
  return { host: m[1], port: Number(m[2]) }
}

export function readToken(file) {
  const t = readFileSync(file, 'utf8').trim()
  if (!/^[0-9a-f]{32,}$/i.test(t)) throw new Error(`${file}: the token is 32 or more hex digits`)
  return t
}

function sameToken(a, b) {
  const x = Buffer.from(a)
  const y = Buffer.from(b)
  return x.length === y.length && timingSafeEqual(x, y)
}

/** Send `chunk` in frames no bigger than `max`. */
function sendData(ctl, id, chunk, max) {
  for (let at = 0; at < chunk.length; at += max) ctl.write(frame(id, DATA, chunk.subarray(at, at + max)))
}

/** The Mac side. Resolves to { listen, control, close } once both listen. */
export async function serve({ listen, control, token, env = process.env, log = () => {} }) {
  const lim = limits(env)
  let ctl // the PC's control connection
  const streams = new Map()
  let next = 1
  const controlServer = net.createServer((sock) => {
    let hello = ''
    let ready = false
    const timer = setTimeout(() => sock.destroy(), lim.HELLO_WAIT_MS)
    const onFrame = (id, type, payload) => {
      const s = streams.get(id)
      if (!s) return
      if (type === DATA) s.write(payload)
      if (type === CLOSE) s.end()
    }
    const reader = frameReader(sock, lim.FRAME_MAX_BYTES + 9, onFrame)
    sock.on('data', (d) => {
      if (ready) return reader(d)
      hello += d.toString('latin1')
      if (hello.length > 256) return sock.destroy()
      const nl = hello.indexOf('\n')
      if (nl < 0) return undefined
      clearTimeout(timer)
      const [magic, given] = hello.slice(0, nl).trim().split(' ')
      if (magic !== MAGIC || !given || !sameToken(given, token) || ctl) {
        log('relay: refused a control connection')
        return sock.destroy()
      }
      ready = true
      ctl = sock
      log('relay: the PC is connected')
      const rest = Buffer.from(hello.slice(nl + 1), 'latin1')
      if (rest.length) reader(rest)
      return undefined
    })
    sock.on('close', () => {
      clearTimeout(timer)
      if (ctl === sock) {
        ctl = undefined
        for (const s of streams.values()) s.destroy()
        streams.clear()
      }
    })
    sock.on('error', () => {})
  })
  const listenServer = net.createServer((s) => {
    if (!ctl || streams.size >= lim.MAX_STREAMS) {
      s.destroy()
      return
    }
    const id = next++
    streams.set(id, s)
    const c = ctl
    c.write(frame(id, OPEN))
    s.on('data', (d) => sendData(c, id, d, lim.FRAME_MAX_BYTES))
    s.on('close', () => {
      if (streams.delete(id) && !c.destroyed) c.write(frame(id, CLOSE))
    })
    s.on('error', () => {})
  })
  const bind = (server, a) =>
    new Promise((done, fail) => {
      server.once('error', fail)
      server.listen(a.port, a.host, () => done(server.address()))
    })
  const l = await bind(listenServer, addr(listen))
  const k = await bind(controlServer, addr(control))
  return {
    listen: l,
    control: k,
    close: async () => {
      ctl?.destroy()
      for (const s of streams.values()) s.destroy()
      await Promise.all([listenServer, controlServer].map((srv) => new Promise((d) => srv.close(() => d()))))
    }
  }
}

/** The PC side: one outbound control connection. Resolves to { close, closed }. */
export async function dial({ relay, to, token, env = process.env, log = () => {} }) {
  const lim = limits(env)
  const r = addr(relay)
  const target = addr(to)
  if (!net.isIP(target.host) || !['127.0.0.1', '::1'].includes(target.host)) {
    throw new Error('--to is this computer\'s loopback listener')
  }
  const ctl = net.connect(r.port, r.host)
  await new Promise((done, fail) => {
    ctl.once('connect', done)
    ctl.once('error', fail)
  })
  ctl.write(`${MAGIC} ${token}\n`)
  const streams = new Map()
  ctl.on('data', frameReader(ctl, lim.FRAME_MAX_BYTES + 9, (id, type, payload) => {
    if (type === OPEN) {
      if (streams.size >= lim.MAX_STREAMS) return ctl.write(frame(id, CLOSE))
      const s = net.connect(target.port, target.host)
      streams.set(id, s)
      s.on('data', (d) => sendData(ctl, id, d, lim.FRAME_MAX_BYTES))
      s.on('close', () => {
        if (streams.delete(id) && !ctl.destroyed) ctl.write(frame(id, CLOSE))
      })
      s.on('error', () => {})
      return undefined
    }
    const s = streams.get(id)
    if (!s) return undefined
    if (type === DATA) s.write(payload)
    if (type === CLOSE) s.end()
    return undefined
  }))
  const closed = new Promise((done) => ctl.on('close', done))
  ctl.on('error', () => {})
  log(`relay: dialled ${relay}, carrying to ${to}`)
  return {
    closed,
    close: () => {
      ctl.destroy()
      for (const s of streams.values()) s.destroy()
    }
  }
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2)
  const value = (n) => {
    const i = args.indexOf(n)
    return i >= 0 ? args[i + 1] : undefined
  }
  const tokenFile = value('--token-file')
  if (!tokenFile) {
    console.error('relay.mjs: --token-file is required')
    process.exit(2)
  }
  const token = readToken(tokenFile)
  const log = (m) => console.error(m)
  if (cmd === 'serve') {
    const s = await serve({ listen: value('--listen'), control: value('--control'), token, log })
    console.log(`relay_listen=${s.listen.address}:${s.listen.port}`)
    console.log(`relay_control=${s.control.address}:${s.control.port}`)
  } else if (cmd === 'dial') {
    const d = await dial({ relay: value('--relay'), to: value('--to'), token, log })
    await d.closed
    console.error('relay: the control connection ended')
    process.exit(1)
  } else {
    console.error('usage: node relay.mjs serve|dial ... (see the header)')
    process.exit(2)
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`relay.mjs: ${e.message}`)
    process.exit(2)
  })
}
