/**
 * Egress guard for app checks (Phase 1b §14, "Plus and egress"). Loaded
 * before any other code (`node --require`, through NODE_OPTIONS, or by the
 * app's check mode from MOUSSE_CHECK_EGRESS_GUARD). It refuses, and
 * records, every socket and name lookup that would leave the cell:
 *
 * - TCP and TLS connects to anything but loopback and the addresses in
 *   MOUSSE_NET_TEST_EGRESS (comma-separated IP literals; the Mac's address
 *   in cross-machine cells);
 * - name lookups (dns.lookup, dns.resolve*, and their promise forms) of
 *   anything but `localhost`;
 * - UDP sends to anything but loopback.
 *
 * Local IPC (Unix sockets, Windows named pipes) is allowed. Each refused
 * attempt appends one JSON line to MOUSSE_CHECK_EGRESS_LOG and fails
 * the call with EACCES, so an endpoint the Plus redirect missed cannot get
 * out unseen. tools/app-check/run.mjs fails the run with `egress_attempted`
 * when the log has any line.
 */
'use strict'

const net = require('node:net')
const dns = require('node:dns')
const dgram = require('node:dgram')
const fs = require('node:fs')

const LOG = process.env.MOUSSE_CHECK_EGRESS_LOG
const allowed = new Set(
  (process.env.MOUSSE_NET_TEST_EGRESS || '')
    .split(',')
    .map((s) => s.trim().replace(/^\[|\]$/g, '').toLowerCase())
    .filter(Boolean)
)

function isLoopback(host) {
  if (typeof host !== 'string') return false
  const h = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true
  if (/^127\.\d+\.\d+\.\d+$/.test(h)) return true
  const mapped = /^::ffff:(127\.\d+\.\d+\.\d+)$/.exec(h)
  return Boolean(mapped)
}

function permitted(host) {
  if (host === undefined || host === null || host === '') return true // Node defaults to localhost
  const h = String(host).replace(/^\[|\]$/g, '').toLowerCase()
  return isLoopback(h) || allowed.has(h)
}

function record(kind, target) {
  const line = JSON.stringify({ kind, target: String(target), pid: process.pid, time: new Date().toISOString() })
  if (LOG) {
    try {
      fs.appendFileSync(LOG, `${line}\n`)
    } catch {
      // The refusal stands even if it cannot be written down.
    }
  }
  process.emitWarning(`mousse egress guard refused ${kind} to ${target}`)
}

function refusal(kind, target) {
  record(kind, target)
  const e = new Error(`egress refused by the check kit: ${kind} to ${target}`)
  e.code = 'EACCES'
  return e
}

// Every TCP connect, including http, https, tls and fetch, ends here.
const connect = net.Socket.prototype.connect
net.Socket.prototype.connect = function guardedConnect(...args) {
  let opts = args[0]
  if (Array.isArray(opts)) opts = opts[0] // internal normalized form
  let host
  let path
  if (opts !== null && typeof opts === 'object') {
    host = opts.host
    path = opts.path
  } else if (typeof opts === 'string' && Number.isNaN(Number(opts))) {
    path = opts
  } else {
    host = typeof args[1] === 'string' ? args[1] : undefined
  }
  if (path === undefined && !permitted(host)) {
    const e = refusal('tcp', `${host}:${opts?.port ?? opts}`)
    process.nextTick(() => this.destroy(e))
    return this
  }
  return connect.apply(this, args)
}

function guardLookup(obj, name, kind) {
  const original = obj[name]
  if (typeof original !== 'function') return
  obj[name] = function guarded(hostname, ...rest) {
    if (typeof hostname === 'string' && !isLoopback(hostname) && !allowed.has(hostname.toLowerCase())) {
      const e = refusal(kind, hostname)
      const cb = rest.find((r) => typeof r === 'function')
      if (cb) {
        process.nextTick(() => cb(e))
        return undefined
      }
      return Promise.reject(e)
    }
    return original.call(this, hostname, ...rest)
  }
}

for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveTxt', 'resolveSrv']) {
  guardLookup(dns, name, 'dns')
  guardLookup(dns.promises, name, 'dns')
}
if (dns.Resolver) {
  for (const name of ['resolve', 'resolve4', 'resolve6', 'resolveAny']) {
    guardLookup(dns.Resolver.prototype, name, 'dns')
    if (dns.promises.Resolver) guardLookup(dns.promises.Resolver.prototype, name, 'dns')
  }
}

const send = dgram.Socket.prototype.send
dgram.Socket.prototype.send = function guardedSend(msg, ...rest) {
  // send(msg[, offset, length], port[, address][, callback])
  const address = rest.find((r, i) => typeof r === 'string' && i > 0)
  if (address !== undefined && !permitted(address)) {
    const e = refusal('udp', address)
    const cb = rest.find((r) => typeof r === 'function')
    if (cb) process.nextTick(() => cb(e))
    return undefined
  }
  return send.call(this, msg, ...rest)
}
