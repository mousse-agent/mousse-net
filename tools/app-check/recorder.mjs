/**
 * The Plus stand-in for app checks (Phase 1b §14, "Plus and egress"): a
 * loopback HTTP server that accepts any request, records it, and answers
 * 403. The app's Plus endpoints (MOUSSE_ID_ORIGIN, MOUSSE_PLUS_ORIGIN) and
 * its update feed (MOUSSE_UPDATE_FEED_URL, under /update-feed) point here,
 * so an app that asks Plus anything during a check is caught: run.mjs fails
 * the run with `plus_contacted` (or `egress_attempted` for the update feed).
 *
 * It never forwards anything and knows nothing about Plus itself.
 */
import { appendFileSync } from 'node:fs'
import { createServer, request } from 'node:http'

export const UPDATE_FEED_PATH = '/update-feed'

/**
 * Start the recorder on 127.0.0.1. `log`: a file to append one JSON line
 * per request to. Resolves to { url, requests(), clear(), close() }.
 */
export async function startRecorder({ log } = {}) {
  const seen = []
  const server = createServer((req, res) => {
    let size = 0
    req.on('data', (d) => {
      size += d.length
    })
    req.on('end', () => {
      const entry = {
        time: new Date().toISOString(),
        method: req.method,
        url: req.url,
        host: req.headers.host,
        body_bytes: size
      }
      seen.push(entry)
      if (log) appendFileSync(log, `${JSON.stringify(entry)}\n`)
      res.writeHead(403, { 'content-type': 'application/json', connection: 'close' })
      res.end('{"error":"forbidden","detail":"recorded by the mousse-net check kit"}')
    })
  })
  await new Promise((done, fail) => {
    server.once('error', fail)
    server.listen(0, '127.0.0.1', done)
  })
  const { port } = server.address()
  return {
    url: `http://127.0.0.1:${port}`,
    requests: () => seen.slice(),
    clear: () => {
      seen.length = 0
    },
    close: () => new Promise((done) => server.close(() => done()))
  }
}

/** Requests that went to Plus, and those that were update checks. */
export function sortRequests(requests) {
  const updates = requests.filter((r) => r.url?.startsWith(UPDATE_FEED_PATH))
  const plus = requests.filter((r) => !r.url?.startsWith(UPDATE_FEED_PATH))
  return { plus, updates }
}

/**
 * The recorder's self-test: one request must come back 403 and be recorded.
 * Throws if not, so a run never relies on a recorder that records nothing.
 */
export async function selfTest(recorder) {
  const status = await new Promise((done, fail) => {
    const req = request(`${recorder.url}/kit-self-test`, { method: 'POST' }, (res) => {
      res.resume()
      res.on('end', () => done(res.statusCode))
    })
    req.on('error', fail)
    req.end('x')
  })
  const got = recorder.requests().filter((r) => r.url === '/kit-self-test')
  if (status !== 403 || got.length !== 1) {
    throw new Error(`the Plus recorder did not record its self-test (status ${status}, ${got.length} recorded)`)
  }
  recorder.clear()
}
