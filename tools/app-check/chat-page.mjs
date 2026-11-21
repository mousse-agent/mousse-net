#!/usr/bin/env node
/**
 * The chat fixture of `phase1b.pair-by-chat-link` (Phase 1b §14): a static
 * page on loopback that shows one chat message holding the Send link, so
 * the tester can open it in the default browser and click the link without
 * any chat account.
 *
 *   node tools/app-check/chat-page.mjs --link <link> [--port <port>]
 *
 * Prints `chat_page=http://127.0.0.1:<port>/` and serves until stopped.
 * Only `mousse:` and `https:` links are shown; the page loads nothing from
 * anywhere else.
 */
import { createServer } from 'node:http'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Whether `link` may be shown as a link. */
export function allowedLink(link) {
  try {
    const u = new URL(link)
    return u.protocol === 'mousse:' || u.protocol === 'https:'
  } catch {
    return false
  }
}

const escape = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

/** The page, with the link as the one message's anchor. */
export function page(link) {
  if (!allowedLink(link)) throw new Error('the chat page shows only mousse: and https: links')
  const l = escape(link)
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Chat (check fixture)</title>
<style>body{font:15px system-ui,sans-serif;max-width:40em;margin:3em auto;color:#222}
.msg{background:#eef;border-radius:12px;padding:.8em 1em;margin:.5em 0}.who{font-size:12px;color:#666}
a{word-break:break-all}</style></head>
<body><p class="who">Mac</p>
<div class="msg">Join me on Mousse: <a id="link" href="${l}">${l}</a></div>
<p class="who">Check fixture: no chat account, served on loopback.</p>
</body></html>
`
}

/** Serve the page on 127.0.0.1; resolves to { url, close }. */
export async function serve(link, port = 0) {
  const body = page(link)
  const server = createServer((req, res) => {
    if (req.method !== 'GET' || (req.url !== '/' && req.url !== '/index.html')) {
      res.writeHead(404).end()
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    res.end(body)
  })
  await new Promise((done, fail) => {
    server.once('error', fail)
    server.listen(port, '127.0.0.1', done)
  })
  return {
    url: `http://127.0.0.1:${server.address().port}/`,
    close: () => new Promise((done) => server.close(() => done()))
  }
}

async function main() {
  const args = process.argv.slice(2)
  const value = (n) => {
    const i = args.indexOf(n)
    return i >= 0 ? args[i + 1] : undefined
  }
  const link = value('--link')
  if (!link || !allowedLink(link)) {
    console.error('usage: node tools/app-check/chat-page.mjs --link <mousse: or https: link> [--port <port>]')
    process.exit(2)
  }
  const { url } = await serve(link, Number(value('--port') ?? 0))
  console.log(`chat_page=${url}`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
