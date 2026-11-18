// Runs the browser Worker spike in one browser and writes the raw result.
//
//   node scripts/run.mjs --browser chromium|firefox|safari [--channel msedge|chrome]
//        [--control tampered-cert|fresh-key-after-restart] --out <dir>
//        [--runner <path>] [--build <id>] [--platform <text>]
//
// Starts browser-worker-runner (127.0.0.1 only), opens its page headless
// (Playwright for Chromium and Firefox, safaridriver for Safari), waits for
// the runner's verdict and closes everything it started. Writes
// <check>__<cell>[__<control>].json and .log into --out.
//
// Exit 0 when the outcome is the expected one (PASS for a normal run, FAIL
// for a control), 1 when it is not, 3 when Safari needs the owner to allow
// remote automation.

import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHECK = 'phase0.browser-worker-cert';
const CONTROLS = { 'tampered-cert': 'tampered-cert', 'fresh-key-after-restart': 'fresh-key' };
const here = dirname(fileURLToPath(import.meta.url));
const spike = resolve(here, '..');

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const browserName = opt('--browser');
const control = opt('--control');
const outDir = opt('--out');
if (!['chromium', 'firefox', 'safari'].includes(browserName) || !outDir || (control && !CONTROLS[control])) {
  console.error('usage: node scripts/run.mjs --browser chromium|firefox|safari [--channel msedge] [--control tampered-cert|fresh-key-after-restart] --out <dir>');
  process.exit(2);
}

function gitBuild() {
  const git = (...a) => execFileSync('git', a, { cwd: spike, encoding: 'utf8' }).trim();
  const sha = git('rev-parse', '--short=9', 'HEAD');
  const dirty = git('status', '--porcelain', '--', '.', '../../crates/mousse-net-core') !== '';
  return `${sha}${dirty ? '-dirty' : ''}+release`;
}

const target = `wasm32-unknown-unknown@worker-${browserName}`;
const build = opt('--build') ?? gitBuild();
const exe = process.platform === 'win32' ? 'browser-worker-runner.exe' : 'browser-worker-runner';
const runnerPath = opt('--runner') ?? join(process.env.CARGO_TARGET_DIR ?? join(spike, 'target'), 'release', exe);
const base = `${CHECK}__${target.replace(/[^A-Za-z0-9.-]+/g, '-')}${control ? `__${control}` : ''}`;
mkdirSync(outDir, { recursive: true });
const resultFile = resolve(outDir, `${base}.json`);
const logLines = [];
const log = (line) => {
  logLines.push(line);
  console.log(line);
};

const env = { ...process.env };
delete env.MOUSSE_BROWSER_SPIKE_BREAK;
if (control) env.MOUSSE_BROWSER_SPIKE_BREAK = CONTROLS[control];
log(`run ${CHECK} target=${target} control=${control ?? 'none'} build=${build}`);

const runner = spawn(runnerPath, ['--web', join(spike, 'web'), '--target', target, '--build', build,
  '--out', resultFile, '--platform', opt('--platform') ?? `${process.platform}-${process.arch}`, '--timeout', '90'],
{ env, stdio: ['ignore', 'pipe', 'pipe'] });
const runnerExit = new Promise((resolveExit) => runner.on('exit', (code) => resolveExit(code)));
const url = await new Promise((resolveUrl, reject) => {
  let buffer = '';
  runner.stdout.on('data', (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trimEnd();
      buffer = buffer.slice(nl + 1);
      log(`runner: ${line}`);
      if (line.startsWith('READY ')) resolveUrl(line.slice(6));
    }
  });
  runner.stderr.on('data', (chunk) => log(`runner stderr: ${String(chunk).trimEnd()}`));
  runnerExit.then((code) => reject(new Error(`runner exited early (${code})`)));
});

function freePort() {
  return new Promise((resolvePort) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolvePort(port));
    });
  });
}

async function openPlaywright() {
  const playwright = await import('playwright');
  const type = browserName === 'chromium' ? playwright.chromium : playwright.firefox;
  const channel = opt('--channel');
  const browser = await type.launch({ headless: true, ...(channel ? { channel } : {}) });
  log(`browser: ${browserName}${channel ? ` (${channel})` : ''} ${browser.version()}`);
  const page = await (await browser.newContext()).newPage();
  page.on('console', (m) => log(`console.${m.type()}: ${m.text()}`));
  page.on('pageerror', (e) => log(`pageerror: ${e}`));
  await page.goto(url);
  return async () => browser.close();
}

async function openSafari() {
  const port = await freePort();
  const driver = spawn('/usr/bin/safaridriver', ['--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  driver.stderr.on('data', (c) => log(`safaridriver: ${String(c).trimEnd()}`));
  const stopDriver = () => new Promise((r) => {
    if (driver.exitCode !== null) return r();
    driver.on('exit', r);
    driver.kill();
  });
  const call = async (method, path, body) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json().catch(() => ({})) };
  };
  for (let i = 0; ; i++) {
    try {
      if ((await call('GET', '/status')).status === 200) break;
    } catch { /* not up yet */ }
    if (driver.exitCode !== null) {
      // Without "Allow Remote Automation" its service is refused by
      // webinspectord and safaridriver exits at once, silently.
      const message = `safaridriver exited with ${driver.exitCode} before listening`;
      log(message);
      return { needsOwner: message };
    }
    if (i > 50) {
      await stopDriver();
      throw new Error('safaridriver did not start');
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  const session = await call('POST', '/session', { capabilities: { alwaysMatch: { browserName: 'safari' } } });
  const sessionId = session.json?.value?.sessionId;
  if (!sessionId) {
    const message = session.json?.value?.message ?? JSON.stringify(session.json);
    log(`safaridriver session refused: ${message}`);
    await stopDriver();
    return { needsOwner: message };
  }
  const caps = session.json.value.capabilities ?? {};
  log(`browser: safari ${caps.browserVersion ?? '?'} (${caps.platformName ?? '?'})`);
  await call('POST', `/session/${sessionId}/url`, { url });
  return async () => {
    await call('DELETE', `/session/${sessionId}`).catch(() => {});
    await stopDriver();
  };
}

let close = async () => {};
let needsOwner = null;
let opened = false;
try {
  const result = browserName === 'safari' ? await openSafari() : await openPlaywright();
  if (typeof result === 'function') {
    close = result;
    opened = true;
  } else {
    needsOwner = result.needsOwner;
  }
} catch (e) {
  log(`browser failed: ${(e && e.stack) || e}`);
}
// Without a browser there is nothing to wait for.
if (!opened) runner.kill();
const code = await runnerExit;
await close().catch((e) => log(`close failed: ${e}`));
const outcome = code === 0 ? 'PASS' : code === 1 ? 'FAIL' : 'NO RESULT';
const expected = control ? 'FAIL' : 'PASS';
log(needsOwner !== null ? 'Safari needs the owner: allow remote automation' :
  `outcome ${outcome}, expected ${expected}: ${outcome === expected ? 'as expected' : 'NOT as expected'}`);
writeFileSync(resolve(outDir, `${base}.log`), logLines.join('\n') + '\n');
process.exit(needsOwner !== null ? 3 : outcome === expected ? 0 : 1);
