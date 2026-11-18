#!/usr/bin/env node
// Runs the browser Worker spike headless and has the native verifier judge it.
//
//   node run.mjs [--browser chromium|webkit|firefox|all] [--break <mode>]
//                [--all] [--no-build] [--build <id>] [--results <dir>]
//
// --break    a must-fail control: tampered-cert, fresh-key, der-signature
//            (applied in the Worker) or skip-pin (applied in the verifier).
//            MOUSSE_BROWSER_SPIKE_BREAK sets it too.
// --all      the normal run and every control, for every browser chosen.
//
// The last line is `PASS phase0.browser-worker-cert` or
// `FAIL phase0.browser-worker-cert`; the exit code matches.

import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const CHECK = 'phase0.browser-worker-cert';
const BROWSERS = ['chromium', 'webkit', 'firefox'];
// Cells in checks/phase0.toml. Playwright's WebKit stands in for Safari.
const TARGETS = {
  chromium: 'wasm32-unknown-unknown@worker-chromium',
  webkit: 'wasm32-unknown-unknown@worker-safari',
  firefox: 'wasm32-unknown-unknown@worker-firefox',
};
// Break mode -> control name in checks/phase0.toml (the last two are extra).
const CONTROLS = {
  'tampered-cert': 'tampered-cert',
  'fresh-key': 'fresh-key-after-restart',
  'der-signature': 'der-signature',
  'skip-pin': 'skip-pin',
};
const PROFILE = 'release';

function parseArgs(argv) {
  const a = {
    browsers: BROWSERS,
    break: process.env.MOUSSE_BROWSER_SPIKE_BREAK || 'none',
    all: false,
    build: null,
    noBuild: false,
    results: join(HERE, 'results'),
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${flag} needs a value`);
      return argv[++i];
    };
    if (flag === '--browser') {
      const b = value();
      a.browsers = b === 'all' ? BROWSERS : b.split(',');
    } else if (flag === '--break') a.break = value();
    else if (flag === '--all') a.all = true;
    else if (flag === '--build') a.build = value();
    else if (flag === '--no-build') a.noBuild = true;
    else if (flag === '--results') a.results = resolve(value());
    else throw new Error(`unknown argument ${flag}`);
  }
  for (const b of a.browsers) if (!BROWSERS.includes(b)) throw new Error(`unknown browser ${b}`);
  if (a.break !== 'none' && !CONTROLS[a.break]) throw new Error(`unknown break ${a.break}`);
  return a;
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (r.error) throw r.error;
  return r;
}

function must(cmd, args, opts = {}) {
  const r = sh(cmd, args, { stdio: ['ignore', 'pipe', 'inherit'], ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}`);
  return (r.stdout ?? "").trim();
}

// `<commit>[-dirty]+<profile>` as mousse-check computes it: the last commit
// that changed anything outside checks/, dirty if anything outside
// checks/results and checks/runs is uncommitted.
function buildId() {
  const commit = must('git', ['log', '-1', '--format=%h', '--', '.', ':(exclude)checks'], { cwd: ROOT });
  const status = must('git', ['status', '--porcelain', '--', '.', ':(exclude)checks/results', ':(exclude)checks/runs'], { cwd: ROOT });
  return `${commit}${status ? '-dirty' : ''}+${PROFILE}`;
}

function targetDir() {
  return process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(HERE, 'target');
}

function buildAll() {
  console.log('building the wasm engine and the native verifier');
  must('cargo', ['build', '--lib', '--release', '--target', 'wasm32-unknown-unknown'], { cwd: HERE, stdio: ['ignore', 'inherit', 'inherit'] });
  const wasm = join(targetDir(), 'wasm32-unknown-unknown', 'release', 'browser_worker.wasm');
  const bindgen = process.env.WASM_BINDGEN || 'wasm-bindgen';
  must(bindgen, ['--target', 'web', '--no-typescript', '--out-dir', join(HERE, 'web', 'pkg'), wasm]);
  must('cargo', ['build', '--release', '--bin', 'verify-worker-cert'], { cwd: HERE, stdio: ['ignore', 'inherit', 'inherit'] });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
};

function serve() {
  const webRoot = join(HERE, 'web');
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    if (path === '/clear-site-data') {
      res.writeHead(200, { 'Clear-Site-Data': '"storage"', 'Cache-Control': 'no-store', 'Content-Type': 'text/plain' });
      res.end('cleared\n');
      return;
    }
    const file = normalize(join(webRoot, path === '/' ? 'index.html' : path));
    if (!file.startsWith(webRoot) || !existsSync(file)) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(readFileSync(file));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server)));
}

function browserVersion(name) {
  try {
    const list = JSON.parse(readFileSync(join(HERE, 'node_modules', 'playwright-core', 'browsers.json'), 'utf8'));
    return list.browsers.find((b) => b.name === name)?.browserVersion ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

// One browser, one break mode: drive the page, return the transcript.
async function drive(playwright, name, origin, breakMode) {
  const workerBreak = breakMode === 'skip-pin' ? 'none' : breakMode;
  const profile = join(HERE, '.profiles', `${name}-${breakMode}`);
  rmSync(profile, { recursive: true, force: true });
  mkdirSync(profile, { recursive: true });
  const launch = () => playwright[name].launchPersistentContext(profile, { headless: true });

  const open = async (context) => {
    const page = context.pages()[0] ?? (await context.newPage());
    await page.goto(`${origin}/index.html`);
    await page.waitForFunction(() => window.spikeReady === true);
    return page;
  };
  const worker = (page, phase) => page.evaluate(([p, b]) => window.spike.runWorker(p, b), [phase, workerBreak]);

  const runs = [];
  let context = await launch();
  let page;
  let persist;
  let userAgent;
  let clearMethod;
  try {
    page = await open(context);
    userAgent = await page.evaluate(() => navigator.userAgent);
    persist = await page.evaluate(() => window.spike.requestPersist());
    runs.push(await worker(page, 'first'));
    runs.push(await worker(page, 'after-worker-restart'));
    await context.close();
    // The browser itself restarts with the same profile.
    context = await launch();
    page = await open(context);
    runs.push(await worker(page, 'after-browser-restart'));
    const cleared = await page.evaluate(() => window.spike.clearSiteData());
    clearMethod = `Clear-Site-Data: "storage" response header (${cleared ? 'fetched' : 'fetch failed'})`;
    await page.reload();
    await page.waitForFunction(() => window.spikeReady === true);
    runs.push(await worker(page, 'after-clear-site-data'));
  } finally {
    await context.close();
    rmSync(profile, { recursive: true, force: true });
  }
  return {
    browser: name,
    browser_version: browserVersion(name),
    user_agent: userAgent,
    target: TARGETS[name],
    break: breakMode,
    persist,
    clear_method: clearMethod,
    runs,
  };
}

function verify(transcript, breakMode, build, resultsDir) {
  const name = transcript.browser;
  const runsDir = join(HERE, '.runs');
  mkdirSync(runsDir, { recursive: true });
  const tPath = join(runsDir, `${name}-${breakMode}.json`);
  writeFileSync(tPath, JSON.stringify(transcript, null, 2) + '\n');
  mkdirSync(resultsDir, { recursive: true });
  const control = CONTROLS[breakMode];
  const out = join(resultsDir, control ? `worker-${name}.control-${control}.json` : `worker-${name}.json`);
  const bin = join(targetDir(), 'release', 'verify-worker-cert');
  const args = ['--transcript', tPath, '--build', build, '--out', out, '--break', breakMode];
  if (control) args.push('--control', control);
  if (!control && name === 'chromium') args.push('--vector-out', join(resultsDir, 'worker-cert-vector.json'));
  const r = sh(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  for (const line of `${r.stdout}${r.stderr}`.split('\n').filter(Boolean)) console.log(`  [${name}${control ? ' ' + control : ''}] ${line}`);
  return r.status === 0;
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  const build = a.build ?? buildId();
  if (!a.noBuild) buildAll();
  console.log(`build ${build}`);
  const modes = a.all ? ['none', ...Object.keys(CONTROLS)] : [a.break];
  const { default: playwright } = await import('playwright');
  const server = await serve();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const verdicts = [];
  const outcomes = [];
  try {
    for (const name of a.browsers) {
      for (const mode of modes) {
        let passed;
        try {
          passed = verify(await drive(playwright, name, origin, mode), mode, build, a.results);
        } catch (e) {
          console.log(`  [${name} ${mode}] runner error: ${e.message}`);
          passed = false;
        }
        const expected = mode === 'none';
        console.log(`${name} ${mode === 'none' ? 'normal run' : 'control ' + mode}: ${passed ? 'PASS' : 'FAIL'}${passed === expected ? '' : ' (unexpected)'}`);
        verdicts.push(passed === expected);
        outcomes.push(passed);
      }
    }
  } finally {
    await new Promise((ok) => server.close(ok));
    rmSync(join(HERE, '.profiles'), { recursive: true, force: true });
  }
  // A plain run (normal or one control) reports its own outcome, so a
  // control run must end in FAIL. --all reports whether every run went as
  // required (normal runs PASS, controls FAIL).
  const ok = a.all ? verdicts.every(Boolean) : outcomes.every(Boolean);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${CHECK}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  console.log(`FAIL ${CHECK}`);
  process.exit(1);
});
