#!/usr/bin/env node
/**
 * The six-build smoke of `phase1b.desktop-builds` (Phase 1b §14 and §15,
 * M14 and E12), for one target:
 *
 *   node tools/build-smoke.mjs <check id> --target <target> [--out <dir>]
 *     [--helper <release helper> --probe <mousse-check>]
 *
 * 1. Builds the release helper and mousse-check for the target from this
 *    checkout (unless --helper and --probe name prebuilt ones, as the hosted
 *    job does). The build never sees MOUSSE_BUILD_ID, so the helper is
 *    stamped with this checkout's commit.
 * 2. `--version` must name a release build of the build under test: the
 *    commit part of MOUSSE_BUILD_ID (which the kit sets; this checkout's
 *    commit when run by hand), and control `none`. Otherwise
 *    `reason=stale_helper`.
 * 3. The packaged app: in MOUSSE_APP_DIR, `node
 *    scripts/net-engine-package-smoke.mjs --helper <helper> --target <target>
 *    --out <dir>` packages the app with that helper, starts it, and prints
 *    `app_build=<commit>`, `packaged_helper=<path>` and `PASS package-smoke`
 *    (or `FAIL package-smoke reason=<word>`). The packaged helper's
 *    `--version` must name the same build (`stale_helper` otherwise).
 *    Without MOUSSE_APP_DIR or the script: `reason=no_packaged_app`.
 * 4. The release helper serves on loopback (`serve --port 0 --ws-port 0`, a
 *    throwaway state folder and file key), and `mousse-check probe --no-app`
 *    runs its wire cases over tcp and ws against it, with a Send link
 *    invitation. Any failure: `reason=probe_failed`.
 *
 * Prints `helper_version=`, `helper_build=`, `app_build=` (when the app
 * ran), and last `PASS <id>` or `FAIL <id> reason=<word>`. Exit 0 only on
 * PASS.
 *
 * How each target runs: windows-x64, windows-arm64, macos-arm64 and
 * linux-x64 natively; macos-x64 under Rosetta (built for
 * x86_64-apple-darwin on an Apple silicon Mac); linux-arm64 in arm64
 * containers on the Mac (image MOUSSE_CHECK_LINUX_ARM_IMAGE, default
 * rust:1-slim): one builds (with network, for crates), one runs version,
 * serve and the probe with `--network none`.
 *
 * Waits: MOUSSE_CHECK_SMOKE_SERVE_MS (15000) for serve and invite to be
 * ready, MOUSSE_CHECK_SMOKE_PROBE_MS (120000) per probe run.
 */
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const cargo = process.env.CARGO || 'cargo'

/** Target → Rust triple and how its binaries run on the machine that smokes it. */
export const TARGETS = {
  'windows-x64': { triple: 'x86_64-pc-windows-msvc', run: 'native' },
  'windows-arm64': { triple: 'aarch64-pc-windows-msvc', run: 'native' },
  'macos-arm64': { triple: 'aarch64-apple-darwin', run: 'native' },
  'macos-x64': { triple: 'x86_64-apple-darwin', run: 'rosetta' },
  'linux-x64': { triple: 'x86_64-unknown-linux-gnu', run: 'native' },
  'linux-arm64': { triple: 'aarch64-unknown-linux-gnu', run: 'container' }
}

function waitMs(name, fallback) {
  const v = process.env[name]
  if (v === undefined) return fallback
  const n = Number(v)
  if (!Number.isInteger(n) || n <= 0) usage(`${name}=${v} is not a positive whole number`)
  return n
}

const WIRE_CASES = [
  'not-tls',
  'tls-no-cert',
  'tls-1.2',
  'tls-wrong-alpn',
  'fresh-open-rpc',
  'fresh-open-tunnel',
  'fresh-bad-proof',
  'join-only-open-rpc',
  'join-only-open-hello',
  'join-only-open-tunnel',
  'admission'
]
const WS_CASES = ['ws-plain-get', 'ws-wrong-path', 'ws-origin', 'ws-no-subprotocol', 'ws-text-message']

function usage(message) {
  console.error(`build-smoke.mjs: ${message}`)
  console.error(
    'usage: node tools/build-smoke.mjs <check id> --target <target> [--out <dir>] [--helper <file> --probe <file>]'
  )
  process.exit(2)
}

function parse(argv) {
  const flags = {}
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      if (!['--target', '--out', '--helper', '--probe'].includes(a)) usage(`unknown option ${a}`)
      if (argv[i + 1] === undefined) usage(`${a} needs a value`)
      flags[a.slice(2)] = argv[++i]
    } else positional.push(a)
  }
  if (positional.length !== 1) usage('one check id')
  if (!TARGETS[flags.target]) usage(`--target is one of ${Object.keys(TARGETS).join(', ')}`)
  if (Boolean(flags.helper) !== Boolean(flags.probe)) usage('--helper and --probe go together')
  return { id: positional[0], flags }
}

/** `<package> build <commit>[-dirty]+<profile> control <name>` → its parts. */
export function parseVersion(text) {
  const m = /build (\S+?)\+(\S+) control (\S+)/.exec(text ?? '')
  return m ? { commit: m[1], profile: m[2], control: m[3] } : undefined
}

/** Why `version` is not a release build of `commit`, or undefined. */
export function staleWhy(version, commit) {
  const v = parseVersion(version)
  if (!v) return `unreadable --version: ${JSON.stringify(version)}`
  if (v.commit !== commit) return `the helper is build ${v.commit}, the build under test is ${commit}`
  if (v.profile !== 'release') return `the helper is a ${v.profile} build`
  if (v.control !== 'none') return `the helper carries control ${v.control}`
  return undefined
}

function git(...args) {
  const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
  return r.status === 0 ? r.stdout.trim() : ''
}

/** The commit under test: MOUSSE_BUILD_ID's commit part, else this checkout's. */
function commitUnderTest() {
  const id = process.env.MOUSSE_BUILD_ID?.trim()
  if (id) return id.split('+')[0]
  const commit = git('log', '-1', '--format=%H', '--', '.', ':(exclude)checks')
  const dirty = git('status', '--porcelain', '--untracked-files=all', '--', '.', ':(exclude)checks/results', ':(exclude)checks/runs')
  return `${commit}${dirty ? '-dirty' : ''}`
}

/** Build the release helper and mousse-check for `target`. */
function build(target) {
  const { triple } = TARGETS[target]
  const env = { ...process.env }
  // The stamp comes from this checkout, never from the run's MOUSSE_BUILD_ID.
  delete env.MOUSSE_BUILD_ID
  const host = /host: (\S+)/.exec(spawnSync('rustc', ['-vV'], { encoding: 'utf8' }).stdout ?? '')?.[1]
  const args = ['build', '--release', '-p', 'mousse-helper', '--bin', 'mousse-helper', '-p', 'mousse-check', '--bin', 'mousse-check']
  if (triple !== host) args.push('--target', triple)
  const r = spawnSync(cargo, [...args, '--message-format=json-render-diagnostics'], {
    cwd: root,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 256 * 1024 * 1024
  })
  if (r.status !== 0) return { error: `the release build for ${triple} failed (exit ${r.status})` }
  const out = {}
  for (const line of r.stdout.split('\n')) {
    if (!line.startsWith('{')) continue
    const msg = JSON.parse(line)
    if (msg.reason === 'compiler-artifact' && msg.executable) out[msg.target?.name] = msg.executable
  }
  if (!out['mousse-helper'] || !out['mousse-check']) return { error: 'cargo did not say where the binaries are' }
  return { helper: out['mousse-helper'], probe: out['mousse-check'] }
}

function run(file, args, opts = {}) {
  return spawnSync(file, args, { encoding: 'utf8', ...opts })
}

/** Start the release helper on loopback: { ports, stop } or { error }. */
async function serve(helper, state, wait) {
  const init = run(helper, ['init', '--state', state, '--insecure-file-key'])
  if (init.status !== 0) return { error: `init failed: ${init.stderr}` }
  const child = spawn(helper, ['serve', '--state', state, '--insecure-file-key', '--port', '0', '--ws-port', '0', '--no-mdns'], {
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const stop = () => {
    run(helper, ['stop', '--state', state, '--insecure-file-key'])
    child.kill()
  }
  let text = ''
  const ports = await new Promise((done) => {
    const timer = setTimeout(() => done(undefined), wait)
    const look = (d) => {
      text += d
      const m = /ready \S+ port (\d+) .*ws_port (\d+)/.exec(text)
      if (m) {
        clearTimeout(timer)
        done({ tcp: Number(m[1]), ws: Number(m[2]) })
      }
    }
    child.stdout.on('data', look)
    child.stderr.on('data', look)
    child.on('exit', () => done(undefined))
  })
  if (!ports) {
    stop()
    return { error: `serve did not say ready: ${text.slice(0, 500)}` }
  }
  return { ports, stop }
}

/** A Send link ticket from the running helper: { ticket, stop }. */
async function invite(helper, state, wait) {
  const child = spawn(helper, ['invite', '--link', '--no-qr', '--state', state, '--insecure-file-key'], {
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let text = ''
  const ticket = await new Promise((done) => {
    const timer = setTimeout(() => done(undefined), wait)
    child.stdout.on('data', (d) => {
      text += d
      const m = /^TICKET (\S+)/m.exec(text)
      if (m) {
        clearTimeout(timer)
        done(m[1])
      }
    })
    child.on('exit', () => done(undefined))
  })
  return { ticket, stop: () => child.kill() }
}

function showProbe(text) {
  process.stdout.write(`${text ?? ''}`.replace(/^(PASS|FAIL) smoke-probe/gm, 'probe: $1 smoke-probe'))
}

/** The app's package smoke: { appBuild, packagedHelper } or { error, why }. */
function packagedApp(helper, target, out) {
  const appDir = process.env.MOUSSE_APP_DIR?.trim()
  const script = appDir && join(resolve(appDir), 'scripts', 'net-engine-package-smoke.mjs')
  if (!script || !existsSync(script)) {
    return { error: 'no_packaged_app', why: 'MOUSSE_APP_DIR has no scripts/net-engine-package-smoke.mjs (M14)' }
  }
  const r = run(process.execPath, [script, '--helper', helper, '--target', target, '--out', join(out, 'package')], {
    cwd: resolve(appDir),
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024
  })
  const text = `${r.stdout ?? ''}\n${r.stderr ?? ''}`
  process.stdout.write(text.replace(/^(PASS|FAIL) /gm, 'app: $1 '))
  const value = (k) => new RegExp(`^${k}=(\\S+)`, 'm').exec(text)?.[1]
  if (r.status !== 0 || !/^PASS package-smoke\s*$/m.test(text)) {
    const reason = /^FAIL package-smoke reason=(\S+)/m.exec(text)?.[1] ?? 'app_did_not_start'
    return { error: reason, why: `the packaged app smoke did not pass (exit ${r.status})`, appBuild: value('app_build') }
  }
  return { appBuild: value('app_build'), packagedHelper: value('packaged_helper') }
}

/** linux-arm64 on the Mac: build in one arm64 container, smoke in another with no network. */
function containerSmoke(out, commit) {
  const image = process.env.MOUSSE_CHECK_LINUX_ARM_IMAGE ?? 'rust:1-slim'
  const volume = `mousse-check-smoke-target-${process.env.USER ?? 'kit'}`
  const docker = (args) =>
    spawnSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 64 * 1024 * 1024 })
  const buildCmd = [
    'cargo build --release -p mousse-helper --bin mousse-helper -p mousse-check --bin mousse-check',
    'cp /target/release/mousse-helper /target/release/mousse-check /out/'
  ].join(' && ')
  const b = docker([
    'run', '--rm', '--platform', 'linux/arm64', '-e', 'CARGO_TARGET_DIR=/target',
    '-v', `${root}:/src:ro`, '-v', `${volume}:/target`, '-v', `${out}:/out`, '-w', '/src',
    image, 'sh', '-c', buildCmd
  ])
  if (b.status !== 0) return { error: 'build_failed', why: `the linux-arm64 container build failed (exit ${b.status})` }
  const tcp = WIRE_CASES.join(',')
  const ws = [...WS_CASES, ...WIRE_CASES].join(',')
  const script = [
    'set -e',
    'H=/out/mousse-helper; C=/out/mousse-check; S=/tmp/state',
    'echo "helper_version=$($H --version)"',
    '$H init --state $S --insecure-file-key >/dev/null',
    '$H serve --state $S --insecure-file-key --port 0 --ws-port 0 --no-mdns >/tmp/serve.out 2>&1 &',
    'for i in $(seq 1 150); do grep -q "ready " /tmp/serve.out && break; sleep 0.1; done',
    "P=$(grep -o ' port [0-9]*' /tmp/serve.out | head -1 | tr -dc 0-9)",
    "W=$(grep -o 'ws_port [0-9]*' /tmp/serve.out | head -1 | tr -dc 0-9)",
    '$H invite --link --no-qr --state $S --insecure-file-key >/tmp/inv.out 2>&1 &',
    'for i in $(seq 1 150); do grep -q "^TICKET " /tmp/inv.out && break; sleep 0.1; done',
    "T=$(grep '^TICKET ' /tmp/inv.out | cut -d' ' -f2)",
    `$C probe --route tcp://127.0.0.1:$P --invite "$T" --no-app --cases ${tcp} --marker smoke-probe`,
    `$C probe --route ws://127.0.0.1:$W/mousse-net/1 --invite "$T" --no-app --cases ${ws} --marker smoke-probe`
  ].join('\n')
  const r = docker(['run', '--rm', '--platform', 'linux/arm64', '--network', 'none', '-v', `${out}:/out`, image, 'sh', '-c', script])
  const text = r.stdout ?? ''
  const version = /^helper_version=(.*)$/m.exec(text)?.[1]?.trim()
  console.log(`helper_version=${(version ?? '').replace(/\s+/g, '_')}`)
  console.log(`helper_build=${parseVersion(version)?.commit ?? 'unknown'}+release`)
  showProbe(text.replace(/^helper_version=.*\n/m, ''))
  const stale = staleWhy(version, commit)
  if (stale) return { error: 'stale_helper', why: stale }
  if (r.status !== 0) return { error: 'probe_failed', why: `the smoke in the container failed (exit ${r.status})` }
  return {}
}

async function main() {
  const { id, flags } = parse(process.argv.slice(2))
  const target = flags.target
  const waitServe = waitMs('MOUSSE_CHECK_SMOKE_SERVE_MS', 15000)
  const waitProbe = waitMs('MOUSSE_CHECK_SMOKE_PROBE_MS', 120000)
  const out = resolve(flags.out ?? mkdtempSync(join(tmpdir(), 'build-smoke-')))
  mkdirSync(out, { recursive: true })
  const commit = commitUnderTest()
  const cleanups = []
  const fail = (reason, why) => {
    for (const c of cleanups.reverse()) c()
    console.log(`note: ${why}`)
    console.log(`FAIL ${id} reason=${reason}`)
    process.exit(1)
  }

  if (TARGETS[target].run === 'container') {
    const r = containerSmoke(out, commit)
    if (r.error) fail(r.error, r.why)
    const app = packagedApp(join(out, 'mousse-helper'), target, out)
    if (app.appBuild) console.log(`app_build=${app.appBuild}`)
    if (app.error) fail(app.error, app.why)
    console.log(`PASS ${id}`)
    process.exit(0)
  }

  const built = flags.helper ? { helper: resolve(flags.helper), probe: resolve(flags.probe) } : build(target)
  if (built.error) fail('build_failed', built.error)

  // 1. The helper names the build under test.
  const helperVersion = `${run(built.helper, ['--version']).stdout ?? ''}`.trim()
  console.log(`helper_version=${helperVersion.replace(/\s+/g, '_')}`)
  console.log(`helper_build=${parseVersion(helperVersion)?.commit ?? 'unknown'}+release`)
  const stale = staleWhy(helperVersion, commit)
  if (stale) fail('stale_helper', stale)

  // 2. Release serve answers the probe over tcp and ws on loopback.
  const state = join(out, 'state')
  rmSync(state, { recursive: true, force: true })
  const host = await serve(built.helper, state, waitServe)
  if (host.error) fail('probe_failed', host.error)
  cleanups.push(host.stop)
  const inv = await invite(built.helper, state, waitServe)
  cleanups.push(inv.stop)
  if (!inv.ticket) fail('probe_failed', 'invite --link printed no ticket')
  for (const [route, cases] of [
    [`tcp://127.0.0.1:${host.ports.tcp}`, WIRE_CASES],
    [`ws://127.0.0.1:${host.ports.ws}/mousse-net/1`, [...WS_CASES, ...WIRE_CASES]]
  ]) {
    const args = ['probe', '--route', route, '--invite', inv.ticket, '--no-app', '--cases', cases.join(','), '--marker', 'smoke-probe']
    const r = run(built.probe, args, { timeout: waitProbe })
    showProbe(r.stdout)
    if (r.status !== 0) fail('probe_failed', `the probe over ${route} failed (exit ${r.status})`)
  }
  for (const c of cleanups.splice(0).reverse()) c()

  // 3. The packaged app starts, with this helper inside.
  const app = packagedApp(built.helper, target, out)
  if (app.appBuild) console.log(`app_build=${app.appBuild}`)
  if (app.error) fail(app.error, app.why)
  if (app.packagedHelper) {
    const why = staleWhy(`${run(app.packagedHelper, ['--version']).stdout ?? ''}`.trim(), commit)
    if (why) fail('stale_helper', `packaged helper: ${why}`)
  }

  writeFileSync(
    join(out, 'smoke.json'),
    `${JSON.stringify({ id, target, commit, helper_version: helperVersion, app_build: app.appBuild ?? null }, null, 2)}\n`
  )
  console.log(`PASS ${id}`)
  process.exit(0)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
