#!/usr/bin/env node
/**
 * Runs one app check (`app = true` in checks/<phase>.toml) against this
 * checkout's helper.
 *
 *   node tools/app-check/run.mjs <check id> [--out <dir>] [--role host|caller]
 *     [--topology <name>] [--route tcp|ws|ssh|relay] [--control <name>]
 *     [--target <cell>] [--result <file>]
 *
 * 1. Builds the debug helper (and, for Phase 1b and later checks,
 *    mousse-check) from this checkout with `cargo build` (RUSTFLAGS and
 *    CARGO_TARGET_DIR pass through; CARGO picks the cargo binary).
 * 2. Runs `node scripts/net-engine-check.mjs <check id> --out <dir>` in the
 *    app checkout named by MOUSSE_APP_DIR, with MOUSSE_NET_HELPER set to that
 *    helper and MOUSSE_NET_ENGINE_HELPER_BUILD to its build. --role,
 *    --topology and --route pass through to the app script.
 * 3. Prints `helper_build=<build>`, then the app's output. The app's own
 *    `PASS <id>` and `FAIL <id> ...` lines are shown as `app: PASS <id>` and
 *    `app: FAIL <id> ...`; this script prints the run's verdict line last,
 *    so the kit judges its own assertions and the app's together.
 *
 * Phase 1b and later checks run with the kit's stand-ins (Phase 1b §14,
 * "Plus and egress"). Phase 0 and 1a checks run as they were signed.
 *
 * - Plus recorder (recorder.mjs): MOUSSE_ID_ORIGIN and MOUSSE_PLUS_ORIGIN
 *   point at a loopback server that records each request and answers 403;
 *   MOUSSE_UPDATE_FEED_URL points under it at /update-feed. It proves it
 *   records before each run. A Plus request fails the run with
 *   `plus_contacted`; an update check with `egress_attempted`.
 * - Egress guard (egress-guard.cjs), loaded into every node process of the
 *   app check through NODE_OPTIONS, and named in
 *   MOUSSE_CHECK_EGRESS_GUARD for the app's check mode: sockets and name
 *   lookups outside loopback and MOUSSE_NET_TEST_EGRESS are refused and
 *   logged to MOUSSE_CHECK_EGRESS_LOG. Debug helpers read
 *   MOUSSE_NET_TEST_EGRESS and MOUSSE_NET_TEST_EGRESS_LOG the same way. A
 *   refusal fails the run with `egress_attempted`. The guard proves it
 *   refuses before each run.
 * - OS fence, where the OS allows it without admin rights and no address
 *   outside loopback is allowed: a network namespace with loopback only on
 *   Linux, a `sandbox-exec` profile on macOS. Printed as `fence=`.
 * - MOUSSE_CHECK_PROBE_BIN: `mousse-check` built from this checkout, for the app
 *   script to run `mousse-check probe`.
 * - For `--route ssh` and the checks that add a computer over SSH
 *   (SSH_CHECKS): MOUSSE_CHECK_TEST_SSHD, the test SSH server built from
 *   this checkout, and MOUSSE_CHECK_SSH_ROUTES, the module that starts the
 *   case's two loopback SSH routes (ssh-routes.mjs).
 *
 * --route tcp|ws|ssh: the route case. The app script gives the app only that
 *   route and writes every `conn.up` event it saw, one JSON object per line,
 *   to `<out>/conn-up.jsonl`. Every connection's `route` must be of that
 *   kind (its `kind`, or the scheme of a hint string; `wss` counts as `ws`),
 *   else the run fails with `route_mismatch`. On a single machine (no
 *   --role), `tcp` must show both the `tailnet` and the `public` class
 *   (`route.class`), which the app gets through MOUSSE_NET_TEST_CLASS_MAP.
 * --route relay: the connections go through a running `mousse-relay`,
 *   named by its enrollment links in MOUSSE_RELAY_TEST_LINKS (whitespace- or
 *   comma-separated, each used once; docs/limits.md "Relay tests"), which
 *   the app script gets as they are. Every connection's route must be of
 *   kind `relay` and, when it names a `destination`, one of those relays
 *   (`relay://<host>:<port>`). A relay outside loopback (on the Mac in a
 *   cross-machine cell) is added to MOUSSE_NET_TEST_EGRESS, so the guards
 *   let the app and the helper reach it and nothing else. Links must name
 *   IP addresses (the guards resolve no names); without links nothing runs.
 *
 * The verdict line: `FAIL <id> reason=<word>` with the first of
 * plus_contacted, egress_attempted and route_mismatch that applies; else the
 * app's own FAIL line when it failed cleanly (nonzero exit, its FAIL line,
 * no PASS line); `PASS <id>` when it passed cleanly (exit 0, its PASS line,
 * no FAIL line). An app that does neither cleanly gets no verdict line, so
 * the kit counts the run as neither a pass nor a control's failure.
 *
 * Exit code: the app script's (1 when a kit assertion fails); 2 if the
 * helper does not build or the app checkout cannot run the check.
 *
 * --control <name>: a device run of a must-fail control. The control's
 *   environment comes from this checkout's manifest (`mousse-check
 *   control-env`). Runs through `mousse-check run` get it from the kit
 *   instead and do not pass --control.
 * --result <file>: also writes an unsigned result for `mousse-check sign`:
 *   check, target, case (the route), control, outcome, details (the verdict
 *   line), reason, judged as the kit judges a local run (a control without
 *   a nonzero exit and a FAIL verdict is DID_NOT_FAIL), time, build (the
 *   helper build), app_build, and host_build and host_app_build when the app
 *   printed `host_build=` and `host_app_build=` lines (a caller reports the
 *   builds its host sent over the test link).
 *
 * The kit runs app checks only against a clean app checkout at the revision
 * in app/MOUSSE_REVISION, and counts only results that name that app build.
 * This script warns when the app build it saw is not that one.
 */
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { selfTest as recorderSelfTest, sortRequests, startRecorder, UPDATE_FEED_PATH } from './recorder.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const USAGE =
  'usage: node tools/app-check/run.mjs <check id> [--out <dir>] [--role host|caller] [--topology <name>] [--route tcp|ws|ssh|relay] [--control <name>] [--target <cell>] [--result <file>]'
const VALUE_FLAGS = ['--out', '--role', '--topology', '--route', '--control', '--target', '--result']
const ROUTES = ['tcp', 'ws', 'ssh', 'relay']
const GUARD = join(root, 'tools', 'app-check', 'egress-guard.cjs')

function refuse(message) {
  console.error(`run.mjs: ${message}`)
  process.exit(2)
}

function parseArgs(argv) {
  const flags = {}
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      if (!VALUE_FLAGS.includes(a)) refuse(`unknown option ${a}\n${USAGE}`)
      const v = argv[++i]
      if (v === undefined) refuse(`${a} needs a value`)
      flags[a.slice(2)] = v
    } else {
      positional.push(a)
    }
  }
  if (positional.length !== 1) refuse(USAGE)
  if (flags.role && !['host', 'caller'].includes(flags.role)) refuse(`--role is host or caller, not ${flags.role}`)
  if (flags.route && !ROUTES.includes(flags.route)) refuse(`--route is ${ROUTES.join(', ')}, not ${flags.route}`)
  return { id: positional[0], flags }
}

const git = (...args) => {
  const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
  if (r.status !== 0) refuse(`git ${args.join(' ')} failed: ${r.stderr || r.error}`)
  return r.stdout
}

/** `<commit>[-dirty]+debug`, the way the kit names this checkout's build. */
function helperBuild() {
  const commit = git('log', '-1', '--format=%H', '--', '.', ':(exclude)checks').trim()
  const status = git(
    'status',
    '--porcelain',
    '--untracked-files=all',
    '--',
    '.',
    ':(exclude)checks/results',
    ':(exclude)checks/runs'
  )
  return `${commit}${status.trim() ? '-dirty' : ''}+debug`
}

const cargo = process.env.CARGO || 'cargo'

/** The environment a control adds, from this checkout's manifest. */
function controlEnv(id, control) {
  const r = spawnSync(cargo, ['run', '-q', '-p', 'mousse-check', '--', 'control-env', id, '--control', control], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit']
  })
  if (r.status !== 0) refuse(`cannot read the environment of control ${control} of ${id}`)
  return JSON.parse(r.stdout)
}

/** Builds the debug helper (and mousse-check when `probe`) and returns their paths. */
function buildTools(env, probe, sshd) {
  const args = ['build', '-p', 'mousse-helper', '--bin', 'mousse-helper']
  if (probe) args.push('-p', 'mousse-check', '--bin', 'mousse-check')
  if (sshd) args.push('--example', 'test-sshd')
  const r = spawnSync(cargo, [...args, '--message-format=json-render-diagnostics'], {
    cwd: root,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 256 * 1024 * 1024
  })
  if (r.status !== 0) refuse(`the helper did not build (exit ${r.status})`)
  const exes = {}
  for (const line of r.stdout.split('\n')) {
    if (!line.startsWith('{')) continue
    const msg = JSON.parse(line)
    if (msg.reason === 'compiler-artifact' && msg.executable) exes[msg.target?.name] = msg.executable
  }
  if (!exes['mousse-helper'] || !existsSync(exes['mousse-helper'])) refuse('cargo built the helper but did not say where')
  if (probe && !exes['mousse-check']) refuse('cargo built mousse-check but did not say where')
  if (sshd && !exes['test-sshd']) refuse('cargo built test-sshd but did not say where')
  return { helper: exes['mousse-helper'], probe: exes['mousse-check'], sshd: exes['test-sshd'] }
}

/** App checks that add a computer over SSH, whatever their route case. */
export const SSH_CHECKS = ['phase1b.ssh-add-app', 'phase1b.link-app']

/** Whether a run needs the test SSH server: the `ssh` route case, or a check in SSH_CHECKS. */
export function needsSshd(id, route) {
  return route === 'ssh' || SSH_CHECKS.includes(id)
}

/** Phase 0 and 1a checks run as they were signed; later ones get the stand-ins. */
export function guarded(id) {
  return !/^phase(0|1a)\./.test(id)
}

/** The guard must refuse and log a connection out of the cell, or nothing runs. */
function guardSelfTest(dir) {
  const log = join(dir, 'egress-self-test.jsonl')
  writeFileSync(log, '')
  // 192.0.2.1 is TEST-NET-1: never routed, and the guard refuses it before any packet.
  const code =
    "require('node:net').connect(9, '192.0.2.1').on('error', (e) => { process.exitCode = e.code === 'EACCES' ? 0 : 3 })"
  const r = spawnSync(process.execPath, ['--require', GUARD, '-e', code], {
    encoding: 'utf8',
    env: { ...process.env, MOUSSE_CHECK_EGRESS_LOG: log, MOUSSE_NET_TEST_EGRESS: '' }
  })
  const logged = readFileSync(log, 'utf8')
  rmSync(log, { force: true })
  if (r.status !== 0 || !logged.includes('192.0.2.1')) {
    refuse(`the egress guard did not refuse and log its self-test (exit ${r.status}): ${r.stderr}`)
  }
}

/** Lines of a JSON-lines file; a missing file has none. */
function jsonLines(file) {
  if (!existsSync(file)) return []
  return readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return JSON.parse(l)
      } catch {
        return { unreadable: l }
      }
    })
}

/** `tcp`, `ws`, `ssh` or `relay` for a conn.up route: an object's kind, or a hint's scheme. */
export function routeKind(route) {
  if (route && typeof route === 'object') return route.kind
  if (typeof route !== 'string') return undefined
  const scheme = /^([a-z0-9+.-]+):/i.exec(route)?.[1]?.toLowerCase()
  return scheme === 'wss' ? 'ws' : scheme
}

/**
 * The relays of the enrollment links in `text` (MOUSSE_RELAY_TEST_LINKS):
 * `{ destinations, remote }`, the `relay://<host>:<port>` of each and the
 * hosts outside loopback, or `{ error }`.
 */
export function relayLinks(text) {
  const words = (text ?? '').split(/[\s,]+/).filter(Boolean)
  if (!words.length) return { error: 'a relay route needs MOUSSE_RELAY_TEST_LINKS, enrollment links of a running mousse-relay' }
  const destinations = new Set()
  const remote = new Set()
  for (const w of words) {
    const m = /^mousse-relay:\/\/(\[[0-9a-fA-F:.]+\]|[^/:[\]]+):(\d{1,5})\/#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.exec(w)
    if (!m) return { error: `MOUSSE_RELAY_TEST_LINKS: ${w.slice(0, 40)}... is not a mousse-relay:// enrollment link` }
    const host = m[1].toLowerCase()
    const bare = host.replace(/^\[|\]$/g, '')
    if (!net.isIP(bare)) return { error: `MOUSSE_RELAY_TEST_LINKS: ${host} is a name; the egress guards resolve none, so give the relay's IP address` }
    destinations.add(`relay://${host}:${Number(m[2])}`)
    const loopback = bare === '::1' || /^127\./.test(bare) || /^::ffff:127\./.test(bare)
    if (!loopback) remote.add(bare)
  }
  return { destinations: [...destinations], remote: [...remote] }
}

/** MOUSSE_NET_TEST_EGRESS with `more` addresses added, once each. */
export function withEgress(egress, more) {
  const have = (egress ?? '').split(',').map((a) => a.trim()).filter(Boolean)
  for (const a of more) if (!have.includes(a)) have.push(a)
  return have.join(',')
}

/**
 * Why the connections in `<out>/conn-up.jsonl` break the route case, or
 * undefined. `relays`: for a relay route, the destinations its links name.
 */
export function routeMismatch(out, route, singleMachine, relays = []) {
  const file = join(out, 'conn-up.jsonl')
  if (!existsSync(file)) return 'the app script wrote no conn-up.jsonl'
  const ups = jsonLines(file)
  if (!ups.length) return 'no connection came up'
  for (const up of ups) {
    const kind = routeKind(up.route)
    if (kind !== route) {
      return `a connection used ${kind ?? 'no named route'} (${JSON.stringify(up.route ?? null)}), not ${route}`
    }
    const dest = up.route && typeof up.route === 'object' ? up.route.destination : undefined
    if (route === 'relay' && dest !== undefined && !relays.includes(String(dest).toLowerCase())) {
      return `a relay connection went through ${JSON.stringify(dest)}, not a relay of MOUSSE_RELAY_TEST_LINKS (${relays.join(', ')})`
    }
  }
  if (route === 'tcp' && singleMachine) {
    const classes = new Set(ups.map((u) => u.route?.class).filter(Boolean))
    const missing = ['tailnet', 'public'].filter((c) => !classes.has(c))
    if (missing.length) {
      return `tcp connections showed ${[...classes].join(', ') || 'no class'}; missing ${missing.join(' and ')}`
    }
  }
  return undefined
}

/** An OS fence for the app script, or none, and why. */
function fence(allowsMore) {
  if (allowsMore) return { kind: 'none (cross-machine: the peer is allowed)' }
  if (process.platform === 'linux') {
    const lo = 'ip link set lo up'
    const probe = spawnSync('unshare', ['--user', '--map-root-user', '--net', 'sh', '-c', `${lo} && echo ok`], {
      encoding: 'utf8'
    })
    if (probe.stdout?.trim() === 'ok') {
      return {
        kind: 'linux network namespace (loopback only)',
        wrap: (cmd, args) => [
          'unshare',
          ['--user', '--map-root-user', '--net', 'sh', '-c', `${lo} && exec "$0" "$@"`, cmd, ...args]
        ]
      }
    }
    return { kind: 'none (no unprivileged network namespace here)' }
  }
  if (process.platform === 'darwin') {
    const profile =
      '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))(allow network-outbound (remote unix-socket))'
    const probe = spawnSync('sandbox-exec', ['-p', profile, '/usr/bin/true'])
    if (probe.status === 0) {
      return {
        kind: 'macOS sandbox-exec (loopback only)',
        wrap: (cmd, args) => ['sandbox-exec', ['-p', profile, cmd, ...args]]
      }
    }
    return { kind: 'none (sandbox-exec refused the profile)' }
  }
  return { kind: 'none (Windows relies on the two guards)' }
}

/** The value of the first `<key>=<value>` line. */
function lineValue(text, key) {
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim()
    if (l.startsWith(`${key}=`)) {
      const v = l.slice(key.length + 1).trim()
      if (v && !/\s/.test(v)) return v
    }
  }
  return undefined
}

/** The first line that is `marker` or starts with `marker` and a space. */
function markerLine(text, marker) {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l === marker || l.startsWith(`${marker} `))
}

function pinnedRevision() {
  const file = join(root, 'app', 'MOUSSE_REVISION')
  return existsSync(file) ? readFileSync(file, 'utf8').trim().toLowerCase() : undefined
}

/** Forward a child's output line by line, marking the app's verdict lines. */
function relay(sink, id, keep) {
  const isVerdict = (line) => {
    const l = line.trim()
    return [`PASS ${id}`, `FAIL ${id}`].some((m) => l === m || l.startsWith(`${m} `))
  }
  let partial = ''
  const push = (d) => {
    keep(String(d))
    partial += d
    const lines = partial.split('\n')
    partial = lines.pop()
    for (const line of lines) sink.write(`${isVerdict(line) ? 'app: ' : ''}${line}\n`)
  }
  push.flush = () => {
    if (partial) sink.write(`${isVerdict(partial) ? 'app: ' : ''}${partial}\n`)
    partial = ''
  }
  return push
}

async function main() {
  const { id, flags } = parseArgs(process.argv.slice(2))
  const appDir = process.env.MOUSSE_APP_DIR?.trim()
  if (!appDir) refuse('set MOUSSE_APP_DIR to a checkout of the Mousse app')
  const script = join(resolve(appDir), 'scripts', 'net-engine-check.mjs')
  if (!existsSync(script)) refuse(`${script} does not exist; is MOUSSE_APP_DIR a checkout of the Mousse app?`)

  const env = { ...process.env, ...(flags.control ? controlEnv(id, flags.control) : {}) }
  let relays
  if (flags.route === 'relay') {
    relays = relayLinks(env.MOUSSE_RELAY_TEST_LINKS)
    if (relays.error) refuse(relays.error)
  }
  const stand = guarded(id)
  const build = helperBuild()
  const tools = buildTools(env, stand, needsSshd(id, flags.route))
  console.log(`helper_build=${build}`)

  const run = { id, flags, appDir, relays, tools, build }
  if (stand) {
    const egress = withEgress(env.MOUSSE_NET_TEST_EGRESS, relays?.remote ?? [])
    const f = fence(egress.split(',').some((address) => address.trim()))
    console.log(`fence=${f.kind}`)
    if (f.wrap) {
      // The recorder and the app need the same loopback interface. Build
      // outside the fence, then run both inside it.
      const [cmd, args] = f.wrap(process.execPath, [fileURLToPath(import.meta.url), '--inside-fence'])
      const child = spawnSync(cmd, args, {
        env,
        input: JSON.stringify(run),
        stdio: ['pipe', 'inherit', 'inherit']
      })
      if (child.error) refuse(child.error.message)
      process.exit(child.status ?? 2)
    }
  }
  await runCheck(run, env)
}

async function runCheck({ id, flags, appDir, relays, tools, build }, env) {
  const out = resolve(flags.out ?? mkdtempSync(join(tmpdir(), 'app-check-')))
  mkdirSync(out, { recursive: true })
  const args = [script, id, '--out', out]
  if (flags.role) args.push('--role', flags.role)
  if (flags.topology) args.push('--topology', flags.topology)
  if (flags.route) args.push('--route', flags.route)

  const childEnv = { ...env, MOUSSE_NET_HELPER: tools.helper, MOUSSE_NET_ENGINE_HELPER_BUILD: build }
  const egressLog = join(out, 'egress-refused.jsonl')
  let recorder
  if (guarded(id)) {
    recorder = await startRecorder({ log: join(out, 'plus-requests.jsonl') })
    await recorderSelfTest(recorder).catch((e) => refuse(e.message))
    guardSelfTest(out)
    writeFileSync(egressLog, '')
    // A relay on another machine is the one address the route needs.
    const egress = withEgress(env.MOUSSE_NET_TEST_EGRESS, relays?.remote ?? [])
    Object.assign(childEnv, {
      MOUSSE_ID_ORIGIN: recorder.url,
      MOUSSE_PLUS_ORIGIN: recorder.url,
      MOUSSE_UPDATE_FEED_URL: `${recorder.url}${UPDATE_FEED_PATH}`,
      MOUSSE_CHECK_EGRESS_GUARD: GUARD,
      MOUSSE_CHECK_EGRESS_LOG: egressLog,
      MOUSSE_NET_TEST_EGRESS: egress,
      MOUSSE_NET_TEST_EGRESS_LOG: egressLog,
      // Forward slashes: NODE_OPTIONS reads backslashes as escapes.
      NODE_OPTIONS: `${env.NODE_OPTIONS ? `${env.NODE_OPTIONS} ` : ''}--require "${GUARD.split('\\').join('/')}"`,
      MOUSSE_CHECK_PROBE_BIN: tools.probe,
      // The ssh case: the test SSH server and the two-route helper.
      ...(tools.sshd
        ? { MOUSSE_CHECK_TEST_SSHD: tools.sshd, MOUSSE_CHECK_SSH_ROUTES: join(root, 'tools', 'app-check', 'ssh-routes.mjs') }
        : {})
    })
  }

  const child = spawn(process.execPath, args, { cwd: resolve(appDir), env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] })
  let text = ''
  const keep = (d) => {
    text += d
  }
  const outRelay = relay(process.stdout, id, keep)
  const errRelay = relay(process.stderr, id, keep)
  child.stdout.on('data', outRelay)
  child.stderr.on('data', errRelay)
  let code = await new Promise((done) => {
    child.on('error', (e) => {
      console.error(`run.mjs: ${e.message}`)
      done(2)
    })
    child.on('close', (c) => done(c ?? 2))
  })
  outRelay.flush()
  errRelay.flush()

  const appBuild = lineValue(text, 'app_build')
  const pinned = pinnedRevision()
  if (!appBuild || appBuild !== pinned) {
    console.error(
      `run.mjs: note: app build ${appBuild ?? '(not printed)'}, app/MOUSSE_REVISION pins ${pinned ?? '(nothing)'}; this run will not count`
    )
  }

  // The kit's own assertions, in the order their reasons win.
  const kit = []
  if (recorder) {
    const { plus, updates } = sortRequests(recorder.requests())
    await recorder.close()
    if (plus.length) {
      const what = plus.map((r) => `${r.method} ${r.url}`).join(', ')
      kit.push(['plus_contacted', `${plus.length} request(s) to the Plus stand-in: ${what}`])
    }
    const refused = jsonLines(egressLog)
    if (refused.length || updates.length) {
      const what = [
        ...refused.map((r) => `${r.kind ?? '?'} to ${r.target ?? JSON.stringify(r)}`),
        ...updates.map((r) => `update check ${r.url}`)
      ]
      kit.push(['egress_attempted', `${what.length} attempt(s) out of the cell: ${what.join(', ')}`])
    }
  }
  if (flags.route) {
    const why = routeMismatch(out, flags.route, !flags.role, relays?.destinations)
    if (why) kit.push(['route_mismatch', why])
  }

  const appPass = markerLine(text, `PASS ${id}`)
  const appFail = markerLine(text, `FAIL ${id}`)
  let verdict
  if (kit.length) {
    verdict = `FAIL ${id} reason=${kit[0][0]} (${kit.map(([r, why]) => `${r}: ${why}`).join('; ')})`
    if (code === 0) code = 1
  } else if (code === 0 && appPass && !appFail) {
    verdict = `PASS ${id}`
  } else if (code !== 0 && appFail && !appPass) {
    verdict = appFail
  } else {
    console.error(
      `run.mjs: no clean verdict from the app (exit ${code}, ${appPass ? 'a' : 'no'} PASS line, ${appFail ? 'a' : 'no'} FAIL line)`
    )
    if (code === 0) code = 1
  }
  if (verdict) console.log(verdict)

  if (flags.result) {
    const pass = verdict?.startsWith('PASS ')
    const fail = verdict?.startsWith('FAIL ')
    let outcome
    let details = verdict
    if (flags.control) {
      outcome = fail && code !== 0 ? 'FAIL' : 'DID_NOT_FAIL'
      if (outcome !== 'FAIL') {
        details = `the control did not fail as required (exit ${code}, ${appFail ? 'a' : 'no'} FAIL line, ${appPass ? 'a' : 'no'} PASS line)${verdict ? `: ${verdict}` : ''}`
      }
    } else if (pass && code === 0) {
      outcome = 'PASS'
    } else {
      outcome = 'FAIL'
      if (!fail) details = `no clean pass (exit ${code}, ${appPass ? 'a' : 'no'} PASS line, ${appFail ? 'a' : 'no'} FAIL line)`
    }
    const reason = outcome === 'FAIL' && fail && /reason=([^\s;,)"]+)/.exec(verdict.slice(`FAIL ${id}`.length))?.[1]
    const result = {
      check: id,
      ...(flags.target ? { target: flags.target } : {}),
      ...(flags.route ? { case: flags.route } : {}),
      ...(flags.control ? { control: flags.control } : {}),
      outcome,
      details,
      ...(reason ? { reason } : {}),
      time: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      build,
      ...(appBuild ? { app_build: appBuild } : {})
    }
    for (const key of ['host_build', 'host_app_build']) {
      const v = lineValue(text, key)
      if (v) result[key] = v
    }
    writeFileSync(resolve(flags.result), `${JSON.stringify(result, null, 2)}\n`)
    console.error(`run.mjs: wrote ${resolve(flags.result)}`)
  }
  process.exit(code)
}

// Run only as a script, so the self-tests can import the route assertion.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--inside-fence') runCheck(JSON.parse(readFileSync(0, 'utf8')), process.env)
  else main()
}
