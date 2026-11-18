#!/usr/bin/env node
/**
 * Runs one app check (`app = true` in checks/<phase>.toml) against this
 * checkout's helper.
 *
 *   node tools/app-check/run.mjs <check id> [--out <dir>] [--role host|caller]
 *     [--topology <name>] [--control <name>] [--target <cell>] [--result <file>]
 *
 * 1. Builds the debug helper from this checkout with `cargo build -p
 *    mousse-helper` (RUSTFLAGS and CARGO_TARGET_DIR pass through; CARGO
 *    picks the cargo binary).
 * 2. Runs `node scripts/net-engine-check.mjs <check id> --out <dir>` in the
 *    app checkout named by MOUSSE_APP_DIR, with MOUSSE_NET_HELPER set to that
 *    helper and MOUSSE_NET_ENGINE_HELPER_BUILD to its build. --role and --topology
 *    pass through to the app script.
 * 3. Prints `helper_build=<build>`, then the app's output: its
 *    `app_build=<commit>[-dirty]` line and its `PASS <id>` or
 *    `FAIL <id> reason=<word>` line.
 *
 * Exit code: the app script's; 2 if the helper does not build or the app
 * checkout cannot run the check.
 *
 * --control <name>: a device run of a must-fail control. The control's
 *   environment comes from this checkout's manifest (`mousse-check
 *   control-env`). Runs through `mousse-check run` get it from the kit
 *   instead and do not pass --control.
 * --result <file>: also writes an unsigned result for `mousse-check sign`:
 *   check, target, control, outcome, details (the marker line), reason,
 *   time, build (the helper build), app_build, and host_build and
 *   host_app_build when the app printed `host_build=` and `host_app_build=`
 *   lines (a caller reports the builds its host sent over the test link).
 *
 * The kit runs app checks only against a clean app checkout at the revision
 * in app/MOUSSE_REVISION, and counts only results that name that app build.
 * This script warns when the app build it saw is not that one.
 */
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const USAGE =
  'usage: node tools/app-check/run.mjs <check id> [--out <dir>] [--role host|caller] [--topology <name>] [--control <name>] [--target <cell>] [--result <file>]'
const VALUE_FLAGS = ['--out', '--role', '--topology', '--control', '--target', '--result']

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

/** Builds the debug helper and returns its path. */
function buildHelper(env) {
  const r = spawnSync(
    cargo,
    ['build', '-p', 'mousse-helper', '--bin', 'mousse-helper', '--message-format=json-render-diagnostics'],
    { cwd: root, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 256 * 1024 * 1024 }
  )
  if (r.status !== 0) refuse(`the helper did not build (exit ${r.status})`)
  let exe
  for (const line of r.stdout.split('\n')) {
    if (!line.startsWith('{')) continue
    const msg = JSON.parse(line)
    if (msg.reason === 'compiler-artifact' && msg.target?.name === 'mousse-helper' && msg.executable) {
      exe = msg.executable
    }
  }
  if (!exe || !existsSync(exe)) refuse('cargo built the helper but did not say where')
  return exe
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

async function main() {
  const { id, flags } = parseArgs(process.argv.slice(2))
  const appDir = process.env.MOUSSE_APP_DIR?.trim()
  if (!appDir) refuse('set MOUSSE_APP_DIR to a checkout of the Mousse app')
  const script = join(resolve(appDir), 'scripts', 'net-engine-check.mjs')
  if (!existsSync(script)) refuse(`${script} does not exist; is MOUSSE_APP_DIR a checkout of the Mousse app?`)

  const env = { ...process.env, ...(flags.control ? controlEnv(id, flags.control) : {}) }
  const build = helperBuild()
  const helper = buildHelper(env)
  console.log(`helper_build=${build}`)

  const out = resolve(flags.out ?? mkdtempSync(join(tmpdir(), 'app-check-')))
  mkdirSync(out, { recursive: true })
  const args = [script, id, '--out', out]
  if (flags.role) args.push('--role', flags.role)
  if (flags.topology) args.push('--topology', flags.topology)
  const child = spawn(process.execPath, args, {
    cwd: resolve(appDir),
    env: { ...env, MOUSSE_NET_HELPER: helper, MOUSSE_NET_ENGINE_HELPER_BUILD: build },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let text = ''
  child.stdout.on('data', (d) => {
    text += d
    process.stdout.write(d)
  })
  child.stderr.on('data', (d) => {
    text += d
    process.stderr.write(d)
  })
  const code = await new Promise((done) => {
    child.on('error', (e) => {
      console.error(`run.mjs: ${e.message}`)
      done(2)
    })
    child.on('close', (c) => done(c ?? 2))
  })

  const appBuild = lineValue(text, 'app_build')
  const pinned = pinnedRevision()
  if (!appBuild || appBuild !== pinned) {
    console.error(
      `run.mjs: note: app build ${appBuild ?? '(not printed)'}, app/MOUSSE_REVISION pins ${pinned ?? '(nothing)'}; this run will not count`
    )
  }

  if (flags.result) {
    const pass = markerLine(text, `PASS ${id}`)
    const fail = markerLine(text, `FAIL ${id}`)
    const outcome = fail ? 'FAIL' : pass && code === 0 ? 'PASS' : undefined
    if (!outcome) {
      console.error(`run.mjs: no PASS or FAIL line for ${id}; no result written`)
    } else {
      const details = fail ?? pass
      const reason = fail && /reason=([^\s;,)"]+)/.exec(fail.slice(`FAIL ${id}`.length))?.[1]
      const result = {
        check: id,
        ...(flags.target ? { target: flags.target } : {}),
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
  }
  process.exit(code)
}

main()
