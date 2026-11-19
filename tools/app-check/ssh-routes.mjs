/**
 * The two loopback SSH routes of the `ssh` route case (Phase 1b §14,
 * "Reverse direction"). On one machine both endpoints run on the PC and
 * every listener is on loopback, so the kit runs two test SSH servers
 * (`test-sshd`, checks/README.md), one per direction, each into its own
 * side's Mousse home. Each side's owner address is the other's server, so
 * `pair-both-ways` can assert both directions. The real SSH add
 * (`ssh-add-app`) uses one.
 *
 * run.mjs builds `test-sshd` for `--route ssh` and passes its path in
 * MOUSSE_CHECK_TEST_SSHD, and this module's path in
 * MOUSSE_CHECK_SSH_ROUTES. The app script imports it:
 *
 *   const { startSshRoutes } = await import(pathToFileURL(process.env.MOUSSE_CHECK_SSH_ROUTES))
 *   const routes = await startSshRoutes({ out, sides: { a: { mousseHome, launchers }, b: { ... } } })
 *   // routes.a: { port, hostKey, config, keys } is the server that reaches side a
 *   await routes.stop()
 *
 * Launchers: on Unix each side's `<mousse home>/bin` holds the real
 * launchers; on Windows (not an SSH remote in 1b) `launchers` maps
 * `mousse-helper` and `mousse-cli` to programs, as `--launcher` does.
 */
import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

/** Wait for the server's `ready port <n> host_key <k> config <path>` line. */
function ready(child, waitMs) {
  return new Promise((done, fail) => {
    let text = ''
    const timer = setTimeout(() => fail(new Error(`test-sshd did not say ready: ${text}`)), waitMs)
    const look = (d) => {
      text += d
      const m = /ready port (\d+) host_key (\S+) config (.+)/.exec(text)
      if (m) {
        clearTimeout(timer)
        done({ port: Number(m[1]), hostKey: m[2], config: m[3].trim() })
      }
    }
    child.stdout.on('data', look)
    child.stderr.on('data', look)
    child.on('exit', (code) => {
      clearTimeout(timer)
      fail(new Error(`test-sshd exited (${code}): ${text}`))
    })
  })
}

/**
 * Start one server. `command`: the server program and any leading
 * arguments (default: MOUSSE_CHECK_TEST_SSHD). It serves until `stop()`,
 * which closes its stdin.
 */
export async function startSshRoute({ keys, home, mousseHome, launchers = {}, preamble, command, waitMs = 30000 }) {
  const [exe, ...lead] = command ?? [process.env.MOUSSE_CHECK_TEST_SSHD]
  if (!exe) throw new Error('MOUSSE_CHECK_TEST_SSHD is not set (run.mjs sets it for --route ssh)')
  mkdirSync(keys, { recursive: true })
  const args = [...lead, '--port', '0', '--keys', keys]
  if (home) args.push('--home', home)
  if (mousseHome) args.push('--mousse-home', mousseHome)
  for (const [name, path] of Object.entries(launchers)) args.push('--launcher', `${name}=${path}`)
  if (preamble) args.push('--preamble', preamble)
  const child = spawn(exe, args, { stdio: ['pipe', 'pipe', 'pipe'] })
  const info = await ready(child, waitMs)
  child.removeAllListeners('exit')
  return {
    ...info,
    keys,
    stop: () =>
      new Promise((done) => {
        if (child.exitCode !== null) return done()
        child.once('exit', () => done())
        child.stdin.end()
        setTimeout(() => child.kill(), 5000).unref()
      })
  }
}

/** One server per side, each in `<out>/ssh-<side>`. */
export async function startSshRoutes({ out, sides, command }) {
  const routes = {}
  try {
    for (const [name, side] of Object.entries(sides)) {
      routes[name] = await startSshRoute({ ...side, keys: join(out, `ssh-${name}`), command })
    }
  } catch (e) {
    await Promise.all(Object.values(routes).map((r) => r.stop()))
    throw e
  }
  return {
    ...routes,
    stop: () => Promise.all(Object.values(routes).map((r) => r.stop()))
  }
}
