// Self-tests of tools/build-smoke.mjs that need no build.
// Run: node --test tools/app-check/test/build-smoke.test.mjs
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const smoke = join(root, 'tools', 'build-smoke.mjs')

test('a stale helper still names the app build, before it fails', () => {
  const out = mkdtempSync(join(tmpdir(), 'build-smoke-test-'))
  try {
    const head = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim()
    assert.match(head, /^[0-9a-f]{40}$/)
    // Node stands in for both binaries: its --version names no build, so
    // the helper check fails before anything is served or packaged.
    const r = spawnSync(
      process.execPath,
      [smoke, 'phase1b.desktop-builds', '--target', 'linux-x64', '--out', out, '--helper', process.execPath, '--probe', process.execPath],
      { encoding: 'utf8', env: { ...process.env, MOUSSE_APP_DIR: root, MOUSSE_BUILD_ID: '0000000+release' } }
    )
    assert.equal(r.status, 1, r.stdout + r.stderr)
    assert.match(r.stdout, /^FAIL phase1b\.desktop-builds reason=stale_helper$/m)
    const lines = r.stdout.split(/\r?\n/)
    const at = lines.indexOf(`app_build=${head}`)
    assert.ok(at >= 0, `no app_build line:\n${r.stdout}`)
    assert.ok(at < lines.findIndex((l) => l.startsWith('helper_version=')), r.stdout)
  } finally {
    rmSync(out, { recursive: true, force: true })
  }
})
