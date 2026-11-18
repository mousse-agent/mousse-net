#!/usr/bin/env node
// Reads app output on stdin and writes each `MOUSSE_RESULT <json>` line to a file.
//
//   node scripts/collect-results.mjs --out results [--expect pass|fail] [--log file]
//
// Normal runs go to <out>/<check>__<target>.json. Must-fail control runs (the result
// names a breakMode) go to <out>/controls/<check>__<target>__break-<mode>.json.
// Exit code: --expect pass (default) needs every result PASS; --expect fail needs
// every result FAIL (a control that passes is a broken test). No results at all fails.
import { mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const out = opt('--out', 'results');
const expect = opt('--expect', 'pass');
const logFile = opt('--log', null);
const want = expect === 'fail' ? 'FAIL' : 'PASS';
const PREFIX = 'MOUSSE_RESULT ';

let seen = 0;
let bad = 0;
const rl = createInterface({ input: process.stdin });
for await (const raw of rl) {
  if (logFile) appendFileSync(logFile, raw + '\n');
  // logcat and console prefixes come before the marker.
  const at = raw.indexOf(PREFIX);
  if (at < 0) {
    if (/MOUSSE_|lifecycle:|page:|error/i.test(raw)) console.log(raw);
    continue;
  }
  let r;
  try {
    r = JSON.parse(raw.slice(at + PREFIX.length));
  } catch (e) {
    console.log('unparseable result line: ' + e.message);
    bad++;
    continue;
  }
  seen++;
  const mode = r.details && r.details.breakMode;
  const dir = mode ? join(out, 'controls') : out;
  const name = mode ? `${r.check}__${r.target}__break-${mode}.json` : `${r.check}__${r.target}.json`;
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), JSON.stringify(r, null, 2) + '\n');
  const failing = Object.entries((r.details && r.details.steps) || {})
    .filter(([, s]) => s.failures > 0)
    .map(([k, s]) => `${k} ${s.failures}/${s.runs}`);
  console.log(`${r.outcome} ${r.check} ${r.target} ${r.build}${failing.length ? '  failing: ' + failing.join(', ') : ''}  -> ${join(dir, name)}`);
  if (r.outcome !== want) bad++;
}
if (seen === 0) {
  console.log('no results');
  process.exit(1);
}
process.exit(bad ? 1 : 0);
