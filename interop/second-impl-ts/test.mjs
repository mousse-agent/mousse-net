import { run } from 'node:test';
import { inspect } from 'node:util';
import { fileURLToPath } from 'node:url';

const counts = new Map();
let failed = false;
const result = run({ files: [fileURLToPath(new URL('./vector-tests.mjs', import.meta.url))] });
for await (const { type, data } of result) {
  if (type === 'test:stdout' || type === 'test:stderr') process.stdout.write(data.message);
  if (type !== 'test:pass' && type !== 'test:fail') continue;
  const pass = type === 'test:pass';
  const [group] = data.name.split(' / ');
  if (data.name.includes(' / ')) {
    const tally = counts.get(group) ?? { pass: 0, total: 0 };
    tally.total++;
    if (pass) tally.pass++;
    counts.set(group, tally);
  }
  if (!pass) {
    failed = true;
    if (data.name.includes(' / ') || !counts.size) {
      console.error(`${data.name}: ${inspect(data.details.error, { depth: 3, colors: false })}`);
    }
  }
}
for (const [group, { pass, total }] of [...counts].sort(([a], [b]) => a.localeCompare(b))) {
  console.log(`${group} ${pass}/${total}`);
}
process.exitCode = failed ? 1 : 0;
console.log(failed ? 'FAIL second-impl' : 'PASS second-impl');
