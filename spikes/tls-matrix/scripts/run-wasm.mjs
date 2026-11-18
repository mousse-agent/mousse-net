// Runs the crypto matrix from a wasm-bindgen `--target nodejs` package, or
// collects `MATRIX_RESULT` lines printed by the browser Worker test, and
// writes one JSON result per provider pair.
//
//   node run-wasm.mjs --pkg <dir with tls_matrix.js> [--out <dir>] [--build <id>]
//   <worker test output> | node run-wasm.mjs --stdin [--out <dir>]
//
// MOUSSE_MATRIX_BREAK=1 swaps the pinned server key, so every pair must FAIL.
// Exits 1 if any pair fails or no result was found.

import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const PREFIX = "MATRIX_RESULT ";
const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const pkg = opt("--pkg");
const fromStdin = args.includes("--stdin");
if (!pkg && !fromStdin) {
  console.error("usage: node run-wasm.mjs (--pkg <dir> | --stdin) [--out <dir>] [--build <id>]");
  process.exit(2);
}
const out = opt("--out");

let entries;
if (fromStdin) {
  entries = readFileSync(0, "utf8")
    .split(/\r?\n/)
    .map((line) => line.slice(Math.max(0, line.indexOf(PREFIX))))
    .filter((line) => line.startsWith(PREFIX))
    .map((line) => JSON.parse(line.slice(PREFIX.length)));
} else {
  const build = opt("--build") ?? "unknown";
  const breakPin = process.env.MOUSSE_MATRIX_BREAK === "1";
  const require = createRequire(import.meta.url);
  const wasm = require(resolve(pkg, "tls_matrix.js"));
  entries = JSON.parse(wasm.run_matrix(Date.now(), breakPin, build, `node`));
}

let allPass = entries.length > 0;
for (const { file, result } of entries) {
  allPass &&= result.outcome === "PASS";
  console.log(
    `${result.outcome.padEnd(4)} ${result.target.padEnd(30)} ${result.provider.padEnd(24)} kx=${result.kx_group.padEnd(16)} suite=${result.suite}`,
  );
  if (result.outcome !== "PASS") console.log(JSON.stringify(result, null, 2));
  if (out) {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, file), JSON.stringify(result, null, 2) + "\n");
  }
}
console.log(`${allPass ? "PASS" : "FAIL"} phase0.crypto-matrix`);
process.exit(allPass ? 0 : 1);
