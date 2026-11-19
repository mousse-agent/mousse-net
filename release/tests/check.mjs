#!/usr/bin/env node
// The release checks of checks/phase3.toml, run on any machine with Docker
// (docs/release.md, design §B.15 and Part G):
//
//   node release/tests/check.mjs reproducible --out DIR [--control unsigned-accepted]
//   node release/tests/check.mjs install      --out DIR [--control skip-verify]
//
// reproducible: two independent builds of the relay (separate containers,
//   mount paths, job counts and time zones) give the same bytes; a release
//   signed by release/sign.sh with a throwaway minisign key verifies with
//   minisign and with install.sh; install.sh refuses an unsigned, tampered,
//   re-signed or replayed download.
// install: a fresh Ubuntu cloud image (systemd) goes to an enrollment link
//   with install.sh, and keeps the relay identity on upgrade; a tampered
//   download installs nothing; the cloud-init template does the same on
//   first boot; the relay image runs with a read-only root, no shell and an
//   unprivileged user, and keeps its identity across a restart.
//
// Containers run only on an `--internal` Docker network (or none). Keys are
// throwaway ones made under DIR. Prints `PASS phase3.<check>` or
// `FAIL phase3.<check> reason=<word>`.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const release = path.join(root, "release");

// --- Arguments ----------------------------------------------------------------

const argv = process.argv.slice(2);
const check = argv[0];
const opt = (k) => {
  const i = argv.indexOf(k);
  return i >= 0 ? argv[i + 1] : undefined;
};
const CONTROLS = { reproducible: ["unsigned-accepted"], install: ["skip-verify"] };
if (!CONTROLS[check]) {
  console.error("usage: check.mjs reproducible|install --out DIR [--control NAME]");
  process.exit(2);
}
const ID = `phase3.${check}`;
const control = opt("--control");
if (control && !CONTROLS[check].includes(control)) {
  console.error(`unknown control ${control} for ${ID}`);
  process.exit(2);
}
const out = path.resolve(opt("--out") ?? path.join(root, "checks", "runs", "out", `${ID}-manual`));
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const logFile = path.join(out, "check.log");

// A development source tree (a stand-in relay) may exercise the harness, but
// such a run never passes.
const devSource = process.env.MOUSSE_RELEASE_CHECK_DEV_SOURCE;

const cacheDir = path.resolve(
  process.env.MOUSSE_RELEASE_CACHE ??
    path.join(process.env.CARGO_TARGET_DIR ?? path.join(root, "target"), "release-cache"),
);
fs.mkdirSync(cacheDir, { recursive: true });

const conf = Object.fromEntries(
  fs
    .readFileSync(path.join(release, "toolchain.env"), "utf8")
    .split(/\r?\n/)
    .filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
);
const BUILDER = conf.BUILDER_IMAGE;
const NETWORK = "mousse-release-check";
const RUN = `${process.pid}`;
const PUBLIC = "203.0.113.10:443"; // TEST-NET-3: never routed
const MINISIGN = {
  url: "https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz",
  sha256: "9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73",
  file: "minisign-0.12-linux.tar.gz",
};
// The Ubuntu 24.04 cloud image root (what a VPS boots), imported as is.
const UBUNTU = {
  url: "https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64-root.tar.xz",
  sha256: "ec6972af8ea2bd05c55299d204e5ae3f91769b84cfaec7395639d236a39f9a03",
  tag: "mousse-release-test/ubuntu-cloud:24.04-20261017",
};

// --- Output -------------------------------------------------------------------

function log(text) {
  fs.appendFileSync(logFile, text.endsWith("\n") ? text : `${text}\n`);
}
function say(text) {
  console.log(text);
  log(text);
}
class Failure extends Error {
  constructor(reason, detail) {
    super(detail);
    this.reason = reason;
  }
}
const fail = (reason, detail) => {
  throw new Failure(reason, detail);
};

// --- Processes ------------------------------------------------------------------

function run(cmd, args, { input, allowFail = false, quiet = false } = {}) {
  log(`$ ${cmd} ${args.join(" ")}`);
  const r = spawnSync(cmd, args, {
    input,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
  });
  const text = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  if (!quiet || r.status !== 0) log(text);
  if (r.error) fail("setup", `${cmd}: ${r.error.message}`);
  if (r.status !== 0 && !allowFail) fail("setup", `${cmd} ${args.slice(0, 3).join(" ")} exited ${r.status}`);
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", text };
}

function runAsync(cmd, args) {
  log(`$ ${cmd} ${args.join(" ")} &`);
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env: { ...process.env, MSYS_NO_PATHCONV: "1" } });
    let text = "";
    child.stdout.on("data", (d) => (text += d));
    child.stderr.on("data", (d) => (text += d));
    child.on("close", (code) => {
      log(`--- ${cmd} ${args.slice(0, 4).join(" ")} exited ${code}\n${text}`);
      resolve({ code, text });
    });
  });
}

const docker = (args, o) => run("docker", args, o);
const bind = (src, dst, ro = false) => [
  "--mount",
  `type=bind,source=${src},target=${dst}${ro ? ",readonly" : ""}`,
];
const vol = (name, dst, ro = false) => ["--mount", `type=volume,source=${name},target=${dst}${ro ? ",readonly" : ""}`];

const cleanups = [];
function cleanup() {
  for (const f of cleanups.reverse()) {
    try {
      f();
    } catch {
      // best effort
    }
  }
}

// --- Inputs: network, images, tools, sources -----------------------------------

function ensureNetwork() {
  const r = docker(["network", "inspect", NETWORK, "--format", "{{.Internal}}"], { allowFail: true, quiet: true });
  if (r.code === 0) {
    if (r.stdout.trim() !== "true") fail("setup", `${NETWORK} exists and is not --internal`);
    return;
  }
  docker(["network", "create", "--internal", NETWORK]);
}

async function download(url, dest, sha256) {
  if (fs.existsSync(dest) && sha256File(dest) === sha256) return;
  say(`Downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) fail("setup", `download ${url}: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = createHash("sha256").update(buf).digest("hex");
  if (got !== sha256) fail("setup", `download ${url}: sha256 ${got}, expected ${sha256}`);
  fs.writeFileSync(dest, buf);
}

function sha256File(f) {
  return createHash("sha256").update(fs.readFileSync(f)).digest("hex");
}

async function ensureUbuntu() {
  const r = docker(["image", "inspect", UBUNTU.tag, "--format", '{{index .Config.Labels "source-sha256"}}'], {
    allowFail: true,
    quiet: true,
  });
  if (r.code === 0 && r.stdout.trim() === UBUNTU.sha256) return;
  say(`Importing the Ubuntu cloud image (${UBUNTU.url})`);
  const res = await fetch(UBUNTU.url);
  if (!res.ok) fail("setup", `download ${UBUNTU.url}: ${res.status}`);
  const hash = createHash("sha256");
  const child = spawn(
    "docker",
    ["import", "--change", `LABEL source-sha256=${UBUNTU.sha256}`, "--change", 'CMD ["/sbin/init"]', "-", UBUNTU.tag],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  let text = "";
  child.stdout.on("data", (d) => (text += d));
  child.stderr.on("data", (d) => (text += d));
  const done = new Promise((resolve) => child.on("close", resolve));
  for await (const chunk of Readable.fromWeb(res.body)) {
    hash.update(chunk);
    if (!child.stdin.write(chunk)) await new Promise((r2) => child.stdin.once("drain", r2));
  }
  child.stdin.end();
  const code = await done;
  log(text);
  const got = hash.digest("hex");
  if (got !== UBUNTU.sha256) {
    docker(["image", "rm", "-f", UBUNTU.tag], { allowFail: true });
    fail("setup", `Ubuntu image sha256 ${got}, expected ${UBUNTU.sha256}`);
  }
  if (code !== 0) fail("setup", "docker import failed");
}

async function ensureMinisign() {
  const tgz = path.join(cacheDir, MINISIGN.file);
  await download(MINISIGN.url, tgz, MINISIGN.sha256);
  const dir = path.join(cacheDir, "minisign-0.12");
  const bin = path.join(dir, "minisign-linux", "x86_64", "minisign");
  if (!fs.existsSync(bin)) {
    fs.mkdirSync(dir, { recursive: true });
    docker(["run", "--rm", "--network", "none", ...bind(cacheDir, "/c"), BUILDER, "tar", "-xzf", `/c/${MINISIGN.file}`, "-C", "/c/minisign-0.12"]);
  }
  return path.dirname(bin);
}

function lockHash() {
  return sha256File(path.join(devSource ?? root, "Cargo.lock")).slice(0, 16);
}

// The crates, vendored once per Cargo.lock into a Docker volume. Cargo checks
// every vendored file against the lock's checksums during the build.
function ensureVendor() {
  const name = `mousse-release-vendor-${lockHash()}`;
  const probe = docker(["run", "--rm", "--network", "none", ...vol(name, "/v", true), BUILDER, "test", "-f", "/v/.complete"], {
    allowFail: true,
    quiet: true,
  });
  if (probe.code === 0) return name;
  say("Vendoring crates");
  const tmp = path.join(cacheDir, `vendor-${lockHash()}`);
  fs.rmSync(tmp, { recursive: true, force: true });
  const r = spawnSync("cargo", ["vendor", "--locked", "--versioned-dirs", tmp], {
    cwd: devSource ?? root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  log(r.stderr ?? "");
  if (r.status !== 0) fail("setup", "cargo vendor failed");
  docker(["volume", "create", name], { quiet: true });
  docker(["run", "--rm", "--network", "none", ...bind(tmp, "/from", true), ...vol(name, "/v"), BUILDER, "sh", "-c", "cp -a /from/. /v/ && touch /v/.complete"]);
  fs.rmSync(tmp, { recursive: true, force: true });
  return name;
}

function sourceTree() {
  const src = path.join(out, "src");
  fs.mkdirSync(src, { recursive: true });
  if (devSource) {
    fs.cpSync(devSource, src, {
      recursive: true,
      filter: (p) => !path.relative(devSource, p).split(path.sep).includes("target"),
    });
    fs.mkdirSync(path.join(src, "release"), { recursive: true });
    fs.copyFileSync(path.join(release, "build-in-container.sh"), path.join(src, "release", "build-in-container.sh"));
    return { src, commit: "dev-source", epoch: "1700000000" };
  }
  const commit = run("git", ["-C", root, "rev-parse", "HEAD"], { quiet: true }).stdout.trim();
  const epoch = run("git", ["-C", root, "log", "-1", "--format=%ct", commit], { quiet: true }).stdout.trim();
  const tar = path.join(out, "src.tar");
  run("git", ["-C", root, "archive", "--format=tar", "-o", tar, commit], { quiet: true });
  docker(["run", "--rm", "--network", "none", ...bind(out, "/o"), BUILDER, "tar", "-xf", "/o/src.tar", "-C", "/o/src"], { quiet: true });
  fs.rmSync(tar);
  return { src, commit, epoch };
}

function version() {
  const toml = fs.readFileSync(path.join(root, "Cargo.toml"), "utf8");
  const m = toml.match(/\[workspace\.package\][^[]*?\nversion = "([^"]+)"/);
  if (!m) fail("setup", "no workspace version");
  return m[1];
}

// --- Build ------------------------------------------------------------------------

// One release build in a fresh container. `variant` changes everything that
// must not matter: mount paths, job count, time zone and the container.
function buildArgs({ src, commit, epoch }, vendorVol, outDir, variant) {
  const base = variant.base;
  return [
    "run",
    "--rm",
    "--name",
    `mousse-release-build-${variant.name}-${RUN}`,
    "--network",
    NETWORK,
    ...bind(src, `${base}/src`, true),
    ...vol(vendorVol, `${base}/vendor`, true),
    ...bind(outDir, `${base}/out`),
    "-e",
    `SRC=${base}/src`,
    "-e",
    `VENDOR=${base}/vendor`,
    "-e",
    `OUT=${base}/out`,
    "-e",
    `PACKAGES=${conf.PACKAGES}`,
    "-e",
    `SOURCE_DATE_EPOCH=${epoch}`,
    "-e",
    `MOUSSE_BUILD_ID=${commit}+release`,
    "-e",
    `CARGO_BUILD_JOBS=${variant.jobs}`,
    "-e",
    `TZ=${variant.tz}`,
    BUILDER,
    "sh",
    `${base}/src/release/build-in-container.sh`,
  ];
}

const VARIANTS = [
  { name: "a", base: "/in/a", jobs: 2, tz: "UTC" },
  { name: "b", base: "/mnt/other/b", jobs: 4, tz: "Asia/Kolkata" },
];

async function build(source, vendorVol, variants) {
  const dirs = variants.map((v) => {
    const d = path.join(out, `build-${v.name}`);
    fs.mkdirSync(d, { recursive: true });
    return d;
  });
  say(`Building ${conf.PACKAGES} (${variants.length === 2 ? "two independent builds" : "one build"})`);
  const results = await Promise.all(variants.map((v, i) => runAsync("docker", buildArgs(source, vendorVol, dirs[i], v))));
  results.forEach((r, i) => {
    if (r.code !== 0) fail("build-failed", `build ${variants[i].name} exited ${r.code}; see ${logFile}`);
  });
  return dirs;
}

function sums(dir) {
  const f = fs.readdirSync(dir).find((n) => n.startsWith("SHA256SUMS."));
  if (!f) fail("build-failed", `no checksums in ${dir}`);
  return { file: f, text: fs.readFileSync(path.join(dir, f), "utf8") };
}

// --- Keys, packaging and signing -------------------------------------------------

function minisignRun(minisignDir, mounts, script) {
  return docker([
    "run",
    "--rm",
    "--network",
    "none",
    ...bind(minisignDir, "/opt/minisign", true),
    ...mounts,
    "-e",
    "PATH=/opt/minisign:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    BUILDER,
    "sh",
    "-c",
    script,
  ]);
}

function makeKeys(minisignDir) {
  const keys = path.join(out, "keys");
  fs.mkdirSync(keys, { recursive: true });
  // Throwaway keys, made for this run and never used again.
  minisignRun(
    minisignDir,
    bind(keys, "/k"),
    "minisign -G -W -p /k/release.pub -s /k/release.key && minisign -G -W -p /k/attacker.pub -s /k/attacker.key",
  );
  return keys;
}

// dist: the build output as a release folder, packaged with the throwaway
// public key and signed by release/sign.sh.
function makeDist(name, buildDir, { commit, epoch }, ver, minisignDir, keys, { key = "release", signVersion = ver } = {}) {
  const dist = path.join(out, "dist", name);
  fs.mkdirSync(dist, { recursive: true });
  let sumsText = "";
  for (const f of fs.readdirSync(buildDir)) {
    if (f.startsWith("SHA256SUMS.")) sumsText += fs.readFileSync(path.join(buildDir, f), "utf8");
    else fs.copyFileSync(path.join(buildDir, f), path.join(dist, f));
  }
  fs.writeFileSync(path.join(dist, "SHA256SUMS"), sumsText);
  const buildInfo = `commit=${commit}\nversion=${ver}\nsource_date_epoch=${epoch}\nbuilder=${BUILDER}\n`;
  fs.writeFileSync(path.join(dist, "BUILD"), buildInfo);
  minisignRun(
    minisignDir,
    [...bind(release, "/release", true), ...bind(dist, "/dist"), ...bind(keys, "/k", true)],
    "sh /release/package.sh --pubkey /k/release.pub --dist /dist",
  );
  if (signVersion !== ver) fs.writeFileSync(path.join(dist, "BUILD"), buildInfo.replace(`version=${ver}`, `version=${signVersion}`));
  minisignRun(
    minisignDir,
    [...bind(release, "/release", true), ...bind(dist, "/dist"), ...bind(keys, "/k", true)],
    `sh /release/sign.sh --key /k/${key}.key --pubkey /k/${key}.pub --dist /dist`,
  );
  if (signVersion !== ver) fs.writeFileSync(path.join(dist, "BUILD"), buildInfo);
  return dist;
}

// A must-fail control plants its bug in the test's copy of install.sh only.
function plantControl(dist) {
  const plants = {
    "unsigned-accepted": ["minisig_verify() {\n", "minisig_verify() {\n  return 0 # control: unsigned-accepted\n"],
    "skip-verify": ["verify_release() {\n", "verify_release() {\n  return 0 # control: skip-verify\n"],
  };
  if (!control) return;
  const [from, to] = plants[control];
  for (const [f, indent] of [
    ["install.sh", ""],
    ["cloud-init.yaml", "      "],
  ]) {
    const p = path.join(dist, f);
    const text = fs.readFileSync(p, "utf8");
    const a = `\n${indent}${from}`;
    const b = `\n${indent}${from}${indent}${to.slice(from.length)}`;
    if (text.split(a).length !== 2) fail("setup", `control ${control}: no single ${from.trim()} in ${f}`);
    fs.writeFileSync(p, text.replace(a, b));
  }
}

const artifactName = (dist) => fs.readdirSync(dist).find((f) => /^mousse-relay-.*-linux-musl$/.test(f));

function copyDist(from, name) {
  const to = path.join(out, "dist", name);
  fs.cpSync(from, to, { recursive: true });
  return to;
}

function appendTamper(file) {
  fs.appendFileSync(file, Buffer.from("\nMOUSSE-RELEASE-CHECK-TAMPERED\n"));
}

function rewriteSums(dist) {
  const name = artifactName(dist);
  const hash = sha256File(path.join(dist, name));
  fs.writeFileSync(path.join(dist, "SHA256SUMS"), `${hash}  ${name}\n`);
}

// --- reproducible -------------------------------------------------------------------

function verifyOnly(dist) {
  return docker(
    ["run", "--rm", "--network", NETWORK, ...bind(dist, "/mnt/dist", true), UBUNTU.tag, "sh", "/mnt/dist/install.sh", "--verify-only", "--from", "/mnt/dist"],
    { allowFail: true },
  );
}

async function reproducible() {
  ensureNetwork();
  const source = sourceTree();
  const vendorVol = ensureVendor();
  const minisignDir = await ensureMinisign();
  await ensureUbuntu();
  const ver = version();

  const [a, b] = await build(source, vendorVol, VARIANTS);
  const sa = sums(a);
  const sb = sums(b);
  say(`build a: ${sa.text.trim()}`);
  say(`build b: ${sb.text.trim()}`);
  if (sa.text !== sb.text) fail("not-reproducible", "the two builds differ");
  for (const f of fs.readdirSync(a)) {
    if (!fs.readFileSync(path.join(a, f)).equals(fs.readFileSync(path.join(b, f)))) fail("not-reproducible", `${f} differs`);
  }
  say("The two builds are identical");

  const keys = makeKeys(minisignDir);
  const good = makeDist("good", a, source, ver, minisignDir, keys);
  const name = artifactName(good);

  // minisign itself accepts every signature.
  minisignRun(
    minisignDir,
    [...bind(good, "/dist", true), ...bind(keys, "/k", true)],
    `cd /dist && for f in ${name} SHA256SUMS install.sh cloud-init.yaml; do minisign -V -q -p /k/release.pub -m $f || exit 1; done`,
  );
  plantControl(good);

  const cases = [];
  // An attacker's binary and matching checksums, with no signatures.
  const unsigned = copyDist(good, "unsigned");
  appendTamper(path.join(unsigned, name));
  rewriteSums(unsigned);
  for (const f of fs.readdirSync(unsigned).filter((f) => f.endsWith(".minisig"))) fs.rmSync(path.join(unsigned, f));
  cases.push(["unsigned", unsigned, "unsigned-accepted"]);
  // The signed release with the binary changed.
  const tampered = copyDist(good, "tampered");
  appendTamper(path.join(tampered, name));
  cases.push(["tampered", tampered, "tampered-accepted"]);
  // An attacker's binary, signed by another key.
  const otherKey = path.join(out, "dist", "other-key");
  {
    const d = makeDist("other-key", a, source, ver, minisignDir, keys, { key: "attacker" });
    appendTamper(path.join(d, name));
    rewriteSums(d);
    minisignRun(
      minisignDir,
      [...bind(release, "/release", true), ...bind(d, "/dist"), ...bind(keys, "/k", true)],
      "sh /release/sign.sh --key /k/attacker.key --pubkey /k/attacker.pub --dist /dist",
    );
    // install.sh as the user downloaded it: the release key.
    fs.copyFileSync(path.join(good, "install.sh"), path.join(d, "install.sh"));
  }
  cases.push(["other-key", otherKey, "other-key-accepted"]);
  // A genuine older release served as this one.
  const replay = makeDist("replay", a, source, ver, minisignDir, keys, { signVersion: "0.0.1" });
  fs.copyFileSync(path.join(good, "install.sh"), path.join(replay, "install.sh"));
  cases.push(["replay", replay, "replay-accepted"]);

  const g = verifyOnly(good);
  if (g.code !== 0 || !g.text.includes(`Verified mousse-relay ${ver}`)) fail("signature-rejected", "install.sh refused the signed release");
  say("install.sh verifies the signed release");
  for (const [label, dist, reason] of cases) {
    const r = verifyOnly(dist);
    if (r.code === 0 || r.text.includes("Verified mousse-relay")) fail(reason, `install.sh accepted the ${label} download`);
    say(`install.sh refuses the ${label} download: ${r.text.trim().split("\n").pop()}`);
  }
}

// --- install -----------------------------------------------------------------------

function loadImage(dist, epoch, ver) {
  const ctx = path.join(out, "image");
  fs.mkdirSync(path.join(ctx, "state"), { recursive: true });
  for (const f of fs.readdirSync(dist).filter((f) => /^mousse-relay-.*-linux-musl$/.test(f))) {
    fs.copyFileSync(path.join(dist, f), path.join(ctx, f));
  }
  const tag = `mousse-release-test/relay:${RUN}`;
  docker([
    "buildx",
    "build",
    "--network",
    "none",
    "--build-arg",
    `SOURCE_DATE_EPOCH=${epoch}`,
    "--output",
    `type=oci,dest=${path.join(out, "relay-image.oci.tar")},rewrite-timestamp=true,name=${tag}`,
    "-f",
    path.join(release, "relay.Dockerfile"),
    ctx,
  ]);
  docker(["load", "-i", path.join(out, "relay-image.oci.tar")]);
  cleanups.push(() => docker(["image", "rm", "-f", tag], { allowFail: true, quiet: true }));
  return tag;
}

function bootUbuntu(name, mounts, { cloudInit = false } = {}) {
  const prep = cloudInit ? "" : "touch /etc/cloud/cloud-init.disabled; ";
  docker([
    "run",
    "-d",
    "--name",
    name,
    "--hostname",
    "relay",
    "--privileged",
    "--cgroupns=private",
    "--network",
    NETWORK,
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/run/lock",
    ...mounts,
    UBUNTU.tag,
    "/bin/sh",
    "-c",
    `${prep}exec /sbin/init`,
  ]);
  cleanups.push(() => docker(["rm", "-f", name], { allowFail: true, quiet: true }));
  // Up once multi-user.target is reached; the cloud-init case then waits for
  // cloud-init itself.
  for (let i = 0; i < 180; i++) {
    const r = docker(["exec", name, "systemctl", "is-active", "multi-user.target"], { allowFail: true, quiet: true });
    if (r.stdout.trim() === "active") return;
    sleep(1000);
  }
  fail("setup", `${name} did not boot`);
}

const sleep = (ms) => spawnSync(process.execPath, ["-e", `setTimeout(()=>{},${ms})`]);
const exec = (name, args, o = {}) => docker(["exec", name, ...args], { allowFail: true, ...o });

const LINK = /^mousse-relay:\/\/([^/\s]+)\/#([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/m;

function relayIdFromStatus(text) {
  try {
    const j = JSON.parse(text);
    return j.relay_id ?? j.relay?.id ?? j.id;
  } catch {
    return undefined;
  }
}

function checkService(name, linkId) {
  let active = "";
  for (let i = 0; i < 20; i++) {
    active = exec(name, ["systemctl", "is-active", "mousse-relay"], { quiet: true }).stdout.trim();
    if (active === "active") break;
    sleep(500);
  }
  if (active !== "active") fail("not-running", `mousse-relay is ${active || "missing"}`);
  const show = exec(name, ["systemctl", "show", "mousse-relay", "-p", "User", "-p", "CapabilityBoundingSet", "-p", "AmbientCapabilities"]).stdout;
  if (!/^User=mousse-relay$/m.test(show)) fail("unit", `unit user: ${show}`);
  if (!/^CapabilityBoundingSet=cap_net_bind_service$/m.test(show)) fail("unit", `capabilities: ${show}`);
  if (!/^AmbientCapabilities=cap_net_bind_service$/m.test(show)) fail("unit", `ambient capabilities: ${show}`);
  const user = exec(name, ["ps", "-o", "user=", "-C", "mousse-relay"]).stdout.trim();
  if (user !== "mousse-relay") fail("unit", `relay process runs as ${user || "nobody"}`);
  const status = exec(name, ["runuser", "-u", "mousse-relay", "--", "/usr/local/bin/mousse-relay", "status", "--json", "--state", "/var/lib/mousse-relay"]);
  const id = relayIdFromStatus(status.stdout);
  if (!id || id !== linkId) fail("identity", `status relay id ${id} against link ${linkId}`);
}

async function install() {
  ensureNetwork();
  const source = sourceTree();
  const vendorVol = ensureVendor();
  const minisignDir = await ensureMinisign();
  await ensureUbuntu();
  const ver = version();
  const [built] = await build(source, vendorVol, [VARIANTS[0]]);
  const keys = makeKeys(minisignDir);
  const good = makeDist("good", built, source, ver, minisignDir, keys);
  plantControl(good);
  const name = artifactName(good);

  // 1. A tampered download installs nothing.
  {
    const dist = copyDist(good, "tampered");
    appendTamper(path.join(dist, name));
    const box = `mousse-release-tampered-${RUN}`;
    bootUbuntu(box, bind(dist, "/mnt/dist", true));
    const r = exec(box, ["sh", "/mnt/dist/install.sh", "--from", "/mnt/dist", "--public", PUBLIC]);
    const left = exec(box, ["sh", "-c", "ls /usr/local/bin/mousse-relay /etc/systemd/system/mousse-relay.service 2>/dev/null; id mousse-relay 2>/dev/null"]).stdout.trim();
    if (r.code === 0 || left) fail("tampered-installed", `install.sh installed a tampered download: ${left}`);
    say(`A tampered download installs nothing: ${r.text.trim().split("\n").pop()}`);
    docker(["rm", "-f", box], { quiet: true });
  }

  // 2. install.sh on a fresh server: enrollment link, hardened unit, upgrade.
  {
    const box = `mousse-release-install-${RUN}`;
    bootUbuntu(box, bind(good, "/mnt/dist", true));
    const r = exec(box, ["sh", "/mnt/dist/install.sh", "--from", "/mnt/dist", "--public", PUBLIC]);
    if (r.code !== 0) fail("install-failed", "install.sh failed on a fresh server");
    const m = r.stdout.match(LINK);
    if (!m || m[1] !== PUBLIC) fail("no-link", "install.sh printed no enrollment link for the public address");
    say(`install.sh: enrollment link for ${m[1]}`);
    checkService(box, m[2]);
    const up = exec(box, ["sh", "/mnt/dist/install.sh", "--from", "/mnt/dist"]);
    if (up.code !== 0) fail("upgrade-failed", "install.sh failed as an upgrade");
    if (LINK.test(up.stdout)) fail("upgrade-reinit", "the upgrade made a new enrollment link");
    checkService(box, m[2]);
    say("install.sh upgrade keeps the relay identity");
    docker(["rm", "-f", box], { quiet: true });
  }

  // 3. The cloud-init template on first boot, then its upgrade.
  {
    const seed = path.join(out, "seed");
    fs.mkdirSync(seed, { recursive: true });
    const tpl = fs.readFileSync(path.join(good, "cloud-init.yaml"), "utf8");
    const parts = tpl.split("--public auto");
    if (parts.length !== 2) fail("setup", "the template has no single --public auto");
    fs.writeFileSync(path.join(seed, "user-data"), parts.join(`--public ${PUBLIC} --from /mnt/dist`));
    fs.writeFileSync(path.join(seed, "meta-data"), "instance-id: mousse-relay-check\nlocal-hostname: relay\n");
    const box = `mousse-release-cloudinit-${RUN}`;
    bootUbuntu(box, [...bind(good, "/mnt/dist", true), ...bind(seed, "/var/lib/cloud/seed/nocloud", true)], { cloudInit: true });
    const w = exec(box, ["timeout", "600", "cloud-init", "status", "--wait", "--long"]);
    log(w.text);
    const txt = exec(box, ["cat", "/root/mousse-relay.txt"]).stdout;
    const m = txt.match(LINK);
    if (!m || m[1] !== PUBLIC) fail("template-no-link", "the template left no enrollment link in /root/mousse-relay.txt");
    say(`cloud-init template: enrollment link for ${m[1]}`);
    checkService(box, m[2]);
    const up = exec(box, ["/usr/local/sbin/mousse-relay-install", "--from", "/mnt/dist"]);
    if (up.code !== 0 || LINK.test(up.stdout)) fail("upgrade-failed", "the template's upgrade failed or made a new link");
    checkService(box, m[2]);
    say("The template's upgrade keeps the relay identity");
    docker(["rm", "-f", box], { quiet: true });
  }

  // 4. The relay image: read-only root, no shell, unprivileged, state volume.
  {
    const tag = loadImage(good, source.epoch, ver);
    const cfg = JSON.parse(docker(["image", "inspect", tag, "--format", "{{json .Config}}"]).stdout);
    if (cfg.User !== "65532:65532") fail("image", `image user ${cfg.User}`);
    const sh = docker(["run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", tag, "-c", "true"], { allowFail: true });
    if (sh.code === 0) fail("image", "the image has a shell");
    const state = `mousse-release-state-${RUN}`;
    docker(["volume", "create", state], { quiet: true });
    cleanups.push(() => docker(["volume", "rm", "-f", state], { allowFail: true, quiet: true }));
    const hardened = ["--network", NETWORK, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--ulimit", "core=0", ...vol(state, "/state")];
    const init = docker(["run", "--rm", ...hardened, tag, "init", "--state", "/state", "--public", PUBLIC]);
    const m = init.stdout.match(LINK);
    if (!m || m[1] !== PUBLIC) fail("no-link", "the image's init printed no enrollment link");
    say(`relay image: enrollment link for ${m[1]}`);
    for (const round of [1, 2]) {
      const box = `mousse-release-relay-${RUN}`;
      docker(["run", "-d", "--name", box, "--network-alias", "relay", ...hardened, tag]);
      cleanups.push(() => docker(["rm", "-f", box], { allowFail: true, quiet: true }));
      sleep(2000);
      const st = docker(["inspect", box, "--format", "{{.State.Running}}"]).stdout.trim();
      if (st !== "true") fail("not-running", "the relay container stopped");
      const probe = docker(["run", "--rm", "--network", NETWORK, UBUNTU.tag, "timeout", "5", "bash", "-c", "</dev/tcp/relay/443"], { allowFail: true });
      if (probe.code !== 0) fail("not-listening", "the relay container does not accept on 443");
      docker(["rm", "-f", box], { quiet: true });
      const status = docker(["run", "--rm", ...hardened, tag, "status", "--json", "--state", "/state"]);
      const id = relayIdFromStatus(status.stdout);
      if (id !== m[2]) fail("identity", `round ${round}: status relay id ${id} against link ${m[2]}`);
    }
    say("The relay image keeps its identity in the state volume across restarts");
  }
}

// --- Main ---------------------------------------------------------------------------

const started = Date.now();
try {
  if (!BUILDER) fail("setup", "no BUILDER_IMAGE in release/toolchain.env");
  if (control) say(`Control ${control}: install.sh is planted with the defect for this run`);
  if (devSource) say(`DEV SOURCE ${devSource}: this run cannot pass`);
  await (check === "reproducible" ? reproducible() : install());
  cleanup();
  say(`(${Math.round((Date.now() - started) / 1000)} s)`);
  if (devSource) {
    say(`DEV-ONLY ok ${ID}`);
    process.exit(3);
  }
  say(`PASS ${ID}`);
  process.exit(0);
} catch (e) {
  cleanup();
  if (!(e instanceof Failure)) {
    log(e.stack ?? String(e));
    e = new Failure("setup", e.message);
  }
  say(e.message);
  say(`FAIL ${ID} reason=${e.reason}`);
  process.exit(1);
}
