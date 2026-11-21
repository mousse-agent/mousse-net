//! `tools/app-check/run.mjs` end to end: it builds this checkout's helper,
//! runs a stand-in for the app's check script in an app checkout, and writes
//! a result `mousse-check sign` keeps the builds of. Needs `node` and
//! `cargo` on the path.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mousse_check::kit::{payload_from, SignArgs};

/// Stands in for the app's `scripts/net-engine-check.mjs`: prints what it
/// was given, the builds a caller reports for its host, and PASS, or FAIL
/// with the control's name as the reason.
const FAKE_CHECK: &str = r#"
import { execSync, spawnSync } from 'node:child_process'
import { existsSync, writeFileSync } from 'node:fs'
import net from 'node:net'
const args = process.argv.slice(2)
const id = args[0]
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined }
const head = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim()
console.log(`app_build=${head}`)
const helper = process.env.MOUSSE_NET_HELPER
console.log(`seen_helper=${helper && existsSync(helper) ? 'exists' : 'missing'}`)
// The helper refuses to start with a MOUSSE_NET_* variable it does not
// know. `id` on an empty state folder reads the limits first.
const started = helper && spawnSync(helper, ['id'], {
  encoding: 'utf8',
  env: { ...process.env, MOUSSE_HELPER_STATE: `${flag('--out')}/state` }
})
const refused = !started || /not a known limit/.test(started.stderr)
console.log(`seen_helper_starts=${refused ? 'no' : 'yes'}`)
console.log(`seen_helper_build=${process.env.MOUSSE_NET_ENGINE_HELPER_BUILD}`)
console.log(`seen_role=${flag('--role') ?? 'none'}`)
console.log(`seen_topology=${flag('--topology') ?? 'none'}`)
writeFileSync(`${flag('--out')}/ran`, 'yes')
if (flag('--role') === 'caller') {
  console.log(`host_build=${process.env.MOUSSE_NET_ENGINE_HELPER_BUILD}`)
  console.log(`host_app_build=${head}`)
}
const control = process.env.MOUSSE_NET_ENGINE_CONTROL
// Phase 1b: the route case and the kit's stand-ins. The kit's controls
// stand for an app that breaks the rule and still prints PASS.
const route = flag('--route')
console.log(`seen_route=${route ?? 'none'}`)
console.log(`seen_plus=${process.env.MOUSSE_PLUS_ORIGIN ? 'set' : 'unset'}`)
const probe = process.env.MOUSSE_CHECK_PROBE_BIN
console.log(`seen_probe=${probe && existsSync(probe) ? 'exists' : 'missing'}`)
console.log(`seen_egress=${process.env.MOUSSE_NET_TEST_EGRESS ?? 'unset'}`)
if (route) {
  const kind = control === 'route-leak' ? (route === 'tcp' ? 'ws' : 'tcp') : route
  // A relay connection names the relay of the first link it was given.
  const link = (process.env.MOUSSE_RELAY_TEST_LINKS ?? '').split(/[ ,]+/)[0]
  const destination = 'relay://' + (link.split('//')[1] ?? '').split('/')[0]
  const ups =
    route === 'tcp' ? [{ kind, class: 'tailnet' }, { kind, class: 'public' }]
    : kind === 'relay' ? [{ kind, destination }]
    : [{ kind }]
  const lines = ups.map((r) => JSON.stringify({ ev: 'conn.up', route: r }) + String.fromCharCode(10))
  // FAKE_CONN_UP: the connections a broken app would report instead.
  writeFileSync(`${flag('--out')}/conn-up.jsonl`, process.env.FAKE_CONN_UP ?? lines.join(''))
}
if (control === 'plus-probe') {
  await fetch(`${process.env.MOUSSE_PLUS_ORIGIN}/v1/session`).catch(() => {})
}
if (control === 'egress-probe') {
  await new Promise((done) => net.connect(443, '192.0.2.7').on('error', done).on('connect', done))
}
if (['plus-probe', 'egress-probe', 'route-leak'].includes(control)) {
  console.log(`PASS ${id}`)
  process.exit(0)
}
// FAKE_ENDING: how a broken check script might end instead.
const ending = process.env.FAKE_ENDING
if (ending === 'fail-exit-0') {
  console.log(`FAIL ${id} reason=${control}`)
  process.exit(0)
}
if (ending === 'both-exit-1') {
  console.log(`PASS ${id}`)
  console.log(`FAIL ${id} reason=${control}`)
  process.exit(1)
}
if (ending === 'pass-exit-1') {
  console.log(`PASS ${id}`)
  process.exit(1)
}
if (control) {
  console.log(`FAIL ${id} reason=${control}`)
  process.exit(1)
}
console.log(`PASS ${id}`)
"#;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(o.status.success(), "git {args:?}");
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A throwaway app checkout holding the stand-in check script.
fn fake_app(name: &str) -> (Dir, String) {
    let dir = std::env::temp_dir().join(format!("mousse-app-check-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("scripts")).unwrap();
    std::fs::write(dir.join("scripts/net-engine-check.mjs"), FAKE_CHECK).unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.name", "Tester"]);
    git(&dir, &["config", "user.email", "tester@example.invalid"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "app"]);
    let head = git(&dir, &["rev-parse", "HEAD"]);
    (Dir(dir), head)
}

fn run_mjs(app: Option<&Path>, args: &[&str]) -> Output {
    run_mjs_ending(app, args, None)
}

fn run_mjs_ending(app: Option<&Path>, args: &[&str], ending: Option<&str>) -> Output {
    run_mjs_with(app, args, ending, &[])
}

fn run_mjs_with(
    app: Option<&Path>,
    args: &[&str],
    ending: Option<&str>,
    env: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new("node");
    cmd.arg(root().join("tools/app-check/run.mjs"))
        .args(args)
        .current_dir(root())
        .env_remove("MOUSSE_NET_ENGINE_CONTROL")
        .env_remove("MOUSSE_APP_DIR")
        .env_remove("MOUSSE_RELAY_TEST_LINKS")
        .env_remove("MOUSSE_NET_TEST_EGRESS")
        .env_remove("FAKE_CONN_UP")
        // Its own target folder: the workspace one holds the helper the
        // helper's tests built with every feature, and a default build there
        // would replace it under them.
        .env(
            "CARGO_TARGET_DIR",
            Path::new(env!("CARGO_TARGET_TMPDIR")).join("app-check-build"),
        );
    if let Some(a) = app {
        cmd.env("MOUSSE_APP_DIR", a);
    }
    match ending {
        Some(e) => cmd.env("FAKE_ENDING", e),
        None => cmd.env_remove("FAKE_ENDING"),
    };
    cmd.envs(env.iter().copied());
    cmd.output().expect("node runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn value(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key}= line in:\n{out}"))
        .to_string()
}

fn sign_args() -> SignArgs<'static> {
    SignArgs {
        check: None,
        target: None,
        control: None,
        platform: Some("test"),
        default_build: None,
        config: None,
        device: "pc",
    }
}

#[test]
fn a_caller_run_builds_the_helper_runs_the_app_check_and_keeps_every_build() {
    let (app, head) = fake_app("caller");
    let out_dir = app.0.with_extension("out");
    let result = app.0.with_extension("result.json");
    let o = run_mjs(
        Some(&app.0),
        &[
            "phase1a.pair-offline",
            "--out",
            out_dir.to_str().unwrap(),
            "--role",
            "caller",
            "--topology",
            "four-endpoints",
            "--target",
            "pc-to-mac-lan",
            "--result",
            result.to_str().unwrap(),
        ],
    );
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    // The helper was built from this checkout and handed to the app.
    let build = value(&out, "helper_build");
    let (commit, profile) = build.split_once('+').unwrap();
    assert_eq!(profile, "debug", "{out}");
    let commit = commit.trim_end_matches("-dirty");
    assert_eq!(
        commit,
        git(
            &root(),
            &["log", "-1", "--format=%H", "--", ".", ":(exclude)checks"]
        )
    );
    assert_eq!(value(&out, "seen_helper"), "exists", "{out}");
    assert_eq!(value(&out, "seen_helper_starts"), "yes", "{out}");
    assert_eq!(value(&out, "seen_helper_build"), build);
    assert_eq!(value(&out, "seen_role"), "caller");
    assert_eq!(value(&out, "seen_topology"), "four-endpoints");
    assert!(out_dir.join("ran").exists());
    // The app's lines pass through.
    assert_eq!(value(&out, "app_build"), head);
    // The app's verdict line is shown as the app's; the run's verdict comes
    // last.
    assert!(out
        .lines()
        .any(|l| l.trim() == "app: PASS phase1a.pair-offline"));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .last()
            .map(str::trim),
        Some("PASS phase1a.pair-offline"),
        "{out}"
    );
    // Phase 1a checks run as they were signed: no stand-ins.
    assert_eq!(value(&out, "seen_plus"), "unset", "{out}");

    // The result names both machines' helper and app builds, and signing
    // keeps them where the kit reads them.
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&result).unwrap()).unwrap();
    assert_eq!(v["outcome"], "PASS");
    assert_eq!(v["target"], "pc-to-mac-lan");
    assert_eq!(v["build"], serde_json::Value::String(build.clone()));
    let p = payload_from(&v, &sign_args()).unwrap();
    assert_eq!(p.check, "phase1a.pair-offline");
    assert_eq!(p.build, build);
    assert_eq!(p.extra_str("app_build"), Some(head.as_str()));
    assert_eq!(p.extra_str("host_app_build"), Some(head.as_str()));
    assert_eq!(p.extra_str("host_build"), Some(build.as_str()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let _ = std::fs::remove_file(&result);
}

#[test]
fn a_device_control_run_takes_the_controls_environment_from_the_manifest() {
    let (app, head) = fake_app("control");
    let result = app.0.with_extension("result.json");
    let o = run_mjs(
        Some(&app.0),
        &[
            "phase1a.private-streams",
            "--control",
            "second-reader",
            "--target",
            "linux-x64",
            "--result",
            result.to_str().unwrap(),
        ],
    );
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&result).unwrap()).unwrap();
    let p = payload_from(&v, &sign_args()).unwrap();
    assert_eq!(p.outcome, "FAIL");
    assert_eq!(p.control.as_deref(), Some("second-reader"));
    // The fake app fails with the control it was given as the reason.
    assert_eq!(p.reason().as_deref(), Some("second-reader"));
    assert_eq!(p.extra_str("app_build"), Some(head.as_str()));
    let _ = std::fs::remove_file(&result);
}

#[test]
fn without_an_app_checkout_nothing_runs() {
    let o = run_mjs(None, &["phase1a.private-streams"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}");
    assert!(out.contains("MOUSSE_APP_DIR"), "{out}");
    assert!(!out.contains("helper_build="), "{out}");
}

/// A device result is judged as the kit judges a local run: a control counts
/// as failing only with a nonzero exit, its FAIL line and no PASS line, and a
/// normal run passes only with exit 0, its PASS line and no FAIL line.
#[test]
fn a_device_result_is_judged_like_a_local_run() {
    let (app, _head) = fake_app("judge");
    // (ending, control?, outcome the signed result must carry)
    let rows: [(Option<&str>, bool, &str); 7] = [
        (None, true, "FAIL"),
        (Some("fail-exit-0"), true, "DID_NOT_FAIL"),
        (Some("both-exit-1"), true, "DID_NOT_FAIL"),
        (Some("pass-exit-1"), true, "DID_NOT_FAIL"),
        (None, false, "PASS"),
        (Some("pass-exit-1"), false, "FAIL"),
        (Some("both-exit-1"), false, "FAIL"),
    ];
    for (i, (ending, control, want)) in rows.iter().enumerate() {
        let result = app.0.with_extension(format!("judge-{i}.json"));
        let mut args = vec!["phase1a.private-streams", "--target", "linux-x64"];
        if *control {
            args.extend(["--control", "second-reader"]);
        }
        let r = result.to_str().unwrap().to_string();
        args.extend(["--result", r.as_str()]);
        let o = run_mjs_ending(Some(&app.0), &args, *ending);
        let out = text(&o);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&result).unwrap_or_else(|_| {
                panic!(
                    "no result for {ending:?}:
{out}"
                )
            }))
            .unwrap();
        let p = payload_from(&v, &sign_args()).unwrap();
        assert_eq!(
            p.outcome, *want,
            "ending {ending:?}, control {control}:
{out}"
        );
        let _ = std::fs::remove_file(&result);
    }
}

/// A Phase 1b route case: the app gets the kit's Plus recorder, the egress
/// guard and the probe, and the run passes only when every connection used
/// the route.
#[test]
fn a_route_case_runs_with_the_stand_ins_and_passes_on_its_own_route() {
    let (app, _head) = fake_app("route");
    let out_dir = app.0.with_extension("route-out");
    let o = run_mjs(
        Some(&app.0),
        &[
            "phase1b.routes-app",
            "--route",
            "tcp",
            "--out",
            out_dir.to_str().unwrap(),
        ],
    );
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert_eq!(value(&out, "seen_route"), "tcp", "{out}");
    assert_eq!(value(&out, "seen_plus"), "set", "{out}");
    assert_eq!(value(&out, "seen_probe"), "exists", "{out}");
    assert!(out.contains("fence="), "{out}");
    assert!(
        out.lines().any(|l| l.trim() == "PASS phase1b.routes-app"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Each kit control stands for an app that breaks a rule and still prints
/// PASS: the run fails, with the kit's reason.
#[test]
fn the_kits_controls_fail_with_the_kits_reasons() {
    let (app, _head) = fake_app("kitctl");
    for (control, reason) in [
        ("plus-probe", "plus_contacted"),
        ("egress-probe", "egress_attempted"),
        ("route-leak", "route_mismatch"),
    ] {
        let result = app.0.with_extension(format!("{control}.json"));
        let o = run_mjs(
            Some(&app.0),
            &[
                "phase1b.routes-app",
                "--route",
                "ws",
                "--control",
                control,
                "--target",
                "windows-x64",
                "--result",
                result.to_str().unwrap(),
            ],
        );
        let out = text(&o);
        assert_eq!(o.status.code(), Some(1), "{control}: {out}");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&result).unwrap()).unwrap();
        assert_eq!(v["outcome"], "FAIL", "{control}: {out}");
        assert_eq!(v["reason"], reason, "{control}: {out}");
        assert_eq!(v["case"], "ws", "{control}: {out}");
        let _ = std::fs::remove_file(&result);
    }
}

/// Enrollment links of a relay on another machine (TEST-NET-1; nothing
/// dials it) and of a second relay on loopback.
const REMOTE_RELAY: &str = "mousse-relay://192.0.2.10:7443/#BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc.CQkJCQkJCQkJCQkJCQkJCQ";
const LOOPBACK_RELAY: &str = "mousse-relay://127.0.0.1:7444/#CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg.CQkJCQkJCQkJCQkJCQkJCQ";

/// A relay route case: the app gets the links, the remote relay's address
/// (only that one) is let through the egress guards, and the run passes
/// when every connection went through that relay.
#[test]
fn a_relay_route_case_lets_only_the_remote_relay_through_and_passes_on_relay_connections() {
    let (app, _head) = fake_app("relay");
    let links = format!("{REMOTE_RELAY} {LOOPBACK_RELAY}");
    let o = run_mjs_with(
        Some(&app.0),
        &["phase1b.routes-app", "--route", "relay"],
        None,
        &[("MOUSSE_RELAY_TEST_LINKS", &links)],
    );
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert_eq!(value(&out, "seen_route"), "relay", "{out}");
    assert_eq!(value(&out, "seen_egress"), "192.0.2.10", "{out}");
    assert!(
        out.lines().any(|l| l.trim() == "PASS phase1b.routes-app"),
        "{out}"
    );
}

/// A relay route run in which the app used another route, or another
/// relay, fails with `route_mismatch`, even though the app said PASS.
#[test]
fn a_relay_route_run_that_used_another_route_fails() {
    let (app, _head) = fake_app("relayleak");
    let up = |route: &str| format!("{{\"ev\":\"conn.up\",\"route\":{route}}}\n");
    let relay = up(r#"{"kind":"relay","destination":"relay://192.0.2.10:7443"}"#);
    for (what, conn_up) in [
        (
            "a direct tcp connection beside the relay one",
            format!("{relay}{}", up(r#"{"kind":"tcp","class":"lan"}"#)),
        ),
        ("a tcp hint", up(r#""tcp://192.0.2.10:7000""#)),
        (
            "another relay",
            up(r#"{"kind":"relay","destination":"relay://192.0.2.99:7443"}"#),
        ),
    ] {
        let result = app.0.with_extension("relayleak.json");
        let o = run_mjs_with(
            Some(&app.0),
            &[
                "phase1b.routes-app",
                "--route",
                "relay",
                "--result",
                result.to_str().unwrap(),
            ],
            None,
            &[
                ("MOUSSE_RELAY_TEST_LINKS", REMOTE_RELAY),
                ("FAKE_CONN_UP", &conn_up),
            ],
        );
        let out = text(&o);
        assert_eq!(o.status.code(), Some(1), "{what}: {out}");
        assert!(
            out.lines().any(|l| l
                .trim()
                .starts_with("FAIL phase1b.routes-app reason=route_mismatch")),
            "{what}: {out}"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&result).unwrap()).unwrap();
        assert_eq!(v["outcome"], "FAIL", "{what}: {out}");
        assert_eq!(v["reason"], "route_mismatch", "{what}: {out}");
        assert_eq!(v["case"], "relay", "{what}: {out}");
        let _ = std::fs::remove_file(&result);
    }
}

/// Without links, or with a link naming a host the guards cannot allow,
/// a relay route runs nothing.
#[test]
fn a_relay_route_without_usable_links_runs_nothing() {
    let (app, _head) = fake_app("relaynone");
    let named = REMOTE_RELAY.replace("192.0.2.10", "relay.example");
    for links in ["", named.as_str()] {
        let o = run_mjs_with(
            Some(&app.0),
            &["phase1b.routes-app", "--route", "relay"],
            None,
            &[("MOUSSE_RELAY_TEST_LINKS", links)],
        );
        let out = text(&o);
        assert_eq!(o.status.code(), Some(2), "{links:?}: {out}");
        assert!(out.contains("MOUSSE_RELAY_TEST_LINKS"), "{links:?}: {out}");
        assert!(!out.contains("seen_route="), "the app ran: {out}");
    }
}
