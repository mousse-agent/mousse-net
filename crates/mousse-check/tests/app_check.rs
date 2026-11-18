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
    let mut cmd = Command::new("node");
    cmd.arg(root().join("tools/app-check/run.mjs"))
        .args(args)
        .current_dir(root())
        .env_remove("MOUSSE_NET_ENGINE_CONTROL")
        .env_remove("MOUSSE_APP_DIR");
    if let Some(a) = app {
        cmd.env("MOUSSE_APP_DIR", a);
    }
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
    assert!(out.lines().any(|l| l.trim() == "PASS phase1a.pair-offline"));

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
