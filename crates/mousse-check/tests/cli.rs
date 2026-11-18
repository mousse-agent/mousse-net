//! End-to-end: the real binary in a throwaway git repository, with a probe
//! script standing in for the code under test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mousse-check");

struct Repo {
    dir: PathBuf,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn host() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The probe prints `PASS <id>`, or `FAIL <id>` and exits 1 when
/// `PROBE_MODE=break`. `PROBE_MODE=ignored` is a control the code under test
/// does not read.
fn probe_command(id: &str) -> String {
    if cfg!(windows) {
        // Absolute path: cmd may be set not to search the current folder.
        format!("[\"cmd\", \"/C\", '{{root}}\\probe.cmd', \"{id}\"]")
    } else {
        format!("[\"sh\", \"probe.sh\", \"{id}\"]")
    }
}

fn manifest(with_weak_check: bool) -> String {
    let h = host();
    let mut text = format!(
        r#"phase = "phase9"
title = "cli test"

[[check]]
id = "phase9.ok"
title = "a check with a working control"
plan = "test"
targets = ["here"]
judge = "marker"
[[check.local]]
target = "here"
host = "{h}"
command = {cmd}
[[check.control]]
name = "break"
breaks = "everything"
env = {{ PROBE_MODE = "break" }}

[[check]]
id = "phase9.device"
title = "a device check"
plan = "test"
targets = ["phone"]
[[check.control]]
name = "break"
breaks = "everything"
env = {{ PROBE_MODE = "break" }}
"#,
        cmd = probe_command("phase9.ok")
    );
    if with_weak_check {
        text.push_str(&format!(
            r#"
[[check]]
id = "phase9.weak"
title = "a check whose control changes nothing"
plan = "test"
targets = ["here"]
judge = "marker"
[[check.local]]
target = "here"
host = "{h}"
command = {cmd}
[[check.control]]
name = "ignored"
breaks = "nothing the code reads"
env = {{ PROBE_MODE = "ignored" }}
"#,
            cmd = probe_command("phase9.weak")
        ));
    }
    text
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git runs")
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn repo(name: &str, with_weak_check: bool) -> Repo {
    let dir = std::env::temp_dir().join(format!("mousse-check-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("checks")).unwrap();
    std::fs::write(
        dir.join("probe.cmd"),
        "@echo off\r\nif \"%PROBE_MODE%\"==\"break\" (echo FAIL %1& exit /b 1)\r\necho PASS %1\r\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("probe.sh"),
        "if [ \"$PROBE_MODE\" = break ]; then echo \"FAIL $1\"; exit 1; fi\necho \"PASS $1\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("checks/phase9.toml"), manifest(with_weak_check)).unwrap();
    std::fs::write(dir.join("checks/.gitignore"), "/runs/\n*.key\n").unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.name", "Tester"]);
    git(&dir, &["config", "user.email", "tester@example.invalid"]);
    git(&dir, &["config", "core.autocrlf", "false"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "start"]);
    Repo { dir }
}

fn run(dir: &Path, args: &[&str]) -> Output {
    run_with(dir, args, None)
}

/// `run` with `MOUSSE_APP_DIR` set to `app_dir`, or unset.
fn run_with(dir: &Path, args: &[&str], app_dir: Option<&Path>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(dir)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("MOUSSE_APP_DIR");
    if let Some(a) = app_dir {
        cmd.env("MOUSSE_APP_DIR", a);
    }
    cmd.output().expect("mousse-check runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn row<'a>(out: &'a str, check: &str) -> &'a str {
    out.lines()
        .find(|l| l.starts_with(check))
        .unwrap_or_else(|| panic!("no row for {check} in:\n{out}"))
}

#[test]
fn a_control_that_changes_nothing_fails_the_check_and_the_phase() {
    let r = repo("weak", true);
    let o = run(&r.dir, &["phase9"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(row(&out, "phase9.ok").contains("PASS"), "{out}");
    let weak = row(&out, "phase9.weak");
    assert!(
        weak.contains("FAIL") && weak.contains("control did not fail"),
        "{out}"
    );
}

#[test]
fn signed_device_results_complete_the_phase_and_tampering_breaks_it() {
    let r = repo("device", false);
    let d = &r.dir;

    // Without the device result the phase is incomplete.
    let o = run(d, &["phase9"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(row(&out, "phase9.device").contains("INCOMPLETE"), "{out}");

    trust_phone(d);

    // Before running, the phone records the configuration it runs under.
    let normal_digest = digest(d, &["phase9.device"]);
    let control_digest = digest(d, &["phase9.device", "--control", "break"]);
    assert_ne!(normal_digest, control_digest);

    // The phone's normal run and control run. The build comes from git.
    // Outside the checkout, so they do not make the tree dirty.
    let normal = d.with_extension("normal.json");
    let control = d.with_extension("control.json");
    std::fs::write(&normal, phone_result("PASS", Some(&normal_digest))).unwrap();
    std::fs::write(&control, phone_result("FAIL", None)).unwrap();

    // A result without a recorded digest is not signed.
    let o = sign(d, &["--control", "break", control.to_str().unwrap()]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("config-digest"), "{}", text(&o));

    // The normal result carries its digest; the control's comes with --config.
    let o = sign(d, &[normal.to_str().unwrap()]);
    assert!(o.status.success(), "{}", text(&o));
    let o = sign(
        d,
        &[
            "--control",
            "break",
            "--config",
            &control_digest,
            control.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    std::fs::remove_file(&normal).unwrap();
    std::fs::remove_file(&control).unwrap();

    // Result files are evidence: they do not make the tree dirty.
    let o = run(d, &["phase9"]);
    let out = text(&o);
    assert!(row(&out, "phase9.device").contains("PASS"), "{out}");
    assert_eq!(o.status.code(), Some(0), "{out}");

    // An attestation-only phase would not pass; `report` reads stored runs.
    let o = run(d, &["report", "phase9", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).expect("json report");
    assert_eq!(json["verdict"]["passed"], serde_json::Value::Bool(true));

    // A dirty tree does not pass without --allow-dirty.
    std::fs::write(d.join("new_source.rs"), "// uncommitted\n").unwrap();
    let o = run(d, &["report", "phase9"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(out.contains("DIRTY"), "{out}");
    let o = run(d, &["report", "phase9", "--allow-dirty"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    std::fs::remove_file(d.join("new_source.rs")).unwrap();

    // Change PASS to FAIL inside a signed file: rejected as tampering.
    let dir = d.join("checks/results/phone");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let t = std::fs::read_to_string(&path).unwrap();
        if t.contains("\\\"outcome\\\":\\\"FAIL\\\"") {
            std::fs::write(
                &path,
                t.replace(
                    "\\\"outcome\\\":\\\"FAIL\\\"",
                    "\\\"outcome\\\":\\\"PASS\\\"",
                ),
            )
            .unwrap();
        }
    }
    let o = run(d, &["report", "phase9"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(out.contains("[TAMPERED]"), "{out}");
}

/// A device key, trusted for the phone cell, committed.
fn trust_phone(d: &Path) {
    let o = run(d, &["device", "keygen", "--out", "phone.key"]);
    assert!(o.status.success(), "{}", text(&o));
    let public = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let o = run(
        d,
        &[
            "device",
            "add",
            "--name",
            "phone",
            "--key",
            &public,
            "--targets",
            "phone",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    git(d, &["add", "-A"]);
    git(d, &["commit", "-q", "-m", "trust the phone"]);
}

/// `mousse-check config-digest <args>`.
fn digest(d: &Path, args: &[&str]) -> String {
    let mut all = vec!["config-digest"];
    all.extend_from_slice(args);
    let o = run(d, &all);
    assert!(o.status.success(), "{}", text(&o));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A phone result file, with the digest it recorded if any.
fn phone_result(outcome: &str, config: Option<&str>) -> String {
    let config = config
        .map(|c| format!(", \"config\": \"{c}\""))
        .unwrap_or_default();
    format!(
        "{{\"check\": \"phase9.device\", \"target\": \"phone\", \"outcome\": \"{outcome}\", \"details\": \"probe\"{config}}}"
    )
}

/// `mousse-check sign` with the phone's key.
fn sign(d: &Path, args: &[&str]) -> Output {
    let mut all = vec!["sign", "--device-key", "phone.key", "--profile", "release"];
    all.extend_from_slice(args);
    run(d, &all)
}

#[test]
fn a_result_produced_under_an_old_configuration_stays_incomplete() {
    let r = repo("old-config", false);
    let d = &r.dir;
    trust_phone(d);
    let normal_digest = digest(d, &["phase9.device"]);
    let control_digest = digest(d, &["phase9.device", "--control", "break"]);

    // The control changes after the phone recorded its digests...
    let path = d.join("checks/phase9.toml");
    let m = std::fs::read_to_string(&path).unwrap();
    let changed = m.replacen(
        "targets = [\"phone\"]\n[[check.control]]\nname = \"break\"\nbreaks = \"everything\"\nenv = { PROBE_MODE = \"break\" }",
        "targets = [\"phone\"]\n[[check.control]]\nname = \"break\"\nbreaks = \"everything\"\nenv = { PROBE_MODE = \"break2\" }",
        1,
    );
    assert_ne!(m, changed);
    std::fs::write(&path, changed).unwrap();
    git(d, &["commit", "-q", "-am", "change the control"]);

    // ...so signing its results now does not make them count.
    let normal = d.with_extension("normal.json");
    let control = d.with_extension("control.json");
    std::fs::write(&normal, phone_result("PASS", Some(&normal_digest))).unwrap();
    std::fs::write(&control, phone_result("FAIL", Some(&control_digest))).unwrap();
    for file in [&normal, &control] {
        let control_args: &[&str] = if file == &control {
            &["--control", "break"]
        } else {
            &[]
        };
        let mut args = control_args.to_vec();
        args.push(file.to_str().unwrap());
        let o = sign(d, &args);
        assert!(o.status.success(), "{}", text(&o));
        if file == &control {
            assert!(text(&o).contains("another configuration"), "{}", text(&o));
        }
        std::fs::remove_file(file).unwrap();
    }
    let o = run(d, &["report", "phase9", "--full"]);
    let out = text(&o);
    let device = row(&out, "phase9.device");
    assert!(
        device.contains("INCOMPLETE") && device.contains("configuration"),
        "{out}"
    );
}

#[test]
fn hand_made_run_records_and_old_configurations_do_not_count() {
    let r = repo("records", false);
    let d = &r.dir;
    let o = run(d, &["phase9"]);
    let out = text(&o);
    assert!(row(&out, "phase9.ok").contains("PASS"), "{out}");

    // Copy this machine's records into records for the device-only cell.
    let runs = d.join("checks/runs");
    for part in ["normal", "break"] {
        let t =
            std::fs::read_to_string(runs.join(format!("phase9.ok__here__{part}.json"))).unwrap();
        let forged = t
            .replace("\"phase9.ok\"", "\"phase9.device\"")
            .replace("\"here\"", "\"phone\"");
        std::fs::write(
            runs.join(format!("phase9.device__phone__{part}.json")),
            forged,
        )
        .unwrap();
    }
    let o = run(d, &["report", "phase9"]);
    let out = text(&o);
    assert!(row(&out, "phase9.device").contains("INCOMPLETE"), "{out}");

    // A committed change to the check's configuration: the old runs no
    // longer count until the check runs again.
    let path = d.join("checks/phase9.toml");
    let m = std::fs::read_to_string(&path).unwrap().replacen(
        "judge = \"marker\"\n",
        "judge = \"marker\"\ntimeout_secs = 600\nmin_tests = 2\n",
        1,
    );
    std::fs::write(&path, m).unwrap();
    git(d, &["commit", "-q", "-am", "change the check"]);
    let o = run(d, &["report", "phase9", "--full"]);
    let out = text(&o);
    let ok = row(&out, "phase9.ok");
    assert!(
        ok.contains("INCOMPLETE") && ok.contains("configuration"),
        "{out}"
    );
    let o = run(d, &["phase9", "--only", "phase9.ok"]);
    let out = text(&o);
    assert!(row(&out, "phase9.ok").contains("PASS"), "{out}");
}

#[test]
fn attestations_on_automated_checks_do_not_pass() {
    let r = repo("attest", false);
    let o = run(
        &r.dir,
        &[
            "attest",
            "phase9.device",
            "--note",
            "looked at the phone, it worked",
        ],
    );
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("does not let the phase pass"), "{out}");
    let o = run(&r.dir, &["phase9"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(row(&out, "phase9.device").contains("ATTESTED"), "{out}");
}

// --- App checks ---

/// An app check whose probe prints the app checkout's commit as
/// `app_build=`, the way the app's check script does.
fn app_check(h: &str) -> String {
    let cmd = if cfg!(windows) {
        "[\"cmd\", \"/C\", '{root}\\app_probe.cmd', \"phase9.app\"]".to_string()
    } else {
        "[\"sh\", \"app_probe.sh\", \"phase9.app\"]".to_string()
    };
    format!(
        r#"
[[check]]
id = "phase9.app"
title = "an app check"
plan = "test"
targets = ["here"]
judge = "marker"
app = true
[[check.local]]
target = "here"
host = "{h}"
command = {cmd}
[[check.control]]
name = "break"
breaks = "everything"
env = {{ PROBE_MODE = "break" }}
"#
    )
}

/// A throwaway app checkout with one commit. Returns it and its commit.
fn app_checkout(name: &str) -> (Repo, String) {
    let dir = std::env::temp_dir().join(format!(
        "mousse-check-cli-{}-{name}-app",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("README"), "the app\n").unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.name", "Tester"]);
    git(&dir, &["config", "user.email", "tester@example.invalid"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "app"]);
    let rev = head(&dir);
    (Repo { dir }, rev)
}

fn head(dir: &Path) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn app_checks_run_only_against_a_clean_app_checkout_at_the_pinned_revision() {
    let r = repo("app", false);
    let d = &r.dir;
    let (app, rev) = app_checkout("app");
    let manifest =
        std::fs::read_to_string(d.join("checks/phase9.toml")).unwrap() + &app_check(&host());
    std::fs::write(d.join("checks/phase9.toml"), manifest).unwrap();
    std::fs::write(
        d.join("app_probe.cmd"),
        "@echo off\r\nfor /f %%i in ('git -C \"%MOUSSE_APP_DIR%\" rev-parse HEAD') do echo app_build=%%i\r\nif \"%PROBE_MODE%\"==\"break\" (echo FAIL %1& exit /b 1)\r\necho PASS %1\r\n",
    )
    .unwrap();
    std::fs::write(
        d.join("app_probe.sh"),
        "echo \"app_build=$(git -C \"$MOUSSE_APP_DIR\" rev-parse HEAD)\"\nif [ \"$PROBE_MODE\" = break ]; then echo \"FAIL $1\"; exit 1; fi\necho \"PASS $1\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(d.join("app")).unwrap();
    std::fs::write(d.join("app/MOUSSE_REVISION"), format!("{rev}\n")).unwrap();
    git(d, &["add", "-A"]);
    git(d, &["commit", "-q", "-m", "an app check"]);
    let record = d.join("checks/runs/phase9.app__here__normal.json");
    let only = ["phase9", "--only", "phase9.app"];

    // No app checkout named: not run.
    let o = run_with(d, &only, None);
    let out = text(&o);
    assert!(out.contains("MOUSSE_APP_DIR"), "{out}");
    assert!(row(&out, "phase9.app").contains("INCOMPLETE"), "{out}");
    assert!(!record.exists());

    // A dirty app checkout: not run.
    std::fs::write(app.dir.join("scratch.txt"), "local change\n").unwrap();
    let o = run_with(d, &only, Some(&app.dir));
    let out = text(&o);
    assert!(out.contains("uncommitted"), "{out}");
    assert!(!record.exists(), "{out}");
    std::fs::remove_file(app.dir.join("scratch.txt")).unwrap();

    // An app checkout at another revision: not run.
    std::fs::write(app.dir.join("README"), "the app, later\n").unwrap();
    git(&app.dir, &["commit", "-q", "-am", "later"]);
    let o = run_with(d, &only, Some(&app.dir));
    let out = text(&o);
    assert!(out.contains("pins"), "{out}");
    assert!(!record.exists(), "{out}");

    // Clean, at the pinned revision: runs, records the app build, passes.
    git(&app.dir, &["checkout", "-q", &rev]);
    let o = run_with(d, &only, Some(&app.dir));
    let out = text(&o);
    assert!(row(&out, "phase9.app").contains("PASS"), "{out}");
    let rec: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(rec["app_build"], serde_json::Value::String(rev.clone()));

    // Results signed from a run keep the app build where the kit reads it.
    let o = run(d, &["device", "keygen", "--out", "pc.key"]);
    assert!(o.status.success(), "{}", text(&o));
    let signed = d.with_extension("signed");
    let o = run_with(
        d,
        &[
            "run",
            "phase9.app",
            "--sign-with",
            "pc.key",
            "--device",
            "pc",
            "--out",
            signed.to_str().unwrap(),
        ],
        Some(&app.dir),
    );
    assert!(o.status.success(), "{}", text(&o));
    let file = std::fs::read_dir(&signed)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let payload: serde_json::Value = serde_json::from_str(s["payload"].as_str().unwrap()).unwrap();
    assert_eq!(
        payload["extra"]["app_build"],
        serde_json::Value::String(rev)
    );
    let _ = std::fs::remove_dir_all(&signed);

    // A control's environment, for runs made outside the kit.
    let o = run(d, &["control-env", "phase9.app", "--control", "break"]);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "{\"PROBE_MODE\":\"break\"}"
    );
}

#[test]
fn a_signed_app_result_counts_only_with_the_pinned_app_build() {
    let r = repo("app-device", false);
    let d = &r.dir;
    let rev = "8789ae66461fc994b4e19164d2ac8a721ee1a748";
    let path = d.join("checks/phase9.toml");
    let m = std::fs::read_to_string(&path).unwrap().replacen(
        "targets = [\"phone\"]\n",
        "targets = [\"phone\"]\napp = true\n",
        1,
    );
    std::fs::write(&path, m).unwrap();
    std::fs::create_dir_all(d.join("app")).unwrap();
    std::fs::write(d.join("app/MOUSSE_REVISION"), format!("{rev}\n")).unwrap();
    git(d, &["add", "-A"]);
    git(d, &["commit", "-q", "-m", "the device check runs the app"]);
    trust_phone(d);
    // The phone's normal and control results, naming `app_build`. Returns
    // what `sign` printed.
    let sign_both = |app_build: &str| -> String {
        let mut said = String::new();
        for (control, outcome) in [(None, "PASS"), (Some("break"), "FAIL")] {
            let mut args = vec!["phase9.device"];
            if let Some(c) = control {
                args.extend(["--control", c]);
            }
            let file = d.with_extension(format!("{outcome}.json"));
            let v = serde_json::json!({
                "check": "phase9.device", "target": "phone", "outcome": outcome,
                "details": "probe", "config": digest(d, &args), "app_build": app_build,
                "control": control,
            });
            std::fs::write(&file, v.to_string()).unwrap();
            let o = sign(d, &[file.to_str().unwrap()]);
            assert!(o.status.success(), "{}", text(&o));
            std::fs::remove_file(&file).unwrap();
            said.push_str(&text(&o));
        }
        said
    };
    // Another app build: signed with a note, and it does not count.
    let said = sign_both(&"1".repeat(40));
    assert!(said.contains("will not count"), "{said}");
    let o = run(d, &["report", "phase9", "--full"]);
    let out = text(&o);
    assert!(row(&out, "phase9.device").contains("INCOMPLETE"), "{out}");
    // The pinned app build: PASS.
    let said = sign_both(rev);
    assert!(!said.contains("will not count"), "{said}");
    let o = run(d, &["report", "phase9", "--full"]);
    let out = text(&o);
    assert!(row(&out, "phase9.device").contains("PASS"), "{out}");
}
