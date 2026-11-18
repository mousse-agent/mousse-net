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
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("mousse-check runs")
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

    // A device key, trusted for the phone cell, committed.
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

    // The phone's normal run and control run, signed. The build comes from git.
    let unsigned = |outcome: &str| {
        format!(
            "{{\"check\": \"phase9.device\", \"target\": \"phone\", \"outcome\": \"{outcome}\", \"details\": \"probe\"}}"
        )
    };
    // Outside the checkout, so they do not make the tree dirty.
    let normal = d.with_extension("normal.json");
    let control = d.with_extension("control.json");
    std::fs::write(&normal, unsigned("PASS")).unwrap();
    std::fs::write(&control, unsigned("FAIL")).unwrap();
    let o = run(
        d,
        &[
            "sign",
            "--device-key",
            "phone.key",
            "--profile",
            "release",
            normal.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    let o = run(
        d,
        &[
            "sign",
            "--device-key",
            "phone.key",
            "--profile",
            "release",
            "--control",
            "break",
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
