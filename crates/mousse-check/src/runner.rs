//! Running a check's command and judging its output.
//!
//! Judges are strict about what counts as a run. A control "fails as
//! required" only if it exits non-zero **and** prints the check's FAIL line
//! (or, for `cargo test`, a `test result: FAILED` line with at least one
//! failed test). A build error, a missing cargo feature or a missing binary
//! exits non-zero without that line, so it counts as "did not print FAIL",
//! never as a working control.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::manifest::{Check, Control, Judge, LocalRun};

/// What a process did.
#[derive(Clone, Debug, Default)]
pub struct RunOutput {
    /// Exit code; `None` if it could not start, was killed or timed out.
    pub exit: Option<i32>,
    pub timed_out: bool,
    pub spawn_error: Option<String>,
    /// stdout then stderr.
    pub text: String,
}

/// The judged outcome of one run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunVerdict {
    /// Normal run passed.
    Pass,
    /// Normal run failed (including: could not run, or no PASS line).
    Fail,
    /// Control run printed FAIL and exited non-zero: the control works.
    FailedAsRequired,
    /// Control run passed: the control does not break anything the check sees.
    DidNotFail,
    /// Control run neither passed nor printed FAIL (build error, crash,
    /// timeout): it proves nothing.
    NoFailLine,
    /// Control run printed FAIL, but not with the reason the control must
    /// fail with: something else broke, so it proves nothing about the
    /// defect it names.
    WrongReason,
}

/// Judged result with a one-line summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judged {
    pub verdict: RunVerdict,
    pub summary: String,
    /// For `cargo test`: passed + failed + ignored across all binaries.
    pub tests_total: Option<u64>,
}

/// Sums of every `test result:` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestCounts {
    pub lines: u64,
    pub failed_lines: u64,
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
}

impl TestCounts {
    pub fn total(&self) -> u64 {
        self.passed + self.failed + self.ignored
    }
}

/// Parse `test result: ok. 12 passed; 0 failed; 1 ignored; ...` lines.
pub fn parse_test_counts(text: &str) -> TestCounts {
    let mut c = TestCounts::default();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("test result: ") else {
            continue;
        };
        let (status, counts) = rest.split_once(". ").unwrap_or((rest, ""));
        let num = |name: &str| -> u64 {
            counts
                .split(';')
                .filter_map(|part| {
                    let mut words = part.split_whitespace();
                    let n = words.next()?.parse::<u64>().ok()?;
                    (words.next()? == name).then_some(n)
                })
                .next()
                .unwrap_or(0)
        };
        c.lines += 1;
        if status == "FAILED" {
            c.failed_lines += 1;
        }
        c.passed += num("passed");
        c.failed += num("failed");
        c.ignored += num("ignored");
    }
    c
}

/// True if some line is `marker`, or starts with `marker` and a space.
pub fn has_marker(text: &str, marker: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l == marker || l.strip_prefix(marker).is_some_and(|r| r.starts_with(' '))
    })
}

fn not_run_reason(out: &RunOutput) -> Option<String> {
    if let Some(e) = &out.spawn_error {
        return Some(format!("could not start: {e}"));
    }
    if out.timed_out {
        return Some("timed out".into());
    }
    None
}

/// Judge a normal run.
pub fn judge_normal(judge: Judge, check: &Check, out: &RunOutput) -> Judged {
    let fail = |summary: String, total: Option<u64>| Judged {
        verdict: RunVerdict::Fail,
        summary,
        tests_total: total,
    };
    if let Some(why) = not_run_reason(out) {
        return fail(why, None);
    }
    let exit = out.exit.unwrap_or(-1);
    match judge {
        Judge::CargoTest => {
            let c = parse_test_counts(&out.text);
            let total = Some(c.total());
            if c.lines == 0 {
                return fail(
                    format!("no `test result` line (exit {exit}); tests did not run"),
                    None,
                );
            }
            if c.failed == 0 && exit != 0 {
                return fail(
                    format!(
                        "exit {exit} with no failed test (a test binary did not build or crashed?)"
                    ),
                    total,
                );
            }
            if c.failed_lines > 0 || c.failed > 0 {
                return fail(
                    format!("{} of {} tests failed (exit {exit})", c.failed, c.total()),
                    total,
                );
            }
            if c.passed < check.min_tests {
                return fail(
                    format!(
                        "only {} tests passed, the check needs at least {}",
                        c.passed, check.min_tests
                    ),
                    total,
                );
            }
            Judged {
                verdict: RunVerdict::Pass,
                summary: format!("{} tests passed", c.passed),
                tests_total: total,
            }
        }
        Judge::Marker | Judge::Matrix => {
            let pass = has_marker(&out.text, &check.pass_marker());
            let failed = has_marker(&out.text, &check.fail_marker());
            if failed {
                return fail(
                    format!("printed {:?} (exit {exit})", check.fail_marker()),
                    None,
                );
            }
            if exit != 0 {
                return fail(format!("exit {exit}"), None);
            }
            if !pass {
                return fail(
                    format!("exit 0 but no {:?} line", check.pass_marker()),
                    None,
                );
            }
            Judged {
                verdict: RunVerdict::Pass,
                summary: format!("printed {:?}", check.pass_marker()),
                tests_total: None,
            }
        }
    }
}

/// The `reason=<word>` on the check's FAIL line, if any.
pub fn fail_reason(check: &Check, text: &str) -> Option<String> {
    let marker = check.fail_marker();
    text.lines()
        .map(str::trim)
        .filter(|l| has_marker(l, &marker))
        .find_map(|l| reason_word(&l[marker.len()..]))
}

/// The word after `reason=` in `text`, if any.
pub fn reason_word(text: &str) -> Option<String> {
    let at = text.find("reason=")?;
    let word: String = text[at + "reason=".len()..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ';' | ',' | ')' | '"'))
        .collect();
    (!word.is_empty()).then_some(word)
}

/// Judge a control run. With `expect_reason`, a FAIL line must also carry
/// `reason=<expect_reason>`.
pub fn judge_control(
    judge: Judge,
    check: &Check,
    expect_reason: Option<&str>,
    out: &RunOutput,
) -> Judged {
    let judged = judge_control_line(judge, check, out);
    let Some(want) = expect_reason else {
        return judged;
    };
    if judged.verdict != RunVerdict::FailedAsRequired {
        return judged;
    }
    match fail_reason(check, &out.text) {
        Some(got) if got == want => Judged {
            summary: format!("{} (reason={got})", judged.summary),
            ..judged
        },
        got => Judged {
            verdict: RunVerdict::WrongReason,
            summary: format!(
                "failed with reason {}, the control must fail with reason={want}",
                got.as_deref().unwrap_or("(none given)")
            ),
            ..judged
        },
    }
}

fn judge_control_line(judge: Judge, check: &Check, out: &RunOutput) -> Judged {
    let judged = |verdict, summary: String, total| Judged {
        verdict,
        summary,
        tests_total: total,
    };
    if let Some(why) = not_run_reason(out) {
        return judged(RunVerdict::NoFailLine, why, None);
    }
    let exit = out.exit.unwrap_or(-1);
    match judge {
        Judge::CargoTest => {
            let c = parse_test_counts(&out.text);
            let total = (c.lines > 0).then_some(c.total());
            if exit != 0 && c.failed_lines > 0 && c.failed > 0 {
                judged(
                    RunVerdict::FailedAsRequired,
                    format!("{} of {} tests failed", c.failed, c.total()),
                    total,
                )
            } else if exit == 0 && c.lines > 0 {
                judged(
                    RunVerdict::DidNotFail,
                    format!("all {} tests passed with the control on", c.passed),
                    total,
                )
            } else {
                judged(
                    RunVerdict::NoFailLine,
                    format!(
                        "exit {exit} without a failed test run (build error or missing feature?)"
                    ),
                    total,
                )
            }
        }
        Judge::Marker | Judge::Matrix => {
            let failed = has_marker(&out.text, &check.fail_marker());
            let passed = has_marker(&out.text, &check.pass_marker());
            if exit != 0 && failed && !passed {
                judged(
                    RunVerdict::FailedAsRequired,
                    format!("printed {:?}", check.fail_marker()),
                    None,
                )
            } else if passed || exit == 0 {
                judged(
                    RunVerdict::DidNotFail,
                    format!("exit {exit}, did not print {:?}", check.fail_marker()),
                    None,
                )
            } else {
                judged(
                    RunVerdict::NoFailLine,
                    format!("exit {exit} without {:?}", check.fail_marker()),
                    None,
                )
            }
        }
    }
}

/// A crypto matrix result file, as the spike writes it.
#[derive(Clone, Debug, Deserialize)]
pub struct MatrixFile {
    pub check: String,
    pub target: String,
    pub provider: String,
    pub outcome: String,
    #[serde(default)]
    pub kx_group: String,
    #[serde(default)]
    pub suite: String,
    pub build: String,
    #[serde(default)]
    pub details: String,
}

/// Read every matrix result file in `dir`.
pub fn read_matrix_dir(dir: &Path) -> Vec<(PathBuf, Result<MatrixFile, String>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for p in paths {
        let parsed = std::fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<MatrixFile>(&t).map_err(|e| e.to_string()));
        out.push((p, parsed));
    }
    out
}

/// After a normal matrix run passed its marker: every expected pair for
/// `target` must be in `dir` with PASS.
pub fn judge_matrix_files(check: &Check, target: &str, dir: &Path, judged: Judged) -> Judged {
    if judged.verdict != RunVerdict::Pass {
        return judged;
    }
    let Some(spec) = &check.matrix else {
        return judged;
    };
    let files = read_matrix_dir(dir);
    let mut problems = Vec::new();
    let mut passed = 0;
    let expected = spec.cases(target);
    for case in &expected {
        let found: Vec<&MatrixFile> = files
            .iter()
            .filter_map(|(_, f)| f.as_ref().ok())
            .filter(|f| f.target == target && &f.provider == case)
            .collect();
        match found.as_slice() {
            [] => problems.push(format!("{case}: no result file")),
            [f] if f.outcome == "PASS" && f.check == check.id => passed += 1,
            [f] => problems.push(format!("{case}: {} ({})", f.outcome, f.check)),
            _ => problems.push(format!("{case}: several result files")),
        }
    }
    for (p, f) in &files {
        if let Err(e) = f {
            problems.push(format!("{}: {e}", p.display()));
        }
    }
    if problems.is_empty() {
        Judged {
            verdict: RunVerdict::Pass,
            summary: format!("{passed}/{} pairs PASS", expected.len()),
            tests_total: None,
        }
    } else {
        Judged {
            verdict: RunVerdict::Fail,
            summary: format!(
                "{passed}/{} pairs PASS; {}",
                expected.len(),
                problems.join("; ")
            ),
            tests_total: None,
        }
    }
}

/// Values substituted into commands, working directories and env values.
pub struct Vars<'a> {
    pub root: &'a Path,
    pub out: &'a Path,
    pub build: &'a str,
}

fn subst(text: &str, vars: &Vars<'_>) -> String {
    text.replace("{root}", &vars.root.display().to_string())
        .replace("{out}", &vars.out.display().to_string())
        .replace("{build}", vars.build)
}

/// The command line for a normal run or one control.
pub fn command_for(
    local: &LocalRun,
    control: Option<&Control>,
) -> (Vec<String>, BTreeMap<String, String>) {
    let cmd = crate::manifest::effective_command(local, control);
    let mut env = local.env.clone();
    if let Some(k) = control {
        env.extend(k.env.iter().map(|(a, b)| (a.clone(), b.clone())));
    }
    (cmd, env)
}

/// Run a command with a timeout, capturing output into `log`.
pub fn execute(
    cmd: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
    vars: &Vars<'_>,
    timeout: Duration,
    log: &Path,
) -> RunOutput {
    let cmd: Vec<String> = cmd.iter().map(|a| subst(a, vars)).collect();
    let dir = match cwd {
        Some(c) => vars.root.join(subst(c, vars)),
        None => vars.root.to_path_buf(),
    };
    let mut command = Command::new(&cmd[0]);
    command
        .args(&cmd[1..])
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("MOUSSE_BUILD_ID", vars.build);
    for (k, v) in env {
        command.env(k, subst(v, vars));
    }
    let mut out = RunOutput::default();
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            out.spawn_error = Some(format!("{}: {e}", cmd[0]));
            write_log(log, &cmd, env, &out);
            return out;
        }
    };
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = stdout.as_mut() {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = stderr.as_mut() {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                out.exit = status.code();
                break;
            }
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                out.timed_out = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                out.spawn_error = Some(e.to_string());
                break;
            }
        }
    }
    let so = t_out.join().unwrap_or_default();
    let se = t_err.join().unwrap_or_default();
    out.text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&so),
        String::from_utf8_lossy(&se)
    );
    write_log(log, &cmd, env, &out);
    out
}

fn write_log(log: &Path, cmd: &[String], env: &BTreeMap<String, String>, out: &RunOutput) {
    if let Some(dir) = log.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let env_text: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let text = format!(
        "command: {}\nenv: {}\nexit: {:?} timed_out: {} spawn_error: {:?}\n\n{}",
        cmd.join(" "),
        env_text.join(" "),
        out.exit,
        out.timed_out,
        out.spawn_error,
        out.text
    );
    let _ = std::fs::write(log, text);
}

/// A stored local run, so `report` can show results without re-running.
/// Lives in `checks/runs/` (ignored by git; trusted only on this machine).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunRecord {
    pub check: String,
    pub target: String,
    /// `normal` or the control's name.
    pub part: String,
    pub build: String,
    pub time: String,
    pub verdict: RunVerdict,
    pub summary: String,
    #[serde(default)]
    pub tests_total: Option<u64>,
    pub log: String,
    /// `<os>-<arch>` of the machine that ran it.
    #[serde(default)]
    pub host: String,
    /// The `[[check.local]]` entry that ran it (see [`runner_id`]).
    #[serde(default)]
    pub runner: String,
    /// [`crate::manifest::Manifest::config_digest`] at the time of the run.
    #[serde(default)]
    pub config: String,
    /// The `reason=` word on a control's FAIL line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Names one `[[check.local]]` entry: `local:<target>@<host>:<digest>`,
/// the digest covering its command, working directory and env.
pub fn runner_id(local: &LocalRun) -> String {
    use sha2::Digest;
    let text = serde_json::json!({
        "command": local.command,
        "cwd": local.cwd,
        "env": local.env,
    })
    .to_string();
    let digest = crate::util::to_hex(&sha2::Sha256::digest(text.as_bytes()));
    format!("local:{}@{}:{}", local.target, local.host, &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn check(judge: &str) -> Check {
        let text = format!(
            r#"
phase = "phase9"
title = "t"
[[check]]
id = "phase9.x"
title = "x"
plan = "p"
targets = ["t"]
judge = "{judge}"
min_tests = 3
"#
        );
        Manifest::parse(&text).unwrap().checks.remove(0)
    }

    fn out(exit: i32, text: &str) -> RunOutput {
        RunOutput {
            exit: Some(exit),
            text: text.into(),
            ..Default::default()
        }
    }

    #[test]
    fn cargo_test_lines_are_summed() {
        let c = parse_test_counts(
            "test result: ok. 5 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n\
             test result: FAILED. 2 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
        );
        assert_eq!(c.lines, 2);
        assert_eq!(c.failed_lines, 1);
        assert_eq!((c.passed, c.failed, c.ignored), (7, 3, 1));
        assert_eq!(c.total(), 11);
    }

    #[test]
    fn a_build_error_is_not_a_working_control() {
        let c = check("cargo-test");
        let build_error = out(
            101,
            "error: Package `x` does not have the feature `control-y`",
        );
        assert_eq!(
            judge_control(Judge::CargoTest, &c, None, &build_error).verdict,
            RunVerdict::NoFailLine
        );
        let broke = out(101, "test result: FAILED. 4 passed; 2 failed; 0 ignored;");
        assert_eq!(
            judge_control(Judge::CargoTest, &c, None, &broke).verdict,
            RunVerdict::FailedAsRequired
        );
        let unaffected = out(0, "test result: ok. 6 passed; 0 failed; 0 ignored;");
        assert_eq!(
            judge_control(Judge::CargoTest, &c, None, &unaffected).verdict,
            RunVerdict::DidNotFail
        );
    }

    #[test]
    fn normal_cargo_test_needs_enough_tests_and_no_failures() {
        let c = check("cargo-test");
        assert_eq!(
            judge_normal(
                Judge::CargoTest,
                &c,
                &out(0, "test result: ok. 3 passed; 0 failed;")
            )
            .verdict,
            RunVerdict::Pass
        );
        assert_eq!(
            judge_normal(
                Judge::CargoTest,
                &c,
                &out(0, "test result: ok. 2 passed; 0 failed;")
            )
            .verdict,
            RunVerdict::Fail
        );
        assert_eq!(
            judge_normal(Judge::CargoTest, &c, &out(0, "no tests here")).verdict,
            RunVerdict::Fail
        );
    }

    #[test]
    fn markers_must_be_whole_lines_and_controls_must_exit_non_zero() {
        let c = check("marker");
        assert!(has_marker("x\nPASS phase9.x\n", "PASS phase9.x"));
        assert!(has_marker("FAIL phase9.x  (3 pairs)", "FAIL phase9.x"));
        assert!(!has_marker("say PASS phase9.x", "PASS phase9.x"));
        assert!(!has_marker("PASS phase9.xyz", "PASS phase9.x"));
        assert_eq!(
            judge_normal(Judge::Marker, &c, &out(0, "PASS phase9.x")).verdict,
            RunVerdict::Pass
        );
        assert_eq!(
            judge_normal(Judge::Marker, &c, &out(0, "PASS phase9.x\nFAIL phase9.x")).verdict,
            RunVerdict::Fail
        );
        assert_eq!(
            judge_control(Judge::Marker, &c, None, &out(0, "FAIL phase9.x")).verdict,
            RunVerdict::DidNotFail
        );
        assert_eq!(
            judge_control(Judge::Marker, &c, None, &out(1, "panicked")).verdict,
            RunVerdict::NoFailLine
        );
        assert_eq!(
            judge_control(Judge::Marker, &c, None, &out(1, "FAIL phase9.x")).verdict,
            RunVerdict::FailedAsRequired
        );
    }

    #[test]
    fn a_control_that_fails_for_another_reason_does_not_count() {
        let c = check("marker");
        let pin = Some("pin_mismatch");
        let judged = |text: &str| judge_control(Judge::Marker, &c, pin, &out(1, text)).verdict;
        assert_eq!(
            judged("FAIL phase9.x reason=pin_mismatch"),
            RunVerdict::FailedAsRequired
        );
        assert_eq!(
            judged("FAIL phase9.x reason=timeout"),
            RunVerdict::WrongReason
        );
        assert_eq!(judged("FAIL phase9.x"), RunVerdict::WrongReason);
        // A reason on another line is not the FAIL line's reason.
        assert_eq!(
            judged(
                "note reason=pin_mismatch
FAIL phase9.x"
            ),
            RunVerdict::WrongReason
        );
    }
}
