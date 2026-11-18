//! Tests for the evaluation rules. Each one would fail if the rule it names
//! were removed.

use super::*;
use crate::evidence::ATTEST_FORMAT;

/// This machine in the tests.
const HOST: &str = "windows-x86_64";
/// Stands for "the right value" in records and results; `Case::report`
/// fills it in from the manifest.
const AUTO: &str = "auto";

const HEAD: &str = "1111111111111111111111111111111111111111";
const OLD: &str = "2222222222222222222222222222222222222222";
/// A commit on top of HEAD that only adds evidence: same source commit.
const EVIDENCE_COMMIT: &str = "3333333333333333333333333333333333333333";

struct FakeGit;

impl Commits for FakeGit {
    fn source_commit(&self, rev: &str) -> Option<String> {
        match rev {
            r if HEAD.starts_with(r) || EVIDENCE_COMMIT.starts_with(r) => Some(HEAD.into()),
            r if OLD.starts_with(r) => Some(OLD.into()),
            _ => None,
        }
    }
}

const MANIFEST: &str = r#"
phase = "phase9"
title = "test phase"
profile = "release"

[[check]]
id = "phase9.local"
title = "local command"
plan = "item 1"
targets = ["pc"]
[[check.local]]
target = "pc"
host = "windows-x86_64"
command = ["cargo", "test"]
[[check.control]]
name = "break"
breaks = "the verifier"
args = ["--features", "control-break"]
"#;

const DEVICE_CHECK: &str = r#"
[[check]]
id = "phase9.phone"
title = "device check"
plan = "item 2"
targets = ["ios"]
[[check.control]]
name = "break-path"
breaks = "one byte flipped"
env = { MOUSSE_BREAK = "1" }
"#;

const MATRIX_CHECK: &str = r#"
[[check]]
id = "phase9.matrix"
title = "matrix"
plan = "item 3"
targets = ["mac"]
judge = "matrix"
[check.matrix]
providers = ["a", "b"]
[[check.control]]
name = "break-pin"
breaks = "wrong pin"
env = { MOUSSE_MATRIX_BREAK = "1" }
"#;

const MANUAL_CHECK: &str = r#"
[[check]]
id = "phase9.review"
title = "review"
plan = "item 4"
targets = ["session-cert"]
manual = true
steps = "review the design"
"#;

fn state(dirty: bool) -> BuildState {
    BuildState {
        commit: HEAD.into(),
        dirty,
        dirty_paths: if dirty {
            vec!["src/lib.rs".into()]
        } else {
            vec![]
        },
    }
}

fn release(commit: &str) -> String {
    format!("{commit}+release")
}

fn rec(part: &str, verdict: RunVerdict, total: Option<u64>) -> RunRecord {
    RunRecord {
        check: "phase9.local".into(),
        target: "pc".into(),
        part: part.into(),
        build: release(HEAD),
        time: "2026-11-18T00:00:00Z".into(),
        verdict,
        summary: format!("{verdict:?}"),
        tests_total: total,
        log: String::new(),
        host: AUTO.into(),
        runner: AUTO.into(),
        config: AUTO.into(),
        reason: None,
    }
}

fn result(
    check: &str,
    target: &str,
    case: Option<&str>,
    control: Option<&str>,
    outcome: &str,
    build: &str,
) -> ResultPayload {
    ResultPayload {
        check: check.into(),
        target: target.into(),
        case: case.map(str::to_string),
        control: control.map(str::to_string),
        build: build.into(),
        platform: "test".into(),
        outcome: outcome.into(),
        details: String::new(),
        time: "2026-11-18T00:00:00Z".into(),
        device: "dev".into(),
        config: Some(AUTO.into()),
        extra: serde_json::Value::Null,
    }
}

fn attestation(check: &str, target: &str, commit: &str) -> Attestation {
    Attestation {
        format: ATTEST_FORMAT.into(),
        check: check.into(),
        target: target.into(),
        build: format!("{commit}+manual"),
        by: "owner".into(),
        time: "2026-11-18T00:00:00Z".into(),
        note: "done".into(),
    }
}

struct Case {
    manifest: Manifest,
    build: BuildState,
    allow_dirty: bool,
    records: Vec<RunRecord>,
    evidence: Evidence,
    rejected: Vec<(PathBuf, String, bool)>,
}

impl Case {
    /// The local check passing with its control failing as required, plus
    /// `extra` checks.
    fn new(extra: &str) -> Self {
        Self {
            manifest: Manifest::parse(&format!("{MANIFEST}{extra}")).unwrap(),
            build: state(false),
            allow_dirty: false,
            records: vec![
                rec("normal", RunVerdict::Pass, Some(10)),
                rec("break", RunVerdict::FailedAsRequired, Some(10)),
            ],
            evidence: Evidence::default(),
            rejected: vec![],
        }
    }

    /// Records and results with `AUTO` fields filled in: what the kit would
    /// write for the current manifest on `HOST`.
    fn filled(&self) -> (Vec<RunRecord>, Evidence) {
        let m = &self.manifest;
        let digest = |check: &str, target: &str, control: Option<&str>| {
            let c = m.check(check).expect("check in manifest");
            m.config_digest(c, target, control.and_then(|n| c.control_named(n)))
        };
        let records = self
            .records
            .iter()
            .cloned()
            .map(|mut r| {
                if r.host == AUTO {
                    r.host = HOST.into();
                }
                if r.runner == AUTO {
                    let c = m.check(&r.check).expect("check in manifest");
                    r.runner = c
                        .local_on(&r.target, &r.host)
                        .map(runner_id)
                        .unwrap_or_else(|| "local:forged".into());
                }
                if r.config == AUTO {
                    let control = (r.part != "normal").then_some(r.part.as_str());
                    r.config = digest(&r.check, &r.target, control);
                }
                r
            })
            .collect();
        let mut evidence = Evidence {
            results: self.evidence.results.clone(),
            attestations: self.evidence.attestations.clone(),
            rejected: self.evidence.rejected.clone(),
        };
        for r in &mut evidence.results {
            if r.config.as_deref() == Some(AUTO) {
                r.config = Some(digest(&r.check, &r.target, r.control.as_deref()));
            }
        }
        (records, evidence)
    }

    fn report(&self) -> Report {
        let legacy = BTreeMap::new();
        let (records, evidence) = self.filled();
        evaluate(&Inputs {
            manifest: &self.manifest,
            host: HOST,
            build: &self.build,
            commits: &FakeGit,
            allow_dirty: self.allow_dirty,
            records: &records,
            evidence: &evidence,
            rejected_paths: &self.rejected,
            legacy: &legacy,
        })
    }

    fn cell(&self, check: &str) -> Cell {
        self.report()
            .cells
            .into_iter()
            .find(|c| c.check == check)
            .unwrap()
    }
}

#[test]
fn a_passing_run_with_a_working_control_passes_the_phase() {
    let case = Case::new("");
    let r = case.report();
    assert_eq!(r.cells[0].status, Status::Pass, "{}", r.cells[0].details);
    assert!(r.verdict.passed, "{}", r.verdict.summary);
}

#[test]
fn a_control_that_does_not_fail_makes_the_check_fail() {
    let mut case = Case::new("");
    case.records[1].verdict = RunVerdict::DidNotFail;
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("control did not fail"), "{}", c.details);
    assert!(!case.report().verdict.passed);
}

#[test]
fn a_control_that_printed_no_fail_line_makes_the_check_fail() {
    let mut case = Case::new("");
    case.records[1].verdict = RunVerdict::NoFailLine;
    assert_eq!(case.cell("phase9.local").status, Status::Fail);
}

#[test]
fn a_control_that_ran_other_tests_makes_the_check_fail() {
    let mut case = Case::new("");
    case.records[1].tests_total = Some(4);
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("same tests"), "{}", c.details);
}

#[test]
fn a_check_without_a_control_or_with_a_missing_one_cannot_pass() {
    let mut case = Case::new("");
    case.manifest.checks[0].control.clear();
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("no must-fail control"));

    let mut case = Case::new("");
    case.manifest.checks[0].control[0].missing = Some("feature not added yet".into());
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("control missing"), "{}", c.details);
}

#[test]
fn a_control_not_run_is_incomplete() {
    let mut case = Case::new("");
    case.records.pop();
    assert_eq!(case.cell("phase9.local").status, Status::Incomplete);
}

#[test]
fn a_local_run_for_another_build_is_incomplete() {
    let mut case = Case::new("");
    for r in &mut case.records {
        r.build = release(OLD);
    }
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("does not count"), "{}", c.details);
}

#[test]
fn device_results_with_a_wrong_build_hash_are_incomplete() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![
        result("phase9.phone", "ios", None, None, "PASS", &release(OLD)),
        result(
            "phase9.phone",
            "ios",
            None,
            Some("break-path"),
            "FAIL",
            &release(OLD),
        ),
    ];
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("none for this build"), "{}", c.details);
    // An unknown commit, a wrong profile and a dirty build do not count either.
    for build in [
        "abcdef12345+release".to_string(),
        format!("{HEAD}+debug"),
        format!("{HEAD}-dirty+release"),
    ] {
        case.evidence.results = vec![
            result("phase9.phone", "ios", None, None, "PASS", &build),
            result(
                "phase9.phone",
                "ios",
                None,
                Some("break-path"),
                "FAIL",
                &release(HEAD),
            ),
        ];
        assert_eq!(
            case.cell("phase9.phone").status,
            Status::Incomplete,
            "{build}"
        );
    }
}

#[test]
fn device_results_for_this_build_pass_even_from_an_evidence_only_commit() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![
        result(
            "phase9.phone",
            "ios",
            None,
            None,
            "PASS",
            "333333333+release",
        ),
        result(
            "phase9.phone",
            "ios",
            None,
            Some("break-path"),
            "FAIL",
            &release(HEAD),
        ),
    ];
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Pass, "{}", c.details);
    assert!(case.report().verdict.passed);
}

#[test]
fn device_controls_must_be_reported_and_must_fail() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![result(
        "phase9.phone",
        "ios",
        None,
        None,
        "PASS",
        &release(HEAD),
    )];
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Incomplete);
    assert!(
        c.details.contains("no result for control break-path"),
        "{}",
        c.details
    );

    case.evidence.results.push(result(
        "phase9.phone",
        "ios",
        None,
        Some("break-path"),
        "PASS",
        &release(HEAD),
    ));
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("control did not fail"));
}

#[test]
fn a_device_fail_for_this_build_is_not_hidden_by_a_later_pass() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![
        result("phase9.phone", "ios", None, None, "FAIL", &release(HEAD)),
        result("phase9.phone", "ios", None, None, "PASS", &release(HEAD)),
        result(
            "phase9.phone",
            "ios",
            None,
            Some("break-path"),
            "FAIL",
            &release(HEAD),
        ),
    ];
    assert_eq!(case.cell("phase9.phone").status, Status::Fail);
}

#[test]
fn matrix_cells_need_every_pair() {
    let mut case = Case::new(MATRIX_CHECK);
    let pass = |p: &str| {
        result(
            "phase9.matrix",
            "mac",
            Some(p),
            None,
            "PASS",
            &release(HEAD),
        )
    };
    case.evidence.results = vec![
        pass("a"),
        pass("b"),
        pass("a>b"),
        result(
            "phase9.matrix",
            "mac",
            None,
            Some("break-pin"),
            "FAIL",
            &release(HEAD),
        ),
    ];
    let c = case.cell("phase9.matrix");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("b>a"), "{}", c.details);
    case.evidence.results.push(pass("b>a"));
    assert_eq!(case.cell("phase9.matrix").status, Status::Pass);
}

#[test]
fn attested_never_counts_as_pass_for_an_automated_check() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence
        .attestations
        .push(attestation("phase9.phone", "ios", HEAD));
    let r = case.report();
    let c = r.cells.iter().find(|c| c.check == "phase9.phone").unwrap();
    assert_eq!(c.status, Status::Attested);
    assert!(!r.verdict.passed);
    assert!(r
        .verdict
        .blocking
        .iter()
        .any(|b| b.contains("needs an automated result")));
}

#[test]
fn manual_steps_are_attested_for_this_build_only() {
    let mut case = Case::new(MANUAL_CHECK);
    assert_eq!(case.cell("phase9.review").status, Status::Incomplete);
    case.evidence
        .attestations
        .push(attestation("phase9.review", "session-cert", OLD));
    let c = case.cell("phase9.review");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("another build"), "{}", c.details);
    case.evidence
        .attestations
        .push(attestation("phase9.review", "session-cert", HEAD));
    let r = case.report();
    assert_eq!(r.cells[1].status, Status::Attested);
    assert!(r.verdict.passed, "{}", r.verdict.summary);
    assert!(r.verdict.summary.contains("ATTESTED"));
}

#[test]
fn deferred_only_where_the_phase_allows_it() {
    let defer = |id: &str| {
        format!("\n[[check]]\nid = \"{id}\"\ntitle = \"d\"\nplan = \"p\"\ntargets = [\"x\"]\ndeferred = true\n")
    };
    let mut case = Case::new(&defer("phase9.allowed-defer"));
    case.manifest
        .defer
        .insert("phase9.allowed-defer".into(), "owner deferred it".into());
    let r = case.report();
    assert_eq!(r.cells[1].status, Status::Deferred);
    assert_eq!(r.cells[1].details, "owner deferred it");
    assert!(r.verdict.passed);

    let case = Case::new(&defer("phase9.not-allowed"));
    let r = case.report();
    assert_eq!(r.cells[1].status, Status::Fail);
    assert!(!r.verdict.passed);
}

#[test]
fn a_dirty_tree_never_passes_without_allow_dirty() {
    let mut case = Case::new("");
    case.build = state(true);
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("dirty"));
    assert!(!case.report().verdict.passed);

    case.allow_dirty = true;
    let r = case.report();
    assert_eq!(r.cells[0].status, Status::Pass);
    assert!(r.verdict.passed);
    assert!(r.verdict.summary.contains("dirty tree allowed"));
}

#[test]
fn a_run_recorded_on_a_dirty_tree_does_not_count_on_a_clean_one() {
    let mut case = Case::new("");
    for r in &mut case.records {
        r.build = format!("{HEAD}-dirty+release");
    }
    assert_eq!(case.cell("phase9.local").status, Status::Incomplete);
    case.allow_dirty = true;
    assert_eq!(case.cell("phase9.local").status, Status::Pass);
}

#[test]
fn a_tampered_result_file_blocks_the_verdict() {
    let mut case = Case::new("");
    case.rejected.push((
        "checks/results/x.json".into(),
        "signature does not verify".into(),
        true,
    ));
    assert!(!case.report().verdict.passed);
    case.rejected[0].2 = false;
    assert!(case.report().verdict.passed);
}

#[test]
fn placeholders_are_incomplete() {
    let mut case = Case::new("");
    case.manifest.checks[0].placeholder = Some("crate not merged".into());
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("not wired yet"));
}

// --- Which evidence counts: runner, configuration, reason, host build ---

/// A record that claims a cell from this machine.
fn rec_for(check: &str, target: &str, part: &str, verdict: RunVerdict) -> RunRecord {
    RunRecord {
        check: check.into(),
        target: target.into(),
        ..rec(part, verdict, None)
    }
}

#[test]
fn local_records_never_fill_a_device_only_cell() {
    let mut case = Case::new(DEVICE_CHECK);
    // Hand-written records in checks/runs/ for a cell no local entry runs.
    case.records
        .push(rec_for("phase9.phone", "ios", "normal", RunVerdict::Pass));
    case.records.push(rec_for(
        "phase9.phone",
        "ios",
        "break-path",
        RunVerdict::FailedAsRequired,
    ));
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Incomplete, "{}", c.details);
    assert!(c.details.contains("no signed result"), "{}", c.details);
    assert!(!case.report().verdict.passed);
}

#[test]
fn local_records_count_only_from_the_configured_runner_on_its_host() {
    // Recorded on another kind of machine.
    let mut case = Case::new("");
    for r in &mut case.records {
        r.host = "macos-aarch64".into();
    }
    assert_eq!(case.cell("phase9.local").status, Status::Incomplete);
    // Recorded by a runner that is not the [[check.local]] entry.
    let mut case = Case::new("");
    for r in &mut case.records {
        r.runner = "local:pc@windows-x86_64:0000000000000000".into();
    }
    assert_eq!(case.cell("phase9.local").status, Status::Incomplete);
    // This machine is not the cell's runner: its records do not count even
    // if they name the right runner.
    let mut case = Case::new("");
    case.manifest.checks[0].local[0].host = "linux-x86_64".into();
    for r in &mut case.records {
        r.host = "linux-x86_64".into();
    }
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Incomplete, "{}", c.details);
    assert!(c.details.contains("on linux-x86_64"), "{}", c.details);
}

#[test]
fn a_local_run_with_another_profile_does_not_count() {
    let mut case = Case::new("");
    for r in &mut case.records {
        r.build = format!("{HEAD}+debug");
    }
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Incomplete);
    assert!(c.details.contains("profile"), "{}", c.details);
}

#[test]
fn a_changed_check_configuration_makes_local_runs_incomplete() {
    let changes: [fn(&mut Check); 5] = [
        |c| c.local[0].command.push("--release".into()),
        |c| {
            c.local[0].env.insert("X".into(), "1".into());
        },
        |c| c.min_tests = 50,
        |c| c.control[0].args = vec!["--features".into(), "control-other".into()],
        |c| c.pass_marker = Some("OK".into()),
    ];
    for (i, change) in changes.into_iter().enumerate() {
        let mut case = Case::new("");
        // Records written under the old configuration...
        let (records, _) = case.filled();
        case.records = records;
        // ...then a committed manifest change.
        change(&mut case.manifest.checks[0]);
        let c = case.cell("phase9.local");
        assert_eq!(c.status, Status::Incomplete, "change {i}: {}", c.details);
        assert!(c.details.contains("configuration"), "{}", c.details);
    }
}

#[test]
fn a_changed_check_configuration_makes_device_results_incomplete() {
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![
        result("phase9.phone", "ios", None, None, "PASS", &release(HEAD)),
        result(
            "phase9.phone",
            "ios",
            None,
            Some("break-path"),
            "FAIL",
            &release(HEAD),
        ),
    ];
    assert_eq!(case.cell("phase9.phone").status, Status::Pass);
    let (_, evidence) = case.filled();
    case.evidence = evidence;
    case.manifest.checks[1].control[0]
        .env
        .insert("MOUSSE_BREAK".into(), "2".into());
    let c = case.cell("phase9.phone");
    assert_eq!(c.status, Status::Incomplete, "{}", c.details);
    assert!(c.details.contains("configuration"), "{}", c.details);
    // A result with no digest at all does not count either.
    let mut case = Case::new(DEVICE_CHECK);
    case.evidence.results = vec![
        ResultPayload {
            config: None,
            ..result("phase9.phone", "ios", None, None, "PASS", &release(HEAD))
        },
        result(
            "phase9.phone",
            "ios",
            None,
            Some("break-path"),
            "FAIL",
            &release(HEAD),
        ),
    ];
    assert_eq!(case.cell("phase9.phone").status, Status::Incomplete);
}

const PIN_CHECK: &str = r#"
[[check]]
id = "phase9.slice"
title = "cross machine"
plan = "item 5"
targets = ["pc-to-mac"]
cross_machine = true
[[check.control]]
name = "wrong-identity"
breaks = "the host presents another identity"
env = { MOUSSE_HELPER_BREAK = "wrong-identity" }
expect_reason = "pin_mismatch"
"#;

fn slice(control: Option<&str>, outcome: &str, extra: serde_json::Value) -> ResultPayload {
    ResultPayload {
        extra,
        ..result(
            "phase9.slice",
            "pc-to-mac",
            None,
            control,
            outcome,
            &release(HEAD),
        )
    }
}

#[test]
fn a_control_must_fail_for_the_reason_it_names() {
    let host = release(HEAD);
    let ok_normal = slice(None, "PASS", serde_json::json!({ "host_build": host }));
    let control = |extra: serde_json::Value| {
        let mut r = slice(Some("wrong-identity"), "FAIL", extra);
        r.details = "FAIL pair in person: connection closed".into();
        r
    };
    let mut case = Case::new(PIN_CHECK);
    case.evidence.results = vec![
        ok_normal.clone(),
        control(serde_json::json!({ "host_build": host, "reason": "pin_mismatch" })),
    ];
    let c = case.cell("phase9.slice");
    assert_eq!(c.status, Status::Pass, "{}", c.details);

    for extra in [
        serde_json::json!({ "host_build": host, "reason": "timeout" }),
        serde_json::json!({ "host_build": host }),
    ] {
        case.evidence.results = vec![ok_normal.clone(), control(extra)];
        let c = case.cell("phase9.slice");
        assert_eq!(c.status, Status::Fail, "{}", c.details);
        assert!(c.details.contains("reason=pin_mismatch"), "{}", c.details);
    }

    // The reason may also be on the FAIL line in the details.
    let mut r = control(serde_json::json!({ "host_build": host }));
    r.details = "FAIL phase0.thin-slice-cross-machine reason=pin_mismatch".into();
    case.evidence.results = vec![ok_normal, r];
    assert_eq!(case.cell("phase9.slice").status, Status::Pass);
}

#[test]
fn a_local_control_with_the_wrong_reason_fails_the_check() {
    let with_reason = MANIFEST.replace(
        "args = [\"--features\", \"control-break\"]",
        "args = [\"--features\", \"control-break\"]\nexpect_reason = \"pin_mismatch\"",
    );
    let mut case = Case::new("");
    case.manifest = Manifest::parse(&with_reason).unwrap();
    case.records[1].reason = Some("pin_mismatch".into());
    assert_eq!(case.cell("phase9.local").status, Status::Pass);
    case.records[1].reason = Some("timeout".into());
    assert_eq!(case.cell("phase9.local").status, Status::Fail);
    case.records[1].reason = None;
    case.records[1].verdict = RunVerdict::WrongReason;
    let c = case.cell("phase9.local");
    assert_eq!(c.status, Status::Fail);
    assert!(c.details.contains("wrong reason"), "{}", c.details);
}

#[test]
fn a_cross_machine_cell_needs_the_host_build_under_test_too() {
    let reason = serde_json::json!({ "host_build": release(HEAD), "reason": "pin_mismatch" });
    let control = slice(Some("wrong-identity"), "FAIL", reason);
    let normal = |extra: serde_json::Value| slice(None, "PASS", extra);
    let mut case = Case::new(PIN_CHECK);
    for extra in [
        serde_json::json!({ "host_build": release(OLD) }),
        serde_json::json!({ "host_build": format!("{HEAD}-dirty+release") }),
        serde_json::json!({}),
        serde_json::json!({ "host_build": release(HEAD), "caller_build": release(OLD) }),
    ] {
        case.evidence.results = vec![normal(extra.clone()), control.clone()];
        let c = case.cell("phase9.slice");
        assert_eq!(c.status, Status::Incomplete, "{extra}: {}", c.details);
    }
    case.evidence.results = vec![
        normal(serde_json::json!({ "host_build": "333333333+release" })),
        control,
    ];
    let c = case.cell("phase9.slice");
    assert_eq!(c.status, Status::Pass, "{}", c.details);
}
