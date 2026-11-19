//! Turning manifests, local run records and device evidence into one status
//! per check × target cell, and a phase verdict.
//!
//! Rules, in order:
//! 1. A deferred check is DEFERRED only if the phase's `[defer]` table lists
//!    it; otherwise FAIL.
//! 2. A manual check is ATTESTED if someone attested it for this build;
//!    otherwise INCOMPLETE. It never becomes PASS.
//! 3. An automated check with no control, or with a control marked missing,
//!    is FAIL.
//! 4. A placeholder is INCOMPLETE.
//! 5. Evidence must be for the build under test and the check's current
//!    configuration (its digest, see `Manifest::config_digest`); anything
//!    else is INCOMPLETE. Local run records count only for a target with a
//!    `[[check.local]]` entry for this machine's host, and only if that entry
//!    produced them with the check's profile. Every other cell needs signed
//!    device results. Cross-machine cells also need the host's build to be
//!    the build under test. App checks also need the app build pinned in
//!    `app/MOUSSE_REVISION` (and, cross-machine, the host's app build). Any FAIL, any control that did not fail, printed
//!    no FAIL line or failed for another reason than its `expect_reason` is
//!    FAIL. Missing parts are INCOMPLETE.
//! 6. On a dirty tree, PASS becomes INCOMPLETE unless `--allow-dirty`.
//! 7. An attestation on an automated check shows as ATTESTED but blocks the
//!    verdict like INCOMPLETE.
//!
//! The phase passes only if every cell is PASS, an allowed DEFERRED, or an
//! ATTESTED manual step, and no result file shows signs of tampering.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::app::app_build_counts;
use crate::build::{check_build, BuildState, Commits};
use crate::evidence::{Attestation, Evidence, ResultPayload};
use crate::manifest::{Check, Judge, LocalRun, Manifest};
use crate::runner::{runner_id, RunRecord, RunVerdict};

/// One cell's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Fail,
    Incomplete,
    Deferred,
    Attested,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Incomplete => "INCOMPLETE",
            Status::Deferred => "DEFERRED",
            Status::Attested => "ATTESTED",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Cell {
    pub check: String,
    pub target: String,
    pub status: Status,
    pub details: String,
    pub title: String,
    pub plan: String,
    pub manual: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RejectedFile {
    pub path: String,
    pub reason: String,
    pub tampering: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verdict {
    pub passed: bool,
    pub summary: String,
    pub blocking: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub phase: String,
    pub title: String,
    pub build: String,
    pub dirty: bool,
    pub dirty_paths: Vec<String>,
    pub allow_dirty: bool,
    pub cells: Vec<Cell>,
    pub rejected: Vec<RejectedFile>,
    pub counts: BTreeMap<Status, usize>,
    pub verdict: Verdict,
}

/// Everything the evaluation reads.
pub struct Inputs<'a> {
    pub manifest: &'a Manifest,
    /// `<os>-<arch>` of this machine: only `[[check.local]]` entries for it
    /// can produce local run records that count.
    pub host: &'a str,
    pub build: &'a BuildState,
    pub commits: &'a dyn Commits,
    pub allow_dirty: bool,
    pub records: &'a [RunRecord],
    pub evidence: &'a Evidence,
    pub rejected_paths: &'a [(PathBuf, String, bool)],
    /// Notes about old unsigned results, keyed by (check, target).
    pub legacy: &'a BTreeMap<(String, String), String>,
    /// The app revision pinned in `app/MOUSSE_REVISION`; `None` if the file
    /// is missing or unreadable, which leaves every app check INCOMPLETE.
    pub app_revision: Option<&'a str>,
    /// Whether a path (relative to the repository root) is in the tree:
    /// what a check's `waits` look for.
    pub exists: &'a dyn Fn(&str) -> bool,
}

struct Outcome {
    status: Status,
    details: String,
}

fn out(status: Status, details: impl Into<String>) -> Outcome {
    Outcome {
        status,
        details: details.into(),
    }
}

pub fn evaluate(inp: &Inputs<'_>) -> Report {
    let m = inp.manifest;
    let mut cells = Vec::new();
    for check in &m.checks {
        for target in &check.targets {
            let o = eval_cell(inp, check, target);
            cells.push(Cell {
                check: check.id.clone(),
                target: target.clone(),
                status: o.status,
                details: o.details,
                title: check.title.clone(),
                plan: check.plan.clone(),
                manual: check.manual,
            });
        }
    }
    let rejected: Vec<RejectedFile> = inp
        .rejected_paths
        .iter()
        .map(|(p, r, t)| RejectedFile {
            path: p.display().to_string(),
            reason: r.clone(),
            tampering: *t,
        })
        .collect();
    let mut counts = BTreeMap::new();
    for c in &cells {
        *counts.entry(c.status).or_insert(0) += 1;
    }
    let mut blocking: Vec<String> = cells
        .iter()
        .filter(|c| !cell_ok(c))
        .map(|c| {
            let why = if c.status == Status::Attested {
                "ATTESTED, but needs an automated result".to_string()
            } else {
                c.status.label().to_string()
            };
            format!("{} @ {}: {why}", c.check, c.target)
        })
        .collect();
    for r in rejected.iter().filter(|r| r.tampering) {
        blocking.push(format!("result file {}: {}", r.path, r.reason));
    }
    let passed = blocking.is_empty() && !cells.is_empty();
    let summary = if passed {
        let mut s = format!("{} PASS", m.phase);
        let attested = counts.get(&Status::Attested).copied().unwrap_or(0);
        let deferred = counts.get(&Status::Deferred).copied().unwrap_or(0);
        if deferred > 0 {
            s.push_str(&format!(", {deferred} allowed DEFERRED"));
        }
        if attested > 0 {
            s.push_str(&format!(", {attested} manual steps ATTESTED"));
        }
        if inp.build.dirty {
            s.push_str(" (dirty tree allowed)");
        }
        s
    } else {
        format!("{} NOT PASSED: {} blocking", m.phase, blocking.len())
    };
    Report {
        phase: m.phase.clone(),
        title: m.title.clone(),
        build: inp.build.short(),
        dirty: inp.build.dirty,
        dirty_paths: inp.build.dirty_paths.clone(),
        allow_dirty: inp.allow_dirty,
        cells,
        rejected,
        counts,
        verdict: Verdict {
            passed,
            summary,
            blocking,
        },
    }
}

fn cell_ok(c: &Cell) -> bool {
    match c.status {
        Status::Pass | Status::Deferred => true,
        Status::Attested => c.manual,
        Status::Fail | Status::Incomplete => false,
    }
}

fn eval_cell(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if check.deferred {
        return match inp.manifest.defer.get(&check.id) {
            Some(reason) => out(Status::Deferred, reason.clone()),
            None => out(
                Status::Fail,
                "marked deferred, but this phase's [defer] list does not allow deferring it",
            ),
        };
    }
    if check.manual {
        return eval_manual(inp, check, target);
    }
    let mut o = eval_automated(inp, check, target);
    if o.status == Status::Pass && inp.build.dirty {
        if inp.allow_dirty {
            o.details.push_str(" (dirty tree allowed)");
        } else {
            o = out(
                Status::Incomplete,
                format!(
                    "would pass, but the tree is dirty ({}); commit, or pass --allow-dirty",
                    inp.build.dirty_paths.join(", ")
                ),
            );
        }
    }
    if o.status == Status::Incomplete {
        if let Some(a) = latest_attestation(inp, check, target) {
            o = out(
                Status::Attested,
                format!(
                    "attested by {} at {}: {} (does not count: this check needs an automated result; {})",
                    a.by, a.time, a.note, o.details
                ),
            );
        }
    }
    o
}

fn latest_attestation<'a>(
    inp: &'a Inputs<'_>,
    check: &Check,
    target: &str,
) -> Option<&'a Attestation> {
    inp.evidence
        .attestations
        .iter()
        .filter(|a| a.check == check.id && a.target == target)
        .filter(|a| check_build(inp.commits, inp.build, &a.build, None, inp.allow_dirty).is_ok())
        .max_by(|a, b| a.time.cmp(&b.time))
}

fn eval_manual(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if let Some(a) = latest_attestation(inp, check, target) {
        return out(
            Status::Attested,
            format!("by {} at {}: {}", a.by, a.time, a.note),
        );
    }
    let stale = inp
        .evidence
        .attestations
        .iter()
        .filter(|a| a.check == check.id && a.target == target)
        .filter_map(|a| check_build(inp.commits, inp.build, &a.build, None, inp.allow_dirty).err())
        .next();
    let steps = check.steps.clone().unwrap_or_default();
    match stale {
        Some(why) => out(
            Status::Incomplete,
            format!("attested for another build ({why}); redo: {steps}"),
        ),
        None => out(
            Status::Incomplete,
            format!("manual step not attested yet: {steps}"),
        ),
    }
}

fn eval_automated(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if check.control.is_empty() {
        return out(Status::Fail, "no must-fail control: this check cannot pass");
    }
    let missing: Vec<String> = check
        .control
        .iter()
        .filter_map(|k| k.missing.as_ref().map(|why| format!("{}: {why}", k.name)))
        .collect();
    if !missing.is_empty() {
        return out(
            Status::Fail,
            format!("control missing: {}", missing.join("; ")),
        );
    }
    if let Some(why) = &check.placeholder {
        return out(Status::Incomplete, format!("not wired yet: {why}"));
    }
    if let Some((w, path)) = check.waiting(None, inp.exists) {
        return out(
            Status::Incomplete,
            format!("waits for {} ({path} is not in this tree)", w.slice),
        );
    }
    if check.app && inp.app_revision.is_none() {
        return out(
            Status::Incomplete,
            format!(
                "an app check, but {} is missing or not a full commit",
                crate::app::REVISION_FILE
            ),
        );
    }
    let local = check.local_for(target);
    if let Some(why) = local.and_then(|l| l.placeholder.as_ref()) {
        return out(
            Status::Incomplete,
            format!("not wired yet on {target}: {why}"),
        );
    }
    // Local records count only when this machine is the configured runner
    // for the cell; every other cell is judged from signed results alone.
    let runner = check.local_on(target, inp.host);
    let has_records = runner.is_some_and(|l| {
        inp.records
            .iter()
            .any(|r| r.check == check.id && r.target == target && from_runner(r, l))
    });
    let has_results = inp
        .evidence
        .results
        .iter()
        .any(|r| r.check == check.id && r.target == target);
    if let (Some(l), false, false) = (runner, has_records, has_results) {
        let replaced = inp
            .records
            .iter()
            .any(|r| r.check == check.id && r.target == target && r.host == l.host);
        if replaced {
            return out(
                Status::Incomplete,
                format!(
                    "{CONFIG_CHANGED}: the last runs here used another command; `mousse-check run {}` again",
                    check.id
                ),
            );
        }
    }
    if let (Some(l), false, false) = (local, has_records, has_results) {
        return out(
            Status::Incomplete,
            format!(
                "not run for this build: `mousse-check run {}` on {} (another machine adds --sign-with <key>){}",
                check.id,
                l.host,
                legacy_note(inp, check, target)
            ),
        );
    }
    if let (Some(l), true) = (runner, has_records) {
        let o = eval_local(inp, check, target, l);
        if o.status != Status::Incomplete || !has_results {
            return o;
        }
    }
    eval_device(inp, check, target)
}

/// The record names this `[[check.local]]` entry and its host.
fn from_runner(r: &RunRecord, l: &LocalRun) -> bool {
    r.host == l.host && r.runner == runner_id(l)
}

fn record<'a>(
    inp: &'a Inputs<'_>,
    check: &Check,
    target: &str,
    local: &LocalRun,
    part: &str,
    case: Option<&str>,
) -> Option<&'a RunRecord> {
    inp.records
        .iter()
        .filter(|r| r.check == check.id && r.target == target && r.part == part)
        .filter(|r| r.case.as_deref() == case)
        .filter(|r| from_runner(r, local))
        .max_by(|a, b| a.time.cmp(&b.time))
}

const CONFIG_CHANGED: &str =
    "run with another configuration of this check (the manifest changed since)";

fn eval_local(inp: &Inputs<'_>, check: &Check, target: &str, local: &LocalRun) -> Outcome {
    let mut fails = Vec::new();
    let mut gaps = Vec::new();
    // The record's profile is what the executed command built with (see
    // `command_profile`), not the manifest's label.
    let profile = inp.manifest.device_profile(check);
    let usable = |r: &RunRecord, control| -> Result<(), String> {
        check_build(inp.commits, inp.build, &r.build, profile, inp.allow_dirty)?;
        if r.config != inp.manifest.config_digest(check, target, control) {
            return Err(CONFIG_CHANGED.into());
        }
        if check.app {
            app_build_counts(r.app_build.as_deref(), inp.app_revision)?;
        }
        Ok(())
    };
    let named = check.controls_per_case();
    let cases = if named {
        check.cases(target)
    } else {
        vec![None]
    };
    let mut normal_summary = String::new();
    for case in &cases {
        let case = case.as_deref();
        // In a check with named cases, every message names its case.
        let at = case.map(|c| format!("[{c}] ")).unwrap_or_default();
        if let Some((w, path)) = check.waiting(case, inp.exists) {
            gaps.push(format!(
                "{at}waits for {} ({path} is not in this tree)",
                w.slice
            ));
            continue;
        }
        let mut case_fails = Vec::new();
        let mut case_gaps = Vec::new();
        let normal = record(inp, check, target, local, "normal", case);
        let mut normal_total = None;
        match normal {
            None => case_gaps.push("not run for this build".to_string()),
            Some(r) => match usable(r, None) {
                Err(why) => case_gaps.push(format!("last run does not count: {why}")),
                Ok(_) => match r.verdict {
                    RunVerdict::Pass => {
                        normal_total = r.tests_total;
                        normal_summary = r.summary.clone();
                    }
                    _ => case_fails.push(format!("run failed: {}", r.summary)),
                },
            },
        }
        for k in &check.control {
            match record(inp, check, target, local, &k.name, case) {
                None => case_gaps.push(format!("control {} not run", k.name)),
                Some(r) => match usable(r, Some(k)) {
                    Err(why) => case_gaps.push(format!("control {} does not count: {why}", k.name)),
                    Ok(_) => match r.verdict {
                        RunVerdict::FailedAsRequired => {
                            if let Some(want) = &k.expect_reason {
                                if r.reason.as_ref() != Some(want) {
                                    case_fails.push(format!(
                                        "control {} failed with reason {}, it must fail with reason={want}",
                                        k.name,
                                        r.reason.as_deref().unwrap_or("(none given)")
                                    ));
                                }
                            }
                            if check.judge == Judge::CargoTest {
                                if let (Some(a), Some(b)) = (normal_total, r.tests_total) {
                                    if a != b {
                                        case_fails.push(format!(
                                            "control {} ran {b} tests, the check ran {a}; a control must run the same tests (use --no-fail-fast)",
                                            k.name
                                        ));
                                    }
                                }
                            }
                        }
                        RunVerdict::DidNotFail => case_fails.push(format!(
                            "control did not fail: {} ({}): {}",
                            k.name, k.breaks, r.summary
                        )),
                        RunVerdict::WrongReason => case_fails.push(format!(
                            "control {} failed for the wrong reason: {}",
                            k.name, r.summary
                        )),
                        _ => case_fails.push(format!(
                            "control {} did not print FAIL: {}",
                            k.name, r.summary
                        )),
                    },
                },
            }
        }
        fails.extend(case_fails.into_iter().map(|f| format!("{at}{f}")));
        gaps.extend(case_gaps.into_iter().map(|g| format!("{at}{g}")));
    }
    if !fails.is_empty() {
        return out(Status::Fail, fails.join("; "));
    }
    if !gaps.is_empty() {
        return out(Status::Incomplete, gaps.join("; "));
    }
    let summary = if named {
        format!(
            "{} case(s) passed; {} control(s) failed as required in each",
            cases.len(),
            check.control.len()
        )
    } else {
        format!(
            "{normal_summary}; {} control(s) failed as required",
            check.control.len()
        )
    };
    out(Status::Pass, summary)
}

fn legacy_note(inp: &Inputs<'_>, check: &Check, target: &str) -> String {
    inp.legacy
        .get(&(check.id.clone(), target.to_string()))
        .map(|n| format!("; {n}"))
        .unwrap_or_default()
}

fn eval_device(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    let profile = inp.manifest.device_profile(check);
    let all: Vec<&ResultPayload> = inp
        .evidence
        .results
        .iter()
        .filter(|r| r.check == check.id && r.target == target)
        .collect();
    let legacy = legacy_note(inp, check, target);
    let hint = check
        .device_steps
        .as_ref()
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();
    if all.is_empty() {
        return out(
            Status::Incomplete,
            format!("no signed result yet{hint}{legacy}"),
        );
    }
    let mut stale = Vec::new();
    let mut ok = Vec::new();
    for r in all {
        match device_result_counts(inp, check, target, profile, r) {
            Ok(()) => ok.push(r),
            Err(why) => stale.push(why),
        }
    }
    if ok.is_empty() {
        return out(
            Status::Incomplete,
            format!(
                "{} signed result(s), none for this build and configuration: {}{legacy}",
                stale.len(),
                stale.first().cloned().unwrap_or_default()
            ),
        );
    }
    let mut fails = Vec::new();
    let mut gaps = Vec::new();
    let normal: Vec<&&ResultPayload> = ok.iter().filter(|r| r.control.is_none()).collect();
    for r in normal.iter().filter(|r| r.outcome == "FAIL") {
        fails.push(format!(
            "{} reported FAIL{} at {}: {}",
            r.device,
            r.case
                .as_ref()
                .map(|c| format!(" for {c}"))
                .unwrap_or_default(),
            r.time,
            r.details
        ));
    }
    let expected = check.cases(target);
    let missing: Vec<String> = expected
        .iter()
        .filter(|case| {
            !normal
                .iter()
                .any(|r| &r.case == *case && r.outcome == "PASS")
        })
        .map(|c| c.clone().unwrap_or_else(|| "result".into()))
        .collect();
    if !missing.is_empty() {
        gaps.push(if expected.len() == 1 {
            "no PASS result for this build".to_string()
        } else {
            format!(
                "{} of {} cases missing ({})",
                missing.len(),
                expected.len(),
                missing
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
    }
    // Named cases: every control must have failed in every case. Other
    // checks: at least one result per control, all of them FAIL.
    let control_cases: Vec<Option<String>> = if check.controls_per_case() {
        expected.clone()
    } else {
        vec![None]
    };
    for case in check.cases.iter() {
        if let Some((w, path)) = check.waiting(Some(case), inp.exists) {
            gaps.push(format!(
                "[{case}] waits for {} ({path} is not in this tree)",
                w.slice
            ));
        }
    }
    for k in &check.control {
        let rs: Vec<&&ResultPayload> = ok
            .iter()
            .filter(|r| r.control.as_deref() == Some(k.name.as_str()))
            .collect();
        for case in &control_cases {
            let Some(case) = case else {
                if rs.is_empty() {
                    gaps.push(format!("no result for control {}", k.name));
                }
                continue;
            };
            if !rs.iter().any(|r| r.case.as_ref() == Some(case)) {
                gaps.push(format!("[{case}] no result for control {}", k.name));
            }
        }
        for r in rs.iter().filter(|r| r.outcome != "FAIL") {
            fails.push(format!(
                "control did not fail: {} reported {} for {} ({})",
                r.device, r.outcome, k.name, k.breaks
            ));
        }
        if let Some(want) = &k.expect_reason {
            for r in rs.iter().filter(|r| r.outcome == "FAIL") {
                let got = r.reason();
                if got.as_ref() != Some(want) {
                    fails.push(format!(
                        "control {} on {} failed with reason {}, it must fail with reason={want}",
                        k.name,
                        r.device,
                        got.as_deref().unwrap_or("(none given)")
                    ));
                }
            }
        }
    }
    if !fails.is_empty() {
        return out(Status::Fail, fails.join("; "));
    }
    if !gaps.is_empty() {
        if let Some(why) = stale.first() {
            gaps.push(format!(
                "{} other signed result(s) do not count: {why}",
                stale.len()
            ));
        }
        return out(Status::Incomplete, format!("{}{hint}", gaps.join("; ")));
    }
    let mut devices: Vec<&str> = normal.iter().map(|r| r.device.as_str()).collect();
    devices.sort_unstable();
    devices.dedup();
    let latest = normal.iter().map(|r| r.time.as_str()).max().unwrap_or("");
    out(
        Status::Pass,
        format!(
            "signed by {} (latest {latest}): {} case(s) PASS; {} control(s) failed as required",
            devices.join(", "),
            expected.len(),
            check.control.len()
        ),
    )
}

/// Why a verified device result does not count for this cell: another
/// build (the caller's, and for a cross-machine cell the host's), another
/// check configuration, an unknown control, or for an app check another app
/// build than the pinned one (on both machines for a cross-machine cell).
fn device_result_counts(
    inp: &Inputs<'_>,
    check: &Check,
    target: &str,
    profile: Option<&str>,
    r: &ResultPayload,
) -> Result<(), String> {
    let build = |claimed: &str| {
        check_build(inp.commits, inp.build, claimed, profile, inp.allow_dirty).map(|_| ())
    };
    build(&r.build)?;
    let control = match &r.control {
        None => None,
        Some(name) => Some(
            check
                .control_named(name)
                .ok_or_else(|| format!("names control {name}, which this check does not have"))?,
        ),
    };
    let want = inp.manifest.config_digest(check, target, control);
    match &r.config {
        None => return Err("carries no check configuration digest".into()),
        Some(c) if *c != want => return Err(CONFIG_CHANGED.into()),
        Some(_) => {}
    }
    if check.cross_machine {
        let host = r
            .extra_str("host_build")
            .ok_or("does not say which build the host ran (extra.host_build)")?;
        build(host).map_err(|why| format!("host: {why}"))?;
        if let Some(caller) = r.extra_str("caller_build") {
            build(caller).map_err(|why| format!("caller: {why}"))?;
        }
    }
    if check.app {
        app_build_counts(r.extra_str("app_build"), inp.app_revision)?;
        if check.cross_machine {
            app_build_counts(r.extra_str("host_app_build"), inp.app_revision)
                .map_err(|why| format!("host: {why}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
