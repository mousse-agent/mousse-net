//! Paths, loading, local runs and signing: the pieces the CLI calls.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mousse_net_core::identity::SoftwareKey;
use serde_json::Value;

use crate::build::{BuildState, Git};
use crate::eval::{evaluate, Inputs, Report};
use crate::evidence::{self, file_part, DeviceList, Evidence, ResultPayload};
use crate::manifest::{Check, Judge, Manifest};
use crate::runner::{
    command_for, execute, fail_reason, judge_control, judge_matrix_files, judge_normal,
    read_matrix_dir, runner_id, RunRecord, RunVerdict, Vars,
};
use crate::util::{now_rfc3339, to_hex};

/// `<os>-<arch>` of this machine, as `host` in manifests.
pub fn host() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Which parts of a check to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parts {
    Normal,
    Controls,
    Both,
}

/// Signs results of local runs, for a machine that is not the one
/// evaluating the phase.
pub struct Signer {
    pub key: SoftwareKey,
    pub device: String,
    pub platform: String,
    pub out_dir: PathBuf,
}

pub struct Kit {
    pub git: Git,
    pub checks: PathBuf,
}

impl Kit {
    pub fn open(root: Option<&Path>) -> Result<Self, String> {
        let start = match root {
            Some(r) => r.to_path_buf(),
            None => std::env::current_dir().map_err(|e| e.to_string())?,
        };
        let root = Git::find_root(&start)?;
        Ok(Self {
            checks: root.join("checks"),
            git: Git::new(&root),
        })
    }

    pub fn root(&self) -> &Path {
        self.git.root()
    }

    pub fn results_dir(&self) -> PathBuf {
        self.checks.join("results")
    }

    fn runs_dir(&self) -> PathBuf {
        self.checks.join("runs")
    }

    pub fn devices_path(&self) -> PathBuf {
        self.checks.join("devices.toml")
    }

    pub fn manifest_path(&self, phase: &str) -> PathBuf {
        self.checks.join(format!("{phase}.toml"))
    }

    pub fn has_phase(&self, phase: &str) -> bool {
        !phase.starts_with('-') && self.manifest_path(phase).is_file()
    }

    pub fn load_manifest(&self, phase: &str) -> Result<Manifest, String> {
        let m = Manifest::load(&self.manifest_path(phase))?;
        if m.phase != phase {
            return Err(format!(
                "{} says phase = {:?}",
                self.manifest_path(phase).display(),
                m.phase
            ));
        }
        Ok(m)
    }

    /// Every phase manifest in `checks/`.
    pub fn phases(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(&self.checks)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let stem = p.file_stem()?.to_str()?.to_string();
                (p.extension()? == "toml" && stem.starts_with("phase")).then_some(stem)
            })
            .collect();
        out.sort();
        out
    }

    /// The manifest that holds check `id` (by its `<phase>.` prefix).
    pub fn find_check(&self, id: &str) -> Result<(Manifest, Check), String> {
        let phase = id
            .split_once('.')
            .map(|(p, _)| p)
            .ok_or_else(|| format!("check id {id} has no phase prefix"))?;
        let m = self.load_manifest(phase)?;
        let c = m
            .check(id)
            .cloned()
            .ok_or_else(|| format!("no check {id} in {phase}"))?;
        Ok((m, c))
    }

    pub fn devices(&self) -> Result<DeviceList, String> {
        DeviceList::load(&self.devices_path())
    }

    pub fn state(&self) -> Result<BuildState, String> {
        self.git.state()
    }

    pub fn evidence(&self, devices: &DeviceList) -> Evidence {
        evidence::collect(&self.results_dir(), devices)
    }

    pub fn records(&self) -> Vec<RunRecord> {
        std::fs::read_dir(self.runs_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect()
    }

    /// Notes about unsigned legacy matrix files, per (check, target).
    pub fn legacy_notes(&self, m: &Manifest) -> BTreeMap<(String, String), String> {
        let mut notes = BTreeMap::new();
        for c in &m.checks {
            let Some(dir) = c.matrix.as_ref().and_then(|x| x.legacy_results.as_ref()) else {
                continue;
            };
            let files = read_matrix_dir(&self.root().join(dir));
            for t in &c.targets {
                let mine: Vec<_> = files
                    .iter()
                    .filter_map(|(_, f)| f.as_ref().ok())
                    .filter(|f| &f.target == t)
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let pass = mine.iter().filter(|f| f.outcome == "PASS").count();
                let mut builds: Vec<&str> = mine.iter().map(|f| f.build.as_str()).collect();
                builds.sort_unstable();
                builds.dedup();
                notes.insert(
                    (c.id.clone(), t.clone()),
                    format!(
                        "legacy unsigned results in {dir}: {pass}/{} PASS at {} (not counted: unsigned and from an older build; re-run signed)",
                        mine.len(),
                        builds.join(", ")
                    ),
                );
            }
        }
        notes
    }

    /// Evaluate a phase from what is on disk.
    pub fn report(&self, m: &Manifest, allow_dirty: bool) -> Result<Report, String> {
        let state = self.state()?;
        let devices = self.devices()?;
        let ev = self.evidence(&devices);
        let rejected: Vec<(PathBuf, String, bool)> = ev
            .rejected
            .iter()
            .map(|(p, r)| {
                (
                    p.strip_prefix(self.root()).unwrap_or(p).to_path_buf(),
                    r.to_string(),
                    r.is_tampering(),
                )
            })
            .collect();
        let records = self.records();
        let legacy = self.legacy_notes(m);
        let here = host();
        Ok(evaluate(&Inputs {
            manifest: m,
            host: &here,
            build: &state,
            commits: &self.git,
            allow_dirty,
            records: &records,
            evidence: &ev,
            rejected_paths: &rejected,
            legacy: &legacy,
        }))
    }

    /// Run a check's local commands on this machine. Returns false if any
    /// part did not do what it must (normal: pass; control: fail).
    pub fn run_local(
        &self,
        m: &Manifest,
        c: &Check,
        target: Option<&str>,
        parts: Parts,
        include_placeholders: bool,
        signer: Option<&Signer>,
    ) -> Result<bool, String> {
        let state = self.state()?;
        let build = state.id(&m.run_profile(c)).to_string();
        let here = host();
        let mut all_ok = true;
        let mut ran = 0;
        for local in &c.local {
            if target.is_some_and(|t| t != local.target) {
                continue;
            }
            if local.host != here {
                if target.is_some() {
                    eprintln!(
                        "  {} @ {}: runs on {}, this machine is {here}",
                        c.id, local.target, local.host
                    );
                    all_ok = false;
                }
                continue;
            }
            if let Some(why) = c.placeholder.as_ref().or(local.placeholder.as_ref()) {
                if !include_placeholders {
                    continue;
                }
                eprintln!(
                    "  note: {} is a placeholder ({why}); running it anyway",
                    c.id
                );
            }
            let timeout = Duration::from_secs(c.timeout_secs);
            let mut jobs: Vec<Option<&crate::manifest::Control>> = Vec::new();
            if parts != Parts::Controls {
                jobs.push(None);
            }
            if parts != Parts::Normal {
                for k in &c.control {
                    if let Some(why) = &k.missing {
                        eprintln!(
                            "  {} @ {}: control {} missing: {why}",
                            c.id, local.target, k.name
                        );
                        all_ok = false;
                    } else {
                        jobs.push(Some(k));
                    }
                }
            }
            for k in jobs {
                let part = k.map(|k| k.name.as_str()).unwrap_or("normal");
                let stem = format!("{}__{}__{}", c.id, file_part(&local.target), part);
                let out_dir = self.runs_dir().join("out").join(&stem);
                let _ = std::fs::remove_dir_all(&out_dir);
                std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
                let log = self.runs_dir().join("logs").join(format!("{stem}.log"));
                let (cmd, env) = command_for(local, k);
                eprint!("  {} @ {} [{part}] ... ", c.id, local.target);
                let started = Instant::now();
                let vars = Vars {
                    root: self.root(),
                    out: &out_dir,
                    build: &build,
                };
                let output = execute(&cmd, &env, local.cwd.as_deref(), &vars, timeout, &log);
                let judged = match k {
                    None => {
                        let j = judge_normal(c.judge, c, &output);
                        if c.judge == Judge::Matrix {
                            judge_matrix_files(c, &local.target, &out_dir, j)
                        } else {
                            j
                        }
                    }
                    Some(k) => judge_control(c.judge, c, k.expect_reason.as_deref(), &output),
                };
                let ok = matches!(
                    judged.verdict,
                    RunVerdict::Pass | RunVerdict::FailedAsRequired
                );
                all_ok &= ok;
                ran += 1;
                eprintln!(
                    "{} ({}) [{:.1}s]",
                    verdict_word(judged.verdict),
                    judged.summary,
                    started.elapsed().as_secs_f64()
                );
                let rec = RunRecord {
                    check: c.id.clone(),
                    target: local.target.clone(),
                    part: part.to_string(),
                    build: build.clone(),
                    time: now_rfc3339(),
                    verdict: judged.verdict,
                    summary: judged.summary.clone(),
                    tests_total: judged.tests_total,
                    log: log
                        .strip_prefix(self.root())
                        .unwrap_or(&log)
                        .display()
                        .to_string(),
                    host: here.clone(),
                    runner: runner_id(local),
                    config: m.config_digest(c, &local.target, k),
                    reason: k.and_then(|_| fail_reason(c, &output.text)),
                };
                let path = self.runs_dir().join(format!("{stem}.json"));
                std::fs::create_dir_all(self.runs_dir()).map_err(|e| e.to_string())?;
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                if let Some(s) = signer {
                    self.sign_run(
                        s,
                        c,
                        &local.target,
                        k.map(|k| k.name.as_str()),
                        &build,
                        &rec,
                        &out_dir,
                    )?;
                }
            }
        }
        if ran == 0 && target.is_some() {
            all_ok = false;
        }
        Ok(all_ok)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_run(
        &self,
        s: &Signer,
        c: &Check,
        target: &str,
        control: Option<&str>,
        build: &str,
        rec: &RunRecord,
        out_dir: &Path,
    ) -> Result<(), String> {
        let base = ResultPayload {
            check: c.id.clone(),
            target: target.to_string(),
            case: None,
            control: control.map(str::to_string),
            build: build.to_string(),
            platform: s.platform.clone(),
            outcome: match rec.verdict {
                RunVerdict::Pass | RunVerdict::DidNotFail => "PASS",
                RunVerdict::Fail | RunVerdict::FailedAsRequired | RunVerdict::WrongReason => "FAIL",
                RunVerdict::NoFailLine => "INCOMPLETE",
            }
            .to_string(),
            details: rec.summary.clone(),
            time: rec.time.clone(),
            device: s.device.clone(),
            config: Some(rec.config.clone()),
            extra: match &rec.reason {
                Some(r) => serde_json::json!({ "reason": r }),
                None => Value::Null,
            },
        };
        let mut payloads = Vec::new();
        if c.judge == Judge::Matrix && control.is_none() {
            for (_, f) in read_matrix_dir(out_dir) {
                let Ok(f) = f else { continue };
                if f.target != target {
                    continue;
                }
                payloads.push(ResultPayload {
                    case: Some(f.provider.clone()),
                    outcome: f.outcome.clone(),
                    details: f.details.clone(),
                    extra: serde_json::json!({"kx_group": f.kx_group, "suite": f.suite}),
                    ..base.clone()
                });
            }
            if rec.verdict != RunVerdict::Pass {
                payloads.push(base);
            }
        } else {
            payloads.push(base);
        }
        for p in payloads {
            let path = write_signed(&s.out_dir, &p, &s.key)?;
            eprintln!("    signed {}", path.display());
        }
        Ok(())
    }
}

fn verdict_word(v: RunVerdict) -> &'static str {
    match v {
        RunVerdict::Pass => "PASS",
        RunVerdict::Fail => "FAIL",
        RunVerdict::FailedAsRequired => "control FAILED as required",
        RunVerdict::DidNotFail => "control DID NOT FAIL",
        RunVerdict::NoFailLine => "control printed no FAIL line",
        RunVerdict::WrongReason => "control FAILED for the wrong reason",
    }
}

/// Sign `p` and write it into `dir`. Returns the path.
pub fn write_signed(dir: &Path, p: &ResultPayload, key: &SoftwareKey) -> Result<PathBuf, String> {
    let signed = evidence::sign(p, key)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let name = format!(
        "{}__{}__{}__{}__{}.json",
        file_part(&p.check),
        file_part(&p.target),
        file_part(p.case.as_deref().unwrap_or("all")),
        file_part(p.control.as_deref().unwrap_or("normal")),
        file_part(&p.time.replace(':', ""))
    );
    let path = dir.join(name);
    let text = serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// Inputs to `sign` for one file: a result payload (fields may be missing),
/// a crypto matrix result file, or a log of `MATRIX_RESULT {...}` lines.
pub fn read_unsigned(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if let Ok(v) = serde_json::from_str::<Value>(&text) {
        return Ok(vec![v]);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("MATRIX_RESULT ") {
            let v: Value = serde_json::from_str(rest)
                .map_err(|e| format!("{}: bad MATRIX_RESULT line: {e}", path.display()))?;
            out.push(v.get("result").cloned().unwrap_or(v));
        }
    }
    if out.is_empty() {
        return Err(format!(
            "{}: neither JSON nor MATRIX_RESULT lines",
            path.display()
        ));
    }
    Ok(out)
}

/// Fill a payload from an unsigned value plus command-line overrides.
pub struct SignArgs<'a> {
    pub check: Option<&'a str>,
    pub target: Option<&'a str>,
    pub control: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub default_build: Option<String>,
    pub device: &'a str,
}

pub fn payload_from(v: &Value, a: &SignArgs<'_>) -> Result<ResultPayload, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let is_matrix = v.get("provider").is_some();
    let check = a
        .check
        .map(str::to_string)
        .or_else(|| s("check"))
        .ok_or("no check (give --check)")?;
    let target = a
        .target
        .map(str::to_string)
        .or_else(|| s("target"))
        .ok_or("no target (give --target)")?;
    let outcome = s("outcome").ok_or("no outcome in the result")?;
    let build = s("build")
        .or_else(|| a.default_build.clone())
        .ok_or("no build in the result and no git checkout to take it from")?;
    crate::build::BuildId::parse(&build)?;
    let mut extra = if is_matrix {
        serde_json::json!({"kx_group": s("kx_group"), "suite": s("suite")})
    } else {
        match v.get("extra") {
            Some(Value::Object(o)) => Value::Object(o.clone()),
            Some(Value::Null) | None => serde_json::json!({}),
            Some(other) => return Err(format!("extra must be an object, not {other}")),
        }
    };
    // Fields a result file may carry at the top level (or, for the reason,
    // inside an object `details`) are kept in `extra`, where the kit reads
    // them.
    let details = match v.get("details") {
        Some(Value::String(d)) => d.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    let lifted = [
        (
            "reason",
            s("reason").or_else(|| {
                v.get("details")
                    .and_then(|d| d.get("reason"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }),
        ),
        ("host_build", s("host_build")),
        ("caller_build", s("caller_build")),
    ];
    if let Value::Object(o) = &mut extra {
        for (key, value) in lifted {
            if let Some(value) = value {
                o.entry(key).or_insert(Value::String(value));
            }
        }
    }
    if extra.as_object().is_some_and(|o| o.is_empty()) {
        extra = Value::Null;
    }
    Ok(ResultPayload {
        check,
        target,
        case: s("case").or_else(|| s("provider")),
        control: a.control.map(str::to_string).or_else(|| s("control")),
        build,
        platform: a
            .platform
            .map(str::to_string)
            .or_else(|| s("platform"))
            .unwrap_or_else(host),
        outcome,
        details,
        time: s("time").unwrap_or_else(now_rfc3339),
        device: a.device.to_string(),
        config: s("config"),
        extra,
    })
}

/// Hex public key for display.
pub fn public_hex(key: &SoftwareKey) -> String {
    to_hex(key.public_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> SignArgs<'static> {
        SignArgs {
            check: None,
            target: None,
            control: None,
            platform: Some("test"),
            default_build: None,
            device: "pc",
        }
    }

    #[test]
    fn a_result_files_reason_and_host_build_are_kept_where_the_kit_reads_them() {
        let v = serde_json::json!({
            "check": "phase0.thin-slice-cross-machine",
            "target": "pc-to-mac-lan",
            "control": "wrong-identity",
            "outcome": "FAIL",
            "details": "FAIL pair in person: refused",
            "build": "1111111+release",
            "host_build": "1111111+debug",
            "reason": "pin_mismatch",
        });
        let p = payload_from(&v, &args()).unwrap();
        assert_eq!(p.reason().as_deref(), Some("pin_mismatch"));
        assert_eq!(p.extra_str("host_build"), Some("1111111+debug"));
        assert_eq!(p.control.as_deref(), Some("wrong-identity"));

        // An object `details` with a reason inside it.
        let mut v = v;
        v.as_object_mut().unwrap().remove("reason");
        v["details"] = serde_json::json!({ "reason": "pin_mismatch", "step": "pair" });
        let p = payload_from(&v, &args()).unwrap();
        assert_eq!(p.reason().as_deref(), Some("pin_mismatch"));
        assert!(p.details.contains("\"step\""), "{}", p.details);
    }
}
