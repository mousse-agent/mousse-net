//! Phase manifests: `checks/<phase>.toml`.
//!
//! A manifest lists the checks a phase must pass. Each check names the plan
//! item it proves, the target cells it must pass on, how each cell is run
//! (a local command, a signed result from a device, or a manual step) and its
//! must-fail controls. See `checks/README.md` for the format.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use sha2::Digest;

/// One phase.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Phase name, the file stem: `phase0`.
    pub phase: String,
    pub title: String,
    /// Where the phase is defined (plan section).
    #[serde(default)]
    pub plan: String,
    /// Default build profile that device results must carry, if a check sets
    /// none. Empty: any profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Checks this phase allows to end DEFERRED, with the reason.
    #[serde(default)]
    pub defer: BTreeMap<String, String>,
    #[serde(rename = "check", default)]
    pub checks: Vec<Check>,
}

/// How a run's output is judged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Judge {
    /// `cargo test` summary lines (`test result: ok. N passed; ...`).
    #[default]
    CargoTest,
    /// A `PASS ...` line and exit 0; a control must print the `FAIL ...`
    /// line and exit non-zero.
    Marker,
    /// As `marker`, and the run must also write one result file per
    /// provider pair into `{out}` (crypto matrix format).
    Matrix,
}

/// One check.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// `<phase>.<name>`.
    pub id: String,
    pub title: String,
    /// The plan item this check proves.
    pub plan: String,
    /// Target cells. Every cell must pass.
    pub targets: Vec<String>,
    /// A manual step: cells can only be ATTESTED.
    #[serde(default)]
    pub manual: bool,
    /// What the person does, for manual checks.
    #[serde(default)]
    pub steps: Option<String>,
    /// How a device produces its result and control result, in plain words.
    #[serde(default)]
    pub device_steps: Option<String>,
    #[serde(default)]
    pub judge: Judge,
    #[serde(default)]
    pub pass_marker: Option<String>,
    #[serde(default)]
    pub fail_marker: Option<String>,
    /// For `cargo-test`: the normal run must pass at least this many tests,
    /// so a run that silently compiled the tests away does not pass.
    #[serde(default = "one")]
    pub min_tests: u64,
    /// Profile device results must carry (overrides the phase default).
    #[serde(default)]
    pub profile: Option<String>,
    /// The cell is one machine dialling another. Each result must name the
    /// host's build in `extra.host_build`, and both builds must be the
    /// build under test.
    #[serde(default)]
    pub cross_machine: bool,
    /// Not wired yet: every cell is INCOMPLETE with this reason, and
    /// `mousse-check <phase>` does not run it. `run` still does.
    #[serde(default)]
    pub placeholder: Option<String>,
    /// The check is deferred. Only counts if the phase's `[defer]` table
    /// lists it; otherwise every cell is FAIL.
    #[serde(default)]
    pub deferred: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Commands the kit runs itself, one per target cell it can fill.
    #[serde(default)]
    pub local: Vec<LocalRun>,
    /// Must-fail controls. Each one must make the check print FAIL.
    #[serde(default)]
    pub control: Vec<Control>,
    /// Crypto matrix settings (judge `matrix` and matrix device results).
    #[serde(default)]
    pub matrix: Option<MatrixSpec>,
}

fn one() -> u64 {
    1
}

fn default_timeout() -> u64 {
    3600
}

/// A command the kit runs for one target cell.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRun {
    pub target: String,
    /// `<os>-<arch>` of machines that can run it (`windows-x86_64`,
    /// `macos-aarch64`, `linux-x86_64`).
    pub host: String,
    pub command: Vec<String>,
    /// Working directory, relative to the repository root.
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Not wired yet on this target.
    #[serde(default)]
    pub placeholder: Option<String>,
}

/// A deliberately broken build of the same check.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub name: String,
    /// What is broken, in plain words.
    pub breaks: String,
    /// Replaces the local command.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Appended to the local command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Added to the local command's environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The control does not exist yet. The check is FAIL until it does.
    #[serde(default)]
    pub missing: Option<String>,
    /// The reason the control must fail with: a `reason=<this>` word on the
    /// FAIL line of a local run, or `extra.reason` (or `reason=<this>` in
    /// the details) of a device result. Failing for another reason is FAIL.
    #[serde(default)]
    pub expect_reason: Option<String>,
}

/// Crypto matrix cells: which provider pairs a cell must report.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixSpec {
    /// Providers on most targets; every ordered pair must be reported.
    pub providers: Vec<String>,
    /// Per-target provider lists.
    #[serde(default)]
    pub providers_for: BTreeMap<String, Vec<String>>,
    /// Folder of old unsigned result files, relative to the root. Shown in
    /// the details, never counted.
    #[serde(default)]
    pub legacy_results: Option<String>,
}

impl MatrixSpec {
    /// Every case (provider label) a target must report: `p` for a
    /// same-provider pair, `c>s` for a cross pair.
    pub fn cases(&self, target: &str) -> Vec<String> {
        let providers = self.providers_for.get(target).unwrap_or(&self.providers);
        let mut out = Vec::new();
        for c in providers {
            for s in providers {
                out.push(if c == s {
                    c.clone()
                } else {
                    format!("{c}>{s}")
                });
            }
        }
        out
    }
}

impl Check {
    /// The pass marker, default `PASS <id>`.
    pub fn pass_marker(&self) -> String {
        self.pass_marker
            .clone()
            .unwrap_or_else(|| format!("PASS {}", self.id))
    }

    /// The fail marker, default `FAIL <id>`.
    pub fn fail_marker(&self) -> String {
        self.fail_marker
            .clone()
            .unwrap_or_else(|| format!("FAIL {}", self.id))
    }

    /// The local run for `target`, if any.
    pub fn local_for(&self, target: &str) -> Option<&LocalRun> {
        self.local.iter().find(|l| l.target == target)
    }

    /// The local run for `target` on machines of kind `host`, if any.
    pub fn local_on(&self, target: &str, host: &str) -> Option<&LocalRun> {
        self.local
            .iter()
            .find(|l| l.target == target && l.host == host)
    }

    /// The control named `name`, if any.
    pub fn control_named(&self, name: &str) -> Option<&Control> {
        self.control.iter().find(|k| k.name == name)
    }

    /// Cases a device must report for `target`: the matrix pairs, or one
    /// unnamed case.
    pub fn cases(&self, target: &str) -> Vec<Option<String>> {
        match &self.matrix {
            Some(m) => m.cases(target).into_iter().map(Some).collect(),
            None => vec![None],
        }
    }
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let manifest: Manifest = toml::from_str(text).map_err(|e| e.to_string())?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn check(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    /// The profile device results for `c` must carry, if any.
    pub fn device_profile<'a>(&'a self, c: &'a Check) -> Option<&'a str> {
        c.profile.as_deref().or(self.profile.as_deref())
    }

    /// Digest of everything that decides what one run of `c` on `target`
    /// proves: the judge, test minimum, markers, profile, matrix cases, the
    /// local commands for that target (command, working directory, env) and,
    /// for a control, its command, args, env and expected reason. Local run
    /// records and signed results carry it; evidence with another digest
    /// was produced under another configuration and does not count.
    pub fn config_digest(&self, c: &Check, target: &str, control: Option<&Control>) -> String {
        let locals: Vec<serde_json::Value> = c
            .local
            .iter()
            .filter(|l| l.target == target)
            .map(|l| {
                serde_json::json!({
                    "host": l.host,
                    "command": l.command,
                    "cwd": l.cwd,
                    "env": l.env,
                })
            })
            .collect();
        let control = control.map(|k| {
            serde_json::json!({
                "name": k.name,
                "command": k.command,
                "args": k.args,
                "env": k.env,
                "expect_reason": k.expect_reason,
            })
        });
        let config = serde_json::json!({
            "format": "mousse-check-config-v1",
            "check": c.id,
            "target": target,
            "judge": format!("{:?}", c.judge),
            "min_tests": c.min_tests,
            "pass_marker": c.pass_marker(),
            "fail_marker": c.fail_marker(),
            "profile": self.device_profile(c),
            "cross_machine": c.cross_machine,
            "cases": c.cases(target),
            "local": locals,
            "control": control,
        });
        let text = serde_json::to_string(&config).unwrap_or_default();
        crate::util::to_hex(&sha2::Sha256::digest(text.as_bytes()))
    }

    /// Structural rules. Anything that would let a check pass without
    /// proving something is an error here.
    pub fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        let prefix = format!("{}.", self.phase);
        for c in &self.checks {
            if !ids.insert(c.id.as_str()) {
                return Err(format!("check id {} appears twice", c.id));
            }
            if !c.id.starts_with(&prefix) || c.id.len() == prefix.len() {
                return Err(format!("check id {} must start with {prefix}", c.id));
            }
            if c.id.contains(['/', '\\', ' ']) {
                return Err(format!("check id {} has a space or slash", c.id));
            }
            if c.plan.trim().is_empty() {
                return Err(format!(
                    "{}: says which plan item it proves (plan = ...)",
                    c.id
                ));
            }
            if c.targets.is_empty() {
                return Err(format!("{}: has no target cells", c.id));
            }
            let mut targets = BTreeSet::new();
            for t in &c.targets {
                if t.is_empty() || t.contains(['/', '\\', ' ']) {
                    return Err(format!("{}: bad target name {t:?}", c.id));
                }
                if !targets.insert(t.as_str()) {
                    return Err(format!("{}: target {t} appears twice", c.id));
                }
            }
            if c.manual {
                if !c.local.is_empty() || !c.control.is_empty() {
                    return Err(format!(
                        "{}: a manual check has no commands or controls; it can only be attested",
                        c.id
                    ));
                }
                if c.steps.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(format!("{}: a manual check needs steps", c.id));
                }
                continue;
            }
            for l in &c.local {
                if !targets.contains(l.target.as_str()) {
                    return Err(format!(
                        "{}: local run for unknown target {}",
                        c.id, l.target
                    ));
                }
                if l.command.is_empty() {
                    return Err(format!(
                        "{}: local run for {} has no command",
                        c.id, l.target
                    ));
                }
            }
            if let Some(want) = self.device_profile(c) {
                for l in &c.local {
                    let mut runs = vec![(String::from("the check"), effective_command(l, None))];
                    for k in c.control.iter().filter(|k| k.missing.is_none()) {
                        runs.push((format!("control {}", k.name), effective_command(l, Some(k))));
                    }
                    for (what, cmd) in runs {
                        match command_profile(&cmd) {
                            Some(p) if p == want => {}
                            got => {
                                return Err(format!(
                                    "{}: needs profile {want}, but {what} on {} builds {}; add --release or --profile {want} to the cargo command",
                                    c.id,
                                    l.target,
                                    got.as_deref().unwrap_or("with no profile the kit can see (not a cargo build, run or test)")
                                ))
                            }
                        }
                    }
                }
            }
            let mut seen = BTreeSet::new();
            for k in &c.control {
                if !seen.insert(k.name.as_str()) {
                    return Err(format!("{}: control {} appears twice", c.id, k.name));
                }
                if k.name.is_empty() || k.name == "normal" || k.name.contains(['/', '\\', ' ']) {
                    return Err(format!("{}: bad control name {:?}", c.id, k.name));
                }
                let changes_something =
                    k.command.is_some() || !k.args.is_empty() || !k.env.is_empty();
                if k.missing.is_none() && !changes_something && !c.local.is_empty() {
                    return Err(format!(
                        "{}: control {} runs the same command as the check; it cannot prove anything",
                        c.id, k.name
                    ));
                }
                if let Some(r) = &k.expect_reason {
                    if r.is_empty() || r.contains(|ch: char| ch.is_whitespace() || ch == ';') {
                        return Err(format!(
                            "{}: control {} expect_reason must be one word",
                            c.id, k.name
                        ));
                    }
                }
                if let Some(cmd) = &k.command {
                    if c.local.iter().any(|l| &l.command == cmd)
                        && k.args.is_empty()
                        && k.env.is_empty()
                    {
                        return Err(format!(
                            "{}: control {} command is the normal command",
                            c.id, k.name
                        ));
                    }
                }
            }
            match c.judge {
                Judge::Matrix if c.matrix.is_none() => {
                    return Err(format!(
                        "{}: judge = \"matrix\" needs a [check.matrix] table",
                        c.id
                    ));
                }
                _ => {}
            }
            if let (Some(p), Some(f)) = (&c.pass_marker, &c.fail_marker) {
                if p == f || p.is_empty() || f.is_empty() {
                    return Err(format!("{}: pass and fail markers must differ", c.id));
                }
            }
        }
        for id in self.defer.keys() {
            if self.check(id).is_none() {
                return Err(format!("[defer] names unknown check {id}"));
            }
        }
        Ok(())
    }
}

/// The command one run executes: the local command, or the control's
/// replacement, plus the control's args.
pub fn effective_command(local: &LocalRun, control: Option<&Control>) -> Vec<String> {
    let mut cmd = local.command.clone();
    if let Some(k) = control {
        if let Some(c) = &k.command {
            cmd = c.clone();
        }
        cmd.extend(k.args.iter().cloned());
    }
    cmd
}

/// The cargo profile a command builds with: `cargo [+toolchain] build | run
/// | test | bench` and its `--release`, `-r` or `--profile <name>` before any
/// `--`. `dev` is reported as `debug`, cargo's folder name for it. `None`
/// for anything else: the kit cannot see which profile a script uses.
pub fn command_profile(cmd: &[String]) -> Option<String> {
    let program = Path::new(cmd.first()?).file_stem()?.to_str()?;
    if !program.eq_ignore_ascii_case("cargo") {
        return None;
    }
    let mut args = cmd[1..]
        .iter()
        .map(String::as_str)
        .skip_while(|a| a.starts_with('+') || a.starts_with('-'));
    let mut profile = match args.next()? {
        "build" | "b" | "run" | "r" | "test" | "t" => "debug",
        "bench" => "release",
        _ => return None,
    }
    .to_string();
    while let Some(a) = args.next() {
        match a {
            "--" => break,
            "--release" | "-r" => profile = "release".into(),
            "--profile" => profile = args.next()?.to_string(),
            _ => {
                if let Some(p) = a.strip_prefix("--profile=") {
                    profile = p.to_string();
                }
            }
        }
    }
    if profile == "dev" {
        profile = "debug".into();
    }
    Some(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn the_profile_comes_from_the_cargo_command() {
        let p = |t: &str| command_profile(&words(t));
        assert_eq!(p("cargo test -p x").as_deref(), Some("debug"));
        assert_eq!(
            p("cargo run --release -p x -- --out y").as_deref(),
            Some("release")
        );
        assert_eq!(p("cargo +stable run -r -p x").as_deref(), Some("release"));
        assert_eq!(p("cargo build --profile ci").as_deref(), Some("ci"));
        assert_eq!(p("cargo build --profile=dev").as_deref(), Some("debug"));
        // After `--` the flags belong to the program, not to cargo.
        assert_eq!(p("cargo run -p x -- --release").as_deref(), Some("debug"));
        assert_eq!(
            p("C:/bin/cargo.exe test --release").as_deref(),
            Some("release")
        );
        assert_eq!(p("sh probe.sh"), None);
        assert_eq!(p("cargo fmt"), None);
    }

    #[test]
    fn a_check_that_needs_a_profile_must_build_with_it() {
        let text = |cmd: &str, control_args: &str| {
            BASE.replace("command = [\"cargo\", \"test\"]", cmd)
                .replace(
                    "title = \"test\"\n",
                    "title = \"test\"\nprofile = \"release\"\n",
                )
                + &format!(
                    "[[check.control]]\nname = \"k\"\nbreaks = \"x\"\nargs = {control_args}\n"
                )
        };
        // The label says release, the command builds debug.
        let err = Manifest::parse(&text(
            "command = [\"cargo\", \"test\"]",
            "[\"--features\", \"k\"]",
        ))
        .unwrap_err();
        assert!(err.contains("needs profile release"), "{err}");
        // A script: the kit cannot see the profile.
        assert!(Manifest::parse(&text("command = [\"sh\", \"t.sh\"]", "[\"--k\"]")).is_err());
        Manifest::parse(&text(
            "command = [\"cargo\", \"test\", \"--release\"]",
            "[\"--features\", \"k\"]",
        ))
        .unwrap();
    }

    const BASE: &str = r#"
phase = "phase9"
title = "test"
[[check]]
id = "phase9.a"
title = "a"
plan = "item"
targets = ["t1"]
[[check.local]]
target = "t1"
host = "windows-x86_64"
command = ["cargo", "test"]
"#;

    #[test]
    fn a_control_identical_to_the_check_is_refused() {
        let text = format!("{BASE}[[check.control]]\nname = \"same\"\nbreaks = \"nothing\"\n");
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.contains("same command"), "{err}");
        let text = format!(
            "{BASE}[[check.control]]\nname = \"same\"\nbreaks = \"nothing\"\ncommand = [\"cargo\", \"test\"]\n"
        );
        assert!(Manifest::parse(&text).is_err());
        let ok = format!(
            "{BASE}[[check.control]]\nname = \"f\"\nbreaks = \"x\"\nargs = [\"--features\", \"control-x\"]\n"
        );
        Manifest::parse(&ok).unwrap();
    }

    #[test]
    fn ids_targets_and_defer_entries_are_validated() {
        assert!(Manifest::parse(&BASE.replace("phase9.a", "other.a")).is_err());
        assert!(Manifest::parse(&BASE.replace("[\"t1\"]", "[\"t1\", \"t1\"]")).is_err());
        let with_defer = |id: &str| {
            BASE.replace(
                "title = \"test\"\n",
                &format!("title = \"test\"\n[defer]\n\"{id}\" = \"why\"\n"),
            )
        };
        assert!(Manifest::parse(&with_defer("phase9.zzz")).is_err());
        Manifest::parse(&with_defer("phase9.a")).unwrap();
    }

    #[test]
    fn matrix_cases_are_every_ordered_pair() {
        let m = MatrixSpec {
            providers: vec!["a".into(), "b".into()],
            providers_for: BTreeMap::from([("w".to_string(), vec!["a".to_string()])]),
            legacy_results: None,
        };
        assert_eq!(m.cases("x"), vec!["a", "a>b", "b>a", "b"]);
        assert_eq!(m.cases("w"), vec!["a"]);
    }
}
