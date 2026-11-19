//! `mousse-check hosted verify`: count a GitHub-hosted run (the
//! `windows-11-arm` smoke of `phase1b.desktop-builds`) only after checking
//! its artifact.
//!
//! The workflow (`.github/workflows/windows-arm-smoke.yml`) uploads one
//! artifact holding `hosted.json` (`engine_commit`, `app_build`,
//! `helper_sha256`), `smoke.log`, one `control-<name>.log` per control, and
//! the helper it smoked. Verification:
//!
//! 1. the archive's SHA-256 is the digest GitHub reports for the artifact
//!    (`--digest sha256:<hex>`);
//! 2. the engine commit is the build under test, and the app build is the
//!    revision pinned in `app/MOUSSE_REVISION` (for an app check);
//! 3. the helper in the archive has the SHA-256 `hosted.json` names;
//! 4. `smoke.log` ends `PASS <check>`, and each control's log ends
//!    `FAIL <check> reason=<word>`, the control's `expect_reason`.
//!
//! Then one record per run goes to `checks/results/hosted/`, with the
//! configuration digest of this checkout's manifest. The cell counts them
//! like device results and shows them as hosted. Nothing is signed.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::evidence::{file_part, HostedRecord, HOSTED_FORMAT};
use crate::manifest::{Check, Manifest};
use crate::util::{now_rfc3339, to_hex};

/// What the workflow wrote about its run.
#[derive(Debug, Deserialize)]
pub struct HostedRun {
    pub engine_commit: String,
    #[serde(default)]
    pub app_build: Option<String>,
    pub helper_sha256: String,
    /// The helper's file name inside the archive.
    pub helper: String,
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(to_hex(&Sha256::digest(&bytes)))
}

/// Unpack a zip archive into `dir` with the system `tar` (bsdtar reads zip
/// on Windows and macOS) or `unzip`.
fn unpack(zip: &Path, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tar = Command::new("tar")
        .arg("-xf")
        .arg(zip)
        .arg("-C")
        .arg(dir)
        .status();
    if matches!(tar, Ok(s) if s.success()) {
        return Ok(());
    }
    let unzip = Command::new("unzip")
        .arg("-q")
        .arg("-o")
        .arg(zip)
        .arg("-d")
        .arg(dir)
        .status();
    match unzip {
        Ok(s) if s.success() => Ok(()),
        _ => Err(format!(
            "cannot unpack {} (tar and unzip failed)",
            zip.display()
        )),
    }
}

/// The last non-empty line of a log.
fn last_line(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .to_owned())
}

/// What `verify` was given.
pub struct VerifyArgs<'a> {
    pub check: &'a Check,
    pub manifest: &'a Manifest,
    pub target: &'a str,
    pub zip: &'a Path,
    pub digest: &'a str,
    pub run: &'a str,
    /// The commit under test.
    pub commit: &'a str,
    /// The pinned app revision, if any.
    pub app_revision: Option<&'a str>,
    /// Where the records go (`checks/results/hosted`).
    pub out: &'a Path,
    pub scratch: &'a Path,
}

/// Check the artifact and write the records. Returns their paths.
pub fn verify(a: &VerifyArgs<'_>) -> Result<Vec<PathBuf>, String> {
    let c = a.check;
    if !c.hosted.iter().any(|h| h == a.target) {
        return Err(format!(
            "{} does not run {} on a hosted runner",
            c.id, a.target
        ));
    }
    let want = a
        .digest
        .strip_prefix("sha256:")
        .ok_or("--digest is sha256:<hex>, as GitHub reports it")?
        .to_ascii_lowercase();
    let got = sha256_file(a.zip)?;
    if got != want {
        return Err(format!(
            "the archive's SHA-256 is {got}, GitHub reports {want}"
        ));
    }
    let _ = std::fs::remove_dir_all(a.scratch);
    unpack(a.zip, a.scratch)?;
    record_unpacked(a, &want)
}

/// Steps 2 to 4 on an unpacked artifact in `a.scratch` whose archive had
/// SHA-256 `digest_hex`.
pub fn record_unpacked(a: &VerifyArgs<'_>, digest_hex: &str) -> Result<Vec<PathBuf>, String> {
    let c = a.check;
    let want = digest_hex.to_owned();
    let run: HostedRun = serde_json::from_str(
        &std::fs::read_to_string(a.scratch.join("hosted.json"))
            .map_err(|e| format!("hosted.json: {e}"))?,
    )
    .map_err(|e| format!("hosted.json: {e}"))?;
    if run.engine_commit != a.commit {
        return Err(format!(
            "the run smoked engine commit {}, the build under test is {}",
            run.engine_commit, a.commit
        ));
    }
    if c.app && run.app_build.as_deref() != a.app_revision {
        return Err(format!(
            "the run used app build {}, app/MOUSSE_REVISION pins {}",
            run.app_build.as_deref().unwrap_or("(none)"),
            a.app_revision.unwrap_or("(nothing)")
        ));
    }
    if run.helper.contains(['/', '\\']) || run.helper.contains("..") {
        return Err("hosted.json names a helper outside the archive".into());
    }
    let helper_hash = sha256_file(&a.scratch.join(&run.helper))?;
    if helper_hash != run.helper_sha256.to_ascii_lowercase() {
        return Err(format!(
            "the helper in the archive has SHA-256 {helper_hash}, hosted.json says {}",
            run.helper_sha256
        ));
    }
    let build = format!("{}+release", run.engine_commit);
    let record = |control: Option<&str>, outcome: &str, reason: Option<String>, details: String| {
        let k = control.and_then(|n| c.control_named(n));
        HostedRecord {
            format: HOSTED_FORMAT.into(),
            check: c.id.clone(),
            target: a.target.into(),
            control: control.map(str::to_owned),
            outcome: outcome.into(),
            reason,
            details,
            build: build.clone(),
            app_build: run.app_build.clone(),
            config: a.manifest.config_digest(c, a.target, k),
            run: a.run.into(),
            artifact_digest: format!("sha256:{want}"),
            helper_sha256: helper_hash.clone(),
            time: now_rfc3339(),
        }
    };
    let mut records = Vec::new();
    let normal = last_line(&a.scratch.join("smoke.log"))?;
    if normal != format!("PASS {}", c.id) {
        return Err(format!("smoke.log does not end PASS {}: {normal:?}", c.id));
    }
    records.push(record(None, "PASS", None, normal));
    for k in &c.control {
        let line = last_line(&a.scratch.join(format!("control-{}.log", k.name)))?;
        let prefix = format!("FAIL {} ", c.id);
        let reason = line
            .strip_prefix(&prefix)
            .and_then(|r| r.split_whitespace().find_map(|w| w.strip_prefix("reason=")))
            .map(str::to_owned);
        if reason.is_none()
            || k.expect_reason
                .as_ref()
                .is_some_and(|w| reason.as_ref() != Some(w))
        {
            return Err(format!(
                "control {} did not fail as required on the hosted run: {line:?}",
                k.name
            ));
        }
        records.push(record(Some(&k.name), "FAIL", reason, line));
    }
    std::fs::create_dir_all(a.out).map_err(|e| e.to_string())?;
    let mut paths = Vec::new();
    for r in records {
        let path = a.out.join(format!(
            "{}__{}__{}__{}.json",
            file_part(&r.check),
            file_part(&r.target),
            file_part(r.control.as_deref().unwrap_or("normal")),
            file_part(&r.time.replace(':', ""))
        ));
        let text = serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?;
        std::fs::write(&path, text + "\n").map_err(|e| format!("{}: {e}", path.display()))?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = r#"
phase = "phase9"
title = "t"
plan = "p"

[[check]]
id = "phase9.builds"
title = "builds"
plan = "x"
targets = ["windows-arm64"]
judge = "marker"
hosted = ["windows-arm64"]

[[check.control]]
name = "stale-helper"
breaks = "stale"
env = { MOUSSE_BUILD_ID = "0000000+release" }
expect_reason = "stale_helper"
"#;

    fn artifact(dir: &Path, control_line: &str, helper_hash: Option<&str>) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("mousse-helper.exe"), b"helper bytes").unwrap();
        let hash = helper_hash
            .map(str::to_owned)
            .unwrap_or_else(|| to_hex(&Sha256::digest(b"helper bytes")));
        std::fs::write(
            dir.join("hosted.json"),
            format!(r#"{{"engine_commit":"abc","app_build":null,"helper_sha256":"{hash}","helper":"mousse-helper.exe"}}"#),
        )
        .unwrap();
        std::fs::write(
            dir.join("smoke.log"),
            "probe: PASS smoke-probe\nPASS phase9.builds\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("control-stale-helper.log"),
            format!("note: x\n{control_line}\n"),
        )
        .unwrap();
    }

    fn run(dir: &Path, out: &Path, commit: &str) -> Result<Vec<PathBuf>, String> {
        let m = Manifest::parse(M).unwrap();
        let c = m.check("phase9.builds").unwrap().clone();
        record_unpacked(
            &VerifyArgs {
                check: &c,
                manifest: &m,
                target: "windows-arm64",
                zip: Path::new("unused"),
                digest: "sha256:ff",
                run: "https://example.invalid/run/1",
                commit,
                app_revision: None,
                out,
                scratch: dir,
            },
            "ff",
        )
    }

    #[test]
    fn a_verified_artifact_writes_one_record_per_run_and_anything_off_writes_none() {
        let base = std::env::temp_dir().join(format!("mousse-hosted-{}", std::process::id()));
        let (dir, out) = (base.join("a"), base.join("out"));
        artifact(&dir, "FAIL phase9.builds reason=stale_helper", None);
        let paths = run(&dir, &out, "abc").unwrap();
        assert_eq!(paths.len(), 2);
        let text = std::fs::read_to_string(&paths[1]).unwrap();
        let r: HostedRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (r.outcome.as_str(), r.reason.as_deref()),
            ("FAIL", Some("stale_helper"))
        );
        assert_eq!(r.build, "abc+release");

        // Another commit, a control failing for another reason, or a helper
        // that is not the one named: nothing is recorded.
        assert!(run(&dir, &base.join("o2"), "def").is_err());
        artifact(&dir, "FAIL phase9.builds reason=probe_failed", None);
        assert!(run(&dir, &base.join("o3"), "abc").is_err());
        artifact(
            &dir,
            "FAIL phase9.builds reason=stale_helper",
            Some(&"0".repeat(64)),
        );
        assert!(run(&dir, &base.join("o4"), "abc").is_err());
        assert!(
            !base.join("o2").exists() && !base.join("o3").exists() && !base.join("o4").exists()
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
