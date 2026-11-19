//! App checks: checks that run the Mousse app against the engine.
//!
//! The engine repository pins the app revision it is tested with in
//! `app/MOUSSE_REVISION` (one full commit hash). That file is outside
//! `checks/`, so changing it changes the build under test. A check with
//! `app = true`:
//!
//! - runs only if `MOUSSE_APP_DIR` is a clean checkout of the app at that
//!   revision ([`check_checkout`]);
//! - counts a run or a signed result only if it names that app build:
//!   `app_build` (the app checkout's commit, printed by the app's check
//!   script as an `app_build=<commit>[-dirty]` line) and, for a
//!   cross-machine cell, `host_app_build` too ([`app_build_counts`]).

use std::path::Path;
use std::process::Command;

/// The pin, relative to the repository root.
pub const REVISION_FILE: &str = "app/MOUSSE_REVISION";

/// The environment variable naming the app checkout.
pub const APP_DIR_ENV: &str = "MOUSSE_APP_DIR";

/// A full commit hash (40 or 64 hex digits), lowercased.
pub fn parse_revision(text: &str) -> Result<String, String> {
    let rev = text.trim().to_ascii_lowercase();
    if !matches!(rev.len(), 40 | 64) || !rev.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{REVISION_FILE} must hold one full app commit hash, not {:?}",
            text.trim()
        ));
    }
    Ok(rev)
}

/// The pinned app revision of the checkout at `root`.
pub fn read_revision(root: &Path) -> Result<String, String> {
    let path = root.join(REVISION_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_revision(&text)
}

/// Why `dir` is not a clean app checkout at `revision`.
pub fn check_checkout(dir: &Path, revision: &str) -> Result<(), String> {
    let git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{} is not a git checkout of the app ({})",
                dir.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let head = git(&["rev-parse", "HEAD"])?.trim().to_ascii_lowercase();
    if head != revision {
        return Err(format!(
            "the app checkout {} is at {head}, {REVISION_FILE} pins {revision}",
            dir.display()
        ));
    }
    let status = git(&["status", "--porcelain"])?;
    if let Some(first) = status.lines().find(|l| !l.trim().is_empty()) {
        return Err(format!(
            "the app checkout {} has uncommitted changes ({})",
            dir.display(),
            first.trim()
        ));
    }
    Ok(())
}

/// The value of the first `<key>=<value>` line in `text`.
pub fn line_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.trim().strip_prefix(key)?.strip_prefix('=')?.trim();
        (!v.is_empty() && !v.contains(char::is_whitespace)).then(|| v.to_string())
    })
}

/// Why a claimed app build does not count. `revision` is the pin, `None` if
/// it is missing or unreadable.
pub fn app_build_counts(claimed: Option<&str>, revision: Option<&str>) -> Result<(), String> {
    let revision =
        revision.ok_or_else(|| format!("{REVISION_FILE} is missing or not a full commit"))?;
    let claimed = claimed.ok_or("names no app build (app_build)")?;
    if claimed.ends_with("-dirty") {
        return Err(format!("app build {claimed} is from a dirty app checkout"));
    }
    if !claimed.eq_ignore_ascii_case(revision) {
        return Err(format!(
            "app build {claimed}, {REVISION_FILE} pins {revision}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "14912a18a2915bc53178597cbc2e9c08441d8fab";

    #[test]
    fn the_pin_is_one_full_commit() {
        assert_eq!(parse_revision(&format!("{REV}\n")).unwrap(), REV);
        assert_eq!(parse_revision(&REV.to_uppercase()).unwrap(), REV);
        assert!(parse_revision("14912a18a").is_err());
        assert!(parse_revision("").is_err());
        assert!(parse_revision(&format!("{REV} {REV}")).is_err());
    }

    #[test]
    fn only_the_pinned_clean_app_build_counts() {
        fn ok(claimed: Option<&str>) -> Result<(), String> {
            app_build_counts(claimed, Some(REV))
        }
        ok(Some(REV)).unwrap();
        ok(Some(&REV.to_uppercase())).unwrap();
        assert!(ok(None).unwrap_err().contains("app_build"));
        assert!(ok(Some(&format!("{REV}-dirty")))
            .unwrap_err()
            .contains("dirty"));
        assert!(ok(Some("14912a18a")).is_err());
        assert!(ok(Some(&"2".repeat(40))).unwrap_err().contains("pins"));
        assert!(app_build_counts(Some(REV), None)
            .unwrap_err()
            .contains(REVISION_FILE));
    }

    #[test]
    fn the_app_build_is_read_from_its_own_line() {
        let out = format!("noise app_build=x\napp_build={REV}\nhelper=fake\nPASS a\n");
        assert_eq!(line_value(&out, "app_build").as_deref(), Some(REV));
        assert_eq!(line_value(&out, "host_app_build"), None);
        assert_eq!(line_value("app_build=\n", "app_build"), None);
        assert_eq!(line_value("app_builds=x\n", "app_build"), None);
    }
}
