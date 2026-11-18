//! The build under test: a source commit, a dirty flag and a profile.
//!
//! The source commit is the last commit that changed anything outside
//! `checks/`. Committing result files, attestations, manifests or the
//! device list does not change the build, so evidence can be committed
//! without making itself stale. A manifest change still makes evidence for
//! the changed check stale: every run record and signed result carries a
//! digest of the check's configuration (`Manifest::config_digest`), and
//! evidence with another digest does not count. The dirty flag covers every uncommitted
//! change except `checks/results/` and `checks/runs/` (evidence and local
//! run records): an uncommitted manifest or device-list edit makes the tree
//! dirty.
//!
//! Text form: `<commit>[-dirty]+<profile>`, the same shape the crypto matrix
//! spike writes (`7fca58b75+release`).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// One build identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildId {
    /// Git commit, full or abbreviated (at least 7 hex digits).
    pub commit: String,
    pub dirty: bool,
    pub profile: String,
}

impl BuildId {
    /// Parse `<commit>[-dirty]+<profile>`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (head, profile) = text
            .rsplit_once('+')
            .ok_or_else(|| format!("build id {text:?} has no +profile"))?;
        let (commit, dirty) = match head.strip_suffix("-dirty") {
            Some(c) => (c, true),
            None => match head.strip_suffix("+dirty") {
                Some(c) => (c, true),
                None => (head, false),
            },
        };
        if commit.len() < 7 || commit.len() > 64 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "build id {text:?} does not start with a git commit"
            ));
        }
        if profile.is_empty()
            || !profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("build id {text:?} has an unreadable profile"));
        }
        Ok(Self {
            commit: commit.to_ascii_lowercase(),
            dirty,
            profile: profile.to_string(),
        })
    }
}

impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}+{}",
            self.commit,
            if self.dirty { "-dirty" } else { "" },
            self.profile
        )
    }
}

/// The checkout the kit runs in.
#[derive(Clone, Debug)]
pub struct BuildState {
    /// Full source commit (see the module docs).
    pub commit: String,
    /// Uncommitted changes outside the evidence folders.
    pub dirty: bool,
    /// Up to a few dirty paths, for the report.
    pub dirty_paths: Vec<String>,
}

impl BuildState {
    pub fn id(&self, profile: &str) -> BuildId {
        BuildId {
            commit: self.commit.clone(),
            dirty: self.dirty,
            profile: profile.to_string(),
        }
    }

    /// Short form for display.
    pub fn short(&self) -> String {
        format!(
            "{}{}",
            &self.commit[..self.commit.len().min(12)],
            if self.dirty { "-dirty" } else { "" }
        )
    }
}

/// Maps any commit to its source commit.
pub trait Commits {
    /// The source commit of `rev`, or `None` if `rev` is unknown here.
    fn source_commit(&self, rev: &str) -> Option<String>;
}

/// Pathspec for "everything that is part of the build".
const SOURCE_PATHSPEC: &[&str] = &["--", ".", ":(exclude)checks"];

/// Pathspec for dirty detection.
const DIRTY_PATHSPEC: &[&str] = &[
    "--",
    ".",
    ":(exclude)checks/results",
    ":(exclude)checks/runs",
];

/// Git in one repository, with lookups cached.
pub struct Git {
    root: PathBuf,
    cache: Mutex<HashMap<String, Option<String>>>,
}

impl Git {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The repository root containing `start`.
    pub fn find_root(start: &Path) -> Result<PathBuf, String> {
        let out = run_git(start, &["rev-parse", "--show-toplevel"])
            .ok_or_else(|| format!("{} is not inside a git checkout", start.display()))?;
        Ok(PathBuf::from(out))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The state of the checkout now.
    pub fn state(&self) -> Result<BuildState, String> {
        let commit = self
            .source_commit("HEAD")
            .ok_or("cannot read the HEAD commit (no commits yet?)")?;
        let mut args = vec!["status", "--porcelain", "--untracked-files=all"];
        args.extend_from_slice(DIRTY_PATHSPEC);
        let status = run_git_raw(&self.root, &args).ok_or("git status failed")?;
        let paths: Vec<String> = status
            .lines()
            .filter(|l| l.len() > 3)
            .map(|l| l[3..].to_string())
            .collect();
        Ok(BuildState {
            commit,
            dirty: !paths.is_empty(),
            dirty_paths: paths.into_iter().take(5).collect(),
        })
    }

    /// `git config user.name`, if set.
    pub fn user_name(&self) -> Option<String> {
        run_git(&self.root, &["config", "user.name"]).filter(|s| !s.is_empty())
    }
}

impl Commits for Git {
    fn source_commit(&self, rev: &str) -> Option<String> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(rev) {
                return hit.clone();
            }
        }
        let full = run_git(
            &self.root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{rev}^{{commit}}"),
            ],
        );
        let source = full.and_then(|full| {
            let mut args = vec!["log", "-1", "--format=%H", full.as_str()];
            args.extend_from_slice(SOURCE_PATHSPEC);
            run_git(&self.root, &args).filter(|s| !s.is_empty())
        });
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(rev.to_string(), source.clone());
        }
        source
    }
}

fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    run_git_raw(dir, args).map(|s| s.trim().to_string())
}

fn run_git_raw(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Why a claimed build does not count as the build under test.
pub fn check_build(
    commits: &dyn Commits,
    current: &BuildState,
    claimed: &str,
    expected_profile: Option<&str>,
    allow_dirty: bool,
) -> Result<BuildId, String> {
    let id = BuildId::parse(claimed)?;
    if id.dirty && !allow_dirty {
        return Err(format!("built from a dirty tree ({claimed})"));
    }
    if let Some(p) = expected_profile {
        if id.profile != p {
            return Err(format!(
                "built with profile {}, this check needs {p}",
                id.profile
            ));
        }
    }
    match commits.source_commit(&id.commit) {
        None => Err(format!(
            "built from commit {} which is not in this checkout (fetch it?)",
            id.commit
        )),
        Some(source) if source != current.commit => Err(format!(
            "built from {}, the build under test is {}",
            &source[..source.len().min(12)],
            &current.commit[..current.commit.len().min(12)]
        )),
        Some(_) => Ok(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_spike_format_and_round_trips() {
        let id = BuildId::parse("7fca58b75+release").unwrap();
        assert_eq!(id.commit, "7fca58b75");
        assert!(!id.dirty);
        assert_eq!(id.profile, "release");
        let dirty = BuildId::parse("7fca58b75-dirty+debug").unwrap();
        assert!(dirty.dirty);
        assert_eq!(dirty.to_string(), "7fca58b75-dirty+debug");
        assert!(BuildId::parse("7fca58b75").is_err());
        assert!(BuildId::parse("main+release").is_err());
        assert!(BuildId::parse("abc+release").is_err());
    }
}
