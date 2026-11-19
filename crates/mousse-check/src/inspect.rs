//! `mousse-check relay-inspect`: what an operator checks on a self-hosted
//! relay (`phase3.inspect`). It compares the deployed binary's hash with a
//! local build, lists the state directory against the files the relay may
//! keep (spec/relay.md 12), and scans a relay log for anything that looks
//! like an address or an identifier. It never prints a secret.

use std::fmt::Write as _;
use std::path::Path;

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay::RelayId;
use sha2::{Digest, Sha256};

/// Files a relay's state directory may hold.
pub const STATE_FILES: &[&str] = &[
    "identity.key",
    "config.json",
    "authorized.json",
    "codes.json",
    "relay.lock",
    "state.lock",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file, as hex.
pub fn file_hash(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// The relay id from a state directory's identity key.
pub fn relay_id(state: &Path) -> Result<RelayId, String> {
    let path = state.join("identity.key");
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
    );
    let t = text.trim();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{}: not a relay identity key", path.display()));
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    for (i, b) in secret.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    let key = SoftwareKey::from_secret_bytes(&secret)
        .map_err(|_| format!("{}: not a P-256 key", path.display()))?;
    Ok(RelayId::of(&key.public_key()))
}

/// What one inspection found.
#[derive(Debug, Default)]
pub struct Report {
    /// Lines to print.
    pub lines: Vec<String>,
    /// Problems, each a short reason word and a description.
    pub problems: Vec<(&'static str, String)>,
}

impl Report {
    fn say(&mut self, line: String) {
        self.lines.push(line);
    }

    fn problem(&mut self, reason: &'static str, what: String) {
        self.lines.push(format!("PROBLEM {what}"));
        self.problems.push((reason, what));
    }
}

/// Inspect a state directory.
pub fn state_dir(state: &Path, r: &mut Report) {
    let entries = match std::fs::read_dir(state) {
        Ok(e) => e,
        Err(e) => {
            r.problem("state", format!("{}: {e}", state.display()));
            return;
        }
    };
    match relay_id(state) {
        Ok(id) => r.say(format!("relay id {}", hex(&id.0))),
        Err(e) => r.problem("state", e),
    }
    let mut names: Vec<(String, u64)> = entries
        .filter_map(Result::ok)
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    names.sort();
    for (name, size) in &names {
        if STATE_FILES.contains(&name.as_str()) {
            r.say(format!("state {name} {size} bytes"));
        } else {
            r.problem(
                "state",
                format!("state directory holds an unexpected file: {name}"),
            );
        }
    }
    for want in [
        "identity.key",
        "authorized.json",
        "codes.json",
        "config.json",
    ] {
        if !names.iter().any(|(n, _)| n == want) {
            r.problem("state", format!("state directory has no {want}"));
        }
    }
    let count = |file: &str| -> usize {
        std::fs::read(state.join(file))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
            .map_or(0, |v| v.len())
    };
    r.say(format!(
        "authorized keys {}, unused enrollment codes {}",
        count("authorized.json"),
        count("codes.json")
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, most) in [
            (state.to_path_buf(), 0o700),
            (state.join("identity.key"), 0o600),
        ] {
            if let Ok(m) = std::fs::metadata(&path) {
                let mode = m.permissions().mode() & 0o777;
                if mode & !most != 0 {
                    r.problem(
                        "state",
                        format!("{} is mode {mode:o}; at most {most:o}", path.display()),
                    );
                }
            }
        }
    }
}

/// Whether `word` looks like an IPv4 address (with an optional port).
fn looks_ipv4(word: &str) -> bool {
    let host = word.split(':').next().unwrap_or("");
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `word` looks like an IPv6 address.
fn looks_ipv6(word: &str) -> bool {
    let w = word.trim_start_matches('[');
    let w = w.split(']').next().unwrap_or(w);
    w.matches(':').count() >= 2 && w.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
}

/// Whether `word` holds a long run of hex or base64url (a key, handle or
/// fingerprint).
fn looks_identifier(word: &str) -> bool {
    let mut run = 0;
    for b in word.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Scan a relay log. The relay's own id and its listen address on the
/// startup line are allowed; anything else that looks like an address or
/// an identifier is a problem.
pub fn log(text: &str, relay: Option<&RelayId>, r: &mut Report) {
    let own = relay.map(|id| hex(&id.0));
    let mut flagged = 0;
    for (n, line) in text.lines().enumerate() {
        let startup = line.contains(" listening on ");
        let bad = line
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .any(|w| {
                let w = w.trim_matches(|c: char| "()\"'".contains(c));
                if Some(w) == own.as_deref() {
                    return false;
                }
                if startup && (looks_ipv4(w) || looks_ipv6(w)) {
                    return false;
                }
                looks_ipv4(w) || looks_ipv6(w) || looks_identifier(w)
            });
        if bad {
            flagged += 1;
            r.problem(
                "log",
                format!("log line {} names an address or identifier", n + 1),
            );
        }
    }
    r.say(format!(
        "log {} lines, {flagged} flagged",
        text.lines().count()
    ));
}

/// The whole inspection.
pub fn run(
    state: &Path,
    deployed: Option<&Path>,
    local: Option<&Path>,
    log_file: Option<&Path>,
) -> Report {
    let mut r = Report::default();
    match (deployed, local) {
        (Some(d), Some(l)) => match (file_hash(d), file_hash(l)) {
            (Ok(a), Ok(b)) => {
                r.say(format!("deployed {a}"));
                r.say(format!("local    {b}"));
                if a != b {
                    r.problem(
                        "hash",
                        "the deployed binary differs from the local build".into(),
                    );
                }
            }
            (Err(e), _) | (_, Err(e)) => r.problem("hash", e),
        },
        (Some(d), None) => match file_hash(d) {
            Ok(a) => r.say(format!("deployed {a} (no local build to compare)")),
            Err(e) => r.problem("hash", e),
        },
        _ => {}
    }
    state_dir(state, &mut r);
    if let Some(path) = log_file {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let id = relay_id(state).ok();
                log(&text, id.as_ref(), &mut r);
            }
            Err(e) => r.problem("log", format!("{}: {e}", path.display())),
        }
    }
    r
}

/// The report as text, ending with `PASS relay-inspect` or `FAIL
/// relay-inspect reason=<first problem>`.
pub fn render(r: &Report) -> String {
    let mut out = String::new();
    for l in &r.lines {
        let _ = writeln!(out, "{l}");
    }
    match r.problems.first() {
        None => out.push_str("PASS relay-inspect\n"),
        Some((reason, _)) => {
            let _ = writeln!(out, "FAIL relay-inspect reason={reason}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        let d = std::env::temp_dir().join(format!("relay-inspect-{}", hex(&b)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_clean_state_directory_passes_and_extra_files_or_leaky_logs_fail() {
        let d = dir();
        std::fs::write(d.join("identity.key"), format!("{}\n", "11".repeat(32))).unwrap();
        std::fs::write(d.join("config.json"), "{\"public\": \"203.0.113.5:443\"}").unwrap();
        std::fs::write(d.join("authorized.json"), "[{\"fingerprint\": \"aa\"}]").unwrap();
        std::fs::write(d.join("codes.json"), "[]").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(
                d.join("identity.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let id = relay_id(&d).unwrap();
        let clean_log = format!(
            "mousse-relay: relay {} listening on 0.0.0.0:443\nmousse-relay: stopping\n",
            hex(&id.0)
        );
        let log_path = d.join("..").join(format!("{}.log", hex(&id.0[..4])));
        std::fs::write(&log_path, &clean_log).unwrap();
        let r = run(&d, None, None, Some(&log_path));
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        let text = render(&r);
        assert!(text.ends_with("PASS relay-inspect\n"), "{text}");
        assert!(
            !text.contains(&"11".repeat(32)),
            "the secret key was printed"
        );

        std::fs::write(
            &log_path,
            format!("{clean_log}call from 198.51.100.7 to {}\n", "ab".repeat(32)),
        )
        .unwrap();
        let r = run(&d, None, None, Some(&log_path));
        assert_eq!(r.problems.len(), 1);
        assert!(render(&r).ends_with("FAIL relay-inspect reason=log\n"));

        std::fs::write(d.join("allow-sets.json"), "{}").unwrap();
        let r = run(&d, None, None, None);
        assert_eq!(r.problems[0].0, "state");

        let a = d.join("identity.key");
        let b = d.join("config.json");
        let r = run(&d, Some(&a), Some(&b), None);
        assert_eq!(r.problems[0].0, "hash");
        let _ = std::fs::remove_file(&log_path);
        let _ = std::fs::remove_dir_all(&d);
    }
}
