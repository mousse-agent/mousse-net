//! `tools/build-smoke.mjs`: the helper it smokes must be a release build of
//! the build under test with no control, or the run fails with
//! `stale_helper` (the `stale-helper` control of `phase1b.desktop-builds`).
//! The full smoke builds release binaries; it runs as the check itself.
//! Needs `node` on the path.

use std::path::Path;
use std::process::Command;

#[test]
fn only_a_release_build_of_the_build_under_test_passes_the_version_check() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/build-smoke.mjs");
    let url = format!(
        "file:///{}",
        script
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches("//?/")
            .trim_start_matches('/')
    );
    let code = format!(
        r#"
const {{ staleWhy, parseVersion }} = await import({url:?})
const ok = 'mousse-helper 0.1.0 build abc123+release control none'
const checks = [
  [staleWhy(ok, 'abc123'), undefined],
  [typeof staleWhy(ok, '0000000'), 'string'],
  [typeof staleWhy('mousse-helper 0.1.0 build abc123+debug control none', 'abc123'), 'string'],
  [typeof staleWhy('mousse-helper 0.1.0 build abc123+release control admit-ungranted', 'abc123'), 'string'],
  [typeof staleWhy('garbage', 'abc123'), 'string'],
  [parseVersion('x build abc-dirty+release control none').commit, 'abc-dirty'],
]
const bad = checks.findIndex(([got, want]) => got !== want)
if (bad >= 0) {{ console.error('case', bad, checks[bad]); process.exit(1) }}
console.log('ok')
"#
    );
    let o = Command::new("node")
        .args(["--input-type=module", "-e", &code])
        .output()
        .expect("node runs");
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}
