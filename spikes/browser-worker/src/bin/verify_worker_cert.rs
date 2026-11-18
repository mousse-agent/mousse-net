//! Native verifier for the browser Worker spike.
//!
//! Reads the transcript the browser runner collected (three Worker runs:
//! first, after a Worker restart, after clearing site data), checks every
//! certificate with `mousse_net_core::session_cert::verify`, runs the
//! negative cases, prints one line per check and a final
//! `PASS phase0.browser-worker-cert` or `FAIL phase0.browser-worker-cert`, and
//! writes a result JSON that `mousse-check sign` accepts.
//!
//! Usage:
//!   verify-worker-cert --transcript <file> --build <id> --out <file>
//!       [--control <name>] [--break skip-pin] [--vector-out <file>]
//!
//! `--break skip-pin` is a must-fail control on the verifier itself: the pin
//! is never passed, so the wrong-pin case is accepted and the run must FAIL.
#![deny(unsafe_code)]

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use browser_worker::{from_hex, to_hex, CHECK_ID};
use mousse_net_core::identity::{PublicKey, SoftwareKey};
use mousse_net_core::session_cert::{self, CertError, VerifiedSessionCert};
use mousse_net_core::time::UnixTime;
use serde_json::{json, Value};

struct Args {
    transcript: String,
    build: String,
    out: String,
    control: Option<String>,
    skip_pin: bool,
    vector_out: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut transcript, mut build, mut out) = (None, None, None);
    let (mut control, mut skip_pin, mut vector_out) = (None, false, None);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--transcript" => transcript = Some(value()?),
            "--build" => build = Some(value()?),
            "--out" => out = Some(value()?),
            "--control" => control = Some(value()?),
            "--vector-out" => vector_out = Some(value()?),
            "--break" => match value()?.as_str() {
                "skip-pin" => skip_pin = true,
                // Worker-side breaks are applied in the browser; nothing to do here.
                "none" | "tampered-cert" | "fresh-key" | "der-signature" => {}
                other => return Err(format!("unknown break {other}")),
            },
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        transcript: transcript.ok_or("--transcript is required")?,
        build: build.ok_or("--build is required")?,
        out: out.ok_or("--out is required")?,
        control,
        skip_pin,
        vector_out,
    })
}

/// One line of the report.
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

struct Report(Vec<Check>);

impl Report {
    fn add(&mut self, name: &'static str, ok: bool, detail: impl Into<String>) {
        self.0.push(Check {
            name,
            ok,
            detail: detail.into(),
        });
    }

    fn passed(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|c| c.ok)
    }
}

fn code(r: &Result<VerifiedSessionCert, CertError>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code().into(),
    }
}

fn bytes(run: &Value, key: &str) -> Result<Vec<u8>, String> {
    let text = run
        .get(key)
        .and_then(Value::as_str)
        .ok_or(format!("{key} missing"))?;
    from_hex(text).map_err(|e| format!("{key}: {e}"))
}

fn find<'a>(runs: &'a [Value], phase: &str) -> Option<&'a Value> {
    runs.iter()
        .find(|r| r.get("phase").and_then(Value::as_str) == Some(phase))
}

fn worker_ok(report: &mut Report, name: &'static str, run: Option<&Value>) -> bool {
    match run {
        None => {
            report.add(name, false, "no Worker run");
            false
        }
        Some(r) if r.get("ok").and_then(Value::as_bool) != Some(true) => {
            let why = r.get("error").and_then(Value::as_str).unwrap_or("unknown");
            report.add(name, false, format!("Worker failed: {why}"));
            false
        }
        Some(_) => true,
    }
}

fn verify_hex(run: &Value, key: &str, now: UnixTime, pin: Option<&PublicKey>) -> String {
    match bytes(run, key) {
        Ok(der) => code(&session_cert::verify(&der, now, pin)),
        Err(e) => format!("unreadable ({e})"),
    }
}

fn evaluate(t: &Value, skip_pin: bool, now: UnixTime) -> (Report, Option<PublicKey>) {
    let mut report = Report(Vec::new());
    let runs = t
        .get("runs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let pin_for = |p: &PublicKey| if skip_pin { None } else { Some(*p) };

    // 1. First Worker: a fresh WebCrypto identity key.
    let first = find(&runs, "first");
    if !worker_ok(&mut report, "first-worker", first) {
        return (report, None);
    }
    let first = first.expect("checked");
    let pin = match bytes(first, "identity_key").and_then(|k| {
        PublicKey::from_sec1(&k).map_err(|e| format!("identity key: {e}"))
    }) {
        Ok(k) => k,
        Err(e) => {
            report.add("identity-key", false, e);
            return (report, None);
        }
    };
    report.add(
        "identity-key-non-extractable",
        first.get("extractable") == Some(&json!(false))
            && first.get("export_refused") == Some(&json!(true)),
        format!(
            "extractable={}, pkcs8 export refused={}",
            first.get("extractable").unwrap_or(&Value::Null),
            first.get("export_refused").unwrap_or(&Value::Null)
        ),
    );
    report.add(
        "webcrypto-signature-raw",
        first.get("webcrypto_signature_len") == Some(&json!(64)),
        format!(
            "WebCrypto ECDSA signature is {} bytes (raw r||s is 64)",
            first.get("webcrypto_signature_len").unwrap_or(&Value::Null)
        ),
    );
    report.add(
        "finish-refuses-der",
        first.get("finish_refuses_der") == Some(&json!(true)),
        format!(
            "PendingCertificate::finish with a DER signature: {}",
            first
                .get("finish_der_error")
                .and_then(Value::as_str)
                .unwrap_or("accepted")
        ),
    );
    let pinned = pin_for(&pin);
    let r1 = verify_hex(first, "certificate", now, pinned.as_ref());
    report.add(
        "first-certificate-accepted",
        r1 == "ok",
        format!("verify(first certificate, pin = Worker identity) = {r1}"),
    );

    // 2. Negative cases on the first Worker's output.
    match bytes(first, "certificate") {
        Ok(mut der) => {
            // Flip one bit in the last byte of tbsCertificate's identity signature.
            let at = browser_worker::splice::identity_signature_field(&der)
                .ok()
                .and_then(|field| {
                    der.windows(field.len())
                        .position(|w| w == field.as_slice())
                        .map(|p| p + field.len() - 1)
                });
            match at {
                Some(i) => {
                    der[i] ^= 0x01;
                    let r = code(&session_cert::verify(&der, now, pinned.as_ref()));
                    report.add(
                        "negative-tampered",
                        r != "ok",
                        format!("one bit flipped in the identity signature: {r}"),
                    );
                }
                None => report.add("negative-tampered", false, "identity signature not found"),
            }
        }
        Err(e) => report.add("negative-tampered", false, e),
    }
    let r = verify_hex(first, "other_spki_certificate", now, pinned.as_ref());
    report.add(
        "negative-other-spki",
        r == CertError::IdentitySignatureInvalid.code(),
        format!("identity signature over another session key's record: {r}"),
    );
    let r = verify_hex(first, "der_certificate", now, pinned.as_ref());
    report.add(
        "negative-der-identity-signature",
        r == CertError::IdentitySignatureNotRaw.code(),
        format!("identity signature in DER, certificate self-signed again: {r}"),
    );
    let stranger = SoftwareKey::from_secret_bytes(&[0x22; 32])
        .expect("fixed key")
        .public_key();
    let r = verify_hex(first, "certificate", now, pin_for(&stranger).as_ref());
    report.add(
        "negative-wrong-pin",
        r == CertError::PinMismatch.code(),
        format!("pin = another identity: {r}"),
    );

    // 3. A new Worker loads the key from IndexedDB.
    let second = find(&runs, "after-worker-restart");
    if worker_ok(&mut report, "restarted-worker", second) {
        let second = second.expect("checked");
        report.add(
            "key-loaded-after-restart",
            second.get("loaded_from_store") == Some(&json!(true)),
            format!(
                "loaded from IndexedDB = {}",
                second.get("loaded_from_store").unwrap_or(&Value::Null)
            ),
        );
        let r2 = verify_hex(second, "certificate", now, pinned.as_ref());
        report.add(
            "second-certificate-same-identity",
            r2 == "ok",
            format!("verify(second certificate, same pin) = {r2}"),
        );
        let distinct = bytes(first, "certificate").ok() != bytes(second, "certificate").ok();
        report.add(
            "second-certificate-new-session-key",
            distinct,
            "the second certificate is a new certificate",
        );
    }

    // 3b. The whole browser restarts with the same profile.
    let reopened = find(&runs, "after-browser-restart");
    if worker_ok(&mut report, "worker-after-browser-restart", reopened) {
        let reopened = reopened.expect("checked");
        let r = verify_hex(reopened, "certificate", now, pinned.as_ref());
        report.add(
            "key-survives-browser-restart",
            reopened.get("loaded_from_store") == Some(&json!(true)) && r == "ok",
            format!(
                "loaded from IndexedDB = {}; verify(certificate, same pin) = {r}",
                reopened.get("loaded_from_store").unwrap_or(&Value::Null)
            ),
        );
    }

    // 4. After clearing site data the key is gone; the old pin refuses the new identity.
    let third = find(&runs, "after-clear-site-data");
    if worker_ok(&mut report, "worker-after-clear", third) {
        let third = third.expect("checked");
        report.add(
            "key-lost-after-clear",
            third.get("loaded_from_store") == Some(&json!(false)),
            format!(
                "loaded from IndexedDB = {} ({})",
                third.get("loaded_from_store").unwrap_or(&Value::Null),
                t.get("clear_method").and_then(Value::as_str).unwrap_or("?")
            ),
        );
        let r3 = verify_hex(third, "certificate", now, pinned.as_ref());
        report.add(
            "old-pin-refuses-new-identity",
            r3 == CertError::PinMismatch.code(),
            format!("verify(certificate after clear, old pin) = {r3}; the app re-pairs"),
        );
        let own = bytes(third, "identity_key")
            .ok()
            .and_then(|k| PublicKey::from_sec1(&k).ok());
        let r = match own {
            Some(k) => verify_hex(third, "certificate", now, Some(&k)),
            None => "no identity key".into(),
        };
        report.add(
            "new-identity-certificate-valid",
            r == "ok",
            format!("verify(certificate after clear, its own new identity) = {r}"),
        );
    }
    (report, Some(pin))
}

/// RFC 3339 UTC from Unix seconds.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn run() -> Result<bool, String> {
    let args = parse_args()?;
    let text = std::fs::read_to_string(&args.transcript)
        .map_err(|e| format!("cannot read {}: {e}", args.transcript))?;
    let t: Value = serde_json::from_str(&text).map_err(|e| format!("transcript: {e}"))?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let now = UnixTime(now_secs);

    let (report, pin) = evaluate(&t, args.skip_pin, now);
    for c in &report.0 {
        println!(
            "{} {}: {}",
            if c.ok { "ok    " } else { "FAILED" },
            c.name,
            c.detail
        );
    }
    let passed = report.passed();
    let failed: Vec<&str> = report.0.iter().filter(|c| !c.ok).map(|c| c.name).collect();
    let browser = t.get("browser").and_then(Value::as_str).unwrap_or("?");
    let version = t.get("browser_version").and_then(Value::as_str).unwrap_or("?");
    let details = if passed {
        format!(
            "{browser} {version}: Worker certificate accepted by the native verifier; key survived a Worker restart; \
             clearing site data lost it; tampered, other-SPKI, DER and wrong-pin certificates refused; persist()={}",
            t.pointer("/persist/persist").unwrap_or(&Value::Null)
        )
    } else {
        format!("{browser} {version}: failed {}", failed.join(", "))
    };

    let mut result = json!({
        "check": CHECK_ID,
        "target": t.get("target").and_then(Value::as_str).unwrap_or("?"),
        "outcome": if passed { "PASS" } else { "FAIL" },
        "build": args.build,
        "platform": format!("macos-aarch64, Playwright {browser} {version} (headless)"),
        "details": details,
        "time": rfc3339(now_secs),
        "extra": {
            "browser": browser,
            "browser_version": version,
            "user_agent": t.get("user_agent").cloned().unwrap_or(Value::Null),
            "break": t.get("break").cloned().unwrap_or(Value::Null),
            "verifier_break": if args.skip_pin { "skip-pin" } else { "none" },
            "persist": t.get("persist").cloned().unwrap_or(Value::Null),
            "clear_method": t.get("clear_method").cloned().unwrap_or(Value::Null),
            "identity_key": pin.map(|p| to_hex(p.as_bytes())),
            "verified_at": now_secs,
            "checks": report.0.iter().map(|c| json!({"name": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>(),
        },
    });
    if let Some(name) = &args.control {
        result["control"] = json!(name);
    }
    let out = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&args.out, out).map_err(|e| format!("cannot write {}: {e}", args.out))?;

    if let (Some(path), true, Some(pin)) = (&args.vector_out, passed, pin) {
        let first = t
            .get("runs")
            .and_then(Value::as_array)
            .and_then(|r| find(r, "first"))
            .ok_or("no first run")?;
        let cert = first
            .get("certificate")
            .and_then(Value::as_str)
            .ok_or("no certificate")?;
        let vector = json!({
            "name": "browser_worker_certificate",
            "note": "A session certificate issued in a browser Worker (wasm32 mousse-net-core, PendingCertificate) with a non-extractable WebCrypto P-256 identity key, accepted by the native verifier. Verify `certificate` at `now` with `expected_identity`; the result must be `ok`, exactly like `valid` in session-cert.json.",
            "browser": format!("{browser} {version}"),
            "build": args.build,
            "certificate": cert,
            "identity_public": to_hex(pin.as_bytes()),
            "expected_identity": to_hex(pin.as_bytes()),
            "not_before": first.get("not_before").cloned().unwrap_or(Value::Null),
            "not_after": first.get("not_after").cloned().unwrap_or(Value::Null),
            "now": first.get("not_before").cloned().unwrap_or(Value::Null),
            "result": "ok",
        });
        let text = serde_json::to_string_pretty(&vector).map_err(|e| e.to_string())? + "\n";
        std::fs::write(path, text).map_err(|e| format!("cannot write {path}: {e}"))?;
    }

    println!("{} {CHECK_ID}", if passed { "PASS" } else { "FAIL" });
    Ok(passed)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("verify-worker-cert: {e}");
            println!("FAIL {CHECK_ID}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn rfc3339_matches_the_vector_base_time() {
        assert_eq!(rfc3339(1_790_000_000), "2026-09-21T14:13:20Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
