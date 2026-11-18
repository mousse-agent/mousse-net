//! Native side of the browser Worker spike (Phase 0 spike 2).
//!
//! Serves the spike page on `127.0.0.1` only, receives the certificates the
//! page's Workers make and checks each with the real verifier,
//! `mousse_net_core::session_cert::verify`:
//!
//! 1. A Worker makes a certificate with its stored (or new) non-extractable
//!    WebCrypto identity key. It must verify, pinned to the identity key the
//!    Worker reports.
//! 2. That Worker is terminated and a new one makes another certificate. It
//!    must verify pinned to step 1's identity key: the key survived the
//!    restart.
//!
//! `MOUSSE_BROWSER_SPIKE_BREAK` selects a must-fail control:
//! `tampered-cert` (the identity signature covers another SPKI, so step 1
//! must fail) or `fresh-key` (the second Worker makes a new key, so step 2
//! must fail).
//!
//! ```text
//! browser-worker-runner --web <dir> --target <cell> --build <id> --out <file>
//!                       [--platform <text>] [--timeout <secs>]
//! ```
//!
//! Prints `READY <url>` once listening and `RESULT PASS` or
//! `RESULT FAIL reason=<word>` at the end. Exit 0 on PASS, 1 on FAIL, 2 when
//! the run did not finish.
#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mousse_net_core::identity::PublicKey;
use mousse_net_core::session_cert;
use mousse_net_core::time::UnixTime;
use serde_json::{Value, json};

const CHECK: &str = "phase0.browser-worker-cert";
const MAX_BODY: usize = 1 << 20;

/// Files the page may load, and their types. Nothing else is served.
const FILES: [(&str, &str); 5] = [
    ("index.html", "text/html; charset=utf-8"),
    ("page.js", "text/javascript; charset=utf-8"),
    ("worker.js", "text/javascript; charset=utf-8"),
    (
        "pkg/mousse_browser_worker.js",
        "text/javascript; charset=utf-8",
    ),
    ("pkg/mousse_browser_worker_bg.wasm", "application/wasm"),
];

struct Options {
    web: PathBuf,
    target: String,
    build: String,
    out: PathBuf,
    platform: String,
    timeout: Duration,
}

fn options() -> Result<Options, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let need = |name: &str| get(name).ok_or_else(|| format!("missing {name}"));
    Ok(Options {
        web: PathBuf::from(need("--web")?),
        target: need("--target")?,
        build: need("--build")?,
        out: PathBuf::from(need("--out")?),
        platform: get("--platform").unwrap_or_else(|| std::env::consts::OS.to_string()),
        timeout: Duration::from_secs(
            get("--timeout")
                .map(|t| t.parse().map_err(|_| "bad --timeout".to_string()))
                .transpose()?
                .unwrap_or(120),
        ),
    })
}

/// The must-fail control: (break mode for the page, control name in
/// checks/phase0.toml).
fn break_mode() -> Result<Option<(&'static str, &'static str)>, String> {
    match std::env::var("MOUSSE_BROWSER_SPIKE_BREAK").as_deref() {
        Err(_) | Ok("") => Ok(None),
        Ok("tampered-cert") => Ok(Some(("tampered-cert", "tampered-cert"))),
        Ok("fresh-key") => Ok(Some(("fresh-key", "fresh-key-after-restart"))),
        Ok(other) => Err(format!("unknown MOUSSE_BROWSER_SPIKE_BREAK {other:?}")),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// What the page reported, and the verifier's answers.
#[derive(Default)]
struct State {
    steps: Vec<Value>,
    /// Step 1's identity key: the pin for step 2.
    pin: Option<PublicKey>,
    page: Option<Value>,
}

/// Check one Worker's result. Returns the step record with `verdict`.
fn check_step(state: &mut State, report: &Value) -> Value {
    let now = unix_now();
    let step = report.get("step").and_then(Value::as_u64).unwrap_or(0);
    let mut failures: Vec<String> = Vec::new();
    let mut record = json!({ "step": step, "verifier_now": now, "worker": report });

    if report.get("ok") != Some(&Value::Bool(true)) {
        failures.push("worker_error".into());
        record["verdict"] = json!("worker_error");
        record["failures"] = json!(failures);
        return record;
    }
    let field = |name: &str| report.get(name).and_then(Value::as_str).unwrap_or("");
    let reported = unhex(field("identity")).and_then(|b| PublicKey::from_sec1(&b).ok());
    let der = unhex(field("certificate")).unwrap_or_default();

    let key = &report["privateKey"];
    if key.get("extractable") != Some(&Value::Bool(false)) {
        failures.push("identity_key_extractable".into());
    }
    for format in ["pkcs8", "jwk"] {
        let answer = key["export"][format].as_str().unwrap_or("");
        if !answer.starts_with("refused") {
            failures.push(format!("identity_key_exported_{format}"));
        }
    }
    if report.get("signatureLength").and_then(Value::as_u64) != Some(64) {
        failures.push("webcrypto_signature_not_raw".into());
    }

    // The pin: step 1 pins the key the Worker reports, so the certificate
    // must speak for that WebCrypto key; step 2 pins step 1's key.
    let pin = match step {
        1 => {
            state.pin = reported;
            reported
        }
        _ => state.pin,
    };
    let verdict = match &pin {
        None => "no_identity".to_string(),
        Some(pin) => match session_cert::verify(&der, UnixTime(now), Some(pin)) {
            Ok(verified) => {
                record["verified_identity"] = json!(hex(verified.identity.as_bytes()));
                record["verified_window"] = json!([
                    verified.window.not_before().0,
                    verified.window.not_after().0
                ]);
                "ok".to_string()
            }
            Err(e) => e.code().to_string(),
        },
    };
    if verdict != "ok" {
        failures.insert(0, verdict.clone());
    }
    if step == 1 && report.get("created") != Some(&Value::Bool(true)) {
        failures.push("step1_did_not_make_a_key".into());
    }
    if step == 2 {
        let same = reported.is_some() && reported == state.pin;
        record["same_identity_as_step1"] = json!(same);
        record["key_loaded_from_indexeddb"] =
            json!(report.get("created") == Some(&Value::Bool(false)));
        if report.get("created") != Some(&Value::Bool(false)) {
            failures.push("key_not_loaded_after_restart".into());
        }
    }
    record["pin"] = json!(pin.as_ref().map(|k| hex(k.as_bytes())));
    record["verdict"] = json!(verdict);
    record["failures"] = json!(failures);
    record
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Request {
    method: String,
    path: String,
    query: String,
    host: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut host = None;
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" => host = Some(value.to_string()),
            "content-length" => length = value.parse().ok()?,
            _ => {}
        }
    }
    if length > MAX_BODY {
        return None;
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Some(Request {
        method,
        path,
        query,
        host,
        body,
    })
}

fn respond(mut stream: &TcpStream, status: &str, kind: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

struct Server {
    web: PathBuf,
    host: String,
    run: String,
    break_mode: Option<&'static str>,
    state: Mutex<State>,
    done: Mutex<Option<Sender<()>>>,
}

impl Server {
    fn handle(&self, stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let Some(req) = read_request(&stream) else {
            return;
        };
        if req.host.as_deref() != Some(self.host.as_str()) {
            respond(&stream, "403 Forbidden", "text/plain", b"wrong host");
            return;
        }
        let name = req.path.trim_start_matches('/');
        let name = if name.is_empty() { "index.html" } else { name };
        let run_ok = req
            .query
            .split('&')
            .any(|kv| kv == format!("run={}", self.run));
        match (req.method.as_str(), name) {
            ("GET", "config") if run_ok => {
                let body = json!({ "breakMode": self.break_mode });
                respond(
                    &stream,
                    "200 OK",
                    "application/json",
                    body.to_string().as_bytes(),
                );
            }
            ("POST", "step") if run_ok => {
                let report: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let record = check_step(&mut state, &report);
                println!(
                    "step {}: {} {}",
                    record["step"], record["verdict"], record["failures"]
                );
                let reply = json!({ "verdict": record["verdict"] });
                state.steps.push(record);
                respond(
                    &stream,
                    "200 OK",
                    "application/json",
                    reply.to_string().as_bytes(),
                );
            }
            ("POST", "done") if run_ok => {
                let page: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                self.state.lock().unwrap_or_else(|e| e.into_inner()).page = Some(page);
                respond(&stream, "200 OK", "application/json", b"{}");
                if let Some(tx) = self.done.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    let _ = tx.send(());
                }
            }
            ("GET", "favicon.ico") => respond(&stream, "204 No Content", "text/plain", b""),
            ("GET", file) => match FILES.iter().find(|(f, _)| *f == file) {
                Some((f, kind)) => match std::fs::read(self.web.join(f)) {
                    Ok(bytes) => respond(&stream, "200 OK", kind, &bytes),
                    Err(_) => respond(&stream, "404 Not Found", "text/plain", b"missing"),
                },
                None => respond(&stream, "404 Not Found", "text/plain", b"not found"),
            },
            _ => respond(&stream, "403 Forbidden", "text/plain", b"refused"),
        }
    }
}

/// The run's outcome: PASS needs both steps verified with no failure.
fn outcome(state: &State, finished: bool) -> (bool, Option<String>, Vec<String>) {
    // (where, reason word)
    let mut failures: Vec<(String, String)> = Vec::new();
    for step in &state.steps {
        let n = step["step"].as_u64().unwrap_or(0);
        for f in step["failures"].as_array().into_iter().flatten() {
            failures.push((format!("step{n}"), f.as_str().unwrap_or("?").to_string()));
        }
    }
    let seen: Vec<u64> = state
        .steps
        .iter()
        .filter_map(|s| s["step"].as_u64())
        .collect();
    for n in [1, 2] {
        if !seen.contains(&n) {
            failures.push((format!("step{n}"), "missing".into()));
        }
    }
    if let Some(page) = &state.page {
        for e in page["errors"].as_array().into_iter().flatten() {
            failures.push((
                format!("page: {}", e.as_str().unwrap_or("?")),
                "page_error".into(),
            ));
        }
    }
    if !finished {
        failures.insert(0, ("run".into(), "timeout".into()));
    }
    let reason = failures.first().map(|(_, word)| word.clone());
    let listed = failures
        .into_iter()
        .map(|(at, word)| format!("{at}: {word}"))
        .collect();
    (reason.is_none(), reason, listed)
}

fn run() -> Result<ExitCode, String> {
    let opts = options()?;
    for (file, _) in FILES {
        if !Path::new(&opts.web).join(file).is_file() {
            return Err(format!(
                "{} is missing; build the wasm package first (README)",
                opts.web.join(file).display()
            ));
        }
    }
    let control = break_mode()?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| format!("bind 127.0.0.1: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let run = format!(
        "{:x}{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let (tx, rx) = mpsc::channel();
    let server = Arc::new(Server {
        web: opts.web.clone(),
        host: format!("127.0.0.1:{port}"),
        run: run.clone(),
        break_mode: control.map(|(mode, _)| mode),
        state: Mutex::new(State::default()),
        done: Mutex::new(Some(tx)),
    });
    {
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let server = Arc::clone(&server);
                std::thread::spawn(move || server.handle(stream));
            }
        });
    }
    println!("READY http://127.0.0.1:{port}/index.html?run={run}");
    let _ = std::io::stdout().flush();

    let finished = rx.recv_timeout(opts.timeout).is_ok();
    let state = server.state.lock().unwrap_or_else(|e| e.into_inner());
    let (pass, reason, failures) = outcome(&state, finished);
    let verdicts: Vec<String> = state
        .steps
        .iter()
        .map(|s| format!("step{}={}", s["step"], s["verdict"].as_str().unwrap_or("?")))
        .collect();
    let details = match &reason {
        None => format!(
            "native verifier accepted the Worker certificate, and the restarted Worker's certificate pinned to the same identity key ({})",
            verdicts.join(", ")
        ),
        Some(r) => format!("reason={r} ({})", failures.join(", ")),
    };
    let result = json!({
        "check": CHECK,
        "target": opts.target,
        "control": control.map(|(_, name)| name),
        "outcome": if pass { "PASS" } else { "FAIL" },
        "build": opts.build,
        "platform": opts.platform,
        "details": details,
        "reason": reason,
        "time_unix": unix_now(),
        "extra": {
            "reason": reason,
            "failures": failures,
            "steps": state.steps,
            "page": state.page,
        },
    });
    if let Some(dir) = opts.out.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&opts.out, text).map_err(|e| format!("{}: {e}", opts.out.display()))?;
    match &reason {
        None => println!("RESULT PASS"),
        Some(r) => println!("RESULT FAIL reason={r}"),
    }
    Ok(if !finished {
        ExitCode::from(2)
    } else if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("browser-worker-runner: {e}");
            ExitCode::from(2)
        }
    }
}
