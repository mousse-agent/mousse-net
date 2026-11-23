//! The headless daemon (design §B.13, check `phase3.headless`): `serve
//! --headless` makes its own endpoint with an owner-only key file, one
//! process per endpoint, another profile's endpoint alongside, the terminal
//! QR code pairs a device, and the shipped systemd unit runs it.
//!
//! Everything listens on loopback only, without mDNS.

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{bin, temp_dir, WAIT};

/// A running helper process. Killed on drop.
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

fn pump(mut from: impl Read + Send + 'static, into: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                return;
            }
            into.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
}

impl Proc {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.spawn().expect("start the helper");
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        pump(child.stdout.take().unwrap(), stdout.clone());
        pump(child.stderr.take().unwrap(), stderr.clone());
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout.lock().unwrap()).into_owned()
    }

    fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    fn wait_for(&self, needle: &str) -> String {
        let start = Instant::now();
        loop {
            let out = self.out();
            if let Some(at) = out.find(needle) {
                let line_start = out[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = out[at..].find('\n').map(|i| at + i).unwrap_or(out.len());
                return out[line_start..line_end].trim().to_owned();
            }
            assert!(
                start.elapsed() < WAIT,
                "no {needle:?} within {WAIT:?}\nstdout: {out}\nstderr: {}",
                self.err()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn type_line(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("piped stdin");
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        let start = Instant::now();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status.code().unwrap_or(-1));
            }
            if start.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Run to the end; (exit code, stdout, stderr).
    fn finish(mut self) -> (Option<i32>, String, String) {
        let code = self.exit_within(WAIT + Duration::from_secs(15));
        std::thread::sleep(Duration::from_millis(50));
        (code, self.out(), self.err())
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A command for the helper with no key flags: a headless endpoint loads its
/// own key.
fn helper(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env_remove("MOUSSE_HELPER_STATE")
        // A held lock is retried for this long before the second process
        // gives up.
        .env("MOUSSE_NET_ENDPOINT_LOCK_WAIT_MS", "300")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn state_args(dir: &Path) -> Vec<String> {
    vec!["--state".into(), dir.display().to_string()]
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut all = state_args(dir);
    all.extend(args.iter().map(|a| a.to_string()));
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    Proc::spawn(helper(&all)).finish()
}

/// `serve --headless` on loopback, without mDNS; waits until ready.
fn serve_headless(dir: &Path, name: &str, extra: &[&str]) -> Proc {
    let mut all = state_args(dir);
    all.extend(
        [
            "serve",
            "--headless",
            "--listen-ip",
            "127.0.0.1",
            "--no-mdns",
            "--name",
            name,
        ]
        .iter()
        .map(|a| a.to_string()),
    );
    all.extend(extra.iter().map(|a| a.to_string()));
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let proc = Proc::spawn(helper(&all));
    proc.wait_for("ready ");
    proc
}

fn stop(dir: &Path, mut server: Proc) {
    let (code, out, err) = run(dir, &["stop"]);
    assert_eq!(code, Some(0), "stop: {out} {err}");
    assert!(server.exit_within(WAIT).is_some(), "serve did not stop");
}

fn identity_storage(dir: &Path) -> String {
    let text = std::fs::read_to_string(dir.join("identity.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["storage"].as_str().unwrap_or("").to_owned()
}

fn cleanup(dirs: &[&Path]) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn headless_serve_creates_its_endpoint_with_an_owner_only_key_file() {
    let dir = temp_dir("hl-new");
    assert!(!dir.exists());
    let server = serve_headless(&dir, "server", &["--key-file"]);
    assert!(
        server.out().contains("identity key: in an owner-only file"),
        "{}",
        server.out()
    );
    assert_eq!(identity_storage(&dir), "file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.join("identity.secret")), 0o600);
        assert_eq!(mode(dir.clone()), 0o700);
    }
    // Commands load the key without any key flag.
    let (code, out, err) = run(&dir, &["id"]);
    assert_eq!(code, Some(0), "id: {out} {err}");
    stop(&dir, server);
    // A restart uses the same endpoint.
    let server = serve_headless(&dir, "server", &[]);
    assert!(
        !server.out().contains("created endpoint"),
        "{}",
        server.out()
    );
    stop(&dir, server);
    cleanup(&[&dir]);
}

#[cfg(unix)]
#[test]
fn a_loosened_key_file_is_made_owner_only_again_before_use() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("hl-mode");
    let (code, out, err) = run(&dir, &["init", "--headless", "--key-file"]);
    assert_eq!(code, Some(0), "init: {out} {err}");
    let key = dir.join("identity.secret");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let server = serve_headless(&dir, "server", &[]);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&dir), 0o700);
    stop(&dir, server);
    cleanup(&[&dir]);
}

/// Several first starts at once on one empty folder: one identity, one
/// host, and every other process refuses as a second process would.
#[test]
fn concurrent_first_starts_make_one_endpoint_and_the_rest_refuse() {
    for round in 0..4 {
        let dir = temp_dir(&format!("hl-race{round}"));
        let mut procs: Vec<Proc> = (0..6)
            .map(|_| {
                let mut all = state_args(&dir);
                all.extend(
                    [
                        "serve",
                        "--headless",
                        "--key-file",
                        "--listen-ip",
                        "127.0.0.1",
                        "--no-mdns",
                    ]
                    .iter()
                    .map(|a| a.to_string()),
                );
                let all: Vec<&str> = all.iter().map(String::as_str).collect();
                Proc::spawn(helper(&all))
            })
            .collect();
        // Every loser ends; the one host keeps running. Wait until all but
        // one have exited and the survivor is ready (or WAIT passes).
        let start = Instant::now();
        let mut codes: Vec<Option<i32>> = vec![None; procs.len()];
        while start.elapsed() < WAIT {
            for (i, p) in procs.iter_mut().enumerate() {
                if codes[i].is_none() {
                    codes[i] = p.exit_within(Duration::ZERO);
                }
            }
            let alive: Vec<usize> = (0..procs.len()).filter(|i| codes[*i].is_none()).collect();
            if alive.len() <= 1 && alive.iter().all(|i| procs[*i].out().contains("ready ")) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut running = Vec::new();
        for (i, p) in procs.iter_mut().enumerate() {
            match codes[i] {
                Some(code) => {
                    assert_eq!(
                        code,
                        2,
                        "round {round}: process {i} exited {code}\nstdout: {}\nstderr: {}",
                        p.out(),
                        p.err()
                    );
                    assert!(
                        p.err().contains("already running this endpoint"),
                        "round {round}: process {i} did not refuse as a second process:\nstdout: {}\nstderr: {}",
                        p.out(),
                        p.err()
                    );
                }
                None => running.push(i),
            }
        }
        assert_eq!(
            running.len(),
            1,
            "round {round}: hosts running: {running:?}"
        );
        let host = procs.swap_remove(running[0]);
        host.wait_for("ready ");
        let created = host.out().matches("created endpoint").count();
        assert!(created <= 1);
        assert_eq!(identity_storage(&dir), "file");
        stop(&dir, host);
        cleanup(&[&dir]);
    }
}

#[test]
fn a_second_process_for_the_same_endpoint_refuses_and_another_profile_starts() {
    let a = temp_dir("hl-lock-a");
    let b = temp_dir("hl-lock-b");
    let copy = temp_dir("hl-lock-copy");
    let server = serve_headless(&a, "hostA", &["--key-file"]);

    let refused = |dir: &Path, what: &str| {
        let mut all = state_args(dir);
        all.extend(
            [
                "serve",
                "--headless",
                "--listen-ip",
                "127.0.0.1",
                "--no-mdns",
            ]
            .iter()
            .map(|a| a.to_string()),
        );
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        let mut second = Proc::spawn(helper(&all));
        let code = second.exit_within(WAIT);
        assert_eq!(
            code,
            Some(2),
            "{what}: a second process ran the same endpoint\nstdout: {}\nstderr: {}",
            second.out(),
            second.err()
        );
        assert!(
            second.err().contains("already running this endpoint"),
            "{what}: {}",
            second.err()
        );
    };
    // The same state directory.
    refused(&a, "same folder");
    // A copy of it elsewhere: the same identity.
    std::fs::create_dir_all(&copy).unwrap();
    for entry in std::fs::read_dir(&a).unwrap().flatten() {
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    refused(&copy, "copied folder");

    // Another profile's endpoint on the same machine starts alongside.
    let other = serve_headless(&b, "hostB", &["--key-file"]);
    let (_, a_id, _) = run(&a, &["id"]);
    let (_, b_id, _) = run(&b, &["id"]);
    assert_ne!(
        a_id.split_whitespace().next(),
        b_id.split_whitespace().next()
    );
    stop(&b, other);
    stop(&a, server);
    cleanup(&[&a, &b, &copy]);
}

/// The QR code `invite` printed between its TICKET line and its routes
/// line, as module rows: each character is two modules, top and bottom.
fn qr_modules(out: &str) -> Vec<Vec<bool>> {
    let lines: Vec<&str> = out.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("TICKET "))
        .expect("a TICKET line")
        + 1;
    let end = lines[start..]
        .iter()
        .position(|l| l.starts_with("routes:"))
        .expect("a routes line")
        + start;
    let art: Vec<Vec<char>> = lines[start..end]
        .iter()
        .filter(|l| !l.is_empty())
        .map(|l| l.chars().collect())
        .collect();
    assert!(
        !art.is_empty(),
        "no QR code between the ticket and routes lines"
    );
    let width = art.iter().map(Vec::len).max().unwrap();
    let mut rows = Vec::new();
    for line in &art {
        let mut top = Vec::with_capacity(width);
        let mut bottom = Vec::with_capacity(width);
        for x in 0..width {
            let (t, b) = match line.get(x).copied().unwrap_or(' ') {
                ' ' => (false, false),
                '\u{2580}' => (true, false),
                '\u{2584}' => (false, true),
                '\u{2588}' => (true, true),
                c => panic!("unexpected character {c:?} in the QR code"),
            };
            top.push(t);
            bottom.push(b);
        }
        rows.push(top);
        rows.push(bottom);
    }
    rows
}

/// Decode the printed QR code as a phone's scanner would see it. A block
/// may stand for a dark or a light module depending on the renderer, so
/// both readings are tried; only one can hold a valid code.
fn scan(rows: &[Vec<bool>]) -> String {
    const SCALE: usize = 6;
    const MARGIN: usize = 4 * SCALE;
    let h = rows.len();
    let w = rows[0].len();
    let (iw, ih) = (w * SCALE + 2 * MARGIN, h * SCALE + 2 * MARGIN);
    let mut found = Vec::new();
    for block_is_dark in [true, false] {
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(iw, ih, |x, y| {
            let inside =
                x >= MARGIN && y >= MARGIN && x < MARGIN + w * SCALE && y < MARGIN + h * SCALE;
            let dark = inside && {
                let block = rows[(y - MARGIN) / SCALE][(x - MARGIN) / SCALE];
                block == block_is_dark
            };
            if dark {
                0
            } else {
                255
            }
        });
        for grid in img.detect_grids() {
            if let Ok((_, text)) = grid.decode() {
                found.push(text);
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "the terminal QR code does not scan: {found:?}"
    );
    found.pop().unwrap()
}

/// Pair `phone` (a new headless endpoint) with the headless host in `host`
/// through the terminal QR code; the host's `serve` is running.
fn pair_by_qr(host: &Path, phone: &Path) {
    let (code, out, err) = run(phone, &["init", "--headless", "--key-file"]);
    assert_eq!(code, Some(0), "init: {out} {err}");

    let mut invite_cmd = helper(&["--state", &host.display().to_string(), "invite", "--qr"]);
    invite_cmd.stdin(Stdio::piped());
    let mut invite = Proc::spawn(invite_cmd);
    invite.wait_for("waiting for the device to join");
    // Only what the scanner reads from the QR code: never the ticket line.
    let ticket = scan(&qr_modules(&invite.out()));
    assert!(!ticket.is_empty());

    // The test build's --in-person stands in for the phone's scanner.
    let phone_state = phone.display().to_string();
    let join = Proc::spawn(helper(&[
        "--state",
        &phone_state,
        "join",
        &ticket,
        "--in-person",
        "--name",
        "phone",
    ]));
    invite.wait_for("Is the device next to you?");
    invite.type_line("y\n");
    let (code, out, err) = join.finish();
    assert_eq!(code, Some(0), "join: {out} {err}");
    invite.wait_for("paired: grant ");
}

/// `phone` runs `echo hello-headless` in a terminal on the host named
/// `server`: the exit code and output.
fn term_echo(phone: &Path) -> (Option<i32>, String, String) {
    let phone_state = phone.display().to_string();
    let echo: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/c", "echo", "hello-headless"]
    } else {
        vec!["sh", "-c", "echo hello-headless"]
    };
    let mut args = vec!["--state", &phone_state, "term", "server", "--"];
    args.extend(echo);
    Proc::spawn(helper(&args)).finish()
}

#[test]
fn the_terminal_qr_code_pairs_a_device() {
    let host = temp_dir("hl-qr-host");
    let phone = temp_dir("hl-qr-phone");
    let server = serve_headless(&host, "server", &["--key-file"]);
    pair_by_qr(&host, &phone);

    // The pairing works: a command runs on the headless host.
    let (code, out, err) = term_echo(&phone);
    assert_eq!(code, Some(0), "term: {out} {err}");
    assert!(out.contains("hello-headless"), "{out}");

    stop(&host, server);
    cleanup(&[&host, &phone]);
}

/// Every `grants.json` under `dir`.
fn grant_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(grant_files(&path));
        } else if path.file_name().is_some_and(|n| n == "grants.json") {
            found.push(path);
        }
    }
    found
}

/// Standalone `serve` opens a terminal only for an owner grant: once the
/// paired device's grant is stored with another role, its terminal is
/// refused.
#[test]
fn a_restricted_grant_gets_no_standalone_terminal() {
    let host = temp_dir("hl-role-host");
    let phone = temp_dir("hl-role-phone");
    let server = serve_headless(&host, "server", &["--key-file"]);
    pair_by_qr(&host, &phone);
    stop(&host, server);

    // The grant as a helper with roles stores a narrowed one.
    let files = grant_files(&host);
    assert_eq!(files.len(), 1, "{files:?}");
    let mut table: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    table["version"] = serde_json::json!(3);
    for grant in table["grants"].as_array_mut().unwrap() {
        grant["role"] = serde_json::json!("member");
        grant["revision"] = serde_json::json!(2);
    }
    std::fs::write(&files[0], serde_json::to_vec(&table).unwrap()).unwrap();

    let server = serve_headless(&host, "server", &["--key-file"]);
    let (code, out, err) = term_echo(&phone);
    assert_ne!(code, Some(0), "term: {out} {err}");
    assert!(!out.contains("hello-headless"), "{out}");

    stop(&host, server);
    cleanup(&[&host, &phone]);
}

#[test]
fn the_shipped_systemd_unit_starts_the_headless_daemon() {
    let unit = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd/mousse-helper.service"),
    )
    .unwrap();
    let exec = unit
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .expect("an ExecStart line");
    let home = temp_dir("hl-unit");
    let words: Vec<String> = exec
        .split_whitespace()
        .map(|w| w.replace("%h", &home.display().to_string()))
        .collect();
    assert!(words[0].ends_with("/.local/bin/mousse-helper"), "{exec}");
    assert!(!exec.contains("insecure"), "{exec}");
    // Tests listen on loopback only and never use multicast.
    let mut args: Vec<String> = words[1..]
        .iter()
        .map(|w| {
            if w == "0.0.0.0" {
                "127.0.0.1".into()
            } else {
                w.clone()
            }
        })
        .collect();
    args.extend(["--no-mdns".into(), "--name".into(), "unit".into()]);
    let state = words
        .iter()
        .skip_while(|w| *w != "--state")
        .nth(1)
        .expect("a --state in ExecStart")
        .clone();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut cmd = helper(&args);
    cmd.arg("--key-file");
    let server = Proc::spawn(cmd);
    server.wait_for("ready ");
    stop(Path::new(&state), server);
    cleanup(&[&home]);
}
