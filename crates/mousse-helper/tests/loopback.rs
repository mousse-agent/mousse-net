//! The helper binary end to end on loopback: endpoints in their own state
//! directories, hosts serving on 127.0.0.1, peers pairing in person and
//! opening terminals.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);

/// The helper these tests run: a private copy of the binary cargo built
/// with them, checked to be that build.
///
/// Cargo puts every build of the helper at the same path, whatever its
/// flags, so a build with a must-fail control (another configuration
/// sharing the target folder) can replace it while these tests run or
/// just before. Without the copy and the check, the revocation tests then
/// fail for a defect they were not compiled with (`keep-removed-grant`
/// leaves the terminal open).
fn bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let built = Path::new(env!("CARGO_BIN_EXE_mousse-helper"));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("helper-under-test");
        std::fs::create_dir_all(&dir).unwrap();
        // Copies left by earlier runs; one still running stays.
        for old in std::fs::read_dir(&dir).unwrap().flatten() {
            let _ = std::fs::remove_file(old.path());
        }
        let copy = dir.join(format!(
            "mousse-helper-{}{}",
            std::process::id(),
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::copy(built, &copy).unwrap();
        let out = Command::new(&copy).arg("--version").output().unwrap();
        let expected = format!(
            "mousse-helper {} build {} control {}",
            env!("CARGO_PKG_VERSION"),
            env!("MOUSSE_HELPER_BUILD"),
            env!("MOUSSE_HELPER_CONTROL")
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            expected,
            "{} is not the build these tests were compiled with: another build \
             (other flags, same target folder) replaced it; give each \
             configuration its own CARGO_TARGET_DIR",
            built.display()
        );
        copy
    })
}

fn temp_dir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // On Unix the control socket goes in this folder, and a socket path
    // must stay short (104 bytes on macOS).
    if cfg!(windows) {
        std::env::temp_dir().join(format!("mousse-helper-it-{tag}-{}-{n}", std::process::id()))
    } else {
        PathBuf::from("/tmp").join(format!(
            "mh-{tag}-{}-{}",
            std::process::id(),
            n % 1_000_000_000
        ))
    }
}

/// A command that prints `hello-<tag>` on the host.
fn echo_command(tag: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/c".into(), format!("echo hello-{tag}")]
    } else {
        vec!["sh".into(), "-c".into(), format!("echo hello-{tag}")]
    }
}

/// A line typed into the host's shell whose output differs from the typed
/// text, so seeing the output proves the shell ran it.
fn typed_marker(tag: &str) -> (String, String) {
    if cfg!(windows) {
        (format!("echo mk^-{tag}\r\n"), format!("mk-{tag}"))
    } else {
        (format!("echo mk''-{tag}\n"), format!("mk-{tag}"))
    }
}

/// One endpoint's state directory.
struct Endpoint {
    dir: PathBuf,
}

impl Endpoint {
    fn init(tag: &str) -> Self {
        let endpoint = Endpoint { dir: temp_dir(tag) };
        let out = endpoint.run(&["init"]);
        assert!(out.ok(), "init: {}", out.text());
        endpoint
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.arg("--state")
            .arg(&self.dir)
            .arg("--insecure-file-key")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run to the end (bounded by `WAIT` plus a margin).
    fn run(&self, args: &[&str]) -> Done {
        let proc = Proc::spawn(self.command(args));
        proc.finish(WAIT + Duration::from_secs(15))
    }

    fn spawn(&self, args: &[&str]) -> Proc {
        Proc::spawn(self.command(args))
    }

    fn spawn_with_stdin(&self, args: &[&str]) -> Proc {
        let mut cmd = self.command(args);
        cmd.stdin(Stdio::piped());
        Proc::spawn(cmd)
    }

    /// Start `serve` on loopback and wait until it is ready.
    fn serve(&self, name: &str, extra: &[&str]) -> Server {
        let mut args = vec!["serve", "--name", name];
        args.extend_from_slice(extra);
        let proc = self.spawn(&args);
        let ready = proc.wait_for("ready ", WAIT);
        let port = ready
            .split_whitespace()
            .skip_while(|w| *w != "port")
            .nth(1)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("no port in {ready:?}"));
        Server { proc, port }
    }
}

struct Done {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Done {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }

    fn text(&self) -> String {
        format!(
            "code {:?}\nstdout: {}\nstderr: {}",
            self.code, self.stdout, self.stderr
        )
    }
}

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

    /// Wait until stdout contains `needle`; return the line it is on.
    fn wait_for(&self, needle: &str, limit: Duration) -> String {
        let start = Instant::now();
        loop {
            let out = self.out();
            if let Some(at) = out.find(needle) {
                let line_start = out[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = out[at..].find('\n').map(|i| at + i).unwrap_or(out.len());
                return out[line_start..line_end].trim().to_owned();
            }
            if start.elapsed() > limit {
                panic!(
                    "no {needle:?} within {limit:?}\nstdout: {out}\nstderr: {}",
                    self.err()
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn type_line(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("piped stdin");
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Wait for the process to exit within `limit`.
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

    fn finish(mut self, limit: Duration) -> Done {
        let code = self.exit_within(limit);
        // Let the pumps catch up.
        std::thread::sleep(Duration::from_millis(50));
        Done {
            code,
            stdout: self.out(),
            stderr: self.err(),
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Server {
    proc: Proc,
    port: u16,
}

impl Server {
    fn route(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }
}

/// Stop a host through its control channel and wait for it to exit.
fn stop(host: &Endpoint, mut server: Server) {
    let done = host.run(&["stop"]);
    assert!(done.ok(), "stop: {}", done.text());
    assert!(
        server.proc.exit_within(WAIT).is_some(),
        "serve did not stop"
    );
}

/// Pair `peer` with the running host of `host` in person. Returns the
/// grant id the host made.
fn pair(host: &Endpoint, peer: &Endpoint, peer_name: &str) -> (u64, String) {
    let mut invite = host.spawn_with_stdin(&["invite", "--no-qr"]);
    let ticket_line = invite.wait_for("TICKET ", WAIT);
    let ticket = ticket_line.trim_start_matches("TICKET ").trim().to_owned();
    let join = peer.spawn(&["join", &ticket, "--in-person", "--name", peer_name]);
    invite.wait_for("Is the device next to you?", WAIT);
    invite.type_line("y\n");
    let joined = join.finish(WAIT);
    assert!(joined.ok(), "join: {}", joined.text());
    let paired = invite.wait_for("paired: grant ", WAIT);
    // The line may follow the question's prompt: the answer typed into
    // a pipe is not echoed.
    let grant = paired
        .split("paired: grant ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|g| g.parse().ok())
        .unwrap_or_else(|| panic!("no grant in {paired:?}"));
    (grant, ticket)
}

/// Open the host's shell from `peer` and check it runs a typed line.
fn live_terminal(peer: &Endpoint, host_name: &str, tag: &str) -> Proc {
    let mut term = peer.spawn_with_stdin(&["term", host_name]);
    check_live(&mut term, tag);
    term
}

fn check_live(term: &mut Proc, tag: &str) {
    let (typed, shown) = typed_marker(tag);
    // The shell may still be starting: type until its output shows.
    let start = Instant::now();
    loop {
        term.type_line(&typed);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if term.out().contains(&shown) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if start.elapsed() > WAIT {
            panic!(
                "the shell never ran {typed:?}\nstdout: {}\nstderr: {}",
                term.out(),
                term.err()
            );
        }
    }
}

fn run_command(peer: &Endpoint, host_name: &str, extra: &[&str], tag: &str) -> Done {
    let cmd = echo_command(tag);
    let mut args: Vec<&str> = vec!["term", host_name];
    args.extend_from_slice(extra);
    args.push("--");
    args.extend(cmd.iter().map(String::as_str));
    peer.run(&args)
}

fn cleanup(dirs: &[&Endpoint]) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(&d.dir);
    }
}

fn assert_closed_by_removal(term: &mut Proc) {
    let started = Instant::now();
    let code = term.exit_within(Duration::from_secs(3));
    assert_eq!(
        code,
        Some(3),
        "terminal still open after removal\nstderr: {}",
        term.err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(term.err().contains("GRANT_REVOKED"), "{}", term.err());
}

#[test]
fn pair_in_person_run_a_terminal_then_removing_the_grant_closes_it() {
    let host = Endpoint::init("host");
    let peer = Endpoint::init("peer");
    let server = host.serve("hostA", &[]);
    let (grant, _) = pair(&host, &peer, "laptop");

    let done = run_command(&peer, "hostA", &[], "one");
    assert!(done.ok(), "{}", done.text());
    assert!(done.stdout.contains("hello-one"), "{}", done.text());

    let mut term = live_terminal(&peer, "hostA", "live");
    let listed = host.run(&["grants"]);
    assert!(listed.stdout.contains("laptop"), "{}", listed.text());
    assert!(listed.stdout.contains("connections 1"), "{}", listed.text());

    let removed = host.run(&["remove", &grant.to_string()]);
    assert!(removed.ok(), "{}", removed.text());
    assert_closed_by_removal(&mut term);

    // The device is no longer known: the host refuses it (after its
    // join-proof wait).
    let again = run_command(&peer, "hostA", &[], "two");
    assert_eq!(again.code, Some(2), "{}", again.text());
    assert!(again.stderr.contains("NOT_AUTHORIZED"), "{}", again.text());
    assert!(!again.stdout.contains("hello-two"));

    stop(&host, server);
    cleanup(&[&host, &peer]);
}

#[test]
fn rejections_wrong_identity_used_ticket_and_declined_pairing() {
    let host = Endpoint::init("rhost");
    let peer = Endpoint::init("rpeer");
    let other = Endpoint::init("rother");
    let server = host.serve("hostA", &["--port", "0"]);
    let port = server.port;
    let (_, ticket) = pair(&host, &peer, "laptop");

    // The used ticket does not pair a second device.
    let replay = other.run(&["join", &ticket, "--in-person", "--name", "intruder"]);
    assert_eq!(replay.code, Some(2), "{}", replay.text());
    assert!(
        replay.stderr.contains("INVITATION_INVALID"),
        "{}",
        replay.text()
    );

    // The owner says no.
    let mut invite = host.spawn_with_stdin(&["invite", "--no-qr"]);
    let ticket_line = invite.wait_for("TICKET ", WAIT);
    let fresh = ticket_line.trim_start_matches("TICKET ").trim().to_owned();
    // Pasted, not scanned: an in-person ticket does not pair, and the
    // owner is not asked.
    let pasted = other.run(&["join", &fresh, "--name", "intruder"]);
    assert_eq!(pasted.code, Some(2), "{}", pasted.text());
    assert!(
        pasted.stderr.contains("PAIRING_FAILED"),
        "{}",
        pasted.text()
    );
    assert!(!invite.out().contains("Is the device next to you?"));

    let mut join = other.spawn(&["join", &fresh, "--in-person", "--name", "intruder"]);
    invite.wait_for("Is the device next to you?", WAIT);
    invite.type_line("n\n");
    assert_eq!(join.exit_within(WAIT), Some(2));
    assert!(join.err().contains("PAIRING_DECLINED"), "{}", join.err());
    drop(invite);

    // Another endpoint takes the host's port: the paired peer refuses it
    // in the handshake, before any data.
    stop(&host, server);
    let impostor_port = port.to_string();
    let impostor = other.serve("hostA", &["--port", &impostor_port]);
    let refused = run_command(&peer, "hostA", &[], "imp");
    assert_eq!(refused.code, Some(2), "{}", refused.text());
    assert!(
        refused.stderr.contains("no candidate answered"),
        "{}",
        refused.text()
    );
    assert!(!refused.stdout.contains("hello-imp"));
    assert!(
        !impostor.proc.out().contains("connected"),
        "{}",
        impostor.proc.out()
    );
    stop(&other, impostor);
    cleanup(&[&host, &peer, &other]);
}

#[test]
fn two_endpoints_on_one_computer_stay_separate() {
    // One computer, two profiles: endpoints A and B. Each pairs with its
    // own peer.
    let a = Endpoint::init("shared-a");
    let b = Endpoint::init("shared-b");
    let pa = Endpoint::init("peer-a");
    let pb = Endpoint::init("peer-b");
    let a_server = a.serve("hostA", &[]);
    let b_server = b.serve("hostB", &[]);
    assert_ne!(a_server.port, b_server.port);
    let a_id = a.run(&["id"]).stdout;
    let b_id = b.run(&["id"]).stdout;
    assert_ne!(
        a_id.split_whitespace().next(),
        b_id.split_whitespace().next()
    );

    pair(&a, &pa, "peer of A");
    let (b_grant, _) = pair(&b, &pb, "peer of B");
    let mut a_term = live_terminal(&pa, "hostA", "a1");
    let mut b_term = live_terminal(&pb, "hostB", "b1");

    // B removes its peer: B's terminal closes, A's stays open.
    let removed = b.run(&["remove", &b_grant.to_string()]);
    assert!(removed.ok(), "{}", removed.text());
    assert_closed_by_removal(&mut b_term);
    assert_eq!(a_term.exit_within(Duration::from_millis(500)), None);
    check_live(&mut a_term, "a2");
    assert!(a.run(&["grants"]).stdout.contains("peer of A"));

    // Neither peer reaches the other endpoint.
    let b_route = b_server.route();
    let cross = run_command(&pa, "hostA", &["--route", &b_route], "cross");
    assert_eq!(cross.code, Some(2), "{}", cross.text());
    assert!(
        cross.stderr.contains("no candidate answered"),
        "{}",
        cross.text()
    );
    let a_route = a_server.route();
    let cross = run_command(&pb, "hostB", &["--route", &a_route], "cross");
    assert_eq!(cross.code, Some(2), "{}", cross.text());
    assert!(
        cross.stderr.contains("no candidate answered"),
        "{}",
        cross.text()
    );

    // A restarts on its kept port; its peer reconnects.
    drop(a_term);
    stop(&a, a_server);
    let a_server = a.serve("hostA", &[]);
    assert_eq!(a_server.route(), a_route);
    let again = run_command(&pa, "hostA", &[], "back");
    assert!(again.ok(), "{}", again.text());
    assert!(again.stdout.contains("hello-back"), "{}", again.text());

    stop(&a, a_server);
    stop(&b, b_server);
    cleanup(&[&a, &b, &pa, &pb]);
}

#[test]
fn a_second_process_for_the_same_endpoint_does_not_start() {
    let a = Endpoint::init("lock-a");
    let b = Endpoint::init("lock-b");
    let server = a.serve("hostA", &[]);
    let second = a.run(&["serve", "--name", "again"]);
    assert_eq!(second.code, Some(2), "{}", second.text());
    assert!(
        second.stderr.contains("already running this endpoint"),
        "{}",
        second.text()
    );
    // Another endpoint on the same machine starts normally.
    let other = b.serve("hostB", &[]);
    stop(&b, other);
    stop(&a, server);
    cleanup(&[&a, &b]);
}

/// Wait until `proc` has printed `count` lines containing `needle`; return
/// them.
fn lines_with(proc: &Proc, needle: &str, count: usize) -> Vec<String> {
    let start = Instant::now();
    loop {
        let lines: Vec<String> = proc
            .out()
            .lines()
            .filter(|l| l.contains(needle))
            .map(|l| l.trim().to_owned())
            .collect();
        if lines.len() >= count {
            return lines;
        }
        if start.elapsed() > WAIT {
            panic!(
                "fewer than {count} {needle:?} lines\nstdout: {}\nstderr: {}",
                proc.out(),
                proc.err()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The newest code an `invite --link` shows.
fn shown_code(invite: &Proc, count: usize) -> String {
    let lines = lines_with(invite, "CODE ", count);
    let last = &lines[count - 1];
    last.split_whitespace().nth(1).unwrap_or("").to_owned()
}

/// A six-digit code that differs from `code` in every digit.
fn wrong_code(code: &str) -> String {
    code.bytes()
        .map(|d| char::from(b'0' + (d - b'0' + 1) % 10))
        .collect()
}

#[test]
fn send_link_right_code_pairs_and_three_wrong_codes_end_the_invitation() {
    let host = Endpoint::init("link-host");
    let phone = Endpoint::init("link-phone");
    let stranger = Endpoint::init("link-stranger");
    let server = host.serve("hostL", &[]);

    // The code shown on the host pairs.
    let invite = host.spawn(&["invite", "--link", "--no-qr"]);
    let ticket = invite.wait_for("TICKET ", WAIT)["TICKET ".len()..].to_owned();
    let mut join = phone.spawn_with_stdin(&["join", &ticket, "--name", "phone"]);
    let code = shown_code(&invite, 1);
    assert_eq!(code.len(), 6, "{code:?}");
    lines_with(&join, "shown on the host", 1);
    join.type_line(&format!("{code}\n"));
    let joined = join.finish(WAIT);
    assert!(joined.ok(), "join: {}", joined.text());
    invite.wait_for("paired: grant ", WAIT);
    let done = run_command(&phone, "hostL", &[], "link");
    assert!(done.stdout.contains("hello-link"), "{}", done.text());

    // Three wrong codes: a fresh code is shown for each attempt, and after
    // the third the invitation ends and nothing is granted.
    let mut invite = host.spawn(&["invite", "--link", "--no-qr"]);
    let ticket = invite.wait_for("TICKET ", WAIT)["TICKET ".len()..].to_owned();
    let mut join = stranger.spawn_with_stdin(&["join", &ticket, "--name", "stranger"]);
    let mut shown = Vec::new();
    for attempt in 1..=3 {
        lines_with(&join, "shown on the host", attempt);
        if attempt > 1 {
            lines_with(&join, "That code didn't work.", attempt - 1);
        }
        let code = shown_code(&invite, attempt);
        join.type_line(&format!("{}\n", wrong_code(&code)));
        shown.push(code);
    }
    shown.dedup();
    assert_eq!(shown.len(), 3, "each attempt shows a fresh code: {shown:?}");
    let refused = join.finish(WAIT);
    assert!(!refused.ok(), "{}", refused.text());
    assert!(
        refused.stderr.contains("ATTEMPTS_EXHAUSTED"),
        "{}",
        refused.text()
    );
    assert!(invite.exit_within(WAIT).is_some(), "invite still waiting");
    assert!(
        invite.err().contains("AttemptsExhausted"),
        "{}",
        invite.err()
    );
    // One grant, the phone's, named after its computer: a send link sends
    // no other name, so `--name phone` never reached the host.
    let listed = host.run(&["grants"]);
    assert_eq!(
        listed.stdout.matches("connections").count(),
        1,
        "{}",
        listed.text()
    );
    assert!(
        refused.stdout.contains("--name is not used"),
        "{}",
        refused.text()
    );
    assert!(!listed.stdout.contains("phone"), "{}", listed.text());

    // Opened again on the same device, the link has no tries left; on
    // another device the ended ticket is refused by the host.
    let again = stranger.run(&["join", &ticket]);
    assert!(!again.ok(), "{}", again.text());
    assert!(
        again.stderr.contains("ATTEMPTS_EXHAUSTED"),
        "{}",
        again.text()
    );
    let late = Endpoint::init("link-late");
    let refused = late.run(&["join", &ticket]);
    assert!(!refused.ok(), "{}", refused.text());
    assert!(
        refused.stderr.contains("INVITATION_INVALID"),
        "{}",
        refused.text()
    );

    stop(&host, server);
    cleanup(&[&host, &phone, &stranger, &late]);
}

#[test]
fn removing_the_grant_kills_a_silent_command_after_the_caller_finished_sending() {
    let host = Endpoint::init("silent-host");
    let peer = Endpoint::init("silent-peer");
    let server = host.serve("hostS", &[]);
    let (grant, _) = pair(&host, &peer, "laptop");

    // A command that writes a mark, stays silent for a while, then writes
    // another. The caller's stdin is empty, so it finishes its side of the
    // stream at once.
    let marks = temp_dir("silent-marks");
    std::fs::create_dir_all(&marks).unwrap();
    let (started, finished) = (marks.join("started"), marks.join("finished"));
    let command: Vec<String> = if cfg!(windows) {
        vec![
            "cmd".into(),
            "/c".into(),
            format!(
                "echo x>{} & ping -n 6 127.0.0.1 >nul & echo x>{}",
                started.display(),
                finished.display()
            ),
        ]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "touch '{}'; sleep 5; touch '{}'",
                started.display(),
                finished.display()
            ),
        ]
    };
    let mut args = vec!["term", "hostS", "--"];
    args.extend(command.iter().map(String::as_str));
    let mut term = peer.spawn(&args);
    let start = Instant::now();
    while !started.exists() {
        assert!(
            start.elapsed() < WAIT,
            "the command never started\nstdout: {}\nstderr: {}",
            term.out(),
            term.err()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let removed = host.run(&["remove", &grant.to_string()]);
    assert!(removed.ok(), "{}", removed.text());
    assert_closed_by_removal(&mut term);
    // The host killed the command: it never gets to its second mark.
    std::thread::sleep(Duration::from_secs(8));
    assert!(!finished.exists(), "the command kept running after removal");

    stop(&host, server);
    let _ = std::fs::remove_dir_all(&marks);
    cleanup(&[&host, &peer]);
}

#[test]
fn an_approval_answer_applies_only_to_the_request_it_names() {
    let host = Endpoint::init("ask-host");
    let first = Endpoint::init("ask-first");
    let second = Endpoint::init("ask-second");
    let server = host.serve("hostQ", &[]);

    // Two devices join with the same in-person ticket. The owner is asked
    // about the first; the second asks while that question is open.
    let mut invite = host.spawn_with_stdin(&["invite", "--no-qr"]);
    let ticket = invite.wait_for("TICKET ", WAIT)["TICKET ".len()..].to_owned();
    let mut join_first = first.spawn(&["join", &ticket, "--in-person", "--name", "first"]);
    invite.wait_for("\"first\"", WAIT);
    let mut join_second = second.spawn(&["join", &ticket, "--in-person", "--name", "second"]);
    server.proc.wait_for("approval requested for second", WAIT);

    // "Yes" to the question about the first device pairs that device only.
    invite.type_line("y\n");
    invite.wait_for("paired: grant ", WAIT);
    assert_eq!(
        join_first.exit_within(WAIT),
        Some(0),
        "{}",
        join_first.err()
    );
    assert_eq!(join_second.exit_within(WAIT), Some(2));
    assert!(
        join_second.err().contains("INVITATION_INVALID"),
        "{}",
        join_second.err()
    );
    let listed = host.run(&["grants"]);
    assert!(listed.stdout.contains("first"), "{}", listed.text());
    assert!(!listed.stdout.contains("second"), "{}", listed.text());

    stop(&host, server);
    cleanup(&[&host, &first, &second]);
}

#[test]
fn the_state_folder_control_file_and_control_channel_are_owner_only() {
    use mousse_net_io::private::is_owner_only;
    let host = Endpoint::init("private-host");
    let server = host.serve("hostP", &[]);
    assert!(is_owner_only(&host.dir).unwrap(), "state folder");
    let control = host.dir.join("control.json");
    assert!(is_owner_only(&control).unwrap(), "control.json");
    let addr = serde_json::from_slice::<serde_json::Value>(&std::fs::read(&control).unwrap())
        .unwrap()["addr"]
        .as_str()
        .unwrap()
        .to_owned();
    if cfg!(windows) {
        // A named pipe that allows the current user alone.
        assert!(addr.starts_with(r"\\.\pipe\"), "{addr}");
        assert!(is_owner_only(std::path::Path::new(&addr)).unwrap(), "pipe");
    } else {
        // A Unix socket in the owner-only state folder, owner-only itself.
        assert_eq!(addr, "unix:control.sock");
        assert!(
            is_owner_only(&host.dir.join("control.sock")).unwrap(),
            "control.sock"
        );
    }
    // The control channel still works for the owner.
    let status = host.run(&["id"]);
    assert!(status.stdout.contains("serving at"), "{}", status.text());
    stop(&host, server);
    cleanup(&[&host]);
}

#[test]
fn a_control_file_left_by_an_older_build_does_not_block_the_offline_commands() {
    let host = Endpoint::init("oldctl-host");
    let peer = Endpoint::init("oldctl-peer");
    let server = host.serve("hostO", &[]);
    let (grant, _) = pair(&host, &peer, "laptop");
    stop(&host, server);
    // An older `serve` recorded a port instead of an address and was
    // killed before it could remove the file.
    std::fs::write(
        host.dir.join("control.json"),
        br#"{"port":49152,"token":"00ff","pid":1}"#,
    )
    .unwrap();

    let id = host.run(&["id"]);
    assert!(id.ok() && id.stdout.contains("profile"), "{}", id.text());
    let listed = host.run(&["grants"]);
    assert!(
        listed.ok() && listed.stdout.contains("laptop"),
        "{}",
        listed.text()
    );
    let removed = host.run(&["remove", &grant.to_string()]);
    assert!(
        removed.ok() && removed.stdout.contains("host not running"),
        "{}",
        removed.text()
    );
    let listed = host.run(&["grants"]);
    assert!(listed.stdout.contains("no grants"), "{}", listed.text());
    cleanup(&[&host, &peer]);
}

/// `text` shows a peer's name escaped: the part after its newline does
/// not start a line of its own, and no escape sequence reaches the
/// terminal.
fn assert_escaped(text: &str, after_newline: &str) {
    assert!(
        !text.contains(&format!("\n{after_newline}")),
        "a peer's name started a line\n{text}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "an escape sequence got through\n{text}"
    );
}

#[test]
fn the_slice_check_runs_on_loopback_and_peer_names_print_escaped() {
    // Names chosen to forge log lines and drive a terminal.
    let host_name = "hostS\nPASS forged by the host\u{1b}[2J";
    let device_name = "laptop\nconnected forged by the device\u{1b}[31m";
    let host = Endpoint::init("slice-host");
    let peer = Endpoint::init("slice-peer");
    let server = host.serve(host_name, &[]);
    let mut invite = host.spawn_with_stdin(&["invite", "--no-qr"]);
    let ticket_line = invite.wait_for("TICKET ", WAIT);
    let ticket = ticket_line.trim_start_matches("TICKET ").trim().to_owned();

    let out = temp_dir("slice-result").with_extension("json");
    let out_arg = out.display().to_string();
    let command = echo_command("slice");
    let mut args = vec![
        "slice-check",
        "--ticket",
        &ticket,
        "--in-person",
        "--name",
        device_name,
        "--removal-timeout",
        "60",
        "--out",
        &out_arg,
        "--",
    ];
    args.extend(command.iter().map(String::as_str));
    let check = peer.spawn(&args);
    invite.wait_for("Is the device next to you?", WAIT);
    invite.type_line("y\n");
    check.wait_for("WAITING ", WAIT);
    let paired = invite.wait_for("paired: grant ", WAIT);
    let grant = paired
        .split("paired: grant ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap()
        .to_owned();

    let listed = host.run(&["grants"]);
    assert!(
        listed
            .stdout
            .contains(r"laptop\nconnected forged by the device\u{1b}[31m"),
        "{}",
        listed.text()
    );
    assert_escaped(&listed.stdout, "connected forged");
    let removed = host.run(&["remove", &grant]);
    assert!(removed.ok(), "{}", removed.text());

    let done = check.finish(WAIT + Duration::from_secs(15));
    assert_eq!(done.code, Some(0), "{}", done.text());
    assert!(done.stdout.contains("RESULT PASS"), "{}", done.text());
    // The host answered the build question, which it does only once the
    // request side of that stream is finished.
    assert!(
        done.stdout.contains(&format!(
            "PASS the host runs build {}",
            env!("MOUSSE_HELPER_BUILD")
        )),
        "{}",
        done.text()
    );
    assert!(
        done.stdout
            .contains(r"paired with hostS\nPASS forged by the host\u{1b}[2J ("),
        "{}",
        done.text()
    );
    assert_escaped(&done.stdout, "PASS forged");
    let result: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(result["outcome"], "PASS", "{result}");

    let peers = peer.run(&["peers"]);
    assert_escaped(&peers.stdout, "PASS forged");
    assert!(
        peers.stdout.contains(r"hostS\nPASS forged"),
        "{}",
        peers.text()
    );

    // The host's log and the inviting command show the device's name.
    let log = server.proc.out();
    assert!(
        log.contains(r"approval requested for laptop\nconnected forged"),
        "{log}"
    );
    assert_escaped(&log, "connected forged");
    let asked = invite.out();
    assert!(asked.contains(r"laptop\nconnected forged"), "{asked}");
    assert_escaped(&asked, "connected forged");
    drop(invite);
    stop(&host, server);
    cleanup(&[&host, &peer]);
    let _ = std::fs::remove_file(&out);
}

/// A bad `MOUSSE_NET_*` value stops the helper before it does anything,
/// with a message naming the variable and its allowed range.
#[test]
fn a_bad_limit_variable_stops_startup() {
    let dir = temp_dir("limits");
    for (name, value, says) in [
        (
            "MOUSSE_NET_KEEPALIVE_MS",
            "soon",
            "MOUSSE_NET_KEEPALIVE_MS=\"soon\" is not a whole number; allowed range is 1000 to 15000",
        ),
        (
            "MOUSSE_NET_CLOCK_SKEW_SECS",
            "601",
            "MOUSSE_NET_CLOCK_SKEW_SECS=601 is out of range; allowed range is 0 to 600",
        ),
        (
            "MOUSSE_NET_KEEPALIVE",
            "1000",
            "MOUSSE_NET_KEEPALIVE is not a known limit",
        ),
    ] {
        let out = Command::new(bin())
            .arg("--state")
            .arg(&dir)
            .arg("id")
            .env(name, value)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{name}={value}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{name}={value}: {stderr}");
        assert!(!dir.exists(), "{name}={value} created state");
    }
}
