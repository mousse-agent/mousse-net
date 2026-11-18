//! The helper binary end to end on loopback: endpoints in their own state
//! directories, hosts serving on 127.0.0.1, peers pairing in person and
//! opening terminals.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mousse-helper")
}

fn temp_dir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mousse-helper-it-{tag}-{}-{n}", std::process::id()))
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
    let invite = host.spawn(&["invite", "--approve-next", "--no-qr"]);
    let ticket_line = invite.wait_for("TICKET ", WAIT);
    let ticket = ticket_line.trim_start_matches("TICKET ").trim().to_owned();
    let joined = peer.run(&["join", &ticket, "--name", peer_name]);
    assert!(joined.ok(), "join: {}", joined.text());
    let paired = invite.wait_for("paired: grant ", WAIT);
    let grant = paired
        .split_whitespace()
        .nth(2)
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
    let replay = other.run(&["join", &ticket, "--name", "intruder"]);
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
    let mut join = other.spawn(&["join", &fresh, "--name", "intruder"]);
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
    let listed = host.run(&["grants"]);
    assert!(listed.stdout.contains("phone"), "{}", listed.text());
    assert!(!listed.stdout.contains("stranger"), "{}", listed.text());

    // The ended ticket does not work again.
    let again = stranger.run(&["join", &ticket, "--name", "stranger"]);
    assert!(!again.ok(), "{}", again.text());
    assert!(
        again.stderr.contains("INVITATION_INVALID"),
        "{}",
        again.text()
    );

    stop(&host, server);
    cleanup(&[&host, &phone, &stranger]);
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
    let mut join_first = first.spawn(&["join", &ticket, "--name", "first"]);
    invite.wait_for("\"first\"", WAIT);
    let mut join_second = second.spawn(&["join", &ticket, "--name", "second"]);
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
    }
    // The control channel still works for the owner.
    let status = host.run(&["id"]);
    assert!(status.stdout.contains("serving at"), "{}", status.text());
    stop(&host, server);
    cleanup(&[&host]);
}
