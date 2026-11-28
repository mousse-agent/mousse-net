//! The Windows command forms of Phase 1b §3.3 through the real shells
//! (Windows only; elsewhere it says so and passes).
//!
//! Windows OpenSSH runs a remote command as `cmd.exe /c <command>`, or
//! `powershell.exe -c <command>` when PowerShell is the default shell, in
//! the user's profile folder. This runs [`remote_command`]'s exact strings
//! the same way, with a temporary home as the working folder, against
//! `.cmd` launchers in `<home>\.mousse\bin` like the ones Mousse writes,
//! around a byte-echo program (this test's own executable, run again as a
//! child). It checks that:
//!
//! - every byte value, CRLF and lone CR and LF, and 1 MiB of random bytes
//!   come back unchanged after the marker;
//! - the launcher's exit code is the session's;
//! - the arguments and `MOUSSE_HOME` reach the program as written;
//! - launcher targets in folders with a space, `&`, `(` and `%` work,
//!   written relative to `%LOCALAPPDATA%` or literally, and through `call`
//!   of another `.cmd`; a non-ASCII profile folder (a user name) works
//!   through `%USERPROFILE%` and `%LOCALAPPDATA%`. The launchers themselves
//!   are ASCII: `cmd` reads them in the console's code page, which is the
//!   OEM one (437 on US Windows) in an SSH session.
//! - the `sh` form's answer names each shell, and a missing launcher after
//!   the Windows form is `remote_not_installed`.
//!
//! It has its own `main` (`harness = false`), so the echo child writes
//! nothing but its bytes.

use mousse_net_io::pipe::ssh::{
    find_marker, reason_of_after, remote_command, MarkerSearch, RemoteShell, SshReason, MARKER,
};

/// Set for the echo child: the exit code it ends with.
const CHILD: &str = "MOUSSE_NET_TEST_ECHO_CHILD";

fn main() {
    if let Some(code) = std::env::var_os(CHILD) {
        echo(code.to_str().and_then(|c| c.parse().ok()).unwrap_or(1));
    }
    #[cfg(windows)]
    windows::run();
    #[cfg(not(windows))]
    println!("windows_shells: Windows only; skipped");
}

/// The echo child: its arguments and `MOUSSE_HOME` on stderr, the marker,
/// then stdin back on stdout until it ends; then `code`.
fn echo(code: i32) -> ! {
    use std::io::Write;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = std::env::var("MOUSSE_HOME").unwrap_or_default();
    eprintln!("args={}", args.join(" "));
    eprintln!("home={home}");
    let mut out = std::io::stdout().lock();
    out.write_all(MARKER).unwrap();
    std::io::copy(&mut std::io::stdin().lock(), &mut out).unwrap();
    out.flush().unwrap();
    std::process::exit(code);
}

/// Not used off Windows; keeps the imports in use there too.
#[allow(dead_code)]
fn after_marker(out: &[u8]) -> Option<&[u8]> {
    match find_marker(out, 64 * 1024) {
        MarkerSearch::After(at) => Some(&out[at..]),
        _ => None,
    }
}

#[allow(dead_code)]
fn reason(shell: RemoteShell, code: Option<i32>, stderr: &str) -> SshReason {
    reason_of_after(shell, code, stderr)
}

#[allow(dead_code)]
fn command(shell: RemoteShell, launcher: &str, args: &[&str]) -> String {
    remote_command(shell, launcher, args).unwrap()
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const SHELLS: [RemoteShell; 2] = [RemoteShell::Cmd, RemoteShell::PowerShell];

    /// What one session gave.
    struct Ended {
        code: Option<i32>,
        stdout: Vec<u8>,
        stderr: String,
    }

    /// The temporary home: a profile folder, its `AppData\Local`, and the
    /// echo program copied into folders whose names need care in `cmd`.
    struct Home {
        root: PathBuf,
        home: PathBuf,
        local: PathBuf,
    }

    impl Home {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "mousse-winshells-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let home = root.join("J\u{fc}rgen O'Brien & (home)");
            let local = home.join("AppData").join("Local");
            std::fs::create_dir_all(home.join(".mousse").join("bin")).unwrap();
            std::fs::create_dir_all(&local).unwrap();
            Self { root, home, local }
        }

        /// A copy of the echo program at `dir\echo.exe`.
        fn echo_in(&self, dir: &Path) -> PathBuf {
            std::fs::create_dir_all(dir).unwrap();
            let exe = dir.join("echo.exe");
            std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
            exe
        }

        fn launcher(&self, name: &str, text: &str) {
            assert!(text.is_ascii(), "a launcher is ASCII: {text}");
            let path = self
                .home
                .join(".mousse")
                .join("bin")
                .join(format!("{name}.cmd"));
            std::fs::write(path, text.replace('\n', "\r\n")).unwrap();
        }

        fn mousse_home(&self) -> String {
            self.home.join(".mousse").display().to_string()
        }

        /// Run `command` as Windows OpenSSH does in `shell`, in the home,
        /// with `input` on stdin; the echo child ends with `code`.
        fn session(&self, shell: RemoteShell, command: &str, input: &[u8], code: i32) -> Ended {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            let system = PathBuf::from(root).join("System32");
            let (exe, flag) = match shell {
                RemoteShell::Cmd => (system.join("cmd.exe"), "/c"),
                _ => (
                    system
                        .join("WindowsPowerShell")
                        .join("v1.0")
                        .join("powershell.exe"),
                    "-c",
                ),
            };
            // `CREATE_NO_WINDOW`: a console of its own, in the system's OEM
            // code page as in an SSH session, not the test runner's.
            let mut child = Command::new(exe)
                .creation_flags(0x0800_0000)
                .raw_arg(flag)
                .raw_arg(command)
                .current_dir(&self.home)
                .env("USERPROFILE", &self.home)
                .env("LOCALAPPDATA", &self.local)
                .env(CHILD, code.to_string())
                .env_remove("MOUSSE_HOME")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let input = input.to_vec();
            let feed = std::thread::spawn(move || {
                let _ = stdin.write_all(&input);
            });
            let mut stderr = child.stderr.take().unwrap();
            let errs = std::thread::spawn(move || {
                let mut text = Vec::new();
                let _ = stderr.read_to_end(&mut text);
                String::from_utf8_lossy(&text).into_owned()
            });
            let mut stdout = Vec::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut stdout)
                .unwrap();
            feed.join().unwrap();
            let code = child.wait().unwrap().code();
            Ended {
                code,
                stdout,
                stderr: errs.join().unwrap(),
            }
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Every byte value, line ends, then 1 MiB from a fixed xorshift.
    fn payload() -> Vec<u8> {
        let mut out: Vec<u8> = (0..=255u8).collect();
        out.extend_from_slice(b"a\r\nb\nc\rd\r\n\r\n");
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..(1 << 20) / 8 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out
    }

    /// A launcher as Mousse writes it: `MOUSSE_HOME` from `%USERPROFILE%`,
    /// then `target` with the arguments.
    fn launcher_text(target: &str) -> String {
        format!(
            "@echo off\nsetlocal DisableDelayedExpansion\nset \"MOUSSE_HOME=%USERPROFILE%\\.mousse\"\n{target} %*\nexit /b %ERRORLEVEL%\n"
        )
    }

    fn check(h: &Home, shell: RemoteShell, command: &str, args: &str, what: &str) {
        let input = payload();
        let got = h.session(shell, command, &input, 7);
        let tag = format!("{shell:?} {what}");
        assert_eq!(got.code, Some(7), "{tag}: exit; stderr {}", got.stderr);
        let bytes = after_marker(&got.stdout)
            .unwrap_or_else(|| panic!("{tag}: no marker; stderr {}", got.stderr));
        assert_eq!(bytes.len(), input.len(), "{tag}: length");
        assert!(bytes == input.as_slice(), "{tag}: the bytes changed");
        assert!(
            got.stderr.contains(&format!("args={args}\n"))
                || got.stderr.contains(&format!("args={args}\r\n")),
            "{tag}: {}",
            got.stderr
        );
        assert!(
            got.stderr.contains(&format!("home={}", h.mousse_home())),
            "{tag}: {}",
            got.stderr
        );
    }

    pub fn run() {
        let h = Home::new();
        let sel = "abcdefghijklmnopqrstuvwx23";

        // A target under %LOCALAPPDATA% (inside the non-ASCII profile
        // folder), in a folder with a space, `&` and `(`.
        h.echo_in(&h.local.join("Programs (x86) & Mousse"));
        h.launcher(
            "mousse-helper",
            &launcher_text("\"%LOCALAPPDATA%\\Programs (x86) & Mousse\\echo.exe\""),
        );
        // `mousse-cli` calls another `.cmd` (the app's own `mousse-cli.cmd`),
        // here written literally. `call` expands `%` once more, so a `%` on
        // its line is written `%%%%`.
        let app = h.root.join("100% sure & (app)");
        let exe = h.echo_in(&app);
        std::fs::write(
            app.join("mousse-cli.cmd"),
            "@echo off\r\nsetlocal\r\n\"%~dp0echo.exe\" %*\r\nexit /b %ERRORLEVEL%\r\n",
        )
        .unwrap();
        let literal = app.join("mousse-cli.cmd").display().to_string();
        assert!(
            literal.is_ascii(),
            "the temporary folder must be ASCII here"
        );
        let _ = exe;
        h.launcher(
            "mousse-cli",
            &launcher_text(&format!("call \"{}\"", literal.replace('%', "%%%%"))),
        );

        for shell in SHELLS {
            check(
                &h,
                shell,
                &command(shell, "mousse-helper", &["pipe", "--profile", sel]),
                &format!("pipe --profile {sel}"),
                "helper",
            );
            check(
                &h,
                shell,
                &command(shell, "mousse-cli", &["net-engine", "ssh"]),
                "net-engine ssh",
                "cli",
            );

            // The `sh` form names the shell.
            let got = h.session(
                shell,
                &command(RemoteShell::Sh, "mousse-cli", &["net-engine", "ssh"]),
                b"",
                0,
            );
            assert_eq!(
                reason(RemoteShell::Sh, got.code, &got.stderr),
                SshReason::WindowsRemoteUnsupported,
                "{shell:?}: {}",
                got.stderr
            );
            assert_eq!(
                RemoteShell::windows_of(&got.stderr),
                Some(shell),
                "{}",
                got.stderr
            );

            // No launcher, then no `.mousse\bin` at all.
            let missing = command(shell, "mousse-nothing", &["x"]);
            let got = h.session(shell, &missing, b"", 0);
            assert_eq!(
                reason(shell, got.code, &got.stderr),
                SshReason::RemoteNotInstalled,
                "{shell:?}: {}",
                got.stderr
            );
        }
        let bin = h.home.join(".mousse").join("bin");
        std::fs::rename(&bin, h.home.join(".mousse").join("bin-gone")).unwrap();
        for shell in SHELLS {
            let got = h.session(
                shell,
                &command(shell, "mousse-cli", &["net-engine", "ssh"]),
                b"",
                0,
            );
            assert_eq!(
                reason(shell, got.code, &got.stderr),
                SshReason::RemoteNotInstalled,
                "{shell:?}: {}",
                got.stderr
            );
        }
        println!("windows_shells: cmd and PowerShell passed");
    }
}
