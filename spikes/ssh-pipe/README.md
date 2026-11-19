# S1: the pipe spike

Phase 1b design §3.1 to §3.3 and §3.7; §15 row S1. Result recorded in
§16 "Spike results (S1, S2)". Run on 2026-11-19.

## What is here

- `src/sshd.rs`: the test SSH server, written to be lifted into
  `crates/mousse-helper/tests/common/sshd.rs`. `russh` `=0.65.2`
  (`default-features = false, features = ["aws-lc-rs"]`), `tokio`, `rand`.
  No `unsafe`. One generated Ed25519 host key, exactly one accepted client
  key, exec requests only (shell, pty and subsystem are refused), the
  command run as the current user through `/bin/sh -c` (Unix) or
  `cmd.exe /c <command>` (Windows), with `HOME`, `MOUSSE_HOME` (and
  `USERPROFILE` on Windows) set and the home as working directory. stdin,
  stdout, stderr and the exit status are wired. A configurable preamble is
  printed on stdout before the command's output. When the channel or the
  session ends the child's whole tree is killed (Unix process group,
  `taskkill /T /F` on Windows).
- `src/drive.rs`: the client side. It writes §3.1's constrained config
  (`-F <state>/ssh/<alias>.conf`, `HostKeyAlias`, `UserKnownHostsFile` in
  the state folder, `GlobalKnownHostsFile none`, `StrictHostKeyChecking
  yes`, `IdentitiesOnly yes`, `IdentityAgent none`, the generated key) and
  runs the system client with §3.1's fixed options. It never reads
  `~/.ssh`.
- `src/remote.rs`: commands run on the remote end (`echo`, `sleeper`,
  `alive`), the macOS socket check (`sock-test`) and a quiet TCP listener.
- `src/winpipe.rs`: an owner-only named pipe made as
  `crates/mousse-net-io/src/private.rs` makes it (`D:P(A;;GA;;;<user SID>)`,
  remote clients rejected), and a client that splices it like
  `mousse-helper pipe`.

Build (PC): `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc cargo build`.
`aws-lc-rs` is listed only to turn on `prebuilt-nasm`; `aws-lc-sys` needs
NASM on Windows otherwise.

## Method

| Run | Server | Client |
|---|---|---|
| Windows | PC, `127.0.0.1` | `C:\Windows\System32\OpenSSH\ssh.exe` (OpenSSH_for_Windows_9.5p2) |
| PC to Mac | Mac mini, `192.168.0.59:47101` | PC `ssh.exe` 9.5p2 |
| macOS | Mac, `127.0.0.1:47103` (`/bin/sh`) and `:47105` (`/bin/zsh` with a `.zshenv`) | `/usr/bin/ssh` (OpenSSH_10.3p1) |
| Linux | WSL `mousse-sandbox`, `127.0.0.1` | `ssh` (OpenSSH_9.6p1 Ubuntu) |

Each run: `keygen` (system `ssh-keygen`, two Ed25519 keys) in a state
folder named `state dir O'Brien`, the server with a preamble, then
`drive`: probe, trust, strict connect with 1 MiB of random bytes echoed,
five timed sessions, the quoting matrix, the stderr cases and the kill
check.

## Results

1. **Constrained config with the system client: works** on Windows
   (9.5p2), macOS (10.3p1), Linux (9.6p1), and PC to Mac over the LAN.
   `ControlMaster=no`/`ControlPath=none` are accepted by Windows `ssh.exe`.
   Session setup (login, marker, exit): Windows loopback 0.13 to 0.43 s,
   PC to Mac 0.12 to 0.27 s, Linux 61 ms, macOS 15 ms.
2. **Quoting in the config file** (Windows `ssh.exe` 9.5p2; Linux and
   macOS the same):
   - A path is written in double quotes. Inside them a space and an
     apostrophe need nothing. On Windows, backslashes and forward slashes
     both work; doubled backslashes work too (Windows folds them).
   - `%` must be written `%%`. Unescaped, `100%\x` fails with
     `vdollar_percent_expand: unknown key %\`, and `%d` silently expands to
     the home folder, so the wrong `known_hosts` is read
     (`host_key_unknown`).
   - Single quotes break on an apostrophe in the path (`invalid quotes` /
     `extra arguments at end of line`). Unquoted paths split at spaces.
   - The same holds for a `-o UserKnownHostsFile=...` value on the
     command line (the probe uses one): it needs the inner double quotes,
     or ssh reads two files.
3. **Host key probe** (`-N`, `PubkeyAuthentication`, `PasswordAuthentication`,
   `KbdInteractiveAuthentication`, `HostbasedAuthentication` all `no`,
   `StrictHostKeyChecking=accept-new`, `HashKnownHosts=no`, a temporary
   `UserKnownHostsFile`): exits 255 with `Permission denied (publickey).`
   after writing one line `mousse-<id> ssh-ed25519 AAAA...` (keyed by the
   `HostKeyAlias`). The key bytes are that line's base64; SHA256 is
   `SHA256:` + unpadded base64 of the SHA-256 of the key blob, matching the
   server's fingerprint on all three clients. Writing that line to the
   route's `known_hosts` makes the strict connect pass; another key for
   the alias fails with `Host key for mousse-<id> has changed and you have
   requested strict checking.`
4. **Preamble and marker: works, with one change to the client rule.** A
   139-byte preamble (text, CRLF, ANSI codes, a line containing
   `mousse-ssh/1 is not alone on this line`) is skipped; 1 MiB of random
   bytes then echoes back identical on every OS pair, including Windows
   `ssh.exe` and a Windows remote through `cmd /c` and a `.cmd` launcher.
   A `.zshenv` that prints without a final newline (`print -n`) puts the
   marker mid-line (`no newline at endmousse-ssh/1`), so a client that
   wants the marker at the start of a line fails. The client must skip to
   the first `mousse-ssh/1\n` anywhere in the first
   `SSH_PREAMBLE_MAX_BYTES`. §3.3's `exec /bin/sh -c '"$HOME"/.mousse/bin/<launcher> <args>'`
   form passes through zsh as the login shell unchanged.
5. **150-byte Unix socket path on macOS: as designed.** Binding the
   absolute path fails (`path must be shorter than SUN_LEN` from Rust's
   std; `nc -U -l` fails with `File name too long`); after changing to the
   socket's folder, binding and connecting by the relative name
   `control.sock` work (another process connected after its own `chdir`).
   Linux behaves the same.
6. **Killing the client ends the remote child, on each OS:** the remote
   `sleeper` (which never reads stdin) was gone 15 ms (macOS), 62 ms
   (Linux), 520 ms (PC to Mac) and about 1.1 s (Windows, through
   `cmd /c` and a `.cmd` launcher; most of it is `tasklist`) after the
   client was killed. This is the test server's own kill on session end;
   it shows the client's death reaches the server at once.
7. **Stderr texts** (exit code 255 unless noted; `LogLevel=ERROR`):

   | Reason | Text |
   |---|---|
   | `auth_denied` | `<user>@<host>: Permission denied (publickey).` |
   | `host_key_changed` | `@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @` banner, then `Host key for <alias> has changed and you have requested strict checking.` and `Host key verification failed.` |
   | `host_key_unknown` | `No ED25519 host key is known for <alias> and you have requested strict checking.` then `Host key verification failed.` (same with the file missing) |
   | `unreachable` (refused) | Unix: `ssh: connect to host <h> port <p>: Connection refused`. Windows 9.5p2 with `ConnectTimeout` set: **nothing on stderr** at `LogLevel=ERROR`, after about 2.1 s; at `INFO` it prints `banner exchange: Connection to UNKNOWN port -1: Connection refused` |
   | `timeout` (connect) | `ssh: connect to host <h> port <p>: Connection timed out` (Linux, in a private network namespace dropping every packet; Windows prints the same for a refused port when `ConnectTimeout` is under about 2 s) |
   | `timeout` (banner) | `Connection timed out during banner exchange` (all three) |
   | `remote_not_installed` | exit 127 with `/bin/sh: 1: <cmd>: not found` (dash) or `/bin/sh: <cmd>: command not found` (macOS); a `cmd` remote exits **1** with `'<cmd>' is not recognized as an internal or external command,` / `operable program or batch file.` |

   So the mapping must treat "exit 255, empty stderr" as `unreachable`
   (Windows), and must not rely on 127 alone for a Windows remote.
8. **Windows as a remote: no-go.**
   - Key logon reaching a GUI-session pipe: **not tested.** Registering an
     S4U (non-interactive, no stored password) scheduled task is refused
     for the non-elevated user (`Access is denied`); a password logon
     would need a stored password, and Windows `sshd` was not installed.
     Within one interactive session the owner-only pipe opens and carries
     1 MiB both ways through `ssh` → `cmd /c` → `.cmd` launcher →
     client → pipe.
   - Remote process exits when the session is killed: **not tested with
     Windows `sshd`.** With the stand-in server it does, because the
     stand-in kills the tree; whether Windows `sshd` does is unknown.
   - Space in the launcher path, `cmd /c` form: works only in the
     outer-quotes form `""<launcher path>" <args>"` (also with
     `%USERPROFILE%`). The plain form `"<launcher path>" <args>` breaks
     once the path has `&` or `(`/`)` (`cmd` drops the quotes; seen with
     `home O'Brien & Co (x)`); a space or apostrophe alone is fine.
     `cmd /s /c ""…" args"` nested inside fails the same way. This
     assumes Windows `sshd` runs `cmd.exe /c <command>` as the stand-in
     does; not checked against `sshd`.

   Decision: Windows remotes are refused in 1b with
   `windows_remote_unsupported`.

## Not done here

- Windows `sshd` itself (not installed on purpose), so its command line
  for `cmd` and its session teardown are unverified.
- Real login shells other than zsh on macOS (fish, bash with `.bashrc`).
