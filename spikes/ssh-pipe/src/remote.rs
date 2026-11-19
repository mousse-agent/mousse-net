//! Commands the client runs on the remote end through the test server.

use std::io::{Read, Write};

pub const MARKER: &[u8] = b"mousse-ssh/1\n";

/// The marker, then stdin copied to stdout until stdin ends.
pub fn echo() -> i32 {
    let mut out = std::io::stdout().lock();
    out.write_all(MARKER).unwrap();
    out.flush().unwrap();
    let mut input = std::io::stdin().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match input.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.write_all(&buf[..n]).and_then(|_| out.flush()).is_err() {
                    return 1;
                }
            }
        }
    }
    0
}

/// The marker and this process's id, then sleeps without reading stdin
/// (a `pipe` that is stuck), for at most ten minutes.
pub fn sleeper() -> i32 {
    let mut out = std::io::stdout().lock();
    write!(out, "mousse-ssh/1\npid={}\n", std::process::id()).unwrap();
    out.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(600));
    0
}

/// Prints `alive` or `gone` for a process id.
pub fn alive(args: &[String]) -> i32 {
    let pid: u32 = args.first().and_then(|p| p.parse().ok()).expect("pid");
    let alive = is_alive(pid);
    println!("{}", if alive { "alive" } else { "gone" });
    0
}

#[cfg(unix)]
fn is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_alive(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .expect("tasklist");
    String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
}

/// macOS long socket path check (§3.3 "Long socket paths").
#[cfg(unix)]
pub fn sock_test(args: &[String]) -> i32 {
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    let base = PathBuf::from(args.first().expect("base dir"));
    // Pad a folder name so that <dir>/control.sock is exactly 150 bytes.
    let fixed = base.as_os_str().len() + "/".len() + "/control.sock".len();
    let pad = 150usize.checked_sub(fixed).expect("base too long");
    let dir = base.join("s".repeat(pad));
    std::fs::create_dir_all(&dir).unwrap();
    let full = dir.join("control.sock");
    let _ = std::fs::remove_file(&full);
    println!("path_bytes={}", full.as_os_str().len());
    match UnixListener::bind(&full) {
        Ok(_) => println!("absolute_bind=ok (unexpected)"),
        Err(e) => println!("absolute_bind=err kind={:?} msg={e}", e.kind()),
    }
    // The same through the OS, without std's own length check: `nc -U`.
    let nc = std::process::Command::new("nc")
        .arg("-U")
        .arg("-l")
        .arg(&full)
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn();
    if let Ok(mut nc) = nc {
        std::thread::sleep(std::time::Duration::from_millis(500));
        match nc.try_wait() {
            Ok(Some(st)) => {
                let mut err = String::new();
                nc.stderr.take().unwrap().read_to_string(&mut err).ok();
                println!("nc_absolute_bind=exited {st} stderr={}", err.trim());
            }
            _ => {
                let _ = nc.kill();
                let _ = nc.wait();
                println!("nc_absolute_bind=listening (path may have been truncated)");
            }
        }
    }
    let _ = std::fs::remove_file(&full);
    std::env::set_current_dir(&dir).unwrap();
    let listener = match UnixListener::bind("control.sock") {
        Ok(l) => {
            println!("relative_bind=ok");
            l
        }
        Err(e) => {
            println!("relative_bind=err {e}");
            return 1;
        }
    };
    let me = std::env::current_exe().unwrap();
    let child = std::process::Command::new(me)
        .arg("sock-connect")
        .arg(&dir)
        .current_dir("/")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (mut conn, _) = listener.accept().unwrap();
    let mut got = [0u8; 4];
    conn.read_exact(&mut got).unwrap();
    conn.write_all(b"pong").unwrap();
    let child = child.wait_with_output().unwrap();
    println!(
        "server_got={} client_said={}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&child.stdout).trim()
    );
    drop(listener);
    let _ = std::fs::remove_file(dir.join("control.sock"));
    0
}

#[cfg(unix)]
pub fn sock_connect(args: &[String]) -> i32 {
    use std::os::unix::net::UnixStream;
    let dir = std::path::PathBuf::from(args.first().expect("dir"));
    if let Err(e) = UnixStream::connect(dir.join("control.sock")) {
        print!("absolute_connect=err({e}) ");
    }
    std::env::set_current_dir(&dir).unwrap();
    let mut s = UnixStream::connect("control.sock").expect("relative connect");
    s.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    s.read_exact(&mut got).unwrap();
    println!(
        "relative_connect=ok reply={}",
        String::from_utf8_lossy(&got)
    );
    0
}

#[cfg(windows)]
pub fn sock_test(_: &[String]) -> i32 {
    eprintln!("Unix only");
    2
}

#[cfg(windows)]
pub fn sock_connect(_: &[String]) -> i32 {
    eprintln!("Unix only");
    2
}

/// Accepts TCP connections and never sends a byte (an SSH banner timeout).
pub fn quiet_listen(args: &[String]) -> i32 {
    let addr = args.first().expect("addr");
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(600);
    let l = std::net::TcpListener::bind(addr).expect("bind");
    println!("quiet {}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming().flatten() {
            held.push(s);
        }
    });
    std::thread::sleep(std::time::Duration::from_secs(secs));
    0
}
