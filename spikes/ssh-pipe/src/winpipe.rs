//! Windows as a remote (risk 1): an owner-only named pipe made the way
//! `crates/mousse-net-io/src/private.rs` makes it, served from the GUI
//! session, opened from another logon (a batch logon through Task Scheduler).

use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_PIPE_BUSY};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::Args;

/// `--name foo` is the pipe `foo` on this computer.
fn pipe_name(args: &Args) -> String {
    let name = args.need("--name");
    let bs = '\u{5c}';
    if name.starts_with(bs) {
        name
    } else {
        format!("{bs}{bs}.{bs}pipe{bs}{name}")
    }
}

/// The current user's SID, from `whoami /user`.
fn user_sid() -> String {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami");
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

/// Logon groups and integrity level of this process, from `whoami /groups`.
pub fn context() -> String {
    let out = std::process::Command::new("whoami")
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tags = Vec::new();
    for line in text.lines() {
        let name = line.split(',').next().unwrap_or("").trim_matches('"');
        for key in [
            "INTERACTIVE",
            "BATCH",
            "SERVICE",
            "CONSOLE LOGON",
            "REMOTE INTERACTIVE",
        ] {
            if name.ends_with(key) {
                tags.push(key.to_string());
            }
        }
        if name.starts_with("Mandatory Label") {
            tags.push(name.trim_start_matches("Mandatory Label\\").to_string());
        }
    }
    format!("{} session={}", tags.join(","), session_id())
}

fn session_id() -> String {
    let out = std::process::Command::new("tasklist")
        .args([
            "/FI",
            &format!("PID eq {}", std::process::id()),
            "/NH",
            "/FO",
            "CSV",
        ])
        .output()
        .expect("tasklist");
    let text = String::from_utf8_lossy(&out.stdout);
    text.split(',')
        .nth(3)
        .unwrap_or("?")
        .trim_matches('"')
        .to_string()
}

fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let sddl = format!("D:P(A;;GA;;;{})", user_sid());
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid NUL-terminated input and out pointer.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attrs` and the descriptor outlive the call.
    let server = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    // SAFETY: allocated by ConvertStringSecurityDescriptor...W.
    unsafe { LocalFree(sd) };
    server
}

/// Serve `NAME`: each connection is echoed until the client closes.
pub fn server(args: &Args) -> i32 {
    let name = pipe_name(args);
    let secs: u64 = args
        .get("--seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        println!("server context: {}", context());
        let mut server = create(&name, true).expect("create pipe");
        println!("listening {name}");
        let serve = async {
            loop {
                server.connect().await.expect("connect");
                let next = create(&name, false).expect("create pipe");
                let mut conn = std::mem::replace(&mut server, next);
                println!("client connected");
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut total = 0usize;
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                total += n;
                                if conn.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    println!("client gone after {total} bytes");
                });
            }
        };
        tokio::select! {
            _ = serve => {}
            _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        }
    });
    0
}

/// Open `NAME` like `mousse-helper pipe` would: print the marker, then
/// splice stdin and stdout to the pipe. Ends when the pipe closes, or once
/// every byte sent after stdin ended has come back.
pub fn client(args: &Args) -> i32 {
    let name = pipe_name(args);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        eprintln!("client context: {}", context());
        let pipe = loop {
            match ClientOptions::new().open(&name) {
                Ok(p) => break p,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => {
                    eprintln!("mousse-pipe: open failed: {e}");
                    return 2;
                }
            }
        };
        eprintln!("client opened the pipe");
        let mut stdout = tokio::io::stdout();
        stdout.write_all(crate::remote::MARKER).await.unwrap();
        stdout.flush().await.unwrap();
        let (mut pr, mut pw) = tokio::io::split(pipe);
        let (sent_tx, mut sent_rx) = tokio::sync::watch::channel::<Option<usize>>(None);
        let up = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 64 * 1024];
            let mut sent = 0usize;
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sent += n;
                        if pw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = sent_tx.send(Some(sent));
        });
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0usize;
        loop {
            if let Some(sent) = *sent_rx.borrow() {
                if got >= sent {
                    break;
                }
            }
            tokio::select! {
                r = pr.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if stdout.write_all(&buf[..n]).await.is_err() { break; }
                        let _ = stdout.flush().await;
                    }
                },
                _ = sent_rx.changed() => {}
            }
        }
        up.abort();
        0
    })
}
