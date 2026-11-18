//! Counts the process's open socket file descriptors, as the OS sees them.
//! Used to prove that dials, cancels and stop leave no socket behind.

use std::os::unix::fs::FileTypeExt;

fn fd_dir() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    }
}

/// Number of open file descriptors that are sockets (any family), or -1 if the
/// descriptor table can't be read.
#[uniffi::export]
pub fn open_socket_fds() -> i32 {
    let dir = fd_dir();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return -1;
    };
    let mut n = 0;
    for entry in entries.flatten() {
        // stat follows the descriptor to the open object, so a socket reports as one.
        if let Ok(meta) = std::fs::metadata(entry.path())
            && meta.file_type().is_socket()
        {
            n += 1;
        }
    }
    n
}

/// Which table of `/proc/net` lists this socket inode (Linux and Android only).
fn proc_net_kind(inode: &str) -> Option<String> {
    for table in [
        "tcp", "tcp6", "udp", "udp6", "unix", "netlink", "raw", "raw6",
    ] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/self/net/{table}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let hit = match table {
                // Local address is column 1 and the inode column 9 for tcp/udp/raw.
                "tcp" | "tcp6" | "udp" | "udp6" | "raw" | "raw6" => (cols.get(9) == Some(&inode))
                    .then(|| format!("{table} {}", cols.get(1).unwrap_or(&""))),
                "unix" => (cols.get(6) == Some(&inode))
                    .then(|| format!("unix {}", cols.get(7).copied().unwrap_or("(unnamed)"))),
                _ => line.contains(inode).then(|| table.to_string()),
            };
            if hit.is_some() {
                return hit;
            }
        }
    }
    None
}

/// One line per open socket descriptor: `fd=<n> <what>`. On Linux and Android
/// `<what>` names the table (tcp, unix, ...) and local address; elsewhere just `socket`.
/// For diagnosing a socket count that changed.
#[uniffi::export]
pub fn socket_fd_list() -> Vec<String> {
    let dir = fd_dir();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_socket() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let link = std::fs::read_link(&path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let inode = link
            .strip_prefix("socket:[")
            .and_then(|s| s.strip_suffix(']'));
        let what = inode.and_then(proc_net_kind).unwrap_or_else(|| {
            if link.is_empty() {
                "socket".into()
            } else {
                link.clone()
            }
        });
        out.push(format!("fd={name} {what}"));
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn counts_a_listener() {
        let before = super::open_socket_fds();
        assert!(before >= 0);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(super::open_socket_fds(), before + 1);
        drop(l);
        assert_eq!(super::open_socket_fds(), before);
    }
}
