//! Where the helper's own lines go. On the command line they go to stdout.
//! In app mode stdout carries only app-channel frames, so they go to
//! `<state>/helper.log` instead, rotated at `APP_LOG_MAX_BYTES` with
//! `APP_LOG_FILES` files kept (`helper.log`, `helper.log.1`, ...).
//!
//! Lines never carry secrets: no keys, tickets or pairing codes.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The log file's name in the state directory.
pub const LOG_FILE: &str = "helper.log";

struct FileLog {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    max: u64,
    files: u64,
}

impl FileLog {
    fn open(path: PathBuf, max: u64, files: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            file: Some(file),
            size,
            max,
            files,
        })
    }

    fn rotated(&self, n: u64) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// Start a new file: `helper.log` becomes `helper.log.1`, and so on;
    /// the oldest beyond `files` goes.
    fn rotate(&mut self) {
        self.file = None;
        let keep = self.files.saturating_sub(1);
        if keep == 0 {
            let _ = std::fs::remove_file(&self.path);
        } else {
            let _ = std::fs::remove_file(self.rotated(keep));
            for n in (1..keep).rev() {
                let _ = std::fs::rename(self.rotated(n), self.rotated(n + 1));
            }
            let _ = std::fs::rename(&self.path, self.rotated(1));
        }
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        self.size = 0;
    }

    fn write(&mut self, line: &str) {
        let len = line.len() as u64;
        if self.size > 0 && self.size.saturating_add(len) > self.max {
            self.rotate();
        }
        if let Some(file) = self.file.as_mut() {
            if file.write_all(line.as_bytes()).is_ok() {
                self.size = self.size.saturating_add(len);
            }
        }
    }
}

fn sink() -> &'static Mutex<Option<FileLog>> {
    static SINK: OnceLock<Mutex<Option<FileLog>>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(None))
}

/// Send every later line to `<dir>/helper.log` instead of stdout.
pub fn to_file(dir: &Path) -> Result<(), String> {
    let limits = crate::limits::helper();
    let log = FileLog::open(
        dir.join(LOG_FILE),
        limits.app_log_max_bytes(),
        limits.app_log_files(),
    )
    .map_err(|e| format!("cannot open {LOG_FILE}: {e}"))?;
    *sink().lock().unwrap_or_else(|e| e.into_inner()) = Some(log);
    Ok(())
}

/// One line of the helper's own output.
pub fn line(text: impl AsRef<str>) {
    let text = text.as_ref();
    let mut sink = sink().lock().unwrap_or_else(|e| e.into_inner());
    match sink.as_mut() {
        Some(log) => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            log.write(&format!("{secs} {text}\n"));
        }
        None => {
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("mousse-helper-log-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_log_rotates_and_keeps_its_file_count() {
        let d = dir("rotate");
        let mut log = FileLog::open(d.join(LOG_FILE), 100, 2).unwrap();
        for i in 0..10 {
            log.write(&format!("line {i:02} {}\n", "x".repeat(30)));
        }
        let current = std::fs::read_to_string(d.join(LOG_FILE)).unwrap();
        let older = std::fs::read_to_string(d.join("helper.log.1")).unwrap();
        assert!(current.len() <= 100 && older.len() <= 100);
        assert!(current.contains("line 09"), "{current}");
        assert!(older.contains("line 08") || older.contains("line 07"));
        assert!(!d.join("helper.log.2").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_file_means_the_log_starts_over() {
        let d = dir("one");
        let mut log = FileLog::open(d.join(LOG_FILE), 50, 1).unwrap();
        for i in 0..5 {
            log.write(&format!("line {i} {}\n", "y".repeat(30)));
        }
        let current = std::fs::read_to_string(d.join(LOG_FILE)).unwrap();
        assert!(current.contains("line 4") && !current.contains("line 3"));
        assert!(!d.join("helper.log.1").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
