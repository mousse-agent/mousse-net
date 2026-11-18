//! Owner-only state: folders and files that only the OS user running the
//! endpoint can open, and on Windows the owner-only named pipe for the local
//! control channel.
//!
//! - Unix: folders `0700`, files `0600`.
//! - Windows: a protected DACL (no inherited entries) with one entry, full
//!   access for the current user. A folder's entry is inherited by what is
//!   created in it, so new files start owner-only as well.
//!
//! This is the only module with `unsafe` code: the Windows security calls.

use std::fs;
use std::io;
use std::path::Path;

/// Create `dir` (and its parents) and make it owner-only.
pub fn make_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    restrict(dir, true)
}

/// Make an existing file owner-only.
pub fn restrict_file(path: &Path) -> io::Result<()> {
    restrict(path, false)
}

/// Whether only the current user can open `path`.
pub fn is_owner_only(path: &Path) -> io::Result<bool> {
    imp::is_owner_only(path)
}

/// Rename `from` over `to`. On Windows the rename is written through to
/// disk before it returns; on Unix the folder is synced after it.
pub fn replace_durably(from: &Path, to: &Path) -> io::Result<()> {
    imp::replace_durably(from, to)
}

fn restrict(path: &Path, dir: bool) -> io::Result<()> {
    imp::restrict(path, dir)
}

#[cfg(unix)]
mod imp {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    pub fn restrict(path: &Path, dir: bool) -> io::Result<()> {
        let mode = if dir { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    pub fn is_owner_only(path: &Path) -> io::Result<bool> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o077 == 0)
    }

    pub fn replace_durably(from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)?;
        if let Some(dir) = to.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use imp::create_pipe_server;

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    /// Read a NUL-terminated UTF-16 string that the system allocated, and
    /// free it.
    ///
    /// # Safety
    /// `ptr` is null or a `LocalAlloc`ed NUL-terminated string.
    unsafe fn take_wide(ptr: *mut u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        // SAFETY: the string is NUL-terminated.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units were just read.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) });
        // SAFETY: allocated by the system with LocalAlloc.
        unsafe { LocalFree(ptr.cast()) };
        text
    }

    /// The current user's SID as text (`S-1-5-...`).
    fn user_sid() -> io::Result<String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: valid out pointer; the pseudo handle needs no closing.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        // SAFETY: a size query with no buffer.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
        // u64 units keep the buffer aligned for TOKEN_USER.
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: the buffer holds at least `len` bytes.
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        };
        let err = io::Error::last_os_error();
        // SAFETY: the token handle is ours.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(err);
        }
        // SAFETY: GetTokenInformation filled a TOKEN_USER at the start of
        // the aligned buffer; its SID points into the same buffer.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text: *mut u16 = null_mut();
        // SAFETY: `sid` is valid while `buf` lives.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: allocated by ConvertSidToStringSidW.
        Ok(unsafe { take_wide(text) })
    }

    /// A security descriptor built from SDDL, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn owner_only(rights: &str, inherit: bool) -> io::Result<Self> {
            let sid = user_sid()?;
            let flags = if inherit { "OICI" } else { "" };
            let sddl = format!("D:P(A;{flags};{rights};;;{sid})");
            let text = wide(sddl.as_ref());
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: valid NUL-terminated input and out pointer.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(sd))
        }

        fn dacl(&self) -> io::Result<*mut ACL> {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: `self.0` is a valid descriptor; out pointers are valid.
            let ok = unsafe {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)
            };
            if ok == 0 || present == 0 || dacl.is_null() {
                return Err(io::Error::other("no DACL in the descriptor"));
            }
            Ok(dacl)
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptor...W.
            unsafe { LocalFree(self.0) };
        }
    }

    pub fn restrict(path: &Path, dir: bool) -> io::Result<()> {
        let sd = Descriptor::owner_only("FA", dir)?;
        let dacl = sd.dacl()?;
        let name = wide(path.as_os_str());
        // SAFETY: valid name and DACL; owner, group and SACL are not set.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    /// The DACL of `path` as SDDL.
    fn dacl_sddl(path: &Path) -> io::Result<String> {
        let name = wide(path.as_os_str());
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: valid name and out pointers.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut text: *mut u16 = null_mut();
        // SAFETY: `sd` came from GetNamedSecurityInfoW.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        let err = io::Error::last_os_error();
        // SAFETY: allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(sd) };
        if ok == 0 {
            return Err(err);
        }
        // SAFETY: allocated by the conversion above.
        Ok(unsafe { take_wide(text) })
    }

    pub fn is_owner_only(path: &Path) -> io::Result<bool> {
        let sddl = dacl_sddl(path)?;
        Ok(sddl_is_owner_only(&sddl, &user_sid()?))
    }

    /// A protected DACL whose every entry allows only `sid`.
    pub(super) fn sddl_is_owner_only(sddl: &str, sid: &str) -> bool {
        let Some(rest) = sddl.strip_prefix("D:") else {
            return false;
        };
        let (flags, aces) = rest.split_at(rest.find('(').unwrap_or(rest.len()));
        if !flags.contains('P') || aces.is_empty() {
            return false;
        }
        aces.trim_end_matches(')').split(')').all(|ace| {
            let fields: Vec<&str> = ace.trim_start_matches('(').split(';').collect();
            fields.len() == 6 && fields[0] == "A" && fields[5] == sid
        })
    }

    pub fn replace_durably(from: &Path, to: &Path) -> io::Result<()> {
        let (a, b) = (wide(from.as_os_str()), wide(to.as_os_str()));
        // SAFETY: valid NUL-terminated names.
        let ok = unsafe {
            MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A named pipe instance only the current user can open, local clients
    /// only. `first` refuses to start if the name exists already (another
    /// process got there first).
    pub fn create_pipe_server(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let sd = Descriptor::owner_only("GA", false)?;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: `attrs` and the descriptor it points to outlive the call.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{hex, write_atomic};

    fn temp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "mousse-net-private-{tag}-{}",
            hex(&crate::rng::random_bytes::<6>())
        ))
    }

    #[test]
    fn a_private_folder_and_the_files_written_in_it_are_owner_only() {
        let base = temp("dir");
        // A folder made the usual way is open to others (on Windows the
        // temp folder grants SYSTEM and administrators, on Unix the umask
        // leaves read access): the check can fail.
        fs::create_dir_all(&base).unwrap();
        let plain = base.join("plain.txt");
        fs::write(&plain, b"x").unwrap();
        assert!(!is_owner_only(&plain).unwrap());

        let dir = base.join("state");
        make_private_dir(&dir).unwrap();
        assert!(is_owner_only(&dir).unwrap());
        let file = dir.join("control.json");
        write_atomic(&file, b"{}").unwrap();
        assert!(is_owner_only(&file).unwrap());
        // Written elsewhere, the file is still made owner-only.
        let outside = base.join("grants.json");
        write_atomic(&outside, b"{}").unwrap();
        assert!(is_owner_only(&outside).unwrap());
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn only_a_protected_dacl_for_the_user_alone_counts() {
        use imp::sddl_is_owner_only as ok;
        let me = "S-1-5-21-1-2-3-1001";
        assert!(ok(&format!("D:P(A;;FA;;;{me})"), me));
        assert!(ok(&format!("D:PAI(A;OICI;FA;;;{me})"), me));
        assert!(!ok(&format!("D:(A;;FA;;;{me})"), me));
        assert!(!ok(&format!("D:P(A;;FA;;;{me})(A;;FA;;;SY)"), me));
        assert!(!ok("D:P(A;;FA;;;S-1-5-21-1-2-3-1002)", me));
        assert!(!ok("D:P", me));
        assert!(!ok("", me));
    }
}
