//! The hosted relay's files in its state directory (`docs/phase34-design.md`
//! §B.1): the boot generation and the report key. The identity key, the
//! lock and the configuration are the relay's own.

use std::fs;
use std::io;
use std::path::Path;

use mousse_net_core::identity::{PublicKey, SoftwareKey};
use mousse_net_io::rng::os_rng;
use mousse_net_io::store::{hex, unhex, write_atomic_checked};

/// File name of the boot generation.
pub const BOOT_GENERATION_FILE: &str = "boot-generation";
/// File name of the report key.
pub const REPORT_KEY_FILE: &str = "report-key";

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The boot generation stored in `dir`, or 0 if none is.
pub fn boot_generation(dir: &Path) -> io::Result<u64> {
    let path = dir.join(BOOT_GENERATION_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let t = text.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(other(format!(
            "{} does not hold a boot generation",
            path.display()
        )));
    }
    t.parse()
        .map_err(|_| other(format!("{} is out of range", path.display())))
}

/// Add one to the boot generation in `dir` and store it durably (write,
/// fsync, rename, folder sync) before returning it (§A.9 duty 1). The
/// caller holds the state directory's exclusive lock and serves only after
/// this returns. Any failure stops startup: a boot must never reuse a
/// generation.
pub fn next_boot_generation(dir: &Path) -> io::Result<u64> {
    let next = boot_generation(dir)?
        .checked_add(1)
        .ok_or_else(|| other("boot generation overflow"))?;
    write_atomic_checked(
        &dir.join(BOOT_GENERATION_FILE),
        format!("{next}\n").as_bytes(),
    )
    .map_err(|f| other(f.error))?;
    Ok(next)
}

/// The report key in `dir`, made (owner-only) on first use. It signs boot
/// and report bodies; it is not the relay's identity key (§A.3).
pub fn report_key(dir: &Path) -> io::Result<SoftwareKey> {
    let path = dir.join(REPORT_KEY_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let bytes = zeroize::Zeroizing::new(unhex(text.trim()).map_err(other)?);
            let secret: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| other(format!("{} is not a P-256 key", path.display())))?;
            let secret = zeroize::Zeroizing::new(secret);
            SoftwareKey::from_secret_bytes(&secret).map_err(other)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SoftwareKey::generate(&mut os_rng());
            let text = zeroize::Zeroizing::new(format!("{}\n", hex(key.secret_bytes().as_ref())));
            write_atomic_checked(&path, text.as_bytes()).map_err(|f| other(f.error))?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// The report public key as hex, for adding the relay to Plus's fleet.
pub fn report_public_hex(key: &PublicKey) -> String {
    hex(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        // Beside the test binary, in the build folder.
        let exe = std::env::current_exe().unwrap();
        let base = exe.parent().unwrap().join("relay-plus-tmp");
        let dir = base.join(format!(
            "relay-plus-{name}-{}",
            hex(&mousse_net_io::rng::random_bytes::<6>())
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_generation_grows_by_one_per_boot_and_survives_a_restart() {
        let dir = temp("gen");
        assert_eq!(boot_generation(&dir).unwrap(), 0);
        assert_eq!(next_boot_generation(&dir).unwrap(), 1);
        assert_eq!(next_boot_generation(&dir).unwrap(), 2);
        assert_eq!(boot_generation(&dir).unwrap(), 2);
        assert_eq!(
            fs::read_to_string(dir.join(BOOT_GENERATION_FILE)).unwrap(),
            "2\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_generation_stops_startup_rather_than_starting_over() {
        let dir = temp("gen-bad");
        fs::write(dir.join(BOOT_GENERATION_FILE), "x7\n").unwrap();
        assert!(next_boot_generation(&dir).is_err());
        fs::write(dir.join(BOOT_GENERATION_FILE), "").unwrap();
        assert!(next_boot_generation(&dir).is_err());
        assert_eq!(
            fs::read_to_string(dir.join(BOOT_GENERATION_FILE)).unwrap(),
            ""
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_report_key_is_made_once_and_kept() {
        let dir = temp("key");
        let a = report_key(&dir).unwrap();
        let b = report_key(&dir).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert!(mousse_net_io::private::is_owner_only(&dir.join(REPORT_KEY_FILE)).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }
}
