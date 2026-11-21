//! The pinned issuer keys file (`docs/phase34-design.md` §A.12, §B.10).
//!
//! One issuer public key per line, as 130 hex digits (the 65-byte SEC1
//! point). Blank lines and lines starting with `#` are ignored. Two keys
//! overlap during a rotation. `mousse-relay reload` reads the file again
//! without ending the boot; a file that does not parse leaves the keys in
//! force unchanged.

use std::fs;
use std::io;
use std::path::Path;

use mousse_net_core::identity::PublicKey;
use mousse_net_core::relay_hosted::IssuerKeys;
use mousse_net_io::store::unhex;

/// Parse the file's text. Every key must be a valid P-256 point, and at
/// least one must be given.
pub fn parse(text: &str) -> Result<IssuerKeys, String> {
    let mut keys = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = unhex(line).map_err(|_| format!("line {}: not hex", i + 1))?;
        let key = PublicKey::from_sec1(&bytes).map_err(|e| format!("line {}: {e}", i + 1))?;
        keys.push(key);
    }
    if keys.is_empty() {
        return Err("no issuer key".into());
    }
    Ok(IssuerKeys::new(keys))
}

/// Read and parse the file at `path`.
pub fn load(path: &Path) -> io::Result<IssuerKeys> {
    let text = fs::read_to_string(path)?;
    parse(&text).map_err(|why| io::Error::other(format!("{}: {why}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_io::store::hex;

    #[test]
    fn keys_comments_and_errors() {
        let a = SoftwareKey::generate(&mut mousse_net_io::rng::os_rng()).public_key();
        let b = SoftwareKey::generate(&mut mousse_net_io::rng::os_rng()).public_key();
        let text = format!(
            "# issuer keys\n{}\n\n  {}  \n",
            hex(a.as_bytes()),
            hex(b.as_bytes())
        );
        let keys = parse(&text).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(parse("# nothing\n").is_err());
        assert!(parse("zz\n").is_err());
        // A compressed point is refused.
        let mut compressed = a.as_bytes()[..33].to_vec();
        compressed[0] = 0x02;
        assert!(parse(&hex(&compressed)).is_err());
    }
}
