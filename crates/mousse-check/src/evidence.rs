//! Signed device results, the trusted device list and attestations.
//!
//! A device (a phone, the Mac, another PC) writes a result payload and signs
//! it with its own P-256 key. The file keeps the exact payload text that was
//! signed, so verification never depends on re-serializing JSON:
//!
//! ```json
//! { "format": "mousse-check-signed-result-v1",
//!   "device": "mac-mini",
//!   "key": "04…",            // SEC1 uncompressed public key, hex
//!   "payload": "{\"check\":…}",
//!   "signature": "…" }       // raw r||s, 64 bytes, hex
//! ```
//!
//! The signature is ECDSA P-256 / SHA-256 over
//! `"mousse-check-result-v1\0" || payload bytes`. WebCrypto's ECDSA output
//! is already raw `r||s`, so a browser page can sign results directly.

use std::path::{Path, PathBuf};

use mousse_net_core::identity::{PublicKey, RawSignature, SoftwareKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::util::{from_hex, to_hex};

pub const SIGNED_FORMAT: &str = "mousse-check-signed-result-v1";
pub const ATTEST_FORMAT: &str = "mousse-check-attestation-v1";
const SIGNING_DOMAIN: &[u8] = b"mousse-check-result-v1\0";

/// What a device reports for one run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPayload {
    pub check: String,
    pub target: String,
    /// Sub-case, such as a crypto matrix provider pair (`aws-lc-rs>ring`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    /// The must-fail control's name for a control run; absent for a normal
    /// run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    /// `<commit>[-dirty]+<profile>`.
    pub build: String,
    pub platform: String,
    /// PASS or FAIL. Anything else counts as neither.
    pub outcome: String,
    pub details: String,
    /// When the run happened, `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: String,
    /// The signing device's name in `checks/devices.toml`.
    pub device: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// The file a device hands over.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedResult {
    pub format: String,
    pub device: String,
    pub key: String,
    pub payload: String,
    pub signature: String,
}

/// A trusted device.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: String,
    /// SEC1 uncompressed P-256 public key, hex.
    pub key: String,
    #[serde(default)]
    pub platform: String,
    /// Target cells this device may report.
    pub targets: Vec<String>,
    #[serde(default)]
    pub added: String,
}

/// `checks/devices.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceList {
    #[serde(rename = "device", default)]
    pub devices: Vec<Device>,
}

impl DeviceList {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let list: DeviceList = toml::from_str(text).map_err(|e| e.to_string())?;
        for (i, d) in list.devices.iter().enumerate() {
            parse_public_key(&d.key).map_err(|e| format!("device {}: {e}", d.name))?;
            if list.devices[..i].iter().any(|o| o.name == d.name) {
                return Err(format!("device name {} appears twice", d.name));
            }
            if list.devices[..i]
                .iter()
                .any(|o| o.key.eq_ignore_ascii_case(&d.key))
            {
                return Err(format!("device {} reuses another device's key", d.name));
            }
        }
        Ok(list)
    }

    pub fn by_key(&self, key: &PublicKey) -> Option<&Device> {
        self.devices
            .iter()
            .find(|d| parse_public_key(&d.key).ok().as_ref() == Some(key))
    }

    /// A TOML block for one new device, to append to the file.
    pub fn entry_text(device: &Device) -> String {
        let targets = device
            .targets
            .iter()
            .map(|t| format!("{t:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "\n[[device]]\nname = {:?}\nkey = {:?}\nplatform = {:?}\ntargets = [{targets}]\nadded = {:?}\n",
            device.name, device.key, device.platform, device.added
        )
    }
}

pub fn parse_public_key(hex: &str) -> Result<PublicKey, String> {
    let bytes = from_hex(hex)?;
    PublicKey::from_sec1(&bytes).map_err(|e| e.to_string())
}

/// A device key file: the 32-byte secret scalar in hex on one line.
pub fn load_device_key(path: &Path) -> Result<SoftwareKey, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read key {}: {e}", path.display()))?,
    );
    let bytes = Zeroizing::new(from_hex(&text).map_err(|_| "key file is not hex".to_string())?);
    let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "key file must hold a 32-byte secret".to_string())?,
    );
    SoftwareKey::from_secret_bytes(&secret).map_err(|e| e.to_string())
}

/// A fresh device key from the operating system's random source.
pub fn generate_device_key() -> Result<SoftwareKey, String> {
    for _ in 0..8 {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(secret.as_mut()).map_err(|e| format!("no randomness: {e}"))?;
        if let Ok(key) = SoftwareKey::from_secret_bytes(&secret) {
            return Ok(key);
        }
    }
    Err("could not draw a valid key".into())
}

/// Hex of the secret, for the key file.
pub fn device_key_text(key: &SoftwareKey) -> Zeroizing<String> {
    Zeroizing::new(format!("{}\n", to_hex(key.secret_bytes().as_ref())))
}

fn signing_input(payload: &str) -> Vec<u8> {
    [SIGNING_DOMAIN, payload.as_bytes()].concat()
}

/// Sign a payload. The payload's `device` must already be set.
pub fn sign(payload: &ResultPayload, key: &SoftwareKey) -> Result<SignedResult, String> {
    let text = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let signature = key.sign_raw(&signing_input(&text));
    Ok(SignedResult {
        format: SIGNED_FORMAT.into(),
        device: payload.device.clone(),
        key: to_hex(key.public_key().as_bytes()),
        payload: text,
        signature: to_hex(signature.as_bytes()),
    })
}

/// Why a result file does not count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a signed result, or a field cannot be read.
    Malformed(String),
    /// The key is not in the trusted device list.
    UnknownDevice(String),
    /// The key is trusted but the signature does not verify: the file was
    /// changed after signing, or forged.
    BadSignature { device: String },
    /// The payload names a different device than the key belongs to.
    DeviceMismatch { device: String, claimed: String },
    /// The device is not trusted for this target cell.
    TargetNotAllowed { device: String, target: String },
}

impl Rejection {
    /// Signs of tampering: these block the phase verdict.
    pub fn is_tampering(&self) -> bool {
        matches!(
            self,
            Rejection::BadSignature { .. } | Rejection::DeviceMismatch { .. }
        )
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::Malformed(e) => write!(f, "unreadable: {e}"),
            Rejection::UnknownDevice(k) => write!(f, "signed by a key not in devices.toml ({k})"),
            Rejection::BadSignature { device } => {
                write!(
                    f,
                    "signature by {device} does not verify (changed after signing?)"
                )
            }
            Rejection::DeviceMismatch { device, claimed } => {
                write!(
                    f,
                    "key belongs to {device} but the payload claims {claimed}"
                )
            }
            Rejection::TargetNotAllowed { device, target } => {
                write!(f, "{device} is not trusted to report {target}")
            }
        }
    }
}

/// Verify a signed result against the trusted devices.
pub fn verify(signed: &SignedResult, devices: &DeviceList) -> Result<ResultPayload, Rejection> {
    if signed.format != SIGNED_FORMAT {
        return Err(Rejection::Malformed(format!("format {:?}", signed.format)));
    }
    let key = parse_public_key(&signed.key).map_err(Rejection::Malformed)?;
    let device = devices.by_key(&key).ok_or_else(|| {
        Rejection::UnknownDevice(signed.key.chars().take(18).collect::<String>() + "…")
    })?;
    let sig_bytes = from_hex(&signed.signature).map_err(Rejection::Malformed)?;
    let signature = RawSignature::from_slice(&sig_bytes).map_err(|_| Rejection::BadSignature {
        device: device.name.clone(),
    })?;
    key.verify(&signing_input(&signed.payload), &signature)
        .map_err(|_| Rejection::BadSignature {
            device: device.name.clone(),
        })?;
    let payload: ResultPayload =
        serde_json::from_str(&signed.payload).map_err(|e| Rejection::Malformed(e.to_string()))?;
    if payload.device != device.name || signed.device != device.name {
        return Err(Rejection::DeviceMismatch {
            device: device.name.clone(),
            claimed: payload.device,
        });
    }
    if !device.targets.iter().any(|t| t == &payload.target) {
        return Err(Rejection::TargetNotAllowed {
            device: device.name.clone(),
            target: payload.target,
        });
    }
    Ok(payload)
}

/// A manual step someone says they did. Never counts as PASS.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub format: String,
    pub check: String,
    pub target: String,
    pub build: String,
    pub by: String,
    pub time: String,
    pub note: String,
}

/// Everything found in `checks/results/`.
#[derive(Debug, Default)]
pub struct Evidence {
    pub results: Vec<ResultPayload>,
    pub attestations: Vec<Attestation>,
    pub rejected: Vec<(PathBuf, Rejection)>,
}

/// Read every `.json` file under `dir` (recursively).
pub fn collect(dir: &Path, devices: &DeviceList) -> Evidence {
    let mut ev = Evidence::default();
    let mut files = Vec::new();
    walk(dir, &mut files);
    files.sort();
    for path in files {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                ev.rejected
                    .push((path, Rejection::Malformed(e.to_string())));
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                ev.rejected
                    .push((path, Rejection::Malformed(e.to_string())));
                continue;
            }
        };
        match value.get("format").and_then(|f| f.as_str()) {
            Some(ATTEST_FORMAT) => match serde_json::from_value::<Attestation>(value) {
                Ok(a) => ev.attestations.push(a),
                Err(e) => ev
                    .rejected
                    .push((path, Rejection::Malformed(e.to_string()))),
            },
            _ => match serde_json::from_value::<SignedResult>(value) {
                Ok(signed) => match verify(&signed, devices) {
                    Ok(p) => ev.results.push(p),
                    Err(r) => ev.rejected.push((path, r)),
                },
                Err(e) => ev.rejected.push((
                    path,
                    Rejection::Malformed(format!("not a signed result: {e}")),
                )),
            },
        }
    }
    ev
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// A file name piece with only safe characters.
pub fn file_part(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '+' | '@' => c,
            '>' => '~',
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SoftwareKey {
        SoftwareKey::from_secret_bytes(&[n; 32]).unwrap()
    }

    fn devices() -> DeviceList {
        DeviceList {
            devices: vec![Device {
                name: "mac".into(),
                key: to_hex(key(7).public_key().as_bytes()),
                platform: "macOS".into(),
                targets: vec!["aarch64-apple-darwin".into()],
                added: String::new(),
            }],
        }
    }

    fn payload() -> ResultPayload {
        ResultPayload {
            check: "phase0.x".into(),
            target: "aarch64-apple-darwin".into(),
            case: None,
            control: None,
            build: "0123456789abcdef0123456789abcdef01234567+release".into(),
            platform: "macOS".into(),
            outcome: "PASS".into(),
            details: "ok".into(),
            time: "2026-11-18T00:00:00Z".into(),
            device: "mac".into(),
            extra: serde_json::Value::Null,
        }
    }

    #[test]
    fn a_signed_result_verifies() {
        let signed = sign(&payload(), &key(7)).unwrap();
        assert_eq!(verify(&signed, &devices()), Ok(payload()));
    }

    #[test]
    fn a_changed_payload_is_rejected_as_tampering() {
        let mut signed = sign(&payload(), &key(7)).unwrap();
        signed.payload = signed.payload.replace("\"PASS\"", "\"FAIL\"");
        let err = verify(&signed, &devices()).unwrap_err();
        assert_eq!(
            err,
            Rejection::BadSignature {
                device: "mac".into()
            }
        );
        assert!(err.is_tampering());
        // Flip one signature bit.
        let mut signed = sign(&payload(), &key(7)).unwrap();
        let mut sig = from_hex(&signed.signature).unwrap();
        sig[10] ^= 1;
        signed.signature = to_hex(&sig);
        assert!(matches!(
            verify(&signed, &devices()),
            Err(Rejection::BadSignature { .. })
        ));
    }

    #[test]
    fn an_untrusted_key_is_rejected_even_if_the_signature_is_valid() {
        let signed = sign(&payload(), &key(8)).unwrap();
        assert!(matches!(
            verify(&signed, &devices()),
            Err(Rejection::UnknownDevice(_))
        ));
    }

    #[test]
    fn a_trusted_key_cannot_claim_another_device_or_target() {
        let mut p = payload();
        p.device = "iphone".into();
        let signed = sign(&p, &key(7)).unwrap();
        assert!(matches!(
            verify(&signed, &devices()),
            Err(Rejection::DeviceMismatch { .. })
        ));
        let mut p = payload();
        p.target = "aarch64-apple-ios".into();
        let signed = sign(&p, &key(7)).unwrap();
        assert!(matches!(
            verify(&signed, &devices()),
            Err(Rejection::TargetNotAllowed { .. })
        ));
    }

    #[test]
    fn device_list_refuses_duplicates_and_bad_keys() {
        let entry = DeviceList::entry_text(&devices().devices[0]);
        DeviceList::parse(&entry).unwrap();
        assert!(DeviceList::parse(&format!("{entry}{entry}")).is_err());
        assert!(DeviceList::parse(&entry.replace("\"04", "\"05")).is_err());
    }

    #[test]
    fn key_files_round_trip() {
        let dir = std::env::temp_dir().join(format!("mousse-check-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.key");
        let k = generate_device_key().unwrap();
        std::fs::write(&path, device_key_text(&k).as_bytes()).unwrap();
        let back = load_device_key(&path).unwrap();
        assert_eq!(back.public_key(), k.public_key());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
