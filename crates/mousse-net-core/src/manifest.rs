//! Manifests: where a host can be reached through relays (design
//! `phase34-design.md` §B.11), signed by the host's identity key.
//!
//! A manifest record is canonical CBOR:
//!
//! | Key | Value |
//! |---|---|
//! | 1 | `"mousse-manifest-v1"` |
//! | 2 | host identity key (65) |
//! | 3 | sequence (grows) |
//! | 4 | issued at |
//! | 5 | expires at |
//! | 6 | routes: at most 4 of `{1: relay key (65), 2: endpoints (1–4 host:port texts), 3: handle (32), 4: region (0–32 bytes)}` |
//!
//! The identity key signs it only through [`IdentityRecord::manifest`], so
//! an [`IdentitySigner`](crate::identity::IdentitySigner) still never signs
//! anything else. It travels as an [`Envelope`]. A caller keeps the highest
//! sequence it has seen from the pinned host and refuses any manifest not
//! signed by that pin.

use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::{IdentityPublicKey, IdentityRecord, PublicKey, RawSignature};
use crate::relay_wire::{relay_id, Envelope, Handle, RelayEndpoint, RelayId, RelayRoute};

/// The domain at key 1.
pub const MANIFEST_DOMAIN: &str = "mousse-manifest-v1";
/// Most routes in one manifest.
pub const MANIFEST_ROUTES_MAX: usize = 4;
/// Most endpoints of one route.
pub const MANIFEST_ENDPOINTS_MAX: usize = 4;
/// Longest region text, in bytes.
pub const MANIFEST_REGION_MAX: usize = 32;

/// One relay a host is registered on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRoute {
    /// The relay's identity key; its id is pinned on every dial.
    pub relay_key: PublicKey,
    /// Where it listens, 1 to 4.
    pub endpoints: Vec<RelayEndpoint>,
    /// The host's handle there.
    pub handle: Handle,
    /// A region label, 0 to 32 bytes.
    pub region: String,
}

impl ManifestRoute {
    /// The relay id.
    pub fn relay(&self) -> RelayId {
        relay_id(&self.relay_key)
    }

    /// One dialable route per endpoint.
    pub fn routes(&self) -> Vec<RelayRoute> {
        self.endpoints
            .iter()
            .map(|endpoint| RelayRoute {
                endpoint: endpoint.clone(),
                relay: self.relay(),
                handle: self.handle,
            })
            .collect()
    }
}

/// A manifest's contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The host this manifest is for (and the key that signs it).
    pub host: IdentityPublicKey,
    /// Grows with every new manifest of this host.
    pub sequence: u64,
    /// Seconds since the Unix epoch.
    pub issued_at: u64,
    /// After this it is stale: still tried, after every other route.
    pub expires_at: u64,
    /// At most [`MANIFEST_ROUTES_MAX`].
    pub routes: Vec<ManifestRoute>,
}

/// Why a manifest was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// Malformed record or envelope.
    Field(FieldError),
    /// Not signed by the pinned host, or for another host.
    WrongSigner,
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ManifestError::Field(e) => write!(f, "malformed manifest: {e}"),
            ManifestError::WrongSigner => {
                f.write_str("the manifest is not signed by the pinned host")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<FieldError> for ManifestError {
    fn from(e: FieldError) -> Self {
        ManifestError::Field(e)
    }
}

impl Manifest {
    /// The canonical CBOR record. Fails if a limit is broken.
    pub fn encode(&self) -> Result<Vec<u8>, FieldError> {
        if self.routes.len() > MANIFEST_ROUTES_MAX {
            return Err(FieldError::Invalid(6));
        }
        if self.expires_at < self.issued_at {
            return Err(FieldError::Invalid(5));
        }
        let mut routes = Vec::with_capacity(self.routes.len());
        for r in &self.routes {
            if r.endpoints.is_empty()
                || r.endpoints.len() > MANIFEST_ENDPOINTS_MAX
                || r.region.len() > MANIFEST_REGION_MAX
            {
                return Err(FieldError::Invalid(6));
            }
            routes.push(Value::Map(vec![
                (1, Value::Bytes(r.relay_key.as_bytes().to_vec())),
                (
                    2,
                    Value::Array(
                        r.endpoints
                            .iter()
                            .map(|e| Value::Text(e.to_string()))
                            .collect(),
                    ),
                ),
                (3, Value::Bytes(r.handle.to_vec())),
                (4, Value::Text(r.region.clone())),
            ]));
        }
        Ok(cbor::encode(&Value::Map(vec![
            (1, Value::Text(MANIFEST_DOMAIN.into())),
            (2, Value::Bytes(self.host.as_bytes().to_vec())),
            (3, Value::Uint(self.sequence)),
            (4, Value::Uint(self.issued_at)),
            (5, Value::Uint(self.expires_at)),
            (6, Value::Array(routes)),
        ])))
    }

    /// Read a record. Strict: canonical CBOR, every limit, no extra keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, FieldError> {
        let mut f = Fields::decode(bytes)?;
        if f.text(1)? != MANIFEST_DOMAIN {
            return Err(FieldError::Invalid(1));
        }
        let host = PublicKey::from_sec1(&f.bytes(2)?).map_err(|_| FieldError::Invalid(2))?;
        let sequence = f.uint(3)?;
        let issued_at = f.uint(4)?;
        let expires_at = f.uint(5)?;
        if expires_at < issued_at {
            return Err(FieldError::Invalid(5));
        }
        let list = f.array(6)?;
        if list.len() > MANIFEST_ROUTES_MAX {
            return Err(FieldError::Invalid(6));
        }
        let mut routes = Vec::with_capacity(list.len());
        for item in list {
            let mut r = Fields::from_value(item).map_err(|_| FieldError::Invalid(6))?;
            let relay_key = PublicKey::from_sec1(&r.bytes(1).map_err(|_| FieldError::Invalid(6))?)
                .map_err(|_| FieldError::Invalid(6))?;
            let texts = r.array(2).map_err(|_| FieldError::Invalid(6))?;
            if texts.is_empty() || texts.len() > MANIFEST_ENDPOINTS_MAX {
                return Err(FieldError::Invalid(6));
            }
            let mut endpoints = Vec::with_capacity(texts.len());
            for t in texts {
                let Value::Text(t) = t else {
                    return Err(FieldError::Invalid(6));
                };
                // Written as read back: lower case, canonical.
                let e = RelayEndpoint::parse(&t).ok_or(FieldError::Invalid(6))?;
                if e.to_string() != t {
                    return Err(FieldError::Invalid(6));
                }
                endpoints.push(e);
            }
            let handle = r.fixed::<32>(3).map_err(|_| FieldError::Invalid(6))?;
            let region = r.text(4).map_err(|_| FieldError::Invalid(6))?;
            if region.len() > MANIFEST_REGION_MAX {
                return Err(FieldError::Invalid(6));
            }
            r.finish().map_err(|_| FieldError::Invalid(6))?;
            routes.push(ManifestRoute {
                relay_key,
                endpoints,
                handle,
                region,
            });
        }
        f.finish()?;
        Ok(Self {
            host,
            sequence,
            issued_at,
            expires_at,
            routes,
        })
    }

    /// Whether it is past its expiry at `now` (stale manifests are still
    /// dialled, last).
    pub fn is_stale(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Check an envelope against the pinned host: signed by `pin`, for
    /// `pin`. Returns the manifest.
    pub fn open(envelope: &Envelope, pin: &IdentityPublicKey) -> Result<Self, ManifestError> {
        if !envelope.verify(pin) {
            return Err(ManifestError::WrongSigner);
        }
        let manifest = Self::decode(&envelope.record)?;
        if manifest.host != *pin {
            return Err(ManifestError::WrongSigner);
        }
        Ok(manifest)
    }

    /// Wrap a record and its signature by the host's identity key.
    pub fn seal(record: &IdentityRecord, signature: RawSignature) -> Envelope {
        Envelope {
            record: record.as_bytes().to_vec(),
            signature,
        }
    }
}

impl IdentityRecord {
    /// The record the identity key signs for `manifest`. The only way to
    /// have an identity key sign a manifest.
    pub fn manifest(manifest: &Manifest) -> Result<Self, FieldError> {
        Ok(IdentityRecord::new(MANIFEST_DOMAIN, manifest.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentitySigner, SoftwareKey};

    fn rng() -> rand_chacha::ChaCha20Rng {
        use rand_chacha::rand_core::SeedableRng;
        rand_chacha::ChaCha20Rng::from_seed([7; 32])
    }

    fn sample(host: &SoftwareKey, relay: &SoftwareKey) -> Manifest {
        Manifest {
            host: host.public_key(),
            sequence: 3,
            issued_at: 1_000,
            expires_at: 2_000,
            routes: vec![ManifestRoute {
                relay_key: relay.public_key(),
                endpoints: vec![RelayEndpoint::parse("relay.example:443").unwrap()],
                handle: [9; 32],
                region: "eu".into(),
            }],
        }
    }

    #[test]
    fn a_manifest_round_trips_and_opens_only_under_its_host() {
        let mut r = rng();
        let (host, relay, other) = (
            SoftwareKey::generate(&mut r),
            SoftwareKey::generate(&mut r),
            SoftwareKey::generate(&mut r),
        );
        let m = sample(&host, &relay);
        let record = IdentityRecord::manifest(&m).unwrap();
        assert_eq!(record.domain(), MANIFEST_DOMAIN);
        let env = Manifest::seal(&record, host.sign(&record).unwrap());
        let decoded = Envelope::decode(&env.encode()).unwrap();
        assert_eq!(Manifest::open(&decoded, &host.public_key()).unwrap(), m);
        assert_eq!(
            Manifest::open(&decoded, &other.public_key()),
            Err(ManifestError::WrongSigner)
        );
        // Signed by another key for this host's identity.
        let forged = Manifest::seal(&record, other.sign(&record).unwrap());
        assert_eq!(
            Manifest::open(&forged, &host.public_key()),
            Err(ManifestError::WrongSigner)
        );
        // Signed by the other key, naming it as host: the pin refuses it.
        let mut theirs = m.clone();
        theirs.host = other.public_key();
        let record = IdentityRecord::manifest(&theirs).unwrap();
        let env = Manifest::seal(&record, other.sign(&record).unwrap());
        assert_eq!(
            Manifest::open(&env, &host.public_key()),
            Err(ManifestError::WrongSigner)
        );
    }

    #[test]
    fn limits_and_canonical_endpoints_are_enforced() {
        let mut r = rng();
        let (host, relay) = (SoftwareKey::generate(&mut r), SoftwareKey::generate(&mut r));
        let mut m = sample(&host, &relay);
        m.routes = vec![m.routes[0].clone(); 5];
        assert!(m.encode().is_err());
        let mut m = sample(&host, &relay);
        m.routes[0].region = "x".repeat(33);
        assert!(m.encode().is_err());
        let mut m = sample(&host, &relay);
        m.routes[0].endpoints.clear();
        assert!(m.encode().is_err());
        // An upper-case endpoint is not the canonical form.
        let m = sample(&host, &relay);
        let bytes = m.encode().unwrap();
        let swapped: Vec<u8> = {
            let text = b"relay.example:443";
            let at = bytes.windows(text.len()).position(|w| w == text).unwrap();
            let mut b = bytes.clone();
            b[at] = b'R';
            b
        };
        assert!(Manifest::decode(&swapped).is_err());
        assert!(Manifest::decode(&bytes).is_ok());
    }

    #[test]
    fn staleness_is_after_expiry() {
        let mut r = rng();
        let m = sample(
            &SoftwareKey::generate(&mut r),
            &SoftwareKey::generate(&mut r),
        );
        assert!(!m.is_stale(2_000));
        assert!(m.is_stale(2_001));
    }
}
