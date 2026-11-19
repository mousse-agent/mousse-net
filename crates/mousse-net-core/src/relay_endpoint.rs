//! What an endpoint adds to the relay protocol ([`crate::relay`]) on its
//! own side (design `phase34-design.md` §B.11 and §B.12): relay endpoints
//! and the `relay` route hint, the destination an owner approves, the
//! `mousse-keys` records, and how an endpoint derives its relay keys.
//!
//! Everything here is pure.

use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::base64url;
use crate::cbor::{self, FieldError, Fields, Value};
use crate::identity::{PublicKey, SoftwareKey};
use crate::pairing::{Route, RouteHost};
use crate::relay::proof::RelayId;

/// The scheme of a relay route hint and of an approved destination.
pub const RELAY_SCHEME: &str = "relay";

/// Longest relay route hint, in bytes (a route hint's limit).
pub const RELAY_HINT_MAX: usize = 255;

/// HKDF info of a registration key derived from the relay seed.
pub const REGISTRATION_KEY_INFO: &str = "mousse-relay-registration-key-v1";
/// HKDF info of a caller key derived from the relay seed.
pub const CALLER_KEY_INFO: &str = "mousse-relay-caller-key-v1";
/// HKDF info of a pair secret derived from the relay seed.
pub const PAIR_SECRET_INFO: &str = "mousse-pair-secret-v1";

/// Where a relay listens: `host:port`, with the `tcp` hint rules.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayEndpoint {
    /// IP literal or lower-case DNS name.
    pub host: EndpointHost,
    /// TCP port.
    pub port: u16,
}

/// The host of a [`RelayEndpoint`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EndpointHost {
    /// IPv4.
    Ipv4(core::net::Ipv4Addr),
    /// IPv6, written in brackets.
    Ipv6(core::net::Ipv6Addr),
    /// Lower-case DNS name.
    Dns(String),
}

impl RelayEndpoint {
    /// Parse `host:port` with the `tcp` hint rules (wire.md 10.2.1). Host
    /// names are lower-cased.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > RELAY_HINT_MAX {
            return None;
        }
        match Route::parse(&format!("tcp://{text}")) {
            Ok(Route::Tcp { host, port }) => Some(Self::from_route_host(host, port)),
            _ => None,
        }
    }

    /// From a route host and port (an enrollment link's).
    pub fn from_route_host(host: RouteHost, port: u16) -> Self {
        Self {
            host: match host {
                RouteHost::Ipv4(ip) => EndpointHost::Ipv4(ip),
                RouteHost::Ipv6(ip) => EndpointHost::Ipv6(ip),
                RouteHost::Dns(name) => EndpointHost::Dns(name),
            },
            port,
        }
    }

    /// The host as dialled (no brackets).
    pub fn host_text(&self) -> String {
        match &self.host {
            EndpointHost::Ipv4(ip) => ip.to_string(),
            EndpointHost::Ipv6(ip) => ip.to_string(),
            EndpointHost::Dns(name) => name.clone(),
        }
    }

    /// The approved destination: `relay://<lower-case host>:<port>`.
    pub fn destination(&self) -> String {
        format!("{RELAY_SCHEME}://{self}")
    }

    /// Parse a destination written by [`RelayEndpoint::destination`].
    pub fn from_destination(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("relay://")?;
        let ep = Self::parse(rest)?;
        (ep.destination() == text).then_some(ep)
    }
}

impl fmt::Display for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            EndpointHost::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            EndpointHost::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
            EndpointHost::Dns(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

/// A relay route: a relay to dial, pinned to its id, and the target's
/// handle on it. The `relay` hint form (§B.11) is
/// `relay://<host>:<port>/<relay id>/<handle>`, base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayRoute {
    /// Where the relay listens.
    pub endpoint: RelayEndpoint,
    /// The relay id to pin.
    pub relay: RelayId,
    /// The target's handle there.
    pub handle: [u8; 32],
}

impl RelayRoute {
    /// The hint text.
    pub fn to_hint(&self) -> String {
        format!(
            "{RELAY_SCHEME}://{}/{}/{}",
            self.endpoint,
            base64url::encode(&self.relay.0),
            base64url::encode(&self.handle)
        )
    }

    /// Parse the hint text.
    pub fn parse_hint(text: &str) -> Option<Self> {
        if text.len() > RELAY_HINT_MAX {
            return None;
        }
        let rest = text.strip_prefix("relay://")?;
        let mut parts = rest.split('/');
        let endpoint = RelayEndpoint::parse(parts.next()?)?;
        let relay = <[u8; 32]>::try_from(base64url::decode(parts.next()?).ok()?.as_slice()).ok()?;
        let handle =
            <[u8; 32]>::try_from(base64url::decode(parts.next()?).ok()?.as_slice()).ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            endpoint,
            relay: RelayId(relay),
            handle,
        })
    }
}

/// `mousse-keys`, caller → host: `{1: caller relay public key}`.
pub fn encode_keys_request(caller_key: &PublicKey) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(
        1,
        Value::Bytes(caller_key.as_bytes().to_vec()),
    )]))
}

/// Read a `mousse-keys` request.
pub fn decode_keys_request(input: &[u8]) -> Result<PublicKey, FieldError> {
    let mut f = Fields::decode(input)?;
    let key = PublicKey::from_sec1(&f.bytes(1)?).map_err(|_| FieldError::Invalid(1))?;
    f.finish()?;
    Ok(key)
}

/// `mousse-keys`, host → caller: `{1: pair secret}`.
pub fn encode_keys_answer(pair_secret: &[u8; 32]) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(1, Value::Bytes(pair_secret.to_vec()))]))
}

/// Read a `mousse-keys` answer.
pub fn decode_keys_answer(input: &[u8]) -> Result<[u8; 32], FieldError> {
    let mut f = Fields::decode(input)?;
    let secret = f.fixed::<32>(1)?;
    f.finish()?;
    Ok(secret)
}

/// 32 bytes from `seed` for `info` and `salt` (HKDF-SHA256). Local only:
/// nothing on the wire depends on how an endpoint makes its keys.
pub fn derive_secret(seed: &[u8; 32], info: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// A P-256 key from `seed` for `info` and `salt`. The rare output that is
/// not a valid scalar moves to the next counter byte.
pub fn derive_key(
    seed: &[u8; 32],
    info: &str,
    salt: &[u8],
) -> Result<SoftwareKey, crate::identity::KeyError> {
    let mut last = None;
    for counter in 0u8..=255 {
        let mut salted = salt.to_vec();
        salted.push(counter);
        let secret = derive_secret(seed, info, &salted);
        match SoftwareKey::from_secret_bytes(&secret) {
            Ok(key) => return Ok(key),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(crate::identity::KeyError::NotOnCurve))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_hints_round_trip_and_destinations_are_canonical() {
        let r = RelayRoute {
            endpoint: RelayEndpoint::parse("Relay.Example:443").unwrap(),
            relay: RelayId([3; 32]),
            handle: [4; 32],
        };
        assert_eq!(RelayRoute::parse_hint(&r.to_hint()), Some(r.clone()));
        assert_eq!(r.endpoint.destination(), "relay://relay.example:443");
        assert_eq!(
            RelayEndpoint::from_destination("relay://relay.example:443"),
            Some(r.endpoint.clone())
        );
        assert_eq!(
            RelayEndpoint::from_destination("relay://Relay.example:443"),
            None
        );
        let v6 = RelayEndpoint::parse("[2001:db8::1]:7000").unwrap();
        assert_eq!(v6.destination(), "relay://[2001:db8::1]:7000");
        assert_eq!(v6.host_text(), "2001:db8::1");
        assert!(RelayRoute::parse_hint("relay://relay.example:443/AA/BB").is_none());
    }

    #[test]
    fn keys_records_round_trip_and_refuse_extras() {
        let key = SoftwareKey::from_secret_bytes(&[7; 32])
            .unwrap()
            .public_key();
        assert_eq!(decode_keys_request(&encode_keys_request(&key)), Ok(key));
        assert_eq!(
            decode_keys_answer(&encode_keys_answer(&[9; 32])),
            Ok([9; 32])
        );
        let extra = cbor::encode(&Value::Map(vec![
            (1, Value::Bytes(vec![9; 32])),
            (2, Value::Uint(1)),
        ]));
        assert!(decode_keys_answer(&extra).is_err());
        assert!(decode_keys_answer(&encode_keys_answer(&[9; 32])[..10]).is_err());
    }

    #[test]
    fn derived_keys_depend_on_seed_info_and_salt() {
        let a = derive_key(&[1; 32], CALLER_KEY_INFO, b"x")
            .unwrap()
            .public_key();
        assert_eq!(
            a,
            derive_key(&[1; 32], CALLER_KEY_INFO, b"x")
                .unwrap()
                .public_key()
        );
        assert_ne!(
            a,
            derive_key(&[1; 32], CALLER_KEY_INFO, b"y")
                .unwrap()
                .public_key()
        );
        assert_ne!(
            a,
            derive_key(&[2; 32], CALLER_KEY_INFO, b"x")
                .unwrap()
                .public_key()
        );
        assert_ne!(
            a,
            derive_key(&[1; 32], REGISTRATION_KEY_INFO, b"x")
                .unwrap()
                .public_key()
        );
    }
}
