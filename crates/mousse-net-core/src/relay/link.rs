//! The enrollment link of a self-hosted relay (spec `relay.md` section 11):
//! `mousse-relay://<host>:<port>/#<relay id>.<code>`.

use core::fmt;

use crate::base64url;
use crate::pairing::{Route, RouteHost};

use super::proof::RelayId;

/// The scheme and separator before the authority.
pub const LINK_PREFIX: &str = "mousse-relay://";

/// A parsed enrollment link.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentLink {
    /// Where the relay listens.
    pub host: RouteHost,
    /// TCP port.
    pub port: u16,
    /// The relay id to pin.
    pub relay: RelayId,
    /// The single-use enrollment code.
    pub code: [u8; 16],
}

impl fmt::Debug for EnrollmentLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The code is a credential: never print it.
        write!(f, "EnrollmentLink({}, {:?})", self.authority(), self.relay)
    }
}

/// Why an enrollment link was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Not `mousse-relay://<host>:<port>/#<id>.<code>`.
    Form,
    /// The host or port breaks the `tcp` hint grammar (wire.md 10.2.1).
    Address,
    /// The relay id or code is not strict base64url of the right length.
    Encoding,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Form => "not a mousse-relay:// enrollment link",
            Self::Address => "the relay address is not valid",
            Self::Encoding => "the relay id or code is not valid",
        })
    }
}

impl std::error::Error for LinkError {}

impl EnrollmentLink {
    /// `host:port`, IPv6 in brackets, DNS names lowercased.
    pub fn authority(&self) -> String {
        match &self.host {
            RouteHost::Ipv4(ip) => format!("{ip}:{}", self.port),
            RouteHost::Ipv6(ip) => format!("[{ip}]:{}", self.port),
            RouteHost::Dns(name) => format!("{name}:{}", self.port),
        }
    }

    /// The link text.
    pub fn to_text(&self) -> String {
        format!(
            "{LINK_PREFIX}{}/#{}.{}",
            self.authority(),
            base64url::encode(&self.relay.0),
            base64url::encode(&self.code)
        )
    }

    /// Parse a link.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        let rest = text.strip_prefix(LINK_PREFIX).ok_or(LinkError::Form)?;
        let (authority, fragment) = rest.split_once("/#").ok_or(LinkError::Form)?;
        let (host, port) = match Route::parse(&format!("tcp://{authority}")) {
            Ok(Route::Tcp { host, port }) => (host, port),
            _ => return Err(LinkError::Address),
        };
        let (id, code) = fragment.split_once('.').ok_or(LinkError::Form)?;
        let id = base64url::decode(id).map_err(|_| LinkError::Encoding)?;
        let code = base64url::decode(code).map_err(|_| LinkError::Encoding)?;
        Ok(Self {
            host,
            port,
            relay: RelayId(id.try_into().map_err(|_| LinkError::Encoding)?),
            code: code.try_into().map_err(|_| LinkError::Encoding)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn round_trip_and_rejections() {
        let link = EnrollmentLink {
            host: RouteHost::Ipv4("203.0.113.5".parse().unwrap()),
            port: 443,
            relay: RelayId([7; 32]),
            code: [9; 16],
        };
        let text = link.to_text();
        assert_eq!(EnrollmentLink::parse(&text), Ok(link.clone()));
        let v6 = "mousse-relay://[2001:DB8::1]:8443/#BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc.CQkJCQkJCQkJCQkJCQkJCQ";
        let parsed = EnrollmentLink::parse(v6).unwrap();
        assert_eq!(parsed.authority(), "[2001:db8::1]:8443");
        for bad in [
            text.replace("mousse-relay://", "relay://"),
            text.replace("/#", "#"),
            text.replace(":443", ":0443"),
            format!("{text}="),
            text.replace('.', ""),
            "mousse-relay://203.0.113.5:443/#AA.AA".to_string(),
        ] {
            assert!(EnrollmentLink::parse(&bad).is_err(), "{bad}");
        }
    }
}
