//! The hosted relay's side of Plus (`docs/phase34-design.md` §A.9, §B.10,
//! §B.14).
//!
//! - [`settings`]: `MOUSSE_NET_RELAY_PLUS_URL` and the hosted limits.
//! - [`state`]: the boot generation and the report key in the state
//!   directory.
//! - [`issuers`]: the pinned issuer keys file, read again on reload.
//! - [`http`]: one CBOR `POST` to Plus.
//! - [`link`]: the shared boot state, the boot announcement and the
//!   snapshot reports.
//!
//! The relay's own logic (admission, leases, counters, reports) is
//! [`mousse_net_core::relay_hosted`], which does no I/O.
#![deny(unsafe_code)]

pub mod http;
pub mod issuers;
pub mod link;
pub mod settings;
pub mod state;
