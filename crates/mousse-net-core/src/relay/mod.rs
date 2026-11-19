//! The relay protocol (spec `relay.md`): messages, proofs, the relay
//! certificate and pin check, the enrollment link, the relay's limits and
//! its admission state machine for self-hosted mode.
//!
//! The relay forwards peer messages it cannot read; admission is all it
//! judges. Hosted-mode leases and tokens are carried by [`msg`] only.

pub mod cert;
pub mod limits;
pub mod link;
pub mod machine;
pub mod msg;
pub mod proof;

#[cfg(test)]
mod hosted_tests;

pub use cert::{check_pin, relay_certificate, RelayCertError};
pub use limits::RelayLimits;
pub use link::{EnrollmentLink, LinkError};
pub use machine::{
    close, AuthorizedKey, ConnId, EnrollCode, IpKey, Now, Output, Relay, RelayConfig, RelayCounts,
};
pub use msg::{Class, Mode, RefuseReason, RelayMessage};
pub use proof::{Binding, RelayClientKey, RelayId};
