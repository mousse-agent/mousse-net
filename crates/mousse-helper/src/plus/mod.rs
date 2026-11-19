//! The helper's Plus client (Phase 4, E-L2 and E-L3): the endpoint's only
//! path to Plus. The app reaches it through the app channel (`plus.*`).

pub mod client;
pub mod http;
// Leases and relay moves are driven by the hosted relay client; until it
// lands they run only in tests.
#[allow(dead_code)]
pub mod lease;
pub mod proto;
#[allow(dead_code)]
pub mod relay_move;

pub use client::{Failure, Plus};

#[cfg(test)]
#[path = "../../tests/common/plus_standin.rs"]
#[allow(dead_code)]
pub mod plus_standin;
#[cfg(test)]
pub mod tests;
