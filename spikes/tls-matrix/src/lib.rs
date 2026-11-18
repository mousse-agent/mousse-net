//! Phase 0 spike 1, the crypto matrix.
//!
//! Runs real mutual TLS 1.3 handshakes between two rustls endpoints that each
//! hold a fresh self-signed P-256 certificate. Each side accepts only the
//! peer key it has pinned and ignores chains. The same cases run for every
//! crypto provider compiled in, over an in-memory pipe and (on native) over
//! TCP loopback, and the run is summed up as one JSON result per provider pair.

#![forbid(unsafe_code)]

pub mod certs;
pub mod handshake;
pub mod matrix;
#[cfg(feature = "pq-pure")]
pub mod pq;
pub mod provider;
#[cfg(not(target_arch = "wasm32"))]
pub mod tcp;
pub mod verify;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub mod wasm;

/// Exporter label used to prove both sides derive the same keying material.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-mousse-net-matrix-v1";
/// Exporter context; fixed so results are comparable between runs.
pub const EXPORTER_CONTEXT: &[u8] = b"phase0.crypto-matrix";
/// Target triple this crate was built for.
pub const TARGET: &str = env!("MATRIX_TARGET");
