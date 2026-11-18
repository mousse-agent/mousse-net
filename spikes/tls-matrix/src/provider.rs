//! The rustls crypto providers this spike compares, and an injected clock.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    AwsLcRs,
    Ring,
    RustCrypto,
    /// ring plus the experimental pure-Rust X25519MLKEM768 group.
    RingPq,
    /// rustcrypto plus the experimental pure-Rust X25519MLKEM768 group.
    RustCryptoPq,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::AwsLcRs => "aws-lc-rs",
            Provider::Ring => "ring",
            Provider::RustCrypto => "rustcrypto",
            Provider::RingPq => "ring+pq",
            Provider::RustCryptoPq => "rustcrypto+pq",
        }
    }

    /// Providers compiled into this build, in a fixed order.
    pub fn compiled() -> Vec<Provider> {
        let mut out = Vec::new();
        if cfg!(feature = "aws-lc") {
            out.push(Provider::AwsLcRs);
        }
        if cfg!(feature = "ring") {
            out.push(Provider::Ring);
        }
        if cfg!(feature = "rustcrypto") {
            out.push(Provider::RustCrypto);
        }
        if cfg!(all(feature = "ring", feature = "pq-pure")) {
            out.push(Provider::RingPq);
        }
        if cfg!(all(feature = "rustcrypto", feature = "pq-pure")) {
            out.push(Provider::RustCryptoPq);
        }
        out
    }

    pub fn from_name(name: &str) -> Option<Provider> {
        Provider::compiled().into_iter().find(|p| p.name() == name)
    }

    /// The provider's default configuration. Returns `None` if it was not compiled in.
    pub fn crypto_provider(self) -> Option<Arc<CryptoProvider>> {
        match self {
            #[cfg(feature = "aws-lc")]
            Provider::AwsLcRs => Some(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
            #[cfg(feature = "ring")]
            Provider::Ring => Some(Arc::new(rustls::crypto::ring::default_provider())),
            #[cfg(feature = "rustcrypto")]
            Provider::RustCrypto => Some(Arc::new(rustls_rustcrypto::provider())),
            #[cfg(all(feature = "ring", feature = "pq-pure"))]
            Provider::RingPq => Some(Arc::new(crate::pq::with_hybrid(
                rustls::crypto::ring::default_provider(),
            ))),
            #[cfg(all(feature = "rustcrypto", feature = "pq-pure"))]
            Provider::RustCryptoPq => Some(Arc::new(crate::pq::with_hybrid(
                rustls_rustcrypto::provider(),
            ))),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Whether the provider offers the X25519MLKEM768 hybrid group.
    pub fn has_pq(self) -> bool {
        matches!(
            self,
            Provider::AwsLcRs | Provider::RingPq | Provider::RustCryptoPq
        )
    }

    /// Key-exchange groups the provider offers, in preference order.
    pub fn kx_groups(self) -> Vec<String> {
        self.crypto_provider()
            .map(|p| {
                p.kx_groups
                    .iter()
                    .map(|g| format!("{:?}", g.name()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A clock that always reports the time it was given. The caller injects
/// "now" (on wasm32 `SystemTime::now()` is not available).
#[derive(Debug)]
pub struct FixedClock(pub UnixTime);

impl FixedClock {
    pub fn at_unix_secs(secs: u64) -> Arc<Self> {
        Arc::new(FixedClock(UnixTime::since_unix_epoch(Duration::from_secs(
            secs,
        ))))
    }
}

impl TimeProvider for FixedClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}
