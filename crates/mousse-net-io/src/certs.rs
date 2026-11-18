//! Our own session certificate: issued from the identity signer, renewed
//! before it runs out.

use std::sync::{Arc, Mutex};

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::session::RENEW_LEAD_SECS;
use mousse_net_core::session_cert::{self, SessionCertificate, ValidityWindow, MAX_LIFETIME_SECS};
use mousse_net_core::UnixTime;

use crate::clock::Clock;
use crate::error::NetError;
use crate::rng::os_rng;
use crate::SharedSigner;

/// Holds the current session certificate and issues a new one when it is
/// within [`RENEW_LEAD_SECS`] of `not_after` (or not yet valid).
///
/// Each new connection takes [`CertManager::current`]. A connection keeps the
/// certificate it started with and closes at its effective deadline.
pub struct CertManager {
    signer: SharedSigner,
    clock: Arc<dyn Clock>,
    lifetime_secs: u64,
    current: Mutex<Option<SessionCertificate>>,
}

impl CertManager {
    /// A manager that issues 24 h certificates.
    pub fn new(signer: SharedSigner, clock: Arc<dyn Clock>) -> Self {
        Self::with_lifetime(signer, clock, MAX_LIFETIME_SECS)
    }

    /// A manager with a custom certificate lifetime (at most 24 h).
    pub fn with_lifetime(signer: SharedSigner, clock: Arc<dyn Clock>, lifetime_secs: u64) -> Self {
        Self {
            signer,
            clock,
            lifetime_secs: lifetime_secs.clamp(1, MAX_LIFETIME_SECS),
            current: Mutex::new(None),
        }
    }

    /// The identity this manager speaks for.
    pub fn identity(&self) -> IdentityPublicKey {
        self.signer.public_key()
    }

    /// The certificate to use for a new connection, issuing one if needed.
    pub fn current(&self) -> Result<SessionCertificate, NetError> {
        let now = self.clock.now();
        let mut slot = self
            .current
            .lock()
            .map_err(|_| NetError::Signer("certificate lock poisoned".into()))?;
        if let Some(cert) = slot.as_ref() {
            if !needs_renewal(cert.window(), now) {
                return Ok(cert.clone());
            }
        }
        let window = ValidityWindow::starting_at(now, self.lifetime_secs)
            .map_err(|e| NetError::Signer(e.to_string()))?;
        let cert = session_cert::issue(&*self.signer, &mut os_rng(), window)
            .map_err(|e| NetError::Signer(e.to_string()))?;
        *slot = Some(cert.clone());
        Ok(cert)
    }
}

/// Whether a certificate with `window` should be replaced at `now`.
pub fn needs_renewal(window: ValidityWindow, now: UnixTime) -> bool {
    now < window.not_before() || now.plus(RENEW_LEAD_SECS) >= window.not_after()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use mousse_net_core::identity::SoftwareKey;

    #[test]
    fn renews_only_near_the_end_of_the_window() {
        let window = ValidityWindow::starting_at(UnixTime(1_000), 86_400).unwrap();
        assert!(!needs_renewal(window, UnixTime(1_000)));
        assert!(!needs_renewal(
            window,
            UnixTime(87_400 - RENEW_LEAD_SECS - 1)
        ));
        assert!(needs_renewal(window, UnixTime(87_400 - RENEW_LEAD_SECS)));
        assert!(needs_renewal(window, UnixTime(999)));
    }

    #[test]
    fn manager_reuses_then_reissues_after_time_moves() {
        let clock = Arc::new(ManualClock::new());
        let key = SoftwareKey::generate(&mut os_rng());
        let manager = CertManager::new(Arc::new(key), clock.clone());
        let first = manager.current().unwrap();
        let again = manager.current().unwrap();
        assert_eq!(first.der(), again.der());
        clock.advance(86_400 - RENEW_LEAD_SECS as i64);
        let renewed = manager.current().unwrap();
        assert_ne!(first.der(), renewed.der());
        assert_eq!(renewed.identity(), first.identity());
    }
}
