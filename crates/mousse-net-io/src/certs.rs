//! Our own session certificate: issued from the identity signer, renewed
//! before it runs out.

use std::sync::{Arc, Mutex};

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::session_cert::{self, SessionCertificate, ValidityWindow, MAX_LIFETIME_SECS};
use mousse_net_core::UnixTime;

use crate::clock::Clock;
use crate::error::NetError;
use crate::limits::Limits;
use crate::rng::os_rng;
use crate::SharedSigner;

/// Holds the current session certificate and issues a new one when it is
/// within the renewal lead of `not_after` (or not yet valid).
///
/// Each new connection takes [`CertManager::current`]. A connection keeps the
/// certificate it started with and closes at its effective deadline.
pub struct CertManager {
    signer: SharedSigner,
    clock: Arc<dyn Clock>,
    lifetime_secs: u64,
    renew_lead_secs: u64,
    current: Mutex<Option<SessionCertificate>>,
}

impl CertManager {
    /// A manager with the default limits: 24 h certificates, renewed 30
    /// minutes before they run out.
    pub fn new(signer: SharedSigner, clock: Arc<dyn Clock>) -> Self {
        Self::with_limits(signer, clock, &Limits::DEFAULT)
    }

    /// A manager with the certificate lifetime (at most 24 h) and renewal
    /// lead from `limits`.
    pub fn with_limits(signer: SharedSigner, clock: Arc<dyn Clock>, limits: &Limits) -> Self {
        Self {
            signer,
            clock,
            lifetime_secs: limits.io.cert_lifetime_secs.clamp(1, MAX_LIFETIME_SECS),
            renew_lead_secs: limits.core.renew_lead_secs,
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
            if !needs_renewal(cert.window(), now, self.renew_lead_secs) {
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

/// Whether a certificate with `window` should be replaced at `now`, given
/// the renewal lead.
pub fn needs_renewal(window: ValidityWindow, now: UnixTime, renew_lead_secs: u64) -> bool {
    now < window.not_before() || now.plus(renew_lead_secs) >= window.not_after()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use mousse_net_core::identity::SoftwareKey;

    const RENEW_LEAD_SECS: u64 = Limits::DEFAULT.core.renew_lead_secs;

    #[test]
    fn renews_only_near_the_end_of_the_window() {
        let window = ValidityWindow::starting_at(UnixTime(1_000), 86_400).unwrap();
        assert!(!needs_renewal(window, UnixTime(1_000), RENEW_LEAD_SECS));
        assert!(!needs_renewal(
            window,
            UnixTime(87_400 - RENEW_LEAD_SECS - 1),
            RENEW_LEAD_SECS
        ));
        assert!(needs_renewal(
            window,
            UnixTime(87_400 - RENEW_LEAD_SECS),
            RENEW_LEAD_SECS
        ));
        assert!(needs_renewal(window, UnixTime(999), RENEW_LEAD_SECS));
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
