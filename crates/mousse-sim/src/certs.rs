//! Fixed identity keys and real session certificates, with caches.
//!
//! Every simulated device has a fixed P-256 identity key derived from its
//! label, so runs never depend on the order keys were made. Session
//! certificates are issued by core's [`session_cert::issue`] with a session
//! key derived from `(label, not_before, lifetime)`, so the same window always
//! gives the same certificate bytes.
//!
//! ## The TLS boundary
//!
//! The simulator does not run TLS. A connection's handshake is modelled as:
//! the client verifies the server's certificate with core's step 1 at the
//! client's wall time and with its pin, then the server verifies the
//! client's certificate at its own wall time with no pin. If both pass, the
//! pipe is an *authenticated pipe* carrying the two verified identities, both
//! windows, and one pair of exporter values (32 random bytes each, drawn from
//! the run's RNG, equal on both ends). `CertificateVerify` (proof that the
//! peer holds the session key now) is assumed, not simulated.
//!
//! ## The verify cache
//!
//! Step 1 checks 1 to 8 are pure functions of the certificate bytes; only
//! check 9 (pin) and check 10 (window at `now`) depend on the call. P-256 is
//! slow in debug builds, so by default the simulator runs core's full
//! [`session_cert::verify`] once per certificate (at issue time, inside its
//! window), keeps the result, and for each handshake applies check 9 by
//! comparing keys and check 10 with core's [`ValidityWindow::accepts`], in
//! that order. `RunConfig::full_verify` turns the cache off; a test checks that
//! both paths agree.

use std::cell::RefCell;
use std::collections::HashMap;

use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::session_cert::{
    self, CertError, SessionCertificate, ValidityWindow, VerifiedSessionCert,
};
use mousse_net_core::UnixTime;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

/// Virtual wall-clock origin of every run (2026-09-21T10:13:20Z).
pub const T0: u64 = 1_790_000_000;

/// Certificates start on this grid (seconds), so the number of distinct
/// certificates across thousands of seeds stays small and the caches hit.
pub const CERT_GRID_SECS: u64 = 300;

thread_local! {
    static KEYS: RefCell<HashMap<String, SoftwareKey>> = RefCell::new(HashMap::new());
    static CERTS: RefCell<HashMap<(String, u64, u64), SessionCertificate>> =
        RefCell::new(HashMap::new());
    static VERIFIED: RefCell<HashMap<Vec<u8>, VerifiedSessionCert>> = RefCell::new(HashMap::new());
}

fn seed_for(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// The fixed identity key for a device label.
pub(crate) fn identity_key(label: &str) -> SoftwareKey {
    KEYS.with(|k| {
        k.borrow_mut()
            .entry(label.to_owned())
            .or_insert_with(|| {
                let seed = seed_for(&[b"mousse-sim identity", label.as_bytes()]);
                SoftwareKey::generate(&mut ChaCha20Rng::from_seed(seed))
            })
            .clone()
    })
}

/// The first grid point at or before `wall`.
pub(crate) fn grid(wall: UnixTime) -> UnixTime {
    UnixTime(wall.secs() - wall.secs() % CERT_GRID_SECS)
}

/// A real session certificate for `label`, valid from `not_before` for
/// `lifetime` seconds.
pub(crate) fn certificate(label: &str, not_before: UnixTime, lifetime: u64) -> SessionCertificate {
    let key = (label.to_owned(), not_before.secs(), lifetime);
    if let Some(c) = CERTS.with(|c| c.borrow().get(&key).cloned()) {
        return c;
    }
    let identity = identity_key(label);
    let window =
        ValidityWindow::starting_at(not_before, lifetime).expect("lifetimes are 1 s to 24 h");
    let seed = seed_for(&[
        b"mousse-sim session key",
        label.as_bytes(),
        &not_before.secs().to_be_bytes(),
        &lifetime.to_be_bytes(),
    ]);
    let cert = session_cert::issue(&identity, &mut ChaCha20Rng::from_seed(seed), window)
        .expect("issuing with a software key cannot fail");
    // Run the full step 1 once, inside the window, with no pin.
    let verified = session_cert::verify(cert.der(), not_before, None)
        .expect("a freshly issued certificate verifies inside its window");
    VERIFIED.with(|v| v.borrow_mut().insert(cert.der().to_vec(), verified));
    CERTS.with(|c| c.borrow_mut().insert(key, cert.clone()));
    cert
}

/// Step 1 for one side of a handshake. See the module docs for the cache.
pub(crate) fn verify(
    der: &[u8],
    now: UnixTime,
    pin: Option<&IdentityPublicKey>,
    full: bool,
) -> Result<VerifiedSessionCert, CertError> {
    if full {
        return session_cert::verify(der, now, pin);
    }
    let Some(cached) = VERIFIED.with(|v| v.borrow().get(der).cloned()) else {
        return session_cert::verify(der, now, pin);
    };
    if let Some(expected) = pin {
        if *expected != cached.identity {
            return Err(CertError::PinMismatch);
        }
    }
    if !cached.window.accepts(now) {
        return Err(CertError::OutsideWindow);
    }
    Ok(cached)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CLOCK_SKEW_SECS: u64 = mousse_net_core::Limits::DEFAULT.clock_skew_secs;

    #[test]
    fn cached_and_full_verification_agree() {
        let nb = UnixTime(T0);
        let cert = certificate("a", nb, 3_600);
        let a = identity_key("a").public_key();
        let b = identity_key("b").public_key();
        let edges = [
            0,
            T0 - CLOCK_SKEW_SECS - 1,
            T0 - CLOCK_SKEW_SECS,
            T0,
            T0 + 3_600,
            T0 + 3_600 + CLOCK_SKEW_SECS,
            T0 + 3_600 + CLOCK_SKEW_SECS + 1,
            u64::MAX / 2,
        ];
        let mut outcomes = std::collections::BTreeSet::new();
        for now in edges {
            for pin in [None, Some(&a), Some(&b)] {
                let full = verify(cert.der(), UnixTime(now), pin, true);
                let fast = verify(cert.der(), UnixTime(now), pin, false);
                assert_eq!(full, fast, "now {now}, pin {pin:?}");
                outcomes.insert(format!("{:?}", fast.map(|_| ())));
            }
        }
        // The edges reach all three outcomes, so agreement is not vacuous.
        assert_eq!(outcomes.len(), 3, "{outcomes:?}");
    }

    #[test]
    fn same_inputs_give_the_same_certificate() {
        let a = certificate("dev", UnixTime(T0), 600);
        CERTS.with(|c| c.borrow_mut().clear());
        let b = certificate("dev", UnixTime(T0), 600);
        assert_eq!(a.der(), b.der());
        assert_ne!(a.der(), certificate("dev", UnixTime(T0 + 60), 600).der());
    }
}
