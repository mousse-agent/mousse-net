//! Peer session lifetime: certificate deadlines and path switches.
//!
//! A [`PeerSession`] is the long-lived relationship with one pinned peer. At
//! any moment it has at most one **current** path (an authenticated
//! connection carrying channels) and at most one **candidate** path being
//! brought up to replace it.
//!
//! - **Deadline.** A path's effective deadline is the earlier of the two
//!   certificates' `not_after`, plus the clock skew. The path may run through
//!   that second and closes with `CERT_EXPIRED` at the first second after it.
//!   The time left at authentication is also a monotonic budget: the path
//!   closes when either clock runs out, so setting the wall clock back
//!   cannot keep it open past its deadline.
//! - **Renewal.** [`Limits::renew_lead_secs`] before the earlier `not_after`, the
//!   session asks for a new path (a fresh handshake, with a fresh certificate
//!   if ours is the one running out). Renewal is just a path switch. If no
//!   new path with a later renewal time is current by the next retry time,
//!   it asks again: after
//!   [`Limits::renew_retry_first_secs`], doubling up to
//!   [`Limits::renew_retry_max_secs`],
//!   until the path's deadline.
//! - **Path switch.** Authenticate the new path (step 1 with the same pin),
//!   reopen channels on it from the app's cursors, then close the old path
//!   with `PATH_REPLACED`.
//!
//! This models state and decisions only; the I/O layer dials, handshakes and
//! moves bytes.

use crate::identity::IdentityPublicKey;
use crate::limits::Limits;
use crate::session_cert::{ValidityWindow, VerifiedSessionCert};
use crate::time::{Millis, UnixTime};
use crate::{ConnectionId, ErrorCode};

/// Pending renewal of the current path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Renewal {
    /// When to ask (again).
    next_at: UnixTime,
    /// The wait after the next request.
    backoff: u64,
}

/// One authenticated path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathInfo {
    /// The connection.
    pub conn: ConnectionId,
    /// When renewal should start.
    pub renew_at: UnixTime,
    /// When the path must close (wall clock): it runs through this second.
    pub deadline: UnixTime,
    /// The same limit on the monotonic clock: the path closes once the
    /// monotonic clock reaches this, whatever the wall clock says.
    pub mono_deadline: Millis,
}

impl PathInfo {
    fn new(
        conn: ConnectionId,
        local: ValidityWindow,
        peer: ValidityWindow,
        now: UnixTime,
        mono: Millis,
        limits: &SessionLimits,
    ) -> Self {
        let not_after = local.not_after().min(peer.not_after());
        let not_before = local.not_before().max(peer.not_before());
        // Never schedule renewal before the window starts.
        let renew_at = not_after.minus(limits.renew_lead_secs).max(not_before);
        let skew = limits.clock_skew_secs;
        let deadline = local
            .deadline_with_skew(skew)
            .min(peer.deadline_with_skew(skew));
        // Seconds left at authentication, counting the deadline second.
        let left = deadline.secs().saturating_add(1).saturating_sub(now.secs());
        Self {
            conn,
            renew_at,
            deadline,
            mono_deadline: mono.plus(left.saturating_mul(1_000)),
        }
    }

    fn expired(&self, now: UnixTime, mono: Millis) -> bool {
        now > self.deadline || mono >= self.mono_deadline
    }
}

/// Where the candidate path is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidatePhase {
    /// Dialled; step 1 not finished.
    Authenticating,
    /// Authenticated; the app is reopening channels from cursors.
    Reopening,
}

/// A path being brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The connection.
    pub conn: ConnectionId,
    /// Its phase.
    pub phase: CandidatePhase,
    /// Its timing, once authenticated.
    pub info: Option<PathInfo>,
}

/// Something the I/O layer or app must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// The current path is near its deadline: bring up a new path (renew our
    /// certificate first if it is ours that runs out).
    RenewDue {
        /// The path to replace.
        conn: ConnectionId,
    },
    /// The new path is authenticated: reopen channels on `to` from cursors.
    Reopen {
        /// Old path (may be gone already).
        from: Option<ConnectionId>,
        /// New path.
        to: ConnectionId,
    },
    /// The new path is now current.
    Switched {
        /// New current path.
        conn: ConnectionId,
    },
    /// Close this connection with this code.
    Close {
        /// Connection.
        conn: ConnectionId,
        /// Code.
        code: ErrorCode,
    },
}

/// Why a new path was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The peer on the new path is not the pinned identity.
    PinMismatch,
    /// The connection is not the candidate.
    UnknownPath,
    /// The new path's certificates are already past their deadline.
    Expired,
}

/// The session with one pinned peer.
#[derive(Clone, Debug)]
pub struct PeerSession {
    pin: IdentityPublicKey,
    current: Option<PathInfo>,
    /// Set once renewal is due; cleared when a new path with a later
    /// renewal time becomes current.
    renewal: Option<Renewal>,
    candidate: Option<Candidate>,
    limits: SessionLimits,
}

/// The limits a [`PeerSession`] uses, taken from [`Limits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SessionLimits {
    renew_lead_secs: u64,
    renew_retry_first_secs: u64,
    renew_retry_max_secs: u64,
    clock_skew_secs: u64,
}

impl PeerSession {
    /// A session for `pin` with no path yet. Uses the default limits; see
    /// [`PeerSession::with_limits`].
    pub fn new(pin: IdentityPublicKey) -> Self {
        Self::with_limits(pin, &Limits::DEFAULT)
    }

    /// [`PeerSession::new`] with other limits (renewal lead and retries,
    /// clock skew).
    pub fn with_limits(pin: IdentityPublicKey, limits: &Limits) -> Self {
        Self {
            pin,
            current: None,
            renewal: None,
            candidate: None,
            limits: SessionLimits {
                renew_lead_secs: limits.renew_lead_secs(),
                renew_retry_first_secs: limits.renew_retry_first_secs(),
                renew_retry_max_secs: limits.renew_retry_max_secs(),
                clock_skew_secs: limits.clock_skew_secs(),
            },
        }
    }

    /// The pinned identity.
    pub fn pin(&self) -> &IdentityPublicKey {
        &self.pin
    }

    /// The current path.
    pub fn current(&self) -> Option<&PathInfo> {
        self.current.as_ref()
    }

    /// The candidate path.
    pub fn candidate(&self) -> Option<&Candidate> {
        self.candidate.as_ref()
    }

    /// A new connection was dialled or accepted for this peer. It replaces
    /// any earlier candidate, which is closed.
    pub fn begin_path(&mut self, conn: ConnectionId) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(old) = self.candidate.take() {
            if old.conn != conn {
                events.push(SessionEvent::Close {
                    conn: old.conn,
                    code: ErrorCode::PathReplaced,
                });
            }
        }
        self.candidate = Some(Candidate {
            conn,
            phase: CandidatePhase::Authenticating,
            info: None,
        });
        events
    }

    /// Step 1 passed on the candidate. `peer` is the verified certificate,
    /// `local` our own certificate's window on that connection, `now` and
    /// `mono` the wall and monotonic clocks at authentication. The pin is
    /// checked again here: every path must be the same identity.
    pub fn on_authenticated(
        &mut self,
        conn: ConnectionId,
        peer: &VerifiedSessionCert,
        local: ValidityWindow,
        now: UnixTime,
        mono: Millis,
    ) -> Result<Vec<SessionEvent>, PathError> {
        let candidate = match self.candidate {
            Some(c) if c.conn == conn && c.phase == CandidatePhase::Authenticating => c,
            _ => return Err(PathError::UnknownPath),
        };
        if peer.identity != self.pin {
            self.candidate = None;
            return Err(PathError::PinMismatch);
        }
        let info = PathInfo::new(conn, local, peer.window, now, mono, &self.limits);
        if now > info.deadline {
            self.candidate = None;
            return Err(PathError::Expired);
        }
        self.candidate = Some(Candidate {
            phase: CandidatePhase::Reopening,
            info: Some(info),
            ..candidate
        });
        Ok(vec![SessionEvent::Reopen {
            from: self.current.map(|p| p.conn),
            to: conn,
        }])
    }

    /// The app reopened its channels on the candidate. It becomes current;
    /// the old path closes.
    pub fn on_reopened(&mut self, conn: ConnectionId) -> Result<Vec<SessionEvent>, PathError> {
        let info = match self.candidate {
            Some(Candidate {
                conn: c,
                phase: CandidatePhase::Reopening,
                info: Some(info),
            }) if c == conn => info,
            _ => return Err(PathError::UnknownPath),
        };
        self.candidate = None;
        let mut events = Vec::new();
        let old = self.current.replace(info);
        if let Some(old) = old {
            events.push(SessionEvent::Close {
                conn: old.conn,
                code: ErrorCode::PathReplaced,
            });
        }
        // Renewal ends only when the new path renews later than the old one.
        // A new path that still carries a certificate as old as before (the
        // peer has not renewed yet) keeps the pending renewal and its
        // growing backoff, so it is not replaced again every first retry.
        if old.is_none_or(|old| info.renew_at > old.renew_at) {
            self.renewal = None;
        }
        events.push(SessionEvent::Switched { conn });
        Ok(events)
    }

    /// A connection failed or closed on its own.
    pub fn on_path_closed(&mut self, conn: ConnectionId) {
        if self.candidate.is_some_and(|c| c.conn == conn) {
            self.candidate = None;
        }
        if self.current.is_some_and(|p| p.conn == conn) {
            self.current = None;
            self.renewal = None;
        }
    }

    /// When [`PeerSession::tick`] must next run by the monotonic clock: the
    /// earliest monotonic deadline of the current and candidate paths. Run
    /// `tick` at whichever of this and [`PeerSession::next_deadline`] comes
    /// first.
    pub fn next_mono_deadline(&self) -> Option<Millis> {
        let current = self.current.map(|p| p.mono_deadline);
        let candidate = self.candidate.and_then(|c| c.info).map(|i| i.mono_deadline);
        current.into_iter().chain(candidate).min()
    }

    /// When [`PeerSession::tick`] must next run by the wall clock.
    pub fn next_deadline(&self) -> Option<UnixTime> {
        let current = self.current.map(|p| match self.renewal {
            Some(r) => r.next_at.min(p.deadline.plus(1)),
            None => p.renew_at,
        });
        let candidate = self.candidate.and_then(|c| c.info).map(|i| i.deadline);
        current.into_iter().chain(candidate).min()
    }

    /// Run deadlines at wall-clock `now` and monotonic `mono`. A path ends
    /// when either clock passes its deadline; renewal follows the wall
    /// clock.
    pub fn tick(&mut self, now: UnixTime, mono: Millis) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(info) = self.candidate.and_then(|c| c.info) {
            if info.expired(now, mono) {
                self.candidate = None;
                events.push(SessionEvent::Close {
                    conn: info.conn,
                    code: ErrorCode::CertExpired,
                });
            }
        }
        if let Some(path) = self.current {
            if path.expired(now, mono) {
                self.current = None;
                self.renewal = None;
                events.push(SessionEvent::Close {
                    conn: path.conn,
                    code: ErrorCode::CertExpired,
                });
            } else if now >= path.renew_at {
                let renewal = self.renewal.get_or_insert(Renewal {
                    next_at: path.renew_at,
                    backoff: self.limits.renew_retry_first_secs,
                });
                if now >= renewal.next_at {
                    // Ask again later unless a new path becomes current. The
                    // next wait starts now. A candidate still being brought
                    // up is left alone, but the skipped retry still counts.
                    let in_progress = self.candidate.is_some();
                    renewal.next_at = now.plus(renewal.backoff);
                    renewal.backoff = (renewal.backoff * 2).min(self.limits.renew_retry_max_secs);
                    if !in_progress {
                        events.push(SessionEvent::RenewDue { conn: path.conn });
                    }
                }
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::identity::SoftwareKey;
    use crate::session_cert::{issue, verify};
    const CLOCK_SKEW_SECS: u64 = Limits::DEFAULT.clock_skew_secs();
    const RENEW_LEAD_SECS: u64 = Limits::DEFAULT.renew_lead_secs();
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const T0: UnixTime = UnixTime(1_790_000_000);

    fn peer_cert(seed: u8, lifetime: u64) -> VerifiedSessionCert {
        let id = SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]));
        let c = issue(
            &id,
            &mut ChaCha20Rng::from_seed([seed + 100; 32]),
            ValidityWindow::starting_at(T0, lifetime).unwrap(),
        )
        .unwrap();
        verify(c.der(), T0, None).unwrap()
    }

    /// The monotonic clock in these tests: zero at T0, running with the
    /// wall clock.
    fn m(t: UnixTime) -> Millis {
        Millis((t.secs() - T0.secs()) * 1_000)
    }

    fn local(lifetime: u64) -> ValidityWindow {
        ValidityWindow::starting_at(T0, lifetime).unwrap()
    }

    #[test]
    fn live_path_is_closed_at_the_effective_certificate_deadline() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let deadline = T0.plus(3_600 + CLOCK_SKEW_SECS);
        assert_eq!(s.current().unwrap().deadline, deadline);
        assert_eq!(
            s.tick(
                T0.plus(3_600 - RENEW_LEAD_SECS),
                m(T0.plus(3_600 - RENEW_LEAD_SECS))
            ),
            vec![SessionEvent::RenewDue {
                conn: ConnectionId(1)
            }]
        );
        // Still open through the deadline second (renewal is asked again).
        assert!(s
            .tick(deadline, m(deadline))
            .iter()
            .all(|e| matches!(e, SessionEvent::RenewDue { .. })));
        assert!(s.current().is_some());
        assert_eq!(
            s.tick(deadline.plus(1), m(deadline.plus(1))),
            vec![SessionEvent::Close {
                conn: ConnectionId(1),
                code: ErrorCode::CertExpired
            }]
        );
        assert!(s.current().is_none());
    }

    /// The first renewal fails: the session asks again on a growing
    /// backoff until the deadline, and stops once a new path is current.
    #[test]
    fn setting_the_wall_clock_back_does_not_keep_a_path_open() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let deadline = T0.plus(3_600 + CLOCK_SKEW_SECS);
        let mono_deadline = m(deadline.plus(1));
        assert_eq!(s.next_mono_deadline(), Some(mono_deadline));
        // The wall clock is set back an hour: by wall time the path has
        // plenty left, but the monotonic budget still runs out on time.
        let wall = T0.plus(60);
        assert_eq!(s.tick(wall, Millis(mono_deadline.ms() - 1)), vec![]);
        assert_eq!(
            s.tick(wall, mono_deadline),
            vec![SessionEvent::Close {
                conn: ConnectionId(1),
                code: ErrorCode::CertExpired
            }]
        );
        assert!(s.current().is_none());
    }

    #[test]
    fn a_failed_renewal_is_asked_for_again_until_the_deadline() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let renew_at = T0.plus(3_600 - RENEW_LEAD_SECS);
        let due = vec![SessionEvent::RenewDue {
            conn: ConnectionId(1),
        }];
        assert_eq!(s.tick(renew_at, m(renew_at)), due);
        assert_eq!(s.next_deadline(), Some(renew_at.plus(30)));

        // The new path fails.
        s.begin_path(ConnectionId(2));
        s.on_path_closed(ConnectionId(2));
        assert_eq!(s.tick(renew_at.plus(29), m(renew_at.plus(29))), vec![]);
        assert_eq!(s.tick(renew_at.plus(30), m(renew_at.plus(30))), due);
        assert_eq!(s.next_deadline(), Some(renew_at.plus(30 + 60)));

        // A candidate still being brought up is not interrupted.
        s.begin_path(ConnectionId(3));
        assert_eq!(s.tick(renew_at.plus(90), m(renew_at.plus(90))), vec![]);
        s.on_path_closed(ConnectionId(3));
        assert_eq!(
            s.tick(renew_at.plus(90 + 120), m(renew_at.plus(90 + 120))),
            due
        );

        // Waits double up to the cap, and requests continue until the
        // deadline.
        let mut t = renew_at.plus(210);
        let mut waits = Vec::new();
        let deadline = s.current().unwrap().deadline;
        while let Some(next) = s.next_deadline() {
            if next > deadline {
                break;
            }
            waits.push(next.secs() - t.secs());
            t = next;
            assert_eq!(s.tick(t, m(t)), due);
        }
        assert_eq!(&waits[..3], &[240, 300, 300]);
        assert_eq!(s.next_deadline(), Some(deadline.plus(1)));
        assert_eq!(
            s.tick(deadline.plus(1), m(deadline.plus(1))),
            vec![SessionEvent::Close {
                conn: ConnectionId(1),
                code: ErrorCode::CertExpired
            }]
        );
    }

    #[test]
    fn a_new_current_path_ends_renewal_requests() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let renew_at = T0.plus(3_600 - RENEW_LEAD_SECS);
        assert_eq!(s.tick(renew_at, m(renew_at)).len(), 1);
        let fresh = peer_cert(1, 86_400);
        s.begin_path(ConnectionId(2));
        s.on_authenticated(
            ConnectionId(2),
            &fresh,
            local(86_400),
            renew_at,
            m(renew_at),
        )
        .unwrap();
        s.on_reopened(ConnectionId(2)).unwrap();
        assert_eq!(s.tick(renew_at.plus(30), m(renew_at.plus(30))), vec![]);
        assert_eq!(
            s.tick(renew_at.plus(3_600), m(renew_at.plus(3_600))),
            vec![]
        );
    }

    /// The peer has not renewed yet (for example its clock is behind ours):
    /// the new path carries the same old certificate. Switching to it must
    /// not restart renewal at the first retry; the backoff keeps growing.
    #[test]
    fn a_new_path_with_the_same_old_certificate_keeps_the_renewal_backoff() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let renew_at = T0.plus(3_600 - RENEW_LEAD_SECS);
        let mut t = renew_at;
        let mut conn = 1;
        let mut waits = Vec::new();
        assert_eq!(s.tick(t, m(t)).len(), 1);
        for _ in 0..5 {
            // Each request brings up a new path with the peer's old
            // certificate, which becomes current right away.
            conn += 1;
            s.begin_path(ConnectionId(conn));
            s.on_authenticated(ConnectionId(conn), &peer, local(86_400), t, m(t))
                .unwrap();
            s.on_reopened(ConnectionId(conn)).unwrap();
            assert_eq!(
                s.tick(t.plus(1), m(t.plus(1))),
                vec![],
                "asked again at once"
            );
            let next = s.next_deadline().unwrap();
            waits.push(next.secs() - t.secs());
            t = next;
            assert_eq!(
                s.tick(t, m(t)),
                vec![SessionEvent::RenewDue {
                    conn: ConnectionId(conn)
                }]
            );
        }
        assert_eq!(waits, vec![30, 60, 120, 240, 300]);
    }

    #[test]
    fn path_switch_authenticates_reopens_then_closes_the_old_path() {
        let peer = peer_cert(1, 86_400);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        s.begin_path(ConnectionId(2));
        let events = s
            .on_authenticated(ConnectionId(2), &peer, local(86_400), T0, m(T0))
            .unwrap();
        assert_eq!(
            events,
            vec![SessionEvent::Reopen {
                from: Some(ConnectionId(1)),
                to: ConnectionId(2)
            }]
        );
        assert_eq!(
            s.current().unwrap().conn,
            ConnectionId(1),
            "old path stays until reopen is done"
        );
        let events = s.on_reopened(ConnectionId(2)).unwrap();
        assert_eq!(
            events,
            vec![
                SessionEvent::Close {
                    conn: ConnectionId(1),
                    code: ErrorCode::PathReplaced
                },
                SessionEvent::Switched {
                    conn: ConnectionId(2)
                }
            ]
        );
    }

    #[test]
    fn a_new_path_with_another_identity_is_refused_and_the_old_path_stays() {
        let peer = peer_cert(1, 86_400);
        let impostor = peer_cert(2, 86_400);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        s.begin_path(ConnectionId(2));
        assert_eq!(
            s.on_authenticated(ConnectionId(2), &impostor, local(86_400), T0, m(T0)),
            Err(PathError::PinMismatch)
        );
        assert_eq!(s.current().unwrap().conn, ConnectionId(1));
        assert!(s.candidate().is_none());
    }

    #[test]
    fn the_earlier_certificate_sets_the_deadline() {
        let peer = peer_cert(1, 86_400);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(7_200), T0, m(T0))
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        assert_eq!(
            s.current().unwrap().deadline,
            T0.plus(7_200 + CLOCK_SKEW_SECS)
        );
        assert_eq!(
            s.current().unwrap().renew_at,
            T0.plus(7_200 - RENEW_LEAD_SECS)
        );
    }
}
