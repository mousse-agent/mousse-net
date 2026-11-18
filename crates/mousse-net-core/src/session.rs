//! Peer session lifetime: certificate deadlines and path switches.
//!
//! A [`PeerSession`] is the long-lived relationship with one pinned peer. At
//! any moment it has at most one **current** path (an authenticated
//! connection carrying channels) and at most one **candidate** path being
//! brought up to replace it.
//!
//! - **Deadline.** A path's effective deadline is the earlier of the two
//!   certificates' `not_after`, plus the 10 min skew. The path may run through
//!   that second and closes with `CERT_EXPIRED` at the first second after it.
//! - **Renewal.** [`RENEW_LEAD_SECS`] before the earlier `not_after`, the
//!   session asks for a new path (a fresh handshake, with a fresh certificate
//!   if ours is the one running out). Renewal is just a path switch. If no
//!   new path is current by the next retry time, it asks again: after
//!   [`RENEW_RETRY_FIRST_SECS`], doubling up to [`RENEW_RETRY_MAX_SECS`],
//!   until the path's deadline.
//! - **Path switch.** Authenticate the new path (step 1 with the same pin),
//!   reopen channels on it from the app's cursors, then close the old path
//!   with `PATH_REPLACED`.
//!
//! This models state and decisions only; the I/O layer dials, handshakes and
//! moves bytes.

use crate::identity::IdentityPublicKey;
use crate::session_cert::{ValidityWindow, VerifiedSessionCert};
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

/// Start renewal this long before the earlier certificate's `not_after`
/// (30 minutes).
pub const RENEW_LEAD_SECS: u64 = 1_800;

/// First wait before asking again for a renewal that has not happened
/// (30 seconds).
pub const RENEW_RETRY_FIRST_SECS: u64 = 30;

/// Longest wait between renewal requests (5 minutes).
pub const RENEW_RETRY_MAX_SECS: u64 = 300;

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
    /// When the path must close.
    pub deadline: UnixTime,
}

impl PathInfo {
    fn new(conn: ConnectionId, local: ValidityWindow, peer: ValidityWindow) -> Self {
        let not_after = local.not_after().min(peer.not_after());
        let not_before = local.not_before().max(peer.not_before());
        // Never schedule renewal before the window starts.
        let renew_at = not_after.minus(RENEW_LEAD_SECS).max(not_before);
        Self {
            conn,
            renew_at,
            deadline: local.effective_deadline().min(peer.effective_deadline()),
        }
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
    /// Set once renewal is due; cleared when a new path becomes current.
    renewal: Option<Renewal>,
    candidate: Option<Candidate>,
}

impl PeerSession {
    /// A session for `pin` with no path yet.
    pub fn new(pin: IdentityPublicKey) -> Self {
        Self {
            pin,
            current: None,
            renewal: None,
            candidate: None,
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
    /// `local` our own certificate's window on that connection. The pin is
    /// checked again here: every path must be the same identity.
    pub fn on_authenticated(
        &mut self,
        conn: ConnectionId,
        peer: &VerifiedSessionCert,
        local: ValidityWindow,
        now: UnixTime,
    ) -> Result<Vec<SessionEvent>, PathError> {
        let candidate = match self.candidate {
            Some(c) if c.conn == conn && c.phase == CandidatePhase::Authenticating => c,
            _ => return Err(PathError::UnknownPath),
        };
        if peer.identity != self.pin {
            self.candidate = None;
            return Err(PathError::PinMismatch);
        }
        let info = PathInfo::new(conn, local, peer.window);
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
        if let Some(old) = self.current.replace(info) {
            events.push(SessionEvent::Close {
                conn: old.conn,
                code: ErrorCode::PathReplaced,
            });
        }
        self.renewal = None;
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

    /// When [`PeerSession::tick`] must next run.
    pub fn next_deadline(&self) -> Option<UnixTime> {
        let current = self.current.map(|p| match self.renewal {
            Some(r) => r.next_at.min(p.deadline.plus(1)),
            None => p.renew_at,
        });
        let candidate = self.candidate.and_then(|c| c.info).map(|i| i.deadline);
        current.into_iter().chain(candidate).min()
    }

    /// Run deadlines at wall-clock `now`.
    pub fn tick(&mut self, now: UnixTime) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(info) = self.candidate.and_then(|c| c.info) {
            if now > info.deadline {
                self.candidate = None;
                events.push(SessionEvent::Close {
                    conn: info.conn,
                    code: ErrorCode::CertExpired,
                });
            }
        }
        if let Some(path) = self.current {
            if now > path.deadline {
                self.current = None;
                self.renewal = None;
                events.push(SessionEvent::Close {
                    conn: path.conn,
                    code: ErrorCode::CertExpired,
                });
            } else if now >= path.renew_at {
                let renewal = self.renewal.get_or_insert(Renewal {
                    next_at: path.renew_at,
                    backoff: RENEW_RETRY_FIRST_SECS,
                });
                if now >= renewal.next_at {
                    // Ask again later unless a new path becomes current. A
                    // candidate still being brought up is left alone.
                    let in_progress = self.candidate.is_some();
                    renewal.next_at = now.plus(renewal.backoff);
                    renewal.backoff = (renewal.backoff * 2).min(RENEW_RETRY_MAX_SECS);
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
    use super::*;
    use crate::identity::SoftwareKey;
    use crate::session_cert::{issue, verify};
    use crate::CLOCK_SKEW_SECS;
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

    fn local(lifetime: u64) -> ValidityWindow {
        ValidityWindow::starting_at(T0, lifetime).unwrap()
    }

    #[test]
    fn live_path_is_closed_at_the_effective_certificate_deadline() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0)
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let deadline = T0.plus(3_600 + CLOCK_SKEW_SECS);
        assert_eq!(s.current().unwrap().deadline, deadline);
        assert_eq!(
            s.tick(T0.plus(3_600 - RENEW_LEAD_SECS)),
            vec![SessionEvent::RenewDue {
                conn: ConnectionId(1)
            }]
        );
        // Still open through the deadline second (renewal is asked again).
        assert!(s
            .tick(deadline)
            .iter()
            .all(|e| matches!(e, SessionEvent::RenewDue { .. })));
        assert!(s.current().is_some());
        assert_eq!(
            s.tick(deadline.plus(1)),
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
    fn a_failed_renewal_is_asked_for_again_until_the_deadline() {
        let peer = peer_cert(1, 3_600);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0)
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let renew_at = T0.plus(3_600 - RENEW_LEAD_SECS);
        let due = vec![SessionEvent::RenewDue {
            conn: ConnectionId(1),
        }];
        assert_eq!(s.tick(renew_at), due);
        assert_eq!(s.next_deadline(), Some(renew_at.plus(30)));

        // The new path fails.
        s.begin_path(ConnectionId(2));
        s.on_path_closed(ConnectionId(2));
        assert_eq!(s.tick(renew_at.plus(29)), vec![]);
        assert_eq!(s.tick(renew_at.plus(30)), due);
        assert_eq!(s.next_deadline(), Some(renew_at.plus(30 + 60)));

        // A candidate still being brought up is not interrupted.
        s.begin_path(ConnectionId(3));
        assert_eq!(s.tick(renew_at.plus(90)), vec![]);
        s.on_path_closed(ConnectionId(3));
        assert_eq!(s.tick(renew_at.plus(90 + 120)), due);

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
            assert_eq!(s.tick(t), due);
        }
        assert_eq!(&waits[..3], &[240, 300, 300]);
        assert_eq!(s.next_deadline(), Some(deadline.plus(1)));
        assert_eq!(
            s.tick(deadline.plus(1)),
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
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0)
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        let renew_at = T0.plus(3_600 - RENEW_LEAD_SECS);
        assert_eq!(s.tick(renew_at).len(), 1);
        let fresh = peer_cert(1, 86_400);
        s.begin_path(ConnectionId(2));
        s.on_authenticated(ConnectionId(2), &fresh, local(86_400), renew_at)
            .unwrap();
        s.on_reopened(ConnectionId(2)).unwrap();
        assert_eq!(s.tick(renew_at.plus(30)), vec![]);
        assert_eq!(s.tick(renew_at.plus(3_600)), vec![]);
    }

    #[test]
    fn path_switch_authenticates_reopens_then_closes_the_old_path() {
        let peer = peer_cert(1, 86_400);
        let mut s = PeerSession::new(peer.identity);
        s.begin_path(ConnectionId(1));
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0)
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        s.begin_path(ConnectionId(2));
        let events = s
            .on_authenticated(ConnectionId(2), &peer, local(86_400), T0)
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
        s.on_authenticated(ConnectionId(1), &peer, local(86_400), T0)
            .unwrap();
        s.on_reopened(ConnectionId(1)).unwrap();
        s.begin_path(ConnectionId(2));
        assert_eq!(
            s.on_authenticated(ConnectionId(2), &impostor, local(86_400), T0),
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
        s.on_authenticated(ConnectionId(1), &peer, local(7_200), T0)
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
