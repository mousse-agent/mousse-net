//! A target's registration on one relay (§B.4, §B.5, §B.8, §B.10).
//!
//! [`TargetLink::register`] proves the registration key on a fresh outer
//! connection (`REGISTER`, `REGISTER` with an admission token on a hosted
//! relay, or `ENROLL` with a code from an enrollment link).
//! [`TargetLink::run`] then keeps it: it pushes the allow-set at once and
//! on every change, answers and sends keepalives, for each `INCOMING` opens
//! an accept leg on a new connection, signed by the registration key, and
//! hands the spliced pipe out. On a hosted relay it also sends `LEASE`,
//! `RELEASE` and `ADMIT` and reports `LEASE_STATUS`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::relay::msg::{InvitationEntry, LeaseStatusEntry};
use mousse_net_core::relay::{Class, RefuseReason, RelayClientKey, RelayId, RelayMessage};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::outer::{RelayAddr, RelayLink, WsPipe};
use super::{wait_spliced, RelayError};

/// What a target lets through: listed caller keys and open invitations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowSet {
    /// Caller key fingerprints, at most 256.
    pub callers: Vec<[u8; 32]>,
    /// Invitation tag hashes, at most 8.
    pub invitations: Vec<InvitationEntry>,
}

/// Something for a live registration to send.
#[derive(Debug)]
pub enum TargetCommand {
    /// Make a join circuit a listed caller's circuit (§B.7).
    Promote { circuit: [u8; 16], caller: [u8; 32] },
    /// Vouch for a new registration key (self mode, §B.4).
    Successor { new_key: Arc<RelayClientKey> },
    /// `LEASE` with a signed block (hosted, §B.10).
    Lease(Vec<u8>),
    /// `RELEASE` these leases (hosted, §B.10).
    Release(Vec<[u8; 16]>),
    /// `ADMIT` with a renewed admission token (hosted, §B.4).
    Admit(Vec<u8>),
}

/// What a live registration reports.
#[derive(Debug)]
pub enum TargetEvent {
    /// The relay took the allow-set with this sequence.
    AllowSetOk { sequence: u64 },
    /// A caller (`caller` set) or a joiner (`None`) was spliced to an
    /// accept leg: run the host side of the peer session on `pipe`.
    Incoming {
        circuit: [u8; 16],
        class: Class,
        caller: Option<[u8; 32]>,
        pipe: Box<WsPipe>,
    },
    /// An accept leg failed; the caller gets `UNREACHABLE`.
    AcceptFailed {
        circuit: [u8; 16],
        error: RelayError,
    },
    /// A hosted relay's `LEASE_STATUS` (§B.10).
    LeaseStatus(Vec<LeaseStatusEntry>),
    /// `REFUSED(chain_full)`: the relay did not take a `SUCCESSOR` because
    /// the key chain is full. The registration goes on.
    ChainFull,
}

/// Allow-set sequences grow for the life of the process and start from the
/// clock, so a new registration after a restart starts above the last.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn next_sequence() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut cur = SEQUENCE.load(Ordering::Relaxed);
    loop {
        let next = cur.saturating_add(1).max(now);
        match SEQUENCE.compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(seen) => cur = seen,
        }
    }
}

fn allow_message(set: AllowSet) -> RelayMessage {
    RelayMessage::AllowSet {
        sequence: next_sequence(),
        callers: set.callers,
        invitations: set.invitations,
    }
}

/// How a registration is proved.
#[derive(Clone)]
pub enum Proof {
    /// `REGISTER`: the key is already authorized.
    Register,
    /// `ENROLL` with a single-use code from an enrollment link.
    Enroll([u8; 16]),
    /// `REGISTER` on a hosted relay: the admission token for this handle,
    /// and the lease use (percent) at which the relay sends `LEASE_STATUS`.
    Hosted {
        /// The signed admission token envelope.
        token: Vec<u8>,
        /// The status threshold, percent.
        threshold: u8,
    },
}

/// One live registration connection.
pub struct TargetLink {
    link: RelayLink,
    addr: RelayAddr,
    relay: RelayId,
    key: Arc<RelayClientKey>,
    handle: [u8; 32],
    within: Duration,
    successor_overlap: Option<u64>,
}

impl std::fmt::Debug for TargetLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TargetLink({})", self.addr.addr)
    }
}

impl TargetLink {
    /// Dial the relay, prove the registration key and wait for
    /// `REGISTERED`, all within `within`.
    pub async fn register(
        addr: &RelayAddr,
        relay: RelayId,
        key: Arc<RelayClientKey>,
        proof: Proof,
        within: Duration,
    ) -> Result<Self, RelayError> {
        let started = Instant::now();
        let mut link = RelayLink::connect(addr, relay, within).await?;
        let expected = key.handle(&relay);
        let signed = key.register_proof(&relay, &link.binding());
        let msg = match proof {
            Proof::Register => RelayMessage::Register {
                key: key.public_key(),
                proof: signed,
                hosted: None,
            },
            Proof::Hosted { token, threshold } => RelayMessage::Register {
                key: key.public_key(),
                proof: signed,
                hosted: Some((token, threshold)),
            },
            Proof::Enroll(code) => RelayMessage::Enroll {
                key: key.public_key(),
                proof: signed,
                code,
            },
        };
        let left = within.saturating_sub(started.elapsed());
        let got = tokio::time::timeout(left, async {
            link.send(&msg).await?;
            match link.recv().await? {
                RelayMessage::Registered {
                    handle,
                    successor_overlap,
                } => Ok((handle, successor_overlap)),
                RelayMessage::Refused { reason } => Err(RelayError::Refused(reason)),
                other => Err(RelayError::Protocol(format!(
                    "expected REGISTERED, got {}",
                    other.name()
                ))),
            }
        })
        .await
        .map_err(|_| RelayError::Timeout)??;
        let (got, successor_overlap) = got;
        if got != expected {
            return Err(RelayError::Protocol(
                "the relay named another handle".into(),
            ));
        }
        Ok(Self {
            link,
            addr: addr.clone(),
            relay,
            key,
            handle: expected,
            within,
            successor_overlap,
        })
    }

    /// This registration's handle.
    pub fn handle(&self) -> [u8; 32] {
        self.handle
    }

    /// The relay's `RELAY_SUCCESSOR_OVERLAP_SECS`, from `REGISTERED` (self
    /// mode only): how long a key a `SUCCESSOR` supersedes stays listed.
    pub fn successor_overlap(&self) -> Option<u64> {
        self.successor_overlap
    }

    /// The relay's identity key, from its pinned certificate.
    pub fn relay_key(&self) -> Option<mousse_net_core::identity::PublicKey> {
        self.link.relay_key()
    }

    /// The relay's boot (`RELAY_HELLO`): blocks name it (§B.10).
    pub fn boot_id(&self) -> [u8; 16] {
        self.link.boot_id()
    }

    /// Keep the registration until it ends; returns why. The allow-set is
    /// pushed at once and again on every change of `allow`. At most
    /// `accept_legs` accept legs are dialled at once: an `INCOMING` past
    /// that is reported as [`TargetEvent::AcceptFailed`] and left to time
    /// out at the relay, so a relay cannot make the target dial without
    /// bound.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        mut self,
        mut allow: watch::Receiver<AllowSet>,
        mut commands: mpsc::UnboundedReceiver<TargetCommand>,
        events: mpsc::UnboundedSender<TargetEvent>,
        keepalive: Duration,
        idle: Duration,
        accept_legs: usize,
    ) -> RelayError {
        let legs = Arc::new(Semaphore::new(accept_legs.max(1)));
        let mut last_sent = Instant::now();
        let mut last_heard = Instant::now();
        let mut push = true;
        let mut commands_open = true;
        loop {
            if push {
                push = false;
                let set = allow.borrow_and_update().clone();
                if let Err(e) = self.link.send(&allow_message(set)).await {
                    return e;
                }
                last_sent = Instant::now();
            }
            let ping_at = last_sent + keepalive;
            let dead_at = last_heard + idle;
            tokio::select! {
                changed = allow.changed() => match changed {
                    Ok(()) => push = true,
                    // Nobody keeps this registration any more.
                    Err(_) => {
                        self.link.close(1000).await;
                        return RelayError::Closed(None);
                    }
                },
                cmd = commands.recv(), if commands_open => {
                    // A command follows the allow-set it depends on: a
                    // `PROMOTE` names a caller the set just listed.
                    if allow.has_changed().unwrap_or(false) {
                        let set = allow.borrow_and_update().clone();
                        if let Err(e) = self.link.send(&allow_message(set)).await {
                            return e;
                        }
                    }
                    let msg = match cmd {
                        None => { commands_open = false; continue }
                        Some(TargetCommand::Promote { circuit, caller }) => {
                            RelayMessage::Promote { circuit, caller }
                        }
                        Some(TargetCommand::Successor { new_key }) => {
                            let binding = self.link.binding();
                            let new_public = new_key.public_key();
                            RelayMessage::Successor {
                                key: new_public,
                                new_proof: new_key.successor_proof(&self.relay, &new_public, &binding),
                                current_proof: self.key.successor_proof(&self.relay, &new_public, &binding),
                            }
                        }
                        Some(TargetCommand::Lease(block)) => RelayMessage::Lease { block },
                        Some(TargetCommand::Release(leases)) => RelayMessage::Release { leases },
                        Some(TargetCommand::Admit(token)) => RelayMessage::Admit { token },
                    };
                    if let Err(e) = self.link.send(&msg).await {
                        return e;
                    }
                    last_sent = Instant::now();
                }
                got = self.link.recv() => {
                    last_heard = Instant::now();
                    match got {
                        Err(e) => return e,
                        Ok(RelayMessage::Ping { data }) => {
                            if let Err(e) = self.link.send(&RelayMessage::Pong { data }).await {
                                return e;
                            }
                            last_sent = Instant::now();
                        }
                        Ok(RelayMessage::Pong { .. }) => {}
                        Ok(RelayMessage::AllowSetOk { sequence }) => {
                            let _ = events.send(TargetEvent::AllowSetOk { sequence });
                        }
                        Ok(RelayMessage::Incoming { circuit, class, caller }) => {
                            let permit = if cfg!(mousse_control = "accept-legs-unbounded") {
                                None
                            } else {
                                match legs.clone().try_acquire_owned() {
                                    Ok(permit) => Some(permit),
                                    Err(_) => {
                                        let _ = events.send(TargetEvent::AcceptFailed {
                                            circuit,
                                            error: RelayError::Refused(RefuseReason::Limit),
                                        });
                                        continue;
                                    }
                                }
                            };
                            tokio::spawn(accept_leg(
                                permit,
                                self.addr.clone(),
                                self.relay,
                                self.key.clone(),
                                self.within,
                                circuit,
                                class,
                                caller,
                                events.clone(),
                            ));
                        }
                        Ok(RelayMessage::Refused { reason: RefuseReason::ChainFull }) => {
                            let _ = events.send(TargetEvent::ChainFull);
                        }
                        Ok(RelayMessage::Refused { reason }) => return RelayError::Refused(reason),
                        Ok(RelayMessage::LeaseStatus { entries }) => {
                            let _ = events.send(TargetEvent::LeaseStatus(entries));
                        }
                        Ok(other) => {
                            return RelayError::Protocol(format!(
                                "unexpected relay message {}",
                                other.name()
                            ))
                        }
                    }
                }
                () = tokio::time::sleep_until(ping_at) => {
                    let data = crate::rng::random_bytes::<8>();
                    if let Err(e) = self.link.send(&RelayMessage::Ping { data }).await {
                        return e;
                    }
                    last_sent = Instant::now();
                }
                () = tokio::time::sleep_until(dead_at) => {
                    self.link.close(1000).await;
                    return RelayError::Timeout;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_leg(
    // Held until the leg is spliced or has failed.
    _permit: Option<OwnedSemaphorePermit>,
    addr: RelayAddr,
    relay: RelayId,
    key: Arc<RelayClientKey>,
    within: Duration,
    circuit: [u8; 16],
    class: Class,
    caller: Option<[u8; 32]>,
    events: mpsc::UnboundedSender<TargetEvent>,
) {
    let leg = async {
        let started = Instant::now();
        let mut link = RelayLink::connect(&addr, relay, within).await?;
        let msg = RelayMessage::Accept {
            handle: key.handle(&relay),
            circuit,
            proof: key.accept_proof(&relay, &circuit, &link.binding()),
        };
        let left = within.saturating_sub(started.elapsed());
        tokio::time::timeout(left, async {
            link.send(&msg).await?;
            wait_spliced(&mut link).await
        })
        .await
        .map_err(|_| RelayError::Timeout)??;
        Ok::<_, RelayError>(link.into_pipe())
    };
    let event = match leg.await {
        Ok(pipe) => TargetEvent::Incoming {
            circuit,
            class,
            caller,
            pipe: Box::new(pipe),
        },
        Err(error) => TargetEvent::AcceptFailed { circuit, error },
    };
    let _ = events.send(event);
}
