//! The relay's admission state machine (spec `relay.md` sections 6 to 11),
//! in self-hosted mode and, with a [`Hosted`] state, in hosted mode
//! (`docs/phase34-design.md` §B.10). No I/O: the caller passes events, both
//! clocks and the randomness, and carries out the [`Output`]s in order.

use std::collections::{BTreeMap, BTreeSet};

use rand_core::CryptoRng;

use crate::identity::PublicKey;
use crate::relay_hosted::{self, Direction, Hosted};
use crate::time::{Millis, UnixTime};

use super::limits::RelayLimits;
use super::msg::{Class, InvitationEntry, Mode, RefuseReason, RelayMessage, RELAY_VERSION};
use super::proof::{self, Binding, RelayId};

/// WebSocket close codes the relay uses (`relay.md` 4.4).
pub mod close {
    /// Normal close, after `UNREACHABLE` or `REFUSED`, or the other leg.
    pub const NORMAL: u16 = 1000;
    /// A protocol error.
    pub const PROTOCOL: u16 = 1002;
    /// The caller left the allow-set, or the target was revoked.
    pub const REMOVED: u16 = 4000;
    /// Hosted: lease exhausted.
    pub const LEASE_EXHAUSTED: u16 = 4001;
    /// Idle.
    pub const IDLE: u16 = 4002;
    /// The relay stops.
    pub const RELAY_STOPPING: u16 = 4003;
    /// Hosted: admission expired.
    pub const ADMISSION_EXPIRED: u16 = 4004;
    /// Replaced by a new registration of the same handle.
    pub const REPLACED: u16 = 4005;
    /// A local limit.
    pub const LIMIT: u16 = 4006;
}

/// A local handle for one outer connection, assigned by the I/O layer in
/// increasing order. Never on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

/// The address key a connection counts against: an IPv4 address, or the
/// /64 prefix of an IPv6 address. Memory only; never logged.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpKey(pub [u8; 16]);

impl core::fmt::Debug for IpKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IpKey(..)")
    }
}

/// Both clocks at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// Monotonic milliseconds.
    pub mono: Millis,
    /// Wall clock.
    pub wall: UnixTime,
}

/// One entry of the operator's authorized list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizedKey {
    /// Registration fingerprint.
    pub fingerprint: [u8; 32],
    /// Set when a `SUCCESSOR` superseded this key: when it is dropped.
    pub drop_at: Option<UnixTime>,
}

/// One stored enrollment code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollCode {
    /// `H(code)`.
    pub hash: [u8; 32],
    /// When it stops being valid.
    pub expires_at: UnixTime,
}

/// What the I/O layer must do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Send one relay message on `conn`.
    Send {
        /// Connection.
        conn: ConnId,
        /// Canonical CBOR bytes.
        message: Vec<u8>,
    },
    /// Close `conn` with a WebSocket close code. The machine forgets it.
    Close {
        /// Connection.
        conn: ConnId,
        /// Close code ([`close`]).
        code: u16,
    },
    /// From now on forward peer messages between these two legs.
    Splice {
        /// Circuit id.
        circuit: [u8; 16],
        /// The caller's or joiner's leg.
        caller: ConnId,
        /// The target's accept leg.
        target: ConnId,
        /// The circuit's class (egress priority).
        class: Class,
    },
    /// Forward this peer message.
    Forward {
        /// From leg.
        from: ConnId,
        /// To leg.
        to: ConnId,
        /// Payload length.
        len: usize,
    },
    /// Durably add a key to the authorized list before the next output.
    Authorize {
        /// Registration fingerprint.
        fingerprint: [u8; 32],
    },
    /// Durably mark a key superseded.
    Supersede {
        /// Registration fingerprint.
        fingerprint: [u8; 32],
        /// When it is dropped.
        drop_at: UnixTime,
    },
    /// Durably remove a superseded key whose drop time came.
    Drop {
        /// Registration fingerprint.
        fingerprint: [u8; 32],
    },
    /// Durably remove a used enrollment code.
    ConsumeCode {
        /// `H(code)`.
        hash: [u8; 32],
    },
    /// Hosted: the rate bucket of this leg's class is short. Hand the same
    /// peer message to [`Relay::data`] again at `until`, reading nothing
    /// more from `conn` meanwhile.
    Hold {
        /// The leg.
        conn: ConnId,
        /// Monotonic time to try again.
        until: Millis,
    },
    /// Hosted: no lease covers this leg's message. Hand it to
    /// [`Relay::data`] again after [`Output::Resume`] for `conn`, reading
    /// nothing more from `conn` meanwhile (the circuit closes with 4001 if
    /// no lease comes in time).
    Pause {
        /// The leg.
        conn: ConnId,
    },
    /// Hosted: a paused leg may try its message again.
    Resume {
        /// The leg.
        conn: ConnId,
    },
}

/// The relay's fixed configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// The relay identity public key.
    pub relay_key: PublicKey,
    /// This boot's id.
    pub boot_id: [u8; 16],
    /// Limits.
    pub limits: RelayLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// No first message yet.
    Fresh { hello_deadline: Millis },
    /// A registration connection.
    Registration { handle: [u8; 32] },
    /// A refused call or join leg, waiting for its deadline.
    Refusing { deadline: Millis },
    /// A call or join leg with a circuit.
    Leg { circuit: [u8; 16] },
    /// A spliced accept leg.
    AcceptLeg { circuit: [u8; 16] },
}

#[derive(Clone, Debug)]
struct Conn {
    ip: IpKey,
    binding: Binding,
    role: Role,
    /// Counted against its address (everything but accept legs).
    counted: bool,
}

#[derive(Clone, Debug)]
struct AllowSet {
    sequence: u64,
    callers: BTreeSet<[u8; 32]>,
    invitations: Vec<InvitationEntry>,
}

#[derive(Clone, Debug)]
struct Registration {
    conn: ConnId,
    key: PublicKey,
    allow: Option<AllowSet>,
    last_recv: Millis,
    last_sent: Millis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Call {
        caller: [u8; 32],
    },
    Join {
        expires_at: UnixTime,
        /// Peer bytes forwarded so far: caller → target, target → caller.
        sent: [u64; 2],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CircuitState {
    Waiting {
        accept_deadline: Millis,
    },
    Spliced {
        accept: ConnId,
        last_activity: Millis,
    },
}

#[derive(Clone, Debug)]
struct Circuit {
    handle: [u8; 32],
    registration_key: PublicKey,
    caller_conn: ConnId,
    kind: Kind,
    class: Class,
    state: CircuitState,
}

/// The relay's admission state machine.
pub struct Relay {
    config: RelayConfig,
    relay_id: RelayId,
    authorized: BTreeMap<[u8; 32], Option<UnixTime>>,
    codes: BTreeMap<[u8; 32], UnixTime>,
    conns: BTreeMap<ConnId, Conn>,
    per_ip: BTreeMap<IpKey, u32>,
    registrations: BTreeMap<[u8; 32], Registration>,
    circuits: BTreeMap<[u8; 16], Circuit>,
    stopped: bool,
    /// Hosted mode's admission tokens, leases and reports.
    hosted: Option<Hosted>,
}

impl core::fmt::Debug for Relay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relay")
            .field("relay_id", &self.relay_id)
            .field("connections", &self.conns.len())
            .field("registrations", &self.registrations.len())
            .field("circuits", &self.circuits.len())
            .finish_non_exhaustive()
    }
}

/// Aggregate counts, for logs (no identifiers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCounts {
    /// Open connections.
    pub connections: usize,
    /// Live registrations.
    pub registrations: usize,
    /// Circuits waiting for their accept leg.
    pub waiting: usize,
    /// Spliced circuits.
    pub spliced: usize,
    /// Authorized keys.
    pub authorized: usize,
}

impl Relay {
    /// A relay with its stored authorized list and enrollment codes.
    pub fn new(config: RelayConfig, authorized: &[AuthorizedKey], codes: &[EnrollCode]) -> Self {
        Self {
            relay_id: RelayId::of(&config.relay_key),
            config,
            authorized: authorized
                .iter()
                .map(|k| (k.fingerprint, k.drop_at))
                .collect(),
            codes: codes.iter().map(|c| (c.hash, c.expires_at)).collect(),
            conns: BTreeMap::new(),
            per_ip: BTreeMap::new(),
            registrations: BTreeMap::new(),
            circuits: BTreeMap::new(),
            stopped: false,
            hosted: None,
        }
    }

    /// A relay in hosted mode: no authorized list; targets register with
    /// admission tokens and circuits forward against leases. `hosted` must
    /// be for this relay and boot.
    pub fn new_hosted(config: RelayConfig, hosted: Hosted) -> Self {
        let mut relay = Self::new(config, &[], &[]);
        debug_assert_eq!(hosted.relay_id(), relay.relay_id.0);
        debug_assert_eq!(hosted.boot_id(), relay.config.boot_id);
        relay.hosted = Some(hosted);
        relay
    }

    /// The hosted state, in hosted mode.
    pub fn hosted(&self) -> Option<&Hosted> {
        self.hosted.as_ref()
    }

    /// The hosted state, in hosted mode: the relay's Plus link feeds Plus's
    /// answers in and takes report parts out.
    pub fn hosted_mut(&mut self) -> Option<&mut Hosted> {
        self.hosted.as_mut()
    }

    /// The mode in `RELAY_HELLO`.
    pub fn mode(&self) -> Mode {
        if self.hosted.is_some() {
            Mode::Hosted
        } else {
            Mode::SelfHosted
        }
    }

    /// Hosted: the earliest monotonic time a lease, refill or admission wait
    /// fires. Call [`Relay::tick`] then too.
    pub fn next_hosted_wake(&self, now: Now) -> Option<Millis> {
        self.hosted.as_ref().and_then(|h| h.next_wakeup(now))
    }

    /// The relay id.
    pub fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// The limits.
    pub fn limits(&self) -> &RelayLimits {
        &self.config.limits
    }

    /// Aggregate counts.
    pub fn counts(&self) -> RelayCounts {
        let spliced = self
            .circuits
            .values()
            .filter(|c| matches!(c.state, CircuitState::Spliced { .. }))
            .count();
        RelayCounts {
            connections: self.conns.len(),
            registrations: self.registrations.len(),
            waiting: self.circuits.len() - spliced,
            spliced,
            authorized: self.authorized.len(),
        }
    }

    /// The authorized list as the machine holds it, in order of
    /// fingerprint.
    pub fn authorized(&self) -> Vec<AuthorizedKey> {
        self.authorized
            .iter()
            .map(|(fp, drop_at)| AuthorizedKey {
                fingerprint: *fp,
                drop_at: *drop_at,
            })
            .collect()
    }

    /// The stored enrollment codes, in order of their hash.
    pub fn codes(&self) -> Vec<EnrollCode> {
        self.codes
            .iter()
            .map(|(hash, expires_at)| EnrollCode {
                hash: *hash,
                expires_at: *expires_at,
            })
            .collect()
    }

    /// Open connections counted against `ip`.
    pub fn connections_at(&self, ip: IpKey) -> u64 {
        u64::from(self.per_ip.get(&ip).copied().unwrap_or(0))
    }

    /// The earliest monotonic time a wait fires, if any. Wall-clock times
    /// (invitation expiries, key drops) are not included: call
    /// [`Relay::tick`] at least once a second as well.
    pub fn next_wake(&self) -> Option<Millis> {
        let l = &self.config.limits;
        let conns = self.conns.values().filter_map(|c| match c.role {
            Role::Fresh { hello_deadline } => Some(hello_deadline),
            Role::Refusing { deadline } => Some(deadline),
            _ => None,
        });
        let regs = self.registrations.values().flat_map(|r| {
            [
                r.last_recv.plus(l.registration_idle_ms()),
                r.last_sent.plus(l.keepalive_ms()),
            ]
        });
        let circuits = self.circuits.values().map(|c| match c.state {
            CircuitState::Waiting { accept_deadline } => accept_deadline,
            CircuitState::Spliced { last_activity, .. } => last_activity.plus(l.circuit_idle_ms()),
        });
        conns.chain(regs).chain(circuits).min()
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// A client finished its WebSocket upgrade on `conn`, from `ip`, with
    /// this outer exporter.
    pub fn open<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        ip: IpKey,
        exporter: [u8; 32],
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        let l = self.config.limits;
        let at_ip = self.per_ip.get(&ip).copied().unwrap_or(0);
        if self.stopped
            || self.conns.len() as u64 >= l.max_connections()
            || u64::from(at_ip) >= l.connections_per_ip()
        {
            out.push(Output::Close {
                conn,
                code: close::LIMIT,
            });
            return out;
        }
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        self.conns.insert(
            conn,
            Conn {
                ip,
                binding: Binding { nonce, exporter },
                role: Role::Fresh {
                    hello_deadline: now.mono.plus(l.hello_wait_ms()),
                },
                counted: true,
            },
        );
        *self.per_ip.entry(ip).or_insert(0) += 1;
        out.push(Output::Send {
            conn,
            message: RelayMessage::Hello {
                version: RELAY_VERSION,
                nonce,
                boot_id: self.config.boot_id,
                mode: self.mode(),
            }
            .encode(),
        });
        out
    }

    /// The client on `conn` sent a relay message (before splicing). On a
    /// spliced leg this is the same as [`Relay::data`].
    pub fn receive<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        bytes: &[u8],
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        let Some(role) = self.conns.get(&conn).map(|c| c.role) else {
            return out;
        };
        if let Some(true) = self.spliced_leg(conn) {
            out.extend(self.data_inner(conn, bytes.len(), now));
            self.fire_hosted(now, &mut out);
            return out;
        }
        let msg = match RelayMessage::decode(bytes) {
            Ok(m) if !m.from_relay() => m,
            _ => {
                self.protocol_error(conn, &mut out);
                return out;
            }
        };
        let hosted_mode = self.hosted.is_some();
        match role {
            Role::Fresh { .. } => match msg {
                RelayMessage::Register {
                    key,
                    proof,
                    hosted: None,
                } if !hosted_mode => self.register(conn, key, proof, now, &mut out),
                RelayMessage::Register {
                    key,
                    proof,
                    hosted: Some((token, threshold)),
                } if hosted_mode => {
                    self.register_hosted(conn, key, proof, &token, threshold, now, &mut out)
                }
                RelayMessage::Enroll { key, proof, code } if !hosted_mode => {
                    self.enroll(conn, key, proof, code, now, &mut out)
                }
                RelayMessage::Call {
                    handle,
                    key,
                    proof,
                    class,
                } => self.call(conn, handle, key, proof, class, now, rng, &mut out),
                RelayMessage::Join { handle, tag } => {
                    self.join(conn, handle, tag, now, rng, &mut out)
                }
                RelayMessage::Accept {
                    handle,
                    circuit,
                    proof,
                } => self.accept(conn, handle, circuit, proof, now, &mut out),
                _ => self.protocol_error(conn, &mut out),
            },
            Role::Registration { handle } => {
                if let Some(reg) = self.registrations.get_mut(&handle) {
                    reg.last_recv = now.mono;
                }
                match msg {
                    RelayMessage::AllowSet {
                        sequence,
                        callers,
                        invitations,
                    } => self.allow_set(handle, sequence, callers, invitations, now, &mut out),
                    RelayMessage::Promote { circuit, caller } => {
                        self.promote(handle, circuit, caller)
                    }
                    RelayMessage::Successor {
                        key,
                        new_proof,
                        current_proof,
                    } if !hosted_mode => {
                        self.successor(conn, handle, key, new_proof, current_proof, now, &mut out)
                    }
                    RelayMessage::Lease { block } if hosted_mode => {
                        self.lease(handle, &block, now, &mut out)
                    }
                    RelayMessage::Admit { token } if hosted_mode => {
                        // A refused ADMIT changes nothing: the registration
                        // keeps its token, and lives on while funded.
                        if let Some(h) = self.hosted.as_mut() {
                            let _ = h.admit(handle, &token, now);
                        }
                    }
                    RelayMessage::Release { leases } if hosted_mode => {
                        // A RELEASE naming another handle's lease changes
                        // nothing.
                        if let Some(h) = self.hosted.as_mut() {
                            let _ = h.release(handle, &leases, now);
                        }
                    }
                    RelayMessage::Ping { data } => {
                        self.send_registration(handle, RelayMessage::Pong { data }, now, &mut out)
                    }
                    RelayMessage::Pong { .. } => {}
                    _ => self.protocol_error(conn, &mut out),
                }
            }
            Role::Refusing { .. } | Role::Leg { .. } | Role::AcceptLeg { .. } => {
                self.protocol_error(conn, &mut out)
            }
        }
        self.fire_hosted(now, &mut out);
        out
    }

    /// The client on spliced leg `conn` sent a peer message of `len` bytes.
    pub fn data<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        len: usize,
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        if !self.conns.contains_key(&conn) {
            return out;
        }
        if self.spliced_leg(conn) != Some(true) {
            self.protocol_error(conn, &mut out);
            return out;
        }
        out.extend(self.data_inner(conn, len, now));
        self.fire_hosted(now, &mut out);
        out
    }

    /// The client closed `conn` (or it broke).
    pub fn closed<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        self.forget(conn, &mut out);
        self.fire_hosted(now, &mut out);
        out
    }

    /// Only time passed.
    pub fn tick<R: CryptoRng + ?Sized>(&mut self, now: Now, rng: &mut R) -> Vec<Output> {
        self.fire(now, rng)
    }

    /// The operator replaced the authorized list and the enrollment codes
    /// (`revoke`, `enroll` and edits read back from the state directory).
    /// Keys no longer listed lose their registration and every circuit of
    /// their handle (4000).
    pub fn replace_state<R: CryptoRng + ?Sized>(
        &mut self,
        authorized: &[AuthorizedKey],
        codes: &[EnrollCode],
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        let new: BTreeMap<[u8; 32], Option<UnixTime>> = authorized
            .iter()
            .map(|k| (k.fingerprint, k.drop_at))
            .collect();
        let gone: Vec<[u8; 32]> = self
            .authorized
            .keys()
            .filter(|fp| !new.contains_key(*fp))
            .copied()
            .collect();
        self.authorized = new;
        self.codes = codes.iter().map(|c| (c.hash, c.expires_at)).collect();
        for fp in gone {
            self.remove_target(&fp, &mut out);
        }
        out
    }

    /// The operator revoked one registration fingerprint.
    pub fn revoke<R: CryptoRng + ?Sized>(
        &mut self,
        fingerprint: &[u8; 32],
        now: Now,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut out = self.fire(now, rng);
        self.authorized.remove(fingerprint);
        self.remove_target(fingerprint, &mut out);
        out
    }

    /// Hosted: a graceful stop begins. Nothing more is forwarded and no
    /// `LEASE` is taken; every lease is final, and the stopping snapshot is
    /// taken for the Plus link to send (§A.9 duty 11). Call [`Relay::stop`]
    /// once it is stored or the final report wait has passed.
    pub fn begin_stop(&mut self, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        if let Some(h) = self.hosted.as_mut() {
            h.stop(now);
        }
        self.fire_hosted(now, &mut out);
        out
    }

    /// The relay stops: every circuit and connection closes with 4003.
    pub fn stop(&mut self) -> Vec<Output> {
        let mut out = Vec::new();
        self.stopped = true;
        let ids: Vec<[u8; 16]> = self.circuits_by_caller();
        for id in ids {
            self.close_circuit(&id, close::RELAY_STOPPING, &mut out);
        }
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in conns {
            self.close_conn(conn, close::RELAY_STOPPING, &mut out);
        }
        self.registrations.clear();
        out
    }

    // -----------------------------------------------------------------------
    // Timers (relay.md 6)
    // -----------------------------------------------------------------------

    /// Fire every wait due at or before `now`: monotonic waits in order of
    /// the time each fires, then of the rows of `relay.md` section 6, then
    /// of connection; then the wall-clock times.
    fn fire<R: CryptoRng + ?Sized>(&mut self, now: Now, rng: &mut R) -> Vec<Output> {
        let mut out = Vec::new();
        while let Some(at) = self.next_wake().filter(|t| *t <= now.mono) {
            self.fire_at(
                Now {
                    mono: at,
                    wall: now.wall,
                },
                rng,
                &mut out,
            );
        }
        self.fire_wall(now, &mut out);
        self.fire_hosted(now, &mut out);
        out
    }

    /// Fire the monotonic waits due at `now.mono` (none is due earlier).
    fn fire_at<R: CryptoRng + ?Sized>(&mut self, now: Now, rng: &mut R, out: &mut Vec<Output>) {
        let l = self.config.limits;
        // 1. First message.
        let due: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c.role, Role::Fresh { hello_deadline } if hello_deadline <= now.mono))
            .map(|(id, _)| *id)
            .collect();
        for conn in due {
            self.close_conn(conn, close::IDLE, out);
        }
        // 2. Refusal deadlines.
        let due: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c.role, Role::Refusing { deadline } if deadline <= now.mono))
            .map(|(id, _)| *id)
            .collect();
        for conn in due {
            self.unreachable(conn, out);
        }
        // 3. Accept waits.
        let due: Vec<[u8; 16]> = self
            .circuits_by_caller()
            .into_iter()
            .filter(|id| {
                matches!(self.circuits[id].state,
                    CircuitState::Waiting { accept_deadline } if accept_deadline <= now.mono)
            })
            .collect();
        for id in due {
            if let Some(c) = self.circuits.remove(&id) {
                self.unreachable(c.caller_conn, out);
            }
        }
        // 4. Registration idle.
        let due: Vec<[u8; 32]> = self
            .registrations_by_conn()
            .into_iter()
            .filter(|h| {
                self.registrations[h]
                    .last_recv
                    .plus(l.registration_idle_ms())
                    <= now.mono
            })
            .collect();
        for handle in due {
            if let Some(reg) = self.registrations.remove(&handle) {
                self.close_conn(reg.conn, close::IDLE, out);
                if let Some(h) = self.hosted.as_mut() {
                    h.unregister(&handle);
                }
            }
        }
        // 5. Keepalive.
        let due: Vec<[u8; 32]> = self
            .registrations_by_conn()
            .into_iter()
            .filter(|h| self.registrations[h].last_sent.plus(l.keepalive_ms()) <= now.mono)
            .collect();
        for handle in due {
            let mut data = [0u8; 8];
            rng.fill_bytes(&mut data);
            self.send_registration(handle, RelayMessage::Ping { data }, now, out);
        }
        // 6. Circuit idle.
        let due: Vec<[u8; 16]> = self
            .circuits_by_caller()
            .into_iter()
            .filter(|id| {
                matches!(self.circuits[id].state,
                    CircuitState::Spliced { last_activity, .. }
                        if last_activity.plus(l.circuit_idle_ms()) <= now.mono)
            })
            .collect();
        for id in due {
            self.close_circuit(&id, close::IDLE, out);
        }
    }

    /// Fire the wall-clock times due at `now.wall`.
    fn fire_wall(&mut self, now: Now, out: &mut Vec<Output>) {
        // 7. Join circuits at their invitation's expiry.
        let due: Vec<[u8; 16]> = self
            .circuits_by_caller()
            .into_iter()
            .filter(|id| {
                matches!(self.circuits[id].kind,
                    Kind::Join { expires_at, .. } if expires_at <= now.wall)
            })
            .collect();
        for id in due {
            self.close_circuit(&id, close::LIMIT, out);
        }
        // 8. Superseded keys at their drop time.
        let due: Vec<[u8; 32]> = self
            .authorized
            .iter()
            .filter(|(_, drop_at)| matches!(drop_at, Some(t) if *t <= now.wall))
            .map(|(fp, _)| *fp)
            .collect();
        for fp in due {
            self.authorized.remove(&fp);
            out.push(Output::Drop { fingerprint: fp });
            self.remove_target(&fp, out);
        }
    }

    // -----------------------------------------------------------------------
    // Registration (relay.md 7, 11)
    // -----------------------------------------------------------------------

    fn authorized_now(&self, fingerprint: &[u8; 32], now: Now) -> bool {
        match self.authorized.get(fingerprint) {
            Some(None) => true,
            Some(Some(drop_at)) => *drop_at > now.wall,
            None => false,
        }
    }

    fn registration_limit_reached(&self, handle: &[u8; 32]) -> bool {
        let others = self.registrations.keys().filter(|h| *h != handle).count() as u64;
        others >= self.config.limits.max_registrations()
    }

    fn register(
        &mut self,
        conn: ConnId,
        key: PublicKey,
        proof: crate::identity::RawSignature,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let binding = self.conns[&conn].binding;
        let handle = proof::handle(&self.relay_id, &key);
        let record = proof::register_record(&self.relay_id, &handle, &binding);
        if proof::verify(&key, &record, &proof).is_err()
            || !self.authorized_now(&key.fingerprint(), now)
        {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        }
        if self.registration_limit_reached(&handle) {
            return self.refuse(conn, RefuseReason::Limit, out);
        }
        self.install_registration(conn, handle, key, now, out);
    }

    fn enroll(
        &mut self,
        conn: ConnId,
        key: PublicKey,
        proof: crate::identity::RawSignature,
        code: [u8; 16],
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let binding = self.conns[&conn].binding;
        let handle = proof::handle(&self.relay_id, &key);
        let record = proof::register_record(&self.relay_id, &handle, &binding);
        if proof::verify(&key, &record, &proof).is_err() {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        }
        let hash = proof::code_hash(&code);
        if !matches!(self.codes.get(&hash), Some(expires) if *expires > now.wall) {
            return self.refuse(conn, RefuseReason::Enrollment, out);
        }
        if self.registration_limit_reached(&handle) {
            return self.refuse(conn, RefuseReason::Limit, out);
        }
        self.codes.remove(&hash);
        out.push(Output::ConsumeCode { hash });
        let fingerprint = key.fingerprint();
        if let std::collections::btree_map::Entry::Vacant(e) = self.authorized.entry(fingerprint) {
            e.insert(None);
            out.push(Output::Authorize { fingerprint });
        }
        self.install_registration(conn, handle, key, now, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn register_hosted(
        &mut self,
        conn: ConnId,
        key: PublicKey,
        proof: crate::identity::RawSignature,
        token: &[u8],
        threshold: u8,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let binding = self.conns[&conn].binding;
        let handle = proof::handle(&self.relay_id, &key);
        let record = proof::register_record(&self.relay_id, &handle, &binding);
        if proof::verify(&key, &record, &proof).is_err() {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        }
        if self.registration_limit_reached(&handle) {
            return self.refuse(conn, RefuseReason::Limit, out);
        }
        let admitted = match self.hosted.as_mut() {
            Some(h) => h.register(handle, token, Some(u64::from(threshold)), now),
            None => return self.protocol_error(conn, out),
        };
        if admitted.is_err() {
            return self.refuse(conn, RefuseReason::Admission, out);
        }
        self.install_registration(conn, handle, key, now, out);
    }

    /// Hosted: a `LEASE` on the registration of `handle`. Only a refusal is
    /// answered (`LEASE_STATUS` with state 3).
    fn lease(&mut self, handle: [u8; 32], block: &[u8], now: Now, out: &mut Vec<Output>) {
        let Some(h) = self.hosted.as_mut() else {
            return;
        };
        if let Err(refused) = h.lease(handle, block, now) {
            if let Some(status) = refused.status {
                self.send_registration(
                    handle,
                    RelayMessage::LeaseStatus {
                        entries: vec![status.into()],
                    },
                    now,
                    out,
                );
            }
        }
    }

    /// Hosted: carry out what the hosted state asks for (§B.10).
    fn fire_hosted(&mut self, now: Now, out: &mut Vec<Output>) {
        let Some(h) = self.hosted.as_mut() else {
            return;
        };
        for event in h.poll(now) {
            match event {
                relay_hosted::Event::Status { handle, entries } => self.send_registration(
                    handle,
                    RelayMessage::LeaseStatus {
                        entries: entries.into_iter().map(Into::into).collect(),
                    },
                    now,
                    out,
                ),
                relay_hosted::Event::Resumed { handle, class } => {
                    for id in self.circuits_of(&handle, Some(class)) {
                        if let CircuitState::Spliced { accept, .. } = self.circuits[&id].state {
                            out.push(Output::Resume {
                                conn: self.circuits[&id].caller_conn,
                            });
                            out.push(Output::Resume { conn: accept });
                        }
                    }
                }
                relay_hosted::Event::CloseClass {
                    handle,
                    class,
                    code,
                } => {
                    for id in self.circuits_of(&handle, Some(class)) {
                        self.close_circuit(&id, code, out);
                    }
                }
                relay_hosted::Event::CloseHandle { handle, code } => {
                    if let Some(reg) = self.registrations.remove(&handle) {
                        self.close_conn(reg.conn, code, out);
                    }
                    for id in self.circuits_of(&handle, None) {
                        self.close_circuit(&id, code, out);
                    }
                }
            }
        }
    }

    /// Circuits of `handle` (of `class`, if given), in order of their
    /// caller's connection.
    fn circuits_of(&self, handle: &[u8; 32], class: Option<Class>) -> Vec<[u8; 16]> {
        self.circuits_by_caller()
            .into_iter()
            .filter(|id| {
                let c = &self.circuits[id];
                c.handle == *handle && class.is_none_or(|k| c.class == k)
            })
            .collect()
    }

    fn install_registration(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        key: PublicKey,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        if let Some(old) = self.registrations.remove(&handle) {
            if old.conn != conn {
                self.close_conn(old.conn, close::REPLACED, out);
            }
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.role = Role::Registration { handle };
        }
        self.registrations.insert(
            handle,
            Registration {
                conn,
                key,
                allow: None,
                last_recv: now.mono,
                last_sent: now.mono,
            },
        );
        self.send_registration(handle, RelayMessage::Registered { handle }, now, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn successor(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        new_key: PublicKey,
        new_proof: crate::identity::RawSignature,
        current_proof: crate::identity::RawSignature,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let Some(reg) = self.registrations.get(&handle) else {
            return;
        };
        let current_key = reg.key;
        let current_fp = current_key.fingerprint();
        let binding = self.conns[&conn].binding;
        let record = proof::successor_record(
            &self.relay_id,
            &proof::handle(&self.relay_id, &new_key),
            &binding,
        );
        let new_ok = proof::verify(&new_key, &record, &new_proof).is_ok();
        // Must-fail control (phase3.relay-admission `successor-unchecked`):
        // the current key's proof is not checked.
        let current_ok = cfg!(mousse_control = "relay-successor-unchecked")
            || proof::verify(&current_key, &record, &current_proof).is_ok();
        let current_listed = matches!(self.authorized.get(&current_fp), Some(None));
        let new_fp = new_key.fingerprint();
        if !(new_ok && current_ok && current_listed) || self.authorized.contains_key(&new_fp) {
            self.registrations.remove(&handle);
            self.refuse(conn, RefuseReason::NotAuthorized, out);
            return;
        }
        self.authorized.insert(new_fp, None);
        out.push(Output::Authorize {
            fingerprint: new_fp,
        });
        let drop_at = now.wall.plus(self.config.limits.successor_overlap_secs());
        self.authorized.insert(current_fp, Some(drop_at));
        out.push(Output::Supersede {
            fingerprint: current_fp,
            drop_at,
        });
    }

    // -----------------------------------------------------------------------
    // Allow-sets (relay.md 8, 9.4)
    // -----------------------------------------------------------------------

    fn allow_set(
        &mut self,
        handle: [u8; 32],
        sequence: u64,
        callers: Vec<[u8; 32]>,
        invitations: Vec<InvitationEntry>,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let Some(reg) = self.registrations.get_mut(&handle) else {
            return;
        };
        if matches!(&reg.allow, Some(a) if sequence <= a.sequence) {
            return;
        }
        let callers: BTreeSet<[u8; 32]> = callers.into_iter().collect();
        let removed: Vec<[u8; 16]> = self
            .circuits_by_caller()
            .into_iter()
            .filter(|id| {
                let c = &self.circuits[id];
                c.handle == handle
                    && matches!(c.kind, Kind::Call { caller } if !callers.contains(&caller))
            })
            .collect();
        if let Some(reg) = self.registrations.get_mut(&handle) {
            reg.allow = Some(AllowSet {
                sequence,
                callers,
                invitations,
            });
        }
        for id in removed {
            self.close_circuit(&id, close::REMOVED, out);
        }
        self.send_registration(handle, RelayMessage::AllowSetOk { sequence }, now, out);
    }

    fn promote(&mut self, handle: [u8; 32], circuit: [u8; 16], caller: [u8; 32]) {
        let listed = self
            .registrations
            .get(&handle)
            .and_then(|r| r.allow.as_ref())
            .is_some_and(|a| a.callers.contains(&caller));
        if let Some(c) = self.circuits.get_mut(&circuit) {
            if listed
                && c.handle == handle
                && matches!(c.kind, Kind::Join { .. })
                && matches!(c.state, CircuitState::Spliced { .. })
            {
                c.kind = Kind::Call { caller };
            }
        }
    }

    // -----------------------------------------------------------------------
    // Calls and joins (relay.md 9)
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn call<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        key: PublicKey,
        proof: crate::identity::RawSignature,
        class: Class,
        now: Now,
        rng: &mut R,
        out: &mut Vec<Output>,
    ) {
        // The deadline is set before anything is looked up.
        let deadline = now.mono.plus(self.config.limits.refuse_ms());
        let binding = self.conns[&conn].binding;
        let caller = key.fingerprint();
        let record = proof::call_record(&self.relay_id, &handle, &binding, class);
        let proof_ok = proof::verify(&key, &record, &proof).is_ok();
        let allow = self
            .registrations
            .get(&handle)
            .and_then(|r| r.allow.as_ref());
        // Must-fail control (phase3.relay-admission `skip-allow-set`): any
        // caller of a registered handle is admitted.
        let listed = match allow {
            Some(a) => cfg!(mousse_control = "relay-skip-allow-set") || a.callers.contains(&caller),
            None => false,
        };
        let open = self
            .circuits
            .values()
            .filter(|c| c.handle == handle && c.kind_caller() == Some(caller))
            .count() as u64;
        let under_cap = open < self.config.limits.circuits_per_caller();
        // Hosted: the class needs a usable lease. Same answer, same time.
        let funded = self
            .hosted
            .as_mut()
            .is_none_or(|h| h.can_call(&handle, class, now));
        if proof_ok && listed && under_cap && funded {
            self.admit(conn, handle, Kind::Call { caller }, class, now, rng, out);
        } else {
            self.refused(conn, deadline, out);
        }
    }

    fn join<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        tag: [u8; 32],
        now: Now,
        rng: &mut R,
        out: &mut Vec<Output>,
    ) {
        let deadline = now.mono.plus(self.config.limits.refuse_ms());
        let hash = proof::tag_hash(&tag);
        let entry = self
            .registrations
            .get(&handle)
            .and_then(|r| r.allow.as_ref())
            .and_then(|a| a.invitations.iter().find(|i| i.tag_hash == hash))
            .filter(|i| UnixTime(i.expires_at) > now.wall)
            .copied();
        let joins = self
            .circuits
            .values()
            .filter(|c| c.handle == handle && matches!(c.kind, Kind::Join { .. }))
            .count() as u64;
        let under_cap = cfg!(mousse_control = "relay-no-preaccept-budget")
            || joins < self.config.limits.preaccept_per_target();
        // Hosted: pre-accept bytes are charged to the interactive lease.
        let funded = self
            .hosted
            .as_mut()
            .is_none_or(|h| h.can_call(&handle, Class::Interactive, now));
        match entry {
            Some(i) if under_cap && funded => self.admit(
                conn,
                handle,
                Kind::Join {
                    expires_at: UnixTime(i.expires_at),
                    sent: [0, 0],
                },
                Class::Interactive,
                now,
                rng,
                out,
            ),
            _ => self.refused(conn, deadline, out),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn admit<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        kind: Kind,
        class: Class,
        now: Now,
        rng: &mut R,
        out: &mut Vec<Output>,
    ) {
        let registration_key = self.registrations[&handle].key;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.circuits.insert(
            id,
            Circuit {
                handle,
                registration_key,
                caller_conn: conn,
                kind,
                class,
                state: CircuitState::Waiting {
                    accept_deadline: now.mono.plus(self.config.limits.accept_wait_ms()),
                },
            },
        );
        if let Some(c) = self.conns.get_mut(&conn) {
            c.role = Role::Leg { circuit: id };
        }
        let caller = match kind {
            Kind::Call { caller } => Some(caller),
            Kind::Join { .. } => None,
        };
        self.send_registration(
            handle,
            RelayMessage::Incoming {
                circuit: id,
                class,
                caller,
            },
            now,
            out,
        );
    }

    fn refused(&mut self, conn: ConnId, deadline: Millis, out: &mut Vec<Output>) {
        // Must-fail control (phase3.relay-admission `refuse-early`): a
        // refused call is answered at once.
        if cfg!(mousse_control = "relay-refuse-early") {
            self.unreachable(conn, out);
            return;
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.role = Role::Refusing { deadline };
        }
    }

    // -----------------------------------------------------------------------
    // Accept legs and splicing (relay.md 10)
    // -----------------------------------------------------------------------

    fn accept(
        &mut self,
        conn: ConnId,
        handle: [u8; 32],
        circuit: [u8; 16],
        proof: crate::identity::RawSignature,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        let binding = self.conns[&conn].binding;
        let Some(c) = self.circuits.get(&circuit) else {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        };
        if c.handle != handle || !matches!(c.state, CircuitState::Waiting { .. }) {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        }
        let record = proof::accept_record(&self.relay_id, &handle, &circuit, &binding);
        if proof::verify(&c.registration_key, &record, &proof).is_err() {
            return self.refuse(conn, RefuseReason::NotAuthorized, out);
        }
        let legs = self
            .circuits
            .values()
            .filter(|c| c.handle == handle && matches!(c.state, CircuitState::Spliced { .. }))
            .count() as u64;
        if legs >= self.config.limits.accept_legs_per_handle() {
            return self.refuse(conn, RefuseReason::Limit, out);
        }
        let caller = c.caller_conn;
        let class = c.class;
        if let Some(c) = self.circuits.get_mut(&circuit) {
            c.state = CircuitState::Spliced {
                accept: conn,
                last_activity: now.mono,
            };
        }
        self.uncount(conn);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.role = Role::AcceptLeg { circuit };
        }
        let spliced = RelayMessage::Spliced.encode();
        out.push(Output::Send {
            conn: caller,
            message: spliced.clone(),
        });
        out.push(Output::Send {
            conn,
            message: spliced,
        });
        out.push(Output::Splice {
            circuit,
            caller,
            target: conn,
            class,
        });
    }

    /// `Some(true)` for a leg of a spliced circuit, `Some(false)` for a known
    /// connection that is not one.
    fn spliced_leg(&self, conn: ConnId) -> Option<bool> {
        let c = self.conns.get(&conn)?;
        Some(match c.role {
            Role::Leg { circuit } => matches!(
                self.circuits.get(&circuit).map(|c| c.state),
                Some(CircuitState::Spliced { .. })
            ),
            Role::AcceptLeg { .. } => true,
            _ => false,
        })
    }

    fn data_inner(&mut self, conn: ConnId, len: usize, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        let (circuit, from_caller) = match self.conns[&conn].role {
            Role::Leg { circuit } => (circuit, true),
            Role::AcceptLeg { circuit } => (circuit, false),
            _ => return out,
        };
        let budget = self.config.limits.preaccept_bytes();
        let Some(c) = self.circuits.get(&circuit) else {
            return out;
        };
        let CircuitState::Spliced { accept, .. } = c.state else {
            return out;
        };
        let (handle, class, caller_conn) = (c.handle, c.class, c.caller_conn);
        let dir = usize::from(!from_caller);
        let join_total = match c.kind {
            Kind::Join { sent, .. } => Some(sent[dir].saturating_add(len as u64)),
            Kind::Call { .. } => None,
        };
        if let Some(total) = join_total {
            // Must-fail control (phase3.relay-limits `no-preaccept-budget`).
            if total > budget && !cfg!(mousse_control = "relay-no-preaccept-budget") {
                self.close_circuit(&circuit, close::LIMIT, &mut out);
                return out;
            }
        }
        // Hosted: count the message against the class's leases and its
        // rate group, or hold it.
        if let Some(h) = self.hosted.as_mut() {
            let direction = if from_caller {
                Direction::ToTarget
            } else {
                Direction::ToCaller
            };
            let mut socket = [0u8; 8];
            socket.copy_from_slice(&circuit[..8]);
            match h.forward(
                handle,
                class,
                u64::from_be_bytes(socket),
                direction,
                len as u64,
                now,
            ) {
                relay_hosted::Forward::Go => {}
                relay_hosted::Forward::Wait { until } => {
                    out.push(Output::Hold { conn, until });
                    return out;
                }
                relay_hosted::Forward::Paused => {
                    out.push(Output::Pause { conn });
                    return out;
                }
                relay_hosted::Forward::Stopped => return out,
            }
        }
        if let Some(c) = self.circuits.get_mut(&circuit) {
            if let (Kind::Join { sent, .. }, Some(total)) = (&mut c.kind, join_total) {
                sent[dir] = total;
            }
            c.state = CircuitState::Spliced {
                accept,
                last_activity: now.mono,
            };
        }
        let (from, to) = if from_caller {
            (caller_conn, accept)
        } else {
            (accept, caller_conn)
        };
        out.push(Output::Forward { from, to, len });
        out
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn send_registration(
        &mut self,
        handle: [u8; 32],
        message: RelayMessage,
        now: Now,
        out: &mut Vec<Output>,
    ) {
        if let Some(reg) = self.registrations.get_mut(&handle) {
            reg.last_sent = now.mono;
            out.push(Output::Send {
                conn: reg.conn,
                message: message.encode(),
            });
        }
    }

    fn refuse(&mut self, conn: ConnId, reason: RefuseReason, out: &mut Vec<Output>) {
        out.push(Output::Send {
            conn,
            message: RelayMessage::Refused { reason }.encode(),
        });
        self.close_conn(conn, close::NORMAL, out);
    }

    fn unreachable(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        if !self.conns.contains_key(&conn) {
            return;
        }
        out.push(Output::Send {
            conn,
            message: RelayMessage::Unreachable.encode(),
        });
        self.close_conn(conn, close::NORMAL, out);
    }

    fn uncount(&mut self, conn: ConnId) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if c.counted {
            c.counted = false;
            let ip = c.ip;
            if let Some(n) = self.per_ip.get_mut(&ip) {
                *n -= 1;
                if *n == 0 {
                    self.per_ip.remove(&ip);
                }
            }
        }
    }

    /// Close `conn` with `code` and forget it (only the connection).
    fn close_conn(&mut self, conn: ConnId, code: u16, out: &mut Vec<Output>) {
        if !self.conns.contains_key(&conn) {
            return;
        }
        self.uncount(conn);
        self.conns.remove(&conn);
        out.push(Output::Close { conn, code });
    }

    /// Close both legs of a circuit, the caller's first, and forget it.
    fn close_circuit(&mut self, id: &[u8; 16], code: u16, out: &mut Vec<Output>) {
        let Some(c) = self.circuits.remove(id) else {
            return;
        };
        self.close_conn(c.caller_conn, code, out);
        if let CircuitState::Spliced { accept, .. } = c.state {
            self.close_conn(accept, code, out);
        }
    }

    fn protocol_error(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        let Some(role) = self.conns.get(&conn).map(|c| c.role) else {
            return;
        };
        self.close_conn(conn, close::PROTOCOL, out);
        self.after_close(conn, role, out);
    }

    /// The client closed `conn`.
    fn forget(&mut self, conn: ConnId, out: &mut Vec<Output>) {
        let Some(role) = self.conns.get(&conn).map(|c| c.role) else {
            return;
        };
        self.uncount(conn);
        self.conns.remove(&conn);
        self.after_close(conn, role, out);
    }

    fn after_close(&mut self, conn: ConnId, role: Role, out: &mut Vec<Output>) {
        match role {
            Role::Fresh { .. } | Role::Refusing { .. } => {}
            Role::Registration { handle } => {
                if self
                    .registrations
                    .get(&handle)
                    .is_some_and(|r| r.conn == conn)
                {
                    self.registrations.remove(&handle);
                    if let Some(h) = self.hosted.as_mut() {
                        h.unregister(&handle);
                    }
                }
            }
            Role::Leg { circuit } | Role::AcceptLeg { circuit } => {
                if let Some(c) = self.circuits.remove(&circuit) {
                    self.close_conn(c.caller_conn, close::NORMAL, out);
                    if let CircuitState::Spliced { accept, .. } = c.state {
                        self.close_conn(accept, close::NORMAL, out);
                    }
                }
            }
        }
    }

    /// A key left the authorized list: close its registration and every
    /// circuit of its handle with 4000.
    fn remove_target(&mut self, fingerprint: &[u8; 32], out: &mut Vec<Output>) {
        let handles: Vec<[u8; 32]> = self
            .registrations
            .iter()
            .filter(|(_, r)| r.key.fingerprint() == *fingerprint)
            .map(|(h, _)| *h)
            .collect();
        for handle in handles {
            if let Some(reg) = self.registrations.remove(&handle) {
                self.close_conn(reg.conn, close::REMOVED, out);
            }
        }
        let circuits: Vec<[u8; 16]> = self
            .circuits_by_caller()
            .into_iter()
            .filter(|id| self.circuits[id].registration_key.fingerprint() == *fingerprint)
            .collect();
        for id in circuits {
            self.close_circuit(&id, close::REMOVED, out);
        }
    }

    /// Circuit ids in increasing order of their caller's connection.
    fn circuits_by_caller(&self) -> Vec<[u8; 16]> {
        let mut ids: Vec<(ConnId, [u8; 16])> = self
            .circuits
            .iter()
            .map(|(id, c)| (c.caller_conn, *id))
            .collect();
        ids.sort();
        ids.into_iter().map(|(_, id)| id).collect()
    }

    /// Handles in increasing order of their registration connection.
    fn registrations_by_conn(&self) -> Vec<[u8; 32]> {
        let mut hs: Vec<(ConnId, [u8; 32])> = self
            .registrations
            .iter()
            .map(|(h, r)| (r.conn, *h))
            .collect();
        hs.sort();
        hs.into_iter().map(|(_, h)| h).collect()
    }
}

impl Circuit {
    fn kind_caller(&self) -> Option<[u8; 32]> {
        match self.kind {
            Kind::Call { caller } => Some(caller),
            Kind::Join { .. } => None,
        }
    }
}
