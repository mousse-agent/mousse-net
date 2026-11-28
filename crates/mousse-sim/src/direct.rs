//! The `pairing-direct` drill: Pair with IP (`spec/wire.md` 10.9,
//! `docs/pair-with-ip-design.md` §1.4, §1.6). The host shows its address
//! and a 12-character code, the joiner's person types both, and the host
//! owner taps Allow.
//!
//! The host runs the core's [`DirectHostPairing`] with its [`GrantTable`]
//! (the grant store, which survives a restart) and a [`ConnectionGate`] per
//! connection. Each joiner runs one [`DirectJoinerPairing`] flow at a time,
//! with a [`CallerGate`] per connection and its own durable records: the
//! attempt ledger per typed lookup, the pending records and the pin. Both
//! sides start the real code exchange through [`CountingFactory`].
//!
//! Connections are reliable, ordered message pipes with a latency; TLS is
//! abstracted (step 1 shows each device's identity key, and the pair
//! exporter is derived from the connection number). A connection may break
//! after some messages, or on a scripted fault; each end learns of a break
//! on its own, and the host sometimes only at its idle timeout. The route
//! may go down for a while, and the host may restart (its invitations go,
//! its grant store stays).
//!
//! After every step the drill checks:
//!
//! - no grant made by a direct invitation exists for an identity the owner
//!   did not allow on it ([`Invariant::NoGrantWithoutAllow`]);
//! - every enrollment happens on a connection the host still has open,
//!   whose step 1 identity is the requesting one
//!   ([`Invariant::EnrollOnLiveConnection`]);
//! - every code attempt is debited before its code work, on the host per
//!   invitation and on the joiner per typed lookup, where the debit is
//!   stored before the first share goes out ([`Invariant::DebitBeforeWork`]);
//!   a debit is never returned and the limits hold ([`Invariant::AttemptCap`]);
//! - at most one enrollment per invitation ([`Invariant::SingleEnrollment`]);
//! - a joiner that ended its flow holds the host's pin exactly when the host
//!   holds a grant for it ([`Invariant::PairingAgreement`]);
//! - a joiner's cancel that crossed Allow leaves no grant
//!   ([`Invariant::CancelWins`]);
//! - stream traffic runs only under a live grant
//!   ([`Invariant::NoTrafficWithoutGrant`]).
//!
//! The devices' I/O layers are the drill's own; the planted bugs live there.
//!
//! [`DirectHostPairing`]: mousse_net_core::pairing::DirectHostPairing
//! [`DirectJoinerPairing`]: mousse_net_core::pairing::DirectJoinerPairing
//! [`GrantTable`]: mousse_net_core::grants::GrantTable
//! [`ConnectionGate`]: mousse_net_core::authz::ConnectionGate
//! [`CallerGate`]: mousse_net_core::authz::CallerGate

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use mousse_net_core::authz::{
    CallerGate, CallerTraffic, ConnectionGate, GateState, Traffic, Verdict,
};
use mousse_net_core::control::{AuthorizedState, ControlMessage, DIRECT_MINOR_VERSION};
use mousse_net_core::grants::{GrantEvent, GrantId, GrantTable, OwnerRef, Role};
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::pairing::{
    direct_invite_digest, AttemptId, DirectEnd, DirectHostAction, DirectHostPairing,
    DirectInvitationParams, DirectJoinerAction, DirectJoinerPairing, DirectJoinerState,
    DirectLedger, DirectLookup, DirectPaired, DirectPending, DirectRequestId, ExchangeRole,
    InvitationId, RequestDecision, DIRECT_CODE_ALPHABET,
};
use mousse_net_core::{ConnectionId, ErrorCode, Limits, Millis, UnixTime};
use sha2::{Digest, Sha256};

use crate::exchange::{contains, CountingFactory};
use crate::sim::Sim;
use crate::{Bug, Invariant};

pub(crate) const DIRECT_VARIANTS: &[&str] = &[
    "wrong-codes",
    "allow-connected",
    "allow-away",
    "cancel-crossing",
    "decline",
    "expiry",
    "faults",
    "host-restart",
    "race",
];

const WALL0: u64 = 1_790_000_000;
const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;
/// No run goes past this.
const END_MS: u64 = 3 * 60 * MIN;
const HOST_DEV: usize = 0;
const HOST_NAME: &str = "Desk";
/// The address the host shows and the person types.
const ADDRESS: &str = "192.168.1.20:47100";
/// A host that did not see a break learns of it here at the latest.
const IDLE_MS: u64 = 45 * SEC;
/// Recovery backoff while a pending record waits.
const RETRY_FIRST_MS: u64 = 2 * SEC;
const RETRY_MAX_MS: u64 = 60 * SEC;
/// A paired joiner tries this many times to open its first stream.
const STREAM_TRIES: u32 = 8;

type Factory = CountingFactory;

/// What a connection carries.
#[derive(Clone, Debug)]
enum Wire {
    /// The host's `HELLO`; it agrees on minor 4.
    Hello,
    /// An encoded control message.
    Control(Vec<u8>),
    /// A stream frame. The host's application answers each one with one.
    Stream,
    /// `GOAWAY(code)`; the sender has closed its end.
    GoAway(ErrorCode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Host,
    Joiner,
}

impl Side {
    fn idx(self) -> usize {
        match self {
            Side::Host => 0,
            Side::Joiner => 1,
        }
    }

    fn other(self) -> Side {
        match self {
            Side::Host => Side::Joiner,
            Side::Joiner => Side::Host,
        }
    }
}

struct Conn {
    joiner: usize,
    /// A paired joiner's ordinary connection, not a pairing flow's.
    ordinary: bool,
    /// Dialled pinned: a recovery, or an ordinary connection.
    pinned: bool,
    exporter: [u8; 32],
    latency: u64,
    up: bool,
    host_open: bool,
    joiner_open: bool,
    /// The host's pairing machine has heard this connection end.
    host_reported: bool,
    /// The connection breaks when it would carry more messages than this.
    break_after: Option<u32>,
    sent: u32,
    broken: bool,
    /// Last arrival time toward each side ([`Side::idx`]).
    arrival: [u64; 2],
    /// The joiner's gate.
    gate: CallerGate,
}

enum Ev {
    DialDone(ConnectionId),
    Arrive {
        conn: ConnectionId,
        to: Side,
        wire: Wire,
    },
    /// `to` learns that the connection broke.
    Reset {
        conn: ConnectionId,
        to: Side,
    },
    /// The host's miss hold is over.
    MissClose(ConnectionId),
    /// The joiner's wait for the answer to `JOIN_DIRECT` is over.
    AnswerDue(ConnectionId),
    /// The person types the current code and taps Connect.
    Connect(usize),
    /// A flow that is away tries again.
    Retry(usize),
    /// The person cancels.
    Cancel(usize),
    /// The owner answers a prompt.
    Owner,
    /// The joiner's current connection breaks.
    Break(usize),
    HostDown(u64),
    HostUp,
    Route(bool),
    /// A paired joiner opens its first stream.
    Stream(usize),
    /// `direct-debit-after-send`: a ledger write the joiner's I/O already
    /// acknowledged reaches the store.
    LedgerLate(usize, DirectLedger),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Allow,
    Decline,
    CancelInvitation,
    Never,
}

/// The seeded scenario.
struct Plan {
    answer: Answer,
    /// How long after the first prompt the owner answers.
    owner_delay: (u64, u64),
    owner_scheduled: bool,
    /// The joiner's connection breaks this long after its code passed.
    break_after_pass: Option<u64>,
    /// The person cancels this long after the code passed.
    cancel_after_pass: Option<u64>,
    /// The route goes down this long after the code passed, for this long.
    route_down_after_pass: Option<(u64, u64)>,
    /// Chance (per mille) that a new connection breaks after a few messages.
    drop_permille: u32,
    /// Chance (per mille) that the host learns of a break only at its idle
    /// timeout.
    half_open_permille: u32,
    /// The host restarts soon after the owner's Allow.
    restart_after_allow: bool,
    latency: (u64, u64),
}

/// A code the person types.
#[derive(Clone)]
struct Typed {
    text: String,
    /// "the right code", "a wrong code", "a wrong lookup": for the log, which
    /// never shows a code.
    what: &'static str,
}

struct Joiner {
    name: &'static str,
    dev: usize,
    key: IdentityPublicKey,
    skew: i64,
    flow: Option<DirectJoinerPairing<Factory>>,
    flows: u64,
    conn: Option<ConnectionId>,
    dialing: Option<ConnectionId>,
    // Durable records.
    ledgers: BTreeMap<String, DirectLedger>,
    pending: Vec<DirectPending>,
    pin: Option<DirectPaired>,
    // What the checks need.
    /// The last ledger the current flow asked to store.
    ledger_asked: Option<DirectLedger>,
    debits_asked: u64,
    shares_sent: BTreeSet<AttemptId>,
    /// The person cancelled after the code passed.
    cancelled: bool,
    passed_once: bool,
    stream_ok: bool,
    stream_tries: u32,
    retry_ms: u64,
    retry_due: bool,
    // The person.
    codes: VecDeque<Typed>,
    current: Option<Typed>,
    retries: u32,
    gap: (u64, u64),
}

struct Host {
    key: IdentityPublicKey,
    pairing: Option<DirectHostPairing<Factory>>,
    instance: u64,
    grants: GrantTable,
    gates: BTreeMap<ConnectionId, ConnectionGate>,
    invitation: InvitationId,
    digest: [u8; 32],
    cap: u8,
    /// Attempts left on the invitation, as last reported.
    left: u8,
    prompted: BTreeSet<IdentityPublicKey>,
    /// (invitation, identity) the owner tapped Allow for.
    allowed: BTreeSet<(InvitationId, IdentityPublicKey)>,
    /// Connections the machine enrolled on, and the grant.
    enrolled: BTreeMap<ConnectionId, GrantId>,
    /// The host's timers run no earlier than this.
    tick_floor: u64,
}

struct Drive<'a> {
    sim: &'a mut Sim,
    variant: &'static str,
    plan: Plan,
    limits: Limits,
    host: Host,
    joiners: Vec<Joiner>,
    conns: BTreeMap<ConnectionId, Conn>,
    next_conn: u64,
    queue: BTreeMap<(u64, u64), Ev>,
    seq: u64,
    route_down: bool,
}

fn message_name(m: &ControlMessage) -> String {
    match m {
        ControlMessage::Hello { .. } => "HELLO".into(),
        ControlMessage::Authorized { state } => format!("AUTHORIZED {state:?}"),
        ControlMessage::AuthorizedDirect { not_received, .. } => format!(
            "AUTHORIZED join-only{}",
            if *not_received { " not-received" } else { "" }
        ),
        ControlMessage::JoinDirect { recovery, .. } => match recovery {
            Some(r) if r.cancel => "JOIN_DIRECT recovery+cancel".into(),
            Some(_) => "JOIN_DIRECT recovery".into(),
            None => "JOIN_DIRECT".into(),
        },
        ControlMessage::CodeExchange { .. } => "CODE_EXCHANGE".into(),
        ControlMessage::CodeAbort { code, .. } => format!("CODE_ABORT {}", code.name()),
        ControlMessage::Paired { role, .. } => format!("PAIRED {}", role.as_str()),
        _ => "control".into(),
    }
}

fn end_name(end: DirectEnd) -> String {
    match end {
        DirectEnd::Closed(Some(code)) => format!("closed {}", code.name()),
        DirectEnd::Closed(None) => "closed (broken)".into(),
        other => format!("{other:?}"),
    }
}

/// `n` characters drawn from the code alphabet.
fn draw(sim: &mut Sim, n: usize) -> String {
    (0..n)
        .map(|_| char::from(DIRECT_CODE_ALPHABET[sim.range(0, 31) as usize]))
        .collect()
}

/// How the person types `code`: as shown, plain, lower case or with spaces.
fn typed_form(sim: &mut Sim, code: &str) -> String {
    match sim.range(0, 3) {
        0 => format!("{}-{}-{}", &code[..4], &code[4..8], &code[8..]),
        1 => code.to_owned(),
        2 => code.to_ascii_lowercase(),
        _ => format!("{} {} {}", &code[..4], &code[4..8], &code[8..]),
    }
}

impl<'a> Drive<'a> {
    fn failed(&self) -> bool {
        self.sim.check.violation.is_some()
    }

    fn schedule(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.queue.insert((at.max(self.sim.now), self.seq), ev);
    }

    fn after(&mut self, delay: u64, ev: Ev) {
        self.schedule(self.sim.now + delay, ev);
    }

    fn host_now(&self) -> UnixTime {
        UnixTime(WALL0 + self.sim.now / SEC)
    }

    fn joiner_now(&self, j: usize) -> UnixTime {
        UnixTime(WALL0.saturating_add_signed(self.joiners[j].skew) + self.sim.now / SEC)
    }

    fn note(&mut self, actor: &str, args: std::fmt::Arguments<'_>) {
        self.sim.note(actor, args);
    }

    // ---- the loop ---------------------------------------------------------

    /// When the host's timers next have something to do.
    fn host_due(&self) -> Option<u64> {
        let deadline = self.host.pairing.as_ref()?.next_deadline()?;
        let at = deadline.0.saturating_sub(WALL0).saturating_mul(SEC);
        Some(at.max(self.host.tick_floor).max(self.sim.now))
    }

    fn run(&mut self) {
        loop {
            if self.failed() {
                return;
            }
            let next = self.queue.first_key_value().map(|(k, _)| k.0);
            let due = self.host_due();
            let t = match (next, due) {
                (None, None) => break,
                (Some(a), Some(b)) => a.min(b),
                (a, b) => a.or(b).unwrap_or(END_MS),
            };
            if t > END_MS {
                self.sim.now = END_MS;
                break;
            }
            self.sim.now = t;
            self.sim.events += 1;
            if due == Some(t) {
                self.host_tick();
                continue;
            }
            if let Some((_, ev)) = self.queue.pop_first() {
                self.dispatch(ev);
            }
        }
    }

    fn host_tick(&mut self) {
        let now = self.host_now();
        self.host.tick_floor = (self.sim.now / SEC + 1) * SEC;
        let Some(pairing) = self.host.pairing.as_mut() else {
            return;
        };
        let actions = pairing.tick(now);
        self.host_did(actions);
    }

    fn dispatch(&mut self, ev: Ev) {
        match ev {
            Ev::DialDone(conn) => self.dial_done(conn),
            Ev::Arrive { conn, to, wire } => {
                let Some(c) = self.conns.get(&conn) else {
                    return;
                };
                match to {
                    Side::Host if c.host_open => self.host_receive(conn, wire),
                    Side::Joiner if c.joiner_open => self.joiner_receive(conn, wire),
                    _ => {}
                }
            }
            Ev::Reset { conn, to } => self.reset(conn, to),
            Ev::MissClose(conn) => self.host_close(conn, ErrorCode::InvitationInvalid),
            Ev::AnswerDue(conn) => {
                let j = self.conns.get(&conn).map(|c| c.joiner);
                if let Some(j) = j.filter(|&j| self.joiners[j].conn == Some(conn)) {
                    let actions = self.joiners[j]
                        .flow
                        .as_mut()
                        .map(|f| f.on_answer_timeout())
                        .unwrap_or_default();
                    self.joiner_did(j, actions);
                }
            }
            Ev::Connect(j) => self.connect(j),
            Ev::Retry(j) => {
                self.joiners[j].retry_due = false;
                let actions = match self.joiners[j].flow.as_mut() {
                    Some(f) if f.state() == DirectJoinerState::Away => f.start(),
                    _ => Vec::new(),
                };
                self.joiner_did(j, actions);
            }
            Ev::Cancel(j) => self.cancel(j),
            Ev::Owner => self.owner(),
            Ev::Break(j) => {
                if let Some(conn) = self.joiners[j].conn {
                    let name = self.joiners[j].name;
                    self.note("net", format_args!("{name}'s conn {} breaks", conn.0));
                    self.break_conn(conn);
                }
            }
            Ev::HostDown(down) => self.host_down(down),
            Ev::HostUp => self.host_up(),
            Ev::Route(down) => self.set_route(down),
            Ev::Stream(j) => self.open_stream(j),
            Ev::LedgerLate(j, record) => {
                let key = record.lookup.as_str().to_owned();
                self.joiners[j].ledgers.insert(key, record);
            }
        }
    }

    // ---- network ------------------------------------------------------------

    fn dial(&mut self, j: usize, ordinary: bool) {
        let conn = ConnectionId(self.next_conn);
        self.next_conn += 1;
        let latency = self.sim.range(self.plan.latency.0, self.plan.latency.1);
        let break_after = self
            .sim
            .chance(self.plan.drop_permille)
            .then(|| self.sim.range(0, 10) as u32);
        let exporter: [u8; 32] = Sha256::new()
            .chain_update(b"mousse-sim pair exporter")
            .chain_update(conn.0.to_be_bytes())
            .finalize()
            .into();
        let pinned = ordinary
            || self.joiners[j]
                .flow
                .as_ref()
                .is_some_and(|f| f.pinned_host().is_some());
        self.conns.insert(
            conn,
            Conn {
                joiner: j,
                ordinary,
                pinned,
                exporter,
                latency,
                up: false,
                host_open: false,
                joiner_open: false,
                host_reported: false,
                break_after,
                sent: 0,
                broken: false,
                arrival: [0, 0],
                gate: CallerGate::new(),
            },
        );
        if !ordinary {
            self.joiners[j].dialing = Some(conn);
        }
        let name = self.joiners[j].name;
        self.note(
            name,
            format_args!(
                "dials {ADDRESS}{} as conn {}",
                if pinned { " pinned" } else { "" },
                conn.0
            ),
        );
        let handshake = 3 * latency + self.sim.range(0, latency);
        self.after(handshake.max(1), Ev::DialDone(conn));
    }

    fn dial_done(&mut self, conn: ConnectionId) {
        let Some(c) = self.conns.get(&conn) else {
            return;
        };
        let (j, ordinary, pinned, exporter) = (c.joiner, c.ordinary, c.pinned, c.exporter);
        let refused = self.route_down || self.host.pairing.is_none();
        let name = self.joiners[j].name;
        if ordinary {
            if refused {
                self.note(name, format_args!("conn {} failed to connect", conn.0));
                self.conns.remove(&conn);
                return;
            }
            self.open_pipe(conn);
            self.host_accept(conn);
            self.note(name, format_args!("opens a stream on conn {}", conn.0));
            self.transmit(conn, Side::Joiner, Wire::Stream);
            return;
        }
        let wanted = self.joiners[j].dialing == Some(conn)
            && self.joiners[j]
                .flow
                .as_ref()
                .is_some_and(|f| f.state() == DirectJoinerState::Connecting);
        if self.joiners[j].dialing == Some(conn) {
            self.joiners[j].dialing = None;
        }
        if !wanted {
            // The flow moved on while the dial was out: unused.
            self.conns.remove(&conn);
            return;
        }
        if refused {
            self.conns.remove(&conn);
            self.note(name, format_args!("conn {} failed to connect", conn.0));
            let actions = self.joiners[j]
                .flow
                .as_mut()
                .map(|f| f.on_dial_failed())
                .unwrap_or_default();
            self.joiner_did(j, actions);
            return;
        }
        self.open_pipe(conn);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.gate = if pinned {
                CallerGate::new()
            } else {
                CallerGate::pairing_only()
            };
        }
        self.joiners[j].conn = Some(conn);
        self.host_accept(conn);
        let host_key = self.host.key;
        let actions = self.joiners[j]
            .flow
            .as_mut()
            .map(|f| f.on_connected(host_key, exporter))
            .unwrap_or_default();
        self.joiner_did(j, actions);
    }

    fn open_pipe(&mut self, conn: ConnectionId) {
        if let Some(c) = self.conns.get_mut(&conn) {
            c.up = true;
            c.host_open = true;
            c.joiner_open = true;
        }
    }

    fn transmit(&mut self, conn: ConnectionId, from: Side, wire: Wire) {
        let Some(c) = self.conns.get(&conn) else {
            return;
        };
        let open = match from {
            Side::Host => c.host_open,
            Side::Joiner => c.joiner_open,
        };
        if !open || !c.up || c.broken {
            return;
        }
        let latency = c.latency;
        let jitter = self.sim.range(0, latency / 4);
        let now = self.sim.now;
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        c.sent += 1;
        if c.break_after.is_some_and(|n| c.sent > n) {
            self.note("net", format_args!("conn {} breaks", conn.0));
            self.break_conn(conn);
            return;
        }
        let to = from.other();
        let arrival = c.arrival[to.idx()].max(now + latency + jitter);
        c.arrival[to.idx()] = arrival;
        self.schedule(arrival, Ev::Arrive { conn, to, wire });
    }

    /// The connection breaks: what is on its way still arrives, then each
    /// open end learns of the break on its own.
    fn break_conn(&mut self, conn: ConnectionId) {
        let half_open = self.sim.chance(self.plan.half_open_permille);
        let Some(c) = self.conns.get(&conn) else {
            return;
        };
        if c.broken || !c.up {
            return;
        }
        let latency = c.latency;
        let joiner_at = c.arrival[Side::Joiner.idx()].max(self.sim.now + latency);
        let host_at = if half_open {
            self.sim.now + self.sim.range(latency, IDLE_MS)
        } else {
            self.sim.now + latency
        }
        .max(c.arrival[Side::Host.idx()]);
        let (host_open, joiner_open) = (c.host_open, c.joiner_open);
        if let Some(c) = self.conns.get_mut(&conn) {
            c.broken = true;
        }
        if joiner_open {
            self.schedule(
                joiner_at,
                Ev::Reset {
                    conn,
                    to: Side::Joiner,
                },
            );
        }
        if host_open {
            self.schedule(
                host_at,
                Ev::Reset {
                    conn,
                    to: Side::Host,
                },
            );
        }
    }

    fn reset(&mut self, conn: ConnectionId, to: Side) {
        let Some(c) = self.conns.get(&conn) else {
            return;
        };
        match to {
            Side::Host if c.host_open => {
                self.note("host", format_args!("conn {} broke", conn.0));
                self.host_ended(conn, None);
            }
            Side::Joiner if c.joiner_open => {
                let (j, ordinary) = (c.joiner, c.ordinary);
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.joiner_open = false;
                }
                if ordinary {
                    return;
                }
                if self.joiners[j].conn == Some(conn) {
                    self.joiners[j].conn = None;
                    let name = self.joiners[j].name;
                    self.note(name, format_args!("conn {} broke", conn.0));
                    let actions = self.joiners[j]
                        .flow
                        .as_mut()
                        .map(|f| f.on_closed(None))
                        .unwrap_or_default();
                    self.joiner_did(j, actions);
                }
            }
            _ => {}
        }
    }

    fn set_route(&mut self, down: bool) {
        self.route_down = down;
        self.note(
            "net",
            format_args!("the route is {}", if down { "down" } else { "up" }),
        );
        if down {
            let up: Vec<ConnectionId> = self
                .conns
                .iter()
                .filter(|(_, c)| c.up && !c.broken)
                .map(|(id, _)| *id)
                .collect();
            for conn in up {
                self.break_conn(conn);
            }
        }
    }

    // ---- the host -------------------------------------------------------------

    fn host_accept(&mut self, conn: ConnectionId) {
        let j = self.conns[&conn].joiner;
        let key = self.joiners[j].key;
        let now = self.host_now();
        let gate =
            ConnectionGate::open(conn, key, &mut self.host.grants, now, Millis(self.sim.now));
        let state = gate.state().clone();
        self.host.gates.insert(conn, gate);
        self.transmit(conn, Side::Host, Wire::Hello);
        match state {
            GateState::Live { .. } => {
                let m = ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                };
                self.host_send(conn, &m);
            }
            GateState::Closed(code) => self.host_close(conn, code),
            _ => {}
        }
    }

    fn host_send(&mut self, conn: ConnectionId, message: &ControlMessage) {
        let name = message_name(message);
        self.note("host", format_args!("sends {name} on conn {}", conn.0));
        self.transmit(conn, Side::Host, Wire::Control(message.encode()));
    }

    /// The host closes its end with `GOAWAY(code)`.
    fn host_close(&mut self, conn: ConnectionId, code: ErrorCode) {
        if !self.conns.get(&conn).is_some_and(|c| c.host_open) {
            return;
        }
        self.note(
            "host",
            format_args!("closes conn {} with {}", conn.0, code.name()),
        );
        self.transmit(conn, Side::Host, Wire::GoAway(code));
        self.host_ended(conn, None);
    }

    /// The host's end of `conn` is gone: the peer's `GOAWAY` (`code`), a
    /// break, or the host's own close.
    fn host_ended(&mut self, conn: ConnectionId, code: Option<ErrorCode>) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        c.host_open = false;
        let report = !std::mem::replace(&mut c.host_reported, true);
        let broke = code.is_none() && c.broken;
        self.host.gates.remove(&conn);
        self.host.grants.unbind(conn);
        if !report {
            return;
        }
        let now = self.host_now();
        let Some(pairing) = self.host.pairing.as_mut() else {
            return;
        };
        // `direct-lost-close`: the I/O layer never tells the pairing machine
        // that a pairing connection broke.
        if self.sim.cfg.bug == Some(Bug::DirectLostClose)
            && broke
            && pairing.invitation_for(conn).is_some()
        {
            return;
        }
        // `direct-drop-cancel`: the peer's GOAWAY code is lost.
        let told = if self.sim.cfg.bug == Some(Bug::DirectDropCancel) {
            None
        } else {
            code
        };
        let actions = pairing.on_connection_closed(conn, told, &mut self.host.grants, now);
        self.host_did(actions);
    }

    fn host_receive(&mut self, conn: ConnectionId, wire: Wire) {
        let j = self.conns[&conn].joiner;
        match wire {
            Wire::Hello => {}
            Wire::GoAway(code) => {
                self.note(
                    "host",
                    format_args!("conn {} closed by the peer with {}", conn.0, code.name()),
                );
                self.host_ended(conn, Some(code));
                if code == ErrorCode::Cancelled {
                    self.check_cancel_on(conn, j);
                }
            }
            Wire::Stream => self.host_stream(conn, j),
            Wire::Control(bytes) => {
                let Ok(message) = ControlMessage::decode_at(&bytes, DIRECT_MINOR_VERSION) else {
                    self.host_close(conn, ErrorCode::ProtocolError);
                    return;
                };
                let Some(gate) = self.host.gates.get_mut(&conn) else {
                    return;
                };
                // `direct-drop-cancel`: the gate's one exception for a
                // cancel on an enrolled connection is not asked.
                let verdict = if self.sim.cfg.bug == Some(Bug::DirectDropCancel) {
                    gate.check(Traffic::of(&message))
                } else {
                    gate.check_message(&message)
                };
                let name = message_name(&message);
                match verdict {
                    Verdict::Allow => {}
                    Verdict::Close(code) => {
                        self.note(
                            "host",
                            format_args!("gate refuses {name} on conn {}", conn.0),
                        );
                        self.host_close(conn, code);
                        return;
                    }
                    _ => {
                        self.note("host", format_args!("gate drops {name} on conn {}", conn.0));
                        return;
                    }
                }
                self.note("host", format_args!("got {name} on conn {}", conn.0));
                self.host_message(conn, j, message);
            }
        }
    }

    fn host_message(&mut self, conn: ConnectionId, j: usize, message: ControlMessage) {
        let now = self.host_now();
        let key = self.joiners[j].key;
        let exporter = self.conns[&conn].exporter;
        let Some(pairing) = self.host.pairing.as_mut() else {
            return;
        };
        let mut abort_cancel = false;
        let mut recovery_cancel = false;
        let mut exchange = false;
        let actions = match message {
            ControlMessage::JoinDirect {
                lookup,
                name,
                recovery,
            } => {
                recovery_cancel = recovery.is_some_and(|r| r.cancel);
                pairing.on_join_direct(
                    conn,
                    &key,
                    &exporter,
                    &lookup,
                    &name,
                    recovery,
                    &mut self.host.grants,
                    now,
                )
            }
            ControlMessage::CodeExchange { attempt, payload } => {
                exchange = true;
                pairing.on_code_exchange(conn, attempt, &payload, now, &mut self.sim.rng)
            }
            ControlMessage::CodeAbort { attempt, code } => {
                abort_cancel = code == ErrorCode::Cancelled;
                pairing.on_code_abort(conn, attempt, code, &mut self.host.grants, now)
            }
            _ => Vec::new(),
        };
        self.host_did(actions);
        if exchange {
            self.check_host_work();
        }
        if abort_cancel {
            self.check_cancel_on(conn, j);
        }
        if recovery_cancel {
            self.check_recovery_cancel(j);
        }
    }

    fn host_stream(&mut self, conn: ConnectionId, j: usize) {
        let now = self.host_now();
        let Some(gate) = self.host.gates.get_mut(&conn) else {
            return;
        };
        let mut verdict = gate.check(Traffic::Stream);
        if let Verdict::Commit(grant) = verdict {
            let Some(pairing) = self.host.pairing.as_mut() else {
                return;
            };
            let actions = pairing.on_first_stream(conn, grant, &mut self.host.grants, now);
            self.host_did(actions);
            verdict = match self.host.gates.get_mut(&conn) {
                Some(gate) => gate.check(Traffic::Stream),
                None => Verdict::Ignore,
            };
        }
        match verdict {
            Verdict::Allow => {
                let key = self.joiners[j].key;
                let bound = self.host.grants.binding(conn);
                let live = self
                    .host
                    .grants
                    .live_grant(&key, now)
                    .is_some_and(|g| Some(g.id) == bound);
                if !live {
                    let name = self.joiners[j].name;
                    self.sim.fail(
                        Invariant::NoTrafficWithoutGrant,
                        format!(
                            "the host runs a stream of {name} on conn {} with no live grant bound",
                            conn.0
                        ),
                    );
                    return;
                }
                self.note("host", format_args!("serves a stream on conn {}", conn.0));
                self.transmit(conn, Side::Host, Wire::Stream);
            }
            Verdict::Close(code) => self.host_close(conn, code),
            _ => {}
        }
    }

    fn host_did(&mut self, actions: Vec<DirectHostAction>) {
        for action in actions {
            if self.failed() {
                return;
            }
            match action {
                DirectHostAction::Send { conn, message } => self.host_send(conn, &message),
                DirectHostAction::Close { conn, code } => self.host_close(conn, code),
                DirectHostAction::MissHold { conn, hold_ms } => {
                    if let Some(gate) = self.host.gates.get_mut(&conn) {
                        gate.hold();
                    }
                    self.note(
                        "host",
                        format_args!("finds nothing for conn {}; holds it {hold_ms} ms", conn.0),
                    );
                    self.after(hold_ms, Ev::MissClose(conn));
                }
                DirectHostAction::AdmittedJoinOnly { conn, invitation } => {
                    if let Some(gate) = self.host.gates.get_mut(&conn) {
                        gate.admit_join_only(invitation);
                    }
                }
                DirectHostAction::AttemptsLeft {
                    invitation,
                    attempts_left,
                } => {
                    if invitation == self.host.invitation {
                        if attempts_left.saturating_add(1) != self.host.left {
                            self.sim.fail(
                                Invariant::AttemptCap,
                                format!(
                                    "the invitation's attempts left went from {} to {attempts_left}",
                                    self.host.left
                                ),
                            );
                        }
                        self.host.left = attempts_left;
                    }
                    self.note(
                        "host",
                        format_args!("debits an attempt: {attempts_left} left"),
                    );
                }
                DirectHostAction::Approval(a) => {
                    let who = self.who(&a.request.identity);
                    self.note(
                        "host",
                        format_args!(
                            "prompt: allow {who}? {:?}, {:?}, answer by {}",
                            a.presence,
                            a.decision,
                            a.answer_by.0 - WALL0
                        ),
                    );
                    if self.sim.cfg.bug == Some(Bug::DirectAutoAllow)
                        && a.decision == RequestDecision::Pending
                    {
                        // `direct-auto-allow`: the I/O layer answers the
                        // prompt itself.
                        self.allow(a.request, false);
                    }
                    if self.host.prompted.insert(a.request.identity) {
                        self.schedule_owner();
                    }
                }
                DirectHostAction::ApprovalEnded { request, reason } => {
                    let who = self.who(&request.identity);
                    self.note("host", format_args!("prompt for {who} ends: {reason:?}"));
                }
                DirectHostAction::Enrolled {
                    invitation,
                    conn,
                    grant,
                    identity,
                    attempt,
                    ..
                } => {
                    self.on_enrolled(invitation, conn, grant, identity);
                    if let Some(gate) = self.host.gates.get_mut(&conn) {
                        gate.bind_direct(grant, true, attempt);
                    }
                    self.host.enrolled.insert(conn, grant);
                }
                DirectHostAction::Bound {
                    conn,
                    grant,
                    provisional,
                } => {
                    if let Some(gate) = self.host.gates.get_mut(&conn) {
                        gate.bind_direct(grant, provisional, None);
                    }
                    self.note(
                        "host",
                        format_args!("binds conn {} to grant {}", conn.0, grant.0),
                    );
                }
                DirectHostAction::Committed {
                    conn, grant, bound, ..
                } => {
                    for b in bound {
                        if let Some(gate) = self.host.gates.get_mut(&b) {
                            gate.committed();
                        }
                    }
                    self.note(
                        "host",
                        format_args!("grant {} commits on conn {}", grant.0, conn.0),
                    );
                }
                DirectHostAction::EnrollmentUndone {
                    grant, identity, ..
                } => {
                    let who = self.who(&identity);
                    self.note(
                        "host",
                        format_args!("removes {who}'s provisional grant {}", grant.0),
                    );
                }
                DirectHostAction::InvitationEnded { reason, .. } => {
                    self.note(
                        "host",
                        format_args!("the invitation ends: {}", reason.name()),
                    );
                }
                DirectHostAction::Grant(GrantEvent::CloseChannels { channels, code, .. }) => {
                    for c in channels {
                        self.host_close(c, code);
                    }
                }
            }
        }
        self.check_grants();
    }

    fn who(&self, identity: &IdentityPublicKey) -> &'static str {
        self.joiners
            .iter()
            .find(|j| j.key == *identity)
            .map_or("unknown", |j| j.name)
    }

    fn on_enrolled(
        &mut self,
        invitation: InvitationId,
        conn: ConnectionId,
        grant: GrantId,
        identity: IdentityPublicKey,
    ) {
        let who = self.who(&identity);
        self.note(
            "host",
            format_args!(
                "enrolls {who} on conn {}: provisional grant {}",
                conn.0, grant.0
            ),
        );
        if !self.host.allowed.contains(&(invitation, identity)) {
            self.sim.fail(
                Invariant::NoGrantWithoutAllow,
                format!("{who} was enrolled, but the owner never allowed it"),
            );
            return;
        }
        let live = self
            .conns
            .get(&conn)
            .is_some_and(|c| c.host_open && !c.ordinary && self.joiners[c.joiner].key == identity);
        if !live {
            let why = match self.conns.get(&conn) {
                None => "an unknown connection".to_owned(),
                Some(c) if !c.host_open => format!("conn {}, which the host saw end", conn.0),
                Some(c) => format!(
                    "conn {}, a connection of {}",
                    conn.0, self.joiners[c.joiner].name
                ),
            };
            self.sim.fail(
                Invariant::EnrollOnLiveConnection,
                format!("{who} was enrolled on {why}"),
            );
            return;
        }
        let n = self
            .sim
            .check
            .enrolled(HOST_DEV, self.host.instance, invitation.0);
        if n > 1 {
            self.sim.fail(
                Invariant::SingleEnrollment,
                format!("the invitation enrolled {n} times"),
            );
        }
    }

    /// The host's grant (provisional or committed) made by a direct
    /// invitation for `identity`, if any.
    fn direct_grant(&self, identity: &IdentityPublicKey) -> Option<GrantId> {
        let grants = &self.host.grants;
        grants
            .grants()
            .chain(grants.provisional_grants())
            .find(|g| g.direct && g.identity == *identity)
            .map(|g| g.id)
    }

    fn schedule_owner(&mut self) {
        if self.plan.owner_scheduled || self.plan.answer == Answer::Never {
            return;
        }
        self.plan.owner_scheduled = true;
        let delay = self
            .sim
            .range(self.plan.owner_delay.0, self.plan.owner_delay.1);
        self.after(delay, Ev::Owner);
    }

    /// The owner looks at the prompts and answers one.
    fn owner(&mut self) {
        let now = self.host_now();
        let invitation = self.host.invitation;
        let Some(pairing) = self.host.pairing.as_ref() else {
            self.note("owner", format_args!("finds the host restarting"));
            return;
        };
        let prompts = pairing.approvals(&invitation, now);
        if prompts.is_empty() {
            self.note("owner", format_args!("finds no prompt to answer"));
            return;
        }
        let pick = self.sim.range(0, prompts.len() as u64 - 1) as usize;
        let request = prompts[pick].request;
        let who = self.who(&request.identity);
        match self.plan.answer {
            Answer::Allow => {
                self.note("owner", format_args!("taps Allow for {who}"));
                if self.allow(request, true) && self.plan.restart_after_allow {
                    let at = self.sim.range(0, 2 * SEC);
                    let down = self.sim.range(2 * SEC, 20 * SEC);
                    self.after(at, Ev::HostDown(down));
                }
            }
            Answer::Decline => {
                self.note("owner", format_args!("taps Decline for {who}"));
                let Some(pairing) = self.host.pairing.as_mut() else {
                    return;
                };
                match pairing.decline(&request, now) {
                    Ok(actions) => self.host_did(actions),
                    Err(e) => self.note("owner", format_args!("decline refused: {e}")),
                }
            }
            Answer::CancelInvitation => {
                self.note("owner", format_args!("cancels the invitation"));
                let Some(pairing) = self.host.pairing.as_mut() else {
                    return;
                };
                let actions = pairing.cancel(&invitation);
                self.host_did(actions);
            }
            Answer::Never => {}
        }
    }

    /// Allow `request`; `owner` when the owner tapped it. Returns whether
    /// the host took it.
    fn allow(&mut self, request: DirectRequestId, owner: bool) -> bool {
        let now = self.host_now();
        let Some(pairing) = self.host.pairing.as_mut() else {
            return false;
        };
        match pairing.allow(&request, None, &mut self.host.grants, now) {
            Ok(actions) => {
                if owner {
                    self.host
                        .allowed
                        .insert((request.invitation, request.identity));
                }
                self.host_did(actions);
                true
            }
            Err(e) => {
                self.note("owner", format_args!("allow refused: {e}"));
                false
            }
        }
    }

    fn host_down(&mut self, down: u64) {
        if self.host.pairing.is_none() {
            return;
        }
        self.note("host", format_args!("restarts (down {down} ms)"));
        let open: Vec<ConnectionId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.host_open)
            .map(|(id, _)| *id)
            .collect();
        for conn in open {
            let Some(c) = self.conns.get_mut(&conn) else {
                continue;
            };
            c.host_open = false;
            c.host_reported = true;
            let tell_joiner = c.joiner_open && !c.broken;
            c.broken = true;
            let at = c.arrival[Side::Joiner.idx()].max(self.sim.now + c.latency);
            if tell_joiner {
                self.schedule(
                    at,
                    Ev::Reset {
                        conn,
                        to: Side::Joiner,
                    },
                );
            }
        }
        self.host.gates.clear();
        self.host.enrolled.clear();
        self.host.prompted.clear();
        // The grant store survives: what a restart reads back.
        let g = &self.host.grants;
        let mut table = GrantTable::restore(
            g.grants().cloned().collect(),
            g.denials().collect(),
            g.next_grant_id(),
        )
        .expect("the stored grants restore");
        table
            .restore_provisional(g.provisional_grants().cloned().collect())
            .expect("the stored provisional grants restore");
        self.host.grants = table;
        self.host.pairing = None;
        self.after(down, Ev::HostUp);
    }

    fn host_up(&mut self) {
        self.host.instance += 1;
        let factory = CountingFactory::new(HOST_DEV, self.host.instance, self.sim.work.clone());
        self.host.pairing = Some(DirectHostPairing::with_limits(
            self.host.key,
            HOST_NAME.into(),
            factory,
            &self.limits,
        ));
        self.note("host", format_args!("is back, with no invitation"));
    }

    // ---- the joiner -------------------------------------------------------------

    fn connect(&mut self, j: usize) {
        let jn = &self.joiners[j];
        let busy = jn
            .flow
            .as_ref()
            .is_some_and(|f| !matches!(f.state(), DirectJoinerState::Ended(_)));
        let Some(typed) = jn.current.clone() else {
            return;
        };
        if busy || jn.stream_ok || jn.pin.is_some() {
            return;
        }
        let jn = &mut self.joiners[j];
        jn.flows += 1;
        let factory = CountingFactory::new(jn.dev, jn.flows, self.sim.work.clone());
        let (key, name) = (jn.key, jn.name);
        let flow = DirectJoinerPairing::with_limits(
            ADDRESS,
            &typed.text,
            key,
            name,
            factory,
            &self.limits,
        );
        match flow {
            Ok(mut flow) => {
                let actions = flow.start();
                let jn = &mut self.joiners[j];
                jn.flow = Some(flow);
                jn.ledger_asked = None;
                jn.retry_ms = RETRY_FIRST_MS;
                jn.retry_due = false;
                self.note(name, format_args!("types {} and taps Connect", typed.what));
                self.joiner_did(j, actions);
            }
            Err(e) => self.note(name, format_args!("Connect refused: {e}")),
        }
    }

    fn cancel(&mut self, j: usize) {
        let name = self.joiners[j].name;
        let Some(flow) = self.joiners[j].flow.as_mut() else {
            return;
        };
        let had_pending = flow.pending().is_some();
        match flow.cancel() {
            Ok(actions) => {
                if had_pending {
                    self.joiners[j].cancelled = true;
                }
                self.note(name, format_args!("taps Cancel"));
                self.joiner_did(j, actions);
            }
            Err(e) => self.note(name, format_args!("Cancel refused: {e}")),
        }
    }

    fn joiner_receive(&mut self, conn: ConnectionId, wire: Wire) {
        let Some(c) = self.conns.get(&conn) else {
            return;
        };
        let (j, ordinary) = (c.joiner, c.ordinary);
        let name = self.joiners[j].name;
        let mine = self.joiners[j].conn == Some(conn);
        if ordinary || !mine {
            match wire {
                Wire::Stream if ordinary => {
                    self.joiners[j].stream_ok = true;
                    self.note(name, format_args!("the host serves its stream"));
                }
                Wire::GoAway(_) => {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.joiner_open = false;
                    }
                }
                _ => {}
            }
            return;
        }
        let message = match &wire {
            Wire::Control(bytes) => match ControlMessage::decode_at(bytes, DIRECT_MINOR_VERSION) {
                Ok(m) => Some(m),
                Err(_) => {
                    self.joiner_close(j, ErrorCode::ProtocolError);
                    let actions = self.joiners[j]
                        .flow
                        .as_mut()
                        .map(|f| f.on_closed(None))
                        .unwrap_or_default();
                    self.joiner_did(j, actions);
                    return;
                }
            },
            _ => None,
        };
        let traffic = match (&wire, &message) {
            (_, Some(m)) => CallerTraffic::of(m),
            (Wire::Hello, _) => CallerTraffic::Hello,
            (Wire::GoAway(_), _) => CallerTraffic::GoAway,
            _ => CallerTraffic::Stream,
        };
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        let verdict = c.gate.check(traffic);
        if let Wire::GoAway(code) = wire {
            c.joiner_open = false;
            self.joiners[j].conn = None;
            self.note(
                name,
                format_args!("conn {} closed by the host with {}", conn.0, code.name()),
            );
            let actions = self.joiners[j]
                .flow
                .as_mut()
                .map(|f| f.on_closed(Some(code)))
                .unwrap_or_default();
            self.joiner_did(j, actions);
            return;
        }
        match verdict {
            Verdict::Allow => {}
            Verdict::Close(code) => {
                self.note(
                    name,
                    format_args!("gate refuses a message on conn {}", conn.0),
                );
                self.joiner_close(j, code);
                let actions = self.joiners[j]
                    .flow
                    .as_mut()
                    .map(|f| f.on_closed(None))
                    .unwrap_or_default();
                self.joiner_did(j, actions);
                return;
            }
            _ => return,
        }
        let Some(flow) = self.joiners[j].flow.as_mut() else {
            return;
        };
        let done = matches!(
            flow.state(),
            DirectJoinerState::Ended(_) | DirectJoinerState::Away
        );
        let message = match (wire, message) {
            (Wire::Stream, _) => {
                self.joiners[j].stream_ok = true;
                self.note(name, format_args!("the host serves its stream"));
                return;
            }
            (Wire::Hello, _) => {
                let actions = flow.on_hello(DIRECT_MINOR_VERSION);
                self.joiner_did(j, actions);
                return;
            }
            (_, Some(m)) => m,
            _ => return,
        };
        if done {
            return;
        }
        self.note(
            name,
            format_args!("got {} on conn {}", message_name(&message), conn.0),
        );
        let now = self.joiner_now(j);
        let Some(flow) = self.joiners[j].flow.as_mut() else {
            return;
        };
        let actions = match message {
            ControlMessage::Authorized { state } => flow.on_authorized(state),
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received,
            } => flow.on_authorized_direct(invitation, not_received, now, &mut self.sim.rng),
            ControlMessage::CodeExchange { attempt, payload } => {
                flow.on_code_exchange(attempt, &payload, now)
            }
            ControlMessage::CodeAbort { attempt, .. } => flow.on_code_abort(attempt),
            ControlMessage::Paired { host_name, role } => flow.on_paired(host_name, role),
            _ => Vec::new(),
        };
        self.joiner_did(j, actions);
    }

    /// The joiner closes its flow's connection with `GOAWAY(code)`.
    fn joiner_close(&mut self, j: usize, code: ErrorCode) {
        let Some(conn) = self.joiners[j].conn.take() else {
            return;
        };
        let name = self.joiners[j].name;
        self.note(
            name,
            format_args!("closes conn {} with {}", conn.0, code.name()),
        );
        self.transmit(conn, Side::Joiner, Wire::GoAway(code));
        if let Some(c) = self.conns.get_mut(&conn) {
            c.joiner_open = false;
            c.gate.close(code);
        }
    }

    fn joiner_send(&mut self, j: usize, message: ControlMessage) {
        let Some(conn) = self.joiners[j].conn else {
            return;
        };
        let name = self.joiners[j].name;
        if let ControlMessage::CodeExchange { attempt, .. } = &message {
            if self.joiners[j].shares_sent.insert(*attempt) {
                // The first share of an attempt: its debit must be stored.
                let jn = &self.joiners[j];
                let stored = jn
                    .flow
                    .as_ref()
                    .and_then(|f| jn.ledgers.get(f.lookup().as_str()));
                if jn.ledger_asked.is_none() || stored != jn.ledger_asked.as_ref() {
                    self.sim.fail(
                        Invariant::DebitBeforeWork,
                        format!("{name} sent an attempt's first share before its debit was stored"),
                    );
                    return;
                }
            }
        }
        if let ControlMessage::JoinDirect { .. } = &message {
            if let Some(c) = self.conns.get_mut(&conn) {
                if c.pinned {
                    c.gate.sent_join_proof();
                }
            }
            let wait = self.limits.join_proof_wait_ms();
            self.after(wait, Ev::AnswerDue(conn));
        }
        self.note(
            name,
            format_args!("sends {} on conn {}", message_name(&message), conn.0),
        );
        self.transmit(conn, Side::Joiner, Wire::Control(message.encode()));
    }

    fn joiner_did(&mut self, j: usize, actions: Vec<DirectJoinerAction>) {
        let mut queue: VecDeque<DirectJoinerAction> = actions.into();
        let name = self.joiners[j].name;
        while let Some(action) = queue.pop_front() {
            if self.failed() {
                return;
            }
            let now = self.joiner_now(j);
            match action {
                DirectJoinerAction::AcquireHold(lookup) => {
                    let jn = &mut self.joiners[j];
                    // `direct-ledger-ignored`: the I/O layer loads the
                    // records without the ledger.
                    let ledger = if self.sim.cfg.bug == Some(Bug::DirectLedgerIgnored) {
                        None
                    } else {
                        jn.ledgers.get(lookup.as_str()).cloned()
                    };
                    let pending: Vec<DirectPending> = jn
                        .pending
                        .iter()
                        .filter(|p| p.lookup == lookup)
                        .cloned()
                        .collect();
                    if let Some(flow) = jn.flow.as_mut() {
                        queue.extend(flow.on_records(ledger.as_ref(), &pending, now));
                    }
                }
                DirectJoinerAction::ReleaseHold(_) => {}
                DirectJoinerAction::Send(message) => self.joiner_send(j, message),
                DirectJoinerAction::Close(code) => self.joiner_close(j, code),
                DirectJoinerAction::PersistLedger { expected, record } => {
                    let ignored = self.sim.cfg.bug == Some(Bug::DirectLedgerIgnored);
                    let late = self.sim.cfg.bug == Some(Bug::DirectDebitAfterSend);
                    let jn = &mut self.joiners[j];
                    let key = record.lookup.as_str().to_owned();
                    if !ignored && jn.ledgers.get(&key) != expected.as_ref() {
                        if let Some(flow) = jn.flow.as_mut() {
                            queue.extend(flow.on_persist_failed());
                        }
                        continue;
                    }
                    jn.debits_asked += 1;
                    jn.ledger_asked = Some(record.clone());
                    if late {
                        // `direct-debit-after-send`: acknowledged now,
                        // stored a second later.
                        self.after(SEC, Ev::LedgerLate(j, record));
                    } else {
                        self.joiners[j].ledgers.insert(key, record);
                    }
                    if let Some(flow) = self.joiners[j].flow.as_mut() {
                        queue.extend(flow.on_persisted());
                    }
                }
                DirectJoinerAction::PersistPending { expected, record } => {
                    let jn = &mut self.joiners[j];
                    let Some((lookup, address)) = record
                        .as_ref()
                        .or(expected.as_ref())
                        .map(|p| (p.lookup.clone(), p.address))
                    else {
                        continue;
                    };
                    let at = jn
                        .pending
                        .iter()
                        .position(|p| p.lookup == lookup && p.address == address);
                    if at.map(|i| &jn.pending[i]) != expected.as_ref() {
                        if let Some(flow) = jn.flow.as_mut() {
                            queue.extend(flow.on_persist_failed());
                        }
                        continue;
                    }
                    match (at, record) {
                        (Some(i), Some(r)) => jn.pending[i] = r,
                        (Some(i), None) => {
                            jn.pending.remove(i);
                        }
                        (None, Some(r)) => jn.pending.push(r),
                        (None, None) => {}
                    }
                    if let Some(flow) = jn.flow.as_mut() {
                        queue.extend(flow.on_persisted());
                    }
                }
                DirectJoinerAction::CodePassed => self.code_passed(j),
                DirectJoinerAction::Paired(paired) => {
                    self.note(
                        name,
                        format_args!("is paired as {}; stores the pin", paired.role.as_str()),
                    );
                    let jn = &mut self.joiners[j];
                    jn.pin = Some(paired);
                    if let Some(c) = jn.conn.and_then(|c| self.conns.get_mut(&c)) {
                        c.gate.promote_direct();
                        c.gate.promote();
                    }
                    if let Some(flow) = jn.flow.as_mut() {
                        queue.extend(flow.on_pin_stored());
                    }
                }
                DirectJoinerAction::Away => {
                    self.note(name, format_args!("is away; the pending record stays"));
                    let jn = &mut self.joiners[j];
                    if !jn.retry_due {
                        jn.retry_due = true;
                        let wait = jn.retry_ms;
                        jn.retry_ms = (jn.retry_ms * 2).min(RETRY_MAX_MS);
                        let jitter = self.sim.range(0, wait / 4);
                        self.after(wait + jitter, Ev::Retry(j));
                    }
                }
                DirectJoinerAction::Ended(end) => self.joiner_ended(j, end),
            }
        }
        self.check_joiner_work(j);
        let jn = &self.joiners[j];
        let connecting = jn
            .flow
            .as_ref()
            .is_some_and(|f| f.state() == DirectJoinerState::Connecting);
        if connecting && jn.conn.is_none() && jn.dialing.is_none() && !self.failed() {
            self.dial(j, false);
        }
    }

    fn code_passed(&mut self, j: usize) {
        let name = self.joiners[j].name;
        self.note(name, format_args!("code accepted: waiting for Allow"));
        if self.sim.cfg.bug == Some(Bug::DirectPinOnCodePassed) {
            // `direct-pin-on-code-passed`: the I/O layer pins the host as
            // soon as the code passes.
            let jn = &mut self.joiners[j];
            if let Some(p) = jn.flow.as_ref().and_then(|f| f.pending()) {
                jn.pin = Some(DirectPaired {
                    identity: p.host,
                    name: HOST_NAME.into(),
                    role: Role::owner(),
                    invitation: p.invitation,
                    address: p.address,
                });
            }
        }
        if std::mem::replace(&mut self.joiners[j].passed_once, true) {
            return;
        }
        if let Some(d) = self.plan.break_after_pass {
            self.after(d, Ev::Break(j));
        }
        if let Some(d) = self.plan.cancel_after_pass {
            self.after(d, Ev::Cancel(j));
        }
        if let Some((d, len)) = self.plan.route_down_after_pass {
            self.after(d, Ev::Route(true));
            self.after(d + len, Ev::Route(false));
        }
    }

    fn joiner_ended(&mut self, j: usize, end: DirectEnd) {
        let name = self.joiners[j].name;
        self.note(name, format_args!("the flow ends: {}", end_name(end)));
        self.check_agreement(j);
        self.check_cancel_left_nothing(j);
        let jn = &mut self.joiners[j];
        let next = match end {
            DirectEnd::Paired => {
                let at = self.sim.range(0, 3 * SEC);
                self.after(at, Ev::Stream(j));
                return;
            }
            DirectEnd::CodeFailed { .. }
            | DirectEnd::Closed(Some(ErrorCode::InvitationInvalid)) => jn.codes.pop_front(),
            DirectEnd::NotReceived { .. } => jn.current.clone(),
            DirectEnd::Closed(None | Some(ErrorCode::InternalError | ErrorCode::NotAuthorized))
                if jn.retries > 0 =>
            {
                jn.retries -= 1;
                jn.current.clone()
            }
            _ => None,
        };
        let Some(next) = next else {
            return;
        };
        jn.current = Some(next);
        let gap = jn.gap;
        let at = self.sim.range(gap.0, gap.1);
        self.after(at, Ev::Connect(j));
    }

    /// A paired joiner opens its first stream: on the pairing connection if
    /// it is still up, else on a new ordinary connection.
    fn open_stream(&mut self, j: usize) {
        let jn = &mut self.joiners[j];
        if jn.stream_ok || jn.stream_tries >= STREAM_TRIES || jn.pin.is_none() {
            return;
        }
        jn.stream_tries += 1;
        let name = jn.name;
        let on = jn.conn.filter(|c| {
            self.conns
                .get(c)
                .is_some_and(|c| c.joiner_open && !c.broken)
        });
        match on {
            Some(conn) => {
                self.note(name, format_args!("opens a stream on conn {}", conn.0));
                self.transmit(conn, Side::Joiner, Wire::Stream);
            }
            None => self.dial(j, true),
        }
        let again = self.sim.range(5 * SEC, 30 * SEC);
        self.after(again, Ev::Stream(j));
    }

    // ---- checks ---------------------------------------------------------------

    /// Every grant a direct invitation made is for an identity the owner
    /// allowed on it.
    fn check_grants(&mut self) {
        let grants = &self.host.grants;
        let bad = grants
            .grants()
            .chain(grants.provisional_grants())
            .filter(|g| g.direct)
            .find(|g| {
                g.enrolled_by
                    .is_none_or(|i| !self.host.allowed.contains(&(i, g.identity)))
            })
            .map(|g| (g.id, g.identity));
        if let Some((id, identity)) = bad {
            let who = self.who(&identity);
            self.sim.fail(
                Invariant::NoGrantWithoutAllow,
                format!(
                    "the host holds grant {} for {who}, which the owner never allowed",
                    id.0
                ),
            );
        }
    }

    /// The host's code work for the invitation never runs ahead of its
    /// debits, and stays within its cap.
    fn check_host_work(&mut self) {
        let digest = self.host.digest;
        let starts = self
            .sim
            .work
            .borrow()
            .iter()
            .filter(|w| {
                w.dev == HOST_DEV
                    && w.role == ExchangeRole::Responder
                    && contains(&w.transcript, &digest)
            })
            .count() as u64;
        let debits = u64::from(self.host.cap - self.host.left.min(self.host.cap));
        if starts > debits {
            self.sim.fail(
                Invariant::DebitBeforeWork,
                format!("the host started {starts} exchanges for {debits} debits"),
            );
        } else if starts > u64::from(self.host.cap) {
            self.sim.fail(
                Invariant::AttemptCap,
                format!(
                    "the host started {starts} exchanges; the cap is {}",
                    self.host.cap
                ),
            );
        }
    }

    /// The joiner's code work never runs ahead of its debits, and stays
    /// within its cap for the typed lookup.
    fn check_joiner_work(&mut self, j: usize) {
        let jn = &self.joiners[j];
        let starts = self
            .sim
            .work
            .borrow()
            .iter()
            .filter(|w| w.dev == jn.dev && w.role == ExchangeRole::Initiator)
            .count() as u64;
        let cap = self.limits.direct_joiner_attempts();
        let name = jn.name;
        if starts > jn.debits_asked {
            let detail = format!(
                "{name} started {starts} exchanges for {} debits",
                jn.debits_asked
            );
            self.sim.fail(Invariant::DebitBeforeWork, detail);
        } else if starts > cap {
            self.sim.fail(
                Invariant::AttemptCap,
                format!("{name} started {starts} exchanges for one lookup; the cap is {cap}"),
            );
        }
    }

    /// After the host handled a cancel on the connection it enrolled the
    /// joiner on, that provisional grant is gone.
    fn check_cancel_on(&mut self, conn: ConnectionId, j: usize) {
        let Some(grant) = self.host.enrolled.get(&conn).copied() else {
            return;
        };
        if self.host.grants.is_provisional(grant) {
            let name = self.joiners[j].name;
            self.sim.fail(
                Invariant::CancelWins,
                format!(
                    "{name} cancelled on conn {}, where it was enrolled, and provisional grant {} stays",
                    conn.0, grant.0
                ),
            );
        }
    }

    /// After a recovery that carried a cancel, no provisional grant of the
    /// joiner is left.
    fn check_recovery_cancel(&mut self, j: usize) {
        let key = self.joiners[j].key;
        let now = self.host_now();
        let left = self.host.grants.provisional_grant(&key, now).map(|g| g.id);
        if let Some(grant) = left {
            let name = self.joiners[j].name;
            self.sim.fail(
                Invariant::CancelWins,
                format!(
                    "{name}'s cancel reached the host and provisional grant {} stays",
                    grant.0
                ),
            );
        }
    }

    /// A joiner that cancelled after its code passed, and whose flow has
    /// ended, has no grant on the host.
    fn check_cancel_left_nothing(&mut self, j: usize) {
        let jn = &self.joiners[j];
        if !jn.cancelled {
            return;
        }
        if let Some(grant) = self.direct_grant(&jn.key) {
            let name = jn.name;
            self.sim.fail(
                Invariant::CancelWins,
                format!(
                    "{name} cancelled after its code passed and the host holds grant {}",
                    grant.0
                ),
            );
        }
    }

    /// A joiner whose flow has ended holds the host's pin exactly when the
    /// host holds a grant for it.
    fn check_agreement(&mut self, j: usize) {
        let jn = &self.joiners[j];
        let pinned = jn.pin.is_some();
        let granted = self.direct_grant(&jn.key);
        if pinned != granted.is_some() {
            let name = jn.name;
            let detail = match granted {
                Some(g) => format!(
                    "{name} holds no pin, but the host holds grant {} for it",
                    g.0
                ),
                None => format!("{name} pinned the host, which holds no grant for it"),
            };
            self.sim.fail(Invariant::PairingAgreement, detail);
        }
    }

    fn final_checks(&mut self) {
        for j in 0..self.joiners.len() {
            if self.failed() {
                return;
            }
            let settled = self.joiners[j]
                .flow
                .as_ref()
                .is_none_or(|f| matches!(f.state(), DirectJoinerState::Ended(_)));
            let name = self.joiners[j].name;
            if !settled {
                self.note(name, format_args!("still has a pending record at the end"));
                continue;
            }
            self.check_agreement(j);
            self.check_cancel_left_nothing(j);
        }
    }
}

pub(crate) fn run(sim: &mut Sim) -> &'static str {
    let variant = sim.pick(DIRECT_VARIANTS);
    let cfg = sim.cfg;
    sim.note(
        "sim",
        format_args!(
            "drill {} seed {} variant {variant}{}",
            cfg.drill.name(),
            cfg.seed,
            cfg.bug
                .map(|b| format!(" bug {}", b.name()))
                .unwrap_or_default()
        ),
    );

    // Limits.
    let host_attempts = match variant {
        "wrong-codes" => sim.pick(&[2u64, 3, 5, 5, 5]),
        _ => sim.pick(&[3, 5, 5]),
    };
    let joiner_attempts = match variant {
        "wrong-codes" => sim.range(1, 5),
        _ => 5,
    };
    let (lifetime, window) = match variant {
        "expiry" => (sim.range(60, 120), sim.range(60, 120)),
        _ => (sim.pick(&[300, 600]), sim.pick(&[120, 300])),
    };
    let miss_hold = sim.range(1_000, 5_000);
    let limits = Limits::DEFAULT
        .with_overrides(&[
            ("DIRECT_HOST_ATTEMPTS", host_attempts),
            ("DIRECT_JOINER_ATTEMPTS", joiner_attempts),
            ("DIRECT_INVITE_LIFETIME_SECS", lifetime),
            ("DIRECT_ALLOW_WINDOW_SECS", window),
            ("DIRECT_MISS_HOLD_MS", miss_hold),
        ])
        .expect("drill limits");

    // The scenario.
    let mut plan = Plan {
        answer: Answer::Allow,
        owner_delay: (SEC, 20 * SEC),
        owner_scheduled: false,
        break_after_pass: None,
        cancel_after_pass: None,
        route_down_after_pass: None,
        drop_permille: sim.pick(&[0, 0, 50]),
        half_open_permille: 200,
        restart_after_allow: false,
        latency: (1, 40),
    };
    let mut wrong = 0u64;
    let mut start = (SEC, 20 * SEC);
    let mut joiners = 1;
    let mut host_restarts = 0;
    let mut faults = 0;
    match variant {
        "wrong-codes" => {
            wrong = sim.pick(&[
                0,
                1,
                joiner_attempts,
                joiner_attempts + 1,
                joiner_attempts + 2,
                host_attempts + 1,
            ]);
        }
        "allow-connected" => {
            wrong = sim.pick(&[0, 0, 1]);
            plan.owner_delay = (500, 30 * SEC);
            plan.drop_permille = sim.pick(&[0, 0, 100]);
        }
        "allow-away" => {
            let d = sim.range(50, 800);
            plan.break_after_pass = Some(d);
            plan.owner_delay = (d + 300, d + 1_500);
            plan.half_open_permille = 300;
        }
        "cancel-crossing" => {
            // The owner taps Allow `a` after the prompt shows, which is one
            // trip after the joiner's code passed. A cancel `a` to `a` plus
            // two trips after the code passed crosses the Allow: it leaves
            // after the enrollment and before `PAIRED` arrives.
            let trip = sim.range(30, 250);
            plan.latency = (trip, trip);
            let a = sim.range(500, 3 * SEC);
            plan.owner_delay = (a, a);
            let b = if sim.chance(700) {
                a + sim.range(1, 2 * trip)
            } else {
                a.saturating_sub(sim.range(0, 300))
            };
            plan.cancel_after_pass = Some(b);
            if sim.chance(200) {
                // Sometimes the cancel is made while away.
                plan.break_after_pass = Some(b.saturating_sub(sim.range(1, 400)));
            }
        }
        "decline" => {
            plan.answer = if sim.chance(700) {
                Answer::Decline
            } else {
                Answer::CancelInvitation
            };
            plan.owner_delay = (SEC, 30 * SEC);
            if sim.chance(400) {
                plan.break_after_pass = Some(sim.range(50, 800));
            }
        }
        "expiry" => match sim.range(0, 3) {
            0 => {
                // The person starts after the invitation expired.
                start = ((lifetime + 1) * SEC, (lifetime + 60) * SEC);
            }
            1 => {
                // The code passes in the last seconds; the owner answers
                // after the expiry, sometimes after the Allow window.
                start = ((lifetime - 20) * SEC, (lifetime - 5) * SEC);
                plan.owner_delay = (10 * SEC, (window + 30) * SEC);
            }
            2 => plan.answer = Answer::Never,
            _ => {
                // Allowed while away, never claimed: the route stays down
                // past the Allow window.
                let d = sim.range(50, 800);
                plan.break_after_pass = Some(d);
                plan.owner_delay = (d + 300, d + 1_500);
                plan.route_down_after_pass = Some((d, (window + 60) * SEC));
            }
        },
        "faults" => {
            plan.drop_permille = 300;
            plan.half_open_permille = 300;
            plan.owner_delay = (SEC, 40 * SEC);
            faults = sim.range(1, 3);
        }
        "host-restart" => {
            host_restarts = sim.range(1, 2);
            plan.restart_after_allow = sim.chance(500);
        }
        _ => {
            // race
            joiners = 2;
            plan.owner_delay = (2 * SEC, 20 * SEC);
        }
    }

    // The devices.
    let host_key = SoftwareKey::generate(&mut sim.rng).public_key();
    let factory = CountingFactory::new(HOST_DEV, 1, sim.work.clone());
    let mut pairing = DirectHostPairing::with_limits(host_key, HOST_NAME.into(), factory, &limits);
    let params = DirectInvitationParams {
        role: Role::owner(),
        authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
        grant_expires_at: None,
    };
    let created = pairing
        .create(params, UnixTime(WALL0), &mut sim.rng)
        .expect("an invitation");
    let lookup: DirectLookup = created.code.lookup();
    let digest = direct_invite_digest(&lookup, &created.invitation);
    let code = created.code.as_str().to_owned();
    sim.note(
        "host",
        format_args!(
            "shows {ADDRESS} and a code: {host_attempts} attempts, {lifetime} s, Allow window {window} s"
        ),
    );

    let names = ["laptop", "tablet"];
    let mut people = Vec::new();
    for (n, name) in names.iter().copied().enumerate().take(joiners) {
        let key = SoftwareKey::generate(&mut sim.rng).public_key();
        let skew = sim.pick(&[0i64, 0, -40, 25]);
        let mut codes = VecDeque::new();
        for _ in 0..wrong {
            let wrong_lookup = sim.chance(250);
            let text = loop {
                let t = if wrong_lookup {
                    format!("{}{}", draw(sim, 4), &code[4..])
                } else {
                    format!("{}{}", &code[..4], draw(sim, 8))
                };
                if t != code {
                    break t;
                }
            };
            let text = typed_form(sim, &text);
            codes.push_back(Typed {
                text,
                what: if wrong_lookup {
                    "a wrong lookup"
                } else {
                    "a wrong code"
                },
            });
        }
        let right = typed_form(sim, &code);
        codes.push_back(Typed {
            text: right,
            what: "the right code",
        });
        let current = codes.pop_front();
        people.push(Joiner {
            name,
            dev: n + 1,
            key,
            skew,
            flow: None,
            flows: 0,
            conn: None,
            dialing: None,
            ledgers: BTreeMap::new(),
            pending: Vec::new(),
            pin: None,
            ledger_asked: None,
            debits_asked: 0,
            shares_sent: BTreeSet::new(),
            cancelled: false,
            passed_once: false,
            stream_ok: false,
            stream_tries: 0,
            retry_ms: RETRY_FIRST_MS,
            retry_due: false,
            codes,
            current,
            retries: 4,
            gap: (2 * SEC, 25 * SEC),
        });
    }

    let mut d = Drive {
        sim,
        variant,
        plan,
        limits,
        host: Host {
            key: host_key,
            pairing: Some(pairing),
            instance: 1,
            grants: GrantTable::new(),
            gates: BTreeMap::new(),
            invitation: created.invitation,
            digest,
            cap: created.attempts_left,
            left: created.attempts_left,
            prompted: BTreeSet::new(),
            allowed: BTreeSet::new(),
            enrolled: BTreeMap::new(),
            tick_floor: 0,
        },
        joiners: people,
        conns: BTreeMap::new(),
        next_conn: 1,
        queue: BTreeMap::new(),
        seq: 0,
        route_down: false,
    };
    drop(created);

    for j in 0..d.joiners.len() {
        let at = d.sim.range(start.0, start.1);
        d.schedule(at, Ev::Connect(j));
    }
    for _ in 0..host_restarts {
        let at = d.sim.range(start.0, start.1 + 90 * SEC);
        let down = d.sim.range(2 * SEC, 30 * SEC);
        d.schedule(at, Ev::HostDown(down));
    }
    for _ in 0..faults {
        let at = d.sim.range(start.0, start.1 + 2 * MIN);
        d.schedule(at, Ev::Break(0));
    }
    if d.variant == "faults" && d.sim.chance(500) {
        let at = d.sim.range(start.0, start.1 + 2 * MIN);
        let len = d.sim.range(5 * SEC, 3 * MIN);
        d.schedule(at, Ev::Route(true));
        d.schedule(at + len, Ev::Route(false));
    }

    d.run();
    if !d.failed() {
        d.final_checks();
    }
    let grants = d.host.grants.grants().count();
    let provisional = d.host.grants.provisional_grants().count();
    d.note(
        "host",
        format_args!("end: {grants} grants, {provisional} provisional"),
    );
    variant
}
