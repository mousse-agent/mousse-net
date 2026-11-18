//! The engine: RNG, virtual clocks, event queue, virtual network, log.

use std::collections::BTreeMap;

use mousse_net_core::control::ControlMessage;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{frame_type, Mux, MuxRole};
use mousse_net_core::pairing::SessionExporters;
use mousse_net_core::session_cert::{ValidityWindow, VerifiedSessionCert};
use mousse_net_core::{ConnectionId, ErrorCode, Millis, UnixTime};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::certs::T0;
use crate::check::{Checker, Invariant};
use crate::exchange::WorkLog;
use crate::log::EventLog;
use crate::world::Script;
use crate::{Bug, RunConfig};

pub(crate) type DevId = usize;

/// Which end of a pipe. The client dialled; the server accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Client,
    Server,
}

impl Side {
    fn idx(self) -> usize {
        match self {
            Side::Client => 0,
            Side::Server => 1,
        }
    }

    pub(crate) fn other(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

/// A way to reach a device: a LAN address, a tailnet address, a tunnel.
pub(crate) struct Route {
    pub name: &'static str,
    pub target: DevId,
    /// While set, dials on this route reach this device instead (a wrong
    /// device answering on the address).
    pub hijack: Option<DevId>,
    /// While set, dials fail and open pipes on the route go silent.
    pub partitioned: bool,
    pub latency_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeState {
    Dialing,
    Open,
    /// Broken at a byte offset; a reset is on its way to both ends.
    Broken,
    /// Partitioned: bytes vanish and nobody is told.
    Blackholed,
}

#[derive(Default)]
struct Dir {
    sent: u64,
    drop_at: Option<u64>,
    last_arrival: u64,
}

/// A reliable, ordered byte pipe between two devices.
pub(crate) struct Pipe {
    pub client: DevId,
    pub server: DevId,
    pub route: usize,
    pub state: PipeState,
    attached: [bool; 2],
    dirs: [Dir; 2],
}

/// Something that happens at a virtual time.
pub(crate) enum Ev {
    Deliver {
        conn: ConnectionId,
        to: Side,
        bytes: Vec<u8>,
    },
    Eof {
        conn: ConnectionId,
        to: Side,
    },
    Break {
        conn: ConnectionId,
    },
    DialDone {
        conn: ConnectionId,
    },
    Wake {
        dev: DevId,
        at: u64,
    },
    Script(Script),
}

/// What step 1 established for one end of an authenticated pipe.
#[derive(Clone, Debug)]
pub(crate) struct AuthInfo {
    pub peer: VerifiedSessionCert,
    pub local_window: ValidityWindow,
    pub exporters: SessionExporters,
    /// Oracle: `min(both not_after) + 600`, computed by the simulator from
    /// the two certificates, independently of core.
    pub deadline: UnixTime,
}

/// One end of an open connection: the mux plus what step 1 established.
pub(crate) struct Endpoint {
    pub conn: ConnectionId,
    pub side: Side,
    pub mux: Mux,
    pub auth: AuthInfo,
    /// The device already ran its "connection ended" handling.
    pub ended: bool,
    /// The code from the peer's `GOAWAY`, if one arrived.
    pub peer_goaway: Option<ErrorCode>,
}

impl Endpoint {
    pub(crate) fn new(conn: ConnectionId, side: Side, auth: AuthInfo, mono: Millis) -> Self {
        let role = match side {
            Side::Client => MuxRole::Caller,
            Side::Server => MuxRole::Host,
        };
        Self {
            conn,
            side,
            mux: Mux::new(role, mono),
            auth,
            ended: false,
            peer_goaway: None,
        }
    }

    pub(crate) fn send(&mut self, msg: &ControlMessage) {
        if !self.mux.is_closing() {
            let _ = self.mux.send_control(msg.encode());
        }
    }
}

pub(crate) struct Sim {
    pub cfg: RunConfig,
    pub rng: ChaCha20Rng,
    pub now: u64,
    seq: u64,
    queue: BTreeMap<(u64, u64), Ev>,
    pub log: EventLog,
    pub routes: Vec<Route>,
    pub pipes: BTreeMap<ConnectionId, Pipe>,
    next_conn: u64,
    /// Per device: wall clock offset from `T0`, in seconds.
    pub skews: Vec<i64>,
    pub names: Vec<&'static str>,
    /// Per device: the label its identity key is derived from. Two devices
    /// with the same key label are one identity (one laptop talking to two
    /// endpoints).
    pub key_labels: Vec<&'static str>,
    pub identities: Vec<IdentityPublicKey>,
    pub work: WorkLog,
    pub check: Checker,
    /// Chance (per mille) that a new pipe breaks at some byte offset.
    pub drop_permille: u32,
    /// The break offset is drawn from `0..drop_max` in one direction.
    pub drop_max: u64,
    pub events: u64,
}

impl Sim {
    pub(crate) fn new(cfg: RunConfig) -> Self {
        let seed: [u8; 32] = Sha256::new()
            .chain_update(b"mousse-sim run")
            .chain_update(cfg.drill.name().as_bytes())
            .chain_update(cfg.seed.to_be_bytes())
            .finalize()
            .into();
        Self {
            cfg,
            rng: ChaCha20Rng::from_seed(seed),
            now: 0,
            seq: 0,
            queue: BTreeMap::new(),
            log: EventLog::new(cfg.keep_log),
            routes: Vec::new(),
            pipes: BTreeMap::new(),
            next_conn: 1,
            skews: Vec::new(),
            names: Vec::new(),
            key_labels: Vec::new(),
            identities: Vec::new(),
            work: WorkLog::default(),
            check: Checker::default(),
            drop_permille: 0,
            drop_max: 1,
            events: 0,
        }
    }

    // ---- time and randomness ----------------------------------------------

    pub(crate) fn schedule(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.queue.insert((at.max(self.now), self.seq), ev);
    }

    pub(crate) fn after(&mut self, delay_ms: u64, script: Script) {
        self.schedule(self.now + delay_ms, Ev::Script(script));
    }

    pub(crate) fn pop(&mut self) -> Option<(u64, Ev)> {
        self.queue.pop_first().map(|((t, _), ev)| (t, ev))
    }

    /// Device `dev`'s wall clock.
    pub(crate) fn wall(&self, dev: DevId) -> UnixTime {
        UnixTime(self.wall_base(dev) + self.now / 1000)
    }

    fn wall_base(&self, dev: DevId) -> u64 {
        T0.saturating_add_signed(self.skews[dev])
    }

    pub(crate) fn mono(&self) -> Millis {
        Millis(self.now)
    }

    /// The earliest virtual ms at which `dev`'s wall clock reads `w` or
    /// later. If that is now or earlier, the time it reads `w + 1` (timers
    /// that fire "after" a second), and never earlier than `now + 1`.
    pub(crate) fn due_ms(&self, dev: DevId, w: UnixTime) -> u64 {
        let at = |w: u64| w.saturating_sub(self.wall_base(dev)).saturating_mul(1000);
        let mut t = at(w.secs());
        if t <= self.now {
            t = at(w.secs().saturating_add(1));
        }
        t.max(self.now + 1)
    }

    /// Uniform in `lo..=hi`.
    pub(crate) fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.rng.next_u64() % (hi - lo + 1)
    }

    pub(crate) fn chance(&mut self, permille: u32) -> bool {
        self.range(0, 999) < u64::from(permille)
    }

    pub(crate) fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let i = self.range(0, items.len() as u64 - 1) as usize;
        items[i]
    }

    pub(crate) fn bug(&self, bug: Bug) -> bool {
        self.cfg.bug == Some(bug)
    }

    // ---- log and checks ---------------------------------------------------

    pub(crate) fn say(&mut self, dev: DevId, args: std::fmt::Arguments<'_>) {
        let name = self.names[dev];
        self.log.push(self.now, name, args);
    }

    pub(crate) fn note(&mut self, actor: &str, args: std::fmt::Arguments<'_>) {
        self.log.push(self.now, actor, args);
    }

    pub(crate) fn fail(&mut self, invariant: Invariant, detail: String) {
        if self.check.violation.is_none() {
            self.log.push(
                self.now,
                "CHECK",
                format_args!("VIOLATION {invariant}: {detail}"),
            );
        }
        self.check.fail(invariant, self.now, detail);
    }

    pub(crate) fn who(&self, identity: &IdentityPublicKey) -> &'static str {
        self.identities
            .iter()
            .position(|i| i == identity)
            .map_or("unknown", |d| self.key_labels[d])
    }

    /// No traffic past the effective deadline, by `dev`'s own clock.
    pub(crate) fn check_deadline(&mut self, dev: DevId, ep: &Endpoint, what: &str) {
        let wall = self.wall(dev);
        if wall > ep.auth.deadline {
            let name = self.names[dev];
            self.fail(
                Invariant::NoFlowPastDeadline,
                format!(
                    "{name} {what} on conn {} at wall {} after its deadline {}",
                    ep.conn.0,
                    wall.secs(),
                    ep.auth.deadline.secs()
                ),
            );
        }
    }

    // ---- network ----------------------------------------------------------

    /// Start a dial from `client` over `route`. The handshake resolves at
    /// [`Ev::DialDone`].
    pub(crate) fn dial(&mut self, client: DevId, route: usize) -> ConnectionId {
        let conn = ConnectionId(self.next_conn);
        self.next_conn += 1;
        let mut dirs = [Dir::default(), Dir::default()];
        if self.chance(self.drop_permille) {
            let side = self.range(0, 1) as usize;
            dirs[side].drop_at = Some(self.range(0, self.drop_max.max(1) - 1));
        }
        let latency = self.routes[route].latency_ms;
        let handshake = 3 * latency + self.range(0, latency);
        self.pipes.insert(
            conn,
            Pipe {
                client,
                server: self.routes[route].target,
                route,
                state: PipeState::Dialing,
                attached: [true, false],
                dirs,
            },
        );
        self.schedule(self.now + handshake.max(1), Ev::DialDone { conn });
        conn
    }

    /// One frame (or any bytes) from `from` into the pipe.
    pub(crate) fn transmit(&mut self, conn: ConnectionId, from: Side, bytes: Vec<u8>) {
        let Some((route, state)) = self.pipes.get(&conn).map(|p| (p.route, p.state)) else {
            return;
        };
        if state != PipeState::Open || bytes.is_empty() {
            return; // lost: the pipe is broken, silent or not up yet
        }
        let latency = self.routes[route].latency_ms;
        let jitter = self.range(0, latency / 4);
        let split = bytes.len() > 1 && self.chance(300);
        let cut = if split {
            self.range(1, bytes.len() as u64 - 1) as usize
        } else {
            0
        };
        let now = self.now;
        let Some(pipe) = self.pipes.get_mut(&conn) else {
            return;
        };
        let dir = &mut pipe.dirs[from.idx()];
        let arrival = dir.last_arrival.max(now + latency + jitter);
        dir.last_arrival = arrival;
        let start = dir.sent;
        let len = bytes.len() as u64;
        dir.sent += len;
        let to = from.other();
        if let Some(drop) = dir.drop_at.filter(|d| *d >= start && *d < start + len) {
            pipe.state = PipeState::Broken;
            let keep = (drop - start) as usize;
            if keep > 0 {
                self.schedule(
                    arrival,
                    Ev::Deliver {
                        conn,
                        to,
                        bytes: bytes[..keep].to_vec(),
                    },
                );
            }
            self.schedule(arrival, Ev::Break { conn });
            return;
        }
        if cut > 0 {
            let tail = bytes[cut..].to_vec();
            let mut head = bytes;
            head.truncate(cut);
            self.schedule(
                arrival,
                Ev::Deliver {
                    conn,
                    to,
                    bytes: head,
                },
            );
            self.schedule(
                arrival,
                Ev::Deliver {
                    conn,
                    to,
                    bytes: tail,
                },
            );
        } else {
            self.schedule(arrival, Ev::Deliver { conn, to, bytes });
        }
    }

    /// `from` closes its end after its last bytes (TCP FIN).
    pub(crate) fn close_pipe(&mut self, conn: ConnectionId, from: Side) {
        let now = self.now;
        let Some(pipe) = self.pipes.get_mut(&conn) else {
            return;
        };
        pipe.attached[from.idx()] = false;
        let to = from.other();
        let other_attached = pipe.attached[to.idx()];
        if pipe.state == PipeState::Open && other_attached {
            let latency = self.routes[pipe.route].latency_ms;
            let at = pipe.dirs[from.idx()].last_arrival.max(now + latency);
            pipe.state = PipeState::Broken; // nothing more will be sent
            self.schedule(at, Ev::Eof { conn, to });
        } else if !other_attached {
            self.pipes.remove(&conn);
        }
    }

    /// `from` vanished (process killed): the other end sees a reset.
    pub(crate) fn crash_pipe(&mut self, conn: ConnectionId, from: Side) {
        let now = self.now;
        let Some(pipe) = self.pipes.get_mut(&conn) else {
            return;
        };
        pipe.attached[from.idx()] = false;
        if matches!(pipe.state, PipeState::Open | PipeState::Broken) {
            let latency = self.routes[pipe.route].latency_ms;
            pipe.state = PipeState::Broken;
            self.schedule(now + latency, Ev::Break { conn });
        } else if !pipe.attached[from.other().idx()] {
            self.pipes.remove(&conn);
        }
    }

    pub(crate) fn attached(&self, conn: ConnectionId, side: Side) -> bool {
        self.pipes
            .get(&conn)
            .is_some_and(|p| p.attached[side.idx()])
    }

    pub(crate) fn detach(&mut self, conn: ConnectionId, side: Side) {
        if let Some(pipe) = self.pipes.get_mut(&conn) {
            pipe.attached[side.idx()] = false;
            if !pipe.attached.iter().any(|a| *a) {
                self.pipes.remove(&conn);
            }
        }
    }

    pub(crate) fn mark_open(&mut self, conn: ConnectionId, server: DevId) {
        if let Some(pipe) = self.pipes.get_mut(&conn) {
            pipe.state = PipeState::Open;
            pipe.server = server;
            pipe.attached = [true, true];
        }
    }

    pub(crate) fn set_partition(&mut self, route: usize, on: bool) {
        self.routes[route].partitioned = on;
        if on {
            for pipe in self.pipes.values_mut() {
                if pipe.route == route && matches!(pipe.state, PipeState::Open | PipeState::Dialing)
                {
                    pipe.state = PipeState::Blackholed;
                }
            }
        }
    }
}

/// Write everything the mux has queued, checking the deadline for each
/// frame except the closing `GOAWAY`. Returns true once the mux is closed
/// and the pipe has been released.
pub(crate) fn flush_endpoint(sim: &mut Sim, dev: DevId, ep: &mut Endpoint) -> bool {
    while let Some(bytes) = ep.mux.poll_transmit(sim.mono()) {
        if bytes.get(4) != Some(&frame_type::GOAWAY) {
            sim.check_deadline(dev, ep, "sent a frame");
        }
        sim.transmit(ep.conn, ep.side, bytes);
    }
    if ep.mux.is_closed() {
        sim.close_pipe(ep.conn, ep.side);
        true
    } else {
        false
    }
}
