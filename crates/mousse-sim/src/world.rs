//! The world: devices, the event loop, the modelled TLS handshake, scripted
//! actions and the checks that need more than one device.

use mousse_net_core::authz::GateState;
use mousse_net_core::grants::{Denial, Grant};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::{InvitationId, SessionExporters};
use mousse_net_core::session_cert::{CertError, SessionCertificate, VerifiedSessionCert};
use mousse_net_core::{ConnectionId, ErrorCode, Limits, UnixTime};

const CLOCK_SKEW_SECS: u64 = Limits::DEFAULT.clock_skew_secs();
use rand_core::Rng;

use crate::caller::{CallerDev, Mode, Outcome, WRONG_ENDPOINT};
use crate::certs;
use crate::check::Invariant;
use crate::host::HostDev;
use crate::sim::{AuthInfo, DevId, Ev, PipeState, Side, Sim};
use crate::Bug;

/// A scripted action: what people, the network and the drill do.
#[derive(Clone, Debug)]
pub(crate) enum Script {
    /// The host owner answers "Is the device next to you?".
    OwnerDecides {
        host: DevId,
        invitation: InvitationId,
        conn: ConnectionId,
    },
    /// A host drops one connection (used by the fake host).
    HostDrops {
        host: DevId,
        conn: ConnectionId,
    },
    HostCancels {
        host: DevId,
    },
    TypeCode {
        dev: DevId,
    },
    JoinerResends {
        dev: DevId,
    },
    JoinerDrops {
        dev: DevId,
    },
    JoinerSwitchesRoute {
        dev: DevId,
    },
    JoinerStarts {
        dev: DevId,
    },
    PairedStarts {
        dev: DevId,
    },
    IntruderStarts {
        dev: DevId,
    },
    PathSwitch {
        dev: DevId,
    },
    Partition {
        route: usize,
        on: bool,
    },
    /// New dials on the route are refused (existing pipes keep working).
    Refuse {
        route: usize,
        on: bool,
    },
    /// Dials on the route reach another device.
    Hijack {
        route: usize,
        by: Option<DevId>,
    },
    Crash {
        dev: DevId,
        keep: bool,
        down_ms: u64,
    },
    Restart {
        dev: DevId,
        keep: bool,
    },
    RemoveDevice {
        host: DevId,
        of: DevId,
        deny: bool,
    },
    /// The owner pairs a device again (a grant added directly).
    AddDevice {
        host: DevId,
        of: DevId,
    },
    ClockJump {
        dev: DevId,
        secs: i64,
    },
}

pub(crate) enum Device {
    Host(Box<HostDev>),
    Caller(Box<CallerDev>),
}

/// Device `id` as a host. Drills only ask for hosts by the ids they created
/// as hosts.
fn host_of(devs: &mut [Device], id: DevId) -> &mut HostDev {
    match &mut devs[id] {
        Device::Host(h) => h,
        Device::Caller(_) => panic!("device {id} is not a host"),
    }
}

/// Device `id` as a caller.
fn caller_of(devs: &mut [Device], id: DevId) -> &mut CallerDev {
    match &mut devs[id] {
        Device::Caller(c) => c,
        Device::Host(_) => panic!("device {id} is not a caller"),
    }
}

pub(crate) struct World {
    pub sim: Sim,
    pub devs: Vec<Device>,
    wake_at: Vec<Option<u64>>,
    pub end_ms: u64,
    /// End the run a little after every caller is settled.
    pub stop_when_settled: bool,
    pub refusing: Vec<bool>,
    /// Endpoints that share one computer (one per profile).
    pub machine: Vec<DevId>,
    /// `(endpoint, identity)` grants the shared endpoints start with.
    machine_grants: Vec<(DevId, IdentityPublicKey)>,
    /// `(endpoint, identity)` pairs the owner removed or denied there.
    removed_on: Vec<(DevId, IdentityPublicKey)>,
}

/// What another endpoint looked like before an owner action.
struct EndpointSnapshot {
    grants: Vec<Grant>,
    denials: Vec<Denial>,
    live: Vec<ConnectionId>,
}

impl World {
    pub(crate) fn new(sim: Sim) -> Self {
        Self {
            sim,
            devs: Vec::new(),
            wake_at: Vec::new(),
            end_ms: 0,
            stop_when_settled: false,
            refusing: Vec::new(),
            machine: Vec::new(),
            machine_grants: Vec::new(),
            removed_on: Vec::new(),
        }
    }

    /// Register a device slot; returns its id.
    fn slot(&mut self, name: &'static str, key_label: &'static str, skew: i64) -> DevId {
        self.sim.names.push(name);
        self.sim.key_labels.push(key_label);
        self.sim.skews.push(skew);
        self.sim
            .identities
            .push(certs::identity_key(key_label).public_key());
        self.wake_at.push(None);
        self.sim.names.len() - 1
    }

    /// Add a host whose certificates last `lifetime` seconds.
    pub(crate) fn add_host(&mut self, name: &'static str, skew: i64, lifetime: u64) -> DevId {
        let id = self.slot(name, name, skew);
        let host = HostDev::new(&mut self.sim, id, name, lifetime);
        self.devs.push(Device::Host(Box::new(host)));
        id
    }

    /// Add a calling device. Callers with the same `key_label` share one
    /// identity key.
    pub(crate) fn add_caller(
        &mut self,
        name: &'static str,
        key_label: &'static str,
        skew: i64,
        lifetime: u64,
    ) -> DevId {
        let id = self.slot(name, key_label, skew);
        let caller = CallerDev::new(&mut self.sim, id, name, lifetime);
        self.devs.push(Device::Caller(Box::new(caller)));
        id
    }

    /// A host and the engine, borrowed together.
    pub(crate) fn hs(&mut self, id: DevId) -> (&mut HostDev, &mut Sim) {
        match &mut self.devs[id] {
            Device::Host(h) => (h, &mut self.sim),
            Device::Caller(_) => panic!("device {id} is not a host"),
        }
    }

    /// A caller and the engine, borrowed together.
    pub(crate) fn cs(&mut self, id: DevId) -> (&mut CallerDev, &mut Sim) {
        match &mut self.devs[id] {
            Device::Caller(c) => (c, &mut self.sim),
            Device::Host(_) => panic!("device {id} is not a caller"),
        }
    }

    pub(crate) fn at(&mut self, ms: u64, script: Script) {
        self.sim.schedule(ms, Ev::Script(script));
    }

    // ---- the loop ---------------------------------------------------------------

    pub(crate) fn run(&mut self) {
        for &e in &self.machine {
            if let Device::Host(h) = &self.devs[e] {
                for g in h.grants.grants() {
                    self.machine_grants.push((e, g.identity));
                }
            }
        }
        let mut settled_at: Option<u64> = None;
        while let Some((t, ev)) = self.sim.pop() {
            if t > self.end_ms {
                self.sim.now = self.end_ms;
                break;
            }
            self.sim.now = t;
            self.sim.events += 1;
            self.dispatch(ev);
            self.after_step();
            if self.sim.check.violation.is_some() {
                return;
            }
            if self.stop_when_settled && settled_at.is_none() && self.all_settled() {
                settled_at = Some(t);
                self.end_ms = self.end_ms.min(t + 5_000);
            }
        }
        self.end_checks();
    }

    fn all_settled(&self) -> bool {
        self.devs.iter().all(|d| match d {
            Device::Caller(c) => c.is_settled(),
            Device::Host(_) => true,
        })
    }

    fn dispatch(&mut self, ev: Ev) {
        match ev {
            Ev::Deliver { conn, to, bytes } => {
                let Some(pipe) = self.sim.pipes.get(&conn) else {
                    return;
                };
                if pipe.state == PipeState::Blackholed || !self.sim.attached(conn, to) {
                    return;
                }
                let (client, server) = (pipe.client, pipe.server);
                if let Device::Caller(c) = &self.devs[client] {
                    if c.host_dev != server {
                        let (who, at) = (self.sim.names[client], self.sim.names[server]);
                        self.sim.fail(
                            Invariant::WrongEndpointNoData,
                            format!(
                                "conn {} from {who} reached {at}, not its own endpoint, and carried {} bytes",
                                conn.0,
                                bytes.len()
                            ),
                        );
                    }
                }
                let dev = match to {
                    Side::Client => client,
                    Side::Server => server,
                };
                match &mut self.devs[dev] {
                    Device::Host(h) => h.on_bytes(&mut self.sim, conn, &bytes),
                    Device::Caller(c) => c.on_bytes(&mut self.sim, conn, &bytes),
                }
            }
            Ev::Eof { conn, to } => {
                let Some(pipe) = self.sim.pipes.get(&conn) else {
                    return;
                };
                if !self.sim.attached(conn, to) {
                    return;
                }
                let dev = match to {
                    Side::Client => pipe.client,
                    Side::Server => pipe.server,
                };
                self.pipe_closed(dev, conn, false);
                self.sim.detach(conn, to);
            }
            Ev::Break { conn } => {
                let Some(pipe) = self.sim.pipes.get(&conn) else {
                    return;
                };
                let (client, server) = (pipe.client, pipe.server);
                for (side, dev) in [(Side::Client, client), (Side::Server, server)] {
                    if self.sim.attached(conn, side) {
                        self.pipe_closed(dev, conn, true);
                        self.sim.detach(conn, side);
                    }
                }
                self.sim.pipes.remove(&conn);
            }
            Ev::DialDone { conn } => self.handshake(conn),
            Ev::Wake { dev, at } => {
                if self.wake_at[dev] == Some(at) {
                    self.wake_at[dev] = None;
                    match &mut self.devs[dev] {
                        Device::Host(h) => h.run_timers(&mut self.sim),
                        Device::Caller(c) => c.run_timers(&mut self.sim),
                    }
                }
            }
            Ev::Script(s) => self.script(s),
        }
    }

    fn pipe_closed(&mut self, dev: DevId, conn: ConnectionId, abrupt: bool) {
        match &mut self.devs[dev] {
            Device::Host(h) => {
                h.run_timers(&mut self.sim);
                h.on_pipe_closed(&mut self.sim, conn, abrupt)
            }
            Device::Caller(c) => {
                c.run_timers(&mut self.sim);
                c.on_pipe_closed(&mut self.sim, conn, abrupt)
            }
        }
    }

    fn after_step(&mut self) {
        // Timers due at this same millisecond run before the checks. Another
        // event at this time may have been taken from the queue first, and
        // the state is only judged once every device has caught up.
        for id in 0..self.devs.len() {
            if self.wake_at[id].is_some_and(|at| at <= self.sim.now) {
                self.wake_at[id] = None;
                match &mut self.devs[id] {
                    Device::Host(h) => h.run_timers(&mut self.sim),
                    Device::Caller(c) => c.run_timers(&mut self.sim),
                }
            }
        }
        for dev in &mut self.devs {
            match dev {
                Device::Host(h) => h.flush(&mut self.sim),
                Device::Caller(c) => c.flush(&mut self.sim),
            }
        }
        for dev in &mut self.devs {
            match dev {
                Device::Host(h) => h.check(&mut self.sim),
                Device::Caller(c) => c.check(&mut self.sim),
            }
        }
        self.check_new_pairings();
        self.check_machine_grants();
        for id in 0..self.devs.len() {
            let next = match &self.devs[id] {
                Device::Host(h) => h.next_wake(&self.sim),
                Device::Caller(c) => c.next_wake(&self.sim),
            };
            if let Some(at) = next {
                if self.wake_at[id] != Some(at) {
                    self.wake_at[id] = Some(at);
                    self.sim.schedule(at, Ev::Wake { dev: id, at });
                }
            } else {
                self.wake_at[id] = None;
            }
        }
    }

    // ---- handshake (the TLS model) ---------------------------------------------

    fn handshake(&mut self, conn: ConnectionId) {
        let Some(pipe) = self.sim.pipes.get(&conn) else {
            return;
        };
        let (client, route, state) = (pipe.client, pipe.route, pipe.state);
        if !matches!(&self.devs[client], Device::Caller(c) if c.wants(conn)) {
            self.sim.pipes.remove(&conn);
            return;
        }
        let r = &self.sim.routes[route];
        let server = r.hijack.unwrap_or(r.target);
        let failure = if r.partitioned || state == PipeState::Blackholed {
            Some("no route to host")
        } else if self.refusing.get(route).copied().unwrap_or(false)
            || !matches!(&self.devs[server], Device::Host(h) if h.up)
        {
            Some("connection refused")
        } else {
            None
        };
        if let Some(why) = failure {
            self.sim.pipes.remove(&conn);
            caller_of(&mut self.devs, client).on_dial_failed(&mut self.sim, conn, why);
            return;
        }
        let server_cert = host_of(&mut self.devs, server).current_cert(&mut self.sim);
        let client_cert = caller_of(&mut self.devs, client).current_cert(&mut self.sim);
        let pin = caller_of(&mut self.devs, client).pin_for_dial(&self.sim);
        let full = self.sim.cfg.full_verify;

        // TLS 1.3: the client checks the server's certificate first.
        let client_wall = self.sim.wall(client);
        let at_client = certs::verify(server_cert.der(), client_wall, pin.as_ref(), full);
        let at_client = self.planted_window_skip(at_client, &server_cert, pin.as_ref());
        self.step1_oracle(client, &server_cert, client_wall, pin, &at_client);
        let at_client = match at_client {
            Ok(v) => v,
            Err(e) => {
                let (c, s) = (self.sim.names[client], self.sim.names[server]);
                self.sim.note(
                    c,
                    format_args!("rejects {s}'s certificate on conn {}: {}", conn.0, e.code()),
                );
                self.sim.pipes.remove(&conn);
                let why = if e == CertError::PinMismatch {
                    WRONG_ENDPOINT
                } else {
                    "handshake failed"
                };
                caller_of(&mut self.devs, client).on_dial_failed(&mut self.sim, conn, why);
                return;
            }
        };
        let server_wall = self.sim.wall(server);
        let at_server = certs::verify(client_cert.der(), server_wall, None, full);
        let at_server = self.planted_window_skip(at_server, &client_cert, None);
        self.step1_oracle(server, &client_cert, server_wall, None, &at_server);
        let at_server = match at_server {
            Ok(v) => v,
            Err(e) => {
                let (c, s) = (self.sim.names[client], self.sim.names[server]);
                self.sim.note(
                    s,
                    format_args!("rejects {c}'s certificate on conn {}: {}", conn.0, e.code()),
                );
                self.sim.pipes.remove(&conn);
                caller_of(&mut self.devs, client).on_dial_failed(
                    &mut self.sim,
                    conn,
                    "handshake failed",
                );
                return;
            }
        };
        let mut exporters = SessionExporters {
            join: [0; 32],
            pair: [0; 32],
        };
        self.sim.rng.fill_bytes(&mut exporters.join);
        self.sim.rng.fill_bytes(&mut exporters.pair);
        let deadline = UnixTime(
            client_cert
                .window()
                .not_after()
                .secs()
                .min(server_cert.window().not_after().secs())
                + CLOCK_SKEW_SECS,
        );
        self.sim.mark_open(conn, server);
        let server_auth = AuthInfo {
            peer: at_server,
            local_window: server_cert.window(),
            exporters,
            deadline,
        };
        let client_auth = AuthInfo {
            peer: at_client,
            local_window: client_cert.window(),
            exporters,
            deadline,
        };
        let host = host_of(&mut self.devs, server);
        host.run_timers(&mut self.sim);
        let host = host_of(&mut self.devs, server);
        host.on_accepted(&mut self.sim, conn, server_auth);
        let caller = caller_of(&mut self.devs, client);
        caller.run_timers(&mut self.sim);
        let caller = caller_of(&mut self.devs, client);
        caller.on_connected(&mut self.sim, conn, client_auth);
    }

    /// Planted bug: the verifier ignores the validity window, so a
    /// certificate outside it is accepted (as if checked at its start).
    fn planted_window_skip(
        &self,
        got: Result<VerifiedSessionCert, CertError>,
        cert: &SessionCertificate,
        pin: Option<&IdentityPublicKey>,
    ) -> Result<VerifiedSessionCert, CertError> {
        match got {
            Err(CertError::OutsideWindow) if self.sim.bug(Bug::AcceptExpiredCert) => {
                let start = cert.window().not_before();
                certs::verify(cert.der(), start, pin, self.sim.cfg.full_verify)
            }
            other => other,
        }
    }

    /// Step 1 must accept exactly when the spec's window and pin rules say.
    fn step1_oracle(
        &mut self,
        verifier: DevId,
        cert: &SessionCertificate,
        now: UnixTime,
        pin: Option<IdentityPublicKey>,
        got: &Result<VerifiedSessionCert, CertError>,
    ) {
        let nb = cert.window().not_before().secs();
        let na = cert.window().not_after().secs();
        let n = now.secs();
        // The pin comes before the window (wire.md 5.4, checks 9 and 10).
        let expected = if pin.is_some_and(|p| p != *cert.identity()) {
            Err(CertError::PinMismatch)
        } else if n + CLOCK_SKEW_SECS < nb || n > na + CLOCK_SKEW_SECS {
            Err(CertError::OutsideWindow)
        } else {
            Ok(())
        };
        let got = got.as_ref().map(|_| ()).map_err(|e| *e);
        if got != expected {
            let name = self.sim.names[verifier];
            self.sim.fail(
                Invariant::Step1Spec,
                format!(
                    "{name} at wall {n} on window {nb}..{na}: core said {got:?}, the spec says {expected:?}"
                ),
            );
        }
    }

    // ---- scripted actions ---------------------------------------------------------

    fn script(&mut self, s: Script) {
        match s {
            Script::OwnerDecides {
                host,
                invitation,
                conn,
            } => host_of(&mut self.devs, host).owner_decides(&mut self.sim, invitation, conn),
            Script::HostDrops { host, conn } => {
                let h = host_of(&mut self.devs, host);
                if h.up {
                    h.close(&mut self.sim, conn, ErrorCode::NoError);
                }
            }
            Script::HostCancels { host } => {
                let h = host_of(&mut self.devs, host);
                if h.up {
                    h.cancel_invitations(&mut self.sim);
                }
            }
            Script::TypeCode { dev } => {
                let host = caller_of(&mut self.devs, dev).host_dev;
                let shown = match &self.devs[host] {
                    Device::Host(h) if !h.malicious => h.shown_code.clone(),
                    _ => None,
                };
                let c = caller_of(&mut self.devs, dev);
                c.run_timers(&mut self.sim);
                let c = caller_of(&mut self.devs, dev);
                c.type_code(&mut self.sim, shown);
            }
            Script::JoinerResends { dev } => caller_of(&mut self.devs, dev).resend(&mut self.sim),
            Script::JoinerDrops { dev } => {
                caller_of(&mut self.devs, dev).drop_connection(&mut self.sim, false)
            }
            Script::JoinerSwitchesRoute { dev } => {
                caller_of(&mut self.devs, dev).drop_connection(&mut self.sim, true)
            }
            Script::JoinerStarts { dev } => {
                caller_of(&mut self.devs, dev).start_joining(&mut self.sim)
            }
            Script::PairedStarts { dev } => {
                let c = caller_of(&mut self.devs, dev);
                if let Some(pin) = c.expected_host {
                    c.start_paired(&mut self.sim, pin);
                }
            }
            Script::IntruderStarts { dev } => {
                caller_of(&mut self.devs, dev).start_intruder(&mut self.sim)
            }
            Script::PathSwitch { dev } => {
                let c = caller_of(&mut self.devs, dev);
                c.run_timers(&mut self.sim);
                let c = caller_of(&mut self.devs, dev);
                c.path_switch(&mut self.sim);
            }
            Script::Partition { route, on } => {
                let name = self.sim.routes[route].name;
                self.sim.note(
                    "net",
                    format_args!("{} {name}", if on { "partitions" } else { "heals" }),
                );
                self.sim.set_partition(route, on);
            }
            Script::Refuse { route, on } => {
                let name = self.sim.routes[route].name;
                self.sim.note(
                    "net",
                    format_args!(
                        "{} new connections on {name}",
                        if on { "refuses" } else { "accepts" }
                    ),
                );
                if self.refusing.len() <= route {
                    self.refusing.resize(route + 1, false);
                }
                self.refusing[route] = on;
            }
            Script::Hijack { route, by } => {
                let name = self.sim.routes[route].name;
                match by {
                    Some(d) => {
                        let who = self.sim.names[d];
                        self.sim
                            .note("net", format_args!("{who} now answers on {name}"))
                    }
                    None => self
                        .sim
                        .note("net", format_args!("{name} reaches its own host again")),
                }
                self.sim.routes[route].hijack = by;
            }
            Script::Crash { dev, keep, down_ms } => {
                self.sim.say(dev, format_args!("crashes"));
                match &mut self.devs[dev] {
                    Device::Host(h) => {
                        if !h.up {
                            return;
                        }
                        h.crash(&mut self.sim)
                    }
                    Device::Caller(c) => {
                        if !c.up {
                            return;
                        }
                        c.crash(&mut self.sim)
                    }
                }
                self.sim.after(down_ms, Script::Restart { dev, keep });
            }
            Script::Restart { dev, keep } => {
                self.sim.say(
                    dev,
                    format_args!(
                        "starts again, stored state {}",
                        if keep { "kept" } else { "lost" }
                    ),
                );
                match &mut self.devs[dev] {
                    Device::Host(h) => h.start_again(&mut self.sim, keep),
                    Device::Caller(c) => {
                        c.up = true;
                        match (&c.mode, keep) {
                            (Mode::Paired(s), true) => {
                                let pin = *s.pin();
                                c.start_paired(&mut self.sim, pin);
                            }
                            (Mode::Joining(_), _) => c.start_joining(&mut self.sim),
                            _ => c.mode = Mode::Done,
                        }
                    }
                }
            }
            Script::RemoveDevice { host, of, deny } => self.remove_device(host, of, deny),
            Script::AddDevice { host, of } => {
                let (identity, name) = (self.sim.identities[of], self.sim.key_labels[of]);
                let (h, sim) = self.hs(host);
                if h.up {
                    h.run_timers(sim);
                    h.add_grant(sim, identity, name, None);
                }
            }
            Script::ClockJump { dev, secs } => {
                self.sim.skews[dev] += secs;
                self.sim
                    .say(dev, format_args!("wall clock jumps by {secs} s"));
            }
        }
    }

    // ---- multi-device checks ----------------------------------------------------

    /// A joiner that just accepted `PAIRED` must match a host enrollment.
    fn check_new_pairings(&mut self) {
        for id in 0..self.devs.len() {
            let (paired, me, host_dev, label) = match &mut self.devs[id] {
                Device::Caller(c) => match c.just_paired.take() {
                    Some(p) => (p, c.identity, c.host_dev, c.label),
                    None => continue,
                },
                Device::Host(_) => continue,
            };
            let ok = match &self.devs[host_dev] {
                Device::Host(h) => {
                    h.identity == paired.identity
                        && h.enrolled
                            .iter()
                            .any(|(_, ident, _, role)| *ident == me && *role == paired.role)
                }
                Device::Caller(_) => false,
            };
            if !ok {
                self.sim.fail(
                    Invariant::PairingAgreement,
                    format!(
                        "{label} accepted PAIRED as {} but the host has no matching enrollment",
                        paired.role.as_str()
                    ),
                );
            }
        }
    }

    /// At the end: a joiner the host enrolled (and still grants) did not end
    /// its flow as failed.
    fn end_checks(&mut self) {
        let mut problems = Vec::new();
        for c in self.devs.iter().filter_map(|d| match d {
            Device::Caller(c) if c.ticket.is_some() => Some(c),
            _ => None,
        }) {
            let Device::Host(h) = &self.devs[c.host_dev] else {
                continue;
            };
            if h.malicious || !h.up {
                continue;
            }
            for (_, ident, grant, _) in &h.enrolled {
                if *ident != c.identity || h.grants.get(*grant).is_none() {
                    continue;
                }
                if let Outcome::Failed(code) = &c.outcome {
                    problems.push(format!(
                        "{} holds grant {} from this pairing, but {}'s flow ended as failed ({code:?})",
                        h.label, grant.0, c.label
                    ));
                }
            }
        }
        for p in problems {
            self.sim.fail(Invariant::PairingAgreement, p);
        }
    }

    // ---- endpoints that share a computer -------------------------------------------

    /// The owner removes or denies a device on one endpoint. Every other
    /// endpoint on the same computer must come through unchanged.
    fn remove_device(&mut self, host: DevId, of: DevId, deny: bool) {
        let identity = self.sim.identities[of];
        let others: Vec<DevId> = if self.machine.contains(&host) {
            self.machine
                .iter()
                .copied()
                .filter(|d| *d != host)
                .collect()
        } else {
            Vec::new()
        };
        for &d in std::iter::once(&host).chain(&others) {
            let (h, sim) = self.hs(d);
            h.run_timers(sim);
        }
        let before: Vec<EndpointSnapshot> = others.iter().map(|&o| self.snapshot(o)).collect();
        let (h, sim) = self.hs(host);
        h.remove_device(sim, identity, deny);
        self.removed_on.push((host, identity));
        if self.sim.bug(Bug::SharedGrantTable) {
            // Planted bug: one grant table for the whole computer.
            for &o in &others {
                let (h, sim) = self.hs(o);
                h.remove_device(sim, identity, deny);
            }
        }
        for (&o, before) in others.iter().zip(before) {
            self.check_isolation(host, o, before);
        }
    }

    fn snapshot(&mut self, endpoint: DevId) -> EndpointSnapshot {
        let h = host_of(&mut self.devs, endpoint);
        EndpointSnapshot {
            grants: h.grants.grants().cloned().collect(),
            denials: h.grants.denials().collect(),
            live: h
                .conns
                .iter()
                .filter(|(_, c)| !c.closing && matches!(c.gate.state(), GateState::Live { .. }))
                .map(|(conn, _)| *conn)
                .collect(),
        }
    }

    fn check_isolation(&mut self, acted: DevId, other: DevId, before: EndpointSnapshot) {
        let after = self.snapshot(other);
        let (a, o) = (self.sim.names[acted], self.sim.names[other]);
        let mut problems = Vec::new();
        if after.grants != before.grants {
            problems.push(format!(
                "an owner action on {a} changed the grants of {o} ({} before, {} after)",
                before.grants.len(),
                after.grants.len()
            ));
        }
        if after.denials != before.denials {
            problems.push(format!("an owner action on {a} changed the denials of {o}"));
        }
        for conn in before.live {
            if !after.live.contains(&conn) {
                problems.push(format!(
                    "an owner action on {a} closed conn {} of {o}",
                    conn.0
                ));
            }
        }
        for p in problems {
            self.sim.fail(Invariant::EndpointIsolation, p);
        }
    }

    /// A grant a shared endpoint started with stays live unless the owner
    /// removed it on that same endpoint.
    fn check_machine_grants(&mut self) {
        let mut problems = Vec::new();
        for &(e, identity) in &self.machine_grants {
            if self.removed_on.contains(&(e, identity)) {
                continue;
            }
            let Device::Host(h) = &self.devs[e] else {
                continue;
            };
            if h.up && h.grants.live_grant(&identity, self.sim.wall(e)).is_none() {
                problems.push(format!(
                    "{} lost the grant of {} without an owner action there",
                    h.label,
                    self.sim.who(&identity)
                ));
            }
        }
        for p in problems {
            self.sim.fail(Invariant::EndpointIsolation, p);
        }
    }
}
