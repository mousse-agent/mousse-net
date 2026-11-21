//! The `relay-admission` drill: one self-hosted relay (the core's
//! [`Relay`] admission machine) with targets, callers, joiners and an
//! operator acting at seeded times, across reboots and key rotation.
//!
//! The drill keeps its own model of what each target has told the relay
//! (its registration and its last accepted allow-set) and of each
//! circuit, built only from what the relay sent, and checks after every
//! output:
//!
//! - an `INCOMING` only for a caller in the target's current allow-set (or
//!   a joiner with a live invitation tag), with a valid proof;
//! - every refused `CALL` or `JOIN` is answered `UNREACHABLE` exactly at
//!   its refusal deadline, and an admitted one never earlier;
//! - after an allow-set is accepted, no call circuit of a caller it no
//!   longer lists is open;
//! - an unpromoted join circuit never forwards more than the pre-accept
//!   budget either way;
//! - `REGISTERED` only for a key on the operator's list.
//!
//! The relay's I/O layer is the drill's own; the planted bugs live there.
//!
//! [`Relay`]: mousse_net_core::relay::Relay

use std::collections::{BTreeMap, BTreeSet};

use mousse_net_core::identity::{RawSignature, SoftwareKey};
use mousse_net_core::pairing::{InvitationId, TicketSecret};
use mousse_net_core::relay::machine::{
    AuthorizedKey, ConnId, IpKey, Now, Output, Relay, RelayConfig,
};
use mousse_net_core::relay::msg::InvitationEntry;
use mousse_net_core::relay::{
    proof, Binding, Class, RelayClientKey, RelayId, RelayLimits, RelayMessage,
};
use mousse_net_core::time::{Millis, UnixTime};
use sha2::{Digest, Sha256};

use crate::sim::Sim;
use crate::{Bug, Invariant};

pub(crate) const RELAY_VARIANTS: &[&str] = &["calls", "removal", "joins", "reboot", "rotation"];

const WALL0: u64 = 1_790_000_000;
const SEC: u64 = 1_000;

/// Target slots: 0 and 1 are on the operator's list, 2 never is, 3 is
/// target 0's successor key.
const TARGETS: usize = 4;
const SUCCESSOR_OF_0: usize = 3;
const UNLISTED_TARGET: usize = 2;
/// Caller slots; the last one is a stranger no target ever lists.
const CALLERS: usize = 5;
const STRANGER: usize = CALLERS - 1;
const INVITATIONS: usize = 3;

/// A pushed allow-set: callers, invitations, and its bytes.
type PendingSet = (BTreeSet<[u8; 32]>, Vec<InvitationEntry>, Vec<u8>);

struct Target {
    key: RelayClientKey,
    reg: Option<ConnId>,
    /// The allow-set the relay last accepted on the live registration.
    allow: Option<(BTreeSet<[u8; 32]>, Vec<InvitationEntry>)>,
    /// Pushed, not yet answered.
    pending: Option<PendingSet>,
    /// The bytes of the last accepted allow-set (for the stale-set bug).
    last_bytes: Option<Vec<u8>>,
    sequence: u64,
    incoming: Vec<[u8; 16]>,
}

#[derive(Clone, Copy)]
struct Leg {
    arrived: u64,
    admitted: bool,
}

#[derive(Clone)]
struct Circ {
    handle: [u8; 32],
    caller: Option<[u8; 32]>,
    leg: ConnId,
    accept: Option<ConnId>,
    sent: [u64; 2],
}

struct Drive<'a> {
    sim: &'a mut Sim,
    relay: Relay,
    rid: RelayId,
    relay_key: SoftwareKey,
    limits: RelayLimits,
    next_conn: u64,
    open: BTreeSet<ConnId>,
    bindings: BTreeMap<ConnId, Binding>,
    targets: Vec<Target>,
    callers: Vec<RelayClientKey>,
    legs: BTreeMap<ConnId, Leg>,
    circuits: BTreeMap<[u8; 16], Circ>,
    /// The durable authorized list, as the relay's outputs left it.
    authorized: BTreeMap<[u8; 32], AuthorizedKey>,
    secrets: [TicketSecret; INVITATIONS],
    reboots: u32,
    /// The tag each join leg sent.
    join_tags: BTreeMap<ConnId, [u8; 32]>,
    /// Call legs whose proof was made with the wrong key.
    bad_proofs: BTreeSet<ConnId>,
    /// Allow-sets from before the last reboot (for the stale-set bug).
    stale: BTreeMap<usize, Vec<u8>>,
}

fn client_key(sim: &mut Sim) -> RelayClientKey {
    loop {
        let mut b = [0u8; 32];
        rand_core::Rng::fill_bytes(&mut sim.rng, &mut b);
        if let Ok(k) = SoftwareKey::from_secret_bytes(&b) {
            return RelayClientKey::new(k);
        }
    }
}

fn hex6(b: &[u8]) -> String {
    b[..3].iter().map(|x| format!("{x:02x}")).collect()
}

impl<'a> Drive<'a> {
    fn new(sim: &'a mut Sim) -> Self {
        let relay_key = loop {
            let mut b = [0u8; 32];
            rand_core::Rng::fill_bytes(&mut sim.rng, &mut b);
            if let Ok(k) = SoftwareKey::from_secret_bytes(&b) {
                break k;
            }
        };
        let refuse = sim.range(500, 1_500);
        let limits = RelayLimits::DEFAULT
            .with_overrides(&[
                ("RELAY_REFUSE_MS", refuse),
                ("RELAY_ACCEPT_WAIT_MS", sim.range(refuse + 500, 10_000)),
                ("RELAY_PREACCEPT_BYTES", sim.range(16_384, 65_536)),
                ("RELAY_PREACCEPT_PER_TARGET", sim.range(1, 4)),
                ("RELAY_CIRCUITS_PER_CALLER", sim.range(2, 8)),
                ("RELAY_SUCCESSOR_OVERLAP_SECS", 86_400),
            ])
            .expect("drill limits");
        let targets = (0..TARGETS)
            .map(|_| Target {
                key: client_key(sim),
                reg: None,
                allow: None,
                pending: None,
                last_bytes: None,
                sequence: 0,
                incoming: Vec::new(),
            })
            .collect::<Vec<_>>();
        let callers = (0..CALLERS).map(|_| client_key(sim)).collect();
        let secrets = std::array::from_fn(|i| TicketSecret::from_bytes([i as u8 + 1; 16]));
        let authorized: BTreeMap<[u8; 32], AuthorizedKey> = [0, 1]
            .iter()
            .map(|&t| {
                let fp = targets[t].key.fingerprint();
                (fp, AuthorizedKey::listed(fp))
            })
            .collect();
        let rid = RelayId::of(&relay_key.public_key());
        let relay = Self::boot(&relay_key, limits, &authorized, 0);
        sim.note(
            "relay",
            format_args!(
                "limits refuse={}ms accept={}ms budget={} joins={} per-caller={}",
                limits.refuse_ms(),
                limits.accept_wait_ms(),
                limits.preaccept_bytes(),
                limits.preaccept_per_target(),
                limits.circuits_per_caller()
            ),
        );
        Self {
            sim,
            relay,
            rid,
            relay_key,
            limits,
            next_conn: 1,
            open: BTreeSet::new(),
            bindings: BTreeMap::new(),
            targets,
            callers,
            legs: BTreeMap::new(),
            circuits: BTreeMap::new(),
            authorized,
            secrets,
            reboots: 0,
            join_tags: BTreeMap::new(),
            bad_proofs: BTreeSet::new(),
            stale: BTreeMap::new(),
        }
    }

    fn boot(
        key: &SoftwareKey,
        limits: RelayLimits,
        authorized: &BTreeMap<[u8; 32], AuthorizedKey>,
        n: u32,
    ) -> Relay {
        let list: Vec<AuthorizedKey> = authorized.values().copied().collect();
        Relay::new(
            RelayConfig {
                relay_key: key.public_key(),
                boot_id: [n as u8; 16],
                limits,
            },
            &list,
            &[],
        )
    }

    fn now(&self) -> Now {
        Now {
            mono: Millis(self.sim.now),
            wall: UnixTime(WALL0 + self.sim.now / SEC),
        }
    }

    fn failed(&self) -> bool {
        self.sim.check.violation.is_some()
    }

    // ---- time -------------------------------------------------------------

    /// Move to `to`, firing the relay's waits at their exact times.
    fn advance(&mut self, to: u64) {
        // `relay-early-answer`: the timer runs on a clock half a refusal
        // ahead of the one the rest of the relay uses.
        let ahead = if self.sim.bug(Bug::RelayEarlyAnswer) {
            self.limits.refuse_ms() / 2
        } else {
            0
        };
        while let Some(m) = self.relay.next_wake() {
            let at = m.0.saturating_sub(ahead).max(self.sim.now);
            if at > to || self.failed() {
                break;
            }
            self.sim.now = at;
            let now = Now {
                mono: Millis(at + ahead),
                ..self.now()
            };
            let outs = self.relay.tick(now, &mut self.sim.rng);
            self.process(outs, None);
            self.check_unanswered();
        }
        self.sim.now = to.max(self.sim.now);
        let now = self.now();
        let outs = self.relay.tick(now, &mut self.sim.rng);
        self.process(outs, None);
        self.check_unanswered();
    }

    fn wait(&mut self, ms: u64) {
        let to = self.sim.now + ms;
        self.advance(to);
    }

    fn check_unanswered(&mut self) {
        let refuse = self.limits.refuse_ms();
        let late: Vec<ConnId> = self
            .legs
            .iter()
            .filter(|(c, l)| {
                !l.admitted && self.open.contains(c) && l.arrived + refuse < self.sim.now
            })
            .map(|(c, _)| *c)
            .collect();
        for c in late {
            self.sim.fail(
                Invariant::RelayOneAnswer,
                format!("refused leg {} has no answer after its deadline", c.0),
            );
        }
    }

    // ---- connections ------------------------------------------------------

    fn open_conn(&mut self) -> Option<ConnId> {
        let conn = ConnId(self.next_conn);
        self.next_conn += 1;
        let exporter: [u8; 32] = Sha256::digest(conn.0.to_be_bytes()).into();
        let mut ip = [0u8; 16];
        ip[0] = self.sim.range(1, 3) as u8;
        let now = self.now();
        let outs = self
            .relay
            .open(conn, IpKey(ip), exporter, now, &mut self.sim.rng);
        for o in &outs {
            if let Output::Send { message, .. } = o {
                if let Ok(RelayMessage::Hello { nonce, .. }) = RelayMessage::decode(message) {
                    self.bindings.insert(conn, Binding { nonce, exporter });
                    self.open.insert(conn);
                }
            }
        }
        self.process(outs, None);
        self.open.contains(&conn).then_some(conn)
    }

    fn send(&mut self, conn: ConnId, msg: &RelayMessage) {
        self.send_raw(conn, &msg.encode());
    }

    fn send_raw(&mut self, conn: ConnId, bytes: &[u8]) {
        let now = self.now();
        let outs = self.relay.receive(conn, bytes, now, &mut self.sim.rng);
        self.process(outs, Some(conn));
    }

    fn close(&mut self, conn: ConnId) {
        let now = self.now();
        self.forget(conn);
        let outs = self.relay.closed(conn, now, &mut self.sim.rng);
        self.process(outs, None);
    }

    /// The model side of a connection ending.
    fn forget(&mut self, conn: ConnId) {
        self.open.remove(&conn);
        self.legs.remove(&conn);
        for t in &mut self.targets {
            if t.reg == Some(conn) {
                t.reg = None;
                t.allow = None;
                t.pending = None;
            }
        }
        self.circuits
            .retain(|_, c| c.leg != conn && c.accept != Some(conn));
    }

    // ---- what the relay said ------------------------------------------------

    fn process(&mut self, outs: Vec<Output>, from: Option<ConnId>) {
        self.sim.events += 1;
        for out in outs {
            if self.failed() {
                return;
            }
            match out {
                Output::Send { conn, message } => {
                    let msg = RelayMessage::decode(&message).expect("relay output decodes");
                    self.on_send(conn, msg, from);
                }
                Output::Close { conn, code } => {
                    self.sim
                        .note("relay", format_args!("close {} {code}", conn.0));
                    self.forget(conn);
                }
                Output::Splice {
                    circuit,
                    caller,
                    target,
                    ..
                } => {
                    if let Some(c) = self.circuits.get_mut(&circuit) {
                        debug_assert_eq!(c.leg, caller);
                        c.accept = Some(target);
                    }
                    self.sim
                        .note("relay", format_args!("splice {} {}", caller.0, target.0));
                }
                Output::Forward { from: f, len, .. } => self.on_forward(f, len),
                Output::Authorize { fingerprint, chain } => {
                    self.authorized.insert(
                        fingerprint,
                        AuthorizedKey {
                            fingerprint,
                            drop_at: None,
                            chain,
                        },
                    );
                }
                Output::Supersede {
                    fingerprint,
                    drop_at,
                } => {
                    if let Some(k) = self.authorized.get_mut(&fingerprint) {
                        k.drop_at = Some(drop_at);
                    }
                }
                Output::Drop { fingerprint } => {
                    self.authorized.remove(&fingerprint);
                }
                Output::ConsumeCode { .. } => {}
                // Hosted mode only; the drill runs self mode.
                Output::Hold { .. } | Output::Pause { .. } | Output::Resume { .. } => {}
            }
        }
    }

    fn target_of_handle(&self, handle: &[u8; 32]) -> Option<usize> {
        (0..TARGETS).find(|&t| self.targets[t].key.handle(&self.rid) == *handle)
    }

    fn on_send(&mut self, conn: ConnId, msg: RelayMessage, from: Option<ConnId>) {
        match msg {
            RelayMessage::Registered { handle, .. } => {
                let t = self.target_of_handle(&handle).expect("a drill target");
                let fp = self.targets[t].key.fingerprint();
                if !self.authorized.contains_key(&fp) {
                    self.sim.fail(
                        Invariant::RelayRegisterAuthorized,
                        format!("target {t} registered without being authorized"),
                    );
                }
                for other in &mut self.targets {
                    if other.reg == Some(conn) {
                        other.reg = None;
                    }
                }
                let tg = &mut self.targets[t];
                tg.reg = Some(conn);
                tg.allow = None;
                tg.pending = None;
                tg.incoming.clear();
                self.sim
                    .note("relay", format_args!("registered target {t} on {}", conn.0));
            }
            RelayMessage::AllowSetOk { sequence } => {
                let Some(t) = (0..TARGETS).find(|&t| self.targets[t].reg == Some(conn)) else {
                    return;
                };
                let tg = &mut self.targets[t];
                if let Some((callers, invitations, bytes)) = tg.pending.take() {
                    tg.allow = Some((callers, invitations));
                    tg.last_bytes = Some(bytes);
                }
                self.sim.note(
                    "relay",
                    format_args!("allow-set {sequence} of target {t} accepted"),
                );
                self.check_removal(t);
            }
            RelayMessage::Incoming {
                circuit, caller, ..
            } => {
                let Some(t) = (0..TARGETS).find(|&t| self.targets[t].reg == Some(conn)) else {
                    return;
                };
                let leg = from.expect("an INCOMING answers a CALL or JOIN");
                self.check_admission(t, leg, caller);
                if let Some(l) = self.legs.get_mut(&leg) {
                    l.admitted = true;
                }
                self.targets[t].incoming.push(circuit);
                self.circuits.insert(
                    circuit,
                    Circ {
                        handle: self.targets[t].key.handle(&self.rid),
                        caller,
                        leg,
                        accept: None,
                        sent: [0, 0],
                    },
                );
                self.sim.note(
                    "relay",
                    format_args!(
                        "incoming {} for target {t} ({})",
                        hex6(&circuit),
                        if caller.is_some() { "call" } else { "join" }
                    ),
                );
            }
            RelayMessage::Unreachable => {
                let Some(l) = self.legs.get(&conn).copied() else {
                    return;
                };
                let deadline = l.arrived + self.limits.refuse_ms();
                let ok = if l.admitted {
                    self.sim.now >= deadline
                } else {
                    self.sim.now == deadline
                };
                if !ok {
                    self.sim.fail(
                        Invariant::RelayOneAnswer,
                        format!(
                            "leg {} ({}) answered {} ms after its CALL or JOIN; the deadline is {} ms",
                            conn.0,
                            if l.admitted { "admitted" } else { "refused" },
                            self.sim.now - l.arrived,
                            self.limits.refuse_ms()
                        ),
                    );
                }
                self.sim
                    .note("relay", format_args!("unreachable {}", conn.0));
            }
            _ => {}
        }
    }

    /// An `INCOMING` for target `t` on leg `leg`: the model must allow it.
    fn check_admission(&mut self, t: usize, leg: ConnId, caller: Option<[u8; 32]>) {
        let tg = &self.targets[t];
        let wall = self.now().wall.0;
        let why = match (&tg.allow, caller) {
            (None, _) => Some("the target has no allow-set on this registration".to_owned()),
            (Some((callers, _)), Some(fp)) if !callers.contains(&fp) => {
                Some(format!("caller {} is not in the allow-set", hex6(&fp)))
            }
            (Some((_, invitations)), None) => {
                let tag = self.join_tags.get(&leg).copied();
                let live = tag.is_some_and(|tag| {
                    invitations
                        .iter()
                        .any(|i| i.tag_hash == proof::tag_hash(&tag) && i.expires_at > wall)
                });
                (!live).then(|| "the join has no live invitation tag".to_owned())
            }
            _ => None,
        };
        let why = why.or_else(|| {
            self.bad_proofs
                .contains(&leg)
                .then(|| "the call proof was not valid".to_owned())
        });
        if let Some(why) = why {
            self.sim.fail(
                Invariant::RelayAllowSetOnly,
                format!("leg {} admitted to target {t}: {why}", leg.0),
            );
        }
    }

    fn check_removal(&mut self, t: usize) {
        let handle = self.targets[t].key.handle(&self.rid);
        let Some((callers, _)) = &self.targets[t].allow else {
            return;
        };
        if let Some((_, c)) = self
            .circuits
            .iter()
            .find(|(_, c)| c.handle == handle && c.caller.is_some_and(|fp| !callers.contains(&fp)))
        {
            let detail = format!(
                "a circuit of caller {} is still open after target {t} removed it",
                hex6(&c.caller.expect("caller"))
            );
            self.sim.fail(Invariant::RelayRemovalCloses, detail);
        }
    }

    fn on_forward(&mut self, from: ConnId, len: usize) {
        let budget = self.limits.preaccept_bytes();
        let Some((id, c)) = self
            .circuits
            .iter_mut()
            .find(|(_, c)| c.leg == from || c.accept == Some(from))
        else {
            return;
        };
        if c.caller.is_some() {
            return;
        }
        let dir = usize::from(c.leg != from);
        c.sent[dir] += len as u64;
        if c.sent[dir] > budget {
            let detail = format!(
                "join circuit {} forwarded {} bytes one way; the budget is {budget}",
                hex6(id),
                c.sent[dir]
            );
            self.sim.fail(Invariant::RelayPreacceptBudget, detail);
        }
    }
}

/// Actions.
impl Drive<'_> {
    fn register(&mut self, t: usize) {
        let Some(conn) = self.open_conn() else {
            return;
        };
        let k = &self.targets[t].key;
        let msg = RelayMessage::Register {
            key: k.public_key(),
            proof: k.register_proof(&self.rid, &self.bindings[&conn]),
            hosted: None,
        };
        self.sim
            .note("target", format_args!("{t} registers on {}", conn.0));
        self.send(conn, &msg);
        // `relay-stale-allow-set`: after a reboot the relay's I/O layer
        // reapplies the set this target pushed before it, unasked.
        if self.sim.bug(Bug::RelayStaleAllowSet)
            && self.reboots > 0
            && self.targets[t].reg == Some(conn)
        {
            if let Some(bytes) = self.stale.get(&t).cloned() {
                let now = self.now();
                let outs = self.relay.receive(conn, &bytes, now, &mut self.sim.rng);
                let outs = outs
                    .into_iter()
                    .filter(|o| !matches!(o, Output::Send { .. }))
                    .collect();
                self.process(outs, None);
            }
        }
    }

    fn push(&mut self, t: usize, callers: &[usize], invitations: &[(usize, u64)]) {
        let Some(conn) = self.targets[t].reg else {
            return;
        };
        let wall = self.now().wall.0;
        let set: BTreeSet<[u8; 32]> = callers
            .iter()
            .map(|&c| self.callers[c].fingerprint())
            .collect();
        let inv: Vec<InvitationEntry> = invitations
            .iter()
            .map(|&(i, secs)| InvitationEntry {
                tag_hash: proof::tag_hash(&self.tag(i)),
                expires_at: wall + secs,
            })
            .collect();
        self.targets[t].sequence += 1;
        let msg = RelayMessage::AllowSet {
            sequence: self.targets[t].sequence,
            callers: set.iter().copied().collect(),
            invitations: inv.clone(),
        };
        let bytes = msg.encode();
        self.targets[t].pending = Some((set, inv, bytes.clone()));
        self.sim.note(
            "target",
            format_args!("{t} pushes callers {callers:?} invitations {invitations:?}"),
        );
        self.send_raw(conn, &bytes);
    }

    fn tag(&self, i: usize) -> [u8; 32] {
        proof::invitation_tag(&InvitationId([i as u8 + 0x40; 16]), &self.secrets[i])
    }

    fn call(
        &mut self,
        caller: usize,
        t: Option<usize>,
        bad_proof: bool,
        class: Class,
    ) -> Option<ConnId> {
        let conn = self.open_conn()?;
        let handle = t.map_or([0xee; 32], |t| self.targets[t].key.handle(&self.rid));
        let c = &self.callers[caller];
        let binding = self.bindings[&conn];
        let proof = if bad_proof {
            self.callers[(caller + 1) % CALLERS].call_proof(&self.rid, &handle, &binding, class)
        } else {
            c.call_proof(&self.rid, &handle, &binding, class)
        };
        let msg = RelayMessage::Call {
            handle,
            key: c.public_key(),
            proof,
            class,
        };
        if bad_proof {
            self.bad_proofs.insert(conn);
        }
        self.legs.insert(
            conn,
            Leg {
                arrived: self.sim.now,
                admitted: false,
            },
        );
        self.sim.note(
            "caller",
            format_args!(
                "{caller} calls {} on {}{}",
                t.map_or("an unknown handle".to_owned(), |t| format!("target {t}")),
                conn.0,
                if bad_proof { " with a bad proof" } else { "" }
            ),
        );
        self.send(conn, &msg);
        Some(conn)
    }

    fn join(&mut self, t: usize, invitation: Option<usize>) -> Option<ConnId> {
        let conn = self.open_conn()?;
        let tag = match invitation {
            Some(i) => self.tag(i),
            None => [0x99; 32],
        };
        self.join_tags.insert(conn, tag);
        self.legs.insert(
            conn,
            Leg {
                arrived: self.sim.now,
                admitted: false,
            },
        );
        self.sim.note(
            "joiner",
            format_args!(
                "joins target {t} with invitation {invitation:?} on {}",
                conn.0
            ),
        );
        let handle = self.targets[t].key.handle(&self.rid);
        self.send(conn, &RelayMessage::Join { handle, tag });
        Some(conn)
    }

    fn accept(&mut self, t: usize, circuit: [u8; 16], wrong_key: bool) {
        let Some(conn) = self.open_conn() else {
            return;
        };
        let handle = self.targets[t].key.handle(&self.rid);
        let signer = if wrong_key {
            &self.callers[0]
        } else {
            &self.targets[t].key
        };
        let proof: RawSignature = if wrong_key {
            signer.call_proof(
                &self.rid,
                &handle,
                &self.bindings[&conn],
                Class::Interactive,
            )
        } else {
            signer.accept_proof(&self.rid, &circuit, &self.bindings[&conn])
        };
        self.sim.note(
            "target",
            format_args!("{t} accepts {} on {}", hex6(&circuit), conn.0),
        );
        self.send(
            conn,
            &RelayMessage::Accept {
                handle,
                circuit,
                proof,
            },
        );
    }

    fn data(&mut self, conn: ConnId, len: usize) {
        let now = self.now();
        let outs = self.relay.data(conn, len, now, &mut self.sim.rng);
        self.process(outs, Some(conn));
    }

    fn promote(&mut self, t: usize, circuit: [u8; 16], caller: usize) {
        let Some(reg) = self.targets[t].reg else {
            return;
        };
        let fp = self.callers[caller].fingerprint();
        // The model follows the rule of relay.md 9.4.
        let listed = self.targets[t]
            .allow
            .as_ref()
            .is_some_and(|(c, _)| c.contains(&fp));
        let handle = self.targets[t].key.handle(&self.rid);
        if let Some(c) = self.circuits.get_mut(&circuit) {
            if listed && c.handle == handle && c.caller.is_none() && c.accept.is_some() {
                c.caller = Some(fp);
            }
        }
        self.sim.note(
            "target",
            format_args!("{t} promotes {} for caller {caller}", hex6(&circuit)),
        );
        self.send(
            reg,
            &RelayMessage::Promote {
                circuit,
                caller: fp,
            },
        );
    }

    fn successor(&mut self, t: usize, new: usize) {
        let Some(reg) = self.targets[t].reg else {
            return;
        };
        let b = self.bindings[&reg];
        let nk = self.targets[new].key.public_key();
        let msg = RelayMessage::Successor {
            key: nk,
            new_proof: self.targets[new].key.successor_proof(&self.rid, &nk, &b),
            current_proof: self.targets[t].key.successor_proof(&self.rid, &nk, &b),
        };
        self.sim
            .note("target", format_args!("{t} names {new} as its successor"));
        self.send(reg, &msg);
    }

    fn revoke(&mut self, t: usize) {
        let fp = self.targets[t].key.fingerprint();
        // The operator's revoke takes the key's whole SUCCESSOR chain.
        let chain = self.authorized.get(&fp).map_or(fp, |k| k.chain);
        self.authorized.retain(|f, k| *f != fp && k.chain != chain);
        self.sim
            .note("operator", format_args!("revokes target {t}"));
        let now = self.now();
        let outs = self.relay.revoke(&fp, now, &mut self.sim.rng);
        self.process(outs, None);
    }

    fn reboot(&mut self) {
        self.reboots += 1;
        self.sim.note("relay", format_args!("reboots"));
        for t in 0..TARGETS {
            if let Some(b) = self.targets[t].last_bytes.clone() {
                self.stale.insert(t, b);
            }
        }
        self.relay = Self::boot(&self.relay_key, self.limits, &self.authorized, self.reboots);
        let conns: Vec<ConnId> = self.open.iter().copied().collect();
        for c in conns {
            self.forget(c);
        }
        self.circuits.clear();
        self.legs.clear();
        // Connection numbers keep counting up across the reboot; they are the
        // drill's labels.
    }

    // ---- random play ------------------------------------------------------

    fn spliced(&self) -> Vec<([u8; 16], ConnId, ConnId)> {
        self.circuits
            .iter()
            .filter_map(|(id, c)| c.accept.map(|a| (*id, c.leg, a)))
            .collect()
    }

    fn random_step(&mut self) {
        let wait = self.sim.range(0, 1_500);
        self.wait(wait);
        if self.failed() {
            return;
        }
        let t = self.sim.range(0, 1) as usize;
        match self.sim.range(0, 99) {
            0..=7 => {
                let who = self
                    .sim
                    .pick(&[0, 1, 0, 1, UNLISTED_TARGET, SUCCESSOR_OF_0]);
                self.register(who);
            }
            8..=19 => {
                let callers: Vec<usize> = (0..STRANGER).filter(|_| self.sim.chance(500)).collect();
                let mut invitations: Vec<(usize, u64)> = Vec::new();
                for i in 0..INVITATIONS {
                    if self.sim.chance(400) {
                        invitations.push((i, self.sim.range(1, 30)));
                    }
                }
                self.push(t, &callers, &invitations);
            }
            20..=44 => {
                let caller = self.sim.range(0, CALLERS as u64 - 1) as usize;
                let target = match self.sim.range(0, 9) {
                    0 => None,
                    1 => Some(UNLISTED_TARGET),
                    _ => Some(t),
                };
                let bad = self.sim.chance(80);
                let class = if self.sim.chance(300) {
                    Class::Bulk
                } else {
                    Class::Interactive
                };
                self.call(caller, target, bad, class);
            }
            45..=54 => {
                let inv = if self.sim.chance(800) {
                    Some(self.sim.range(0, INVITATIONS as u64 - 1) as usize)
                } else {
                    None
                };
                self.join(t, inv);
            }
            55..=69 => {
                let pending = self.targets[t].incoming.clone();
                if !pending.is_empty() {
                    let c = self.sim.pick(&pending);
                    let wrong = self.sim.chance(100);
                    self.accept(t, c, wrong);
                }
            }
            70..=84 => {
                let s = self.spliced();
                if !s.is_empty() {
                    let (_, a, b) = self.sim.pick(&s);
                    let conn = if self.sim.chance(500) { a } else { b };
                    let len = self.sim.range(1, 30_000) as usize;
                    self.data(conn, len);
                }
            }
            85..=89 => {
                let open: Vec<ConnId> = self.open.iter().copied().collect();
                if !open.is_empty() {
                    let c = self.sim.pick(&open);
                    self.sim.note("client", format_args!("closes {}", c.0));
                    self.close(c);
                }
            }
            90..=95 => {
                let joins: Vec<[u8; 16]> = self
                    .circuits
                    .iter()
                    .filter(|(_, c)| c.caller.is_none() && c.accept.is_some())
                    .map(|(id, _)| *id)
                    .collect();
                if !joins.is_empty() {
                    let c = self.sim.pick(&joins);
                    let caller = self.sim.range(0, CALLERS as u64 - 1) as usize;
                    let owner = self
                        .target_of_handle(&self.circuits[&c].handle)
                        .expect("target");
                    self.promote(owner, c, caller);
                }
            }
            96..=97 => {
                let s = self.spliced();
                if let Some(&(_, leg, _)) = s.first() {
                    self.sim.note("caller", format_args!("closes {}", leg.0));
                    self.close(leg);
                }
            }
            _ => {
                if self.sim.chance(300) {
                    self.revoke(1);
                }
            }
        }
    }

    /// Splice a call from `caller` to target `t`, checking it does.
    fn connect(&mut self, caller: usize, t: usize) {
        let Some(leg) = self.call(caller, Some(t), false, Class::Interactive) else {
            return;
        };
        if let Some(&c) = self.targets[t].incoming.last() {
            if self.circuits.get(&c).is_some_and(|x| x.leg == leg) {
                self.accept(t, c, false);
            }
        }
    }
}

pub(crate) fn run(sim: &mut Sim) -> &'static str {
    let variant = sim.pick(RELAY_VARIANTS);
    sim.note("drill", format_args!("relay-admission {variant}"));
    let mut d = Drive::new(sim);
    match variant {
        "calls" => {
            d.register(0);
            d.push(0, &[0, 1], &[]);
            d.call(STRANGER, Some(0), false, Class::Interactive);
            d.call(0, Some(1), false, Class::Interactive);
            d.connect(0, 0);
            d.wait(2 * SEC);
        }
        "removal" => {
            d.register(0);
            d.push(0, &[0, 1, 2], &[]);
            d.connect(0, 0);
            d.connect(1, 0);
            d.call(2, Some(0), false, Class::Bulk);
            d.wait(100);
            d.push(0, &[1], &[]);
            d.call(0, Some(0), false, Class::Interactive);
            d.wait(2 * SEC);
        }
        "joins" => {
            d.register(0);
            d.push(0, &[], &[(0, 60), (1, 2)]);
            for i in 0..3 {
                d.join(0, Some(i));
            }
            d.join(0, None);
            let pending = d.targets[0].incoming.clone();
            for c in pending {
                d.accept(0, c, false);
            }
            for (_, leg, _) in d.spliced() {
                let len = d.sim.range(10_000, 40_000) as usize;
                d.data(leg, len);
                d.data(leg, len);
            }
            d.wait(3 * SEC);
        }
        "reboot" => {
            d.register(0);
            d.push(0, &[0], &[]);
            d.connect(0, 0);
            d.wait(500);
            d.reboot();
            d.call(0, Some(0), false, Class::Interactive);
            d.register(0);
            d.call(0, Some(0), false, Class::Interactive);
            d.wait(2 * SEC);
            d.push(0, &[0], &[]);
            d.connect(0, 0);
        }
        _ => {
            d.register(0);
            d.push(0, &[0], &[]);
            d.connect(0, 0);
            d.successor(0, SUCCESSOR_OF_0);
            d.register(SUCCESSOR_OF_0);
            d.successor(0, 1);
            d.wait(100 * SEC);
            d.register(0);
            d.push(0, &[0], &[]);
            d.connect(0, 0);
            d.wait(86_400 * SEC);
        }
    }
    let steps = d.sim.range(20, 80);
    for _ in 0..steps {
        if d.failed() {
            break;
        }
        d.random_step();
        if d.sim.chance(20) && variant == "reboot" {
            d.reboot();
        }
    }
    if !d.failed() {
        d.wait(15 * SEC);
    }
    let summary = d.relay.counts();
    d.sim.note(
        "relay",
        format_args!(
            "end: {} connections, {} registrations, {} circuits",
            summary.connections,
            summary.registrations,
            summary.waiting + summary.spliced
        ),
    );
    variant
}
