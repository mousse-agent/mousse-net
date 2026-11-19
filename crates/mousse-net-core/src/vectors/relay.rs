//! `relay-admission.json` (spec `relay.md` section 14): derivations,
//! messages, and scripted runs of one self-hosted relay. Every scenario
//! checks its own rules as it is built, so a planted bug fails here before
//! the file comparison does.

use std::collections::BTreeMap;

use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};

use super::{hex, identity, Draws, T};
use crate::cbor::{self, Value};
use crate::identity::RawSignature;
use crate::pairing::{InvitationId, RouteHost, TicketSecret};
use crate::relay::machine::{
    AuthorizedKey, ConnId, EnrollCode, IpKey, Now, Output, Relay, RelayConfig,
};
use crate::relay::msg::{Class, InvitationEntry, RefuseReason, RelayMessage, RELAY_MESSAGE_MAX};
use crate::relay::proof::{self, Binding, RelayClientKey, RelayId};
use crate::relay::{relay_certificate, EnrollmentLink, RelayLimits};
use crate::time::{Millis, UnixTime};

const RELAY: [u8; 32] = [0x51; 32];
const OTHER_RELAY: [u8; 32] = [0x52; 32];
const TARGET: [u8; 32] = [0x61; 32];
const TARGET_B: [u8; 32] = [0x62; 32];
const NEW_TARGET: [u8; 32] = [0x63; 32];
const STRANGER_TARGET: [u8; 32] = [0x64; 32];
const CALLER_1: [u8; 32] = [0x71; 32];
const CALLER_2: [u8; 32] = [0x72; 32];
const STRANGER: [u8; 32] = [0x73; 32];
const BOOT: [u8; 16] = [0x5b; 16];
const INVITATION: [u8; 16] = [0x81; 16];
const TICKET_SECRET: [u8; 16] = [0x82; 16];
const INVITATION_2: [u8; 16] = [0x83; 16];
const CODE: [u8; 16] = [0x91; 16];
const CODE_2: [u8; 16] = [0x92; 16];

const REFUSE: u64 = 500;
const ACCEPT_WAIT: u64 = 10_000;

fn key(secret: &[u8; 32]) -> RelayClientKey {
    RelayClientKey::new(identity(secret))
}

fn relay_id() -> RelayId {
    RelayId::of(&identity(&RELAY).public_key())
}

fn other_relay_id() -> RelayId {
    RelayId::of(&identity(&OTHER_RELAY).public_key())
}

/// The outer exporter a scenario gives connection `conn`.
fn exporter(conn: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vector outer exporter");
    h.update(conn.to_be_bytes());
    h.finalize().into()
}

/// An address key: 198.51.100.`n`, as the first 4 of 16 bytes.
fn ip(n: u8) -> IpKey {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&[198, 51, 100, n]);
    IpKey(a)
}

fn tag(invitation: [u8; 16]) -> [u8; 32] {
    proof::invitation_tag(
        &InvitationId(invitation),
        &TicketSecret::from_bytes(TICKET_SECRET),
    )
}

/// One line per output, for the rules each scenario checks.
fn summary(outs: &[Output]) -> Vec<String> {
    outs.iter()
        .map(|o| match o {
            Output::Send { conn, message } => format!(
                "send {} {}",
                conn.0,
                RelayMessage::decode(message)
                    .expect("relay output decodes")
                    .name()
            ),
            Output::Close { conn, code } => format!("close {} {code}", conn.0),
            Output::Splice { caller, target, .. } => format!("splice {} {}", caller.0, target.0),
            Output::Forward { from, to, len } => format!("forward {} {} {len}", from.0, to.0),
            Output::Authorize { .. } => "authorize".into(),
            Output::Supersede { .. } => "supersede".into(),
            Output::Drop { .. } => "drop".into(),
            Output::ConsumeCode { .. } => "consume_code".into(),
        })
        .collect()
}

#[track_caller]
fn expect(outs: &[Output], lines: &[&str]) {
    assert_eq!(summary(outs), lines);
}

/// The message sent to `conn` among `outs`.
fn sent(outs: &[Output], conn: u64) -> RelayMessage {
    outs.iter()
        .find_map(|o| match o {
            Output::Send { conn: c, message } if c.0 == conn => {
                Some(RelayMessage::decode(message).expect("decodes"))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("nothing sent to {conn}"))
}

/// The circuit of the `INCOMING` among `outs`.
fn incoming(outs: &[Output]) -> [u8; 16] {
    outs.iter()
        .find_map(|o| match o {
            Output::Send { message, .. } => match RelayMessage::decode(message) {
                Ok(RelayMessage::Incoming { circuit, .. }) => Some(circuit),
                _ => None,
            },
            _ => None,
        })
        .expect("an INCOMING")
}

fn output_json(o: &Output) -> J {
    match o {
        Output::Send { conn, message } => json!({
            "send": conn.0,
            "message": RelayMessage::decode(message).expect("decodes").name(),
            "hex": hex(message),
        }),
        Output::Close { conn, code } => json!({ "close": conn.0, "code": code }),
        Output::Splice {
            circuit,
            caller,
            target,
            class,
        } => json!({
            "splice": [caller.0, target.0],
            "circuit": hex(circuit),
            "class": *class as u64,
        }),
        Output::Forward { from, to, len } => json!({ "forward": [from.0, to.0], "len": len }),
        Output::Authorize { fingerprint } => json!({ "authorize": hex(fingerprint) }),
        Output::Supersede {
            fingerprint,
            drop_at,
        } => json!({ "supersede": hex(fingerprint), "drop_at": drop_at.0 }),
        Output::Drop { fingerprint } => json!({ "drop": hex(fingerprint) }),
        Output::ConsumeCode { hash } => json!({ "consume_code": hex(hash) }),
    }
}

/// One scripted relay run.
struct Sim {
    relay: Relay,
    rng: Draws,
    doc: J,
    wall_base: u64,
    last_at: u64,
    events: Vec<J>,
    bindings: BTreeMap<u64, Binding>,
}

struct Setup<'a> {
    authorized: &'a [([u8; 32], Option<u64>)],
    codes: &'a [([u8; 16], u64)],
    limits: &'a [(&'static str, u64)],
}

const PLAIN: Setup<'static> = Setup {
    authorized: &[],
    codes: &[],
    limits: &[],
};

impl Sim {
    fn new(name: &str, notes: &str, setup: Setup<'_>) -> Self {
        let relay_key = identity(&RELAY).public_key();
        let limits = RelayLimits::DEFAULT
            .with_overrides(setup.limits)
            .expect("scenario limits");
        let authorized: Vec<AuthorizedKey> = setup
            .authorized
            .iter()
            .map(|(fp, drop_at)| AuthorizedKey {
                fingerprint: *fp,
                drop_at: drop_at.map(UnixTime),
            })
            .collect();
        let codes: Vec<EnrollCode> = setup
            .codes
            .iter()
            .map(|(code, expires)| EnrollCode {
                hash: proof::code_hash(code),
                expires_at: UnixTime(*expires),
            })
            .collect();
        let doc = json!({
            "name": name,
            "notes": notes,
            "relay_key": hex(relay_key.as_bytes()),
            "boot_id": hex(&BOOT),
            "wall_base": T,
            "authorized": authorized.iter().map(|k| match k.drop_at {
                Some(t) => json!({ "fingerprint": hex(&k.fingerprint), "drop_at": t.0 }),
                None => json!({ "fingerprint": hex(&k.fingerprint) }),
            }).collect::<Vec<_>>(),
            "codes": codes.iter().map(|c| json!({
                "hash": hex(&c.hash),
                "expires_at": c.expires_at.0,
            })).collect::<Vec<_>>(),
            "limits": setup.limits.iter().map(|(n, v)| ((*n).to_owned(), json!(v))).collect::<serde_json::Map<_, _>>(),
        });
        Self {
            relay: Relay::new(
                RelayConfig {
                    relay_key,
                    boot_id: BOOT,
                    limits,
                },
                &authorized,
                &codes,
            ),
            rng: Draws::recording(0x5e),
            doc,
            wall_base: T,
            last_at: 0,
            events: Vec::new(),
            bindings: BTreeMap::new(),
        }
    }

    fn now(&mut self, at: u64) -> Now {
        assert!(at >= self.last_at, "events go forward in time");
        self.last_at = at;
        Now {
            mono: Millis(at),
            wall: UnixTime(self.wall_base + at / 1000),
        }
    }

    fn record(&mut self, mut event: J, at: u64, outs: Vec<Output>) -> Vec<Output> {
        event["at"] = json!(at);
        event["out"] = J::Array(outs.iter().map(output_json).collect());
        self.events.push(event);
        outs
    }

    fn open(&mut self, at: u64, conn: u64, address: u8) -> Vec<Output> {
        let now = self.now(at);
        let ex = exporter(conn);
        let outs = self
            .relay
            .open(ConnId(conn), ip(address), ex, now, &mut self.rng);
        for o in &outs {
            if let Output::Send { conn: c, message } = o {
                if let Ok(RelayMessage::Hello { nonce, .. }) = RelayMessage::decode(message) {
                    self.bindings.insert(
                        c.0,
                        Binding {
                            nonce,
                            exporter: ex,
                        },
                    );
                }
            }
        }
        self.record(
            json!({ "event": "open", "conn": conn, "ip": hex(&ip(address).0), "exporter": hex(&ex) }),
            at,
            outs,
        )
    }

    fn raw(&mut self, at: u64, conn: u64, bytes: &[u8]) -> Vec<Output> {
        let now = self.now(at);
        let outs = self.relay.receive(ConnId(conn), bytes, now, &mut self.rng);
        self.record(
            json!({ "event": "recv", "conn": conn, "hex": hex(bytes) }),
            at,
            outs,
        )
    }

    fn send(&mut self, at: u64, conn: u64, msg: &RelayMessage) -> Vec<Output> {
        self.raw(at, conn, &msg.encode())
    }

    fn data(&mut self, at: u64, conn: u64, len: usize) -> Vec<Output> {
        let now = self.now(at);
        let outs = self.relay.data(ConnId(conn), len, now, &mut self.rng);
        self.record(
            json!({ "event": "data", "conn": conn, "len": len }),
            at,
            outs,
        )
    }

    fn closed(&mut self, at: u64, conn: u64) -> Vec<Output> {
        let now = self.now(at);
        let outs = self.relay.closed(ConnId(conn), now, &mut self.rng);
        self.record(json!({ "event": "closed", "conn": conn }), at, outs)
    }

    fn tick(&mut self, at: u64) -> Vec<Output> {
        let now = self.now(at);
        let outs = self.relay.tick(now, &mut self.rng);
        self.record(json!({ "event": "tick" }), at, outs)
    }

    fn revoke(&mut self, at: u64, fingerprint: [u8; 32]) -> Vec<Output> {
        let now = self.now(at);
        let outs = self.relay.revoke(&fingerprint, now, &mut self.rng);
        self.record(
            json!({ "event": "revoke", "fingerprint": hex(&fingerprint) }),
            at,
            outs,
        )
    }

    fn binding(&self, conn: u64) -> Binding {
        self.bindings[&conn]
    }

    // Client messages bound to a connection.

    fn register_msg(&self, conn: u64, k: &RelayClientKey) -> RelayMessage {
        RelayMessage::Register {
            key: k.public_key(),
            proof: k.register_proof(&relay_id(), &self.binding(conn)),
            hosted: None,
        }
    }

    fn call_msg(
        &self,
        conn: u64,
        caller: &RelayClientKey,
        handle: [u8; 32],
        class: Class,
    ) -> RelayMessage {
        RelayMessage::Call {
            handle,
            key: caller.public_key(),
            proof: caller.call_proof(&relay_id(), &handle, &self.binding(conn), class),
            class,
        }
    }

    fn accept_msg(&self, conn: u64, target: &RelayClientKey, circuit: [u8; 16]) -> RelayMessage {
        RelayMessage::Accept {
            handle: target.handle(&relay_id()),
            circuit,
            proof: target.accept_proof(&relay_id(), &circuit, &self.binding(conn)),
        }
    }

    // Steps that check the happy path as they go.

    fn hello(&mut self, at: u64, conn: u64, address: u8) {
        let outs = self.open(at, conn, address);
        expect(&outs, &[&format!("send {conn} RELAY_HELLO")]);
    }

    fn register(&mut self, at: u64, conn: u64, address: u8, k: &RelayClientKey) -> [u8; 32] {
        self.hello(at, conn, address);
        let msg = self.register_msg(conn, k);
        let outs = self.send(at, conn, &msg);
        let handle = k.handle(&relay_id());
        assert_eq!(
            summary(&outs).last().map(String::as_str),
            Some(&*format!("send {conn} REGISTERED"))
        );
        assert_eq!(sent(&outs, conn), RelayMessage::Registered { handle });
        handle
    }

    fn allow(
        &mut self,
        at: u64,
        conn: u64,
        sequence: u64,
        callers: &[&RelayClientKey],
        invitations: &[InvitationEntry],
    ) -> Vec<Output> {
        let msg = RelayMessage::AllowSet {
            sequence,
            callers: callers.iter().map(|c| c.fingerprint()).collect(),
            invitations: invitations.to_vec(),
        };
        self.send(at, conn, &msg)
    }

    fn call(
        &mut self,
        at: u64,
        conn: u64,
        address: u8,
        caller: &RelayClientKey,
        handle: [u8; 32],
        class: Class,
    ) -> Vec<Output> {
        self.hello(at, conn, address);
        let msg = self.call_msg(conn, caller, handle, class);
        self.send(at, conn, &msg)
    }

    fn join(
        &mut self,
        at: u64,
        conn: u64,
        address: u8,
        handle: [u8; 32],
        tag: [u8; 32],
    ) -> Vec<Output> {
        self.hello(at, conn, address);
        self.send(at, conn, &RelayMessage::Join { handle, tag })
    }

    fn accept(
        &mut self,
        at: u64,
        conn: u64,
        address: u8,
        target: &RelayClientKey,
        circuit: [u8; 16],
    ) -> Vec<Output> {
        self.hello(at, conn, address);
        let msg = self.accept_msg(conn, target, circuit);
        self.send(at, conn, &msg)
    }

    /// A call from `caller` on `conn`, accepted on `accept`; returns the
    /// circuit.
    #[allow(clippy::too_many_arguments)]
    fn connect(
        &mut self,
        at: u64,
        reg: u64,
        conn: u64,
        accept: u64,
        caller: &RelayClientKey,
        target: &RelayClientKey,
        class: Class,
    ) -> [u8; 16] {
        let outs = self.call(at, conn, 2, caller, target.handle(&relay_id()), class);
        expect(&outs, &[&format!("send {reg} INCOMING")]);
        assert_eq!(
            sent(&outs, reg),
            RelayMessage::Incoming {
                circuit: incoming(&outs),
                class,
                caller: Some(caller.fingerprint()),
            }
        );
        let circuit = incoming(&outs);
        let outs = self.accept(at, accept, 1, target, circuit);
        expect(
            &outs,
            &[
                &format!("send {conn} SPLICED"),
                &format!("send {accept} SPLICED"),
                &format!("splice {conn} {accept}"),
            ],
        );
        circuit
    }

    fn finish(self) -> J {
        let mut doc = self.doc;
        doc["draws"] = J::Array(self.rng.log.iter().map(|d| d["bytes"].clone()).collect());
        doc["events"] = J::Array(self.events);
        doc
    }
}

fn fp(secret: &[u8; 32]) -> [u8; 32] {
    key(secret).fingerprint()
}

fn listed(keys: &[[u8; 32]]) -> Vec<([u8; 32], Option<u64>)> {
    keys.iter().map(|k| (fp(k), None)).collect()
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

fn register_and_call() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "register_and_call",
        "A listed caller reaches a registered target: INCOMING on the registration connection, an accept leg on a new connection, SPLICED on both legs, peer messages forwarded both ways. A bulk call is its own circuit; one leg closing closes only its circuit.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    let outs = s.allow(10, 1, 1, &[&caller], &[]);
    expect(&outs, &["send 1 ALLOW_SET_OK"]);
    assert_eq!(sent(&outs, 1), RelayMessage::AllowSetOk { sequence: 1 });
    s.connect(20, 1, 2, 3, &caller, &target, Class::Interactive);
    expect(&s.data(40, 2, 1200), &["forward 2 3 1200"]);
    expect(&s.data(50, 3, 900), &["forward 3 2 900"]);
    let outs = s.call(60, 4, 2, &caller, h, Class::Bulk);
    let circuit = incoming(&outs);
    assert!(matches!(
        sent(&outs, 1),
        RelayMessage::Incoming {
            class: Class::Bulk,
            ..
        }
    ));
    let outs = s.accept(70, 5, 1, &target, circuit);
    assert!(outs.contains(&Output::Splice {
        circuit,
        caller: ConnId(4),
        target: ConnId(5),
        class: Class::Bulk,
    }));
    expect(&s.closed(80, 2), &["close 3 1000"]);
    expect(&s.data(90, 4, 10), &["forward 4 5 10"]);
    s.finish()
}

fn unlisted_equals_offline() -> J {
    let (target, caller, stranger) = (key(&TARGET), key(&CALLER_1), key(&STRANGER));
    let mut s = Sim::new(
        "unlisted_equals_offline",
        "An unlisted caller, an offline target, an unknown handle, a bad proof and a target with no allow-set yet all get UNREACHABLE exactly at the refusal deadline (500 ms after the CALL), and nothing before. A listed caller to an online target that never accepts gets UNREACHABLE at the accept wait, never before the refusal deadline.",
        Setup { authorized: &listed(&[TARGET, TARGET_B, NEW_TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    let fresh = s.register(0, 6, 1, &key(&NEW_TARGET));
    let offline = key(&TARGET_B).handle(&relay_id());
    // Unlisted caller.
    expect(&s.call(100, 2, 2, &stranger, h, Class::Interactive), &[]);
    // Offline target (authorized, not registered).
    expect(
        &s.call(100, 3, 2, &caller, offline, Class::Interactive),
        &[],
    );
    // Unknown handle.
    expect(
        &s.call(100, 4, 2, &caller, [0xee; 32], Class::Interactive),
        &[],
    );
    // A listed caller's key with someone else's proof.
    s.hello(100, 5, 2);
    let bad = RelayMessage::Call {
        handle: h,
        key: caller.public_key(),
        proof: stranger.call_proof(&relay_id(), &h, &s.binding(5), Class::Interactive),
        class: Class::Interactive,
    };
    expect(&s.send(100, 5, &bad), &[]);
    // A registered target that has not pushed an allow-set.
    expect(&s.call(100, 7, 2, &caller, fresh, Class::Interactive), &[]);
    expect(&s.tick(100 + REFUSE - 1), &[]);
    expect(
        &s.tick(100 + REFUSE),
        &[
            "send 2 UNREACHABLE",
            "close 2 1000",
            "send 3 UNREACHABLE",
            "close 3 1000",
            "send 4 UNREACHABLE",
            "close 4 1000",
            "send 5 UNREACHABLE",
            "close 5 1000",
            "send 7 UNREACHABLE",
            "close 7 1000",
        ],
    );
    // Listed and online, but the target never accepts.
    expect(
        &s.call(700, 8, 2, &caller, h, Class::Interactive),
        &["send 1 INCOMING"],
    );
    expect(&s.tick(700 + REFUSE), &[]);
    expect(&s.tick(700 + ACCEPT_WAIT - 1), &[]);
    expect(
        &s.tick(700 + ACCEPT_WAIT),
        &["send 8 UNREACHABLE", "close 8 1000"],
    );
    s.finish()
}

fn register_other_key() -> J {
    let (target, stranger) = (key(&TARGET), key(&STRANGER_TARGET));
    let mut s = Sim::new(
        "register_other_key",
        "A handle is derived from the key that proved itself: someone else's key with the attacker's proof, an unauthorized key, and a proof over a handle that does not match the key are all REFUSED(not_authorized). The real key registers.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let refused = |outs: &[Output], conn: u64| {
        expect(
            outs,
            &[
                &format!("send {conn} REFUSED"),
                &format!("close {conn} 1000"),
            ],
        );
        assert_eq!(
            sent(outs, conn),
            RelayMessage::Refused {
                reason: RefuseReason::NotAuthorized
            }
        );
    };
    // The target's key with the attacker's proof.
    s.hello(0, 1, 2);
    let msg = RelayMessage::Register {
        key: target.public_key(),
        proof: identity(&STRANGER_TARGET).sign_raw(&proof::register_record(
            &relay_id(),
            &target.handle(&relay_id()),
            &s.binding(1),
        )),
        hosted: None,
    };
    let outs = s.send(0, 1, &msg);
    refused(&outs, 1);
    // The attacker's own key: valid proof, not on the list.
    s.hello(10, 2, 2);
    let msg = s.register_msg(2, &stranger);
    let outs = s.send(10, 2, &msg);
    refused(&outs, 2);
    // The target's key signing a record for another handle.
    s.hello(20, 3, 2);
    let msg = RelayMessage::Register {
        key: target.public_key(),
        proof: identity(&TARGET).sign_raw(&proof::register_record(
            &relay_id(),
            &stranger.handle(&relay_id()),
            &s.binding(3),
        )),
        hosted: None,
    };
    let outs = s.send(20, 3, &msg);
    refused(&outs, 3);
    s.register(30, 4, 1, &target);
    s.finish()
}

fn register_replayed() -> J {
    let target = key(&TARGET);
    let mut s = Sim::new(
        "register_replayed",
        "A REGISTER replayed on another connection, and one proved for another relay, are REFUSED(not_authorized); the original registration is untouched.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.hello(0, 1, 1);
    let original = s.register_msg(1, &target).encode();
    let outs = s.raw(0, 1, &original);
    expect(&outs, &["send 1 REGISTERED"]);
    s.hello(10, 2, 2);
    expect(
        &s.raw(10, 2, &original),
        &["send 2 REFUSED", "close 2 1000"],
    );
    s.hello(20, 3, 2);
    let msg = RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&other_relay_id(), &s.binding(3)),
        hosted: None,
    };
    expect(&s.send(20, 3, &msg), &["send 3 REFUSED", "close 3 1000"]);
    expect(&s.allow(30, 1, 1, &[], &[]), &["send 1 ALLOW_SET_OK"]);
    s.finish()
}

fn call_replayed_other_connection() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "call_replayed_other_connection",
        "A listed caller's CALL replayed verbatim on another connection is refused like any other: UNREACHABLE at the refusal deadline.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.hello(10, 2, 2);
    let original = s.call_msg(2, &caller, h, Class::Interactive).encode();
    expect(&s.raw(10, 2, &original), &["send 1 INCOMING"]);
    s.hello(100, 3, 3);
    expect(&s.raw(100, 3, &original), &[]);
    expect(
        &s.tick(100 + REFUSE),
        &["send 3 UNREACHABLE", "close 3 1000"],
    );
    s.finish()
}

fn call_other_relay() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "call_other_relay",
        "A call proof made for another relay, and one made for the other class, are refused at the refusal deadline.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.hello(100, 2, 2);
    let msg = RelayMessage::Call {
        handle: h,
        key: caller.public_key(),
        proof: caller.call_proof(&other_relay_id(), &h, &s.binding(2), Class::Interactive),
        class: Class::Interactive,
    };
    expect(&s.send(100, 2, &msg), &[]);
    s.hello(100, 3, 2);
    let msg = RelayMessage::Call {
        handle: h,
        key: caller.public_key(),
        proof: caller.call_proof(&relay_id(), &h, &s.binding(3), Class::Interactive),
        class: Class::Bulk,
    };
    expect(&s.send(100, 3, &msg), &[]);
    expect(
        &s.tick(100 + REFUSE),
        &[
            "send 2 UNREACHABLE",
            "close 2 1000",
            "send 3 UNREACHABLE",
            "close 3 1000",
        ],
    );
    s.finish()
}

fn removed_caller_closed() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "removed_caller_closed",
        "An allow-set without the caller closes its spliced circuit (both legs, caller first) and its waiting call with 4000 at once, before ALLOW_SET_OK. Its next call is refused.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.connect(10, 1, 2, 3, &caller, &target, Class::Interactive);
    expect(
        &s.call(20, 4, 2, &caller, h, Class::Bulk),
        &["send 1 INCOMING"],
    );
    expect(
        &s.allow(30, 1, 2, &[], &[]),
        &[
            "close 2 4000",
            "close 3 4000",
            "close 4 4000",
            "send 1 ALLOW_SET_OK",
        ],
    );
    expect(&s.call(40, 5, 2, &caller, h, Class::Interactive), &[]);
    expect(
        &s.tick(40 + REFUSE),
        &["send 5 UNREACHABLE", "close 5 1000"],
    );
    s.finish()
}

fn removal_leaves_others() -> J {
    let (target, c1, c2) = (key(&TARGET), key(&CALLER_1), key(&CALLER_2));
    let mut s = Sim::new(
        "removal_leaves_others",
        "Removing one caller closes only that caller's circuit; another caller's circuit keeps forwarding.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.register(0, 1, 1, &target);
    expect(
        &s.allow(0, 1, 1, &[&c1, &c2], &[]),
        &["send 1 ALLOW_SET_OK"],
    );
    s.connect(10, 1, 2, 3, &c1, &target, Class::Interactive);
    s.connect(20, 1, 4, 5, &c2, &target, Class::Interactive);
    expect(
        &s.allow(30, 1, 2, &[&c2], &[]),
        &["close 2 4000", "close 3 4000", "send 1 ALLOW_SET_OK"],
    );
    expect(&s.data(40, 4, 100), &["forward 4 5 100"]);
    expect(&s.data(50, 5, 100), &["forward 5 4 100"]);
    s.finish()
}

fn join_without_tag() -> J {
    let target = key(&TARGET);
    let mut s = Sim::new(
        "join_without_tag",
        "A JOIN with a wrong tag, with the tag hash in place of the tag, or with the tag of an expired invitation is refused at the refusal deadline. The right tag is admitted: INCOMING with kind join and no caller.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    let live = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION)),
        expires_at: T + 3_600,
    };
    let expired = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION_2)),
        expires_at: T,
    };
    expect(
        &s.allow(0, 1, 1, &[], &[live, expired]),
        &["send 1 ALLOW_SET_OK"],
    );
    expect(&s.join(100, 2, 2, h, [0x99; 32]), &[]);
    expect(&s.join(100, 3, 2, h, live.tag_hash), &[]);
    expect(&s.join(100, 4, 2, h, tag(INVITATION_2)), &[]);
    expect(
        &s.tick(100 + REFUSE),
        &[
            "send 2 UNREACHABLE",
            "close 2 1000",
            "send 3 UNREACHABLE",
            "close 3 1000",
            "send 4 UNREACHABLE",
            "close 4 1000",
        ],
    );
    let outs = s.join(700, 5, 2, h, tag(INVITATION));
    expect(&outs, &["send 1 INCOMING"]);
    assert_eq!(
        sent(&outs, 1),
        RelayMessage::Incoming {
            circuit: incoming(&outs),
            class: Class::Interactive,
            caller: None
        }
    );
    s.finish()
}

fn spliced_join(
    s: &mut Sim,
    at: u64,
    conn: u64,
    accept: u64,
    target: &RelayClientKey,
    invitation: [u8; 16],
) -> [u8; 16] {
    let outs = s.join(at, conn, 2, target.handle(&relay_id()), tag(invitation));
    expect(&outs, &["send 1 INCOMING"]);
    let circuit = incoming(&outs);
    let outs = s.accept(at, accept, 1, target, circuit);
    expect(
        &outs,
        &[
            &format!("send {conn} SPLICED"),
            &format!("send {accept} SPLICED"),
            &format!("splice {conn} {accept}"),
        ],
    );
    circuit
}

fn preaccept_over_budget() -> J {
    let target = key(&TARGET);
    let mut s = Sim::new(
        "preaccept_over_budget",
        "An unpromoted join circuit carries at most RELAY_PREACCEPT_BYTES (65 536) of peer bytes each way; the message that would go over closes both legs with 4006. A join circuit also closes, 4006, when its invitation expires on the relay's wall clock.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.register(0, 1, 1, &target);
    let live = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION)),
        expires_at: T + 3_600,
    };
    let short = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION_2)),
        expires_at: T + 10,
    };
    expect(
        &s.allow(0, 1, 1, &[], &[live, short]),
        &["send 1 ALLOW_SET_OK"],
    );
    spliced_join(&mut s, 100, 2, 3, &target, INVITATION);
    expect(&s.data(200, 2, 65_000), &["forward 2 3 65000"]);
    expect(&s.data(210, 3, 65_536), &["forward 3 2 65536"]);
    expect(&s.data(220, 2, 536), &["forward 2 3 536"]);
    expect(&s.data(230, 2, 1), &["close 2 4006", "close 3 4006"]);
    spliced_join(&mut s, 300, 4, 5, &target, INVITATION_2);
    expect(&s.tick(9_999), &[]);
    expect(&s.tick(10_000), &["close 4 4006", "close 5 4006"]);
    s.finish()
}

fn preaccept_per_target() -> J {
    let target = key(&TARGET);
    let mut s = Sim::new(
        "preaccept_per_target",
        "At most RELAY_PREACCEPT_PER_TARGET (4) join circuits per handle: the fifth JOIN is refused at the refusal deadline; once one ends, a JOIN is admitted again.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    let live = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION)),
        expires_at: T + 3_600,
    };
    expect(&s.allow(0, 1, 1, &[], &[live]), &["send 1 ALLOW_SET_OK"]);
    for conn in 2..=5 {
        expect(
            &s.join(100, conn, 2, h, tag(INVITATION)),
            &["send 1 INCOMING"],
        );
    }
    expect(&s.join(100, 6, 2, h, tag(INVITATION)), &[]);
    expect(
        &s.tick(100 + REFUSE),
        &["send 6 UNREACHABLE", "close 6 1000"],
    );
    expect(&s.closed(700, 2), &[]);
    expect(&s.join(800, 7, 2, h, tag(INVITATION)), &["send 1 INCOMING"]);
    s.finish()
}

fn accept_wrong_key() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "accept_wrong_key",
        "An ACCEPT signed by another key, naming an unknown circuit, or naming another handle is REFUSED(not_authorized) and the circuit keeps waiting; the target's own ACCEPT then splices it.",
        Setup { authorized: &listed(&[TARGET, TARGET_B]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    s.register(0, 9, 1, &key(&TARGET_B));
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    let circuit = incoming(&s.call(10, 2, 2, &caller, h, Class::Interactive));
    // Signed by the caller's key.
    s.hello(20, 3, 2);
    let msg = RelayMessage::Accept {
        handle: h,
        circuit,
        proof: identity(&CALLER_1).sign_raw(&proof::accept_record(
            &relay_id(),
            &h,
            &circuit,
            &s.binding(3),
        )),
    };
    expect(&s.send(20, 3, &msg), &["send 3 REFUSED", "close 3 1000"]);
    // Unknown circuit.
    expect(
        &s.accept(30, 4, 1, &target, [0xcc; 16]),
        &["send 4 REFUSED", "close 4 1000"],
    );
    // Another handle, properly signed by that handle's key.
    expect(
        &s.accept(40, 5, 1, &key(&TARGET_B), circuit),
        &["send 5 REFUSED", "close 5 1000"],
    );
    let outs = s.accept(50, 6, 1, &target, circuit);
    expect(&outs, &["send 2 SPLICED", "send 6 SPLICED", "splice 2 6"]);
    s.finish()
}

fn accept_wait_expires() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "accept_wait_expires",
        "An admitted call with no accept leg gets UNREACHABLE when the accept wait fires; a late ACCEPT is refused like an unknown circuit.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    let circuit = incoming(&s.call(0, 2, 2, &caller, h, Class::Interactive));
    expect(&s.tick(ACCEPT_WAIT - 1), &[]);
    expect(
        &s.tick(ACCEPT_WAIT),
        &["send 2 UNREACHABLE", "close 2 1000"],
    );
    expect(
        &s.accept(ACCEPT_WAIT + 100, 3, 1, &target, circuit),
        &["send 3 REFUSED", "close 3 1000"],
    );
    s.finish()
}

fn successor_msg(
    s: &Sim,
    conn: u64,
    new: &RelayClientKey,
    current_signer: &RelayClientKey,
) -> RelayMessage {
    let b = s.binding(conn);
    RelayMessage::Successor {
        key: new.public_key(),
        new_proof: new.successor_proof(&relay_id(), &new.public_key(), &b),
        current_proof: current_signer.successor_proof(&relay_id(), &new.public_key(), &b),
    }
}

fn successor_without_current_key() -> J {
    let (target, new, caller) = (key(&TARGET), key(&NEW_TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "successor_without_current_key",
        "A SUCCESSOR whose current-key proof is not by the registered key is REFUSED(not_authorized) and closes the registration connection; its spliced circuit keeps running and the new key stays unauthorized.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.connect(10, 1, 2, 3, &caller, &target, Class::Interactive);
    let msg = successor_msg(&s, 1, &new, &new);
    expect(&s.send(20, 1, &msg), &["send 1 REFUSED", "close 1 1000"]);
    expect(&s.data(30, 2, 10), &["forward 2 3 10"]);
    s.hello(40, 4, 1);
    let msg = s.register_msg(4, &new);
    expect(&s.send(40, 4, &msg), &["send 4 REFUSED", "close 4 1000"]);
    s.finish()
}

fn successor_unauthorized_current() -> J {
    let (target, new, other) = (key(&TARGET), key(&NEW_TARGET), key(&STRANGER_TARGET));
    let mut s = Sim::new(
        "successor_unauthorized_current",
        "A SUCCESSOR proved by both keys authorizes the new key and supersedes the current one (no answer). The superseded key, still registered, cannot vouch for another successor. The new key registers on its own connection, and cannot name a key already on the list (the superseded one) as its successor.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.register(0, 1, 1, &target);
    let msg = successor_msg(&s, 1, &new, &target);
    let outs = s.send(10, 1, &msg);
    expect(&outs, &["authorize", "supersede"]);
    assert_eq!(
        outs[0],
        Output::Authorize {
            fingerprint: new.fingerprint()
        }
    );
    assert_eq!(
        outs[1],
        Output::Supersede {
            fingerprint: target.fingerprint(),
            drop_at: UnixTime(T + 604_800)
        }
    );
    let msg = successor_msg(&s, 1, &other, &target);
    expect(&s.send(20, 1, &msg), &["send 1 REFUSED", "close 1 1000"]);
    s.register(30, 2, 1, &new);
    s.hello(40, 3, 1);
    let msg = s.register_msg(3, &other);
    expect(&s.send(40, 3, &msg), &["send 3 REFUSED", "close 3 1000"]);
    let msg = successor_msg(&s, 2, &target, &new);
    expect(&s.send(50, 2, &msg), &["send 2 REFUSED", "close 2 1000"]);
    s.finish()
}

fn successor_drop() -> J {
    let (target, new, caller) = (key(&TARGET), key(&NEW_TARGET), key(&CALLER_1));
    let overlap = 86_400;
    let mut s = Sim::new(
        "successor_drop",
        "After a SUCCESSOR both keys register during the overlap. At the drop time the superseded key leaves the list and its registration and circuits close with 4000; it can no longer register.",
        Setup {
            authorized: &listed(&[TARGET]),
            limits: &[("RELAY_SUCCESSOR_OVERLAP_SECS", 86_400)],
            ..PLAIN
        },
    );
    s.register(0, 1, 1, &target);
    let msg = successor_msg(&s, 1, &new, &target);
    expect(&s.send(0, 1, &msg), &["authorize", "supersede"]);
    s.register(0, 2, 1, &new);
    // Both registrations idle out; nothing else happens.
    expect(
        &s.tick(45_000),
        &[
            "send 1 PING",
            "send 2 PING",
            "send 1 PING",
            "send 2 PING",
            "close 1 4002",
            "close 2 4002",
        ],
    );
    let late = overlap * 1000 - 1000;
    s.register(late, 3, 1, &target);
    expect(
        &s.allow(late, 3, 1, &[&caller], &[]),
        &["send 3 ALLOW_SET_OK"],
    );
    s.connect(late, 3, 4, 5, &caller, &target, Class::Interactive);
    expect(&s.tick(overlap * 1000 - 1), &[]);
    let outs = s.tick(overlap * 1000);
    expect(
        &outs,
        &["drop", "close 3 4000", "close 4 4000", "close 5 4000"],
    );
    assert_eq!(
        outs[0],
        Output::Drop {
            fingerprint: target.fingerprint()
        }
    );
    s.hello(overlap * 1000, 6, 1);
    let msg = s.register_msg(6, &target);
    expect(
        &s.send(overlap * 1000, 6, &msg),
        &["send 6 REFUSED", "close 6 1000"],
    );
    s.finish()
}

fn allow_set_lower_sequence() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "allow_set_lower_sequence",
        "After the first allow-set of a registration, a sequence not above the last one is ignored (no answer, no change). A new registration accepts any first sequence.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 5, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    expect(&s.allow(10, 1, 5, &[], &[]), &[]);
    expect(&s.allow(20, 1, 3, &[], &[]), &[]);
    expect(
        &s.call(30, 2, 2, &caller, h, Class::Interactive),
        &["send 1 INCOMING"],
    );
    expect(
        &s.allow(40, 1, 6, &[], &[]),
        &["close 2 4000", "send 1 ALLOW_SET_OK"],
    );
    s.hello(50, 3, 1);
    let msg = s.register_msg(3, &target);
    expect(&s.send(50, 3, &msg), &["close 1 4005", "send 3 REGISTERED"]);
    expect(
        &s.allow(60, 3, 1, &[&caller], &[]),
        &["send 3 ALLOW_SET_OK"],
    );
    s.finish()
}

fn promote_unlisted() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "promote_unlisted",
        "A PROMOTE naming a fingerprint not in the current allow-set, or a join circuit that is not spliced, is ignored: the circuit stays under the pre-accept budget.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    let live = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION)),
        expires_at: T + 3_600,
    };
    expect(&s.allow(0, 1, 1, &[], &[live]), &["send 1 ALLOW_SET_OK"]);
    let circuit = spliced_join(&mut s, 10, 2, 3, &target, INVITATION);
    let promote = RelayMessage::Promote {
        circuit,
        caller: caller.fingerprint(),
    };
    expect(&s.send(20, 1, &promote), &[]);
    let waiting = incoming(&s.join(30, 4, 2, h, tag(INVITATION)));
    expect(
        &s.allow(40, 1, 2, &[&caller], &[live]),
        &["send 1 ALLOW_SET_OK"],
    );
    expect(
        &s.send(
            50,
            1,
            &RelayMessage::Promote {
                circuit: waiting,
                caller: caller.fingerprint(),
            },
        ),
        &[],
    );
    expect(
        &s.accept(60, 5, 1, &target, waiting),
        &["send 4 SPLICED", "send 5 SPLICED", "splice 4 5"],
    );
    expect(&s.data(70, 2, 65_536), &["forward 2 3 65536"]);
    expect(&s.data(80, 2, 1), &["close 2 4006", "close 3 4006"]);
    expect(&s.data(90, 4, 65_536), &["forward 4 5 65536"]);
    expect(&s.data(100, 4, 1), &["close 4 4006", "close 5 4006"]);
    s.finish()
}

fn join_promoted() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "join_promoted",
        "After pairing over a join circuit the target lists the new caller and sends PROMOTE: the circuit leaves the pre-accept budget and the join count, and is that caller's call circuit from then on, closed with 4000 when the caller is removed.",
        Setup { authorized: &listed(&[TARGET]), limits: &[("RELAY_PREACCEPT_PER_TARGET", 1)], ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    let live = InvitationEntry {
        tag_hash: proof::tag_hash(&tag(INVITATION)),
        expires_at: T + 3_600,
    };
    expect(&s.allow(0, 1, 1, &[], &[live]), &["send 1 ALLOW_SET_OK"]);
    let circuit = spliced_join(&mut s, 10, 2, 3, &target, INVITATION);
    expect(
        &s.allow(20, 1, 2, &[&caller], &[live]),
        &["send 1 ALLOW_SET_OK"],
    );
    expect(
        &s.send(
            30,
            1,
            &RelayMessage::Promote {
                circuit,
                caller: caller.fingerprint(),
            },
        ),
        &[],
    );
    expect(&s.data(40, 2, 65_536), &["forward 2 3 65536"]);
    expect(&s.data(50, 2, 65_536), &["forward 2 3 65536"]);
    // The join count is free again.
    expect(&s.join(60, 4, 2, h, tag(INVITATION)), &["send 1 INCOMING"]);
    expect(
        &s.allow(70, 1, 3, &[], &[live]),
        &["close 2 4000", "close 3 4000", "send 1 ALLOW_SET_OK"],
    );
    s.finish()
}

fn circuits_outlive_registration() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "circuits_outlive_registration",
        "A circuit belongs to the handle: when the registration connection closes, a spliced circuit keeps forwarding and a waiting one can still be accepted. A new registration starts with no allow-set, so calls are refused until it pushes one; a second registration of the handle replaces the first (4005).",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.connect(10, 1, 2, 3, &caller, &target, Class::Interactive);
    let waiting = incoming(&s.call(20, 4, 2, &caller, h, Class::Bulk));
    expect(&s.closed(30, 1), &[]);
    expect(&s.data(40, 2, 10), &["forward 2 3 10"]);
    expect(
        &s.accept(50, 5, 1, &target, waiting),
        &["send 4 SPLICED", "send 5 SPLICED", "splice 4 5"],
    );
    s.register(60, 6, 1, &target);
    expect(&s.call(70, 7, 2, &caller, h, Class::Interactive), &[]);
    expect(
        &s.tick(70 + REFUSE),
        &["send 7 UNREACHABLE", "close 7 1000"],
    );
    expect(
        &s.allow(600, 6, 1, &[&caller], &[]),
        &["send 6 ALLOW_SET_OK"],
    );
    s.hello(700, 8, 1);
    let msg = s.register_msg(8, &target);
    expect(
        &s.send(700, 8, &msg),
        &["close 6 4005", "send 8 REGISTERED"],
    );
    expect(&s.data(710, 4, 10), &["forward 4 5 10"]);
    s.finish()
}

fn enrollment() -> J {
    let (target, other, stranger) = (key(&TARGET), key(&TARGET_B), key(&STRANGER));
    let mut s = Sim::new(
        "enrollment",
        "ENROLL with a valid code removes the code and authorizes the key, durably, before REGISTERED. A bad proof is REFUSED(not_authorized) and keeps the code; a used, expired or unknown code is REFUSED(enrollment). The enrolled key then registers normally.",
        Setup { codes: &[(CODE, T + 3_600), (CODE_2, T + 5)], ..PLAIN },
    );
    let enroll =
        |s: &Sim, conn: u64, k: &RelayClientKey, signer: &RelayClientKey, code: [u8; 16]| {
            RelayMessage::Enroll {
                key: k.public_key(),
                proof: signer.register_proof(&relay_id(), &s.binding(conn)),
                code,
            }
        };
    s.hello(0, 1, 1);
    let msg = enroll(&s, 1, &target, &stranger, CODE);
    expect(&s.send(0, 1, &msg), &["send 1 REFUSED", "close 1 1000"]);
    s.hello(10, 2, 1);
    let msg = enroll(&s, 2, &target, &target, CODE);
    let outs = s.send(10, 2, &msg);
    expect(&outs, &["consume_code", "authorize", "send 2 REGISTERED"]);
    assert_eq!(
        outs[0],
        Output::ConsumeCode {
            hash: proof::code_hash(&CODE)
        }
    );
    assert_eq!(
        outs[1],
        Output::Authorize {
            fingerprint: target.fingerprint()
        }
    );
    s.hello(20, 3, 2);
    let msg = enroll(&s, 3, &other, &other, CODE);
    let outs = s.send(20, 3, &msg);
    expect(&outs, &["send 3 REFUSED", "close 3 1000"]);
    assert_eq!(
        sent(&outs, 3),
        RelayMessage::Refused {
            reason: RefuseReason::Enrollment
        }
    );
    s.hello(6_000, 4, 2);
    let msg = enroll(&s, 4, &other, &other, CODE_2);
    expect(&s.send(6_000, 4, &msg), &["send 4 REFUSED", "close 4 1000"]);
    s.hello(6_010, 5, 2);
    let msg = enroll(&s, 5, &other, &other, [0x93; 16]);
    expect(&s.send(6_010, 5, &msg), &["send 5 REFUSED", "close 5 1000"]);
    s.hello(6_020, 6, 1);
    let msg = s.register_msg(6, &target);
    expect(
        &s.send(6_020, 6, &msg),
        &["close 2 4005", "send 6 REGISTERED"],
    );
    s.finish()
}

fn revoke() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "revoke",
        "The operator revokes a key: its registration and every circuit of its handle close with 4000 (caller legs first), and it can no longer register.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.connect(10, 1, 2, 3, &caller, &target, Class::Interactive);
    expect(
        &s.call(20, 4, 2, &caller, h, Class::Bulk),
        &["send 1 INCOMING"],
    );
    expect(
        &s.revoke(100, target.fingerprint()),
        &[
            "close 1 4000",
            "close 2 4000",
            "close 3 4000",
            "close 4 4000",
        ],
    );
    s.hello(200, 5, 1);
    let msg = s.register_msg(5, &target);
    expect(&s.send(200, 5, &msg), &["send 5 REFUSED", "close 5 1000"]);
    s.finish()
}

fn keepalive_and_idle() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "keepalive_and_idle",
        "A connection with no first message closes 4002 after RELAY_HELLO_WAIT_MS. The relay PINGs a registration RELAY_KEEPALIVE_MS after it last sent, answers a PING with a PONG, and closes it 4002 RELAY_REGISTRATION_IDLE_MS after it last received. A spliced circuit with no bytes for RELAY_CIRCUIT_IDLE_MS closes 4002.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    s.register(0, 1, 1, &target);
    s.hello(0, 2, 2);
    expect(
        &s.allow(100, 1, 1, &[&caller], &[]),
        &["send 1 ALLOW_SET_OK"],
    );
    s.connect(100, 1, 3, 4, &caller, &target, Class::Interactive);
    expect(&s.data(1_000, 3, 10), &["forward 3 4 10"]);
    expect(&s.tick(4_999), &[]);
    expect(&s.tick(5_000), &["close 2 4002"]);
    let outs = s.tick(15_100);
    expect(&outs, &["send 1 PING"]);
    let RelayMessage::Ping { data } = sent(&outs, 1) else {
        unreachable!()
    };
    expect(&s.send(20_000, 1, &RelayMessage::Pong { data }), &[]);
    let outs = s.send(20_000, 1, &RelayMessage::Ping { data: [7; 8] });
    expect(&outs, &["send 1 PONG"]);
    assert_eq!(sent(&outs, 1), RelayMessage::Pong { data: [7; 8] });
    expect(&s.tick(35_000), &["send 1 PING"]);
    expect(
        &s.tick(61_000),
        &["send 1 PING", "close 3 4002", "close 4 4002"],
    );
    expect(&s.tick(64_999), &[]);
    expect(&s.tick(65_000), &["close 1 4002"]);
    s.finish()
}

fn protocol_errors() -> J {
    let (target, caller, stranger) = (key(&TARGET), key(&CALLER_1), key(&STRANGER));
    let mut s = Sim::new(
        "protocol_errors",
        "A malformed message, a relay-to-client type, a hosted REGISTER in self mode, a message the role does not allow, anything on a leg before SPLICED, and a second REGISTER all close the connection with 1002 at once and nothing else is sent. A leg that ends this way ends its circuit; a refused caller that errs gets no UNREACHABLE.",
        Setup { authorized: &listed(&[TARGET]), ..PLAIN },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    s.hello(10, 2, 2);
    expect(&s.raw(10, 2, &[0xff]), &["close 2 1002"]);
    s.hello(20, 3, 2);
    let hello = RelayMessage::Hello {
        version: 1,
        nonce: [1; 32],
        boot_id: BOOT,
        mode: crate::relay::Mode::SelfHosted,
    };
    expect(&s.send(20, 3, &hello), &["close 3 1002"]);
    s.hello(30, 4, 1);
    let msg = RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&relay_id(), &s.binding(4)),
        hosted: Some((vec![1, 2, 3], 50)),
    };
    expect(&s.send(30, 4, &msg), &["close 4 1002"]);
    s.hello(40, 5, 2);
    expect(&s.allow(40, 5, 1, &[], &[]), &["close 5 1002"]);
    // A message on a waiting call leg ends its circuit.
    let circuit = incoming(&s.call(50, 6, 2, &caller, h, Class::Interactive));
    expect(
        &s.send(60, 6, &RelayMessage::Ping { data: [0; 8] }),
        &["close 6 1002"],
    );
    expect(
        &s.accept(70, 7, 1, &target, circuit),
        &["send 7 REFUSED", "close 7 1000"],
    );
    // Data on a waiting leg.
    expect(
        &s.call(80, 8, 2, &caller, h, Class::Interactive),
        &["send 1 INCOMING"],
    );
    expect(&s.data(90, 8, 10), &["close 8 1002"]);
    // A refused caller that sends more.
    expect(&s.call(100, 9, 2, &stranger, h, Class::Interactive), &[]);
    expect(
        &s.send(110, 9, &RelayMessage::Pong { data: [0; 8] }),
        &["close 9 1002"],
    );
    // Non-canonical: the same CALL with its map keys out of order.
    s.hello(120, 10, 2);
    let call = s.call_msg(10, &caller, h, Class::Interactive).encode();
    expect(
        &s.raw(120, 10, &swap_first_two_keys(&call)),
        &["close 10 1002"],
    );
    // A DER proof.
    s.hello(130, 11, 1);
    let der = target.register_proof(&relay_id(), &s.binding(11)).to_der();
    let bytes = cbor::encode(&Value::Map(vec![
        (0, Value::Uint(2)),
        (1, Value::Bytes(target.public_key().as_bytes().to_vec())),
        (2, Value::Bytes(der)),
    ]));
    expect(&s.raw(130, 11, &bytes), &["close 11 1002"]);
    // A second REGISTER on the registration connection.
    let msg = s.register_msg(1, &target);
    expect(&s.send(140, 1, &msg), &["close 1 1002"]);
    expect(&s.tick(100 + REFUSE), &[]);
    s.finish()
}

fn connection_limits() -> J {
    let (target, caller) = (key(&TARGET), key(&CALLER_1));
    let mut s = Sim::new(
        "connection_limits",
        "With RELAY_CONNECTIONS_PER_IP 2, a third connection from one address is closed 4006 before RELAY_HELLO (no nonce drawn); an accept leg stops counting against its address once its ACCEPT arrives. RELAY_CIRCUITS_PER_CALLER 2 refuses a third call at the refusal deadline. RELAY_ACCEPT_LEGS_PER_HANDLE 1 refuses a second accept leg with REFUSED(limit).",
        Setup {
            authorized: &listed(&[TARGET]),
            limits: &[
                ("RELAY_CONNECTIONS_PER_IP", 2),
                ("RELAY_CIRCUITS_PER_CALLER", 2),
                ("RELAY_ACCEPT_LEGS_PER_HANDLE", 1),
            ],
            ..PLAIN
        },
    );
    let h = s.register(0, 1, 1, &target);
    expect(&s.allow(0, 1, 1, &[&caller], &[]), &["send 1 ALLOW_SET_OK"]);
    let c1 = incoming(&s.call(10, 2, 2, &caller, h, Class::Interactive));
    let c2 = incoming(&s.call(20, 3, 2, &caller, h, Class::Bulk));
    expect(&s.open(30, 4, 2), &["close 4 4006"]);
    expect(&s.call(40, 5, 3, &caller, h, Class::Interactive), &[]);
    expect(
        &s.accept(50, 6, 1, &target, c1),
        &["send 2 SPLICED", "send 6 SPLICED", "splice 2 6"],
    );
    let outs = s.accept(60, 7, 1, &target, c2);
    expect(&outs, &["send 7 REFUSED", "close 7 1000"]);
    assert_eq!(
        sent(&outs, 7),
        RelayMessage::Refused {
            reason: RefuseReason::Limit
        }
    );
    expect(
        &s.tick(40 + REFUSE),
        &["send 5 UNREACHABLE", "close 5 1000"],
    );
    s.finish()
}

/// `bytes` is a canonical map; the same map with its first two entries
/// swapped (keys out of order, so not canonical).
fn swap_first_two_keys(bytes: &[u8]) -> Vec<u8> {
    let Value::Map(entries) = cbor::decode(bytes).expect("map") else {
        panic!("map")
    };
    let mut out = vec![bytes[0]];
    let mut parts: Vec<Vec<u8>> = entries
        .iter()
        .map(|(k, v)| {
            let one = cbor::encode(&Value::Map(vec![(*k, v.clone())]));
            one[1..].to_vec()
        })
        .collect();
    parts.swap(0, 1);
    for p in parts {
        out.extend(p);
    }
    out
}

fn scenarios() -> Vec<J> {
    vec![
        register_and_call(),
        unlisted_equals_offline(),
        register_other_key(),
        register_replayed(),
        call_replayed_other_connection(),
        call_other_relay(),
        removed_caller_closed(),
        removal_leaves_others(),
        join_without_tag(),
        preaccept_over_budget(),
        preaccept_per_target(),
        accept_wrong_key(),
        accept_wait_expires(),
        successor_without_current_key(),
        successor_unauthorized_current(),
        successor_drop(),
        allow_set_lower_sequence(),
        promote_unlisted(),
        join_promoted(),
        circuits_outlive_registration(),
        enrollment(),
        revoke(),
        keepalive_and_idle(),
        protocol_errors(),
        connection_limits(),
    ]
}

// ---------------------------------------------------------------------------
// Derivations and messages
// ---------------------------------------------------------------------------

fn derivations() -> J {
    let relay = identity(&RELAY);
    let rid = relay_id();
    let target = key(&TARGET);
    let caller = key(&CALLER_1);
    let new = key(&NEW_TARGET);
    let h = target.handle(&rid);
    let binding = Binding {
        nonce: [0xa1; 32],
        exporter: [0xa2; 32],
    };
    let circuit = [0xa3; 16];
    let proof_json = |name: &str, signer: &RelayClientKey, record: Vec<u8>, sig: RawSignature| {
        assert!(proof::verify(&signer.public_key(), &record, &sig).is_ok());
        json!({
            "name": name,
            "key": hex(signer.public_key().as_bytes()),
            "record": hex(&record),
            "signature": hex(sig.as_bytes()),
        })
    };
    let t = tag(INVITATION);
    let link = EnrollmentLink {
        host: RouteHost::Ipv4("203.0.113.5".parse().expect("ip")),
        port: 443,
        relay: rid,
        code: CODE,
    };
    let link6 = EnrollmentLink {
        host: RouteHost::Ipv6("2001:db8::7".parse().expect("ip")),
        port: 8443,
        relay: rid,
        code: CODE_2,
    };
    let text = link.to_text();
    json!({
        "relay_secret": hex(&RELAY),
        "relay_key": hex(relay.public_key().as_bytes()),
        "relay_id": hex(&rid.0),
        "relay_certificate": hex(&relay_certificate(&relay)),
        "other_relay_certificate": hex(&relay_certificate(&identity(&OTHER_RELAY))),
        "registration_key": hex(target.public_key().as_bytes()),
        "handle": hex(&h),
        "registration_fingerprint": hex(&target.fingerprint()),
        "nonce": hex(&binding.nonce),
        "exporter": hex(&binding.exporter),
        "circuit": hex(&circuit),
        "new_key": hex(new.public_key().as_bytes()),
        "new_handle": hex(&new.handle(&rid)),
        "proofs": [
            proof_json("register", &target, proof::register_record(&rid, &h, &binding), target.register_proof(&rid, &binding)),
            proof_json("successor_new", &new, proof::successor_record(&rid, &new.handle(&rid), &binding), new.successor_proof(&rid, &new.public_key(), &binding)),
            proof_json("successor_current", &target, proof::successor_record(&rid, &new.handle(&rid), &binding), target.successor_proof(&rid, &new.public_key(), &binding)),
            proof_json("call", &caller, proof::call_record(&rid, &h, &binding, Class::Bulk), caller.call_proof(&rid, &h, &binding, Class::Bulk)),
            proof_json("accept", &target, proof::accept_record(&rid, &h, &circuit, &binding), target.accept_proof(&rid, &circuit, &binding)),
        ],
        "invitation": {
            "id": hex(&INVITATION),
            "secret": hex(&TICKET_SECRET),
            "tag": hex(&t),
            "tag_hash": hex(&proof::tag_hash(&t)),
        },
        "enrollment": {
            "code": hex(&CODE),
            "code_hash": hex(&proof::code_hash(&CODE)),
            "links": [
                { "host": "203.0.113.5", "port": 443, "code": hex(&CODE), "text": text },
                { "host": "[2001:db8::7]", "port": 8443, "code": hex(&CODE_2), "text": link6.to_text() },
            ],
            "rejected_links": [
                text.replace("mousse-relay://", "relay://"),
                text.replace("/#", "#"),
                text.replace(":443", ":0443"),
                text.replace(":443", ""),
                format!("{text}="),
                text.replace('.', ""),
                format!("{text}A"),
                text.replace("203.0.113.5", "203.0.113.5.6"),
                "mousse-relay://203.0.113.5:443/#AA.AA".to_string(),
            ],
        },
    })
}

fn messages() -> J {
    let k = identity(&TARGET);
    let pk = k.public_key();
    let sig = k.sign_raw(b"relay message vector");
    let all = vec![
        RelayMessage::Hello {
            version: 1,
            nonce: [1; 32],
            boot_id: BOOT,
            mode: crate::relay::Mode::SelfHosted,
        },
        RelayMessage::Register {
            key: pk,
            proof: sig,
            hosted: None,
        },
        RelayMessage::Register {
            key: pk,
            proof: sig,
            hosted: Some((vec![0xab; 40], 50)),
        },
        RelayMessage::Enroll {
            key: pk,
            proof: sig,
            code: CODE,
        },
        RelayMessage::Registered { handle: [2; 32] },
        RelayMessage::AllowSet {
            sequence: 7,
            callers: vec![[3; 32], [4; 32]],
            invitations: vec![InvitationEntry {
                tag_hash: [5; 32],
                expires_at: T,
            }],
        },
        RelayMessage::AllowSet {
            sequence: 0,
            callers: vec![],
            invitations: vec![],
        },
        RelayMessage::AllowSetOk { sequence: 7 },
        RelayMessage::Call {
            handle: [2; 32],
            key: pk,
            proof: sig,
            class: Class::Bulk,
        },
        RelayMessage::Join {
            handle: [2; 32],
            tag: [6; 32],
        },
        RelayMessage::Incoming {
            circuit: [7; 16],
            class: Class::Interactive,
            caller: Some([3; 32]),
        },
        RelayMessage::Incoming {
            circuit: [7; 16],
            class: Class::Interactive,
            caller: None,
        },
        RelayMessage::Accept {
            handle: [2; 32],
            circuit: [7; 16],
            proof: sig,
        },
        RelayMessage::Spliced,
        RelayMessage::Unreachable,
        RelayMessage::Promote {
            circuit: [7; 16],
            caller: [3; 32],
        },
        RelayMessage::Refused {
            reason: RefuseReason::NotAuthorized,
        },
        RelayMessage::Refused {
            reason: RefuseReason::Enrollment,
        },
        RelayMessage::Successor {
            key: pk,
            new_proof: sig,
            current_proof: sig,
        },
        RelayMessage::Ping { data: [8; 8] },
        RelayMessage::Pong { data: [8; 8] },
    ];
    let valid: Vec<J> = all
        .iter()
        .map(|m| {
            let bytes = m.encode();
            assert_eq!(RelayMessage::decode(&bytes).as_ref(), Ok(m));
            json!({ "name": m.name(), "hex": hex(&bytes) })
        })
        .collect();
    let b = |x: &[u8]| Value::Bytes(x.to_vec());
    let u = Value::Uint;
    let map = |e: Vec<(u64, Value)>| cbor::encode(&Value::Map(e));
    let call = all[8].encode();
    let oversize = map(vec![(0, u(14)), (1, b(&vec![0; RELAY_MESSAGE_MAX]))]);
    let mut malformed = vec![
        ("not a map", cbor::encode(&Value::Array(vec![u(19)]))),
        ("type missing", map(vec![(1, b(&[8; 8]))])),
        ("unknown type 22", map(vec![(0, u(22))])),
        ("type 0", map(vec![(0, u(0))])),
        ("map keys out of order", swap_first_two_keys(&call)),
        ("non-minimal uint", {
            let mut v = map(vec![(0, u(6)), (1, u(7))]);
            // 0x07 as 0x18 0x07.
            let last = v.pop().expect("byte");
            v.extend([0x18, last]);
            v
        }),
        (
            "extra key",
            map(vec![(0, u(19)), (1, b(&[8; 8])), (2, u(0))]),
        ),
        ("missing key", map(vec![(0, u(13)), (1, b(&[7; 16]))])),
        (
            "PING data of 7 bytes",
            map(vec![(0, u(19)), (1, b(&[8; 7]))]),
        ),
        (
            "DER proof",
            map(vec![
                (0, u(2)),
                (1, b(pk.as_bytes())),
                (2, b(&sig.to_der())),
            ]),
        ),
        (
            "proof with s = 0",
            map(vec![
                (0, u(2)),
                (1, b(pk.as_bytes())),
                (2, b(&[[1u8; 32], [0u8; 32]].concat())),
            ]),
        ),
        (
            "compressed key",
            map(vec![
                (0, u(2)),
                (
                    1,
                    b(&{
                        let mut c = vec![0x02 | (pk.as_bytes()[64] & 1)];
                        c.extend_from_slice(&pk.as_bytes()[1..33]);
                        c
                    }),
                ),
                (2, b(sig.as_bytes())),
            ]),
        ),
        (
            "key not on the curve",
            map(vec![
                (0, u(2)),
                (
                    1,
                    b(&{
                        let mut c = pk.as_bytes().to_vec();
                        c[64] ^= 1;
                        c
                    }),
                ),
                (2, b(sig.as_bytes())),
            ]),
        ),
        (
            "REGISTER with a token and no threshold",
            map(vec![
                (0, u(2)),
                (1, b(pk.as_bytes())),
                (2, b(sig.as_bytes())),
                (3, b(&[1])),
            ]),
        ),
        (
            "REGISTER threshold 91",
            map(vec![
                (0, u(2)),
                (1, b(pk.as_bytes())),
                (2, b(sig.as_bytes())),
                (3, b(&[1])),
                (4, u(91)),
            ]),
        ),
        (
            "class 2",
            map(vec![
                (0, u(7)),
                (1, b(&[2; 32])),
                (2, b(pk.as_bytes())),
                (3, b(sig.as_bytes())),
                (4, u(2)),
            ]),
        ),
        (
            "mode 2",
            map(vec![
                (0, u(1)),
                (1, u(1)),
                (2, b(&[1; 32])),
                (3, b(&BOOT)),
                (4, u(2)),
            ]),
        ),
        (
            "version 2",
            map(vec![
                (0, u(1)),
                (1, u(2)),
                (2, b(&[1; 32])),
                (3, b(&BOOT)),
                (4, u(0)),
            ]),
        ),
        (
            "INCOMING call without caller",
            map(vec![(0, u(9)), (1, b(&[7; 16])), (2, u(0)), (3, u(0))]),
        ),
        (
            "INCOMING join with caller",
            map(vec![
                (0, u(9)),
                (1, b(&[7; 16])),
                (2, u(1)),
                (3, u(0)),
                (4, b(&[3; 32])),
            ]),
        ),
        (
            "duplicate caller fingerprints",
            map(vec![
                (0, u(5)),
                (1, u(1)),
                (2, Value::Array(vec![b(&[3; 32]), b(&[3; 32])])),
                (3, Value::Array(vec![])),
            ]),
        ),
        (
            "duplicate tag hashes",
            map(vec![
                (0, u(5)),
                (1, u(1)),
                (2, Value::Array(vec![])),
                (
                    3,
                    Value::Array(vec![
                        Value::Map(vec![(1, b(&[5; 32])), (2, u(T))]),
                        Value::Map(vec![(1, b(&[5; 32])), (2, u(T + 1))]),
                    ]),
                ),
            ]),
        ),
        (
            "257 caller fingerprints",
            map(vec![
                (0, u(5)),
                (1, u(1)),
                (
                    2,
                    Value::Array(
                        (0..257u32)
                            .map(|i| {
                                let mut f = [0u8; 32];
                                f[..4].copy_from_slice(&i.to_be_bytes());
                                b(&f)
                            })
                            .collect(),
                    ),
                ),
                (3, Value::Array(vec![])),
            ]),
        ),
        (
            "9 invitations",
            map(vec![
                (0, u(5)),
                (1, u(1)),
                (2, Value::Array(vec![])),
                (
                    3,
                    Value::Array(
                        (0..9u8)
                            .map(|i| Value::Map(vec![(1, b(&[i; 32])), (2, u(T))]))
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            "unknown refusal reason",
            map(vec![(0, u(16)), (1, Value::Text("busy".into()))]),
        ),
        ("over 16 384 bytes", oversize),
    ];
    malformed.sort_by_key(|(why, _)| *why);
    let malformed: Vec<J> = malformed
        .into_iter()
        .map(|(why, bytes)| {
            assert!(
                RelayMessage::decode(&bytes).is_err(),
                "{why} must not decode"
            );
            json!({ "why": why, "hex": hex(&bytes) })
        })
        .collect();
    json!({ "valid": valid, "malformed": malformed })
}

pub(super) fn relay_admission_vectors() -> J {
    json!({
        "description": "Relay protocol v1 (spec/relay.md): derivations, messages, and scripted runs of one self-hosted relay. Replay model in relay.md section 14.",
        "derivations": derivations(),
        "messages": messages(),
        "scenarios": scenarios(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    /// Every scenario checks its own rules while it is built.
    #[test]
    fn relay_admission_scenarios_hold() {
        let names: Vec<String> = scenarios()
            .iter()
            .map(|s| s["name"].as_str().expect("name").to_owned())
            .collect();
        for required in [
            "register_other_key",
            "successor_without_current_key",
            "successor_unauthorized_current",
            "call_replayed_other_connection",
            "register_replayed",
            "call_other_relay",
            "unlisted_equals_offline",
            "removed_caller_closed",
            "removal_leaves_others",
            "join_without_tag",
            "preaccept_over_budget",
            "preaccept_per_target",
            "accept_wrong_key",
            "allow_set_lower_sequence",
            "promote_unlisted",
        ] {
            assert!(names.iter().any(|n| n == required), "{required}");
        }
    }

    #[test]
    fn relay_admission_derivations_and_messages_hold() {
        derivations();
        messages();
    }
}
