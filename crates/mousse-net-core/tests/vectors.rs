//! Checks the files in `spec/vectors/` through the public API only, the way
//! a second implementation would use them.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use mousse_net_core::authz::{
    CallerGate, CallerGateState, CallerTraffic, ConnectionGate, GateState, Traffic, Verdict,
};
use mousse_net_core::cbor;
use mousse_net_core::control::{
    negotiate_version, AuthorizedState, ControlMessage, HelloOutcome, HelloState, VersionSupport,
};
use mousse_net_core::grants::{GrantTable, NewGrant, OwnerRef, Role};
use mousse_net_core::identity::{IdentityPublicKey, RawSignature, SoftwareKey};
use mousse_net_core::mux::{decode_frame, Frame, Mux, MuxEvent, MuxRole, PriorityClass, StreamId};
use mousse_net_core::pairing::{
    attempt_sid, binding_transcript, join_proof_input, join_proof_mac, verify_join_proof,
    AttemptId, InvitationId, InvitationKind, Route, RouteHost, Ticket, TicketSecret,
};
use mousse_net_core::session::{PeerSession, SessionEvent};
use mousse_net_core::session_cert::{self, PendingCertificate, SessionKey, ValidityWindow};
use mousse_net_core::{ConnectionId, ErrorCode, Millis, UnixTime};
use serde_json::Value as J;

fn load(name: &str) -> J {
    let text = checked_in(name).unwrap_or_else(|| panic!("no vector file {name}"));
    serde_json::from_str(&text).expect("valid JSON")
}

/// A checked-in vector file.
#[cfg(not(target_arch = "wasm32"))]
fn checked_in(name: &str) -> Option<String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    std::fs::read_to_string(path).ok()
}

/// A checked-in vector file. wasm32 has no file system, so there the
/// files are compiled in.
#[cfg(target_arch = "wasm32")]
fn checked_in(name: &str) -> Option<String> {
    macro_rules! files {
        ($($file:literal,)*) => {
            match name {
                $($file => Some(include_str!(concat!("../../../spec/vectors/", $file)).to_string()),)*
                _ => None,
            }
        };
    }
    files!(
        "authz.json",
        "cbor.json",
        "control.json",
        "der-raw.json",
        "hello.json",
        "join-proof.json",
        "mux.json",
        "pairing-attempts.json",
        "relay-admission.json",
        "session-cert.json",
        "session-lifecycle.json",
        "ticket.json",
    )
}

fn unhex(v: &J) -> Vec<u8> {
    let text = v.as_str().expect("hex string");
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixed<const N: usize>(v: &J) -> [u8; N] {
    unhex(v).try_into().expect("length")
}

fn key(v: &J) -> IdentityPublicKey {
    IdentityPublicKey::from_sec1(&unhex(v)).expect("valid key")
}

fn u(v: &J) -> u64 {
    v.as_u64().expect("number")
}

fn s(v: &J) -> &str {
    v.as_str().expect("string")
}

fn list(v: &J) -> &Vec<J> {
    v.as_array().expect("array")
}

fn code_name(code: ErrorCode) -> &'static str {
    code.name()
}

#[test]
fn session_certificates() {
    let doc = load("session-cert.json");
    let v = &doc["valid"];

    // Keys and record.
    let id = SoftwareKey::from_secret_bytes(&fixed(&v["identity_secret"])).expect("identity");
    assert_eq!(
        id.public_key().as_bytes().as_slice(),
        unhex(&v["identity_public"])
    );
    let sk = SessionKey::from_secret_bytes(&fixed(&v["session_secret"])).expect("session");
    assert_eq!(
        sk.public_key().as_bytes().as_slice(),
        unhex(&v["session_public"])
    );
    assert_eq!(sk.spki_der(), unhex(&v["spki"]));
    let (nb, na) = (UnixTime(u(&v["not_before"])), UnixTime(u(&v["not_after"])));
    let record = session_cert::session_record(&sk.spki_der(), nb, na, u(&v["version"]));
    assert_eq!(record, unhex(&v["record"]));
    let sig = RawSignature::from_slice(&unhex(&v["identity_signature"])).expect("raw");
    id.public_key()
        .verify(&record, &sig)
        .expect("identity signature");

    // Rebuilding the certificate from its parts gives the same bytes.
    let pending = PendingCertificate::new(sk, ValidityWindow::new(nb, na).expect("window"));
    assert_eq!(pending.record().as_bytes(), record.as_slice());
    assert_eq!(pending.record().domain(), session_cert::SESSION_DOMAIN);
    let cert = pending.finish(id.public_key(), sig).expect("finish");
    assert_eq!(cert.der(), unhex(&v["certificate"]));
    let der = cert.der();
    let pos = der
        .windows(unhex(&v["serial"]).len())
        .position(|w| w == unhex(&v["serial"]).as_slice());
    assert!(pos.is_some(), "serial appears in the certificate");
    let ext = unhex(&v["extension_value"]);
    assert!(
        der.windows(ext.len()).any(|w| w == ext.as_slice()),
        "extension value appears in the certificate"
    );

    // TLS CertificateVerify signatures.
    let verified = session_cert::verify(der, nb.plus(60), Some(&id.public_key())).expect("verify");
    let t = &v["tls_signature"];
    let msg = unhex(&t["message"]);
    verified
        .verify_tls_signature(&msg, &unhex(&t["signature"]))
        .expect("tls signature");
    assert!(verified
        .verify_tls_signature(&msg, &unhex(&t["wrong_key_signature"]))
        .is_err());

    // Every case.
    let cases = list(&doc["cases"]);
    assert!(cases.len() >= 15);
    for case in cases {
        let pin = case["expected_identity"]
            .as_str()
            .map(|_| key(&case["expected_identity"]));
        let result = session_cert::verify(
            &unhex(&case["certificate"]),
            UnixTime(u(&case["now"])),
            pin.as_ref(),
        );
        let got = match result {
            Ok(_) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(got, s(&case["result"]), "case {}", s(&case["name"]));
    }

    // Certificates made in browser Workers with WebCrypto identity keys: the
    // native verifier accepts them, and their parts check out.
    let browser = list(&doc["browser_worker"]);
    assert!(!browser.is_empty());
    for item in browser {
        let name = s(&item["name"]);
        let identity = key(&item["identity_public"]);
        let (nb, na) = (
            UnixTime(u(&item["not_before"])),
            UnixTime(u(&item["not_after"])),
        );
        let verified =
            session_cert::verify(&unhex(&item["certificate"]), nb.plus(60), Some(&identity))
                .unwrap_or_else(|e| panic!("{name}: {}", e.code()));
        assert_eq!(verified.spki_der, unhex(&item["spki"]), "{name}");
        assert_eq!(
            verified.window,
            ValidityWindow::new(nb, na).expect("window")
        );
        let record = session_cert::session_record(&verified.spki_der, nb, na, verified.version);
        assert_eq!(record, unhex(&item["record"]), "{name}");
        let sig = RawSignature::from_slice(&unhex(&item["identity_signature"])).expect("raw");
        identity.verify(&record, &sig).expect("identity signature");
        assert!(
            cases
                .iter()
                .any(|c| s(&c["name"]) == name && s(&c["result"]) == "ok"),
            "{name} has an ok case"
        );
    }
    assert!(doc.get("pending").is_none());
}

#[test]
fn live_path_closes_at_certificate_expiry() {
    let doc = load("session-lifecycle.json");
    let pin = key(&doc["pin"]);
    let at = UnixTime(u(&doc["authenticated_at"]));
    let peer =
        session_cert::verify(&unhex(&doc["peer_certificate"]), at, Some(&pin)).expect("peer cert");
    let local = ValidityWindow::new(
        UnixTime(u(&doc["local_window"]["not_before"])),
        UnixTime(u(&doc["local_window"]["not_after"])),
    )
    .expect("window");
    let mut session = PeerSession::new(pin);
    let conn = ConnectionId(1);
    session.begin_path(conn);
    session
        .on_authenticated(conn, &peer, local, at, mono(at, at))
        .expect("authenticated");
    session.on_reopened(conn).expect("reopened");
    let path = *session.current().expect("current");
    assert_eq!(path.renew_at, UnixTime(u(&doc["renew_at"])));
    assert_eq!(path.deadline, UnixTime(u(&doc["deadline"])));
    check_ticks(&mut session, at, &doc["ticks"]);

    // The same path again; after the first request a new path with the
    // same certificates becomes current. The retries keep their schedule.
    let switch = &doc["switch_without_renewal"];
    let mut session = PeerSession::new(pin);
    session.begin_path(conn);
    session
        .on_authenticated(conn, &peer, local, at, mono(at, at))
        .expect("authenticated");
    session.on_reopened(conn).expect("reopened");
    assert_eq!(
        session.tick(path.renew_at, mono(at, path.renew_at)).len(),
        1
    );
    let switch_at = UnixTime(u(&switch["switch_at"]));
    let second = ConnectionId(2);
    session.begin_path(second);
    session
        .on_authenticated(second, &peer, local, switch_at, mono(at, switch_at))
        .expect("authenticated");
    session.on_reopened(second).expect("reopened");
    check_ticks(&mut session, at, &switch["ticks"]);

    // A retry skipped while a candidate comes up still counts, also the
    // first request at the renewal time.
    for (name, first_tick) in [
        ("retry_while_candidate", true),
        ("candidate_at_first_renewal", false),
    ] {
        let mut session = PeerSession::new(pin);
        session.begin_path(conn);
        session
            .on_authenticated(conn, &peer, local, at, mono(at, at))
            .expect("authenticated");
        session.on_reopened(conn).expect("reopened");
        if first_tick {
            assert_eq!(
                session.tick(path.renew_at, mono(at, path.renew_at)).len(),
                1
            );
        }
        for step in list(&doc[name]["steps"]) {
            let id = || ConnectionId(u(&step["conn"]));
            match s(&step["op"]) {
                "tick" => check_ticks(&mut session, at, &J::Array(vec![step.clone()])),
                "begin_path" => assert!(session.begin_path(id()).is_empty()),
                "path_closed" => session.on_path_closed(id()),
                other => panic!("op {other}"),
            }
        }
    }

    // Setting the wall clock back does not keep the path open.
    let rollback = &doc["clock_rollback"];
    let mut session = PeerSession::new(pin);
    session.begin_path(conn);
    session
        .on_authenticated(conn, &peer, local, at, mono(at, at))
        .expect("authenticated");
    session.on_reopened(conn).expect("reopened");
    assert_eq!(
        session.next_mono_deadline(),
        Some(Millis(u(&rollback["mono_deadline_ms"])))
    );
    check_ticks(&mut session, at, &rollback["ticks"]);

    let late = &doc["new_connection_after_deadline"];
    let err = session_cert::verify(
        &unhex(&doc["peer_certificate"]),
        UnixTime(u(&late["now"])),
        Some(&pin),
    )
    .unwrap_err();
    assert_eq!(err.code(), s(&late["result"]));
}

/// The vectors' monotonic clock: 0 ms at `authenticated_at`, running with
/// the wall clock unless a tick says otherwise.
fn mono(authenticated_at: UnixTime, now: UnixTime) -> Millis {
    Millis((now.secs() - authenticated_at.secs()) * 1_000)
}

fn check_ticks(session: &mut PeerSession, at: UnixTime, ticks: &J) {
    for tick in list(ticks) {
        let now = UnixTime(u(&tick["now"]));
        let mono = match tick.get("mono_ms") {
            Some(ms) => Millis(u(ms)),
            None => mono(at, now),
        };
        let events: Vec<String> = session
            .tick(now, mono)
            .into_iter()
            .map(|e| match e {
                SessionEvent::RenewDue { conn } => format!("renew_due/{}", conn.0),
                SessionEvent::Close { conn, code } => {
                    format!("close/{}/{}", conn.0, code_name(code))
                }
                other => format!("{other:?}"),
            })
            .collect();
        let expected: Vec<String> = list(&tick["events"])
            .iter()
            .map(|e| match s(&e["event"]) {
                "renew_due" => format!("renew_due/{}", u(&e["conn"])),
                "close" => format!("close/{}/{}", u(&e["conn"]), s(&e["code"])),
                other => panic!("event {other}"),
            })
            .collect();
        assert_eq!(events, expected, "tick at {}", u(&tick["now"]));
    }
}

fn traffic(name: &str) -> Traffic {
    match name {
        "keepalive" => Traffic::Keepalive,
        "hello" => Traffic::Hello,
        "goaway" => Traffic::GoAway,
        "join_proof" => Traffic::JoinProof,
        "pairing" => Traffic::Pairing,
        "stream" => Traffic::Stream,
        "host_only" => Traffic::HostOnly,
        other => panic!("traffic {other}"),
    }
}

fn verdict_name(v: Verdict) -> String {
    match v {
        Verdict::Allow => "allow".into(),
        Verdict::Ignore => "ignore".into(),
        Verdict::Close(code) => format!("close:{}", code.name()),
    }
}

#[test]
fn authorization() {
    let doc = load("authz.json");
    let ids = &doc["identities"];
    for case in list(&doc["cases"]) {
        let name = s(&case["name"]);
        let now = UnixTime(u(&case["now"]));
        let mut grants = GrantTable::new();
        for g in list(&case["grants"]) {
            grants
                .add(
                    NewGrant {
                        identity: key(&ids[s(&g["identity"])]),
                        name: "device".into(),
                        role: Role::new(s(&g["role"])).expect("role"),
                        authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                        expires_at: g["expires_at"].as_u64().map(UnixTime),
                        enrolled_by: None,
                    },
                    UnixTime(now.secs() - 60),
                )
                .expect("add");
        }
        for d in list(&case["denied"]) {
            grants.deny(key(&ids[s(d)]), now);
        }
        let mut gate = ConnectionGate::open(
            ConnectionId(1),
            key(&ids[s(&case["peer"])]),
            &mut grants,
            now,
            Millis(0),
        );
        let step2 = match gate.state() {
            GateState::Live { .. } => "live".to_owned(),
            GateState::AwaitingJoinProof { .. } => "await_join_proof".to_owned(),
            GateState::Closed(code) => format!("close:{}", code.name()),
            GateState::JoinOnly { .. } => "join_only".to_owned(),
        };
        assert_eq!(step2, s(&case["step2"]), "{name}");
        for step in list(&case["steps"]) {
            match s(&step["op"]) {
                "check" => {
                    let got = verdict_name(gate.check(traffic(s(&step["traffic"]))));
                    assert_eq!(got, s(&step["verdict"]), "{name}: {}", s(&step["traffic"]));
                }
                "admit_join_only" => gate.admit_join_only(InvitationId([0; 16])),
                "timeout" => {
                    let got = gate
                        .on_timeout(Millis(u(&step["mono_ms"])))
                        .map(|c| c.name());
                    assert_eq!(got, step["result"].as_str(), "{name}");
                }
                other => panic!("op {other}"),
            }
        }
    }
}

fn caller_traffic(name: &str) -> CallerTraffic {
    match name {
        "keepalive" => CallerTraffic::Keepalive,
        "hello" => CallerTraffic::Hello,
        "goaway" => CallerTraffic::GoAway,
        "authorized_live" => CallerTraffic::Authorized(AuthorizedState::Live),
        "authorized_join_only" => CallerTraffic::Authorized(AuthorizedState::JoinOnly),
        "pairing" => CallerTraffic::Pairing,
        "paired" => CallerTraffic::Paired,
        "stream" => CallerTraffic::Stream,
        "caller_only" => CallerTraffic::CallerOnly,
        other => panic!("caller traffic {other}"),
    }
}

fn caller_state_name(state: CallerGateState) -> String {
    match state {
        CallerGateState::AwaitingAuthorization => "awaiting_authorization".into(),
        CallerGateState::AwaitingProofAnswer => "awaiting_proof_answer".into(),
        CallerGateState::JoinOnly => "join_only".into(),
        CallerGateState::Live => "live".into(),
        CallerGateState::Closed(code) => format!("closed:{}", code.name()),
    }
}

#[test]
fn caller_gate() {
    let doc = load("authz.json");
    let ids = &doc["identities"];
    for case in list(&doc["caller_cases"]) {
        let name = s(&case["name"]);
        let now = UnixTime(case["now"].as_u64().unwrap_or(0));
        // The caller endpoint's own grants, for streams the host opens.
        let mut local = GrantTable::new();
        for g in case["local_grants"].as_array().into_iter().flatten() {
            local
                .add(
                    NewGrant {
                        identity: key(&ids[s(&g["identity"])]),
                        name: "device".into(),
                        role: Role::new(s(&g["role"])).expect("role"),
                        authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                        expires_at: g["expires_at"].as_u64().map(UnixTime),
                        enrolled_by: None,
                    },
                    UnixTime(now.secs().saturating_sub(60)),
                )
                .expect("add");
        }
        let mut gate = CallerGate::new();
        for step in list(&case["steps"]) {
            match s(&step["op"]) {
                "check" => {
                    let got = verdict_name(gate.check(caller_traffic(s(&step["traffic"]))));
                    assert_eq!(got, s(&step["verdict"]), "{name}: {}", s(&step["traffic"]));
                }
                "promote" => gate.promote(),
                "sent_join_proof" => gate.sent_join_proof(),
                "host_stream" => {
                    let host = key(&ids[s(&step["host"])]);
                    let got = gate.host_stream_authority(&local, &host, now);
                    let got = got.as_ref().map_or("none", |r| r.as_str());
                    assert_eq!(got, s(&step["result"]), "{name}: host_stream");
                }
                other => panic!("op {other}"),
            }
            assert_eq!(caller_state_name(gate.state()), s(&step["state"]), "{name}");
        }
    }
}

#[test]
fn hello_negotiation() {
    let doc = load("hello.json");
    let this = &doc["this_build"];
    assert_eq!(
        VersionSupport::LOCAL,
        VersionSupport {
            major: u(&this["major"]),
            minor: u(&this["minor"]),
            oldest_minor: u(&this["oldest_minor"]),
        }
    );
    assert_eq!(ControlMessage::hello().encode(), unhex(&doc["hello"]));
    for case in list(&doc["cases"]) {
        let local = &case["local"];
        let local = VersionSupport {
            major: u(&local["major"]),
            minor: u(&local["minor"]),
            oldest_minor: u(&local["oldest_minor"]),
        };
        let peer = &case["peer"];
        let got = match negotiate_version(local, u(&peer["major"]), u(&peer["minor"])) {
            Ok(minor) => J::from(minor),
            Err(code) => J::from(format!("close:{}", code.name())),
        };
        assert_eq!(got, case["result"], "{}", s(&case["name"]));
    }
    for seq in list(&doc["repeated"]) {
        let name = s(&seq["name"]);
        let local = &seq["local"];
        let mut state = HelloState::new(VersionSupport {
            major: u(&local["major"]),
            minor: u(&local["minor"]),
            oldest_minor: u(&local["oldest_minor"]),
        });
        for hello in list(&seq["hellos"]) {
            let Ok(ControlMessage::Hello {
                major_version,
                minor_version,
            }) = ControlMessage::decode(&unhex(&hello["control"]))
            else {
                panic!("{name}: not a HELLO");
            };
            let got = match state.on_hello(major_version, minor_version) {
                HelloOutcome::Agreed(minor) => J::from(minor),
                HelloOutcome::Ignored => J::from("ignored"),
                HelloOutcome::Close(code) => J::from(format!("close:{}", code.name())),
            };
            assert_eq!(got, hello["result"], "{name}");
        }
        assert_eq!(J::from(state.agreed()), seq["agreed"], "{name}");
    }
}

fn check_ticket(v: &J) -> Ticket {
    let t = Ticket::decode(&unhex(&v["binary"])).expect("valid ticket");
    assert_eq!(t.version, u(&v["version"]));
    assert_eq!(t.kind.as_u64(), u(&v["kind"]));
    assert_eq!(t.host_identity, key(&v["host_identity"]));
    assert_eq!(t.invitation, InvitationId(fixed(&v["invitation"])));
    assert_eq!(t.secret, TicketSecret::from_bytes(fixed(&v["secret"])));
    assert_eq!(t.expires_at, UnixTime(u(&v["expires_at"])));
    let routes: Vec<&str> = list(&v["routes"]).iter().map(s).collect();
    assert_eq!(t.routes, routes);
    assert_eq!(t.encode(), unhex(&v["binary"]));
    assert_eq!(t.to_fragment(), s(&v["fragment"]));
    assert_eq!(
        Ticket::from_fragment(s(&v["fragment"])).expect("fragment"),
        t
    );
    assert_eq!(t.hash().as_slice(), unhex(&v["hash"]));
    t
}

#[test]
fn tickets() {
    let doc = load("ticket.json");
    let t = check_ticket(&doc["valid"]);
    assert_eq!(t.kind, InvitationKind::SendLink);
    assert_eq!(
        check_ticket(&doc["valid_in_person"]).kind,
        InvitationKind::InPerson
    );
    for case in list(&doc["rejections"]) {
        let result = if case["binary"].is_string() {
            Ticket::decode(&unhex(&case["binary"]))
        } else {
            Ticket::from_fragment(s(&case["fragment"]))
        };
        let err = result.expect_err(s(&case["name"]));
        assert_eq!(err.code(), s(&case["result"]), "{}", s(&case["name"]));
    }
    let fresh = &doc["joiner_freshness"];
    let mut t = t;
    t.expires_at = UnixTime(u(&fresh["expires_at"]));
    for case in list(&fresh["cases"]) {
        let got = match t.check_fresh_for_joiner(UnixTime(u(&case["now"]))) {
            Ok(()) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(got, s(&case["result"]));
    }
    for case in list(&doc["route_hints"]["cases"]) {
        let hint = s(&case["hint"]);
        let expected = &case["result"];
        match Route::parse(hint) {
            Ok(Route::Tcp { host, port }) => {
                let tcp = &expected["tcp"];
                assert_eq!(u(&tcp["port"]), u64::from(port), "{hint}");
                let host_ok = match host {
                    RouteHost::Ipv4(a) => tcp["host"]["ipv4"] == a.to_string(),
                    RouteHost::Ipv6(a) => unhex(&tcp["host"]["ipv6"]) == a.octets(),
                    RouteHost::Dns(n) => tcp["host"]["dns"] == n,
                };
                assert!(host_ok, "{hint}");
            }
            Ok(Route::Mdns { instance }) => assert_eq!(expected["mdns"], instance, "{hint}"),
            Err(skip) => assert_eq!(expected["skip"], skip.name(), "{hint}"),
        }
    }
}

#[test]
fn join_proof_and_binding_transcript() {
    let doc = load("join-proof.json");
    let t = Ticket::decode(&unhex(&doc["ticket_binary"])).expect("ticket");
    assert_eq!(t.hash().as_slice(), unhex(&doc["ticket_hash"]));
    let host = key(&doc["host_identity"]);
    let joiner = key(&doc["joiner_identity"]);
    let p = &doc["join_proof"];
    let inv = InvitationId(fixed(&p["invitation"]));
    let secret = TicketSecret::from_bytes(fixed(&p["secret"]));
    let exporter: [u8; 32] = fixed(&p["join_exporter"]);
    assert_eq!(
        join_proof_input(&inv, &host, &joiner, &exporter),
        unhex(&p["input"])
    );
    let mac: [u8; 32] = fixed(&p["mac"]);
    assert_eq!(
        join_proof_mac(&secret, &inv, &host, &joiner, &exporter),
        mac
    );
    assert!(verify_join_proof(
        &secret, &inv, &host, &joiner, &exporter, &mac
    ));
    assert!(!verify_join_proof(
        &secret, &inv, &joiner, &host, &exporter, &mac
    ));
    let b = &doc["binding_transcript"];
    let kind = InvitationKind::from_u64(u(&b["kind"])).expect("kind");
    let transcript = binding_transcript(
        &t.hash(),
        kind,
        u(&b["ticket_version"]),
        &host,
        &joiner,
        &fixed(&b["pair_exporter"]),
    );
    assert_eq!(transcript.as_bytes(), unhex(&b["transcript"]));
    let sid = &doc["sid"];
    let attempt = AttemptId(fixed(&sid["attempt"]));
    let exporter: [u8; 32] = fixed(&sid["pair_exporter"]);
    assert_eq!(
        cbor::decode(&unhex(&sid["input"])).map(|v| cbor::encode(&v)),
        Ok(unhex(&sid["input"]))
    );
    assert_eq!(
        attempt_sid(&attempt, &exporter).as_slice(),
        unhex(&sid["sid"])
    );
}

#[test]
fn canonical_cbor() {
    let doc = load("cbor.json");
    for case in list(&doc["valid"]) {
        let bytes = unhex(&case["hex"]);
        let value =
            cbor::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", s(&case["diagnostic"])));
        assert_eq!(cbor::encode(&value), bytes);
    }
    for case in list(&doc["invalid"]) {
        let err = cbor::decode(&unhex(&case["hex"])).expect_err(s(&case["description"]));
        assert_eq!(err.code(), s(&case["error"]), "{}", s(&case["description"]));
    }
}

#[test]
fn der_to_raw() {
    let doc = load("der-raw.json");
    for case in list(&doc["der_to_raw"]) {
        let name = s(&case["name"]);
        let result = RawSignature::from_der(&unhex(&case["der"]));
        if case["raw"].is_string() {
            let raw = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(raw.as_bytes().as_slice(), unhex(&case["raw"]), "{name}");
            assert_eq!(raw.to_der(), unhex(&case["der"]), "{name}");
        } else {
            assert_eq!(result.expect_err(name).code(), s(&case["error"]), "{name}");
        }
    }
    for case in list(&doc["raw_only"]) {
        let got = match RawSignature::from_slice(&unhex(&case["input"])) {
            Ok(_) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(got, s(&case["result"]), "{}", s(&case["name"]));
    }
}

#[test]
fn mux_stream_rules() {
    let doc = load("mux.json");
    for case in list(&doc["streams"]["cases"]) {
        let name = s(&case["name"]);
        let role = match s(&case["role"]) {
            "host" => MuxRole::Host,
            "caller" => MuxRole::Caller,
            other => panic!("role {other}"),
        };
        let mut mux = Mux::new(role, Millis(0));
        for step in list(&case["steps"]) {
            let bytes = unhex(&step["hex"]);
            assert_eq!(
                frame_from_json(&step["frame"]).encode(),
                bytes,
                "{name}: frame"
            );
            let got = match mux.receive(&bytes, Millis(0)) {
                Ok(events) => J::Array(
                    events
                        .into_iter()
                        .map(|e| {
                            J::String(match e {
                                MuxEvent::StreamOpened { stream, .. } => {
                                    format!("opened:{}", stream.0)
                                }
                                MuxEvent::Data { stream, bytes } => {
                                    format!("data:{}:{}", stream.0, bytes.len())
                                }
                                MuxEvent::Finished { stream } => format!("finished:{}", stream.0),
                                MuxEvent::Reset { stream, code } => {
                                    format!("reset:{}:{}", stream.0, code.name())
                                }
                                other => panic!("{name}: {other:?}"),
                            })
                        })
                        .collect(),
                ),
                Err(e) => {
                    let goaway = mux.poll_transmit(Millis(0)).expect("goaway");
                    assert_eq!(
                        decode_frame(&goaway),
                        Ok(Some((Frame::GoAway { code: e.code }, goaway.len()))),
                        "{name}: goaway"
                    );
                    J::String(format!("close:{}", e.code.name()))
                }
            };
            assert_eq!(got, step["result"], "{name}");
        }
    }
}

fn frame_from_json(v: &J) -> Frame {
    let stream = || StreamId(u32::try_from(u(&v["stream"])).expect("u32"));
    let code =
        || ErrorCode::from_u16(u16::try_from(u(&v["code"])).expect("u16")).expect("known code");
    match s(&v["type"]) {
        "data" => Frame::Data {
            stream: stream(),
            payload: unhex(&v["payload"]),
        },
        "open" => Frame::Open {
            stream: stream(),
            class: if u(&v["class"]) == 0 {
                PriorityClass::Interactive
            } else {
                PriorityClass::Bulk
            },
            label: s(&v["label"]).to_owned(),
        },
        "credit" => Frame::Credit {
            stream: stream(),
            increment: u32::try_from(u(&v["increment"])).expect("u32"),
        },
        "fin" => Frame::Fin { stream: stream() },
        "reset" => Frame::Reset {
            stream: stream(),
            code: code(),
        },
        "ping" => Frame::Ping {
            opaque: fixed(&v["opaque"]),
        },
        "pong" => Frame::Pong {
            opaque: fixed(&v["opaque"]),
        },
        "control" => Frame::Control {
            payload: unhex(&v["payload"]),
        },
        "goaway" => Frame::GoAway { code: code() },
        other => panic!("frame type {other}"),
    }
}

#[test]
fn mux_frames() {
    let doc = load("mux.json");
    for case in list(&doc["valid"]) {
        let bytes = unhex(&case["hex"]);
        let expected = frame_from_json(&case["frame"]);
        let (frame, used) = decode_frame(&bytes).expect("valid").expect("complete");
        assert_eq!(frame, expected);
        assert_eq!(used, bytes.len());
        assert_eq!(frame.encode(), bytes);
        // One byte short is "need more", never an error.
        assert_eq!(decode_frame(&bytes[..bytes.len() - 1]), Ok(None));
    }
    let unknown = unhex(&doc["unknown_error_code"]["hex"]);
    assert!(matches!(
        decode_frame(&unknown),
        Ok(Some((Frame::Reset { .. }, _)))
    ));
    for case in list(&doc["invalid"]) {
        let name = s(&case["name"]);
        let got = match decode_frame(&unhex(&case["hex"])) {
            Ok(None) => "need_more",
            Ok(Some(_)) => panic!("{name} decoded"),
            Err(e) => e.name(),
        };
        assert_eq!(got, s(&case["result"]), "{name}");
    }
}

#[test]
fn control_messages() {
    let doc = load("control.json");
    for case in list(&doc["valid"]) {
        let bytes = unhex(&case["hex"]);
        let m = ControlMessage::decode(&bytes).expect("valid");
        assert_eq!(m.type_number(), u(&case["type"]));
        assert_eq!(m.encode(), bytes);
    }
    for case in list(&doc["invalid"]) {
        assert!(
            ControlMessage::decode(&unhex(&case["hex"])).is_err(),
            "{}",
            s(&case["name"])
        );
    }
}

// ---------------------------------------------------------------------------
// Relay admission (spec/relay.md section 14)
// ---------------------------------------------------------------------------

/// Hands out a scenario's listed random values, in order.
struct Listed(std::collections::VecDeque<Vec<u8>>);

impl rand_core::TryRng for Listed {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("the relay draws only bytes")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("the relay draws only bytes")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let next = self.0.pop_front().expect("a listed draw");
        assert_eq!(next.len(), dst.len(), "draw length");
        dst.copy_from_slice(&next);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Listed {}

fn relay_output(o: &mousse_net_core::relay::Output) -> J {
    use mousse_net_core::relay::{Output, RelayMessage};
    let h = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    match o {
        Output::Send { conn, message } => serde_json::json!({
            "send": conn.0,
            "message": RelayMessage::decode(message).expect("decodes").name(),
            "hex": h(message),
        }),
        Output::Close { conn, code } => serde_json::json!({ "close": conn.0, "code": code }),
        Output::Splice {
            circuit,
            caller,
            target,
            class,
        } => serde_json::json!({
            "splice": [caller.0, target.0],
            "circuit": h(circuit),
            "class": *class as u64,
        }),
        Output::Forward { from, to, len } => {
            serde_json::json!({ "forward": [from.0, to.0], "len": len })
        }
        Output::Authorize { fingerprint } => serde_json::json!({ "authorize": h(fingerprint) }),
        Output::Supersede {
            fingerprint,
            drop_at,
        } => serde_json::json!({ "supersede": h(fingerprint), "drop_at": drop_at.0 }),
        Output::Drop { fingerprint } => serde_json::json!({ "drop": h(fingerprint) }),
        Output::ConsumeCode { hash } => serde_json::json!({ "consume_code": h(hash) }),
        // Hosted mode only; the vectors cover self mode.
        Output::Hold { conn, until } => serde_json::json!({ "hold": conn.0, "until": until.0 }),
        Output::Pause { conn } => serde_json::json!({ "pause": conn.0 }),
        Output::Resume { conn } => serde_json::json!({ "resume": conn.0 }),
    }
}

#[test]
fn relay_admission() {
    use mousse_net_core::relay::machine::{AuthorizedKey, EnrollCode, Now, RelayConfig};
    use mousse_net_core::relay::{
        check_pin, proof, relay_certificate, Class, ConnId, EnrollmentLink, IpKey, Relay, RelayId,
        RelayLimits, RelayMessage,
    };

    let doc = load("relay-admission.json");

    // Derivations.
    let d = &doc["derivations"];
    let relay_secret = SoftwareKey::from_secret_bytes(&fixed::<32>(&d["relay_secret"])).unwrap();
    let relay_key = key(&d["relay_key"]);
    assert_eq!(relay_secret.public_key(), relay_key);
    let rid = RelayId::of(&relay_key);
    assert_eq!(rid.0, fixed::<32>(&d["relay_id"]));
    let cert = unhex(&d["relay_certificate"]);
    assert_eq!(relay_certificate(&relay_secret), cert);
    assert_eq!(check_pin(&cert, &rid), Ok(relay_key));
    assert!(
        check_pin(&unhex(&d["other_relay_certificate"]), &rid).is_err(),
        "another relay's certificate passes the pin"
    );
    let reg = key(&d["registration_key"]);
    let handle = fixed::<32>(&d["handle"]);
    assert_eq!(proof::handle(&rid, &reg), handle);
    assert_eq!(
        reg.fingerprint(),
        fixed::<32>(&d["registration_fingerprint"])
    );
    let new_handle = fixed::<32>(&d["new_handle"]);
    assert_eq!(proof::handle(&rid, &key(&d["new_key"])), new_handle);
    let binding = proof::Binding {
        nonce: fixed(&d["nonce"]),
        exporter: fixed(&d["exporter"]),
    };
    let circuit = fixed::<16>(&d["circuit"]);
    for p in list(&d["proofs"]) {
        let record = match s(&p["name"]) {
            "register" => proof::register_record(&rid, &handle, &binding),
            "successor_new" | "successor_current" => {
                proof::successor_record(&rid, &new_handle, &binding)
            }
            "call" => proof::call_record(&rid, &handle, &binding, Class::Bulk),
            "accept" => proof::accept_record(&rid, &handle, &circuit, &binding),
            other => panic!("proof {other}"),
        };
        assert_eq!(record, unhex(&p["record"]), "{}", s(&p["name"]));
        let sig = RawSignature::from_slice(&unhex(&p["signature"])).unwrap();
        assert!(proof::verify(&key(&p["key"]), &record, &sig).is_ok());
    }
    let inv = &d["invitation"];
    let tag = proof::invitation_tag(
        &InvitationId(fixed(&inv["id"])),
        &TicketSecret::from_bytes(fixed(&inv["secret"])),
    );
    assert_eq!(tag, fixed::<32>(&inv["tag"]));
    assert_eq!(proof::tag_hash(&tag), fixed::<32>(&inv["tag_hash"]));
    let e = &d["enrollment"];
    assert_eq!(
        proof::code_hash(&fixed(&e["code"])),
        fixed::<32>(&e["code_hash"])
    );
    for l in list(&e["links"]) {
        let link = EnrollmentLink::parse(s(&l["text"])).expect("link");
        assert_eq!(
            link.authority(),
            format!("{}:{}", s(&l["host"]), u(&l["port"]))
        );
        assert_eq!(link.relay, rid);
        assert_eq!(link.code, fixed::<16>(&l["code"]));
        assert_eq!(link.to_text(), s(&l["text"]));
    }
    for bad in list(&e["rejected_links"]) {
        assert!(EnrollmentLink::parse(s(bad)).is_err(), "{bad}");
    }

    // Messages.
    for m in list(&doc["messages"]["valid"]) {
        let bytes = unhex(&m["hex"]);
        let msg = RelayMessage::decode(&bytes).expect("valid");
        assert_eq!(msg.name(), s(&m["name"]));
        assert_eq!(msg.encode(), bytes);
    }
    for m in list(&doc["messages"]["malformed"]) {
        assert!(
            RelayMessage::decode(&unhex(&m["hex"])).is_err(),
            "{}",
            s(&m["why"])
        );
    }

    // Scenarios.
    for sc in list(&doc["scenarios"]) {
        let name = s(&sc["name"]);
        let overrides: Vec<(String, u64)> = sc["limits"]
            .as_object()
            .expect("limits")
            .iter()
            .map(|(k, v)| (k.clone(), u(v)))
            .collect();
        let overrides: Vec<(&str, u64)> = overrides.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        let config = RelayConfig {
            relay_key: key(&sc["relay_key"]),
            boot_id: fixed(&sc["boot_id"]),
            limits: RelayLimits::DEFAULT
                .with_overrides(&overrides)
                .expect("limits"),
        };
        let authorized: Vec<AuthorizedKey> = list(&sc["authorized"])
            .iter()
            .map(|a| AuthorizedKey {
                fingerprint: fixed(&a["fingerprint"]),
                drop_at: a.get("drop_at").map(|t| UnixTime(u(t))),
            })
            .collect();
        let codes: Vec<EnrollCode> = list(&sc["codes"])
            .iter()
            .map(|c| EnrollCode {
                hash: fixed(&c["hash"]),
                expires_at: UnixTime(u(&c["expires_at"])),
            })
            .collect();
        let mut relay = Relay::new(config, &authorized, &codes);
        let mut rng = Listed(list(&sc["draws"]).iter().map(unhex).collect());
        let wall_base = u(&sc["wall_base"]);
        for (i, ev) in list(&sc["events"]).iter().enumerate() {
            let at = u(&ev["at"]);
            let now = Now {
                mono: Millis(at),
                wall: UnixTime(wall_base + at / 1000),
            };
            let conn = || ConnId(u(&ev["conn"]));
            let outs = match s(&ev["event"]) {
                "open" => relay.open(
                    conn(),
                    IpKey(fixed(&ev["ip"])),
                    fixed(&ev["exporter"]),
                    now,
                    &mut rng,
                ),
                "recv" => relay.receive(conn(), &unhex(&ev["hex"]), now, &mut rng),
                "data" => relay.data(conn(), u(&ev["len"]) as usize, now, &mut rng),
                "closed" => relay.closed(conn(), now, &mut rng),
                "tick" => relay.tick(now, &mut rng),
                "revoke" => relay.revoke(&fixed(&ev["fingerprint"]), now, &mut rng),
                other => panic!("event {other}"),
            };
            let got: Vec<J> = outs.iter().map(relay_output).collect();
            assert_eq!(&J::Array(got), &ev["out"], "{name} event {i}");
        }
        assert!(rng.0.is_empty(), "{name}: unused draws");
    }
}
