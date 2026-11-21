//! Checks the Plus stand-in fixture itself over real HTTP, so the helper's
//! Plus tests can trust what it answers.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::plus_standin::{base64url, signed_envelope, PlusStandIn};
use mousse_net_core::cbor::{decode, encode, Fields, Value};
use mousse_net_core::identity::{PublicKey, RawSignature, SoftwareKey};
use mousse_net_io::rng::{os_rng, random_bytes};
use sha2::{Digest, Sha256};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn map(entries: Vec<(u64, Value)>) -> Vec<u8> {
    encode(&Value::Map(entries))
}

fn b(x: &[u8]) -> Value {
    Value::Bytes(x.to_vec())
}

/// One request, one answer: (status, body).
fn call_as(
    plus: &PlusStandIn,
    version: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&[u8]>,
) -> (u16, Vec<u8>) {
    let host = plus.url().trim_start_matches("http://").to_string();
    let mut sock = TcpStream::connect(&host).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let method = if body.is_some() { "POST" } else { "GET" };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nMousse-Plus-Api: {version}\r\nConnection: close\r\n"
    );
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/cbor\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    sock.write_all(head.as_bytes()).unwrap();
    if let Some(body) = body {
        sock.write_all(body).unwrap();
    }
    let mut answer = Vec::new();
    sock.read_to_end(&mut answer).unwrap();
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&answer[..split]).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, answer[split + 4..].to_vec())
}

fn call(plus: &PlusStandIn, path: &str, auth: Option<&str>, body: Option<&[u8]>) -> (u16, Vec<u8>) {
    call_as(plus, "1.0", path, auth, body)
}

fn error_code(body: &[u8]) -> String {
    let mut f = Fields::decode(body).unwrap();
    let code = f.text(1).unwrap();
    let _ = f.optional(2);
    f.finish().unwrap();
    code
}

fn field(body: &[u8], key: u64) -> Value {
    match decode(body).unwrap() {
        Value::Map(m) => m.into_iter().find(|(k, _)| *k == key).unwrap().1,
        _ => panic!("not a map"),
    }
}

fn field_bytes(body: &[u8], key: u64) -> Vec<u8> {
    match field(body, key) {
        Value::Bytes(x) => x,
        other => panic!("key {key} is {other:?}"),
    }
}

fn poll(plus: &PlusStandIn, key: &SoftwareKey, link_id: &[u8]) -> (u16, Vec<u8>) {
    let record = map(vec![
        (1, Value::Text("mousse-plus-link-v1".into())),
        (2, b(link_id)),
        (3, Value::Uint(now())),
    ]);
    call(
        plus,
        "/v1/link/poll",
        None,
        Some(&signed_envelope(&record, key)),
    )
}

fn start_link(plus: &PlusStandIn, key: &SoftwareKey) -> (Vec<u8>, String) {
    let body = map(vec![
        (1, b(key.public_key().as_bytes())),
        (2, Value::Text("test os".into())),
    ]);
    let (status, answer) = call(plus, "/v1/link/start", None, Some(&body));
    assert_eq!(status, 200);
    let code = match field(&answer, 2) {
        Value::Text(t) => t,
        other => panic!("code is {other:?}"),
    };
    (field_bytes(&answer, 1), code)
}

fn token_body(plus: &PlusStandIn, key: &SoftwareKey, ep: &[u8; 16], nonce: &[u8; 16]) -> Vec<u8> {
    let record = map(vec![
        (1, Value::Text("mousse-plus-token-v1".into())),
        (2, b(ep)),
        (3, Value::Text(plus.url())),
        (4, Value::Uint(now())),
        (5, b(nonce)),
    ]);
    signed_envelope(&record, key)
}

/// A linked endpoint with a bearer header.
fn linked(plus: &PlusStandIn) -> ([u8; 16], String) {
    let key = SoftwareKey::generate(&mut os_rng());
    let (_, code) = start_link(plus, &key);
    let ep = plus.approve(&code).unwrap();
    let body = token_body(plus, &key, &ep, &random_bytes());
    let (status, answer) = call(plus, "/v1/token", None, Some(&body));
    assert_eq!(status, 200);
    match field(&answer, 1) {
        Value::Text(t) => (ep, format!("Bearer {t}")),
        other => panic!("token is {other:?}"),
    }
}

#[test]
fn a_link_is_pending_until_approved_then_names_its_endpoint() {
    let plus = PlusStandIn::start();
    let key = SoftwareKey::generate(&mut os_rng());
    let (link_id, code) = start_link(&plus, &key);
    assert_eq!(plus.pending_codes(), vec![code.clone()]);

    let (status, answer) = poll(&plus, &key, &link_id);
    assert_eq!(status, 200);
    assert_eq!(field(&answer, 1), Value::Uint(0));

    let (status, answer) = poll(&plus, &key, &link_id);
    assert_eq!(
        (status, error_code(&answer).as_str()),
        (429, "rate_limited")
    );

    let ep = plus.approve(&code).unwrap();
    assert!(plus.approve(&code).is_none(), "approval is single use");
    std::thread::sleep(Duration::from_millis(80));
    let (status, answer) = poll(&plus, &key, &link_id);
    assert_eq!(status, 200);
    assert_eq!(field(&answer, 1), Value::Uint(1));
    assert_eq!(field_bytes(&answer, 2), ep);

    // The same Plus key linked again gets the same endpoint.
    let (_, again) = start_link(&plus, &key);
    assert_eq!(plus.approve(&again), Some(ep));

    let (status, answer) = call_as(&plus, "1.1", "/v1/link/poll", None, Some(&[0xa0]));
    assert_eq!((status, error_code(&answer).as_str()), (400, "version"));
}

#[test]
fn a_token_is_issued_once_per_nonce() {
    let plus = PlusStandIn::start();
    let key = SoftwareKey::generate(&mut os_rng());
    let (_, code) = start_link(&plus, &key);
    let ep = plus.approve(&code).unwrap();

    let body = token_body(&plus, &key, &ep, &random_bytes());
    let (status, answer) = call(&plus, "/v1/token", None, Some(&body));
    assert_eq!(status, 200);
    let token = match field(&answer, 1) {
        Value::Text(t) => t,
        other => panic!("token is {other:?}"),
    };
    let bearer = format!("Bearer {token}");
    let (status, answer) = call(&plus, "/v1/account", Some(&bearer), None);
    assert_eq!(status, 200);
    assert_eq!(field_bytes(&answer, 4), ep);

    let (status, answer) = call(&plus, "/v1/token", None, Some(&body));
    assert_eq!(
        (status, error_code(&answer).as_str()),
        (401, "unauthorized")
    );
}

#[test]
fn a_repeated_lease_request_gets_the_first_block_and_another_body_conflicts() {
    let plus = PlusStandIn::start();
    let (ep, bearer) = linked(&plus);
    let relay: [u8; 32] = random_bytes();
    let boot: [u8; 16] = random_bytes();
    plus.register_boot(relay, boot);

    let registration = SoftwareKey::generate(&mut os_rng());
    let proof = registration.sign_raw(&map(vec![
        (1, Value::Text("mousse-plus-handle-v1".into())),
        (2, b(&relay)),
        (3, b(&ep)),
    ]));
    let admit = map(vec![
        (1, b(&random_bytes::<16>())),
        (2, b(&relay)),
        (3, b(registration.public_key().as_bytes())),
        (4, b(proof.as_bytes())),
    ]);
    let (status, _) = call(&plus, "/v1/relay-admission", Some(&bearer), Some(&admit));
    assert_eq!(status, 200);
    let mut h = Sha256::new();
    h.update(b"mousse-relay-handle-v1");
    h.update(relay);
    h.update(registration.public_key().as_bytes());
    let handle: [u8; 32] = h.finalize().into();

    let id: [u8; 16] = random_bytes();
    let lease = |class: u64| {
        map(vec![
            (1, b(&id)),
            (2, b(&relay)),
            (3, b(&boot)),
            (4, b(&handle)),
            (5, Value::Uint(class)),
        ])
    };
    let (status, first) = call(&plus, "/v1/lease", Some(&bearer), Some(&lease(1)));
    assert_eq!(status, 200);
    let (status, again) = call(&plus, "/v1/lease", Some(&bearer), Some(&lease(1)));
    assert_eq!(status, 200);
    assert_eq!(first, again);
    assert_eq!(plus.lease_request_ids(), vec![id, id]);

    // The block is signed by the issuer and has the 13 frozen keys.
    let envelope = field_bytes(&first, 1);
    let mut env = Fields::decode(&envelope).unwrap();
    let record = env.bytes(1).unwrap();
    let sig = RawSignature::from_slice(&env.bytes(2).unwrap()).unwrap();
    env.finish().unwrap();
    PublicKey::from_sec1(&plus.issuer_public_key())
        .unwrap()
        .verify(&record, &sig)
        .unwrap();
    match decode(&record).unwrap() {
        Value::Map(m) => assert_eq!(
            m.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            (1..=13).collect::<Vec<_>>()
        ),
        _ => panic!("not a map"),
    }

    let (status, answer) = call(&plus, "/v1/lease", Some(&bearer), Some(&lease(0)));
    assert_eq!((status, error_code(&answer).as_str()), (409, "conflict"));
}

#[test]
fn a_deposit_with_a_wrong_token_is_unauthorized() {
    let plus = PlusStandIn::start();
    let (_, bearer) = linked(&plus);
    let inbox: [u8; 32] = random_bytes();
    let token: [u8; 32] = random_bytes();
    let tag: [u8; 16] = random_bytes();
    let hash: [u8; 32] = Sha256::digest(token).into();
    let put = map(vec![
        (1, b(&random_bytes::<16>())),
        (2, b(&inbox)),
        (3, Value::Uint(1)),
        (
            4,
            Value::Array(vec![Value::Map(vec![(1, b(&tag)), (2, b(&hash))])]),
        ),
    ]);
    let (status, _) = call(&plus, "/v1/inbox/put", Some(&bearer), Some(&put));
    assert_eq!(status, 200);

    let deposit = map(vec![
        (1, b(&random_bytes::<16>())),
        (2, b(&inbox)),
        (3, b(b"sealed")),
    ]);
    let right = format!("Deposit {}", base64url(&token));
    let (status, answer) = call(&plus, "/v1/inbox/deposit", Some(&right), Some(&deposit));
    assert_eq!(status, 200);
    let message_id = field_bytes(&answer, 1);

    let wrong = format!("Deposit {}", base64url(&random_bytes::<32>()));
    let (status, answer) = call(&plus, "/v1/inbox/deposit", Some(&wrong), Some(&deposit));
    assert_eq!(
        (status, error_code(&answer).as_str()),
        (401, "unauthorized")
    );

    let messages = plus.inbox_messages(inbox);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0.as_slice(), message_id.as_slice());
    assert_eq!(messages[0].1, tag);
}
