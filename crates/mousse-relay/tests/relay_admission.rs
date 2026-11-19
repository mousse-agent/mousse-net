//! `phase3.relay-admission` over real connections on loopback: calls
//! splice only for listed callers; every refused call is answered at the
//! same constant deadline (the timing rule); a wrong relay key fails before
//! any relay message; `SUCCESSOR` needs the current key.

mod common;

use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::relay::{Class, RefuseReason, RelayId, RelayMessage};
use mousse_relay::client::{DialError, Received, RelayConn};

#[tokio::test(flavor = "multi_thread")]
async fn a_listed_caller_splices_and_bytes_pass_unchanged() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("splice", &[], &[&target]).await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let (mut leg, mut acc) = f
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    let up: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
    leg.send_raw(up.clone()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(up));
    acc.send_raw(b"down".to_vec()).await.unwrap();
    assert_eq!(next(&mut leg).await, Received::Peer(b"down".to_vec()));
    // One leg closing closes the other with 1000.
    leg.close().await;
    assert_eq!(closed(&mut acc).await, Some(1000));
}

/// The timing rule: an unlisted caller, an offline target, an unknown
/// handle and a bad proof all get `UNREACHABLE` at `RELAY_REFUSE_MS`, the
/// same for each, never early.
#[tokio::test(flavor = "multi_thread")]
async fn every_refusal_is_answered_at_the_same_deadline() {
    let (target, offline, caller, stranger) = (key(0x61), key(0x62), key(0x71), key(0x73));
    let f = Fixture::new("timing", &[], &[&target, &offline]).await;
    let refuse = Duration::from_millis(f.limits.refuse_ms());
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let h = f.handle(&target);

    let cases = ["unlisted", "offline", "unknown", "bad proof"];
    let mut times: Vec<(&str, Duration)> = Vec::new();
    for what in cases.iter().cycle().take(12).copied() {
        let mut c = f.dial().await;
        let msg = match what {
            "unlisted" => RelayMessage::Call {
                handle: h,
                key: stranger.public_key(),
                proof: stranger.call_proof(&f.id, &h, &c.binding, Class::Interactive),
                class: Class::Interactive,
            },
            "offline" => {
                let h2 = f.handle(&offline);
                RelayMessage::Call {
                    handle: h2,
                    key: caller.public_key(),
                    proof: caller.call_proof(&f.id, &h2, &c.binding, Class::Interactive),
                    class: Class::Interactive,
                }
            }
            "unknown" => RelayMessage::Call {
                handle: [0xee; 32],
                key: caller.public_key(),
                proof: caller.call_proof(&f.id, &[0xee; 32], &c.binding, Class::Interactive),
                class: Class::Interactive,
            },
            _ => RelayMessage::Call {
                handle: h,
                key: caller.public_key(),
                proof: stranger.call_proof(&f.id, &h, &c.binding, Class::Interactive),
                class: Class::Interactive,
            },
        };
        let sent = Instant::now();
        c.send(&msg).await.unwrap();
        let got = next(&mut c).await;
        let took = sent.elapsed();
        assert_eq!(got, Received::Relay(RelayMessage::Unreachable), "{what}");
        assert_eq!(closed(&mut c).await, Some(1000), "{what}");
        times.push((what, took));
    }
    for (what, took) in &times {
        assert!(
            *took >= refuse,
            "{what} answered after {took:?}, before the deadline"
        );
        assert!(
            *took < refuse + Duration::from_millis(250),
            "{what} answered after {took:?}"
        );
    }
    let min = times.iter().map(|t| t.1).min().unwrap();
    let max = times.iter().map(|t| t.1).max().unwrap();
    assert!(
        max - min < Duration::from_millis(200),
        "spread {:?}",
        max - min
    );
    // The registration was never told about any of them.
    reg.send(&RelayMessage::Ping { data: [1; 8] })
        .await
        .unwrap();
    assert_eq!(relay(&mut reg).await, RelayMessage::Pong { data: [1; 8] });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_relay_key_fails_in_the_handshake() {
    let target = key(0x61);
    let f = Fixture::new("pin", &[], &[&target]).await;
    let wrong = RelayId([0x42; 32]);
    match RelayConn::dial(f.addr, "127.0.0.1", wrong).await {
        Err(DialError::Tls(_)) => {}
        other => panic!("a relay with another key was accepted: {other:?}"),
    }
    // The right pin still works.
    f.dial().await.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn successor_needs_the_current_key() {
    let (target, new) = (key(0x61), key(0x63));
    let f = Fixture::new("successor", &[], &[&target]).await;
    let successor =
        |c: &RelayConn, signer: &mousse_net_core::relay::RelayClientKey| RelayMessage::Successor {
            key: new.public_key(),
            new_proof: new.successor_proof(&f.id, &new.public_key(), &c.binding),
            current_proof: signer.successor_proof(&f.id, &new.public_key(), &c.binding),
        };
    // Proved by the new key twice: refused, and the new key stays out.
    let mut reg = f.register(&target).await;
    let msg = successor(&reg, &new);
    reg.send(&msg).await.unwrap();
    assert_eq!(
        relay(&mut reg).await,
        RelayMessage::Refused {
            reason: RefuseReason::NotAuthorized
        }
    );
    assert_eq!(closed(&mut reg).await, Some(1000));
    let mut c = f.dial().await;
    c.send(&RelayMessage::Register {
        key: new.public_key(),
        proof: new.register_proof(&f.id, &c.binding),
        hosted: None,
    })
    .await
    .unwrap();
    assert!(matches!(relay(&mut c).await, RelayMessage::Refused { .. }));

    // Proved by both: the new key is authorized, durably, and registers.
    let mut reg = f.register(&target).await;
    let msg = successor(&reg, &target);
    reg.send(&msg).await.unwrap();
    let mut new_reg = f.register(&new).await;
    let lists = f.dir.read().unwrap();
    assert!(lists
        .authorized
        .iter()
        .any(|k| k.fingerprint == new.fingerprint() && k.drop_at.is_none()));
    assert!(lists
        .authorized
        .iter()
        .any(|k| k.fingerprint == target.fingerprint() && k.drop_at.is_some()));
    new_reg
        .send(&RelayMessage::Ping { data: [2; 8] })
        .await
        .unwrap();
    assert_eq!(
        relay(&mut new_reg).await,
        RelayMessage::Pong { data: [2; 8] }
    );
    reg.send(&RelayMessage::Ping { data: [3; 8] })
        .await
        .unwrap();
    assert_eq!(relay(&mut reg).await, RelayMessage::Pong { data: [3; 8] });
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_link_and_revoke_take_effect_on_the_running_relay() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("enroll", &[("RELAY_STATE_POLL_MS", 100)], &[]).await;
    let link = f
        .dir
        .enroll(now(), 3_600, &mut mousse_relay::os_rng())
        .unwrap();
    assert_eq!(link.relay, f.id);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut reg = f.dial().await;
    reg.send(&RelayMessage::Enroll {
        key: target.public_key(),
        proof: target.register_proof(&f.id, &reg.binding),
        code: link.code,
    })
    .await
    .unwrap();
    assert_eq!(
        relay(&mut reg).await,
        RelayMessage::Registered {
            handle: f.handle(&target)
        }
    );
    // Stored before REGISTERED: the code is gone, the key listed.
    let lists = f.dir.read().unwrap();
    assert!(lists.codes.is_empty());
    assert!(lists
        .authorized
        .iter()
        .any(|k| k.fingerprint == target.fingerprint()));
    allow(&mut reg, 1, &[&caller]).await;
    let (mut leg, mut acc) = f
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    assert!(f.dir.revoke(now(), &target.fingerprint()).unwrap());
    assert_eq!(closed(&mut reg).await, Some(4000));
    assert_eq!(closed(&mut leg).await, Some(4000));
    assert_eq!(closed(&mut acc).await, Some(4000));
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_upgrades_never_reach_the_relay_protocol() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = key(0x61);
    let f = Fixture::new("upgrade", &[], &[&target]).await;
    let tcp = tokio::net::TcpStream::connect(f.addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(mousse_relay::tls::client_config(f.id))
        .connect(
            rustls::pki_types::ServerName::IpAddress(f.addr.ip().into()),
            tcp,
        )
        .await
        .unwrap();
    tls.write_all(b"GET /other HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: mousse-relay.1\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(Ok(n)) = tokio::time::timeout(WAIT, tls.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        answer.extend_from_slice(&buf[..n]);
    }
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
}

/// The relay may connect a caller to any leg; the caller's peer TLS, pinned
/// to the host it meant, fails before any data when the far end is someone
/// else.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_peer_identity_fails_before_data() {
    use mousse_net_io::certs::CertManager;
    use mousse_net_io::{Clock, SharedSigner, SystemClock, TlsPolicy};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("peer-pin", &[], &[&target]).await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let (leg, acc) = f
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let new_key = || {
        Arc::new(mousse_net_core::identity::SoftwareKey::generate(
            &mut mousse_relay::os_rng(),
        ))
    };
    let (answering, expected) = (new_key(), new_key());
    let answering: SharedSigner = answering;
    let expected_pin = expected.public_key();
    let caller_signer: SharedSigner = new_key();
    let host_cert = CertManager::new(answering, clock.clone())
        .current()
        .unwrap();
    let caller_cert = CertManager::new(caller_signer, clock.clone())
        .current()
        .unwrap();
    let (host_pipe, _) = bridge(acc);
    let (caller_pipe, _) = bridge(leg);
    let host = {
        let clock = clock.clone();
        tokio::spawn(async move {
            let Ok((mut tls, _)) =
                mousse_net_io::tls::accept(host_pipe, &host_cert, clock, TlsPolicy::default())
                    .await
            else {
                return 0;
            };
            let mut buf = [0u8; 64];
            tls.read(&mut buf).await.unwrap_or(0)
        })
    };
    let result = mousse_net_io::tls::connect(
        caller_pipe,
        &caller_cert,
        expected_pin,
        clock,
        TlsPolicy::default(),
    )
    .await;
    if let Ok((mut tls, _)) = result {
        let _ = tls.write_all(b"secret").await;
        panic!("the caller's peer TLS accepted a host it did not pin");
    }
    let got = tokio::time::timeout(WAIT, host).await.unwrap().unwrap();
    assert_eq!(got, 0, "the wrong host received data");
}
