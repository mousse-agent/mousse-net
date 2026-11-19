//! `phase3.relay-reboot`: the identity and the operator's list survive a
//! restart; registrations and allow-sets do not, so calls are refused until
//! the target registers again and pushes its allow-set, and a caller
//! removed before the restart stays removed. One process per state
//! directory.

mod common;

use common::*;
use mousse_net_core::relay::{Class, RelayMessage};
use mousse_relay::client::Received;
use mousse_relay::server::{self, ServerConfig};

#[tokio::test(flavor = "multi_thread")]
async fn admission_resets_on_reboot_and_removal_survives_it() {
    let (target, kept, removed) = (key(0x61), key(0x71), key(0x72));
    let mut f = Fixture::new("reboot", &[], &[&target]).await;
    let id = f.id;
    let h = f.handle(&target);

    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&kept, &removed]).await;
    let (mut leg, _acc) = f
        .connect(&mut reg, &target, &removed, Class::Interactive)
        .await;
    // The removal, before the reboot.
    reg.send(&RelayMessage::AllowSet {
        sequence: 2,
        callers: vec![kept.fingerprint()],
        invitations: vec![],
    })
    .await
    .unwrap();
    assert_eq!(closed(&mut leg).await, Some(4000));
    assert_eq!(
        relay(&mut reg).await,
        RelayMessage::AllowSetOk { sequence: 2 }
    );

    // A second relay on the same directory refuses to start.
    let second = server::start(ServerConfig {
        state: f.dir.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        limits: f.limits,
        hosted: None,
    })
    .await;
    assert!(second.is_err(), "two relays ran on one state directory");

    f.stop().await;
    assert_eq!(closed(&mut reg).await, Some(4003));
    f.start().await;
    assert_eq!(f.id, id, "the relay identity changed across the reboot");

    // Nothing is admitted until the target is back with an allow-set.
    let refused = |what: &'static str| {
        move |got: Received| {
            assert_eq!(got, Received::Relay(RelayMessage::Unreachable), "{what}");
        }
    };
    let mut c = f.call(&kept, h, Class::Interactive).await;
    refused("before re-registration")(next(&mut c).await);
    let mut reg = f.register(&target).await;
    let mut c = f.call(&kept, h, Class::Interactive).await;
    let mut r = f.call(&removed, h, Class::Interactive).await;
    refused("registered, no allow-set yet")(next(&mut c).await);
    refused("removed, no allow-set yet")(next(&mut r).await);

    // The target pushes its set (a fresh registration takes any sequence).
    allow(&mut reg, 1, &[&kept]).await;
    let mut r = f.call(&removed, h, Class::Interactive).await;
    refused("removed after the push")(next(&mut r).await);
    let (mut leg, mut acc) = f
        .connect(&mut reg, &target, &kept, Class::Interactive)
        .await;
    leg.send_raw(b"still here".to_vec()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(b"still here".to_vec()));
}
