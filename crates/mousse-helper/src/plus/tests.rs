//! The Plus client against the test stand-in (`tests/common/plus_standin.rs`,
//! built from the public contract): stored request ids across a restart,
//! prefetch at the threshold, one current and one pending, bulk paused
//! alone on a failed refill; the directory and mailbox (E-L3).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::identity::SoftwareKey;
use mousse_net_io::keystore::{IdentityStore, KeyStorage};
use mousse_net_io::rng::os_rng;
use mousse_net_io::SystemClock;
use serde_json::Value as Json;
use tokio::sync::mpsc;

use super::lease::{self, Registration, RelayCommand, RelayEvent, StatusEntry};
use super::plus_standin::PlusStandIn;
use super::proto::{self, Block, Class};
use super::Plus;

pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mousse-helper-plus-{tag}-{}-{}",
        std::process::id(),
        mousse_net_io::store::hex(&mousse_net_io::rng::random_bytes::<4>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn open(
    standin: &PlusStandIn,
    dir: &std::path::Path,
) -> (Arc<Plus>, mpsc::UnboundedReceiver<Json>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let plus = Plus::open(
        Some(&standin.url()),
        dir,
        Arc::new(SystemClock::new()),
        KeyStorage::InsecureFile,
        IdentityStore::plus_key(dir),
        "test-endpoint",
        tx,
    )
    .unwrap()
    .unwrap();
    (plus, rx)
}

/// A client linked to `standin`: the code is approved as a user would.
pub async fn linked(
    standin: &PlusStandIn,
    dir: &std::path::Path,
) -> (Arc<Plus>, mpsc::UnboundedReceiver<Json>) {
    let (plus, mut rx) = open(standin, dir);
    let link = plus.link_start().await.unwrap();
    assert!(standin.approve(&link.user_code).is_some());
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("plus.link in time")
            .unwrap();
        if ev["ev"] == "plus.link" {
            assert_eq!(ev["state"], "approved");
            break;
        }
    }
    assert!(plus.is_linked());
    (plus, rx)
}

struct Relay {
    reg: Registration,
}

/// A registration funded at the stand-in: the handle's admission token
/// taken and the boot known.
async fn relay(standin: &PlusStandIn, plus: &Plus) -> Relay {
    let relay_id = [7u8; 32];
    let boot_id = [8u8; 16];
    let key = SoftwareKey::generate(&mut os_rng());
    let token = plus.admission(&relay_id, &key).await.unwrap();
    let handle = proto::handle(&relay_id, &key.public_key());
    assert_eq!(token.handle, handle);
    standin.register_boot(relay_id, boot_id);
    Relay {
        reg: Registration {
            relay_id,
            boot_id,
            handle,
        },
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_retry_after_a_lost_answer_uses_the_same_request_id_across_a_restart() {
    let standin = PlusStandIn::start();
    let dir = temp_dir("leaseretry");
    let (plus, _rx) = linked(&standin, &dir).await;
    let r = relay(&standin, &plus).await;
    standin.lose_next_answer("/v1/lease");
    let lost = plus
        .lease(&r.reg.relay_id, &r.reg.boot_id, &r.reg.handle, Class::Bulk)
        .await;
    assert!(lost.is_err(), "the answer was lost");
    drop(plus);
    // A restart: a new client on the same folder.
    let (again, _rx) = open(&standin, &dir);
    let block = again
        .lease(&r.reg.relay_id, &r.reg.boot_id, &r.reg.handle, Class::Bulk)
        .await
        .unwrap();
    let ids = standin.lease_request_ids();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1], "a retry must reuse the stored request id");
    assert_eq!(block.sequence, 1, "one block reserved, not two");
    // The next request is a new one.
    let next = again
        .lease(&r.reg.relay_id, &r.reg.boot_id, &r.reg.handle, Class::Bulk)
        .await
        .unwrap();
    assert_eq!(next.sequence, 2);
    assert_ne!(standin.lease_request_ids()[2], ids[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

fn status(block: &Block, used: u64, state: u8) -> StatusEntry {
    StatusEntry {
        lease_id: block.lease_id,
        class: block.class,
        used,
        bytes: block.bytes,
        state,
    }
}

async fn next_lease(rx: &mut mpsc::UnboundedReceiver<RelayCommand>) -> Block {
    loop {
        match tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("a LEASE in time")
            .expect("driver running")
        {
            RelayCommand::Lease(env) => return Block::parse(&env).unwrap(),
            RelayCommand::Release(_) => {}
        }
    }
}

async fn no_lease(rx: &mut mpsc::UnboundedReceiver<RelayCommand>, wait: Duration) -> bool {
    match tokio::time::timeout(wait, rx.recv()).await {
        Err(_) => true,
        Ok(Some(RelayCommand::Lease(_))) => false,
        Ok(_) => true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_are_fetched_at_the_threshold_with_one_current_and_one_pending() {
    let standin = PlusStandIn::start();
    let dir = temp_dir("prefetch");
    let (plus, _rx) = linked(&standin, &dir).await;
    let r = relay(&standin, &plus).await;
    let (relay_tx, relay_rx) = mpsc::unbounded_channel();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(lease::run(
        plus.clone(),
        r.reg,
        relay_rx,
        cmd_tx,
        ev_tx,
        Arc::new(SystemClock::new()),
    ));
    // At start: one block per class.
    let a = next_lease(&mut cmd_rx).await;
    let b = next_lease(&mut cmd_rx).await;
    let (inter, bulk) = if a.class == Class::Interactive {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(bulk.class, Class::Bulk);
    // Below the threshold: nothing more.
    relay_tx
        .send(RelayEvent::Status(vec![status(&bulk, bulk.bytes / 4, 1)]))
        .unwrap();
    assert!(no_lease(&mut cmd_rx, Duration::from_millis(500)).await);
    // At the threshold (50 %): the next bulk block, pending.
    relay_tx
        .send(RelayEvent::Status(vec![status(&bulk, bulk.bytes / 2, 1)]))
        .unwrap();
    let pending = next_lease(&mut cmd_rx).await;
    assert_eq!((pending.class, pending.sequence), (Class::Bulk, 2));
    // With a current and a pending block, no third however much is used.
    relay_tx
        .send(RelayEvent::Status(vec![status(&bulk, bulk.bytes - 1, 1)]))
        .unwrap();
    assert!(no_lease(&mut cmd_rx, Duration::from_millis(500)).await);
    // Interactive was untouched.
    assert_eq!(inter.sequence, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_pauses_alone_when_its_refill_fails() {
    let standin = PlusStandIn::start();
    let dir = temp_dir("bulkpause");
    let (plus, _rx) = linked(&standin, &dir).await;
    let r = relay(&standin, &plus).await;
    let (relay_tx, relay_rx) = mpsc::unbounded_channel();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(lease::run(
        plus.clone(),
        r.reg,
        relay_rx,
        cmd_tx,
        ev_tx,
        Arc::new(SystemClock::new()),
    ));
    let a = next_lease(&mut cmd_rx).await;
    let b = next_lease(&mut cmd_rx).await;
    let bulk = if a.class == Class::Bulk { a } else { b };
    // The allowance is spent: the bulk block runs out and no refill comes.
    standin.set_balance(0, 1 << 30);
    relay_tx
        .send(RelayEvent::Status(vec![status(&bulk, bulk.bytes, 2)]))
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut paused = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), ev_rx.recv()).await {
            Ok(Some(ev)) if ev["ev"] == "plus.relay.paused" => {
                paused.push((
                    ev["class"].as_str().unwrap().to_owned(),
                    ev["paused"] == true,
                ));
                if paused.iter().any(|(c, p)| c == "bulk" && *p) {
                    break;
                }
            }
            Ok(Some(ev)) if ev["ev"] == "plus.relay" => {
                assert_ne!(ev["interactive"]["state"], "paused");
            }
            _ => {}
        }
    }
    assert!(
        paused.contains(&("bulk".to_owned(), true)),
        "bulk shows paused: {paused:?}"
    );
    assert!(
        !paused.iter().any(|(c, _)| c == "interactive"),
        "interactive must not pause: {paused:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `RELEASE` is asked for, but the kept blocks stay: the registration
/// forgets each only once its `RELEASE` is sent, so a crash before that
/// still releases it after the restart.
#[tokio::test(flavor = "multi_thread")]
async fn release_all_leaves_the_kept_blocks_for_the_registration_to_clear_once_sent() {
    let standin = PlusStandIn::start();
    let dir = temp_dir("release-kept");
    let (plus, _rx) = linked(&standin, &dir).await;
    let r = relay(&standin, &plus).await;
    let (relay_tx, relay_rx) = mpsc::unbounded_channel();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let kept = Arc::new(std::sync::Mutex::new(Vec::<Vec<Vec<u8>>>::new()));
    let sink = kept.clone();
    tokio::spawn(lease::run_funded(
        plus.clone(),
        r.reg,
        true,
        lease::HeldBlocks {
            adopted: Vec::new(),
            keep: Box::new(move |b| sink.lock().unwrap().push(b)),
        },
        relay_rx,
        cmd_tx,
        ev_tx,
        Arc::new(SystemClock::new()),
    ));
    let first = next_lease(&mut cmd_rx).await;
    relay_tx.send(RelayEvent::ReleaseAll).unwrap();
    let mut released = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(20), cmd_rx.recv())
            .await
            .expect("the driver ends")
        {
            Some(RelayCommand::Release(ids)) => released.extend(ids),
            Some(RelayCommand::Lease(_)) => {}
            None => break,
        }
    }
    assert!(released.contains(&first.lease_id), "RELEASE names the block");
    let last = kept.lock().unwrap().last().cloned().unwrap_or_default();
    assert!(
        last.contains(&first.envelope),
        "the kept blocks were cleared before the RELEASE was sent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
