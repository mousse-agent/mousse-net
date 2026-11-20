//! The directory and mailbox against the test stand-in (E-L3): slots per
//! pairing, a removed caller's slot and token gone, a lost slot write
//! written again, mail reaching an offline host, and a hostile Plus
//! refused.

use super::*;
use crate::plus::plus_standin::PlusStandIn;
use crate::plus::tests::{linked, temp_dir};
use mousse_net_core::grants::OwnerRef;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::CpaceExchangeFactory;
use mousse_net_core::removal::{Removal as Record, RemovalId, SignedRemoval};
use mousse_net_io::rng::os_rng;
use mousse_net_io::{Host, HostConfig, SystemClock};
use std::sync::Mutex;

struct TestPairs {
    host: Mutex<Vec<(GrantId, IdentityPublicKey, PairSecret)>>,
    caller: Mutex<Vec<(IdentityPublicKey, PairSecret)>>,
    manifest: Mutex<Option<Vec<u8>>>,
}

impl PairSource for TestPairs {
    fn host_pairings(&self) -> Vec<(GrantId, IdentityPublicKey, PairSecret)> {
        self.host.lock().unwrap().clone()
    }
    fn caller_secret(&self, pin: &IdentityPublicKey) -> Option<PairSecret> {
        self.caller
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p == pin)
            .map(|(_, s)| s.clone())
    }
    fn manifest(&self) -> Option<Vec<u8>> {
        self.manifest.lock().unwrap().clone()
    }
}

/// A real manifest (`IdentityRecord::manifest`) for `named` with sequence
/// `seq`, signed by `signer`: the host's own key, or a stranger's.
fn manifest(signer: &SoftwareKey, named: &IdentityPublicKey, seq: u64) -> Vec<u8> {
    use mousse_net_core::identity::IdentityRecord;
    use mousse_net_core::manifest::Manifest;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let m = Manifest {
        host: *named,
        sequence: seq,
        issued_at: now,
        expires_at: now + 86_400,
        routes: Vec::new(),
    };
    let record = IdentityRecord::manifest(&m).unwrap();
    let signature = signer.sign_raw(record.as_bytes());
    Manifest::seal(&record, signature).encode()
}

struct World {
    standin: PlusStandIn,
    host_dir: PathBuf,
    admin_dir: PathBuf,
    host_key: SoftwareKey,
    admin: SoftwareKey,
    phone: IdentityPublicKey,
    phone_grant: GrantId,
    engine: Arc<Engine>,
    host_plus: Arc<Plus>,
    admin_plus: Arc<Plus>,
    pairs: Arc<TestPairs>,
    mail: HostMail,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.host_dir);
        let _ = std::fs::remove_dir_all(&self.admin_dir);
    }
}

async fn world(tag: &str) -> World {
    let standin = PlusStandIn::start();
    let host_dir = temp_dir(&format!("{tag}h"));
    let admin_dir = temp_dir(&format!("{tag}a"));
    let host_key = SoftwareKey::generate(&mut os_rng());
    let config = HostConfig {
        name: "host".into(),
        state_dir: Some(host_dir.clone()),
        owner: OwnerRef::from_bytes([7; 16]),
        limits: mousse_net_io::Limits::DEFAULT,
        clock: Arc::new(SystemClock::new()),
        ticket_identity: None,
        streams: None,
    };
    let (host, _events) =
        Host::new(Arc::new(host_key.clone()), config, CpaceExchangeFactory).unwrap();
    let admin = SoftwareKey::generate(&mut os_rng());
    let (admin_grant, _) = host
        .add_grant(admin.public_key(), "admin".into(), None)
        .unwrap();
    let phone = SoftwareKey::generate(&mut os_rng()).public_key();
    let (phone_grant, _) = host.add_grant(phone, "phone".into(), None).unwrap();
    let removal = crate::revoke::Removal::start(host.clone(), &host_dir);
    let (engine, _rx) = Engine::new(
        host.clone(),
        removal,
        Arc::new(host_key.clone()),
        Arc::new(SystemClock::new()),
        host_dir.clone(),
    );
    let (host_plus, _) = linked(&standin, &host_dir).await;
    let (admin_plus, _) = linked(&standin, &admin_dir).await;
    let admin_secret = PairSecret::from_bytes([1; 32]);
    let phone_secret = PairSecret::from_bytes([2; 32]);
    let pairs = Arc::new(TestPairs {
        host: Mutex::new(vec![
            (admin_grant.id, admin.public_key(), admin_secret.clone()),
            (phone_grant.id, phone, phone_secret),
        ]),
        caller: Mutex::new(vec![(host_key.public_key(), admin_secret)]),
        manifest: Mutex::new(Some(manifest(&host_key, &host_key.public_key(), 1))),
    });
    let mail = HostMail::in_dir(&host_dir);
    World {
        standin,
        host_dir,
        admin_dir,
        host_key,
        admin,
        phone,
        phone_grant: phone_grant.id,
        engine,
        host_plus,
        admin_plus,
        pairs,
        mail,
    }
}

fn signed_removal(w: &World, id: u8) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let r = Record {
        signer: w.admin.public_key(),
        recipient: w.host_key.public_key(),
        removed: w.phone,
        grant: w.phone_grant,
        id: RemovalId([id; 16]),
        issued_at: mousse_net_core::UnixTime(now),
    };
    SignedRemoval::sign(r, &w.admin).unwrap().encode()
}

fn admin_secret(w: &World) -> PairSecret {
    w.pairs.caller_secret(&w.host_key.public_key()).unwrap()
}

fn phone_secret() -> PairSecret {
    PairSecret::from_bytes([2; 32])
}

async fn dir_get(plus: &Plus, slot: [u8; 32]) -> Result<crate::plus::proto::Answer, Failure> {
    plus.post_anonymous("/v1/dir/get", &map(vec![(1, Value::Bytes(slot.to_vec()))]))
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removal_by_mail_reaches_an_offline_host_through_its_slot_and_inbox() {
    let w = world("mail").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let secret = admin_secret(&w);
    let inbox = host_inbox(&w.admin_plus, &w.host_key.public_key(), &secret)
        .await
        .unwrap();
    assert_eq!(inbox, w.mail.inbox_id().unwrap());
    let msg = deposit(&w.admin_plus, &inbox, &secret, &signed_removal(&w, 1))
        .await
        .unwrap();
    assert_eq!(
        message_state(&w.admin_plus, &secret, &msg).await.unwrap(),
        0
    );
    let acked = w
        .mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    assert_eq!(acked, 1);
    assert!(w.engine.host.grants().iter().all(|g| g.identity != w.phone));
    assert_eq!(
        message_state(&w.admin_plus, &secret, &msg).await.unwrap(),
        1
    );
    // The same removal again by mail is acknowledged and changes nothing.
    deposit(&w.admin_plus, &inbox, &secret, &signed_removal(&w, 1))
        .await
        .unwrap();
    let acked = w
        .mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    assert_eq!(acked, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_pairings_slot_and_token_go_and_its_slot_id_stays_unreadable() {
    let w = world("slotgone").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    assert!(dir_get(&w.admin_plus, phone_secret().slot_id())
        .await
        .is_ok());
    // The phone's grant goes, and its pairing material with it.
    w.engine.host.remove_grant(w.phone_grant).unwrap();
    w.pairs
        .host
        .lock()
        .unwrap()
        .retain(|(g, _, _)| *g != w.phone_grant);
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    match dir_get(&w.admin_plus, phone_secret().slot_id()).await {
        Err(Failure::Plus(e)) => assert_eq!(e.code, "not_found"),
        Err(other) => panic!("unexpected: {other:?}"),
        Ok(_) => panic!("the removed slot is still readable"),
    }
    let inbox = w.mail.inbox_id().unwrap();
    match deposit(&w.admin_plus, &inbox, &phone_secret(), b"x").await {
        Err(Failure::Plus(e)) => assert_eq!(e.code, "unauthorized"),
        other => panic!("the removed device can still deposit: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_slot_write_is_written_again_over_the_stored_version() {
    let w = world("restore").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let secret = admin_secret(&w);
    *w.pairs.manifest.lock().unwrap() = Some(manifest(&w.host_key, &w.host_key.public_key(), 2));
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    // Plus loses the version-2 write (a restore).
    w.standin.restore_lose_slot_write(secret.slot_id());
    *w.pairs.manifest.lock().unwrap() = Some(manifest(&w.host_key, &w.host_key.public_key(), 3));
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let got = dir_get(&w.admin_plus, secret.slot_id()).await.unwrap();
    assert_eq!(
        got.uint(1).unwrap(),
        2,
        "written over the version Plus kept"
    );
    assert!(host_inbox(&w.admin_plus, &w.host_key.public_key(), &secret)
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_plus_is_refused() {
    let w = world("hostile").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let secret = admin_secret(&w);
    // A swapped slot does not open under this pairing's key.
    w.standin
        .swap_slots(secret.slot_id(), phone_secret().slot_id());
    assert!(host_inbox(&w.admin_plus, &w.host_key.public_key(), &secret)
        .await
        .is_err());
    w.standin
        .swap_slots(secret.slot_id(), phone_secret().slot_id());
    // A manifest another key signed, sealed correctly: refused.
    let stranger = SoftwareKey::generate(&mut os_rng());
    let forged = pairmail::seal(
        &secret.slot_key(),
        [9; 24],
        &pairmail::slot_plaintext(&manifest(&stranger, &w.host_key.public_key(), 9), &[3; 32]),
    );
    w.standin.overwrite_slot(secret.slot_id(), 9, forged);
    assert!(host_inbox(&w.admin_plus, &w.host_key.public_key(), &secret)
        .await
        .is_err());
    // A removal Plus deposits itself, not sealed with any pairing's mail
    // key, even one an owner really signed: dropped, not applied.
    let inbox = w.mail.inbox_id().unwrap();
    w.standin
        .plus_deposits_as(inbox, secret.tag(), signed_removal(&w, 5));
    w.mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    assert!(
        w.engine.host.grants().iter().any(|g| g.identity == w.phone),
        "a message Plus made removed a grant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_a_removed_pairing_s_slot_goes_even_at_the_slot_quota() {
    let w = world("slotquota").await;
    w.standin.set_slot_quota(2);
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    // The phone goes and a tablet pairs: at the quota, the tablet's slot
    // can only be written once the phone's is gone.
    w.engine.host.remove_grant(w.phone_grant).unwrap();
    let tablet = SoftwareKey::generate(&mut os_rng()).public_key();
    let (tablet_grant, _) = w
        .engine
        .host
        .add_grant(tablet, "tablet".into(), None)
        .unwrap();
    {
        let mut host = w.pairs.host.lock().unwrap();
        host.retain(|(g, _, _)| *g != w.phone_grant);
        host.push((tablet_grant.id, tablet, PairSecret::from_bytes([3; 32])));
    }
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    match dir_get(&w.admin_plus, phone_secret().slot_id()).await {
        Err(Failure::Plus(e)) => assert_eq!(e.code, "not_found"),
        Err(other) => panic!("unexpected: {other:?}"),
        Ok(_) => panic!("the removed pairing's slot is still readable"),
    }
    assert!(
        dir_get(&w.admin_plus, PairSecret::from_bytes([3; 32]).slot_id())
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_a_grant_removal_wakes_the_mailbox_at_once() {
    let w = world("kick").await;
    w.engine.set_pairs(w.pairs.clone());
    w.engine.set_plus(w.host_plus.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while dir_get(&w.admin_plus, phone_secret().slot_id())
        .await
        .is_err()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the first sync never ran"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Removed through the journal, as the app's grant.remove and a
    // received removal do; the poll interval is minutes away. (The real
    // pair source reads the grants, so it drops the pairing with them.)
    w.pairs
        .host
        .lock()
        .unwrap()
        .retain(|(g, _, _)| *g != w.phone_grant);
    w.engine.removal.remove(w.phone_grant).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if matches!(
            dir_get(&w.admin_plus, phone_secret().slot_id()).await,
            Err(Failure::Plus(ref e)) if e.code == "not_found"
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the removed pairing's slot waited for the next poll"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_a_plus_that_repeats_its_pages_cannot_hold_the_fetch() {
    let w = world("repeat").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let secret = admin_secret(&w);
    let inbox = w.mail.inbox_id().unwrap();
    deposit(&w.admin_plus, &inbox, &secret, &signed_removal(&w, 1))
        .await
        .unwrap();
    w.standin.set_fetch_repeats(true);
    let polled = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        w.mail.poll(&w.host_plus, &w.engine, &*w.pairs),
    )
    .await
    .expect("the fetch round ended");
    polled.unwrap();
    assert!(
        w.standin.request_count("/v1/inbox/fetch")
            <= crate::limits::helper().plus_mail_pages_max() as usize,
        "fetched past the page bound"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mailbox_a_removal_the_host_cannot_decide_is_not_acknowledged() {
    let w = world("noack").await;
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let secret = admin_secret(&w);
    let inbox = w.mail.inbox_id().unwrap();
    deposit(&w.admin_plus, &inbox, &secret, &signed_removal(&w, 1))
        .await
        .unwrap();
    // The removal journal cannot be written: the host cannot decide.
    let journal = w.host_dir.join(crate::revoke::REMOVALS_JOURNAL);
    std::fs::create_dir_all(&journal).unwrap();
    let acked = w
        .mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    assert_eq!(acked, 0, "a removal nobody applied was acknowledged");
    assert_eq!(w.standin.inbox_messages(inbox).len(), 1);
    assert!(w.engine.host.grants().iter().any(|g| g.identity == w.phone));
    // Once it can be written, the next round applies and acknowledges it.
    std::fs::remove_dir_all(&journal).unwrap();
    let acked = w
        .mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    assert_eq!(acked, 1);
    assert!(w.engine.host.grants().iter().all(|g| g.identity != w.phone));
}

#[test]
fn mailbox_only_an_expired_or_unknown_message_is_deposited_again() {
    use crate::plus::proto::PlusError;
    let plus_error = |status: u16, code: &str| {
        Err(Failure::Plus(PlusError {
            status,
            code: code.into(),
            retry_after: None,
        }))
    };
    assert_eq!(after_message_state(&Ok(0)), None);
    assert_eq!(after_message_state(&Ok(1)), Some("delivered"));
    assert_eq!(after_message_state(&Ok(2)), Some("waiting"));
    assert_eq!(
        after_message_state(&plus_error(404, "not_found")),
        Some("waiting")
    );
    // A busy or failing Plus never gets a duplicate deposit.
    assert_eq!(after_message_state(&plus_error(429, "rate_limited")), None);
    assert_eq!(after_message_state(&plus_error(500, "internal")), None);
    assert_eq!(after_message_state(&plus_error(503, "")), None);
    assert_eq!(
        after_message_state(&Err(Failure::Local("timeout".into()))),
        None
    );
}

/// A removal of `device` (grant `grant`) on the world's host, signed by the
/// admin device, with removal id `id`.
fn removal_of(w: &World, device: IdentityPublicKey, grant: GrantId, id: u8) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let r = Record {
        signer: w.admin.public_key(),
        recipient: w.host_key.public_key(),
        removed: device,
        grant,
        id: RemovalId([id; 16]),
        issued_at: mousse_net_core::UnixTime(now),
    };
    SignedRemoval::sign(r, &w.admin).unwrap().encode()
}

#[tokio::test(flavor = "multi_thread")]
async fn removal_nine_by_mail_reach_an_offline_host_past_a_device_filling_the_inbox() {
    let w = world("nine").await;
    // Nine more devices on the host, each with its own pairing.
    let mut devices = Vec::new();
    for i in 0..9u8 {
        let key = SoftwareKey::generate(&mut os_rng()).public_key();
        let (grant, _) = w
            .engine
            .host
            .add_grant(key, format!("device {i}"), None)
            .unwrap();
        w.pairs
            .host
            .lock()
            .unwrap()
            .push((grant.id, key, PairSecret::from_bytes([20 + i; 32])));
        devices.push((key, grant.id));
    }
    w.mail.sync(&w.host_plus, &*w.pairs).await.unwrap();
    let inbox = w.mail.inbox_id().unwrap();
    // The inbox holds 12; one pairing at most 3 (A.6).
    w.standin.set_inbox_quota(12);
    w.standin.set_tag_quota(3);
    // A device deposits junk with its own token until Plus refuses it.
    let mut junk = 0;
    for _ in 0..20 {
        match deposit(&w.admin_plus, &inbox, &phone_secret(), b"junk").await {
            Ok(_) => junk += 1,
            Err(_) => break,
        }
    }
    assert!(junk <= 3, "one pairing filled {junk} places");
    // The admin device's nine removals all fit, while the host is offline.
    let secret = admin_secret(&w);
    let mut sent = 0;
    for (n, (key, grant)) in devices.iter().enumerate() {
        let env = removal_of(&w, *key, *grant, 100 + n as u8);
        match deposit(&w.admin_plus, &inbox, &secret, &env).await {
            Ok(_) => sent += 1,
            Err(e) => panic!("removal {n} not deposited: {e}"),
        }
        if sent == 3 {
            // A pairing's own quota: the host fetches between batches, as
            // its poll does, and the rest follow.
            w.mail
                .poll(&w.host_plus, &w.engine, &*w.pairs)
                .await
                .unwrap();
            sent = 0;
        }
    }
    w.mail
        .poll(&w.host_plus, &w.engine, &*w.pairs)
        .await
        .unwrap();
    for (key, _) in &devices {
        assert!(
            w.engine.host.grants().iter().all(|g| g.identity != *key),
            "a removal did not arrive"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn removal_the_other_profile_on_a_shared_computer_is_untouched() {
    let w = world("profiles").await;
    // A second profile on the same computer: its own endpoint, also paired
    // with the phone.
    let other_dir = temp_dir("profilesb");
    let other_key = SoftwareKey::generate(&mut os_rng());
    let config = HostConfig {
        name: "other profile".into(),
        state_dir: Some(other_dir.clone()),
        owner: OwnerRef::from_bytes([8; 16]),
        limits: mousse_net_io::Limits::DEFAULT,
        clock: Arc::new(SystemClock::new()),
        ticket_identity: None,
        streams: None,
    };
    let (other, _events) =
        Host::new(Arc::new(other_key.clone()), config, CpaceExchangeFactory).unwrap();
    other
        .add_grant(w.admin.public_key(), "admin".into(), None)
        .unwrap();
    other.add_grant(w.phone, "phone".into(), None).unwrap();
    let removal = crate::revoke::Removal::start(other.clone(), &other_dir);
    let (other_engine, _rx) = Engine::new(
        other.clone(),
        removal,
        Arc::new(other_key.clone()),
        Arc::new(SystemClock::new()),
        other_dir.clone(),
    );
    // The removal for the first profile's host, by mail or on a session.
    let env = signed_removal(&w, 1);
    assert!(
        !matches!(
            other_engine.apply_removal(&env),
            Ok(ref a) if a.result == mousse_net_core::removal::RemovalResult::Applied
        ),
        "another profile applied a removal for this one"
    );
    assert!(other.grants().iter().any(|g| g.identity == w.phone));
    // The first profile applies it; the other is still untouched.
    let applied = w.engine.apply_removal(&env).unwrap();
    assert_eq!(
        applied.result,
        mousse_net_core::removal::RemovalResult::Applied
    );
    assert!(w.engine.host.grants().iter().all(|g| g.identity != w.phone));
    assert!(other.grants().iter().any(|g| g.identity == w.phone));
    let _ = std::fs::remove_dir_all(&other_dir);
}
