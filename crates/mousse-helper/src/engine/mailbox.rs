//! Plus's directory and mailbox, both sides (design A.5, A.6, B.12, D.3
//! to D.5; E-L3).
//!
//! **Host.** One inbox per endpoint, whose token set holds `{tag, SHA-256
//! of the deposit token}` for every pairing with a pair secret; one
//! directory slot per pairing holding `{nonce, AEAD(manifest envelope ‖
//! inbox id)}`, written again when the manifest changes. A lost write
//! (a Plus restore, A.13) shows as `conflict`: list, then write the stored
//! version + 1. The inbox is fetched every `MOUSSE_NET_PLUS_MAIL_POLL_SECS`
//! and after a network change, each round from the oldest message; each
//! message is acted on and acknowledged whatever the result. When a
//! pairing's grant goes, its slot is deleted and its tag leaves the set.
//!
//! **Caller (admin device).** A removal for a host it is not connected to
//! is sealed with that pairing's mail key and deposited with its deposit
//! token, after reading the host's inbox id from its slot. A slot counts
//! only if the manifest in it is signed by the pinned host.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mousse_net_core::cbor::Value;
use mousse_net_core::grants::GrantId;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::manifest::{Envelope, Manifest};
use mousse_net_core::pairmail::{self, PairSecret};
use mousse_net_io::rng::random_bytes;
use mousse_net_io::store::{hex, identity_from_hex, unhex, write_atomic};
use serde::{Deserialize, Serialize};

use super::removals::ApplyError;
use super::Engine;
use crate::applog;
use crate::plus::proto::{map, DEPOSIT_TOKENS_MAX, DIR_ENTRY_MAX, MAIL_ENVELOPE_MAX};
use crate::plus::{Failure, Plus};

/// The host's mailbox state, in the endpoint's folder.
pub const MAILBOX_FILE: &str = "mailbox.json";

/// Where pair secrets and the current manifest come from: the relay client
/// keeps them (`mousse-keys`, `mousse-manifest`).
pub trait PairSource: Send + Sync {
    /// Host side: every grant with a pair secret, and the device it names.
    fn host_pairings(&self) -> Vec<(GrantId, IdentityPublicKey, PairSecret)>;
    /// Caller side: the pair secret the host `pin` sent.
    fn caller_secret(&self, pin: &IdentityPublicKey) -> Option<PairSecret>;
    /// This host's current signed manifest envelope.
    fn manifest(&self) -> Option<Vec<u8>>;
    /// Caller side: a manifest the host `pin` signed, read from its
    /// directory slot: kept if newer, so its routes reach the dialer.
    fn keep_manifest(&self, _pin: &IdentityPublicKey, _envelope: &[u8]) {}
}

/// No pairing material yet (before the relay client provides it).
pub struct NoPairs;

impl PairSource for NoPairs {
    fn host_pairings(&self) -> Vec<(GrantId, IdentityPublicKey, PairSecret)> {
        Vec::new()
    }
    fn caller_secret(&self, _: &IdentityPublicKey) -> Option<PairSecret> {
        None
    }
    fn manifest(&self) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct SlotRecord {
    /// The slot id (hex).
    slot: String,
    /// The version last written.
    version: u64,
    /// SHA-256 of the manifest last written (hex), so an unchanged
    /// manifest is not written again.
    manifest: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct MailboxFile {
    version: u32,
    /// The inbox id (hex), drawn once.
    #[serde(default)]
    inbox: Option<String>,
    /// The sequence of the last `inbox/put`.
    #[serde(default)]
    sequence: u64,
    /// SHA-256 of the token set last put (hex).
    #[serde(default)]
    token_set: String,
    /// Slots by grant id.
    #[serde(default)]
    slots: BTreeMap<u64, SlotRecord>,
}

fn load(path: &Path) -> Result<MailboxFile, Failure> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| Failure::Local(e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(MailboxFile::default()),
        Err(e) => Err(Failure::Local(e.to_string())),
    }
}

fn save(path: &Path, file: &MailboxFile) -> Result<(), Failure> {
    let mut f = file.clone();
    f.version = 1;
    let bytes = serde_json::to_vec(&f).map_err(|e| Failure::Local(e.to_string()))?;
    write_atomic(path, &bytes).map_err(|e| Failure::Local(e.to_string()))
}

fn sha_hex(parts: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex(&h.finalize())
}

fn rid() -> Value {
    Value::Bytes(random_bytes::<16>().to_vec())
}

/// The host side of one endpoint's mailbox and directory.
pub struct HostMail {
    path: PathBuf,
    lock: std::sync::Mutex<()>,
}

impl HostMail {
    /// In the endpoint's folder.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(MAILBOX_FILE),
            lock: std::sync::Mutex::new(()),
        }
    }

    /// The inbox id, drawn and stored on first use.
    pub fn inbox_id(&self) -> Result<[u8; 32], Failure> {
        let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = load(&self.path)?;
        if let Some(id) = file.inbox.as_deref().and_then(|h| unhex(h).ok()) {
            if let Ok(id) = <[u8; 32]>::try_from(id.as_slice()) {
                return Ok(id);
            }
        }
        let id = random_bytes::<32>();
        file.inbox = Some(hex(&id));
        save(&self.path, &file)?;
        Ok(id)
    }

    /// Bring Plus in line: the inbox's token set, every pairing's slot,
    /// and no slot for a pairing that is gone.
    pub async fn sync(&self, plus: &Plus, pairs: &dyn PairSource) -> Result<(), Failure> {
        let inbox = self.inbox_id()?;
        let pairings = pairs.host_pairings();
        // Gone pairings first: their slots free their places at Plus, so a
        // new slot at the quota cannot keep a removed pairing's slot
        // readable, and the token set loses the removed tag before anything
        // else can fail.
        self.delete_gone_slots(plus, &pairings).await?;
        self.put_tokens(plus, &inbox, &pairings).await?;
        if let Some(manifest) = pairs.manifest() {
            for (grant, _, secret) in &pairings {
                self.write_slot(plus, *grant, secret, &manifest, &inbox)
                    .await?;
            }
        }
        Ok(())
    }

    async fn put_tokens(
        &self,
        plus: &Plus,
        inbox: &[u8; 32],
        pairings: &[(GrantId, IdentityPublicKey, PairSecret)],
    ) -> Result<(), Failure> {
        let mut tokens: Vec<([u8; 16], [u8; 32])> = pairings
            .iter()
            .map(|(_, _, s)| (s.tag(), s.deposit_token_hash()))
            .collect();
        tokens.sort();
        if tokens.len() > DEPOSIT_TOKENS_MAX {
            // An inbox holds at most this many tokens (fixed); later
            // pairings get no mail and still get removals on sessions.
            applog::line("mail: more pairings than an inbox has tokens");
            tokens.truncate(DEPOSIT_TOKENS_MAX);
        }
        let set_hash = sha_hex(
            &tokens
                .iter()
                .flat_map(|(t, h)| [t.as_slice(), h.as_slice()])
                .collect::<Vec<_>>(),
        );
        let sequence = {
            let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            let file = load(&self.path)?;
            if file.token_set == set_hash && file.sequence > 0 {
                return Ok(());
            }
            file.sequence + 1
        };
        let set: Vec<Value> = tokens
            .iter()
            .map(|(tag, hash)| {
                Value::Map(vec![
                    (1, Value::Bytes(tag.to_vec())),
                    (2, Value::Bytes(hash.to_vec())),
                ])
            })
            .collect();
        let body = map(vec![
            (1, rid()),
            (2, Value::Bytes(inbox.to_vec())),
            (3, Value::Uint(sequence)),
            (4, Value::Array(set)),
        ]);
        match plus.post_bearer("/v1/inbox/put", &body).await {
            Ok(_) => {}
            // A restore can leave Plus with an older sequence than ours,
            // or ours older than Plus's after a lost save: move past it.
            Err(Failure::Plus(e)) if e.code == "conflict" => {
                let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
                let mut file = load(&self.path)?;
                file.sequence = sequence.saturating_add(1);
                save(&self.path, &file)?;
                return Err(Failure::Plus(e));
            }
            Err(e) => return Err(e),
        }
        let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = load(&self.path)?;
        file.sequence = sequence;
        file.token_set = set_hash;
        save(&self.path, &file)
    }

    async fn write_slot(
        &self,
        plus: &Plus,
        grant: GrantId,
        secret: &PairSecret,
        manifest: &[u8],
        inbox: &[u8; 32],
    ) -> Result<(), Failure> {
        let slot = secret.slot_id();
        let manifest_hash = sha_hex(&[manifest, inbox]);
        let stored = {
            let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            load(&self.path)?.slots.get(&grant.0).cloned()
        };
        if stored
            .as_ref()
            .is_some_and(|s| s.manifest == manifest_hash && s.slot == hex(&slot))
        {
            return Ok(());
        }
        let mut version = stored
            .filter(|s| s.slot == hex(&slot))
            .map_or(1, |s| s.version + 1);
        let sealed = pairmail::seal(
            &secret.slot_key(),
            random_bytes::<24>(),
            &pairmail::slot_plaintext(manifest, inbox),
        );
        if sealed.len() > DIR_ENTRY_MAX {
            return Err(Failure::Local(
                "the manifest is too large for a slot".into(),
            ));
        }
        let put = |version: u64| {
            map(vec![
                (1, rid()),
                (2, Value::Bytes(slot.to_vec())),
                (3, Value::Uint(version)),
                (4, Value::Bytes(sealed.clone())),
            ])
        };
        match plus.post_bearer("/v1/dir/put", &put(version)).await {
            Ok(_) => {}
            Err(Failure::Plus(e)) if e.code == "conflict" => {
                // A write Plus lost or kept (A.13): read the stored version.
                let listed = plus.post_bearer("/v1/dir/list", &map(vec![])).await?;
                let current = listed
                    .maps(1)?
                    .into_iter()
                    .find(|s| s.fixed::<32>(1).ok() == Some(slot))
                    .and_then(|s| s.opt_uint(2))
                    .unwrap_or(0);
                version = current + 1;
                plus.post_bearer("/v1/dir/put", &put(version)).await?;
            }
            Err(e) => return Err(e),
        }
        let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = load(&self.path)?;
        file.slots.insert(
            grant.0,
            SlotRecord {
                slot: hex(&slot),
                version,
                manifest: manifest_hash,
            },
        );
        save(&self.path, &file)
    }

    /// Delete the slot of every pairing whose grant is gone.
    async fn delete_gone_slots(
        &self,
        plus: &Plus,
        pairings: &[(GrantId, IdentityPublicKey, PairSecret)],
    ) -> Result<(), Failure> {
        if cfg!(mousse_control = "keep-removed-slot") {
            // Must-fail control (tests only): a removed pairing's slot stays.
            return Ok(());
        }
        let gone: Vec<(u64, String)> = {
            let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            load(&self.path)?
                .slots
                .iter()
                .filter(|(g, _)| !pairings.iter().any(|(id, _, _)| id.0 == **g))
                .map(|(g, s)| (*g, s.slot.clone()))
                .collect()
        };
        for (grant, slot) in gone {
            let Ok(id) = unhex(&slot) else { continue };
            plus.post_bearer("/v1/dir/delete", &map(vec![(1, Value::Bytes(id))]))
                .await?;
            let _l = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            let mut file = load(&self.path)?;
            file.slots.remove(&grant);
            save(&self.path, &file)?;
        }
        Ok(())
    }

    /// One fetch round from the oldest message: open each with its
    /// pairing's mail key, apply the removal inside, and acknowledge it,
    /// whatever the result. Returns how many messages were acknowledged.
    pub async fn poll(
        &self,
        plus: &Plus,
        engine: &Engine,
        pairs: &dyn PairSource,
    ) -> Result<usize, Failure> {
        let inbox = self.inbox_id()?;
        let keys: Vec<([u8; 16], PairSecret)> = pairs
            .host_pairings()
            .into_iter()
            .map(|(_, _, s)| (s.tag(), s))
            .collect();
        let mut after: Option<u64> = None;
        let mut acked = 0;
        // A Plus that answers the same page whatever `after` says, or pages
        // without end, cannot hold the loop: at most this many pages a
        // round, and each must move past the last.
        for _ in 0..crate::limits::helper().plus_mail_pages_max() {
            let mut body = vec![(1, Value::Bytes(inbox.to_vec()))];
            if let Some(a) = after {
                body.push((2, Value::Uint(a)));
            }
            let page = plus.post_bearer("/v1/inbox/fetch", &map(body)).await?;
            let messages = page.maps(1)?;
            if messages.is_empty() {
                return Ok(acked);
            }
            let before = after;
            let mut ids = Vec::new();
            for m in &messages {
                let id = m.fixed::<16>(1)?;
                let sequence = m.uint(2)?;
                if before.is_some_and(|b| sequence <= b) {
                    continue; // not past the last page: seen already
                }
                after = Some(sequence.max(after.unwrap_or(0)));
                let tag = m.fixed::<16>(3)?;
                let sealed = m.bytes(5)?;
                // Only mail sealed with a pairing's own key is opened; Plus
                // cannot make one. Whatever opens must still be a removal an
                // owner-role device signed.
                let opened = if cfg!(mousse_control = "trust-from-plus") {
                    Some(sealed.clone())
                } else {
                    keys.iter()
                        .find(|(t, _)| *t == tag)
                        .and_then(|(_, s)| pairmail::open(&s.mail_key(), &sealed).ok())
                        .map(|p| p.to_vec())
                };
                match opened {
                    Some(envelope) => match engine.apply_removal(&envelope) {
                        Ok(answer) => {
                            applog::line(format!("mail: a removal was {}", answer.result.name()))
                        }
                        // Decided by nobody yet: never acknowledged, so it
                        // stays at Plus for the next round.
                        Err(ApplyError::NotNow(e)) => {
                            applog::line(format!("mail: a removal waits: {e}"));
                            continue;
                        }
                        Err(e @ ApplyError::NotARemoval(_)) => {
                            applog::line(format!("mail: dropped a message: {e}"));
                        }
                    },
                    None => applog::line("mail: dropped a message no pairing's key opens"),
                }
                ids.push(Value::Bytes(id.to_vec()));
            }
            if after == before {
                // Nothing past the last page: Plus is not moving on.
                return Ok(acked);
            }
            if !ids.is_empty() {
                acked += ids.len();
                plus.post_bearer(
                    "/v1/inbox/ack",
                    &map(vec![
                        (1, Value::Bytes(inbox.to_vec())),
                        (2, Value::Array(ids)),
                    ]),
                )
                .await?;
            }
        }
        applog::line("mail: stopped a fetch round at its page limit");
        Ok(acked)
    }
}

// ---------------------------------------------------------------------------
// Caller side
// ---------------------------------------------------------------------------

/// The pairing's directory slot: the host's signed manifest envelope and
/// its inbox id. The slot counts only if it opens under this pairing's
/// slot key and its manifest is a manifest the pinned host signed
/// (`Manifest::open`), whatever Plus serves.
pub async fn read_slot(
    plus: &Plus,
    pin: &IdentityPublicKey,
    secret: &PairSecret,
) -> Result<(Vec<u8>, [u8; 32]), Failure> {
    let slot = secret.slot_id();
    let got = plus
        .post_anonymous("/v1/dir/get", &map(vec![(1, Value::Bytes(slot.to_vec()))]))
        .await?;
    let sealed = got.bytes(2)?;
    let plain = pairmail::open(&secret.slot_key(), &sealed)
        .map_err(|e| Failure::Bad(format!("slot: {e}")))?;
    let (manifest, inbox) =
        pairmail::split_slot(&plain).map_err(|e| Failure::Bad(format!("slot: {e}")))?;
    if !cfg!(mousse_control = "unpinned-manifest") {
        // Must-fail control (tests only): the manifest counts unchecked.
        Envelope::decode(manifest)
            .map_err(|e| e.to_string())
            .and_then(|env| Manifest::open(&env, pin).map_err(|e| e.to_string()))
            .map_err(|e| Failure::Bad(format!("slot manifest: {e}")))?;
    }
    Ok((manifest.to_vec(), inbox))
}

/// The host's inbox id, from the pairing's directory slot ([`read_slot`]).
#[cfg(test)]
pub async fn host_inbox(
    plus: &Plus,
    pin: &IdentityPublicKey,
    secret: &PairSecret,
) -> Result<[u8; 32], Failure> {
    read_slot(plus, pin, secret).await.map(|(_, inbox)| inbox)
}

/// Deposit a removal envelope for the host, sealed with the pairing's mail
/// key. Returns the message id.
pub async fn deposit(
    plus: &Plus,
    inbox: &[u8; 32],
    secret: &PairSecret,
    envelope: &[u8],
) -> Result<[u8; 16], Failure> {
    let sealed = pairmail::seal(&secret.mail_key(), random_bytes::<24>(), envelope);
    if sealed.len() > MAIL_ENVELOPE_MAX {
        return Err(Failure::Local("removal too large for mail".into()));
    }
    let body = map(vec![
        (1, rid()),
        (2, Value::Bytes(inbox.to_vec())),
        (3, Value::Bytes(sealed)),
    ]);
    let answer = plus
        .post_deposit("/v1/inbox/deposit", &body, &secret.deposit_token())
        .await?;
    Ok(answer.fixed::<16>(1)?)
}

/// A deposited message's state: 0 pending, 1 delivered, 2 expired.
pub async fn message_state(
    plus: &Plus,
    secret: &PairSecret,
    message: &[u8; 16],
) -> Result<u64, Failure> {
    let answer = plus
        .post_deposit(
            "/v1/message/state",
            &map(vec![(1, Value::Bytes(message.to_vec()))]),
            &secret.deposit_token(),
        )
        .await?;
    Ok(answer.uint(1)?)
}

impl Engine {
    /// The admin side's mail round: deposit each open removal for a host
    /// this device is not connected to, and follow what was deposited.
    pub async fn mail_round(&self, plus: &Plus, pairs: &dyn PairSource) {
        for item in self.all_open_items() {
            let Ok(host) = identity_from_hex(&item.host) else {
                continue;
            };
            if !self.outbound_conns(&host).is_empty() {
                continue; // sent on the session
            }
            let Some(secret) = pairs.caller_secret(&host) else {
                continue; // "Waits until this device reaches <host>"
            };
            let Ok(envelope) = unhex(&item.envelope) else {
                continue;
            };
            match item.state.as_str() {
                "waiting" | "quota" => {
                    let inbox = match read_slot(plus, &host, &secret).await {
                        Ok((manifest, inbox)) => {
                            // Its routes may be newer than the ones kept.
                            pairs.keep_manifest(&host, &manifest);
                            inbox
                        }
                        Err(e) => {
                            applog::line(format!("mail: no inbox for a host: {e}"));
                            continue;
                        }
                    };
                    match deposit(plus, &inbox, &secret, &envelope).await {
                        Ok(id) => self.set_item_state(&item.id, "sent", None, Some(hex(&id))),
                        Err(Failure::Plus(e)) if e.code == "quota" => {
                            if item.state != "quota" {
                                self.set_item_state(&item.id, "quota", None, None);
                            }
                        }
                        Err(e) => applog::line(format!("mail: deposit failed: {e}")),
                    }
                }
                "sent" => {
                    let Some(msg) = item
                        .message
                        .as_deref()
                        .and_then(|m| unhex(m).ok())
                        .and_then(|m| <[u8; 16]>::try_from(m.as_slice()).ok())
                    else {
                        continue;
                    };
                    if let Some(next) =
                        after_message_state(&message_state(plus, &secret, &msg).await)
                    {
                        self.set_item_state(&item.id, next, None, None);
                    }
                }
                _ => {}
            }
        }
    }
}

/// What a deposited removal becomes after asking Plus for its message's
/// state: `delivered` once fetched; `waiting` (deposit again; the host
/// deduplicates by removal id) only when the message expired or Plus no
/// longer knows it (404, a restore, A.13). Any other failure (a 429, a 500,
/// a timeout) changes nothing, so a busy Plus never gets duplicates.
fn after_message_state(state: &Result<u64, Failure>) -> Option<&'static str> {
    match state {
        Ok(1) => Some("delivered"),
        Ok(2) => Some("waiting"),
        Err(Failure::Plus(e)) if e.status == 404 || e.code == "not_found" => Some("waiting"),
        _ => None,
    }
}

/// Keep the mailbox: on a host, sync the inbox and slots and fetch mail;
/// on an admin device, deposit and follow removals. Every
/// `MOUSSE_NET_PLUS_MAIL_POLL_SECS`, after a kick, while Plus is linked.
pub async fn run(engine: Arc<Engine>, plus: Arc<Plus>, pairs: Arc<dyn PairSource>) {
    let host = HostMail::in_dir(&engine.state_dir);
    let every = std::time::Duration::from_secs(crate::limits::helper().plus_mail_poll_secs());
    loop {
        if plus.is_linked() {
            match host.sync(&plus, &*pairs).await {
                Ok(()) => engine.cleanup_after_sync(),
                Err(e) => applog::line(format!("mailbox sync: {e}")),
            }
            if let Err(e) = host.poll(&plus, &engine, &*pairs).await {
                applog::line(format!("mailbox fetch: {e}"));
            }
        }
        engine.mail_round(&plus, &*pairs).await;
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            () = engine.mail_woken() => {}
        }
    }
}

#[cfg(test)]
#[path = "mailbox_tests.rs"]
mod tests;
