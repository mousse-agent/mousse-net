//! The host grant table: who may use this host, and which live channels each
//! grant authorized.
//!
//! - A grant is the only source of a device's role on this host.
//! - Every live channel (an authorized connection) is bound to the grant that
//!   authorized it. Removing or expiring a grant closes those channels at once.
//! - A local denial is host-wide and always wins: it removes the identity's
//!   grant, closes its channels, and blocks new grants until it is lifted
//!   locally. Nothing else clears it.
//!
//! The table is plain state. The caller persists [`GrantTable::grants`] and
//! [`GrantTable::denials`] and restores them with [`GrantTable::restore`].

use std::collections::BTreeMap;
use std::fmt;

use crate::identity::IdentityPublicKey;
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

/// Local identifier of a grant. Unique within one table, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId(pub u64);

/// A device's role on this host. The app gives roles their meaning; core
/// only stores and reports them.
///
/// A role is 1 to 32 bytes of lowercase ASCII letters, digits and `-`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

impl Role {
    /// The owner's own devices.
    pub const OWNER: &'static str = "owner";
    /// A client-only device such as a browser.
    pub const CLIENT: &'static str = "client";

    /// Validate a role name.
    pub fn new(name: &str) -> Result<Self, GrantError> {
        let ok = !name.is_empty()
            && name.len() <= 32
            && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(GrantError::InvalidRole)
        }
    }

    /// The owner role.
    pub fn owner() -> Self {
        Self(Self::OWNER.to_owned())
    }

    /// The role name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who authorized a grant on this host: the owner or profile id the app uses
/// (1 to 128 bytes of UTF-8). "Remove on all my hosts" (Phase 4) affects only
/// grants whose authorizing owner matches.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerRef(String);

impl OwnerRef {
    /// Validate an owner reference.
    pub fn new(id: &str) -> Result<Self, GrantError> {
        if id.is_empty() || id.len() > 128 {
            return Err(GrantError::InvalidOwner);
        }
        Ok(Self(id.to_owned()))
    }

    /// The owner id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a grant came from. Only `Local` exists until the shared roster
/// (Phase 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantSource {
    /// Approved on this host (pairing or a local action).
    Local,
}

/// A shared roster id (Phase 6). Present now so stored grants keep a stable
/// shape; always `None` in `adopted_into` until then.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RosterId(pub [u8; 32]);

/// One grant: `{identity, name, role, source, authorizing owner/profile,
/// adopted_into, granted_at}` plus an optional expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Local id.
    pub id: GrantId,
    /// The device's identity key.
    pub identity: IdentityPublicKey,
    /// Display name (1 to 64 bytes), as the device or owner gave it.
    pub name: String,
    /// The role on this host.
    pub role: Role,
    /// Where the grant came from.
    pub source: GrantSource,
    /// The owner or profile that authorized it.
    pub authorizing_owner: OwnerRef,
    /// The roster this grant was adopted into. Always `None` before Phase 6.
    pub adopted_into: Option<RosterId>,
    /// When it was granted (host clock).
    pub granted_at: UnixTime,
    /// When it stops being valid, if ever (host clock). At this second the
    /// grant is already expired.
    pub expires_at: Option<UnixTime>,
}

impl Grant {
    fn is_live(&self, now: UnixTime) -> bool {
        self.expires_at.is_none_or(|t| now < t)
    }
}

/// Fields for a new grant; the table assigns the id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewGrant {
    /// The device's identity key.
    pub identity: IdentityPublicKey,
    /// Display name (1 to 64 bytes).
    pub name: String,
    /// The role on this host.
    pub role: Role,
    /// The owner or profile that authorized it.
    pub authorizing_owner: OwnerRef,
    /// Optional expiry.
    pub expires_at: Option<UnixTime>,
}

/// A local denial: this identity may not hold a grant on this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denial {
    /// The denied identity.
    pub identity: IdentityPublicKey,
    /// When it was denied.
    pub denied_at: UnixTime,
}

/// Something the I/O layer must do because the table changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantEvent {
    /// Close these live channels now, with `code` in `GOAWAY`. They were
    /// bound to `grant`, which no longer authorizes anything.
    CloseChannels {
        /// The grant that ended.
        grant: GrantId,
        /// The channels it had authorized.
        channels: Vec<ConnectionId>,
        /// Always [`ErrorCode::GrantRevoked`].
        code: ErrorCode,
    },
}

/// Why a grant-table operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// The identity has a local denial. Only a local undeny clears it.
    Denied,
    /// No such grant, or it has expired.
    UnknownGrant,
    /// The channel is already bound to a grant.
    AlreadyBound,
    /// The role name is not valid.
    InvalidRole,
    /// The owner reference is not valid.
    InvalidOwner,
    /// The name is empty or longer than 64 bytes.
    InvalidName,
    /// Restored data has duplicate ids or identities.
    Inconsistent,
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GrantError::Denied => "identity is denied on this host",
            GrantError::UnknownGrant => "no such live grant",
            GrantError::AlreadyBound => "channel already bound to a grant",
            GrantError::InvalidRole => "invalid role name",
            GrantError::InvalidOwner => "invalid owner reference",
            GrantError::InvalidName => "invalid device name",
            GrantError::Inconsistent => "inconsistent stored grants",
        })
    }
}

impl std::error::Error for GrantError {}

/// Validate a device display name: 1 to 64 bytes of UTF-8.
pub fn validate_name(name: &str) -> Result<(), GrantError> {
    if name.is_empty() || name.len() > 64 {
        Err(GrantError::InvalidName)
    } else {
        Ok(())
    }
}

/// The host's grant table.
#[derive(Clone, Debug, Default)]
pub struct GrantTable {
    grants: BTreeMap<GrantId, Grant>,
    by_identity: BTreeMap<IdentityPublicKey, GrantId>,
    denials: BTreeMap<IdentityPublicKey, UnixTime>,
    bindings: BTreeMap<ConnectionId, GrantId>,
    next_id: u64,
}

impl GrantTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a table from stored grants and denials. Channels are not
    /// stored; they are rebound as connections arrive.
    pub fn restore(grants: Vec<Grant>, denials: Vec<Denial>) -> Result<Self, GrantError> {
        let mut table = Self::new();
        for d in denials {
            table.denials.insert(d.identity, d.denied_at);
        }
        for g in grants {
            // Ids are never reused, even those of grants dropped below.
            table.next_id = table.next_id.max(g.id.0.saturating_add(1));
            if table.denials.contains_key(&g.identity) {
                continue; // a denial wins over any stored grant
            }
            if table.grants.contains_key(&g.id) || table.by_identity.contains_key(&g.identity) {
                return Err(GrantError::Inconsistent);
            }
            table.by_identity.insert(g.identity, g.id);
            table.grants.insert(g.id, g);
        }
        Ok(table)
    }

    /// Add a local grant. If the identity already has one, the old grant is
    /// replaced and its channels are closed (they must re-authorize).
    pub fn add(&mut self, new: NewGrant, now: UnixTime) -> Result<(GrantId, Vec<GrantEvent>), GrantError> {
        if self.denials.contains_key(&new.identity) {
            return Err(GrantError::Denied);
        }
        validate_name(&new.name)?;
        let mut events = Vec::new();
        if let Some(old) = self.by_identity.get(&new.identity).copied() {
            events.extend(self.remove(old));
        }
        let id = GrantId(self.next_id);
        self.next_id += 1;
        let grant = Grant {
            id,
            identity: new.identity,
            name: new.name,
            role: new.role,
            source: GrantSource::Local,
            authorizing_owner: new.authorizing_owner,
            adopted_into: None,
            granted_at: now,
            expires_at: new.expires_at,
        };
        self.by_identity.insert(grant.identity, id);
        self.grants.insert(id, grant);
        Ok((id, events))
    }

    /// Remove a grant and close every channel bound to it.
    pub fn remove(&mut self, id: GrantId) -> Vec<GrantEvent> {
        let Some(grant) = self.grants.remove(&id) else {
            return Vec::new();
        };
        self.by_identity.remove(&grant.identity);
        let channels: Vec<ConnectionId> = self
            .bindings
            .iter()
            .filter(|(_, g)| **g == id)
            .map(|(c, _)| *c)
            .collect();
        for c in &channels {
            self.bindings.remove(c);
        }
        if channels.is_empty() {
            Vec::new()
        } else {
            vec![GrantEvent::CloseChannels {
                grant: id,
                channels,
                code: ErrorCode::GrantRevoked,
            }]
        }
    }

    /// Deny an identity host-wide: removes its grant, closes its channels and
    /// blocks future grants.
    pub fn deny(&mut self, identity: IdentityPublicKey, now: UnixTime) -> Vec<GrantEvent> {
        self.denials.entry(identity).or_insert(now);
        match self.by_identity.get(&identity).copied() {
            Some(id) => self.remove(id),
            None => Vec::new(),
        }
    }

    /// Lift a local denial. Grants nothing by itself.
    pub fn undeny(&mut self, identity: &IdentityPublicKey) -> bool {
        self.denials.remove(identity).is_some()
    }

    /// Whether the identity is denied.
    pub fn is_denied(&self, identity: &IdentityPublicKey) -> bool {
        self.denials.contains_key(identity)
    }

    /// The identity's live grant at `now`: present, not expired, not denied.
    pub fn live_grant(&self, identity: &IdentityPublicKey, now: UnixTime) -> Option<&Grant> {
        if self.is_denied(identity) {
            return None;
        }
        let id = self.by_identity.get(identity)?;
        self.grants.get(id).filter(|g| g.is_live(now))
    }

    /// A grant by id, live or not.
    pub fn get(&self, id: GrantId) -> Option<&Grant> {
        self.grants.get(&id)
    }

    /// Bind a channel to the grant that authorized it. The grant must be live.
    pub fn bind(&mut self, channel: ConnectionId, id: GrantId, now: UnixTime) -> Result<(), GrantError> {
        if self.bindings.contains_key(&channel) {
            return Err(GrantError::AlreadyBound);
        }
        let grant = self.grants.get(&id).filter(|g| g.is_live(now)).ok_or(GrantError::UnknownGrant)?;
        if self.denials.contains_key(&grant.identity) {
            return Err(GrantError::Denied);
        }
        self.bindings.insert(channel, id);
        Ok(())
    }

    /// Forget a channel (it closed on its own).
    pub fn unbind(&mut self, channel: ConnectionId) {
        self.bindings.remove(&channel);
    }

    /// The grant a channel is bound to.
    pub fn binding(&self, channel: ConnectionId) -> Option<GrantId> {
        self.bindings.get(&channel).copied()
    }

    /// Remove grants that expired at or before `now`, closing their channels.
    pub fn tick(&mut self, now: UnixTime) -> Vec<GrantEvent> {
        let expired: Vec<GrantId> = self
            .grants
            .values()
            .filter(|g| !g.is_live(now))
            .map(|g| g.id)
            .collect();
        expired.into_iter().flat_map(|id| self.remove(id)).collect()
    }

    /// The earliest grant expiry, so the caller knows when to call `tick`.
    pub fn next_expiry(&self) -> Option<UnixTime> {
        self.grants.values().filter_map(|g| g.expires_at).min()
    }

    /// All grants, for persistence and display.
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    /// All denials, for persistence and display.
    pub fn denials(&self) -> impl Iterator<Item = Denial> + '_ {
        self.denials.iter().map(|(identity, at)| Denial {
            identity: *identity,
            denied_at: *at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SoftwareKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn id(seed: u8) -> IdentityPublicKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
    }

    fn new_grant(seed: u8, expires_at: Option<UnixTime>) -> NewGrant {
        NewGrant {
            identity: id(seed),
            name: format!("device {seed}"),
            role: Role::owner(),
            authorizing_owner: OwnerRef::new("profile-1").unwrap(),
            expires_at,
        }
    }

    const NOW: UnixTime = UnixTime(1_000);

    #[test]
    fn removing_a_grant_closes_exactly_its_channels() {
        let mut t = GrantTable::new();
        let (a, _) = t.add(new_grant(1, None), NOW).unwrap();
        let (b, _) = t.add(new_grant(2, None), NOW).unwrap();
        t.bind(ConnectionId(10), a, NOW).unwrap();
        t.bind(ConnectionId(11), a, NOW).unwrap();
        t.bind(ConnectionId(12), b, NOW).unwrap();
        let events = t.remove(a);
        assert_eq!(
            events,
            vec![GrantEvent::CloseChannels {
                grant: a,
                channels: vec![ConnectionId(10), ConnectionId(11)],
                code: ErrorCode::GrantRevoked
            }]
        );
        assert_eq!(t.binding(ConnectionId(12)), Some(b));
        assert!(t.live_grant(&id(1), NOW).is_none());
    }

    #[test]
    fn expiry_closes_channels_at_the_expiry_second() {
        let mut t = GrantTable::new();
        let (a, _) = t.add(new_grant(1, Some(UnixTime(2_000))), NOW).unwrap();
        t.bind(ConnectionId(1), a, NOW).unwrap();
        assert!(t.tick(UnixTime(1_999)).is_empty());
        assert!(t.live_grant(&id(1), UnixTime(1_999)).is_some());
        assert!(t.live_grant(&id(1), UnixTime(2_000)).is_none());
        assert_eq!(t.tick(UnixTime(2_000)).len(), 1);
        assert_eq!(t.binding(ConnectionId(1)), None);
    }

    #[test]
    fn local_denial_wins_over_existing_and_new_grants() {
        let mut t = GrantTable::new();
        let (a, _) = t.add(new_grant(1, None), NOW).unwrap();
        t.bind(ConnectionId(1), a, NOW).unwrap();
        let events = t.deny(id(1), NOW);
        assert_eq!(events.len(), 1);
        assert!(t.live_grant(&id(1), NOW).is_none());
        assert_eq!(t.add(new_grant(1, None), NOW).unwrap_err(), GrantError::Denied);
        // Undeny lifts the block but grants nothing.
        assert!(t.undeny(&id(1)));
        assert!(t.live_grant(&id(1), NOW).is_none());
        assert!(t.add(new_grant(1, None), NOW).is_ok());
    }

    #[test]
    fn restore_drops_grants_of_denied_identities() {
        let mut t = GrantTable::new();
        t.add(new_grant(1, None), NOW).unwrap();
        t.add(new_grant(2, None), NOW).unwrap();
        let grants: Vec<Grant> = t.grants().cloned().collect();
        let restored = GrantTable::restore(grants, vec![Denial { identity: id(2), denied_at: NOW }]).unwrap();
        assert!(restored.live_grant(&id(1), NOW).is_some());
        assert!(restored.live_grant(&id(2), NOW).is_none());
        // New ids continue after restored ones.
        let mut restored = restored;
        let (next, _) = restored.add(new_grant(3, None), NOW).unwrap();
        assert_eq!(next, GrantId(2));
    }

    #[test]
    fn regranting_replaces_the_old_grant_and_closes_its_channels() {
        let mut t = GrantTable::new();
        let (a, _) = t.add(new_grant(1, None), NOW).unwrap();
        t.bind(ConnectionId(5), a, NOW).unwrap();
        let (b, events) = t.add(new_grant(1, None), NOW).unwrap();
        assert_ne!(a, b);
        assert_eq!(events.len(), 1);
        assert!(t.get(a).is_none());
    }

    #[test]
    fn roles_are_validated() {
        assert!(Role::new("owner").is_ok());
        assert!(Role::new("team-admin2").is_ok());
        assert!(Role::new("").is_err());
        assert!(Role::new("Owner").is_err());
        assert!(Role::new(&"a".repeat(33)).is_err());
    }
}
