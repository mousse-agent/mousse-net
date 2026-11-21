//! Pre-auth admission: places for inbound connections that are not live
//! yet (Phase 1b §6.2).
//!
//! Each listener kind has its own pool per endpoint (`PREAUTH_TCP`,
//! `PREAUTH_WS`, `PREAUTH_PIPE`), so a flood through one kind cannot take
//! the places of another. TCP connections also count against
//! `PREAUTH_PER_SOURCE` per IPv4 address or IPv6 /64; `ws` and pipe
//! connections all come from loopback.
//!
//! A listener takes a [`PreAuthSlot`] at accept, before it reads anything,
//! and hands it to [`Host::accept_admitted`](crate::Host::accept_admitted),
//! which holds it until the connection is live or closed. The slot frees
//! its place when dropped.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::limits::IoLimits;

/// The kind of listener a connection arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerKind {
    /// Direct TCP.
    Tcp,
    /// A WebSocket through a user tunnel.
    Ws,
    /// The local IPC pipe an SSH login reaches.
    Pipe,
}

impl ListenerKind {
    /// Every kind, in the order [`PreAuthStats`] lists them.
    pub const ALL: [ListenerKind; 3] = [Self::Tcp, Self::Ws, Self::Pipe];

    /// The name used in `stats` and logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Pipe => "pipe",
        }
    }

    /// The limit that caps this kind's pool.
    pub fn limit_name(self) -> &'static str {
        match self {
            Self::Tcp => "PREAUTH_TCP",
            Self::Ws => "PREAUTH_WS",
            Self::Pipe => "PREAUTH_PIPE",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Ws => 1,
            Self::Pipe => 2,
        }
    }
}

/// Where a TCP connection counts for `PREAUTH_PER_SOURCE`: its IPv4
/// address, or the /64 of its IPv6 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// One IPv4 address (an IPv4-mapped IPv6 address counts as IPv4).
    V4([u8; 4]),
    /// The first 64 bits of an IPv6 address.
    V6Prefix([u8; 8]),
}

impl SourceKey {
    /// The key for `ip`.
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let mut prefix = [0; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                Self::V6Prefix(prefix)
            }
        }
    }
}

/// Why a connection got no place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreAuthFull {
    /// The kind's pool is full.
    Pool(ListenerKind),
    /// `PREAUTH_PER_SOURCE` connections from this source are waiting.
    Source,
}

impl fmt::Display for PreAuthFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pool(kind) => write!(
                f,
                "too many {} connections waiting for authorization ({})",
                kind.name(),
                kind.limit_name()
            ),
            Self::Source => f.write_str(
                "too many connections from its address waiting for authorization (PREAUTH_PER_SOURCE)",
            ),
        }
    }
}

/// Places taken and refused per kind, for `stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreAuthStats {
    /// Places held now, by [`ListenerKind::ALL`] order.
    pub open: [u64; 3],
    /// Connections refused a place since start, by the same order.
    pub refused: [u64; 3],
}

impl PreAuthStats {
    /// Places of `kind` held now.
    pub fn open(&self, kind: ListenerKind) -> u64 {
        self.open[kind.index()]
    }

    /// Connections of `kind` refused since start.
    pub fn refused(&self, kind: ListenerKind) -> u64 {
        self.refused[kind.index()]
    }
}

/// The pools of one endpoint.
pub struct PreAuth {
    caps: [usize; 3],
    per_source: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    open: [usize; 3],
    refused: [u64; 3],
    by_source: HashMap<SourceKey, usize>,
}

/// A place in one pool; freed when dropped.
pub struct PreAuthSlot {
    pool: Arc<PreAuth>,
    kind: ListenerKind,
    source: Option<SourceKey>,
}

impl fmt::Debug for PreAuthSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreAuthSlot")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .finish()
    }
}

fn count(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

impl PreAuth {
    /// Pools sized by `limits`.
    pub fn new(limits: &IoLimits) -> Arc<Self> {
        Self::with_caps(
            [
                limits.preauth_tcp(),
                limits.preauth_ws(),
                limits.preauth_pipe(),
            ],
            limits.preauth_per_source(),
        )
    }

    /// Pools of these sizes (tcp, ws, pipe) and per-source cap.
    pub fn with_caps(caps: [u64; 3], per_source: u64) -> Arc<Self> {
        Arc::new(Self {
            caps: caps.map(count),
            per_source: count(per_source),
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A place of `kind`, counted against `source` too when given (TCP).
    pub fn try_take(
        self: &Arc<Self>,
        kind: ListenerKind,
        source: Option<IpAddr>,
    ) -> Result<PreAuthSlot, PreAuthFull> {
        let source = source.map(SourceKey::of);
        let mut st = self.lock();
        let i = kind.index();
        let in_pool = if cfg!(mousse_control = "shared-preauth-pool") {
            // Control (tests only): every kind draws on one pool.
            st.open.iter().sum()
        } else {
            st.open[i]
        };
        let capped = !cfg!(mousse_control = "no-preauth-budget");
        if capped && in_pool >= self.caps[i] {
            st.refused[i] += 1;
            return Err(PreAuthFull::Pool(kind));
        }
        if let Some(key) = source {
            let from = st.by_source.get(&key).copied().unwrap_or(0);
            if capped && from >= self.per_source {
                st.refused[i] += 1;
                return Err(PreAuthFull::Source);
            }
            st.by_source.insert(key, from + 1);
        }
        st.open[i] += 1;
        Ok(PreAuthSlot {
            pool: self.clone(),
            kind,
            source,
        })
    }

    /// A place of `kind` for a connection that already passed its listener,
    /// not counted per source: a re-pair from live (§6.2).
    pub(crate) fn try_take_again(
        self: &Arc<Self>,
        kind: ListenerKind,
    ) -> Result<PreAuthSlot, PreAuthFull> {
        self.try_take(kind, None)
    }

    /// Places held and refused so far.
    pub fn stats(&self) -> PreAuthStats {
        let st = self.lock();
        PreAuthStats {
            open: st.open.map(|n| n as u64),
            refused: st.refused,
        }
    }
}

impl PreAuthSlot {
    /// The pool this place is in.
    pub fn kind(&self) -> ListenerKind {
        self.kind
    }
}

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        let mut st = self.pool.lock();
        let i = self.kind.index();
        st.open[i] = st.open[i].saturating_sub(1);
        if let Some(key) = self.source {
            if let Some(n) = st.by_source.get_mut(&key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.by_source.remove(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, last)))
    }

    #[test]
    fn ipv6_counts_per_64_and_mapped_ipv4_as_ipv4() {
        let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: Ipv6Addr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(SourceKey::of(a.into()), SourceKey::of(b.into()));
        assert_ne!(SourceKey::of(a.into()), SourceKey::of(c.into()));
        let mapped: Ipv6Addr = "::ffff:192.168.1.7".parse().unwrap();
        assert_eq!(SourceKey::of(mapped.into()), SourceKey::of(v4(7).unwrap()));
    }

    #[test]
    fn places_free_on_drop() {
        let pool = PreAuth::with_caps([2, 1, 1], 2);
        let a = pool.try_take(ListenerKind::Tcp, v4(1)).unwrap();
        let _b = pool.try_take(ListenerKind::Tcp, v4(2)).unwrap();
        assert_eq!(
            pool.try_take(ListenerKind::Tcp, v4(3)).unwrap_err(),
            PreAuthFull::Pool(ListenerKind::Tcp)
        );
        drop(a);
        let _c = pool.try_take(ListenerKind::Tcp, v4(3)).unwrap();
        let stats = pool.stats();
        assert_eq!(stats.open(ListenerKind::Tcp), 2);
        assert_eq!(stats.refused(ListenerKind::Tcp), 1);
    }
}
