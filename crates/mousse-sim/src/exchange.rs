//! The code exchange the simulated devices run, and a counter around it.
//!
//! Pairing core only sees the [`CodeExchangeFactory`] trait. The simulator
//! picks the implementation with the single alias [`ExchangeImpl`]: real
//! CPace by default, or core's insecure stand-in with the
//! `insecure-exchange` feature (only for speed comparisons).
//!
//! [`CountingFactory`] wraps it and records every exchange start. Starting an
//! exchange is the first piece of code work for an attempt, so the record is
//! what the "debit before code work" invariant compares with the attempt
//! counters of the host and joiner state machines.

use std::cell::RefCell;
use std::rc::Rc;

use mousse_net_core::pairing::{
    BindingTranscript, CodeExchangeFactory, ExchangeRole, PairingCode, SID_LEN,
};
use rand_core::CryptoRng;

/// The code-exchange factory the simulated devices use: real CPace (the
/// joiner is the initiator, the host the responder).
#[cfg(not(feature = "insecure-exchange"))]
pub type ExchangeImpl = mousse_net_core::pairing::CpaceExchangeFactory;

/// The code-exchange factory the simulated devices use: core's insecure
/// stand-in (same message shape and confirmation rules as CPace, not
/// secure), for speed comparisons only.
#[cfg(feature = "insecure-exchange")]
pub type ExchangeImpl = mousse_net_core::pairing::insecure::InsecureTestExchangeFactory;

fn new_exchange_impl() -> ExchangeImpl {
    ExchangeImpl::default()
}

/// One exchange start, as seen by the counter.
#[derive(Clone, Debug)]
pub(crate) struct WorkRecord {
    /// Device that started the exchange.
    pub dev: usize,
    /// Host: pairing instance (changes on restart). Joiner: state machine
    /// instance (one per `JoinerPairing` value).
    pub instance: u64,
    /// Initiator (joiner) or responder (host).
    pub role: ExchangeRole,
    /// The binding transcript (it contains the ticket hash).
    pub transcript: Vec<u8>,
}

/// Shared list of exchange starts for one run.
pub(crate) type WorkLog = Rc<RefCell<Vec<WorkRecord>>>;

/// A factory that records each start, then delegates to [`ExchangeImpl`].
pub(crate) struct CountingFactory {
    inner: ExchangeImpl,
    dev: usize,
    instance: u64,
    log: WorkLog,
}

impl CountingFactory {
    pub(crate) fn new(dev: usize, instance: u64, log: WorkLog) -> Self {
        Self {
            inner: new_exchange_impl(),
            dev,
            instance,
            log,
        }
    }
}

impl CodeExchangeFactory for CountingFactory {
    type Exchange = <ExchangeImpl as CodeExchangeFactory>::Exchange;

    fn start<R: CryptoRng + ?Sized>(
        &self,
        role: ExchangeRole,
        code: &PairingCode,
        binding: &BindingTranscript,
        sid: &[u8; SID_LEN],
        rng: &mut R,
    ) -> Self::Exchange {
        self.log.borrow_mut().push(WorkRecord {
            dev: self.dev,
            instance: self.instance,
            role,
            transcript: binding.as_bytes().to_vec(),
        });
        self.inner.start(role, code, binding, sid, rng)
    }
}

/// Whether `haystack` contains `needle` (used to find a ticket hash inside a
/// binding transcript).
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
