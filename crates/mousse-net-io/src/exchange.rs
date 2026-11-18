//! The code exchange used by "Send link" pairing.
//!
//! The Phase 0 slice pairs in person only, where no code is used. Until the
//! CPace exchange is wired in, [`InPersonOnly`] stands in: any code exchange
//! fails at once, so a "send link" attempt can never enroll a device.

use mousse_net_core::pairing::{
    BindingTranscript, CodeExchange, CodeExchangeFactory, ExchangeError, ExchangeRole,
    ExchangeStep, PairingCode,
};
use rand_core::CryptoRng;

/// A factory whose exchanges always fail. Hosts using it only offer
/// in-person invitations.
#[derive(Clone, Copy, Debug, Default)]
pub struct InPersonOnly;

/// An exchange that refuses every step.
#[derive(Debug)]
pub struct NoExchange;

impl CodeExchange for NoExchange {
    fn step(&mut self, _incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
        Err(ExchangeError::ConfirmationFailed)
    }
}

impl CodeExchangeFactory for InPersonOnly {
    type Exchange = NoExchange;

    fn start<R: CryptoRng + ?Sized>(
        &self,
        _role: ExchangeRole,
        _code: &PairingCode,
        _binding: &BindingTranscript,
        _rng: &mut R,
    ) -> NoExchange {
        NoExchange
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_fails() {
        let mut exchange = NoExchange;
        assert_eq!(exchange.step(None), Err(ExchangeError::ConfirmationFailed));
        assert_eq!(
            exchange.step(Some(b"x")),
            Err(ExchangeError::ConfirmationFailed)
        );
    }
}
