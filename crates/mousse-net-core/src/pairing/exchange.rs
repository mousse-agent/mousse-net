//! The code-exchange seam and the pairing code.
//!
//! The real exchange is CPace (spec `cpace.md`), implemented in
//! [`crate::cpace`]. The pairing state machines only see these traits, so they
//! can be tested and simulated without it.

use std::fmt;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::BindingTranscript;

/// A 6-digit pairing code: six ASCII digits `0`-`9`, uniformly random.
/// The digits are the exchange password and are never transmitted.
/// Zeroized on drop; `Debug` hides it.
#[derive(Clone)]
pub struct PairingCode(Zeroizing<[u8; 6]>);

impl PairingCode {
    /// A fresh uniform code (rejection sampling, no modulo bias).
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        // 4_294_000_000 is the largest multiple of 10^6 below 2^32.
        let n = loop {
            let x = rng.next_u32();
            if x < 4_294_000_000 {
                break x % 1_000_000;
            }
        };
        let mut digits = Zeroizing::new([0u8; 6]);
        let mut rest = n;
        for d in digits.iter_mut().rev() {
            *d = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
        Self(digits)
    }

    /// Parse what the owner typed: exactly six ASCII digits.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes: [u8; 6] = text.as_bytes().try_into().ok()?;
        if bytes.iter().all(u8::is_ascii_digit) {
            Some(Self(Zeroizing::new(bytes)))
        } else {
            None
        }
    }

    /// The six ASCII digit bytes (the exchange password).
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// The code as text, for display on the host.
    pub fn as_str(&self) -> &str {
        // Always six ASCII digits.
        std::str::from_utf8(self.0.as_slice()).unwrap_or("")
    }
}

impl PartialEq for PairingCode {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for PairingCode {}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(******)")
    }
}

/// Which side of the exchange this is. The joiner is the initiator; the host
/// is the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeRole {
    /// The joiner: sends the first message.
    Initiator,
    /// The host.
    Responder,
}

/// The result of one exchange step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeStep {
    /// A message to send to the peer, if any.
    pub send: Option<Vec<u8>>,
    /// True once this side has verified the peer's key confirmation. After
    /// sending `send` (if any), this side's exchange is complete.
    pub peer_confirmed: bool,
}

/// Why an exchange step failed. Any failure ends the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeError {
    /// The peer's confirmation did not match: wrong code, or a different
    /// binding transcript.
    ConfirmationFailed,
    /// The peer's message could not be parsed or is invalid (for example, an
    /// identity point).
    Malformed,
    /// A message arrived when none was expected, or none arrived when one was.
    OutOfOrder,
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExchangeError::ConfirmationFailed => "code exchange confirmation failed",
            ExchangeError::Malformed => "code exchange message malformed",
            ExchangeError::OutOfOrder => "code exchange message out of order",
        })
    }
}

impl std::error::Error for ExchangeError {}

/// One run of a code exchange (one attempt), on one side.
///
/// The expected flow, for an exchange with explicit key confirmation in both
/// directions (CPace initiator/responder):
/// 1. initiator `step(None)` → send message 1;
/// 2. responder `step(Some(m1))` → send message 2 (its share and its
///    confirmation);
/// 3. initiator `step(Some(m2))` → verifies the responder's confirmation,
///    sends message 3 (its own confirmation), `peer_confirmed = true`;
/// 4. responder `step(Some(m3))` → verifies, `send = None`,
///    `peer_confirmed = true`.
///
/// The pairing state machines do not assume the number of messages; they
/// only rely on `peer_confirmed` and on every error ending the attempt.
pub trait CodeExchange {
    /// Feed the next peer message (`None` for the initiator's first call).
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError>;
}

/// Creates exchanges. Pairing calls this only after it has debited an
/// attempt, so no exchange work ever happens on an undebited attempt.
pub trait CodeExchangeFactory {
    /// The per-attempt exchange.
    type Exchange: CodeExchange;

    /// Start an exchange for `role`, with the code as the password and the
    /// binding transcript as the channel identifier / associated data.
    fn start<R: CryptoRng + ?Sized>(
        &self,
        role: ExchangeRole,
        code: &PairingCode,
        binding: &BindingTranscript,
        rng: &mut R,
    ) -> Self::Exchange;
}

/// A stand-in exchange for tests and the simulator. **Not secure**: anyone
/// who sees its messages can test every code offline. It has the same
/// message shape as CPace with confirmation (three messages) so state
/// machines see realistic traffic.
#[cfg(any(test, feature = "insecure-test-exchange"))]
pub mod insecure {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    use super::*;

    /// Factory for [`InsecureTestExchange`].
    #[derive(Clone, Copy, Debug, Default)]
    pub struct InsecureTestExchangeFactory;

    /// One side of the stand-in exchange.
    pub struct InsecureTestExchange {
        role: ExchangeRole,
        code: PairingCode,
        binding: Vec<u8>,
        own_nonce: [u8; 16],
        peer_nonce: Option<[u8; 16]>,
        stage: u8,
    }

    impl InsecureTestExchange {
        fn tag(
            &self,
            initiator_nonce: &[u8; 16],
            responder_nonce: &[u8; 16],
            label: u8,
        ) -> [u8; 32] {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.code.as_bytes())
                .expect("any key length");
            mac.update(&self.binding);
            mac.update(initiator_nonce);
            mac.update(responder_nonce);
            mac.update(&[label]);
            mac.finalize().into_bytes().into()
        }
    }

    impl CodeExchangeFactory for InsecureTestExchangeFactory {
        type Exchange = InsecureTestExchange;

        fn start<R: CryptoRng + ?Sized>(
            &self,
            role: ExchangeRole,
            code: &PairingCode,
            binding: &BindingTranscript,
            rng: &mut R,
        ) -> InsecureTestExchange {
            let mut own_nonce = [0u8; 16];
            rng.fill_bytes(&mut own_nonce);
            InsecureTestExchange {
                role,
                code: code.clone(),
                binding: binding.as_bytes().to_vec(),
                own_nonce,
                peer_nonce: None,
                stage: 0,
            }
        }
    }

    impl CodeExchange for InsecureTestExchange {
        fn step(&mut self, incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
            match (self.role, self.stage, incoming) {
                (ExchangeRole::Initiator, 0, None) => {
                    self.stage = 1;
                    let mut m = vec![1u8];
                    m.extend_from_slice(&self.own_nonce);
                    Ok(ExchangeStep {
                        send: Some(m),
                        peer_confirmed: false,
                    })
                }
                (ExchangeRole::Responder, 0, Some(m)) => {
                    let peer: [u8; 16] = match m {
                        [1, rest @ ..] => rest.try_into().map_err(|_| ExchangeError::Malformed)?,
                        _ => return Err(ExchangeError::Malformed),
                    };
                    self.peer_nonce = Some(peer);
                    self.stage = 1;
                    let tag = self.tag(&peer, &self.own_nonce, b'r');
                    let mut out = vec![2u8];
                    out.extend_from_slice(&self.own_nonce);
                    out.extend_from_slice(&tag);
                    Ok(ExchangeStep {
                        send: Some(out),
                        peer_confirmed: false,
                    })
                }
                (ExchangeRole::Initiator, 1, Some(m)) => {
                    let (nonce, tag) = match m {
                        [2, rest @ ..] if rest.len() == 48 => (&rest[..16], &rest[16..]),
                        _ => return Err(ExchangeError::Malformed),
                    };
                    let peer: [u8; 16] = nonce.try_into().map_err(|_| ExchangeError::Malformed)?;
                    let expected = self.tag(&self.own_nonce, &peer, b'r');
                    if !bool::from(expected.ct_eq(tag)) {
                        return Err(ExchangeError::ConfirmationFailed);
                    }
                    self.stage = 2;
                    let mine = self.tag(&self.own_nonce, &peer, b'i');
                    let mut out = vec![3u8];
                    out.extend_from_slice(&mine);
                    Ok(ExchangeStep {
                        send: Some(out),
                        peer_confirmed: true,
                    })
                }
                (ExchangeRole::Responder, 1, Some(m)) => {
                    let tag = match m {
                        [3, rest @ ..] if rest.len() == 32 => rest,
                        _ => return Err(ExchangeError::Malformed),
                    };
                    let peer = self.peer_nonce.ok_or(ExchangeError::OutOfOrder)?;
                    let expected = self.tag(&peer, &self.own_nonce, b'i');
                    if !bool::from(expected.ct_eq(tag)) {
                        return Err(ExchangeError::ConfirmationFailed);
                    }
                    self.stage = 2;
                    Ok(ExchangeStep {
                        send: None,
                        peer_confirmed: true,
                    })
                }
                _ => Err(ExchangeError::OutOfOrder),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::insecure::InsecureTestExchangeFactory;
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn generated_codes_are_six_digits_and_parse_back() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        for _ in 0..100 {
            let code = PairingCode::generate(&mut rng);
            assert_eq!(code.as_str().len(), 6);
            assert_eq!(PairingCode::parse(code.as_str()), Some(code));
        }
        assert!(PairingCode::parse("12345").is_none());
        assert!(PairingCode::parse("12345a").is_none());
        assert!(PairingCode::parse("１２３４５６").is_none());
        assert_eq!(
            format!("{:?}", PairingCode::parse("123456").unwrap()),
            "PairingCode(******)"
        );
    }

    fn binding() -> BindingTranscript {
        let key = crate::identity::SoftwareKey::generate(&mut ChaCha20Rng::from_seed([9; 32]))
            .public_key();
        crate::pairing::binding_transcript(
            &[0; 32],
            crate::pairing::InvitationKind::SendLink,
            1,
            &key,
            &key,
            &[0; 32],
        )
    }

    fn run(
        initiator_code: &str,
        responder_code: &str,
    ) -> (
        Result<ExchangeStep, ExchangeError>,
        Option<Result<ExchangeStep, ExchangeError>>,
    ) {
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let f = InsecureTestExchangeFactory;
        let b = binding();
        let mut i = f.start(
            ExchangeRole::Initiator,
            &PairingCode::parse(initiator_code).unwrap(),
            &b,
            &mut rng,
        );
        let mut r = f.start(
            ExchangeRole::Responder,
            &PairingCode::parse(responder_code).unwrap(),
            &b,
            &mut rng,
        );
        let m1 = i.step(None).unwrap().send.unwrap();
        let m2 = r.step(Some(&m1)).unwrap().send.unwrap();
        let i2 = i.step(Some(&m2));
        let r2 = i2
            .as_ref()
            .ok()
            .and_then(|s| s.send.clone())
            .map(|m3| r.step(Some(&m3)));
        (i2, r2)
    }

    #[test]
    fn stand_in_exchange_confirms_only_with_equal_codes() {
        let (i, r) = run("123456", "123456");
        assert!(i.unwrap().peer_confirmed);
        assert!(r.unwrap().unwrap().peer_confirmed);
        let (i, r) = run("123456", "654321");
        assert_eq!(i, Err(ExchangeError::ConfirmationFailed));
        assert!(r.is_none());
    }
}
