//! The code-exchange seam and the pairing code.
//!
//! The real exchange is CPace (spec `cpace.md`), implemented in
//! [`crate::cpace`] and adapted here as [`CpaceExchangeFactory`]. The pairing
//! state machines only see the traits.

use std::fmt;

use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::proof::SID_LEN;
use super::BindingTranscript;
use crate::cpace::{sample_scalar, share_has_empty_ad, CpaceError, Initiator, Inputs, Responder};

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
    /// The host: checks both confirmations.
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
    /// binding transcript or session id.
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
/// The flow, for CPace with key confirmation in both directions:
/// 1. initiator `step(None)` → send `msg_a`;
/// 2. responder `step(Some(msg_a))` → send `msg_b` (its share and its
///    confirmation);
/// 3. initiator `step(Some(msg_b))` → verifies the responder's confirmation,
///    sends `msg_c` (its own confirmation), `peer_confirmed = true`;
/// 4. responder `step(Some(msg_c))` → verifies, `send = None`,
///    `peer_confirmed = true`.
///
/// The pairing state machines rely only on `peer_confirmed` and on every
/// error ending the attempt.
pub trait CodeExchange {
    /// Feed the next peer message (`None` for the initiator's first call).
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError>;
}

/// Creates exchanges. Pairing calls this only after it has debited an
/// attempt, so no exchange work ever happens on an undebited attempt.
pub trait CodeExchangeFactory {
    /// The per-attempt exchange.
    type Exchange: CodeExchange;

    /// Start an exchange for `role`: the code is the password, the binding
    /// transcript the channel identifier (CI) and `sid` the attempt's session
    /// id (see [`super::attempt_sid`]). All randomness the exchange needs is
    /// drawn here, from `rng`.
    fn start<R: CryptoRng + ?Sized>(
        &self,
        role: ExchangeRole,
        code: &PairingCode,
        binding: &BindingTranscript,
        sid: &[u8; SID_LEN],
        rng: &mut R,
    ) -> Self::Exchange;
}

/// The real code exchange: CPace profile 1 (spec `cpace.md`), with empty
/// associated data on both sides.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpaceExchangeFactory;

enum CpaceState {
    /// Created; holds this side's secret scalar.
    Fresh(Zeroizing<Scalar>),
    /// Initiator, `msg_a` sent.
    AwaitingResponse(Initiator),
    /// Responder, `msg_b` sent.
    AwaitingConfirmation(Responder),
    /// Finished or failed.
    Done,
}

/// One side of a CPace attempt.
pub struct CpaceExchange {
    role: ExchangeRole,
    code: PairingCode,
    ci: Vec<u8>,
    sid: [u8; SID_LEN],
    state: CpaceState,
}

impl fmt::Debug for CpaceExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CpaceExchange({:?})", self.role)
    }
}

impl CodeExchangeFactory for CpaceExchangeFactory {
    type Exchange = CpaceExchange;

    fn start<R: CryptoRng + ?Sized>(
        &self,
        role: ExchangeRole,
        code: &PairingCode,
        binding: &BindingTranscript,
        sid: &[u8; SID_LEN],
        rng: &mut R,
    ) -> CpaceExchange {
        // The scalar is drawn now, so all of an attempt's draws happen when it
        // starts, in a fixed order.
        CpaceExchange {
            role,
            code: code.clone(),
            ci: binding.as_bytes().to_vec(),
            sid: *sid,
            state: CpaceState::Fresh(sample_scalar(rng)),
        }
    }
}

fn from_cpace(e: CpaceError) -> ExchangeError {
    match e {
        CpaceError::ConfirmationFailed => ExchangeError::ConfirmationFailed,
        _ => ExchangeError::Malformed,
    }
}

impl CodeExchange for CpaceExchange {
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
        let state = std::mem::replace(&mut self.state, CpaceState::Done);
        let inputs = Inputs {
            prs: self.code.as_bytes(),
            ci: &self.ci,
            sid: &self.sid,
            ad: &[],
        };
        inputs.check().map_err(from_cpace)?;
        // Version 1 sends empty AD both ways; a share with AD is refused
        // before any group work.
        let carries_share = matches!(
            (self.role, &state),
            (ExchangeRole::Responder, CpaceState::Fresh(_))
                | (ExchangeRole::Initiator, CpaceState::AwaitingResponse(_))
        );
        if let (true, Some(share)) = (carries_share, incoming) {
            if !share_has_empty_ad(share).map_err(from_cpace)? {
                return Err(ExchangeError::Malformed);
            }
        }
        let (next, send, peer_confirmed) = match (self.role, state, incoming) {
            (ExchangeRole::Initiator, CpaceState::Fresh(ya), None) => {
                let (initiator, msg_a) = Initiator::start_with_scalar(&inputs, ya);
                (CpaceState::AwaitingResponse(initiator), Some(msg_a), false)
            }
            (ExchangeRole::Responder, CpaceState::Fresh(yb), Some(msg_a)) => {
                let (responder, msg_b) =
                    Responder::respond_with_scalar(&inputs, msg_a, yb).map_err(from_cpace)?;
                (
                    CpaceState::AwaitingConfirmation(responder),
                    Some(msg_b),
                    false,
                )
            }
            (ExchangeRole::Initiator, CpaceState::AwaitingResponse(initiator), Some(msg_b)) => {
                // Pairing does not use the session key; it is wiped on drop.
                let (_confirmed, msg_c) = initiator.finish(msg_b).map_err(from_cpace)?;
                (CpaceState::Done, Some(msg_c), true)
            }
            (ExchangeRole::Responder, CpaceState::AwaitingConfirmation(responder), Some(msg_c)) => {
                responder.finish(msg_c).map_err(from_cpace)?;
                (CpaceState::Done, None, true)
            }
            _ => return Err(ExchangeError::OutOfOrder),
        };
        self.state = next;
        Ok(ExchangeStep {
            send,
            peer_confirmed,
        })
    }
}

/// A stand-in exchange for the simulator. **Not secure**: anyone who sees its
/// messages can test every code offline. It has the same message shape as
/// CPace with confirmation (three messages) and costs less to run.
#[cfg(feature = "insecure-test-exchange")]
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
            sid: &[u8; SID_LEN],
            rng: &mut R,
        ) -> InsecureTestExchange {
            let mut own_nonce = [0u8; 16];
            rng.fill_bytes(&mut own_nonce);
            let mut bound = binding.as_bytes().to_vec();
            bound.extend_from_slice(sid);
            InsecureTestExchange {
                role,
                code: code.clone(),
                binding: bound,
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

    fn binding(ticket_hash: u8) -> BindingTranscript {
        let key = crate::identity::SoftwareKey::generate(&mut ChaCha20Rng::from_seed([9; 32]))
            .public_key();
        crate::pairing::binding_transcript(
            &[ticket_hash; 32],
            crate::pairing::InvitationKind::SendLink,
            1,
            &key,
            &key,
            &[0; 32],
        )
    }

    type Outcome = (
        Result<ExchangeStep, ExchangeError>,
        Option<Result<ExchangeStep, ExchangeError>>,
    );

    /// One attempt. Returns the initiator's second step and the responder's
    /// last step (when the initiator got that far).
    fn run<F: CodeExchangeFactory>(
        f: &F,
        codes: (&str, &str),
        bindings: (u8, u8),
        sids: ([u8; SID_LEN], [u8; SID_LEN]),
    ) -> Outcome {
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let code = |c: &str| PairingCode::parse(c).unwrap();
        let mut i = f.start(
            ExchangeRole::Initiator,
            &code(codes.0),
            &binding(bindings.0),
            &sids.0,
            &mut rng,
        );
        let mut r = f.start(
            ExchangeRole::Responder,
            &code(codes.1),
            &binding(bindings.1),
            &sids.1,
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
    fn cpace_confirms_only_with_equal_code_transcript_and_sid() {
        let f = CpaceExchangeFactory;
        let (i, r) = run(&f, ("123456", "123456"), (0, 0), ([1; 32], [1; 32]));
        assert!(i.unwrap().peer_confirmed);
        let r = r.unwrap().unwrap();
        assert!(r.peer_confirmed);
        assert_eq!(r.send, None);
        for (codes, bindings, sids) in [
            (("123456", "654321"), (0, 0), ([1; 32], [1; 32])),
            (("123456", "123456"), (0, 1), ([1; 32], [1; 32])),
            (("123456", "123456"), (0, 0), ([1; 32], [2; 32])),
        ] {
            let (i, r) = run(&f, codes, bindings, sids);
            assert_eq!(i, Err(ExchangeError::ConfirmationFailed));
            assert!(r.is_none());
        }
    }

    #[test]
    fn cpace_rejects_out_of_order_and_malformed_messages() {
        let f = CpaceExchangeFactory;
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let code = PairingCode::parse("123456").unwrap();
        let b = binding(0);
        let mut r = f.start(ExchangeRole::Responder, &code, &b, &[1; 32], &mut rng);
        assert_eq!(r.step(None), Err(ExchangeError::OutOfOrder));
        let mut r = f.start(ExchangeRole::Responder, &code, &b, &[1; 32], &mut rng);
        assert_eq!(r.step(Some(&[0x20; 10])), Err(ExchangeError::Malformed));
        // A failed step ends the exchange.
        assert_eq!(r.step(Some(&[0x20; 10])), Err(ExchangeError::OutOfOrder));
        let mut i = f.start(ExchangeRole::Initiator, &code, &b, &[1; 32], &mut rng);
        assert_eq!(i.step(Some(b"x")), Err(ExchangeError::OutOfOrder));
        // A forged confirmation from the initiator fails on the responder.
        let mut i = f.start(ExchangeRole::Initiator, &code, &b, &[1; 32], &mut rng);
        let mut r = f.start(ExchangeRole::Responder, &code, &b, &[1; 32], &mut rng);
        let m1 = i.step(None).unwrap().send.unwrap();
        r.step(Some(&m1)).unwrap();
        assert_eq!(
            r.step(Some(&[0; crate::cpace::TAG_LEN])),
            Err(ExchangeError::ConfirmationFailed)
        );
    }

    /// A peer running CPace with the same code, transcript and sid but
    /// non-empty AD would confirm; version 1 refuses its share instead.
    #[test]
    fn cpace_shares_with_associated_data_are_refused() {
        let f = CpaceExchangeFactory;
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let code = PairingCode::parse("123456").unwrap();
        let b = binding(0);
        let sid = [1u8; 32];
        let inputs = Inputs {
            prs: code.as_bytes(),
            ci: b.as_bytes(),
            sid: &sid,
            ad: b"x",
        };
        // msg_a with AD, to our responder.
        let (_, msg_a) = Initiator::start(&inputs, &mut rng).unwrap();
        let mut r = f.start(ExchangeRole::Responder, &code, &b, &sid, &mut rng);
        assert_eq!(r.step(Some(&msg_a)), Err(ExchangeError::Malformed));
        // msg_b with AD, to our initiator.
        let mut i = f.start(ExchangeRole::Initiator, &code, &b, &sid, &mut rng);
        let ours = i.step(None).unwrap().send.unwrap();
        let (_, msg_b) = Responder::respond(&inputs, &ours, &mut rng).unwrap();
        assert_eq!(i.step(Some(&msg_b)), Err(ExchangeError::Malformed));
    }

    #[cfg(feature = "insecure-test-exchange")]
    #[test]
    fn stand_in_exchange_confirms_only_with_equal_inputs() {
        let f = insecure::InsecureTestExchangeFactory;
        let (i, r) = run(&f, ("123456", "123456"), (0, 0), ([1; 32], [1; 32]));
        assert!(i.unwrap().peer_confirmed);
        assert!(r.unwrap().unwrap().peer_confirmed);
        for (codes, sids) in [
            (("123456", "654321"), ([1; 32], [1; 32])),
            (("123456", "123456"), ([1; 32], [2; 32])),
        ] {
            let (i, r) = run(&f, codes, (0, 0), sids);
            assert_eq!(i, Err(ExchangeError::ConfirmationFailed));
            assert!(r.is_none());
        }
    }
}
