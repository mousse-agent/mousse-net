//! CPace (ristretto255, SHA-512), draft-irtf-cfrg-cpace-21, in the
//! initiator-responder setting with the key confirmation of section 10.4.
//!
//! `spec/cpace.md` is the normative description of how Mousse uses it.
//!
//! The exchange is three messages:
//!
//! ```text
//! Initiator (A)                                Responder (B)
//! Initiator::start  -- msg_a = lv_cat(Ya,ADa) -->
//!                                              Responder::respond
//!                   <-- msg_b = lv_cat(Yb,ADb) || Tb --
//! Initiator::finish (checks Tb)
//!                   -- msg_c = Ta -->
//!                                              Responder::finish (checks Ta)
//! ```
//!
//! Each state is consumed by value, so a state can be used only once. No
//! function does I/O; randomness comes from the caller's RNG.

mod primitives;
mod wire;

#[cfg(test)]
mod tests;

use core::fmt;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use primitives::{ISK_LEN, POINT_LEN, TAG_LEN};
pub use wire::MAX_AD_LEN;

use curve25519_dalek::scalar::Scalar;
pub(crate) use primitives::sample_scalar;
use primitives::{calculate_generator, isk, mac_key, scalar_mult, scalar_mult_vfy, tag};

/// The shortest session id Mousse accepts.
pub const MIN_SID_LEN: usize = 16;

/// Whether the share at the start of `msg_a` or `msg_b` carries empty AD.
/// Only reads the framing; no group work.
pub(crate) fn share_has_empty_ad(msg: &[u8]) -> Result<bool, CpaceError> {
    Ok(wire::parse_share(msg)?.ad.is_empty())
}

/// Whether a constant-time tag compare matched.
#[cfg(not(mousse_control = "break-cpace-confirm"))]
fn tags_match(equal: subtle::Choice) -> bool {
    bool::from(equal)
}

/// Must-fail control: the confirmation compare always passes.
#[cfg(mousse_control = "break-cpace-confirm")]
fn tags_match(_equal: subtle::Choice) -> bool {
    true
}

/// Why a CPace step failed. A failed step consumes its state; the attempt is
/// over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpaceError {
    /// The password (PRS) is empty.
    EmptyPassword,
    /// The session id is shorter than [`MIN_SID_LEN`].
    SidTooShort,
    /// Our own associated data is longer than [`MAX_AD_LEN`].
    AdTooLong,
    /// A received message has the wrong length or framing.
    Malformed,
    /// A received point does not decode, or is the identity element.
    InvalidPoint,
    /// The peer's confirmation tag is wrong: a different code, inputs or
    /// transcript, or a tampered message.
    ConfirmationFailed,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CpaceError::EmptyPassword => "CPace password is empty",
            CpaceError::SidTooShort => "CPace session id is too short",
            CpaceError::AdTooLong => "CPace associated data is too long",
            CpaceError::Malformed => "CPace message is malformed",
            CpaceError::InvalidPoint => "CPace message carries an invalid point",
            CpaceError::ConfirmationFailed => "CPace key confirmation failed",
        })
    }
}

impl core::error::Error for CpaceError {}

/// The inputs of one party (draft section 4.1). All are opaque bytes.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// The password-related string: the pairing code.
    pub prs: &'a [u8],
    /// The channel identifier. Never sent; both sides must hold the same value.
    pub ci: &'a [u8],
    /// The session id. Public; both sides must hold the same value.
    pub sid: &'a [u8],
    /// This party's associated data (ADa for the initiator, ADb for the
    /// responder). Sent in clear inside this party's message.
    pub ad: &'a [u8],
}

impl fmt::Debug for Inputs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inputs")
            .field("prs", &"<redacted>")
            .field("ci_len", &self.ci.len())
            .field("sid_len", &self.sid.len())
            .field("ad_len", &self.ad.len())
            .finish()
    }
}

impl Inputs<'_> {
    pub(crate) fn check(&self) -> Result<(), CpaceError> {
        if self.prs.is_empty() {
            return Err(CpaceError::EmptyPassword);
        }
        if self.sid.len() < MIN_SID_LEN {
            return Err(CpaceError::SidTooShort);
        }
        if self.ad.len() > MAX_AD_LEN {
            return Err(CpaceError::AdTooLong);
        }
        Ok(())
    }
}

/// The intermediate session key. Wiped on drop. Derive keys from it with a
/// KDF and a label of your own; do not use it directly.
pub struct Isk(Zeroizing<[u8; ISK_LEN]>);

impl Isk {
    /// The key bytes.
    pub fn as_bytes(&self) -> &[u8; ISK_LEN] {
        &self.0
    }
}

impl fmt::Debug for Isk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Isk(<redacted>)")
    }
}

/// The result of a confirmed exchange.
#[derive(Debug)]
pub struct Confirmed {
    isk: Isk,
    peer_ad: Vec<u8>,
}

impl Confirmed {
    /// The shared intermediate session key.
    pub fn isk(&self) -> &Isk {
        &self.isk
    }

    /// The associated data the peer sent. It is authenticated: the peer's
    /// confirmation tag covers it.
    pub fn peer_ad(&self) -> &[u8] {
        &self.peer_ad
    }

    /// Splits into the key and the peer's associated data.
    pub fn into_parts(self) -> (Isk, Vec<u8>) {
        (self.isk, self.peer_ad)
    }
}

/// The initiator, waiting for the responder's message.
pub struct Initiator {
    ya: Zeroizing<Scalar>,
    sid: Vec<u8>,
    msg_a: Vec<u8>,
}

impl fmt::Debug for Initiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Initiator(<awaiting response>)")
    }
}

impl Initiator {
    /// Starts an exchange. Returns the state and `msg_a` to send.
    pub fn start<R: CryptoRng + ?Sized>(
        inputs: &Inputs<'_>,
        rng: &mut R,
    ) -> Result<(Initiator, Vec<u8>), CpaceError> {
        inputs.check()?;
        Ok(Self::start_with_scalar(inputs, sample_scalar(rng)))
    }

    pub(crate) fn start_with_scalar(
        inputs: &Inputs<'_>,
        ya: Zeroizing<Scalar>,
    ) -> (Initiator, Vec<u8>) {
        let g = calculate_generator(inputs.prs, inputs.ci, inputs.sid);
        let ya_enc = scalar_mult(&ya, &g);
        let msg_a = primitives::lv_cat(&[&ya_enc, inputs.ad]);
        let state = Initiator {
            ya,
            sid: inputs.sid.to_vec(),
            msg_a: msg_a.clone(),
        };
        (state, msg_a)
    }

    /// Takes `msg_b`, checks the responder's tag, and returns the confirmed
    /// result and `msg_c` (our tag) to send. On error, send nothing.
    pub fn finish(self, msg_b: &[u8]) -> Result<(Confirmed, Vec<u8>), CpaceError> {
        let share = wire::parse_share(msg_b)?;
        if share.rest.len() != TAG_LEN {
            return Err(CpaceError::Malformed);
        }
        let k = scalar_mult_vfy(&self.ya, &share.point);
        if bool::from(primitives::is_identity(&k)) {
            return Err(CpaceError::InvalidPoint);
        }
        let isk = isk(&self.sid, &k, &[&self.msg_a, share.body]);
        let mac_key = mac_key(&self.sid, &isk);
        let expected_tb = tag(&mac_key, share.body);
        if !tags_match(expected_tb[..].ct_eq(share.rest)) {
            return Err(CpaceError::ConfirmationFailed);
        }
        let ta = tag(&mac_key, &self.msg_a);
        let confirmed = Confirmed {
            isk: Isk(isk),
            peer_ad: share.ad.to_vec(),
        };
        Ok((confirmed, ta.to_vec()))
    }
}

/// The responder, waiting for the initiator's tag.
pub struct Responder {
    isk: Zeroizing<[u8; ISK_LEN]>,
    expected_ta: Zeroizing<[u8; TAG_LEN]>,
    peer_ad: Vec<u8>,
}

impl fmt::Debug for Responder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Responder(<awaiting confirmation>)")
    }
}

impl Responder {
    /// Takes `msg_a` and returns the state and `msg_b` to send.
    pub fn respond<R: CryptoRng + ?Sized>(
        inputs: &Inputs<'_>,
        msg_a: &[u8],
        rng: &mut R,
    ) -> Result<(Responder, Vec<u8>), CpaceError> {
        inputs.check()?;
        Self::respond_with_scalar(inputs, msg_a, sample_scalar(rng))
    }

    pub(crate) fn respond_with_scalar(
        inputs: &Inputs<'_>,
        msg_a: &[u8],
        yb: Zeroizing<Scalar>,
    ) -> Result<(Responder, Vec<u8>), CpaceError> {
        let share = wire::parse_share(msg_a)?;
        if !share.rest.is_empty() {
            return Err(CpaceError::Malformed);
        }
        let k = scalar_mult_vfy(&yb, &share.point);
        if bool::from(primitives::is_identity(&k)) {
            return Err(CpaceError::InvalidPoint);
        }
        let g = calculate_generator(inputs.prs, inputs.ci, inputs.sid);
        let yb_enc = scalar_mult(&yb, &g);
        let mut msg_b = primitives::lv_cat(&[&yb_enc, inputs.ad]);
        let isk = isk(inputs.sid, &k, &[share.body, &msg_b]);
        let mac_key = mac_key(inputs.sid, &isk);
        let tb = tag(&mac_key, &msg_b);
        let expected_ta = tag(&mac_key, share.body);
        msg_b.extend_from_slice(&tb[..]);
        let state = Responder {
            isk,
            expected_ta,
            peer_ad: share.ad.to_vec(),
        };
        Ok((state, msg_b))
    }

    /// Takes `msg_c`, checks the initiator's tag and returns the confirmed
    /// result.
    pub fn finish(self, msg_c: &[u8]) -> Result<Confirmed, CpaceError> {
        if msg_c.len() != TAG_LEN {
            return Err(CpaceError::Malformed);
        }
        let Responder {
            isk,
            expected_ta,
            peer_ad,
        } = self;
        if !tags_match(expected_ta[..].ct_eq(msg_c)) {
            return Err(CpaceError::ConfirmationFailed);
        }
        Ok(Confirmed {
            isk: Isk(isk),
            peer_ad,
        })
    }
}
