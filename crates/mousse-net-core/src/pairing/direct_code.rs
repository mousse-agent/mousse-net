//! The direct code (spec `wire.md` 10.9): the 12-character code a host shows
//! for "Pair with IP" and the joiner types.
//!
//! The first 4 characters are the **lookup** `L`, which finds the invitation
//! on the host. The last 8 are the **secret** `S`, the code exchange's
//! password; it is never sent. Both are derived from the code, so none of
//! these types prints its characters in `Debug`, and the code and the secret
//! are zeroized on drop and compared in constant time.

use std::fmt;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// The code alphabet: Crockford base32 (no `I`, `L`, `O`, `U`).
pub const DIRECT_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a code.
pub const DIRECT_CODE_LEN: usize = 12;
/// Characters of the lookup, the code's first part.
pub const DIRECT_LOOKUP_LEN: usize = 4;
/// Characters of the secret, the code's last part.
pub const DIRECT_SECRET_LEN: usize = DIRECT_CODE_LEN - DIRECT_LOOKUP_LEN;

/// A direct code: 12 characters of [`DIRECT_CODE_ALPHABET`], canonical form
/// (uppercase, no separators). Zeroized on drop; `Debug` hides it.
#[derive(Clone)]
pub struct DirectCode(Zeroizing<[u8; DIRECT_CODE_LEN]>);

impl DirectCode {
    /// A fresh code: 12 random bytes from `rng`, mapped by [`Self::from_draw`].
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut draw = Zeroizing::new([0u8; DIRECT_CODE_LEN]);
        rng.fill_bytes(&mut draw[..]);
        Self::from_draw(&draw)
    }

    /// A fresh code whose lookup does not satisfy `taken`: the whole code is
    /// drawn again until it does not. The host uses this to keep lookups of
    /// its open invitations distinct. `taken` must leave some lookup free.
    pub fn generate_avoiding<R, F>(rng: &mut R, mut taken: F) -> Self
    where
        R: CryptoRng + ?Sized,
        F: FnMut(&DirectLookup) -> bool,
    {
        loop {
            let code = Self::generate(rng);
            if !taken(&code.lookup()) {
                return code;
            }
        }
    }

    /// The code for 12 drawn bytes: byte `b` becomes `ALPHABET[b & 0x1f]`.
    /// Uniform for uniform bytes, with no redraw.
    pub fn from_draw(draw: &[u8; DIRECT_CODE_LEN]) -> Self {
        let mut chars = Zeroizing::new([0u8; DIRECT_CODE_LEN]);
        for (c, b) in chars.iter_mut().zip(draw) {
            *c = DIRECT_CODE_ALPHABET[usize::from(b & 0x1f)];
        }
        Self(chars)
    }

    /// Read a code as a person typed it. ASCII spaces and `-` are dropped,
    /// ASCII letters are uppercased, `O` reads as `0` and `I` and `L` as `1`.
    /// Any other character, or a length other than 12 after that, is an
    /// error; a bad character is reported before a wrong length.
    pub fn parse(text: &str) -> Result<Self, DirectCodeError> {
        let mut chars = Zeroizing::new([0u8; DIRECT_CODE_LEN]);
        let mut len = 0usize;
        for &byte in text.as_bytes() {
            let c = match byte.to_ascii_uppercase() {
                b' ' | b'-' => continue,
                b'O' => b'0',
                b'I' | b'L' => b'1',
                c if DIRECT_CODE_ALPHABET.contains(&c) => c,
                _ => return Err(DirectCodeError::BadCharacter),
            };
            if let Some(slot) = chars.get_mut(len) {
                *slot = c;
            }
            len = len.saturating_add(1);
        }
        if len == DIRECT_CODE_LEN {
            Ok(Self(chars))
        } else {
            Err(DirectCodeError::WrongLength)
        }
    }

    /// The canonical 12 characters, as the joiner uses them.
    pub fn as_str(&self) -> &str {
        // Always ASCII from the alphabet.
        std::str::from_utf8(self.0.as_slice()).unwrap_or("")
    }

    /// The code as the host shows it: three groups of four joined by `-`.
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(DIRECT_CODE_LEN + 2));
        for (i, group) in self.as_str().as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push('-');
            }
            for &c in group {
                out.push(char::from(c));
            }
        }
        out
    }

    /// The lookup `L`: characters 1 to 4.
    pub fn lookup(&self) -> DirectLookup {
        let mut l = [0u8; DIRECT_LOOKUP_LEN];
        l.copy_from_slice(&self.0[..DIRECT_LOOKUP_LEN]);
        DirectLookup(l)
    }

    /// The secret `S`: characters 5 to 12.
    pub fn secret(&self) -> DirectSecret {
        let mut s = Zeroizing::new([0u8; DIRECT_SECRET_LEN]);
        s.copy_from_slice(&self.0[DIRECT_LOOKUP_LEN..]);
        DirectSecret(s)
    }
}

impl PartialEq for DirectCode {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for DirectCode {}

impl fmt::Debug for DirectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectCode(****-****-****)")
    }
}

/// The lookup `L`: the code's first 4 characters. It is sent inside TLS to
/// find the invitation and says nothing about the secret. Not a secret once
/// used, but derived from the code, so `Debug` hides it and it is zeroized
/// on drop.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DirectLookup([u8; DIRECT_LOOKUP_LEN]);

impl DirectLookup {
    /// A lookup as it travels in `JOIN_DIRECT`: exactly 4 characters of
    /// [`DIRECT_CODE_ALPHABET`], canonical (no folding, no separators).
    pub fn from_canonical(text: &str) -> Option<Self> {
        let bytes: [u8; DIRECT_LOOKUP_LEN] = text.as_bytes().try_into().ok()?;
        if bytes.iter().all(|c| DIRECT_CODE_ALPHABET.contains(c)) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// The 4 characters as text.
    pub fn as_str(&self) -> &str {
        // Always ASCII from the alphabet.
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for DirectLookup {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DirectLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectLookup(****)")
    }
}

/// The secret `S`: the code's last 8 characters as ASCII bytes, the code
/// exchange's password. Never sent. Zeroized on drop; `Debug` hides it;
/// compared in constant time.
#[derive(Clone)]
pub struct DirectSecret(Zeroizing<[u8; DIRECT_SECRET_LEN]>);

impl DirectSecret {
    /// The 8 ASCII bytes, the password (CPace `PRS`) for the exchange.
    pub fn as_bytes(&self) -> &[u8; DIRECT_SECRET_LEN] {
        &self.0
    }
}

impl PartialEq for DirectSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for DirectSecret {}

impl fmt::Debug for DirectSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectSecret(..)")
    }
}

/// Why typed text is not a direct code. The person sees one message for
/// both; nothing is dialled and no attempt is spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectCodeError {
    /// A character other than the alphabet, `O`, `I`, `L` (any case), an
    /// ASCII space or `-`.
    BadCharacter,
    /// Not 12 characters once spaces and dashes are dropped.
    WrongLength,
}

impl DirectCodeError {
    /// Stable snake_case name, used in test vectors.
    pub fn code(&self) -> &'static str {
        match self {
            DirectCodeError::BadCharacter => "bad_character",
            DirectCodeError::WrongLength => "wrong_length",
        }
    }
}

impl fmt::Display for DirectCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectCodeError::BadCharacter => f.write_str("the code has a character it cannot have"),
            DirectCodeError::WrongLength => f.write_str("the code is not 12 characters long"),
        }
    }
}

impl std::error::Error for DirectCodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    #[test]
    fn generate_maps_twelve_drawn_bytes() {
        let mut a = ChaCha20Rng::from_seed([5; 32]);
        let mut b = ChaCha20Rng::from_seed([5; 32]);
        let mut draw = [0u8; DIRECT_CODE_LEN];
        b.fill_bytes(&mut draw);
        assert_eq!(DirectCode::generate(&mut a), DirectCode::from_draw(&draw));
        // Both consumed the same 12 bytes.
        assert_eq!(a.next_u32(), b.next_u32());
    }

    #[test]
    fn generated_codes_parse_back_from_their_display_form() {
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        for _ in 0..200 {
            let code = DirectCode::generate(&mut rng);
            assert_eq!(DirectCode::parse(&code.to_display()), Ok(code.clone()));
            assert_eq!(DirectCode::parse(code.as_str()), Ok(code));
        }
    }

    #[test]
    fn generate_avoiding_redraws_the_whole_code_on_a_taken_lookup() {
        let mut probe = ChaCha20Rng::from_seed([7; 32]);
        let first = DirectCode::generate(&mut probe);
        let second = DirectCode::generate(&mut probe);
        assert_ne!(first.lookup(), second.lookup());

        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let taken = first.lookup();
        let got = DirectCode::generate_avoiding(&mut rng, |l| *l == taken);
        assert_eq!(got, second);

        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        assert_eq!(DirectCode::generate_avoiding(&mut rng, |_| false), first);
    }

    #[test]
    fn nothing_derived_from_the_code_shows_in_debug() {
        let code = DirectCode::parse("K7QM-2XPA-9RTE").expect("valid");
        assert_eq!(code.to_display().as_str(), "K7QM-2XPA-9RTE");
        assert_eq!(format!("{code:?}"), "DirectCode(****-****-****)");
        assert_eq!(format!("{:?}", code.lookup()), "DirectLookup(****)");
        assert_eq!(format!("{:?}", code.secret()), "DirectSecret(..)");
    }

    #[test]
    fn secret_compare_sees_every_byte() {
        let a = DirectCode::parse("K7QM2XPA9RTE").expect("valid");
        // Same secret under another lookup.
        let other_lookup = DirectCode::parse("0000-2XPA-9RTE").expect("valid");
        assert_ne!(a.lookup(), other_lookup.lookup());
        assert_eq!(a.secret(), other_lookup.secret());
        assert_ne!(a, other_lookup);

        // One mismatch at each of the eight secret positions.
        for i in DIRECT_LOOKUP_LEN..DIRECT_CODE_LEN {
            let mut text = a.as_str().as_bytes().to_vec();
            text[i] = if text[i] == b'Z' { b'Y' } else { b'Z' };
            let b = DirectCode::parse(std::str::from_utf8(&text).expect("ascii")).expect("valid");
            assert_eq!(a.lookup(), b.lookup(), "position {i}");
            assert_ne!(a.secret(), b.secret(), "position {i}");
            assert_ne!(a, b, "position {i}");
        }
    }
}
