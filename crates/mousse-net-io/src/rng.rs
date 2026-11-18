//! Randomness from the operating system, in the form core expects.

use getrandom::SysRng;
use rand_core::UnwrapErr;

/// The OS random source as a `rand_core` [`CryptoRng`](rand_core::CryptoRng).
/// It panics only if the operating system cannot provide randomness.
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// `N` random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::Rng;
    let mut out = [0u8; N];
    os_rng().fill_bytes(&mut out);
    out
}
