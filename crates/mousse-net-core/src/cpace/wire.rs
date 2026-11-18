//! Parsing of the CPace messages on the Mousse wire. See `spec/cpace.md`,
//! "Messages".
//!
//! A share is lv_cat(Y, AD): the byte 0x20, the 32-byte encoded point, the
//! LEB128 length of AD and AD. The parser accepts exactly one encoding for
//! each share: the length of AD must use the shortest LEB128 form.

use super::primitives::POINT_LEN;
use super::CpaceError;

/// The largest associated data a message may carry.
pub const MAX_AD_LEN: usize = 4096;

/// A parsed share. `body` is the exact bytes of lv_cat(Y, AD) and `rest` is
/// whatever follows it in the message.
pub(crate) struct Share<'a> {
    pub(crate) point: [u8; POINT_LEN],
    pub(crate) ad: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) rest: &'a [u8],
}

/// Reads the shortest-form LEB128 length at the start of `input`. Returns the
/// value and the number of bytes used.
fn read_len(input: &[u8]) -> Result<(usize, usize), CpaceError> {
    let mut value: usize = 0;
    // MAX_AD_LEN fits in two LEB128 bytes; a third byte is never valid.
    for (i, &byte) in input.iter().take(2).enumerate() {
        value |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(CpaceError::Malformed);
            }
            if value > MAX_AD_LEN {
                return Err(CpaceError::Malformed);
            }
            return Ok((value, i + 1));
        }
    }
    Err(CpaceError::Malformed)
}

/// Parses lv_cat(Y, AD) at the start of `msg`.
pub(crate) fn parse_share(msg: &[u8]) -> Result<Share<'_>, CpaceError> {
    let (&y_len, after_tag) = msg.split_first().ok_or(CpaceError::Malformed)?;
    if usize::from(y_len) != POINT_LEN {
        return Err(CpaceError::Malformed);
    }
    let (point, after_point) = after_tag
        .split_first_chunk::<POINT_LEN>()
        .ok_or(CpaceError::Malformed)?;
    let (ad_len, len_size) = read_len(after_point)?;
    let ad_start = len_size;
    let ad_end = ad_start.checked_add(ad_len).ok_or(CpaceError::Malformed)?;
    let ad = after_point
        .get(ad_start..ad_end)
        .ok_or(CpaceError::Malformed)?;
    let body_len = 1 + POINT_LEN + ad_end;
    Ok(Share {
        point: *point,
        ad,
        body: &msg[..body_len],
        rest: &msg[body_len..],
    })
}
