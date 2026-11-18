//! Minimal strict DER: just what the session certificate profile, ECDSA
//! signatures and PKCS#8 need. Not a general ASN.1 library.

pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTF8_STRING: u8 = 0x0c;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
pub(crate) const CONTEXT_0: u8 = 0xa0;
pub(crate) const CONTEXT_1: u8 = 0xa1;
pub(crate) const CONTEXT_3: u8 = 0xa3;

/// DER parse failure. Callers map it to their own error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerError;

/// Append a tag-length-value with a minimal definite length.
pub(crate) fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        // Nothing in our profiles comes close; keep the encoder total anyway.
        out.push(0x83);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    }
    out.extend_from_slice(content);
}

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    write_tlv(&mut out, tag, content);
    out
}

/// Concatenate parts and wrap them in one TLV.
pub(crate) fn wrap(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.concat();
    tlv(tag, &content)
}

/// DER INTEGER content for a non-negative big-endian magnitude: leading zero
/// bytes removed, one 0x00 added if the top bit is set, zero encoded as 0x00.
pub(crate) fn uint_content(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|b| *b != 0);
    let trimmed = match first {
        Some(i) => &magnitude[i..],
        None => return vec![0],
    };
    let mut out = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Parse DER INTEGER content as a non-negative magnitude, enforcing minimal
/// encoding. Returns the magnitude without a sign byte ("0" gives `[0]`).
pub(crate) fn parse_uint_content(content: &[u8]) -> Result<&[u8], DerError> {
    match content {
        [] => Err(DerError),
        [first, ..] if first & 0x80 != 0 => Err(DerError),
        [0] => Ok(content),
        [0, second, ..] if second & 0x80 == 0 => Err(DerError),
        [0, rest @ ..] => Ok(rest),
        _ => Ok(content),
    }
}

/// A strict DER reader over one buffer.
pub(crate) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Read one TLV. Returns (tag, full TLV bytes, content).
    pub(crate) fn read_any(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), DerError> {
        let input = self.input;
        let tag = *input.first().ok_or(DerError)?;
        if tag & 0x1f == 0x1f {
            return Err(DerError); // high tag numbers are outside our profiles
        }
        let first = *input.get(1).ok_or(DerError)?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 {
                return Err(DerError); // indefinite, or longer than we ever use
            }
            let bytes = input.get(2..2 + count).ok_or(DerError)?;
            if bytes[0] == 0 {
                return Err(DerError);
            }
            let len = bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            if len < 0x80 {
                return Err(DerError);
            }
            (len, 2 + count)
        };
        let end = header.checked_add(len).ok_or(DerError)?;
        let full = input.get(..end).ok_or(DerError)?;
        self.input = &input[end..];
        Ok((tag, full, &full[header..]))
    }

    /// Read one TLV with the expected tag; returns its content.
    pub(crate) fn read(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let (got, _, content) = self.read_any()?;
        if got != tag {
            return Err(DerError);
        }
        Ok(content)
    }

    /// Read one TLV with the expected tag; returns the full TLV bytes.
    pub(crate) fn read_raw(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let (got, full, _) = self.read_any()?;
        if got != tag {
            return Err(DerError);
        }
        Ok(full)
    }

    /// Require that nothing is left.
    pub(crate) fn finish(self) -> Result<(), DerError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(DerError)
        }
    }
}

/// Parse a complete buffer that must be exactly one TLV with `tag`.
pub(crate) fn single(input: &[u8], tag: u8) -> Result<&[u8], DerError> {
    let mut reader = Reader::new(input);
    let content = reader.read(tag)?;
    reader.finish()?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn lengths_use_minimal_forms() {
        assert_eq!(tlv(OCTET_STRING, &[0; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(OCTET_STRING, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(
            tlv(OCTET_STRING, &[0; 0x100])[..4],
            [0x04, 0x82, 0x01, 0x00]
        );
    }

    #[test]
    fn non_minimal_and_indefinite_lengths_are_rejected() {
        assert!(Reader::new(&[0x04, 0x81, 0x01, 0x00]).read_any().is_err());
        assert!(Reader::new(&[0x04, 0x82, 0x00, 0x80]).read_any().is_err());
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00]).read_any().is_err());
        assert!(Reader::new(&[0x04, 0x02, 0x00]).read_any().is_err());
        assert!(Reader::new(&[0x1f, 0x01, 0x00]).read_any().is_err());
    }

    #[test]
    fn integers_must_be_minimal_and_non_negative() {
        assert_eq!(parse_uint_content(&[0x00]), Ok(&[0x00][..]));
        assert_eq!(parse_uint_content(&[0x00, 0x80]), Ok(&[0x80][..]));
        assert_eq!(parse_uint_content(&[0x7f]), Ok(&[0x7f][..]));
        assert!(parse_uint_content(&[]).is_err());
        assert!(parse_uint_content(&[0x80]).is_err());
        assert!(parse_uint_content(&[0x00, 0x7f]).is_err());
        assert_eq!(uint_content(&[0x00, 0x00, 0x80]), [0x00, 0x80]);
        assert_eq!(uint_content(&[0x00, 0x00]), [0x00]);
    }
}
