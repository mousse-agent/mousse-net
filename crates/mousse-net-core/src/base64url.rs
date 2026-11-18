//! Strict base64url without padding (RFC 4648 §5), for ticket fragments.
//!
//! The decoder rejects padding, characters outside the URL-safe alphabet,
//! a length of 1 mod 4, and non-zero unused bits in the last character, so
//! each byte string has exactly one accepted text form.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Base64Error;

pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

fn value(c: u8) -> Result<u32, Base64Error> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return Err(Base64Error),
    };
    Ok(u32::from(v))
}

pub(crate) fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Base64Error);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        // Unused low bits of a partial chunk must be zero.
        let unused_mask = match produced {
            1 => 0x00ff_ffff >> 8,
            2 => 0x0000_00ff,
            _ => 0,
        };
        if n & unused_mask != 0 {
            return Err(Base64Error);
        }
        let all = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&all[..produced]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn rfc4648_vectors_without_padding() {
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn padding_bad_characters_and_dirty_bits_are_rejected() {
        assert!(decode("Zg==").is_err());
        assert!(decode("Zm9v+").is_err());
        assert!(decode("Zm9v/A").is_err());
        assert!(decode("Z").is_err());
        assert!(decode("Zh").is_err()); // "Zg" with a non-zero unused bit
        assert!(decode("Zm9").is_err()); // "Zm8" with a non-zero unused bit
    }
}
