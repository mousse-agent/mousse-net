//! A tiny canonical CBOR (RFC 8949) subset for Mousse records.
//!
//! Supported items: unsigned integers (major type 0), byte strings (2), text
//! strings (3), arrays (4) and maps (5) whose keys are unsigned integers.
//! Everything else (negative integers, tags, floats, simple values) is
//! rejected.
//!
//! Encoding is deterministic (RFC 8949 §4.2.1 core rules):
//! - every integer, length and count uses the shortest form;
//! - lengths are always definite;
//! - map keys are unsigned integers in strictly ascending order, which is the
//!   same as bytewise order of their shortest encodings.
//!
//! The decoder accepts only that form. Anything else is an error, so a record
//! has exactly one valid byte encoding.

use std::fmt;

/// Maximum nesting depth the decoder accepts.
pub const MAX_DEPTH: usize = 8;

/// A decoded CBOR item from the supported subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3 (valid UTF-8).
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5 with unsigned integer keys, ascending.
    Map(Vec<(u64, Value)>),
}

/// Why CBOR input was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// Input ended inside an item.
    Truncated,
    /// Bytes remain after the top-level item.
    TrailingBytes,
    /// An integer, length or count is not in its shortest form, or a length
    /// is indefinite.
    NonCanonical,
    /// Map keys are not strictly ascending (includes duplicates).
    UnsortedKeys,
    /// A map key is not an unsigned integer.
    NonIntegerKey,
    /// A major type or simple value outside the subset.
    Unsupported,
    /// A text string is not valid UTF-8.
    InvalidUtf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl CborError {
    /// Stable snake_case name, used in test vectors.
    pub const fn code(self) -> &'static str {
        match self {
            CborError::Truncated => "truncated",
            CborError::TrailingBytes => "trailing_bytes",
            CborError::NonCanonical => "non_canonical",
            CborError::UnsortedKeys => "unsorted_keys",
            CborError::NonIntegerKey => "non_integer_key",
            CborError::Unsupported => "unsupported",
            CborError::InvalidUtf8 => "invalid_utf8",
            CborError::TooDeep => "too_deep",
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CborError::Truncated => "truncated CBOR",
            CborError::TrailingBytes => "trailing bytes after CBOR item",
            CborError::NonCanonical => "non-canonical CBOR encoding",
            CborError::UnsortedKeys => "CBOR map keys not strictly ascending",
            CborError::NonIntegerKey => "CBOR map key is not an unsigned integer",
            CborError::Unsupported => "unsupported CBOR item",
            CborError::InvalidUtf8 => "CBOR text is not UTF-8",
            CborError::TooDeep => "CBOR nesting too deep",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CborError {}

/// Encode `value` canonically. Map entries are written in ascending key
/// order regardless of the order in `value`.
///
/// # Panics
/// Panics if a map has a duplicate key. Maps are built by our own code, so a
/// duplicate is a programming error, never untrusted input.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Bytes(bytes) => {
            write_head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            write_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            let mut sorted: Vec<&(u64, Value)> = entries.iter().collect();
            sorted.sort_by_key(|(key, _)| *key);
            for pair in sorted.windows(2) {
                assert!(
                    pair[0].0 != pair[1].0,
                    "duplicate CBOR map key {}",
                    pair[0].0
                );
            }
            write_head(out, 5, sorted.len() as u64);
            for (key, item) in sorted {
                write_head(out, 0, *key);
                encode_into(item, out);
            }
        }
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Decode exactly one canonical item from `input`.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    let mut decoder = Decoder { input, pos: 0 };
    let value = decoder.item(0)?;
    if decoder.pos != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.input.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: u64) -> Result<&[u8], CborError> {
        let remaining = self.input.len() - self.pos;
        let len = usize::try_from(len).map_err(|_| CborError::Truncated)?;
        if len > remaining {
            return Err(CborError::Truncated);
        }
        let slice = &self.input[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Read a head; returns (major type, argument). Enforces shortest form.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let n = match info {
            0..=23 => u64::from(info),
            24 => {
                let n = u64::from(self.byte()?);
                if n < 24 {
                    return Err(CborError::NonCanonical);
                }
                n
            }
            25 => {
                let b = self.take(2)?;
                let n = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if n <= 0xff {
                    return Err(CborError::NonCanonical);
                }
                n
            }
            26 => {
                let b = self.take(4)?;
                let n = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if n <= 0xffff {
                    return Err(CborError::NonCanonical);
                }
                n
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let n = u64::from_be_bytes(a);
                if n <= 0xffff_ffff {
                    return Err(CborError::NonCanonical);
                }
                n
            }
            31 => return Err(CborError::NonCanonical),
            _ => return Err(CborError::Unsupported),
        };
        Ok((major, n))
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let start = self.pos;
        let first = *self.input.get(start).ok_or(CborError::Truncated)?;
        let major = first >> 5;
        if !matches!(major, 0 | 2 | 3 | 4 | 5) {
            return Err(CborError::Unsupported);
        }
        let (major, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            2 => Ok(Value::Bytes(self.take(n)?.to_vec())),
            3 => {
                let bytes = self.take(n)?;
                let text = std::str::from_utf8(bytes).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                // Every item is at least one byte, which bounds the allocation.
                if n > (self.input.len() - self.pos) as u64 {
                    return Err(CborError::Truncated);
                }
                let mut items = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if n > ((self.input.len() - self.pos) / 2) as u64 {
                    return Err(CborError::Truncated);
                }
                let mut entries: Vec<(u64, Value)> = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let key_first = *self.input.get(self.pos).ok_or(CborError::Truncated)?;
                    if key_first >> 5 != 0 {
                        return Err(CborError::NonIntegerKey);
                    }
                    let (_, key) = self.head()?;
                    if let Some((last, _)) = entries.last() {
                        if key <= *last {
                            return Err(CborError::UnsortedKeys);
                        }
                    }
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CborError::Unsupported),
        }
    }
}

/// Why a decoded record did not have the expected fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    /// The bytes are not canonical CBOR.
    Cbor(CborError),
    /// The top-level item is not a map.
    NotAMap,
    /// A required key is missing.
    Missing(u64),
    /// A key the record does not define.
    Unknown(u64),
    /// A field has the wrong CBOR type.
    WrongType(u64),
    /// A field has the right type but an invalid value (length, range).
    Invalid(u64),
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldError::Cbor(e) => write!(f, "{e}"),
            FieldError::NotAMap => f.write_str("record is not a CBOR map"),
            FieldError::Missing(k) => write!(f, "record field {k} is missing"),
            FieldError::Unknown(k) => write!(f, "record field {k} is not defined"),
            FieldError::WrongType(k) => write!(f, "record field {k} has the wrong type"),
            FieldError::Invalid(k) => write!(f, "record field {k} has an invalid value"),
        }
    }
}

impl std::error::Error for FieldError {}

impl From<CborError> for FieldError {
    fn from(e: CborError) -> Self {
        FieldError::Cbor(e)
    }
}

/// Typed access to the fields of a decoded map. Call [`Fields::finish`]
/// last: it rejects any key that was not taken.
pub struct Fields {
    entries: Vec<(u64, Option<Value>)>,
}

impl Fields {
    /// Decode `input` and require a top-level map.
    pub fn decode(input: &[u8]) -> Result<Self, FieldError> {
        Self::from_value(decode(input)?)
    }

    /// Wrap an already decoded map.
    pub fn from_value(value: Value) -> Result<Self, FieldError> {
        match value {
            Value::Map(entries) => Ok(Self {
                entries: entries.into_iter().map(|(k, v)| (k, Some(v))).collect(),
            }),
            _ => Err(FieldError::NotAMap),
        }
    }

    fn take_value(&mut self, key: u64) -> Option<Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| *k == key)
            .and_then(|(_, v)| v.take())
    }

    /// A required field, any type.
    pub fn required(&mut self, key: u64) -> Result<Value, FieldError> {
        self.take_value(key).ok_or(FieldError::Missing(key))
    }

    /// An optional field, any type.
    pub fn optional(&mut self, key: u64) -> Option<Value> {
        self.take_value(key)
    }

    /// A required unsigned integer.
    pub fn uint(&mut self, key: u64) -> Result<u64, FieldError> {
        match self.required(key)? {
            Value::Uint(n) => Ok(n),
            _ => Err(FieldError::WrongType(key)),
        }
    }

    /// A required byte string.
    pub fn bytes(&mut self, key: u64) -> Result<Vec<u8>, FieldError> {
        match self.required(key)? {
            Value::Bytes(b) => Ok(b),
            _ => Err(FieldError::WrongType(key)),
        }
    }

    /// A required byte string of exactly `N` bytes.
    pub fn fixed<const N: usize>(&mut self, key: u64) -> Result<[u8; N], FieldError> {
        let bytes = self.bytes(key)?;
        <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| FieldError::Invalid(key))
    }

    /// A required text string.
    pub fn text(&mut self, key: u64) -> Result<String, FieldError> {
        match self.required(key)? {
            Value::Text(t) => Ok(t),
            _ => Err(FieldError::WrongType(key)),
        }
    }

    /// A required array.
    pub fn array(&mut self, key: u64) -> Result<Vec<Value>, FieldError> {
        match self.required(key)? {
            Value::Array(a) => Ok(a),
            _ => Err(FieldError::WrongType(key)),
        }
    }

    /// Reject any field that was not taken.
    pub fn finish(self) -> Result<(), FieldError> {
        match self.entries.iter().find(|(_, v)| v.is_some()) {
            Some((k, _)) => Err(FieldError::Unknown(*k)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn round_trip(value: Value) {
        let bytes = encode(&value);
        assert_eq!(decode(&bytes), Ok(value));
    }

    #[test]
    fn integers_use_the_shortest_head_at_every_boundary() {
        let cases: [(u64, &[u8]); 9] = [
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65_535, &[0x19, 0xff, 0xff]),
            (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (4_294_967_295, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (4_294_967_296, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        ];
        for (n, bytes) in cases {
            assert_eq!(encode(&Value::Uint(n)), bytes, "encoding {n}");
            assert_eq!(decode(bytes), Ok(Value::Uint(n)));
        }
    }

    #[test]
    fn longer_than_needed_heads_are_rejected() {
        for bytes in [
            &[0x18, 0x17][..],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x58, 0x01, 0xaa],
        ] {
            assert_eq!(decode(bytes), Err(CborError::NonCanonical), "{bytes:02x?}");
        }
    }

    #[test]
    fn indefinite_lengths_and_unsupported_types_are_rejected() {
        assert_eq!(
            decode(&[0x5f, 0x41, 0x00, 0xff]),
            Err(CborError::NonCanonical)
        );
        assert_eq!(decode(&[0x9f, 0xff]), Err(CborError::NonCanonical));
        assert_eq!(decode(&[0x20]), Err(CborError::Unsupported)); // -1
        assert_eq!(decode(&[0xc0, 0x00]), Err(CborError::Unsupported)); // tag
        assert_eq!(decode(&[0xf5]), Err(CborError::Unsupported)); // true
        assert_eq!(decode(&[0x1c]), Err(CborError::Unsupported)); // reserved info
    }

    #[test]
    fn map_keys_must_be_strictly_ascending_unsigned_integers() {
        assert_eq!(
            decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
            Err(CborError::UnsortedKeys)
        );
        assert_eq!(
            decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]),
            Err(CborError::UnsortedKeys)
        );
        assert_eq!(
            decode(&[0xa1, 0x61, 0x61, 0x00]),
            Err(CborError::NonIntegerKey)
        );
        assert_eq!(
            decode(&[0xa2, 0x01, 0x00, 0x02, 0x00]),
            Ok(Value::Map(vec![(1, Value::Uint(0)), (2, Value::Uint(0))]))
        );
    }

    #[test]
    fn encoder_sorts_map_keys() {
        let value = Value::Map(vec![(5, Value::Uint(1)), (1, Value::Uint(2))]);
        assert_eq!(encode(&value), [0xa2, 0x01, 0x02, 0x05, 0x01]);
    }

    #[test]
    fn truncation_trailing_bytes_and_bad_utf8_are_rejected() {
        assert_eq!(decode(&[]), Err(CborError::Truncated));
        assert_eq!(decode(&[0x42, 0x00]), Err(CborError::Truncated));
        assert_eq!(decode(&[0x00, 0x00]), Err(CborError::TrailingBytes));
        assert_eq!(decode(&[0x62, 0xc3, 0x28]), Err(CborError::InvalidUtf8));
        // A huge claimed array count must not allocate.
        assert_eq!(
            decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(CborError::Truncated)
        );
    }

    #[test]
    fn nesting_is_bounded() {
        let mut bytes = vec![0x81; MAX_DEPTH + 1];
        bytes.push(0x00);
        assert_eq!(decode(&bytes), Err(CborError::TooDeep));
        let mut ok = vec![0x81; MAX_DEPTH];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn nested_values_round_trip() {
        round_trip(Value::Map(vec![
            (1, Value::Text("héllo".into())),
            (2, Value::Bytes(vec![0; 300])),
            (
                3,
                Value::Array(vec![Value::Uint(70_000), Value::Text(String::new())]),
            ),
        ]));
    }

    #[test]
    fn fields_reject_unknown_and_missing_keys() {
        let bytes = encode(&Value::Map(vec![(1, Value::Uint(7)), (9, Value::Uint(0))]));
        let mut fields = Fields::decode(&bytes).unwrap();
        assert_eq!(fields.uint(1), Ok(7));
        assert_eq!(fields.uint(2), Err(FieldError::Missing(2)));
        assert_eq!(fields.finish(), Err(FieldError::Unknown(9)));
    }
}
