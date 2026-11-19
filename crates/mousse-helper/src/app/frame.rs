//! App channel framing (Phase 1a §2.1).
//!
//! Each frame is `u32 BE length | u8 type | body`. The length counts the
//! type byte and the body, and is at most 1 MiB.
//!
//! - `0x01` JSON: one UTF-8 JSON object.
//! - `0x02` DATA: `u32 BE handle | u8 flags | bytes`, at most 64 KiB of
//!   bytes. Flag `0x01` is FIN; the other bits must be zero. FIN may come
//!   with no bytes.
//! - `0x03` CREDIT: `u32 BE handle | u32 BE bytes`, bytes at least 1.
//!
//! The sizes are protocol constants: both ends rely on them.

use serde_json::Value;

/// Largest length field: the type byte and the body.
pub const MAX_FRAME: usize = 1 << 20;
/// Most bytes in one DATA frame.
pub const MAX_DATA: usize = 1 << 16;
/// The length field.
const LEN: usize = 4;

/// Frame types.
pub const JSON: u8 = 0x01;
/// DATA frame type.
pub const DATA: u8 = 0x02;
/// CREDIT frame type.
pub const CREDIT: u8 = 0x03;
/// DATA flag: the stream's last frame in this direction.
pub const FIN: u8 = 0x01;

/// One decoded frame.
#[derive(Debug, PartialEq)]
pub enum Frame {
    /// A request, reply or event.
    Json(serde_json::Map<String, Value>),
    /// Stream bytes, maybe with FIN.
    Data {
        handle: u32,
        fin: bool,
        bytes: Vec<u8>,
    },
    /// More credit on a stream.
    Credit { handle: u32, bytes: u32 },
}

/// Why a frame is malformed. Any of these closes the channel.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The length is 0 or above [`MAX_FRAME`].
    BadLength(u32),
    /// Not one of the three types.
    UnknownType(u8),
    /// DATA too short, too long or with unknown flags.
    BadData,
    /// CREDIT not exactly 8 bytes, or 0 bytes of credit.
    BadCredit,
    /// JSON that is not one object.
    BadJson,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::BadLength(n) => write!(f, "frame length {n} is outside 1 to {MAX_FRAME}"),
            FrameError::UnknownType(t) => write!(f, "unknown frame type {t:#04x}"),
            FrameError::BadData => f.write_str("malformed DATA frame"),
            FrameError::BadCredit => f.write_str("malformed CREDIT frame"),
            FrameError::BadJson => f.write_str("a JSON frame must hold one JSON object"),
        }
    }
}

/// Decode the first frame in `buf`: `Ok(None)` until it is complete. The
/// length and type are checked as soon as they arrive, before the body.
pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    let Some(head) = buf.get(..LEN) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let n = len as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(FrameError::BadLength(len));
    }
    let Some(&kind) = buf.get(LEN) else {
        return Ok(None);
    };
    if !matches!(kind, JSON | DATA | CREDIT) {
        return Err(FrameError::UnknownType(kind));
    }
    if kind == DATA && n > 1 + 5 + MAX_DATA {
        return Err(FrameError::BadData);
    }
    if kind == CREDIT && n != 1 + 8 {
        return Err(FrameError::BadCredit);
    }
    let Some(body) = buf.get(LEN + 1..LEN + n) else {
        return Ok(None);
    };
    let frame = match kind {
        JSON => match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(map)) => Frame::Json(map),
            _ => return Err(FrameError::BadJson),
        },
        DATA => {
            if body.len() < 5 {
                return Err(FrameError::BadData);
            }
            let handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let flags = body[4];
            if flags & !FIN != 0 {
                return Err(FrameError::BadData);
            }
            Frame::Data {
                handle,
                fin: flags & FIN != 0,
                bytes: body[5..].to_vec(),
            }
        }
        _ => {
            let handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let bytes = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            if bytes == 0 {
                return Err(FrameError::BadCredit);
            }
            Frame::Credit { handle, bytes }
        }
    };
    Ok(Some((frame, LEN + n)))
}

fn with_header(kind: u8, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN + 1 + body_len);
    out.extend_from_slice(&((body_len + 1) as u32).to_be_bytes());
    out.push(kind);
    out
}

/// A JSON frame. A value that does not fit in a frame is replaced by an
/// error the other end can read.
pub fn json(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    if body.len() + 1 > MAX_FRAME {
        return json(&serde_json::json!({"ev": "error", "reason": "message too large"}));
    }
    let mut out = with_header(JSON, body.len());
    out.extend_from_slice(&body);
    out
}

/// A DATA frame; `bytes` is at most [`MAX_DATA`].
pub fn data(handle: u32, fin: bool, bytes: &[u8]) -> Vec<u8> {
    debug_assert!(bytes.len() <= MAX_DATA);
    let mut out = with_header(DATA, 5 + bytes.len());
    out.extend_from_slice(&handle.to_be_bytes());
    out.push(if fin { FIN } else { 0 });
    out.extend_from_slice(bytes);
    out
}

/// A CREDIT frame; `bytes` is at least 1.
pub fn credit(handle: u32, bytes: u32) -> Vec<u8> {
    let mut out = with_header(CREDIT, 8);
    out.extend_from_slice(&handle.to_be_bytes());
    out.extend_from_slice(&bytes.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json as j;

    #[test]
    fn frames_round_trip_and_wait_for_their_last_byte() {
        let mut stream = json(&j!({"id": 1, "op": "hello"}));
        stream.extend(data(7, false, b"abc"));
        stream.extend(data(7, true, b""));
        stream.extend(credit(9, 65_536));
        let mut at = 0;
        let mut got = Vec::new();
        while let Some((frame, used)) = decode(&stream[at..]).unwrap() {
            got.push(frame);
            at += used;
        }
        assert_eq!(at, stream.len());
        assert!(matches!(&got[0], Frame::Json(m) if m["op"] == "hello"));
        assert_eq!(
            got[1],
            Frame::Data {
                handle: 7,
                fin: false,
                bytes: b"abc".to_vec()
            }
        );
        assert_eq!(
            got[2],
            Frame::Data {
                handle: 7,
                fin: true,
                bytes: vec![]
            }
        );
        assert_eq!(
            got[3],
            Frame::Credit {
                handle: 9,
                bytes: 65_536
            }
        );
        let one = data(1, false, b"xyz");
        for cut in 0..one.len() {
            assert_eq!(decode(&one[..cut]), Ok(None), "cut at {cut}");
        }
    }

    #[test]
    fn malformed_frames_are_refused_from_the_header() {
        assert_eq!(decode(&[0, 0, 0, 0]), Err(FrameError::BadLength(0)));
        let big = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert_eq!(
            decode(&big),
            Err(FrameError::BadLength(MAX_FRAME as u32 + 1))
        );
        assert_eq!(decode(&[0, 0, 0, 1, 9]), Err(FrameError::UnknownType(9)));
        // DATA over 64 KiB, from the header alone.
        let n = (1 + 5 + MAX_DATA + 1) as u32;
        let mut over = n.to_be_bytes().to_vec();
        over.push(DATA);
        assert_eq!(decode(&over), Err(FrameError::BadData));
        // Unknown flag bits.
        let mut flags = data(1, false, b"x");
        flags[9] = 0x02;
        assert_eq!(decode(&flags), Err(FrameError::BadData));
        // CREDIT of zero, or of the wrong size.
        assert_eq!(decode(&credit(1, 0)), Err(FrameError::BadCredit));
        assert_eq!(decode(&[0, 0, 0, 2, CREDIT, 0]), Err(FrameError::BadCredit));
        // JSON that is not an object.
        let mut arr = with_header(JSON, 2);
        arr.extend_from_slice(b"[]");
        assert_eq!(decode(&arr), Err(FrameError::BadJson));
        assert_eq!(
            decode(&data(1, false, &[0; MAX_DATA])).unwrap().unwrap().1,
            4 + 1 + 5 + MAX_DATA
        );
    }
}
