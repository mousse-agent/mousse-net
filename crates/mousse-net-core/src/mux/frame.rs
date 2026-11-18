//! Mux frame codec.
//!
//! Every frame is a 9-byte header followed by `length` payload bytes:
//!
//! ```text
//! stream id : u32, big-endian
//! type      : u8
//! length    : u32, big-endian (payload bytes, at most 65536)
//! ```

use std::fmt;

use crate::cbor::{self, Fields, Value};
use crate::ErrorCode;

/// Header length in bytes.
pub const HEADER_LEN: usize = 9;

/// Largest payload of any frame, in bytes.
pub const MAX_PAYLOAD: usize = 65_536;

/// Largest `CONTROL` payload, in bytes.
pub const MAX_CONTROL_PAYLOAD: usize = 16_384;

/// Largest `OPEN` payload, in bytes.
pub const MAX_OPEN_PAYLOAD: usize = 256;

/// Longest stream label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// A stream id. 0 is the control stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u32);

impl StreamId {
    /// The control stream.
    pub const CONTROL: StreamId = StreamId(0);
}

/// A stream's priority class. Interactive is always sent before bulk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PriorityClass {
    /// Typing, terminal output, RPC.
    Interactive = 0,
    /// File copies and other large transfers.
    Bulk = 1,
}

/// Frame type numbers.
pub mod frame_type {
    /// Stream bytes.
    pub const DATA: u8 = 0x0;
    /// Open a stream.
    pub const OPEN: u8 = 0x1;
    /// Add send credit.
    pub const CREDIT: u8 = 0x2;
    /// The sender finished sending on a stream.
    pub const FIN: u8 = 0x3;
    /// Abort a stream in both directions.
    pub const RESET: u8 = 0x4;
    /// Keepalive probe.
    pub const PING: u8 = 0x5;
    /// Keepalive answer.
    pub const PONG: u8 = 0x6;
    /// Control message.
    pub const CONTROL: u8 = 0x7;
    /// Close the connection.
    pub const GOAWAY: u8 = 0x8;
}

/// One frame.
#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    /// Stream bytes (1 to 65536).
    Data {
        /// Stream.
        stream: StreamId,
        /// Bytes.
        payload: Vec<u8>,
    },
    /// Open a stream with a class and a label.
    Open {
        /// Stream.
        stream: StreamId,
        /// Priority class.
        class: PriorityClass,
        /// Label naming the channel kind (1 to 64 bytes of UTF-8).
        label: String,
    },
    /// Grant `increment` more bytes of send credit on a stream.
    Credit {
        /// Stream.
        stream: StreamId,
        /// Bytes (at least 1).
        increment: u32,
    },
    /// The sender will send no more bytes on the stream.
    Fin {
        /// Stream.
        stream: StreamId,
    },
    /// Abort a stream.
    Reset {
        /// Stream.
        stream: StreamId,
        /// Why.
        code: ErrorCode,
    },
    /// Keepalive probe with 8 opaque bytes.
    Ping {
        /// Echoed in the `PONG`.
        opaque: [u8; 8],
    },
    /// Keepalive answer.
    Pong {
        /// Copied from the `PING`.
        opaque: [u8; 8],
    },
    /// A control message (canonical CBOR).
    Control {
        /// Encoded [`crate::control::ControlMessage`].
        payload: Vec<u8>,
    },
    /// The sender is closing the connection.
    GoAway {
        /// Why.
        code: ErrorCode,
    },
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Frame::Data { stream, payload } => {
                write!(f, "Data({}, {} bytes)", stream.0, payload.len())
            }
            Frame::Open {
                stream,
                class,
                label,
            } => write!(f, "Open({}, {class:?}, {label:?})", stream.0),
            Frame::Credit { stream, increment } => write!(f, "Credit({}, {increment})", stream.0),
            Frame::Fin { stream } => write!(f, "Fin({})", stream.0),
            Frame::Reset { stream, code } => write!(f, "Reset({}, {code:?})", stream.0),
            Frame::Ping { .. } => f.write_str("Ping"),
            Frame::Pong { .. } => f.write_str("Pong"),
            Frame::Control { payload } => write!(f, "Control({} bytes)", payload.len()),
            Frame::GoAway { code } => write!(f, "GoAway({code:?})"),
        }
    }
}

/// Why a frame was rejected. Every frame error closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// `length` is above the limit for any frame or for its type.
    TooLarge,
    /// Unknown frame type.
    UnknownType(u8),
    /// The stream id is not allowed for this type (0 vs non-zero).
    BadStream,
    /// The payload has the wrong size or content for its type.
    BadPayload,
}

impl FrameError {
    /// The connection error code to send in `GOAWAY`.
    pub fn code(self) -> ErrorCode {
        match self {
            FrameError::TooLarge => ErrorCode::FrameTooLarge,
            _ => ErrorCode::ProtocolError,
        }
    }

    /// Stable snake_case name, used in test vectors.
    pub fn name(self) -> &'static str {
        match self {
            FrameError::TooLarge => "too_large",
            FrameError::UnknownType(_) => "unknown_type",
            FrameError::BadStream => "bad_stream",
            FrameError::BadPayload => "bad_payload",
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad mux frame: {}", self.name())
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// The frame's stream id.
    pub fn stream(&self) -> StreamId {
        match self {
            Frame::Data { stream, .. }
            | Frame::Open { stream, .. }
            | Frame::Credit { stream, .. }
            | Frame::Fin { stream }
            | Frame::Reset { stream, .. } => *stream,
            _ => StreamId::CONTROL,
        }
    }

    /// Append the encoded frame to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let (kind, payload): (u8, Vec<u8>) = match self {
            Frame::Data { payload, .. } => (frame_type::DATA, payload.clone()),
            Frame::Open { class, label, .. } => (
                frame_type::OPEN,
                cbor::encode(&Value::Map(vec![
                    (1, Value::Uint(*class as u64)),
                    (2, Value::Text(label.clone())),
                ])),
            ),
            Frame::Credit { increment, .. } => {
                (frame_type::CREDIT, increment.to_be_bytes().to_vec())
            }
            Frame::Fin { .. } => (frame_type::FIN, Vec::new()),
            Frame::Reset { code, .. } => (frame_type::RESET, code.as_u16().to_be_bytes().to_vec()),
            Frame::Ping { opaque } => (frame_type::PING, opaque.to_vec()),
            Frame::Pong { opaque } => (frame_type::PONG, opaque.to_vec()),
            Frame::Control { payload } => (frame_type::CONTROL, payload.clone()),
            Frame::GoAway { code } => (frame_type::GOAWAY, code.as_u16().to_be_bytes().to_vec()),
        };
        out.extend_from_slice(&self.stream().0.to_be_bytes());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
    }

    /// The encoded frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
}

/// Parse one frame from the front of `input`.
///
/// Returns `Ok(None)` if more bytes are needed, `Ok(Some((frame, used)))` on
/// success. A header whose length is over the limit is rejected as soon as
/// the 9 header bytes are present, before any payload is buffered.
pub fn decode(input: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    if input.len() < HEADER_LEN {
        return Ok(None);
    }
    let stream = StreamId(u32::from_be_bytes([input[0], input[1], input[2], input[3]]));
    let kind = input[4];
    let len = u32::from_be_bytes([input[5], input[6], input[7], input[8]]) as usize;
    if kind > frame_type::GOAWAY {
        return Err(FrameError::UnknownType(kind));
    }
    let type_limit = match kind {
        frame_type::CONTROL => MAX_CONTROL_PAYLOAD,
        frame_type::OPEN => MAX_OPEN_PAYLOAD,
        _ => MAX_PAYLOAD,
    };
    if len > type_limit {
        return Err(FrameError::TooLarge);
    }
    let control_only = matches!(
        kind,
        frame_type::PING | frame_type::PONG | frame_type::CONTROL | frame_type::GOAWAY
    );
    if control_only != (stream == StreamId::CONTROL) {
        return Err(FrameError::BadStream);
    }
    let Some(payload) = input.get(HEADER_LEN..HEADER_LEN + len) else {
        return Ok(None);
    };
    let frame = match kind {
        frame_type::DATA => {
            if payload.is_empty() {
                return Err(FrameError::BadPayload);
            }
            Frame::Data {
                stream,
                payload: payload.to_vec(),
            }
        }
        frame_type::OPEN => {
            let mut f = Fields::decode(payload).map_err(|_| FrameError::BadPayload)?;
            let class = match f.uint(1).map_err(|_| FrameError::BadPayload)? {
                0 => PriorityClass::Interactive,
                1 => PriorityClass::Bulk,
                _ => return Err(FrameError::BadPayload),
            };
            let label = f.text(2).map_err(|_| FrameError::BadPayload)?;
            f.finish().map_err(|_| FrameError::BadPayload)?;
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(FrameError::BadPayload);
            }
            Frame::Open {
                stream,
                class,
                label,
            }
        }
        frame_type::CREDIT => {
            let bytes: [u8; 4] = payload.try_into().map_err(|_| FrameError::BadPayload)?;
            let increment = u32::from_be_bytes(bytes);
            if increment == 0 {
                return Err(FrameError::BadPayload);
            }
            Frame::Credit { stream, increment }
        }
        frame_type::FIN => {
            if !payload.is_empty() {
                return Err(FrameError::BadPayload);
            }
            Frame::Fin { stream }
        }
        frame_type::RESET | frame_type::GOAWAY => {
            let bytes: [u8; 2] = payload.try_into().map_err(|_| FrameError::BadPayload)?;
            // Unknown codes are kept as INTERNAL_ERROR for display; the frame
            // itself is still valid.
            let code =
                ErrorCode::from_u16(u16::from_be_bytes(bytes)).unwrap_or(ErrorCode::InternalError);
            if kind == frame_type::RESET {
                Frame::Reset { stream, code }
            } else {
                Frame::GoAway { code }
            }
        }
        frame_type::PING | frame_type::PONG => {
            let opaque: [u8; 8] = payload.try_into().map_err(|_| FrameError::BadPayload)?;
            if kind == frame_type::PING {
                Frame::Ping { opaque }
            } else {
                Frame::Pong { opaque }
            }
        }
        frame_type::CONTROL => {
            if payload.is_empty() {
                return Err(FrameError::BadPayload);
            }
            Frame::Control {
                payload: payload.to_vec(),
            }
        }
        other => return Err(FrameError::UnknownType(other)),
    };
    Ok(Some((frame, HEADER_LEN + len)))
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn every_frame() -> Vec<Frame> {
        vec![
            Frame::Data {
                stream: StreamId(1),
                payload: b"hi".to_vec(),
            },
            Frame::Open {
                stream: StreamId(3),
                class: PriorityClass::Bulk,
                label: "file".into(),
            },
            Frame::Credit {
                stream: StreamId(1),
                increment: 65_536,
            },
            Frame::Fin {
                stream: StreamId(1),
            },
            Frame::Reset {
                stream: StreamId(2),
                code: ErrorCode::Cancelled,
            },
            Frame::Ping { opaque: [1; 8] },
            Frame::Pong { opaque: [1; 8] },
            Frame::Control {
                payload: vec![0xa0],
            },
            Frame::GoAway {
                code: ErrorCode::IdleTimeout,
            },
        ]
    }

    #[test]
    fn every_frame_round_trips_and_needs_all_its_bytes() {
        for frame in every_frame() {
            let bytes = frame.encode();
            assert_eq!(decode(&bytes), Ok(Some((frame.clone(), bytes.len()))));
            assert_eq!(decode(&bytes[..bytes.len() - 1]), Ok(None), "{frame:?}");
        }
    }

    #[test]
    fn oversize_length_is_rejected_from_the_header_alone() {
        let mut header = vec![0, 0, 0, 1, frame_type::DATA];
        header.extend_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        assert_eq!(decode(&header), Err(FrameError::TooLarge));
        let mut control = vec![0, 0, 0, 0, frame_type::CONTROL];
        control.extend_from_slice(&(MAX_CONTROL_PAYLOAD as u32 + 1).to_be_bytes());
        assert_eq!(decode(&control), Err(FrameError::TooLarge));
    }

    #[test]
    fn stream_zero_rules_are_enforced() {
        let ping_on_stream = [
            0,
            0,
            0,
            1,
            frame_type::PING,
            0,
            0,
            0,
            8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(decode(&ping_on_stream), Err(FrameError::BadStream));
        let data_on_control = [0, 0, 0, 0, frame_type::DATA, 0, 0, 0, 1, 7];
        assert_eq!(decode(&data_on_control), Err(FrameError::BadStream));
    }

    #[test]
    fn bad_payloads_and_unknown_types_are_rejected() {
        assert_eq!(
            decode(&[0, 0, 0, 1, 9, 0, 0, 0, 0]),
            Err(FrameError::UnknownType(9))
        );
        assert_eq!(
            decode(&[0, 0, 0, 1, frame_type::DATA, 0, 0, 0, 0]),
            Err(FrameError::BadPayload)
        );
        assert_eq!(
            decode(&[0, 0, 0, 1, frame_type::CREDIT, 0, 0, 0, 4, 0, 0, 0, 0]),
            Err(FrameError::BadPayload)
        );
        assert_eq!(
            decode(&[0, 0, 0, 1, frame_type::FIN, 0, 0, 0, 1, 0]),
            Err(FrameError::BadPayload)
        );
    }
}
