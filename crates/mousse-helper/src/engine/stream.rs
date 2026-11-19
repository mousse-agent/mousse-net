//! Messages on engine-owned streams (labels starting `mousse-`): each is a
//! `u32` big-endian length, then that many bytes of canonical CBOR, at most
//! [`MESSAGE_MAX`] bytes (fixed: the other side relies on it).

use std::time::Duration;

use mousse_net_core::ErrorCode;
use mousse_net_io::{NetError, StreamReader, StreamWriter};

/// Largest engine-stream message, in bytes (fixed).
pub const MESSAGE_MAX: usize = 262_144;

/// Why reading a message failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The length is above [`MESSAGE_MAX`], or the stream ended inside a
    /// message.
    Malformed,
    /// The peer reset the stream, or the connection closed.
    Gone,
    /// Nothing complete arrived in time.
    Timeout,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReadError::Malformed => "malformed engine-stream message",
            ReadError::Gone => "the stream ended",
            ReadError::Timeout => "no message in time",
        })
    }
}

/// Reads whole messages from a stream.
pub struct MessageReader {
    reader: StreamReader,
    buf: Vec<u8>,
    ended: bool,
}

impl MessageReader {
    /// Read messages from `reader`.
    pub fn new(reader: StreamReader) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            ended: false,
        }
    }

    fn take(&mut self) -> Result<Option<Vec<u8>>, ReadError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MESSAGE_MAX {
            return Err(ReadError::Malformed);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let message = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(message))
    }

    /// The next message; `Ok(None)` when the peer finished its side
    /// cleanly between messages.
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, ReadError> {
        loop {
            if let Some(message) = self.take()? {
                return Ok(Some(message));
            }
            if self.ended {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ReadError::Malformed)
                };
            }
            match self.reader.read().await {
                // A declared length above the maximum is refused by
                // `take` before more is read, so the buffer stays below one
                // message plus one chunk.
                Ok(Some(chunk)) => self.buf.extend_from_slice(&chunk),
                Ok(None) => self.ended = true,
                Err(_) => return Err(ReadError::Gone),
            }
        }
    }

    /// [`MessageReader::next`] within `wait`.
    pub async fn next_within(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, ReadError> {
        match tokio::time::timeout(wait, self.next()).await {
            Ok(result) => result,
            Err(_) => Err(ReadError::Timeout),
        }
    }
}

/// Write one message.
pub async fn write(writer: &StreamWriter, message: &[u8]) -> Result<(), NetError> {
    if message.len() > MESSAGE_MAX {
        writer.reset(ErrorCode::InternalError);
        return Err(NetError::Refused("engine-stream message too large".into()));
    }
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    writer.write(&framed).await
}
