//! Engine stream messages, as the app frames them on a helper stream:
//! `u32 BE header length | JSON header | binary parts`, the header listing
//! each part's length in `parts`. The editor tunnel's first messages are
//! v1's tunnel messages (`tunnel.open`, then `tunnel.ready` or
//! `tunnel.close`).

use serde_json::{json, Value};

/// `tunnel.open` for an ssh tunnel with a fresh id.
pub fn open_message() -> Vec<u8> {
    let id = mousse_net_io::store::hex(&mousse_net_io::rng::random_bytes::<16>());
    encode(&json!({"t": "tunnel.open", "tunnel": id, "kind": "ssh"}))
}

pub fn encode(header: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(header).expect("a JSON value encodes");
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// The first message's header, once all of it (and its parts) arrived.
pub fn first(buf: &[u8]) -> Option<Value> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let header: Value = serde_json::from_slice(buf.get(4..4 + len)?).ok()?;
    let parts: usize = header
        .get("parts")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).sum::<u64>() as usize)
        .unwrap_or(0);
    (buf.len() >= 4 + len + parts).then_some(header)
}

/// Whether `buf` holds at least one whole message.
pub fn complete(buf: &[u8]) -> bool {
    first(buf).is_some()
}

/// A short word for the first message: `tunnel.close:<reason>`,
/// `tunnel.ready`, or what else it was.
pub fn word(buf: &[u8]) -> String {
    match first(buf) {
        None if buf.is_empty() => "nothing".into(),
        None => "unreadable".into(),
        Some(h) => {
            let t = h.get("t").and_then(Value::as_str).unwrap_or("?");
            match h.get("reason").and_then(Value::as_str) {
                Some(r) => format!("{t}:{r}"),
                None => t.to_owned(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_reads_back_once_its_parts_are_in() {
        let msg = encode(&json!({"t": "tunnel.close", "tunnel": "ab", "reason": "editor_off"}));
        assert!(!complete(&msg[..msg.len() - 1]));
        assert_eq!(word(&msg), "tunnel.close:editor_off");
        let with_part = encode(&json!({"t": "x", "parts": [3]}));
        assert!(!complete(&with_part));
        let mut whole = with_part.clone();
        whole.extend_from_slice(b"abc");
        assert_eq!(word(&whole), "x");
    }
}
