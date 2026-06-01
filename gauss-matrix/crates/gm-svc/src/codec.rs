// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A small, dependency-free length-prefixed codec for persisting a [`Pdu`] as
//! opaque bytes in the store.
//!
//! Strings are length-prefixed (`u32` LE + bytes), so event content can hold
//! any byte including the separators the audit log uses — no escaping, no
//! collisions. Decoding re-validates every identifier through `gm-util`, so a
//! corrupt or tampered record is rejected rather than trusted. The production
//! build uses the same serde/CBOR encoding the rest of the server moves to.

use gm_api::Pdu;
use gm_util::{EventId, RoomId, UserId};

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

/// Encode a PDU to bytes.
pub fn encode(pdu: &Pdu) -> Vec<u8> {
    let mut out = Vec::new();
    put_str(&mut out, pdu.event_id.as_str());
    put_str(&mut out, pdu.room_id.as_str());
    put_str(&mut out, pdu.sender.as_str());
    put_str(&mut out, &pdu.kind);
    match &pdu.state_key {
        Some(key) => {
            out.push(1);
            put_str(&mut out, key);
        }
        None => out.push(0),
    }
    put_u64(&mut out, pdu.origin_server_ts);
    put_u64(&mut out, pdu.depth);
    out.extend_from_slice(&(pdu.prev_events.len() as u32).to_le_bytes());
    for e in &pdu.prev_events {
        put_str(&mut out, e.as_str());
    }
    out.extend_from_slice(&(pdu.auth_events.len() as u32).to_le_bytes());
    for e in &pdu.auth_events {
        put_str(&mut out, e.as_str());
    }
    put_str(&mut out, &pdu.content_json);
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
}

/// Decode a PDU from bytes, re-validating every identifier. Returns `None` on a
/// truncated, malformed, or invalid record.
pub fn decode(bytes: &[u8]) -> Option<Pdu> {
    let mut r = Reader::new(bytes);
    let event_id = EventId::parse(r.string()?).ok()?;
    let room_id = RoomId::parse(r.string()?).ok()?;
    let sender = UserId::parse(r.string()?).ok()?;
    let kind = r.string()?;
    let state_key = match r.byte()? {
        1 => Some(r.string()?),
        0 => None,
        _ => return None,
    };
    let origin_server_ts = r.u64()?;
    let depth = r.u64()?;
    let prev_count = r.u32()? as usize;
    let mut prev_events = Vec::with_capacity(prev_count);
    for _ in 0..prev_count {
        prev_events.push(EventId::parse(r.string()?).ok()?);
    }
    let auth_count = r.u32()? as usize;
    let mut auth_events = Vec::with_capacity(auth_count);
    for _ in 0..auth_count {
        auth_events.push(EventId::parse(r.string()?).ok()?);
    }
    let content_json = r.string()?;
    Some(Pdu {
        event_id,
        room_id,
        sender,
        kind,
        state_key,
        origin_server_ts,
        depth,
        prev_events,
        auth_events,
        content_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_pdu_including_separator_bytes_in_content() {
        let pdu = Pdu {
            event_id: EventId::parse("$e1").unwrap(),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse("@a:gaussian.tech").unwrap(),
            kind: "m.room.message".to_owned(),
            state_key: None,
            origin_server_ts: 42,
            depth: 7,
            prev_events: vec![EventId::parse("$p1").unwrap()],
            auth_events: vec![
                EventId::parse("$a1").unwrap(),
                EventId::parse("$a2").unwrap(),
            ],
            // Content with a unit-separator byte and quotes — must survive.
            content_json: "{\"body\":\"x\u{1f}y\\\"z\"}".to_owned(),
        };
        assert_eq!(decode(&encode(&pdu)), Some(pdu));
    }

    #[test]
    fn rejects_truncated_or_malformed_bytes() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[1, 2, 3]), None);
    }
}
