// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The Persistent Data Unit (PDU) envelope — the event metadata the homeserver
//! authenticates and resolves over (spec §III.D, §III.E).
//!
//! State resolution, the auth-chain walk and federation reason about the
//! *envelope* — sender, type, state key, depth, and the `prev_events` /
//! `auth_events` DAG links — far more than the event content, which is carried
//! opaquely here (`content_json`) and typed by `ruma` in the production build.

use crate::json::Json;
use gm_util::{EventId, RoomId, UserId};
use std::collections::BTreeMap;
use std::fmt;

/// A persistent room event as the server stores and authenticates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// The event's identifier.
    pub event_id: EventId,
    /// The room the event belongs to.
    pub room_id: RoomId,
    /// The sender.
    pub sender: UserId,
    /// The event type (one of the `gm_api::events::*` constants, or another).
    pub kind: String,
    /// The state key, present iff this is a state event.
    pub state_key: Option<String>,
    /// Origin server timestamp (ms since the Unix epoch).
    pub origin_server_ts: u64,
    /// Depth in the room DAG.
    pub depth: u64,
    /// The events this one builds on (the DAG edges).
    pub prev_events: Vec<EventId>,
    /// The events authorising this one (the auth chain).
    pub auth_events: Vec<EventId>,
    /// The event content, carried opaquely as JSON at this layer.
    pub content_json: String,
}

impl Pdu {
    /// Whether this is a state event (has a state key).
    pub fn is_state(&self) -> bool {
        self.state_key.is_some()
    }

    /// The `(type, state_key)` pair that identifies a slot in room state, or
    /// `None` for non-state (message) events.
    pub fn state_tuple(&self) -> Option<(&str, &str)> {
        self.state_key
            .as_deref()
            .map(|state_key| (self.kind.as_str(), state_key))
    }

    /// The **content hash** of this event: unpadded base64 of the SHA-256 of the
    /// event's canonical JSON *without* `event_id`, `hashes`, `signatures` or
    /// `unsigned` (spec §III.D). It is published in the event's `hashes.sha256`
    /// and lets a peer verify the content even after the event is redacted.
    pub fn content_hash(&self) -> String {
        let canonical = Json::Object(self.unhashed()).to_string();
        gm_util::ed25519::base64_encode(&gm_util::hashing::sha256(canonical.as_bytes()))
    }

    /// The content-addressed **reference-hash event id** for this PDU at
    /// `room_version` (room version 3+): `$` + URL-safe unpadded base64 of the
    /// SHA-256 of the **redacted** event's canonical JSON (with `event_id`,
    /// `signatures` and `unsigned` removed). Redacting before hashing makes the
    /// id invariant under later redaction; the redacted event still carries the
    /// `hashes.sha256` content hash, so the id transitively binds the content.
    pub fn reference_id(&self, room_version: u8) -> String {
        let redacted = crate::redaction::redact(&self.to_json(), room_version);
        let mut obj = match redacted {
            Json::Object(map) => map,
            _ => BTreeMap::new(),
        };
        obj.remove("event_id");
        obj.remove("signatures");
        obj.remove("unsigned");
        let canonical = Json::Object(obj).to_string();
        gm_util::hashing::reference_id(canonical.as_bytes())
    }

    /// The event's fields used for the content hash: everything in [`Self::to_json`]
    /// except the derived `event_id` and `hashes`.
    fn unhashed(&self) -> BTreeMap<String, Json> {
        let mut obj = BTreeMap::new();
        obj.insert("room_id".into(), Json::String(self.room_id.as_str().into()));
        obj.insert("sender".into(), Json::String(self.sender.as_str().into()));
        obj.insert("type".into(), Json::String(self.kind.clone()));
        if let Some(state_key) = &self.state_key {
            obj.insert("state_key".into(), Json::String(state_key.clone()));
        }
        obj.insert(
            "origin_server_ts".into(),
            Json::Number(self.origin_server_ts as f64),
        );
        obj.insert("depth".into(), Json::Number(self.depth as f64));
        obj.insert("prev_events".into(), event_id_array(&self.prev_events));
        obj.insert("auth_events".into(), event_id_array(&self.auth_events));
        obj.insert(
            "content".into(),
            Json::parse(&self.content_json).unwrap_or_else(|_| Json::Object(BTreeMap::new())),
        );
        obj
    }

    /// Serialize this PDU to its Matrix JSON form (the shape federation sends and
    /// the event-storage / `/state` paths return). `content_json` is embedded as
    /// the parsed `content` object (an empty object if it does not parse), and a
    /// `hashes.sha256` content hash is attached.
    pub fn to_json(&self) -> Json {
        let mut obj = self.unhashed();
        obj.insert(
            "event_id".into(),
            Json::String(self.event_id.as_str().into()),
        );
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_owned(), Json::String(self.content_hash()));
        obj.insert("hashes".into(), Json::Object(hashes));
        Json::Object(obj)
    }

    /// Parse a PDU from its Matrix JSON form, re-validating every identifier
    /// (federated input is untrusted). `content` is re-serialized compactly into
    /// `content_json`; an absent `content` is treated as the empty object.
    pub fn from_json(value: &Json) -> Result<Self, PduError> {
        let event_id = parse_id(value, "event_id", EventId::parse)?;
        let room_id = parse_id(value, "room_id", RoomId::parse)?;
        let sender = parse_id(value, "sender", UserId::parse)?;
        let kind = str_field(value, "type")?.to_owned();
        let state_key = match value.get("state_key") {
            None => None,
            Some(Json::String(s)) => Some(s.clone()),
            Some(_) => return Err(PduError::InvalidField("state_key")),
        };
        let origin_server_ts = u64_field(value, "origin_server_ts")?;
        let depth = u64_field(value, "depth")?;
        let prev_events = parse_id_array(value, "prev_events")?;
        let auth_events = parse_id_array(value, "auth_events")?;
        let content_json = match value.get("content") {
            None => "{}".to_owned(),
            Some(content) => content.to_string(),
        };
        Ok(Pdu {
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
}

/// An error decoding a [`Pdu`] from JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present but malformed (wrong type or an invalid id).
    InvalidField(&'static str),
}

impl fmt::Display for PduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PduError::MissingField(k) => write!(f, "missing PDU field: {k}"),
            PduError::InvalidField(k) => write!(f, "invalid PDU field: {k}"),
        }
    }
}

impl std::error::Error for PduError {}

fn event_id_array(ids: &[EventId]) -> Json {
    Json::Array(
        ids.iter()
            .map(|e| Json::String(e.as_str().to_owned()))
            .collect(),
    )
}

fn str_field<'a>(value: &'a Json, key: &'static str) -> Result<&'a str, PduError> {
    value
        .get(key)
        .ok_or(PduError::MissingField(key))?
        .as_str()
        .ok_or(PduError::InvalidField(key))
}

fn u64_field(value: &Json, key: &'static str) -> Result<u64, PduError> {
    value
        .get(key)
        .ok_or(PduError::MissingField(key))?
        .as_u64()
        .ok_or(PduError::InvalidField(key))
}

fn parse_id<T, E>(
    value: &Json,
    key: &'static str,
    parse: impl Fn(String) -> Result<T, E>,
) -> Result<T, PduError> {
    let s = str_field(value, key)?;
    parse(s.to_owned()).map_err(|_| PduError::InvalidField(key))
}

fn parse_id_array(value: &Json, key: &'static str) -> Result<Vec<EventId>, PduError> {
    let array = value
        .get(key)
        .ok_or(PduError::MissingField(key))?
        .as_array()
        .ok_or(PduError::InvalidField(key))?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let id = item.as_str().ok_or(PduError::InvalidField(key))?;
        out.push(EventId::parse(id).map_err(|_| PduError::InvalidField(key))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events;

    fn pdu(kind: &str, state_key: Option<&str>) -> Pdu {
        Pdu {
            event_id: EventId::parse("$e1").unwrap(),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse("@a:gaussian.tech").unwrap(),
            kind: kind.to_owned(),
            state_key: state_key.map(str::to_owned),
            origin_server_ts: 1,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{}".to_owned(),
        }
    }

    #[test]
    fn reference_id_is_content_addressed_and_id_independent() {
        let mut a = pdu(events::ROOM_MESSAGE, None);
        a.content_json = r#"{"body":"one"}"#.to_owned();
        let id = a.reference_id(11);
        // A reference-hash id is `$` + URL-safe base64 of SHA-256, not the
        // event's own (placeholder) id.
        assert!(id.starts_with('$') && id.len() > 1);
        assert_ne!(id, "$e1");
        // It does not depend on the carried event_id …
        let mut a2 = a.clone();
        a2.event_id = EventId::parse("$different").unwrap();
        assert_eq!(a.reference_id(11), a2.reference_id(11));
        // … but it does depend on the content.
        let mut b = a.clone();
        b.content_json = r#"{"body":"two"}"#.to_owned();
        assert_ne!(a.reference_id(11), b.reference_id(11));
    }

    #[test]
    fn redacting_a_message_does_not_change_its_reference_id() {
        // A message's content is fully stripped by redaction, but its id is the
        // hash of the redacted form (which keeps the content hash), so redacting
        // the event leaves its id unchanged.
        let mut a = pdu(events::ROOM_MESSAGE, None);
        a.content_json = r#"{"body":"secret","extra":1}"#.to_owned();
        let id = a.reference_id(11);

        // The event id and content hash appear in the JSON.
        let json = a.to_json();
        assert!(json
            .get("hashes")
            .and_then(|h| h.get("sha256"))
            .and_then(Json::as_str)
            .is_some());

        // Compute the id from the redacted event directly: same id.
        let redacted = crate::redaction::redact(&a.to_json(), 11);
        let mut obj = match redacted {
            Json::Object(m) => m,
            _ => unreachable!(),
        };
        obj.remove("event_id");
        let canonical = Json::Object(obj).to_string();
        assert_eq!(gm_util::hashing::reference_id(canonical.as_bytes()), id);
    }

    #[test]
    fn state_events_expose_their_state_tuple() {
        let create = pdu(events::ROOM_CREATE, Some(""));
        assert!(create.is_state());
        assert_eq!(create.state_tuple(), Some(("m.room.create", "")));

        let message = pdu(events::ROOM_MESSAGE, None);
        assert!(!message.is_state());
        assert_eq!(message.state_tuple(), None);
    }

    #[test]
    fn json_round_trips_a_state_event_with_dag_links() {
        let mut p = pdu(events::ROOM_NAME, Some(""));
        p.event_id = EventId::parse("$evt").unwrap();
        p.origin_server_ts = 1_700_000_000_000; // a realistic ms timestamp
        p.depth = 7;
        p.prev_events = vec![
            EventId::parse("$p1").unwrap(),
            EventId::parse("$p2").unwrap(),
        ];
        p.auth_events = vec![EventId::parse("$a1").unwrap()];
        p.content_json = "{\"name\":\"Ops\"}".to_owned();

        let json = p.to_json();
        // The JSON carries the Matrix field names.
        assert_eq!(json.get("type").and_then(Json::as_str), Some("m.room.name"));
        assert_eq!(
            json.get("origin_server_ts").and_then(Json::as_u64),
            Some(1_700_000_000_000)
        );
        assert_eq!(
            json.get("content")
                .and_then(|c| c.get("name"))
                .and_then(Json::as_str),
            Some("Ops")
        );

        // Parsing it back yields an identical PDU (content re-serialized compact).
        let restored = Pdu::from_json(&json).unwrap();
        assert_eq!(restored, p);
    }

    #[test]
    fn message_event_round_trips_without_a_state_key() {
        let p = pdu(events::ROOM_MESSAGE, None);
        let restored = Pdu::from_json(&p.to_json()).unwrap();
        assert_eq!(restored, p);
        assert!(restored.state_key.is_none());
    }

    #[test]
    fn decoding_rejects_a_missing_field() {
        let json = pdu(events::ROOM_MESSAGE, None).to_json();
        let Json::Object(mut map) = json else {
            unreachable!()
        };
        map.remove("sender");
        assert_eq!(
            Pdu::from_json(&Json::Object(map)),
            Err(PduError::MissingField("sender"))
        );
    }

    #[test]
    fn decoding_rejects_a_malformed_identifier() {
        let json = pdu(events::ROOM_MESSAGE, None).to_json();
        let Json::Object(mut map) = json else {
            unreachable!()
        };
        // A room id without its `!` sigil is rejected (untrusted federated input).
        map.insert("room_id".into(), Json::String("not-a-room".into()));
        assert_eq!(
            Pdu::from_json(&Json::Object(map)),
            Err(PduError::InvalidField("room_id"))
        );
    }
}
