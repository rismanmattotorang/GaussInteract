// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The Persistent Data Unit (PDU) envelope — the event metadata the homeserver
//! authenticates and resolves over (spec §III.D, §III.E).
//!
//! State resolution, the auth-chain walk and federation reason about the
//! *envelope* — sender, type, state key, depth, and the `prev_events` /
//! `auth_events` DAG links — far more than the event content, which is carried
//! opaquely here (`content_json`) and typed by `ruma` in the production build.

use gm_util::{EventId, RoomId, UserId};

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
    fn state_events_expose_their_state_tuple() {
        let create = pdu(events::ROOM_CREATE, Some(""));
        assert!(create.is_state());
        assert_eq!(create.state_tuple(), Some(("m.room.create", "")));

        let message = pdu(events::ROOM_MESSAGE, None);
        assert!(!message.is_state());
        assert_eq!(message.state_tuple(), None);
    }
}
