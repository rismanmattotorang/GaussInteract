// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-svc
//!
//! The service core of GaussMatrix (GaussInteract-SPECS §III.B): rooms, the
//! timeline, and current room state, persisted through the pluggable
//! [`gm_store::Store`] and resolved with [`gm_stateres`].
//!
//! [`RoomService`] is the seam the CS/SS handlers (`gm-http`) and federation
//! (`gm-fed`) drive. It appends [`Pdu`]s to a per-room, depth-ordered timeline
//! and maintains the current state map; when forked state must be merged (the
//! federation path), it delegates to the deterministic resolver in
//! `gm-stateres`. Sync, devices, push and account-data services build on it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

mod codec;

use gm_api::Pdu;
use gm_stateres::StateMap;
use gm_store::{cf, Store};
use gm_util::{EventId, RoomId};
use std::collections::HashMap;

const SEP: char = '\u{1f}';

/// The room service: timeline persistence + current-state tracking over a store.
#[derive(Debug)]
pub struct RoomService<S: Store> {
    store: S,
}

impl<S: Store> RoomService<S> {
    /// Create a service over a storage backend.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    // Timeline key: "{room}\u{1f}{depth:020}\u{1f}{event_id}" — ordered by room
    // then depth, so a prefix scan yields a room's events oldest-first.
    fn timeline_key(pdu: &Pdu) -> String {
        format!(
            "{}{SEP}{:020}{SEP}{}",
            pdu.room_id.as_str(),
            pdu.depth,
            pdu.event_id.as_str(),
        )
    }

    fn state_key(room: &RoomId, kind: &str, state_key: &str) -> String {
        format!("{}{SEP}{kind}{SEP}{state_key}", room.as_str())
    }

    fn room_prefix(room: &RoomId) -> String {
        format!("{}{SEP}", room.as_str())
    }

    /// Append an event: persist it to the room timeline and, if it is a state
    /// event, update the current-state slot (last write wins for the linear
    /// case; divergent state is merged via [`Self::resolve_forks`]).
    pub fn append(&mut self, pdu: &Pdu) {
        self.store
            .put(cf::EVENTS, &Self::timeline_key(pdu), &codec::encode(pdu));
        if let Some((kind, state_key)) = pdu.state_tuple() {
            self.store.put(
                cf::ROOM_STATE,
                &Self::state_key(&pdu.room_id, kind, state_key),
                pdu.event_id.as_str().as_bytes(),
            );
        }
    }

    /// The room's timeline, oldest first.
    pub fn timeline(&self, room: &RoomId) -> Vec<Pdu> {
        let prefix = Self::room_prefix(room);
        self.store
            .scan(cf::EVENTS)
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, v)| codec::decode(&v))
            .collect()
    }

    /// The event currently filling a state slot, if any.
    pub fn state_event(&self, room: &RoomId, kind: &str, state_key: &str) -> Option<EventId> {
        self.store
            .get(cf::ROOM_STATE, &Self::state_key(room, kind, state_key))
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| EventId::parse(s).ok())
    }

    /// The room's full current state map.
    pub fn current_state(&self, room: &RoomId) -> StateMap {
        let prefix = Self::room_prefix(room);
        let mut state = StateMap::new();
        for (key, value) in self.store.scan(cf::ROOM_STATE) {
            let Some(rest) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some((kind, state_key)) = rest.split_once(SEP) else {
                continue;
            };
            let Some(event_id) = String::from_utf8(value)
                .ok()
                .and_then(|s| EventId::parse(s).ok())
            else {
                continue;
            };
            state.insert((kind.to_owned(), state_key.to_owned()), event_id);
        }
        state
    }

    /// Merge divergent state sets (the federation path) into one map via the
    /// deterministic resolver in `gm-stateres`.
    pub fn resolve_forks(&self, forks: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
        gm_stateres::resolve(forks, pdus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_api::events;
    use gm_store::MemoryStore;
    use gm_util::UserId;

    fn pdu(id: &str, depth: u64, kind: &str, state_key: Option<&str>) -> Pdu {
        Pdu {
            event_id: EventId::parse(id).unwrap(),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse("@a:gaussian.tech").unwrap(),
            kind: kind.to_owned(),
            state_key: state_key.map(str::to_owned),
            origin_server_ts: depth,
            depth,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{}".to_owned(),
        }
    }

    #[test]
    fn timeline_is_persisted_in_depth_order() {
        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        let mut svc = RoomService::new(MemoryStore::default());
        svc.append(&pdu("$c", 1, events::ROOM_CREATE, Some("")));
        svc.append(&pdu("$m2", 3, events::ROOM_MESSAGE, None));
        svc.append(&pdu("$m1", 2, events::ROOM_MESSAGE, None));

        let ids: Vec<_> = svc
            .timeline(&room)
            .into_iter()
            .map(|p| p.event_id.as_str().to_owned())
            .collect();
        assert_eq!(ids, ["$c", "$m1", "$m2"]); // ordered by depth
    }

    #[test]
    fn state_events_update_current_state() {
        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        let mut svc = RoomService::new(MemoryStore::default());
        svc.append(&pdu("$c", 1, events::ROOM_CREATE, Some("")));
        svc.append(&pdu("$n1", 2, events::ROOM_NAME, Some("")));
        svc.append(&pdu("$n2", 3, events::ROOM_NAME, Some(""))); // overwrites the slot

        assert_eq!(
            svc.state_event(&room, events::ROOM_NAME, ""),
            Some(EventId::parse("$n2").unwrap())
        );
        // create + name slots are present; messages are not state.
        let state = svc.current_state(&room);
        assert_eq!(state.len(), 2);
        assert!(state.contains_key(&("m.room.create".to_owned(), String::new())));
    }

    #[test]
    fn other_rooms_do_not_leak_into_the_timeline() {
        let mut svc = RoomService::new(MemoryStore::default());
        let mut other = pdu("$x", 1, events::ROOM_MESSAGE, None);
        other.room_id = RoomId::parse("!other:gaussian.tech").unwrap();
        svc.append(&pdu("$m", 1, events::ROOM_MESSAGE, None));
        svc.append(&other);

        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        assert_eq!(svc.timeline(&room).len(), 1);
    }
}
