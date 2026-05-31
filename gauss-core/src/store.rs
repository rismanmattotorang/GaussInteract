// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local event store and incremental, persisted timeline cache (spec §V.B/§V.C).
//!
//! The store is what makes re-launch warm and the `< 1.2 s` cold-start target
//! attainable. Phase 2 backs this with the encrypted `matrix-sdk` state store
//! (SQLCipher / IndexedDB on web); this scaffold provides an in-memory backend
//! behind the [`EventStore`] trait so the contract is exercised by tests.

use crate::timeline::TimelineItem;
use std::collections::HashMap;

/// A room identifier, e.g. `!abcdef:example.org`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoomId(pub String);

/// Pluggable local persistence. Mirrors the server's `gm-store` philosophy
/// (spec §III.C): the schema lives behind a trait so the backend is swappable.
pub trait EventStore: Send + Sync {
    /// Append a materialised timeline item to a room's cache.
    fn append(&mut self, room: &RoomId, item: TimelineItem);

    /// Return the cached timeline window for a room (oldest → newest).
    fn timeline(&self, room: &RoomId) -> Vec<TimelineItem>;

    /// Number of rooms currently cached.
    fn room_count(&self) -> usize;
}

/// Volatile, in-memory [`EventStore`] used for the scaffold and tests.
#[derive(Default)]
pub struct MemoryStore {
    rooms: HashMap<RoomId, Vec<TimelineItem>>,
}

impl EventStore for MemoryStore {
    fn append(&mut self, room: &RoomId, item: TimelineItem) {
        self.rooms.entry(room.clone()).or_default().push(item);
    }

    fn timeline(&self, room: &RoomId) -> Vec<TimelineItem> {
        self.rooms.get(room).cloned().unwrap_or_default()
    }

    fn room_count(&self) -> usize {
        self.rooms.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::TimelineItem;

    #[test]
    fn append_and_read_back() {
        let mut store = MemoryStore::default();
        let room = RoomId("!r:example.org".into());
        store.append(&room, TimelineItem::message("@a:example.org", "hello"));
        store.append(&room, TimelineItem::message("@b:example.org", "hi"));
        assert_eq!(store.room_count(), 1);
        assert_eq!(store.timeline(&room).len(), 2);
    }
}
