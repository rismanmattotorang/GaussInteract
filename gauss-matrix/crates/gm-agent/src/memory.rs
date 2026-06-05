// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Scoped, durable agent memory / context (spec §IV).
//!
//! An agent needs context that outlives a single tool call — notes, summaries,
//! task state. GaussInteract gives it that with the **same guarantees as
//! everything else** an agent touches: memory is **scoped to the rooms the
//! agent's grant permits** (it can never stash or recall context for a room it
//! was not admitted to), it is **durable** (persisted through [`gm_store::Store`]
//! like the audit log), and every read, write and deletion is **audited** on the
//! tamper-evident chain. So agent memory cannot become a side channel that
//! escapes the capability grant.
//!
//! Keys are namespaced `{agent}␟{room}␟{key}` in the [`gm_store::cf::AGENT_MEMORY`]
//! column family, so a prefix scan yields exactly one agent's memories for one
//! room. As with the audit log, the unit separator must not appear in a memory
//! key (see [`MemoryError::InvalidKey`]).

use gm_store::{cf, Store};
use gm_util::{AgentId, RoomId};

/// The unit separator delimiting the namespaced memory key components.
const SEP: char = '\u{1f}';

/// Why a memory operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// The agent's grant does not permit the room the memory is scoped to.
    RoomNotPermitted(String),
    /// The memory key contained the reserved unit separator.
    InvalidKey,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::RoomNotPermitted(room) => {
                write!(f, "agent memory denied for room outside grant: {room}")
            }
            MemoryError::InvalidKey => write!(f, "memory key contains a reserved separator"),
        }
    }
}

impl std::error::Error for MemoryError {}

/// A single remembered item: the key it is stored under and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryItem {
    /// The agent-chosen key (unique within an agent+room).
    pub key: String,
    /// The remembered value.
    pub value: String,
}

/// The full storage key for one memory item.
fn item_key(agent: &AgentId, room: &RoomId, key: &str) -> String {
    format!("{}{SEP}{}{SEP}{}", agent.as_str(), room.as_str(), key)
}

/// The prefix selecting all of `agent`'s memories scoped to `room`.
fn room_prefix(agent: &AgentId, room: &RoomId) -> String {
    format!("{}{SEP}{}{SEP}", agent.as_str(), room.as_str())
}

/// Validate an agent-chosen memory key.
fn check_key(key: &str) -> Result<(), MemoryError> {
    if key.contains(SEP) {
        Err(MemoryError::InvalidKey)
    } else {
        Ok(())
    }
}

/// Store a memory item for `agent` scoped to `room` (the caller has already
/// confirmed the room is permitted).
pub(crate) fn store<S: Store>(
    store: &mut S,
    agent: &AgentId,
    room: &RoomId,
    key: &str,
    value: &str,
) -> Result<(), MemoryError> {
    check_key(key)?;
    // Best-effort persistence (the durable backends report errors via Store).
    let _ = store.put(
        cf::AGENT_MEMORY,
        &item_key(agent, room, key),
        value.as_bytes(),
    );
    Ok(())
}

/// Recall a single memory item by key.
pub(crate) fn recall<S: Store>(
    store: &S,
    agent: &AgentId,
    room: &RoomId,
    key: &str,
) -> Option<String> {
    store
        .get(cf::AGENT_MEMORY, &item_key(agent, room, key))
        .and_then(|v| String::from_utf8(v).ok())
}

/// Recall all of `agent`'s memory items scoped to `room`, key-ordered.
pub(crate) fn recall_all<S: Store>(store: &S, agent: &AgentId, room: &RoomId) -> Vec<MemoryItem> {
    let prefix = room_prefix(agent, room);
    store
        .scan(cf::AGENT_MEMORY)
        .into_iter()
        .filter_map(|(k, v)| {
            let key = k.strip_prefix(&prefix)?.to_owned();
            let value = String::from_utf8(v).ok()?;
            Some(MemoryItem { key, value })
        })
        .collect()
}

/// Forget a single memory item by key.
pub(crate) fn forget<S: Store>(store: &mut S, agent: &AgentId, room: &RoomId, key: &str) {
    let _ = store.delete(cf::AGENT_MEMORY, &item_key(agent, room, key));
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_store::MemoryStore;

    fn agent() -> AgentId {
        AgentId::parse("@gauss_agent_x:gaussian.tech").unwrap()
    }
    fn room(id: &str) -> RoomId {
        RoomId::parse(id).unwrap()
    }

    #[test]
    fn store_recall_round_trips_and_is_scoped_per_room() {
        let mut s = MemoryStore::default();
        let a = agent();
        let r1 = room("!r1:gaussian.tech");
        let r2 = room("!r2:gaussian.tech");

        store(&mut s, &a, &r1, "task", "summarise thread").unwrap();
        store(&mut s, &a, &r2, "task", "draft reply").unwrap();

        assert_eq!(
            recall(&s, &a, &r1, "task").as_deref(),
            Some("summarise thread")
        );
        // The same key in another room is a different memory (room-scoped).
        assert_eq!(recall(&s, &a, &r2, "task").as_deref(), Some("draft reply"));
        // recall_all is scoped to one room.
        assert_eq!(recall_all(&s, &a, &r1).len(), 1);
    }

    #[test]
    fn forget_removes_one_item() {
        let mut s = MemoryStore::default();
        let a = agent();
        let r = room("!r:gaussian.tech");
        store(&mut s, &a, &r, "k", "v").unwrap();
        forget(&mut s, &a, &r, "k");
        assert_eq!(recall(&s, &a, &r, "k"), None);
        assert!(recall_all(&s, &a, &r).is_empty());
    }

    #[test]
    fn a_separator_in_the_key_is_rejected() {
        let mut s = MemoryStore::default();
        let a = agent();
        let r = room("!r:gaussian.tech");
        assert_eq!(
            store(&mut s, &a, &r, "bad\u{1f}key", "v"),
            Err(MemoryError::InvalidKey)
        );
    }
}
