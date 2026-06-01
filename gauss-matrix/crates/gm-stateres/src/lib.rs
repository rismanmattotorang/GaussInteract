// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-stateres
//!
//! The state-resolution core of GaussMatrix (GaussInteract-SPECS §III.D).
//!
//! Room state is a map from a `(type, state_key)` slot to the event that
//! currently fills it. When a server receives an event whose parents carry
//! different state, the conflicting slots must be resolved to a single value.
//! This crate implements the deterministic core of that process:
//!
//! 1. [`separate`] — partition the input state maps into the **unconflicted**
//!    slots (present in *every* input with an identical value) and the
//!    **conflicted** slots (everything else), exactly as Matrix state-resolution
//!    v2 defines that split.
//! 2. [`resolve`] — pass the unconflicted slots through unchanged and pick one
//!    winner per conflicted slot under a **total, deterministic order**
//!    (greatest `origin_server_ts`, ties broken by the lexicographically
//!    greatest event id).
//!
//! 3. [`CachedResolver`] — memoise the conflicted-slot resolution keyed by the
//!    (immutable) set of conflicting event ids, the resolved-state cache of
//!    §III.D, so recurrent conflicts are not recomputed.
//!
//! The conflict order here is the deterministic tie-break that the full
//! state-resolution v2 algorithm layers its auth-chain-difference and
//! reverse-topological *power/mainline* ordering on top of; that ordering, the
//! iterative auth checks, and the parallelised engine are the remaining work.
//! The partition, the total-order contract, and the cache defined here are what
//! they build on, and are correct and tested today.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

use gm_api::Pdu;
use gm_util::EventId;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A room-state slot: `(event type, state key)`.
pub type StateKey = (String, String);

/// A resolved room-state map: each slot filled by exactly one event.
pub type StateMap = BTreeMap<StateKey, EventId>;

/// Distinct candidate events per conflicted slot.
pub type Conflicts = BTreeMap<StateKey, Vec<EventId>>;

/// Partition `states` into the unconflicted map and the conflicted slots.
///
/// A slot is **unconflicted** iff it is present in *every* input state map with
/// one and the same event; otherwise it is **conflicted**, and the returned
/// candidate list holds its distinct events (deduplicated, input order).
pub fn separate(states: &[StateMap]) -> (StateMap, Conflicts) {
    let mut keys: BTreeSet<&StateKey> = BTreeSet::new();
    for state in states {
        keys.extend(state.keys());
    }

    let mut unconflicted = StateMap::new();
    let mut conflicted = Conflicts::new();

    for key in keys {
        let present: Vec<&EventId> = states.iter().filter_map(|s| s.get(key)).collect();
        let mut distinct: Vec<EventId> = Vec::new();
        for ev in &present {
            if !distinct.iter().any(|d| d.as_str() == ev.as_str()) {
                distinct.push((*ev).clone());
            }
        }
        if present.len() == states.len() && distinct.len() == 1 {
            unconflicted.insert(key.clone(), distinct.into_iter().next().unwrap());
        } else {
            conflicted.insert(key.clone(), distinct);
        }
    }

    (unconflicted, conflicted)
}

/// Resolve `states` to a single state map: unconflicted slots pass through, and
/// each conflicted slot is filled by its winning candidate under the
/// deterministic order (greatest `origin_server_ts`, then greatest event id).
///
/// `pdus` supplies the event metadata used for ordering; a candidate missing
/// from it is ordered as timestamp `0` (it still participates by event id).
pub fn resolve(states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
    let (mut resolved, conflicted) = separate(states);
    resolved.extend(resolve_conflicts(&conflicted, pdus));
    resolved
}

/// Resolve only the conflicted slots, picking each slot's winner under the
/// deterministic order. The result depends solely on the conflicting events
/// (which are immutable once created), which is what makes it cacheable.
fn resolve_conflicts(conflicted: &Conflicts, pdus: &HashMap<EventId, Pdu>) -> StateMap {
    let mut out = StateMap::new();
    for (key, candidates) in conflicted {
        if let Some(winner) = candidates
            .iter()
            .max_by(|a, b| {
                let ta = pdus.get(a).map(|p| p.origin_server_ts).unwrap_or(0);
                let tb = pdus.get(b).map(|p| p.origin_server_ts).unwrap_or(0);
                ta.cmp(&tb).then_with(|| a.as_str().cmp(b.as_str()))
            })
            .cloned()
        {
            out.insert(key.clone(), winner);
        }
    }
    out
}

/// The cache key for a resolution: the sorted, deduplicated set of conflicting
/// event ids. The conflicted-slot resolution depends only on these (and their
/// immutable metadata), so it is safe to memoise against this key (spec §III.D).
fn conflict_key(conflicted: &Conflicts) -> Vec<String> {
    let mut ids: Vec<String> = conflicted
        .values()
        .flatten()
        .map(|e| e.as_str().to_owned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// A resolved-state cache (spec §III.D): memoises the output of conflict
/// resolution keyed by the set of conflicting state-event identifiers, so
/// recurrent conflicts are not recomputed. Unconflicted slots are always merged
/// from the live inputs, so the cache only ever holds the (input-independent)
/// resolution of a given conflict set.
#[derive(Debug, Default)]
pub struct CachedResolver {
    cache: HashMap<Vec<String>, StateMap>,
    hits: u64,
    misses: u64,
}

impl CachedResolver {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve `states`, memoising the conflicted-slot resolution.
    pub fn resolve(&mut self, states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
        let (mut resolved, conflicted) = separate(states);
        if !conflicted.is_empty() {
            let key = conflict_key(&conflicted);
            let resolved_conflicts = if let Some(cached) = self.cache.get(&key) {
                self.hits += 1;
                cached.clone()
            } else {
                self.misses += 1;
                let rc = resolve_conflicts(&conflicted, pdus);
                self.cache.insert(key, rc.clone());
                rc
            };
            resolved.extend(resolved_conflicts);
        }
        resolved
    }

    /// Number of cache hits so far.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of cache misses so far.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Number of distinct conflict sets memoised.
    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_util::{RoomId, UserId};

    fn ev(id: &str) -> EventId {
        EventId::parse(id).unwrap()
    }

    fn slot(kind: &str, state_key: &str) -> StateKey {
        (kind.to_owned(), state_key.to_owned())
    }

    fn pdu(id: &str, ts: u64) -> Pdu {
        Pdu {
            event_id: ev(id),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse("@a:gaussian.tech").unwrap(),
            kind: "m.room.name".to_owned(),
            state_key: Some(String::new()),
            origin_server_ts: ts,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{}".to_owned(),
        }
    }

    #[test]
    fn separates_unconflicted_from_conflicted_slots() {
        let create = slot("m.room.create", "");
        let name = slot("m.room.name", "");
        let topic = slot("m.room.topic", "");

        let a: StateMap = [
            (create.clone(), ev("$create")),
            (name.clone(), ev("$name_a")),
        ]
        .into();
        let b: StateMap = [
            (create.clone(), ev("$create")), // agrees -> unconflicted
            (name.clone(), ev("$name_b")),   // differs -> conflicted
            (topic.clone(), ev("$topic")),   // present in only one -> conflicted
        ]
        .into();

        let (unconflicted, conflicted) = separate(&[a, b]);
        assert_eq!(unconflicted.get(&create), Some(&ev("$create")));
        assert!(!unconflicted.contains_key(&name));
        assert_eq!(conflicted[&name].len(), 2);
        assert_eq!(conflicted[&topic], vec![ev("$topic")]);
    }

    #[test]
    fn resolves_conflict_by_greatest_timestamp() {
        let name = slot("m.room.name", "");
        let a: StateMap = [(name.clone(), ev("$old"))].into();
        let b: StateMap = [(name.clone(), ev("$new"))].into();

        let mut pdus = HashMap::new();
        pdus.insert(ev("$old"), pdu("$old", 100));
        pdus.insert(ev("$new"), pdu("$new", 200));

        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(resolved.get(&name), Some(&ev("$new")));
    }

    #[test]
    fn ties_break_by_greatest_event_id() {
        let name = slot("m.room.name", "");
        let a: StateMap = [(name.clone(), ev("$aaa"))].into();
        let b: StateMap = [(name.clone(), ev("$bbb"))].into();

        let mut pdus = HashMap::new();
        pdus.insert(ev("$aaa"), pdu("$aaa", 100));
        pdus.insert(ev("$bbb"), pdu("$bbb", 100)); // same ts -> tie

        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(resolved.get(&name), Some(&ev("$bbb")));
    }

    #[test]
    fn unconflicted_state_passes_through_resolution() {
        let create = slot("m.room.create", "");
        let a: StateMap = [(create.clone(), ev("$create"))].into();
        let b: StateMap = [(create.clone(), ev("$create"))].into();
        let resolved = resolve(&[a, b], &HashMap::new());
        assert_eq!(resolved.get(&create), Some(&ev("$create")));
    }

    #[test]
    fn cache_memoises_recurrent_conflicts_and_matches_uncached() {
        let name = slot("m.room.name", "");
        let a: StateMap = [(name.clone(), ev("$old"))].into();
        let b: StateMap = [(name.clone(), ev("$new"))].into();
        let mut pdus = HashMap::new();
        pdus.insert(ev("$old"), pdu("$old", 100));
        pdus.insert(ev("$new"), pdu("$new", 200));

        let mut resolver = CachedResolver::new();
        let first = resolver.resolve(&[a.clone(), b.clone()], &pdus);
        let second = resolver.resolve(&[a.clone(), b.clone()], &pdus);

        // Same result as the uncached path, and the second call is a cache hit.
        assert_eq!(first, resolve(&[a, b], &pdus));
        assert_eq!(first.get(&name), Some(&ev("$new")));
        assert_eq!(first, second);
        assert_eq!(resolver.misses(), 1);
        assert_eq!(resolver.hits(), 1);
        assert_eq!(resolver.cached_entries(), 1);
    }

    #[test]
    fn cache_is_not_populated_when_there_is_no_conflict() {
        let create = slot("m.room.create", "");
        let a: StateMap = [(create.clone(), ev("$c"))].into();
        let b: StateMap = [(create, ev("$c"))].into();
        let mut resolver = CachedResolver::new();
        resolver.resolve(&[a, b], &HashMap::new());
        assert_eq!(resolver.cached_entries(), 0);
        assert_eq!(resolver.hits(), 0);
        assert_eq!(resolver.misses(), 0);
    }
}
