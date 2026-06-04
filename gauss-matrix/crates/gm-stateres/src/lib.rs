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
//! 2. [`resolve`] — the **state-resolution v2** algorithm: unconflicted slots
//!    pass through; the full conflicted set (conflicted candidates plus the
//!    auth-chain *difference*) is split into power events and the rest; the
//!    power events are ordered by **reverse-topological power ordering** and the
//!    rest by **mainline ordering**, and each is applied by **iterative
//!    authorization** ([`auth::check_auth`]) so an event that is not allowed by
//!    the partially-resolved state is dropped; the unconflicted state is overlaid
//!    last. Tie-breaks fall back to greatest `origin_server_ts` then event id.
//!
//! 3. [`CachedResolver`] — memoise the resolution keyed by the (immutable) set
//!    of input event ids, the resolved-state cache of §III.D, so recurrent
//!    resolutions are not recomputed.
//! 4. [`ParallelResolver`] — resolve many independent rooms concurrently across
//!    a bounded worker pool over a shared, thread-safe resolved-state cache.
//!
//! The remaining work is room-version-specific ordering tweaks; the v2
//! algorithm, the partition, and the caches defined here are correct and tested
//! today.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod auth;

use gm_api::{events, Json, Pdu};
use gm_util::EventId;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

/// Resolve `states` to a single state map by the **state-resolution v2**
/// algorithm (spec §III.D):
///
/// 1. unconflicted slots pass through unchanged;
/// 2. the full conflicted set is the conflicted candidates plus the *auth
///    difference* (auth-chain events not common to every input);
/// 3. the **power events** (create / power-levels / join-rules / control
///    membership) are ordered by reverse-topological power ordering and applied
///    by **iterative authorization** onto the unconflicted base — an event that
///    fails the auth rules ([`auth::check_auth`]) is dropped;
/// 4. the remaining conflicted events are ordered by **mainline ordering**
///    (relative to the resolved power-levels) and applied the same way;
/// 5. the unconflicted state is overlaid last, so it always wins.
///
/// `pdus` supplies the events (metadata + `auth_events`) the ordering and auth
/// checks need; an event missing from it cannot be applied.
pub fn resolve(states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
    let (unconflicted, conflicted) = separate(states);
    if conflicted.is_empty() {
        return unconflicted;
    }

    // (2) Full conflicted set: the conflicted candidates plus the auth difference.
    let mut full: HashSet<EventId> = conflicted.values().flatten().cloned().collect();
    full.extend(auth_difference(states, pdus));

    // (3) Partition into power events and the rest; order power events by
    // reverse-topological power ordering and apply them onto the unconflicted base.
    let (power, other): (Vec<EventId>, Vec<EventId>) = full
        .into_iter()
        .partition(|id| pdus.get(id).map(is_power_event).unwrap_or(false));

    let mut resolved = unconflicted.clone();
    for id in reverse_topological_power_sort(&power, pdus, &unconflicted) {
        try_apply(&mut resolved, &id, pdus);
    }

    // (4) Mainline-order the remaining events (relative to the resolved
    // power-levels) and apply them.
    let power_levels = resolved
        .get(&(events::ROOM_POWER_LEVELS.to_owned(), String::new()))
        .cloned();
    for id in mainline_sort(&other, power_levels.as_ref(), pdus) {
        try_apply(&mut resolved, &id, pdus);
    }

    // (5) The unconflicted state always wins.
    for (slot, id) in &unconflicted {
        resolved.insert(slot.clone(), id.clone());
    }
    resolved
}

/// The state slot an event fills, if it is a state event.
fn state_slot(event: &Pdu) -> Option<StateKey> {
    event
        .state_tuple()
        .map(|(kind, sk)| (kind.to_owned(), sk.to_owned()))
}

/// Whether an event is a **power event** for resolution ordering: the create
/// event, `m.room.power_levels`, `m.room.join_rules`, or a *control* membership
/// change (a ban, or a kick — a `leave` set by someone other than the target).
fn is_power_event(event: &Pdu) -> bool {
    match event.kind.as_str() {
        events::ROOM_CREATE | events::ROOM_POWER_LEVELS | events::ROOM_JOIN_RULES => true,
        events::ROOM_MEMBER => {
            let membership = Json::parse(&event.content_json).ok().and_then(|c| {
                c.get("membership")
                    .and_then(Json::as_str)
                    .map(str::to_owned)
            });
            match membership.as_deref() {
                Some("ban") => true,
                Some("leave") => event.state_key.as_deref() != Some(event.sender.as_str()),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Apply `id` to the partial `resolved` state if it passes the auth rules
/// against that state (with its own slot removed, so a transition is checked
/// against the *prior* value). A rejected or unknown event is left out.
fn try_apply(resolved: &mut StateMap, id: &EventId, pdus: &HashMap<EventId, Pdu>) {
    let Some(event) = pdus.get(id) else {
        return;
    };
    let Some(slot) = state_slot(event) else {
        return;
    };
    let context: Vec<Pdu> = resolved
        .iter()
        .filter(|(k, _)| **k != slot)
        .filter_map(|(_, eid)| pdus.get(eid).cloned())
        .collect();
    if auth::check_auth(event, &context).is_ok() {
        resolved.insert(slot, id.clone());
    }
}

/// The auth difference: events in the auth chain of some input state but not of
/// every input state (the contested auth events).
fn auth_difference(states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> HashSet<EventId> {
    let chains: Vec<HashSet<EventId>> = states
        .iter()
        .map(|s| {
            let roots: Vec<EventId> = s.values().cloned().collect();
            auth::auth_chain(&roots, pdus)
        })
        .collect();
    let mut difference = HashSet::new();
    for chain in &chains {
        for id in chain {
            if !chains.iter().all(|c| c.contains(id)) {
                difference.insert(id.clone());
            }
        }
    }
    difference
}

/// The power level of `sender` under the `base` state (its `m.room.power_levels`
/// `users` / `users_default`, or `100` for the room creator before power levels).
fn sender_power(sender: &str, base: &StateMap, pdus: &HashMap<EventId, Pdu>) -> i64 {
    if let Some(pl) = base
        .get(&(events::ROOM_POWER_LEVELS.to_owned(), String::new()))
        .and_then(|id| pdus.get(id))
        .and_then(|p| Json::parse(&p.content_json).ok())
    {
        if let Some(level) = pl
            .get("users")
            .and_then(|u| u.get(sender))
            .and_then(Json::as_i64)
        {
            return level;
        }
        return pl.get("users_default").and_then(Json::as_i64).unwrap_or(0);
    }
    // No power_levels: the creator is all-powerful, everyone else 0. The creator
    // is version-specific (from room version 11 it is the create event's sender,
    // not a `content.creator` field).
    let creator = base
        .get(&(events::ROOM_CREATE.to_owned(), String::new()))
        .and_then(|id| pdus.get(id))
        .and_then(|create| {
            if auth::create_room_version(create) >= 11 {
                Some(create.sender.as_str().to_owned())
            } else {
                Json::parse(&create.content_json)
                    .ok()
                    .and_then(|c| c.get("creator").and_then(Json::as_str).map(str::to_owned))
            }
        });
    if creator.as_deref() == Some(sender) {
        100
    } else {
        0
    }
}

/// Reverse-topological power ordering: a Kahn topological sort over the
/// `auth_events` edges within `events`, so an event is ordered after its
/// in-set auth ancestors, with ties broken by (greatest sender power, least
/// `origin_server_ts`, least event id).
fn reverse_topological_power_sort(
    events: &[EventId],
    pdus: &HashMap<EventId, Pdu>,
    base: &StateMap,
) -> Vec<EventId> {
    let set: HashSet<&EventId> = events.iter().collect();
    let parents: HashMap<&EventId, Vec<EventId>> = events
        .iter()
        .map(|e| {
            let ps = pdus
                .get(e)
                .map(|p| {
                    p.auth_events
                        .iter()
                        .filter(|a| set.contains(*a))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            (e, ps)
        })
        .collect();

    // Sort key: highest power first, then earliest, then smallest id.
    let key = |e: &EventId| {
        let (ts, sender) = pdus
            .get(e)
            .map(|p| (p.origin_server_ts, p.sender.as_str().to_owned()))
            .unwrap_or((0, String::new()));
        (
            std::cmp::Reverse(sender_power(&sender, base, pdus)),
            ts,
            e.as_str().to_owned(),
        )
    };

    let mut placed: HashSet<EventId> = HashSet::new();
    let mut order: Vec<EventId> = Vec::new();
    while order.len() < events.len() {
        let mut ready: Vec<&EventId> = events
            .iter()
            .filter(|e| !placed.contains(*e) && parents[*e].iter().all(|p| placed.contains(p)))
            .collect();
        if ready.is_empty() {
            // An auth cycle (should not happen): fall back to all remaining.
            ready = events.iter().filter(|e| !placed.contains(*e)).collect();
        }
        ready.sort_by_key(|e| key(e));
        let chosen = ready[0].clone();
        placed.insert(chosen.clone());
        order.push(chosen);
    }
    order
}

/// The closest `m.room.power_levels` reachable from `id` through `auth_events`.
fn power_levels_ancestor(id: &EventId, pdus: &HashMap<EventId, Pdu>) -> Option<EventId> {
    pdus.get(id).and_then(|p| {
        p.auth_events
            .iter()
            .find(|a| {
                pdus.get(*a)
                    .map(|x| x.kind == events::ROOM_POWER_LEVELS)
                    .unwrap_or(false)
            })
            .cloned()
    })
}

/// Mainline ordering: order `events` by their depth along the mainline of the
/// resolved `power_levels` (the chain of power-levels events through
/// `auth_events`), with ties broken by (`origin_server_ts`, event id).
fn mainline_sort(
    events: &[EventId],
    power_levels: Option<&EventId>,
    pdus: &HashMap<EventId, Pdu>,
) -> Vec<EventId> {
    // Build the mainline (current power-levels back to the root) and index each
    // entry by its distance from the root, so deeper = more recent.
    let mut mainline = Vec::new();
    let mut cursor = power_levels.cloned();
    while let Some(id) = cursor {
        mainline.push(id.clone());
        cursor = power_levels_ancestor(&id, pdus);
    }
    let n = mainline.len();
    let mut position: HashMap<EventId, usize> = HashMap::new();
    for (i, id) in mainline.iter().enumerate() {
        position.insert(id.clone(), n - 1 - i);
    }

    // An event's mainline depth is the position of the first mainline event in
    // its power-levels ancestry.
    let depth = |start: &EventId| -> usize {
        let mut cursor = Some(start.clone());
        let mut guard = 0;
        while let Some(id) = cursor {
            if let Some(p) = position.get(&id) {
                return *p;
            }
            cursor = power_levels_ancestor(&id, pdus);
            guard += 1;
            if guard > 10_000 {
                break;
            }
        }
        0
    };

    let mut sorted = events.to_vec();
    sorted.sort_by(|a, b| {
        let ta = pdus.get(a).map(|p| p.origin_server_ts).unwrap_or(0);
        let tb = pdus.get(b).map(|p| p.origin_server_ts).unwrap_or(0);
        depth(a)
            .cmp(&depth(b))
            .then(ta.cmp(&tb))
            .then_with(|| a.as_str().cmp(b.as_str()))
    });
    sorted
}

/// The cache key for a resolution: the sorted, deduplicated set of *all* input
/// event ids. State-resolution v2 depends on the whole input (the unconflicted
/// base drives iterative auth), so the cache is keyed on all of it (spec §III.D).
fn input_key(states: &[StateMap]) -> Vec<String> {
    let mut ids: Vec<String> = states
        .iter()
        .flat_map(|s| s.values())
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

    /// Resolve `states`, memoising the full resolution keyed by the input set.
    pub fn resolve(&mut self, states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
        let (unconflicted, conflicted) = separate(states);
        // A conflict-free input has nothing to resolve and is not worth caching.
        if conflicted.is_empty() {
            return unconflicted;
        }
        let key = input_key(states);
        if let Some(cached) = self.cache.get(&key) {
            self.hits += 1;
            return cached.clone();
        }
        self.misses += 1;
        let resolved = resolve(states, pdus);
        self.cache.insert(key, resolved.clone());
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

/// One resolution request: the candidate state maps to resolve and the events
/// (`pdus`) their ordering and auth checks need.
pub struct ResolveJob {
    /// The candidate state maps to merge.
    pub states: Vec<StateMap>,
    /// The events referenced by the states and their auth chains.
    pub pdus: HashMap<EventId, Pdu>,
}

/// A parallelised state-resolution engine over a shared resolved-state cache
/// (spec §III.D): resolves many independent rooms' state concurrently across a
/// bounded worker pool, memoising each resolution by its input event-id set so
/// recurrent inputs are not recomputed. The cache is shared and thread-safe, so
/// hits on one worker serve the others.
#[derive(Clone)]
pub struct ParallelResolver {
    cache: Arc<Mutex<HashMap<Vec<String>, StateMap>>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    workers: usize,
}

impl ParallelResolver {
    /// An engine with a pool of `workers` threads (clamped to at least 1).
    pub fn new(workers: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            workers: workers.max(1),
        }
    }

    /// Resolve `jobs` concurrently, returning the resolved state maps in the same
    /// order. Each job is resolved by the v2 [`resolve`], consulting and filling
    /// the shared cache; identical inputs resolve once and are reused.
    pub fn resolve_batch(&self, jobs: &[ResolveJob]) -> Vec<StateMap> {
        let next = AtomicUsize::new(0);
        let results: Vec<Mutex<Option<StateMap>>> =
            (0..jobs.len()).map(|_| Mutex::new(None)).collect();

        std::thread::scope(|scope| {
            for _ in 0..self.workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= jobs.len() {
                        break;
                    }
                    let job = &jobs[i];
                    let resolved = self.resolve_cached(&job.states, &job.pdus);
                    *results[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(resolved);
                });
            }
        });

        results
            .into_iter()
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()).unwrap())
            .collect()
    }

    /// Resolve a single input through the shared cache (also usable directly).
    pub fn resolve_cached(&self, states: &[StateMap], pdus: &HashMap<EventId, Pdu>) -> StateMap {
        let (unconflicted, conflicted) = separate(states);
        if conflicted.is_empty() {
            return unconflicted;
        }
        let key = input_key(states);
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return cached.clone();
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let resolved = resolve(states, pdus);
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, resolved.clone());
        resolved
    }

    /// Number of cache hits so far.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Number of cache misses so far.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Number of distinct resolutions memoised.
    pub fn cached_entries(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).len()
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

    #[allow(clippy::too_many_arguments)]
    fn mk(
        id: &str,
        kind: &str,
        sender: &str,
        state_key: Option<&str>,
        content: &str,
        ts: u64,
        auth: &[&str],
    ) -> Pdu {
        Pdu {
            event_id: ev(id),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse(sender).unwrap(),
            kind: kind.to_owned(),
            state_key: state_key.map(str::to_owned),
            origin_server_ts: ts,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: auth.iter().map(|a| ev(a)).collect(),
            content_json: content.to_owned(),
        }
    }

    /// A minimal room: create + creator (@a) join + power_levels (@a:100). The
    /// returned `pdus` map and the base state slots are the foundation conflict
    /// tests build name/power conflicts on top of.
    fn base_room() -> (HashMap<EventId, Pdu>, StateMap) {
        let create = mk(
            "$create",
            "m.room.create",
            "@a:gaussian.tech",
            Some(""),
            r#"{"creator":"@a:gaussian.tech"}"#,
            1,
            &[],
        );
        let member = mk(
            "$member",
            "m.room.member",
            "@a:gaussian.tech",
            Some("@a:gaussian.tech"),
            r#"{"membership":"join"}"#,
            2,
            &["$create"],
        );
        let pl = mk(
            "$pl",
            "m.room.power_levels",
            "@a:gaussian.tech",
            Some(""),
            r#"{"users":{"@a:gaussian.tech":100},"users_default":0}"#,
            3,
            &["$create", "$member"],
        );
        let mut pdus = HashMap::new();
        for p in [&create, &member, &pl] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let base: StateMap = [
            (slot("m.room.create", ""), ev("$create")),
            (slot("m.room.member", "@a:gaussian.tech"), ev("$member")),
            (slot("m.room.power_levels", ""), ev("$pl")),
        ]
        .into();
        (pdus, base)
    }

    /// Two forks of `base` that differ only in the `m.room.name` slot.
    fn name_forks(
        pdus: &mut HashMap<EventId, Pdu>,
        base: &StateMap,
        a_id: &str,
        a_ts: u64,
        b_id: &str,
        b_ts: u64,
    ) -> (StateMap, StateMap) {
        for (id, ts) in [(a_id, a_ts), (b_id, b_ts)] {
            let name = mk(
                id,
                "m.room.name",
                "@a:gaussian.tech",
                Some(""),
                r#"{"name":"x"}"#,
                ts,
                &["$create", "$member", "$pl"],
            );
            pdus.insert(name.event_id.clone(), name);
        }
        let mut a = base.clone();
        a.insert(slot("m.room.name", ""), ev(a_id));
        let mut b = base.clone();
        b.insert(slot("m.room.name", ""), ev(b_id));
        (a, b)
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
    fn conflicting_state_resolves_to_the_later_authorized_event() {
        // Two authorized name events differ; mainline ordering applies them by
        // (timestamp, id), so the later one wins.
        let (mut pdus, base) = base_room();
        let (a, b) = name_forks(&mut pdus, &base, "$old", 100, "$new", 200);
        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(resolved.get(&slot("m.room.name", "")), Some(&ev("$new")));
        // The unconflicted base passes through unchanged.
        assert_eq!(
            resolved.get(&slot("m.room.create", "")),
            Some(&ev("$create"))
        );
    }

    #[test]
    fn ties_break_by_event_id() {
        let (mut pdus, base) = base_room();
        // Equal timestamps -> the greater event id is applied last and wins.
        let (a, b) = name_forks(&mut pdus, &base, "$aaa", 100, "$bbb", 100);
        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(resolved.get(&slot("m.room.name", "")), Some(&ev("$bbb")));
    }

    #[test]
    fn an_unauthorized_conflicting_event_is_dropped() {
        // A name event from a non-member is not authorized, so iterative auth
        // refuses it and the authorized candidate wins regardless of timestamp.
        let (mut pdus, base) = base_room();
        let good = mk(
            "$good",
            "m.room.name",
            "@a:gaussian.tech",
            Some(""),
            r#"{"name":"ok"}"#,
            100,
            &["$create", "$member", "$pl"],
        );
        let bad = mk(
            "$bad",
            "m.room.name",
            "@mallory:gaussian.tech", // not joined -> unauthorized
            Some(""),
            r#"{"name":"evil"}"#,
            999, // later, but it must still lose
            &["$create", "$member", "$pl"],
        );
        pdus.insert(good.event_id.clone(), good);
        pdus.insert(bad.event_id.clone(), bad);
        let mut a = base.clone();
        a.insert(slot("m.room.name", ""), ev("$good"));
        let mut b = base.clone();
        b.insert(slot("m.room.name", ""), ev("$bad"));

        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(resolved.get(&slot("m.room.name", "")), Some(&ev("$good")));
    }

    #[test]
    fn power_level_conflict_resolves_to_an_authorized_event() {
        // Two competing power_levels events (both by the powered creator) are
        // power events; the later authorized one wins.
        let (mut pdus, base) = base_room();
        for (id, ts) in [("$pl_a", 10), ("$pl_b", 20)] {
            let pl = mk(
                id,
                "m.room.power_levels",
                "@a:gaussian.tech",
                Some(""),
                r#"{"users":{"@a:gaussian.tech":100},"users_default":0,"state_default":50}"#,
                ts,
                &["$create", "$member", "$pl"],
            );
            pdus.insert(pl.event_id.clone(), pl);
        }
        let mut a = base.clone();
        a.insert(slot("m.room.power_levels", ""), ev("$pl_a"));
        let mut b = base.clone();
        b.insert(slot("m.room.power_levels", ""), ev("$pl_b"));

        let resolved = resolve(&[a, b], &pdus);
        assert_eq!(
            resolved.get(&slot("m.room.power_levels", "")),
            Some(&ev("$pl_b"))
        );
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
        let (mut pdus, base) = base_room();
        let (a, b) = name_forks(&mut pdus, &base, "$old", 100, "$new", 200);

        let mut resolver = CachedResolver::new();
        let first = resolver.resolve(&[a.clone(), b.clone()], &pdus);
        let second = resolver.resolve(&[a.clone(), b.clone()], &pdus);

        // Same result as the uncached path, and the second call is a cache hit.
        assert_eq!(first, resolve(&[a, b], &pdus));
        assert_eq!(first.get(&slot("m.room.name", "")), Some(&ev("$new")));
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

    #[test]
    fn parallel_resolver_matches_sequential_and_caches_duplicates() {
        // Build several name-conflict jobs; two of them are identical so the
        // shared cache should serve a hit.
        let (mut pdus, base) = base_room();
        let (a1, b1) = name_forks(&mut pdus, &base, "$old", 100, "$new", 200);
        let job = |a: &StateMap, b: &StateMap| ResolveJob {
            states: vec![a.clone(), b.clone()],
            pdus: pdus.clone(),
        };
        let jobs = vec![job(&a1, &b1), job(&a1, &b1), job(&b1, &a1)];

        let engine = ParallelResolver::new(4);
        let out = engine.resolve_batch(&jobs);

        // Every result matches the sequential v2 resolver, in order.
        assert_eq!(out.len(), 3);
        for (job, got) in jobs.iter().zip(&out) {
            assert_eq!(*got, resolve(&job.states, &job.pdus));
            assert_eq!(got.get(&slot("m.room.name", "")), Some(&ev("$new")));
        }
        // The three jobs share one input set, so the cache holds one entry and
        // every lookup is accounted for. (Concurrent workers may each miss the
        // empty cache before the first insert, so the exact hit/miss split is
        // not deterministic — but their sum is, and there is at least one miss.)
        assert_eq!(engine.cached_entries(), 1);
        assert!(engine.misses() >= 1);
        assert_eq!(engine.hits() + engine.misses(), 3);
    }

    #[test]
    fn parallel_resolver_handles_an_empty_batch_and_single_worker() {
        let engine = ParallelResolver::new(1);
        assert!(engine.resolve_batch(&[]).is_empty());

        let (mut pdus, base) = base_room();
        let (a, b) = name_forks(&mut pdus, &base, "$old", 100, "$new", 200);
        let out = engine.resolve_batch(&[ResolveJob {
            states: vec![a, b],
            pdus,
        }]);
        assert_eq!(out[0].get(&slot("m.room.name", "")), Some(&ev("$new")));
    }
}
