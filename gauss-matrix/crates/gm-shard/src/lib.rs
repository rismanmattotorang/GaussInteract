// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-shard
//!
//! Room placement for the GaussMatrix sharded profile (GaussInteract-SPECS
//! §III.F). A [`Placement`] is a consistent-hash ring that maps each room to
//! exactly one owning shard, so a room is always served by a single shard
//! (eliminating cross-shard state contention) and adding or draining a shard
//! moves only a small fraction of rooms.
//!
//! Virtual nodes per shard keep the distribution balanced. The coordination
//! service that warms working sets and cuts over during online rebalancing, and
//! the sharded federation sender, build on this placement.
//!
//! The ring uses the standard-library hasher; a production deployment swaps in a
//! fixed, well-distributed hash so placement is stable across processes and
//! versions. The consistent-hashing *contract* — deterministic ownership and
//! minimal disruption — is what the rest of the sharding layer relies on, and is
//! verified here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

use gm_util::RoomId;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

fn hash(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// A consistent-hash placement of rooms onto shards.
#[derive(Debug, Clone)]
pub struct Placement {
    ring: BTreeMap<u64, String>,
    shards: BTreeSet<String>,
    vnodes: u32,
}

impl Placement {
    /// A default number of virtual nodes per shard, balancing distribution
    /// against ring size.
    pub const DEFAULT_VNODES: u32 = 128;

    /// Create an empty placement with `vnodes` virtual nodes per shard.
    pub fn new(vnodes: u32) -> Self {
        Self {
            ring: BTreeMap::new(),
            shards: BTreeSet::new(),
            vnodes: vnodes.max(1),
        }
    }

    /// Add a shard to the ring (no-op if already present).
    pub fn add_shard(&mut self, shard: &str) {
        if !self.shards.insert(shard.to_owned()) {
            return;
        }
        for vnode in 0..self.vnodes {
            self.ring
                .insert(hash(&format!("{shard}#{vnode}")), shard.to_owned());
        }
    }

    /// Drain a shard from the ring (no-op if absent). Its rooms are
    /// redistributed to the remaining shards.
    pub fn remove_shard(&mut self, shard: &str) {
        if self.shards.remove(shard) {
            self.ring.retain(|_, owner| owner != shard);
        }
    }

    /// The shards currently in the ring.
    pub fn shards(&self) -> impl Iterator<Item = &str> {
        self.shards.iter().map(String::as_str)
    }

    /// The number of shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// The shard that owns `room`, or `None` if the ring is empty.
    pub fn shard_for(&self, room: &RoomId) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let point = hash(room.as_str());
        // The first ring node at or after the room's point owns it; wrap to the
        // first node if the point is past the last.
        self.ring
            .range(point..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, owner)| owner.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(n: usize) -> RoomId {
        RoomId::parse(format!("!room{n}:gaussian.tech")).unwrap()
    }

    #[test]
    fn empty_ring_owns_nothing() {
        let p = Placement::new(8);
        assert_eq!(p.shard_for(&room(1)), None);
    }

    #[test]
    fn placement_is_deterministic_and_within_the_shard_set() {
        let mut p = Placement::new(64);
        for s in ["a", "b", "c"] {
            p.add_shard(s);
        }
        let owner = p.shard_for(&room(7)).unwrap().to_owned();
        assert_eq!(p.shard_for(&room(7)), Some(owner.as_str())); // stable
        assert!(["a", "b", "c"].contains(&owner.as_str()));
    }

    #[test]
    fn every_shard_receives_some_rooms() {
        let mut p = Placement::new(Placement::DEFAULT_VNODES);
        for s in ["a", "b", "c", "d"] {
            p.add_shard(s);
        }
        let mut seen = BTreeSet::new();
        for i in 0..2000 {
            seen.insert(p.shard_for(&room(i)).unwrap().to_owned());
        }
        assert_eq!(seen.len(), 4); // all shards used
    }

    #[test]
    fn adding_a_shard_moves_only_a_minority_of_rooms() {
        let n = 2000;
        let mut p = Placement::new(Placement::DEFAULT_VNODES);
        for s in ["a", "b", "c"] {
            p.add_shard(s);
        }
        let before: Vec<String> = (0..n)
            .map(|i| p.shard_for(&room(i)).unwrap().to_owned())
            .collect();

        p.add_shard("d");
        let moved = (0..n)
            .filter(|&i| p.shard_for(&room(i)).unwrap() != before[i])
            .count();

        // Consistent hashing: only ~1/(k+1) of rooms should remap (here ~25%);
        // assert comfortably under half, and that rooms did move to the new shard.
        assert!(moved < n / 2, "moved {moved} of {n} (expected a minority)");
        assert!(moved > 0);
    }
}
