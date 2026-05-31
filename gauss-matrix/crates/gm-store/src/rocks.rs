// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The single-node RocksDB-profile backend (spec §III.A/C), behind the
//! `rocksdb` feature.
//!
//! The spec's single-node profile is a *tuned RocksDB* that preserves
//! Conduit-family on-disk compatibility. This scaffold models the **on-disk key
//! layout** that backend uses — each per-domain column family namespaced into a
//! single ordered keyspace as `"{cf}\u{1f}{key}"` — so the encoding and
//! ordered-scan semantics are fixed and testable now. It is dependency-free
//! (an ordered in-memory map stands in for the `rocksdb::DB`); wiring the real
//! `rocksdb` crate behind this same feature is then a localised change that
//! keeps this exact key layout (or maps each `cf` onto a native RocksDB column
//! family).

use crate::Store;
use std::collections::BTreeMap;

/// Separator between the column-family prefix and the key in the flat keyspace.
const CF_SEP: char = '\u{1f}';

/// RocksDB-profile [`Store`]: a single ordered keyspace with per-domain column
/// families encoded as key prefixes. (In-memory stand-in for `rocksdb::DB`.)
#[derive(Debug, Default)]
pub struct RocksStore {
    kv: BTreeMap<String, Vec<u8>>,
}

impl RocksStore {
    /// Open a store. The real backend takes a filesystem path and RocksDB
    /// options; the scaffold is in-memory.
    pub fn open() -> Self {
        Self::default()
    }

    fn composite(cf: &str, key: &str) -> String {
        format!("{cf}{CF_SEP}{key}")
    }

    fn prefix(cf: &str) -> String {
        format!("{cf}{CF_SEP}")
    }
}

impl Store for RocksStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) {
        self.kv.insert(Self::composite(cf, key), value.to_vec());
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.kv.get(&Self::composite(cf, key)).cloned()
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        let prefix = Self::prefix(cf);
        // Range from the prefix and stop once keys no longer share it — the
        // ordered iteration a RocksDB prefix scan gives.
        self.kv
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k[prefix.len()..].to_owned(), v.clone()))
            .collect()
    }

    fn count(&self, cf: &str) -> usize {
        let prefix = Self::prefix(cf);
        self.kv
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit, cf};

    #[test]
    fn flat_keyspace_isolates_column_families_and_orders_keys() {
        let mut store = RocksStore::open();
        store.put(cf::EVENTS, "00001", b"e1");
        store.put(cf::ROOM_STATE, "00000", b"s0");
        store.put(cf::EVENTS, "00000", b"e0");

        assert_eq!(store.get(cf::EVENTS, "00000"), Some(b"e0".to_vec()));
        // Scans are scoped to the column family and ordered by key.
        let events: Vec<_> = store.scan(cf::EVENTS).into_iter().map(|(k, _)| k).collect();
        assert_eq!(events, ["00000", "00001"]);
        assert_eq!(store.count(cf::ROOM_STATE), 1);
    }

    #[test]
    fn audit_log_works_over_the_rocksdb_profile() {
        // The same durable audit log runs over any Store backend.
        let mut store = RocksStore::open();
        audit::append(&mut store, "@a:gaussian.tech", "auto_allowed: search");
        audit::append(&mut store, "@a:gaussian.tech", "executed: search ok=true");
        assert_eq!(audit::entries(&store).len(), 2);
        assert_eq!(audit::verify(&store), Ok(()));
    }
}
