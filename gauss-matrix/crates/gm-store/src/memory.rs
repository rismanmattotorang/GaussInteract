// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! In-memory [`Store`] backend. Used for the scaffold, tests, and the
//! `--dry-run` profile; the tuned RocksDB and distributed-KV backends from the
//! spec implement the same trait behind cargo features.

use crate::Store;
use std::collections::BTreeMap;

/// A volatile, ordered, in-memory store. `BTreeMap` gives deterministic,
/// key-ordered [`Store::scan`], which the audit log relies on.
#[derive(Debug, Default)]
pub struct MemoryStore {
    families: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

impl Store for MemoryStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) {
        self.families
            .entry(cf.to_owned())
            .or_default()
            .insert(key.to_owned(), value.to_vec());
    }

    fn delete(&mut self, cf: &str, key: &str) {
        if let Some(family) = self.families.get_mut(cf) {
            family.remove(key);
        }
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.families.get(cf).and_then(|f| f.get(key)).cloned()
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        self.families
            .get(cf)
            .map(|f| f.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    fn count(&self, cf: &str) -> usize {
        self.families.get(cf).map(|f| f.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_scan_are_ordered() {
        let mut store = MemoryStore::default();
        store.put("cf", "00002", b"c");
        store.put("cf", "00000", b"a");
        store.put("cf", "00001", b"b");

        assert_eq!(store.get("cf", "00001"), Some(b"b".to_vec()));
        assert_eq!(store.count("cf"), 3);
        let keys: Vec<_> = store.scan("cf").into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["00000", "00001", "00002"]);
        assert!(store.scan("missing").is_empty());
    }

    #[test]
    fn delete_removes_a_key_and_is_a_noop_when_absent() {
        let mut store = MemoryStore::default();
        store.put("cf", "k", b"v");
        store.delete("cf", "k");
        assert_eq!(store.get("cf", "k"), None);
        assert_eq!(store.count("cf"), 0);
        // Deleting an absent key (or in an absent family) is harmless.
        store.delete("cf", "k");
        store.delete("missing", "x");
    }
}
