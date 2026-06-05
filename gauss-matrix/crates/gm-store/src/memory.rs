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
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) -> Result<(), crate::StoreError> {
        self.families
            .entry(cf.to_owned())
            .or_default()
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, cf: &str, key: &str) -> Result<(), crate::StoreError> {
        if let Some(family) = self.families.get_mut(cf) {
            family.remove(key);
        }
        Ok(())
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

    fn scan_paged(&self, cf: &str, after: Option<&str>, limit: usize) -> Vec<(String, Vec<u8>)> {
        use std::ops::Bound::{Excluded, Unbounded};
        let Some(family) = self.families.get(cf) else {
            return Vec::new();
        };
        let bounds: (std::ops::Bound<String>, std::ops::Bound<String>) = (
            after.map(|a| Excluded(a.to_owned())).unwrap_or(Unbounded),
            Unbounded,
        );
        family
            .range(bounds)
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_scan_are_ordered() {
        let mut store = MemoryStore::default();
        store.put("cf", "00002", b"c").unwrap();
        store.put("cf", "00000", b"a").unwrap();
        store.put("cf", "00001", b"b").unwrap();

        assert_eq!(store.get("cf", "00001"), Some(b"b".to_vec()));
        assert_eq!(store.count("cf"), 3);
        let keys: Vec<_> = store.scan("cf").into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["00000", "00001", "00002"]);
        assert!(store.scan("missing").is_empty());
    }

    #[test]
    fn delete_removes_a_key_and_is_a_noop_when_absent() {
        let mut store = MemoryStore::default();
        store.put("cf", "k", b"v").unwrap();
        store.delete("cf", "k").unwrap();
        assert_eq!(store.get("cf", "k"), None);
        assert_eq!(store.count("cf"), 0);
        // Deleting an absent key (or in an absent family) is harmless.
        store.delete("cf", "k").unwrap();
        store.delete("missing", "x").unwrap();
    }

    #[test]
    fn scan_paged_walks_in_key_order_with_a_cursor() {
        let mut store = MemoryStore::default();
        for i in 0..10 {
            store.put("cf", &format!("{i:02}"), b"v").unwrap();
        }
        // First page from the start.
        let page1 = store.scan_paged("cf", None, 4);
        let keys1: Vec<_> = page1.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys1, ["00", "01", "02", "03"]);
        // Next page after the last key of page 1 (exclusive).
        let page2 = store.scan_paged("cf", Some("03"), 4);
        let keys2: Vec<_> = page2.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys2, ["04", "05", "06", "07"]);
        // A cursor past the end yields nothing; an unknown cf is empty.
        assert!(store.scan_paged("cf", Some("99"), 4).is_empty());
        assert!(store.scan_paged("missing", None, 4).is_empty());
    }

    #[test]
    fn stream_yields_every_entry_in_order_across_pages() {
        let mut store = MemoryStore::default();
        for i in 0..25 {
            store
                .put("cf", &format!("{i:03}"), format!("v{i}").as_bytes())
                .unwrap();
        }
        // Stream in small pages; the result equals a full scan.
        let streamed: Vec<_> = crate::stream(&store, "cf", 7).collect();
        assert_eq!(streamed, store.scan("cf"));
        assert_eq!(streamed.len(), 25);
        // A page size of 0 is clamped (does not stall).
        assert_eq!(crate::stream(&store, "cf", 0).count(), 25);
    }
}
