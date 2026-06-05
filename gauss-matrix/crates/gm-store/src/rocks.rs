// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The single-node RocksDB-profile backend (spec §III.A/C), behind the
//! `rocksdb` feature.
//!
//! The spec's single-node profile is a *tuned RocksDB* that preserves
//! Conduit-family on-disk compatibility. [`RocksStore`] backs the [`Store`]
//! trait with a real `rocksdb::DB`. Per-domain column families are namespaced
//! into the default keyspace as `"{cf}\u{1f}{key}"`, and [`Store::scan`] uses a
//! RocksDB prefix iterator — the key layout fixed by the in-memory scaffold,
//! now persistent. (Mapping each `cf` onto a native RocksDB column family is a
//! later tuning step; the trait contract is identical either way.)
//!
//! Write failures from RocksDB are surfaced as a [`crate::StoreError`] through
//! the fallible [`Store::put`] / [`Store::delete`]; reads are served as `None`
//! on error (consistent with the in-memory backends).

use crate::Store;
use rocksdb::{Direction, IteratorMode, Options, DB};
use std::path::Path;

/// Separator between the column-family prefix and the key in the keyspace.
const CF_SEP: char = '\u{1f}';

/// RocksDB-profile [`Store`]: a persistent single-node backend.
#[derive(Debug)]
pub struct RocksStore {
    db: DB,
}

impl RocksStore {
    /// Open (creating if absent) a RocksDB database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        Ok(Self {
            db: DB::open(&opts, path)?,
        })
    }

    fn composite(cf: &str, key: &str) -> String {
        format!("{cf}{CF_SEP}{key}")
    }

    fn prefix(cf: &str) -> String {
        format!("{cf}{CF_SEP}")
    }
}

impl Store for RocksStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) -> Result<(), crate::StoreError> {
        self.db
            .put(Self::composite(cf, key).as_bytes(), value)
            .map_err(|e| crate::StoreError(e.to_string()))
    }

    fn delete(&mut self, cf: &str, key: &str) -> Result<(), crate::StoreError> {
        self.db
            .delete(Self::composite(cf, key).as_bytes())
            .map_err(|e| crate::StoreError(e.to_string()))
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.db
            .get(Self::composite(cf, key).as_bytes())
            .ok()
            .flatten()
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        let prefix = Self::prefix(cf);
        let mut out = Vec::new();
        let iter = self
            .db
            .iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward));
        for item in iter {
            let Ok((raw_key, value)) = item else { break };
            let Ok(key) = std::str::from_utf8(&raw_key) else {
                continue;
            };
            // The iterator is ordered; once the prefix no longer matches we are
            // past this column family.
            let Some(stripped) = key.strip_prefix(&prefix) else {
                break;
            };
            out.push((stripped.to_owned(), value.to_vec()));
        }
        out
    }

    fn count(&self, cf: &str) -> usize {
        self.scan(cf).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit, cf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDb(std::path::PathBuf);
    impl TempDb {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!("gm-store-rocks-{}-{nanos}", std::process::id()));
            Self(path)
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn persists_isolates_column_families_and_orders_keys() {
        let tmp = TempDb::new();
        let mut store = RocksStore::open(&tmp.0).unwrap();
        store.put(cf::EVENTS, "00001", b"e1").unwrap();
        store.put(cf::ROOM_STATE, "00000", b"s0").unwrap();
        store.put(cf::EVENTS, "00000", b"e0").unwrap();

        assert_eq!(store.get(cf::EVENTS, "00000"), Some(b"e0".to_vec()));
        let events: Vec<_> = store.scan(cf::EVENTS).into_iter().map(|(k, _)| k).collect();
        assert_eq!(events, ["00000", "00001"]);
        assert_eq!(store.count(cf::ROOM_STATE), 1);
        assert!(store.scan("missing").is_empty());
    }

    #[test]
    fn data_survives_reopen() {
        let tmp = TempDb::new();
        {
            let mut store = RocksStore::open(&tmp.0).unwrap();
            store.put(cf::EVENTS, "k", b"v").unwrap();
        }
        // Re-open the same path: the write is durable.
        let store = RocksStore::open(&tmp.0).unwrap();
        assert_eq!(store.get(cf::EVENTS, "k"), Some(b"v".to_vec()));
    }

    #[test]
    fn audit_log_works_over_the_rocksdb_profile() {
        let tmp = TempDb::new();
        let mut store = RocksStore::open(&tmp.0).unwrap();
        audit::append(&mut store, "@a:gaussian.tech", "auto_allowed: search");
        audit::append(&mut store, "@a:gaussian.tech", "executed: search ok=true");
        assert_eq!(audit::entries(&store).len(), 2);
        assert_eq!(audit::verify(&store), Ok(()));
    }
}
