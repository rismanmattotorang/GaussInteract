// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A cloneable, thread-safe shared in-memory [`Store`] handle.
//!
//! The composed homeserver gives each of its sub-services (accounts, sessions,
//! rooms) a handle to *one* dataset. [`SharedStore`] is that handle: cloning it
//! shares the underlying data (an `Arc<RwLock<…>>`), and `&mut`-taking
//! [`Store`] writes go through the lock, so a `&self` service can still mutate
//! the shared state.
//!
//! It is **thread-safe** (`Arc<RwLock<…>>`): reads ([`Store::get`],
//! [`Store::scan`], [`Store::count`]) take a shared read lock and writes
//! ([`Store::put`], [`Store::delete`]) an exclusive write lock, so the handle
//! can be shared across the transport's connection threads. Each call locks
//! independently — there is no cross-call atomicity, so a sequence of reads then
//! a write (as a service method does) is not serialised against concurrent
//! writers; per-room serialisation is a later refinement. A lock poisoned by a
//! panicking thread is recovered rather than propagated, so one bad request
//! cannot wedge the store.

use crate::{MemoryStore, Store};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A cloneable, thread-safe handle to a shared in-memory store.
#[derive(Debug, Clone, Default)]
pub struct SharedStore(Arc<RwLock<MemoryStore>>);

impl SharedStore {
    /// A new, empty shared store.
    pub fn new() -> Self {
        Self::default()
    }

    /// A read guard, recovering the inner value if a writer panicked.
    fn read(&self) -> RwLockReadGuard<'_, MemoryStore> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// A write guard, recovering the inner value if a writer panicked.
    fn write(&self) -> RwLockWriteGuard<'_, MemoryStore> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store for SharedStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) -> Result<(), crate::StoreError> {
        self.write().put(cf, key, value)
    }

    fn delete(&mut self, cf: &str, key: &str) -> Result<(), crate::StoreError> {
        self.write().delete(cf, key)
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.read().get(cf, key)
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        self.read().scan(cf)
    }

    fn count(&self, cf: &str) -> usize {
        self.read().count(cf)
    }

    fn scan_paged(&self, cf: &str, after: Option<&str>, limit: usize) -> Vec<(String, Vec<u8>)> {
        self.read().scan_paged(cf, after, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cf;

    #[test]
    fn clones_share_one_dataset() {
        let a = SharedStore::new();
        let mut b = a.clone();
        b.put(cf::EVENTS, "k", b"v").unwrap();
        // The write through `b` is visible through `a` — same underlying data.
        assert_eq!(a.get(cf::EVENTS, "k"), Some(b"v".to_vec()));
        assert_eq!(a.count(cf::EVENTS), 1);
        b.delete(cf::EVENTS, "k").unwrap();
        assert_eq!(a.get(cf::EVENTS, "k"), None);
    }

    #[test]
    fn concurrent_writers_share_the_store_safely() {
        // The handle is Send + Sync: many threads write into one dataset and
        // every write is observed, with no data races.
        let store = SharedStore::new();
        let mut handles = Vec::new();
        for t in 0..8 {
            let mut store = store.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..100 {
                    store.put(cf::EVENTS, &format!("{t}-{i}"), b"v").unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.count(cf::EVENTS), 8 * 100);
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn shared_store_is_send_and_sync() {
        assert_send_sync::<SharedStore>();
    }
}
