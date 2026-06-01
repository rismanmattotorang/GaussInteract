// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A cloneable, shared in-memory [`Store`] handle.
//!
//! The composed homeserver gives each of its sub-services (accounts, sessions,
//! rooms) a handle to *one* dataset. [`SharedStore`] is that handle: cloning it
//! shares the underlying data (an `Rc<RefCell<…>>`), and `&mut`-taking
//! [`Store`] writes go through the cell, so a `&self` service can still mutate
//! the shared state.
//!
//! It is single-threaded (`Rc`), matching the std-only scaffold; the live server
//! uses a thread-safe handle (an `Arc`-wrapped backend behind a connection pool
//! or lock). The [`Store`] contract is identical either way.

use crate::{MemoryStore, Store};
use std::cell::RefCell;
use std::rc::Rc;

/// A cloneable handle to a shared in-memory store.
#[derive(Debug, Clone, Default)]
pub struct SharedStore(Rc<RefCell<MemoryStore>>);

impl SharedStore {
    /// A new, empty shared store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for SharedStore {
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) {
        self.0.borrow_mut().put(cf, key, value);
    }

    fn delete(&mut self, cf: &str, key: &str) {
        self.0.borrow_mut().delete(cf, key);
    }

    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>> {
        self.0.borrow().get(cf, key)
    }

    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)> {
        self.0.borrow().scan(cf)
    }

    fn count(&self, cf: &str) -> usize {
        self.0.borrow().count(cf)
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
        b.put(cf::EVENTS, "k", b"v");
        // The write through `b` is visible through `a` — same underlying data.
        assert_eq!(a.get(cf::EVENTS, "k"), Some(b"v".to_vec()));
        assert_eq!(a.count(cf::EVENTS), 1);
        b.delete(cf::EVENTS, "k");
        assert_eq!(a.get(cf::EVENTS, "k"), None);
    }
}
