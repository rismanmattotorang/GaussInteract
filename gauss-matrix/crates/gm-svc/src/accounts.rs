// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! User accounts and password verification (spec §II.B).
//!
//! [`AccountStore`] persists a password *verifier* per user (never the password)
//! through the pluggable [`gm_store::Store`], and checks a presented password at
//! login. The session token a successful login mints is issued by
//! [`crate::SessionStore`]; this store only answers "is this the right password
//! for this user?".
//!
//! ## Note on the password verifier
//!
//! The scaffold derives the verifier from a std hash of `user + password`:
//! dependency-free, but **not** a password-hashing function. A real deployment
//! uses a memory-hard KDF (Argon2id) with a per-user salt; the storage shape —
//! `user → verifier` in [`gm_store::cf::ACCOUNTS`] — and the [`AccountStore`]
//! API are unchanged either way (mirroring the audit log's placeholder note).

use gm_store::{cf, Store};
use gm_util::UserId;
use std::hash::{Hash, Hasher};

/// Persists per-user password verifiers and checks presented passwords.
#[derive(Debug)]
pub struct AccountStore<S: Store> {
    store: S,
}

impl<S: Store> AccountStore<S> {
    /// Create an account store over a storage backend.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Register `user` with `password` (or reset it), persisting the verifier.
    pub fn register(&mut self, user: &UserId, password: &str) {
        let verifier = verifier(user, password);
        self.store
            .put(cf::ACCOUNTS, user.as_str(), verifier.as_bytes());
    }

    /// Whether `user` exists and `password` matches its stored verifier.
    pub fn verify(&self, user: &UserId, password: &str) -> bool {
        match self.store.get(cf::ACCOUNTS, user.as_str()) {
            Some(stored) => stored == verifier(user, password).into_bytes(),
            None => false,
        }
    }

    /// Whether `user` has an account.
    pub fn exists(&self, user: &UserId) -> bool {
        self.store.get(cf::ACCOUNTS, user.as_str()).is_some()
    }
}

/// Derive the (scaffold, non-cryptographic) password verifier for a user.
fn verifier(user: &UserId, password: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    user.as_str().hash(&mut h);
    0x5Cu8.hash(&mut h); // domain separator between user (salt) and password
    password.hash(&mut h);
    format!("v1${:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_store::MemoryStore;

    fn user(id: &str) -> UserId {
        UserId::parse(id).unwrap()
    }

    #[test]
    fn verifies_the_right_password_and_rejects_others() {
        let mut accounts = AccountStore::new(MemoryStore::default());
        let alice = user("@alice:gaussian.tech");
        accounts.register(&alice, "correct horse");

        assert!(accounts.exists(&alice));
        assert!(accounts.verify(&alice, "correct horse"));
        assert!(!accounts.verify(&alice, "wrong"));
    }

    #[test]
    fn unknown_user_never_verifies() {
        let accounts = AccountStore::new(MemoryStore::default());
        assert!(!accounts.exists(&user("@nobody:gaussian.tech")));
        assert!(!accounts.verify(&user("@nobody:gaussian.tech"), "x"));
    }

    #[test]
    fn the_password_itself_is_not_stored() {
        // The verifier is a hash, not the password.
        let v = verifier(&user("@alice:gaussian.tech"), "s3cret-passphrase");
        assert!(!v.contains("s3cret-passphrase"));
        assert!(v.starts_with("v1$"));
    }

    #[test]
    fn re_registering_updates_the_verifier() {
        let mut accounts = AccountStore::new(MemoryStore::default());
        let alice = user("@alice:gaussian.tech");
        accounts.register(&alice, "old");
        accounts.register(&alice, "new");
        assert!(!accounts.verify(&alice, "old"));
        assert!(accounts.verify(&alice, "new"));
    }
}
