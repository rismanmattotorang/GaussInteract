// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Client sessions: access tokens ↔ users (spec §II.B).
//!
//! Logging in mints an access token bound to a user (and, later, a device); the
//! ingress presents that token on every authenticated request and the server
//! resolves it back to the user here. [`SessionStore`] persists the mapping
//! through the pluggable [`gm_store::Store`] and implements
//! [`gm_api::TokenAuthority`], so it is exactly the authority the `gm-http`
//! ingress is generic over — the seam between transport and identity.
//!
//! ## Note on token generation
//!
//! The scaffold derives tokens from a std hash of the user plus a per-store
//! counter: unique and dependency-free, but **not** unguessable. A real
//! deployment mints tokens from a CSPRNG; the storage shape and the
//! [`gm_api::TokenAuthority`] contract are unchanged either way (mirroring the
//! audit log's placeholder-hash note).

use gm_api::TokenAuthority;
use gm_store::{cf, Store};
use gm_util::UserId;
use std::hash::{Hash, Hasher};

/// Persists access-token → user mappings and validates tokens.
///
/// Stateless over its store (no in-memory counter), so several short-lived
/// `SessionStore` views over the *same* shared store stay consistent — which is
/// how the composed server constructs one per request.
#[derive(Debug)]
pub struct SessionStore<S: Store> {
    store: S,
}

impl<S: Store> SessionStore<S> {
    /// Create a session store over a storage backend.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Mint a new access token for `user`, persist the mapping, and return it.
    pub fn create(&mut self, user: &UserId) -> String {
        let token = self.mint(user);
        self.store
            .put(cf::ACCESS_TOKENS, &token, user.as_str().as_bytes());
        token
    }

    /// Revoke a token (logout): it no longer authenticates anyone.
    pub fn revoke(&mut self, token: &str) {
        self.store.delete(cf::ACCESS_TOKENS, token);
    }

    /// The user a token authenticates, if it is live.
    pub fn user_for(&self, token: &str) -> Option<UserId> {
        self.store
            .get(cf::ACCESS_TOKENS, token)
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| UserId::parse(s).ok())
    }

    /// Derive a unique (scaffold, not unguessable) token for `user`. Uniqueness
    /// comes from the live token count in the store, so it is stable across
    /// `SessionStore` instances sharing that store.
    fn mint(&mut self, user: &UserId) -> String {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        user.as_str().hash(&mut h);
        0xA7u8.hash(&mut h); // domain separator
        self.store.count(cf::ACCESS_TOKENS).hash(&mut h);
        format!("gmt_{:016x}", h.finish())
    }
}

impl<S: Store> TokenAuthority for SessionStore<S> {
    fn user_for(&self, token: &str) -> Option<UserId> {
        SessionStore::user_for(self, token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_store::MemoryStore;

    fn user(id: &str) -> UserId {
        UserId::parse(id).unwrap()
    }

    #[test]
    fn create_then_validate_round_trips_to_the_user() {
        let mut sessions = SessionStore::new(MemoryStore::default());
        let alice = user("@alice:gaussian.tech");
        let token = sessions.create(&alice);
        assert!(token.starts_with("gmt_"));
        assert_eq!(SessionStore::user_for(&sessions, &token), Some(alice));
        // The trait impl agrees with the inherent method.
        assert!(TokenAuthority::user_for(&sessions, &token).is_some());
    }

    #[test]
    fn distinct_logins_get_distinct_tokens() {
        let mut sessions = SessionStore::new(MemoryStore::default());
        let alice = user("@alice:gaussian.tech");
        let t1 = sessions.create(&alice);
        let t2 = sessions.create(&alice); // same user, second login
        assert_ne!(t1, t2);
        // Both are live and resolve to the same user.
        assert_eq!(sessions.user_for(&t1), Some(alice.clone()));
        assert_eq!(sessions.user_for(&t2), Some(alice));
    }

    #[test]
    fn revoked_token_no_longer_authenticates() {
        let mut sessions = SessionStore::new(MemoryStore::default());
        let token = sessions.create(&user("@bob:gaussian.tech"));
        sessions.revoke(&token);
        assert_eq!(sessions.user_for(&token), None);
    }

    #[test]
    fn unknown_token_is_none() {
        let sessions = SessionStore::new(MemoryStore::default());
        assert_eq!(sessions.user_for("gmt_deadbeef"), None);
    }
}
