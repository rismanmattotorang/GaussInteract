// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The composed homeserver service (spec §III.B).
//!
//! [`GaussServer`] ties the sub-services — accounts, sessions, rooms — over a
//! single shared store into one object implementing the full
//! [`gm_api::Homeserver`] seam the `gm-http` ingress drives. It is the assembly
//! point: `Ingress::with_server(GaussServer::new(store, server_name))` is a
//! homeserver answering real requests against real state.
//!
//! Each capability constructs a short-lived sub-service view over a clone of the
//! shared store handle, so a `&self` trait method (e.g. login minting a token)
//! still mutates the one shared dataset. Use a cloneable store such as
//! [`gm_store::SharedStore`].

use crate::{AccountStore, RoomService, SessionStore};
use gm_api::{Login, LoginGrant, Pdu, RoomReader, TokenAuthority};
use gm_store::Store;
use gm_util::{RoomId, UserId};

/// The composed homeserver: one shared store, one server name, all services.
#[derive(Debug, Clone)]
pub struct GaussServer<S: Store + Clone> {
    store: S,
    server_name: String,
}

impl<S: Store + Clone> GaussServer<S> {
    /// Compose a homeserver over `store`, hosting users on `server_name`.
    pub fn new(store: S, server_name: impl Into<String>) -> Self {
        Self {
            store,
            server_name: server_name.into(),
        }
    }

    /// The server name this homeserver hosts users on.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Register (or reset) an account, returning the full user id. Setup helper
    /// for provisioning users; the password is verified at login.
    pub fn register_account(&self, localpart: &str, password: &str) -> Option<UserId> {
        let user = self.full_user_id(localpart)?;
        AccountStore::new(self.store.clone()).register(&user, password);
        Some(user)
    }

    /// Append an event to a room (setup / federation ingress).
    pub fn append_event(&self, pdu: &Pdu) {
        RoomService::new(self.store.clone()).append(pdu);
    }

    /// Resolve a login `user` field — a bare localpart (`alice`) or a full id
    /// (`@alice:server`) — to a validated [`UserId`] on this server.
    fn full_user_id(&self, user: &str) -> Option<UserId> {
        if user.starts_with('@') {
            UserId::parse(user).ok()
        } else {
            UserId::parse(format!("@{user}:{}", self.server_name)).ok()
        }
    }
}

impl<S: Store + Clone> TokenAuthority for GaussServer<S> {
    fn user_for(&self, token: &str) -> Option<UserId> {
        SessionStore::new(self.store.clone()).user_for(token)
    }
}

impl<S: Store + Clone> RoomReader for GaussServer<S> {
    fn room_state_content(
        &self,
        room: &RoomId,
        event_type: &str,
        state_key: &str,
    ) -> Option<String> {
        RoomService::new(self.store.clone()).state_event_content(room, event_type, state_key)
    }
}

impl<S: Store + Clone> Login for GaussServer<S> {
    fn password_login(&self, localpart: &str, password: &str) -> Option<LoginGrant> {
        let user = self.full_user_id(localpart)?;
        if !AccountStore::new(self.store.clone()).verify(&user, password) {
            return None;
        }
        let access_token = SessionStore::new(self.store.clone()).create(&user);
        Some(LoginGrant {
            user_id: user,
            access_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_api::events;
    use gm_store::SharedStore;

    fn server() -> GaussServer<SharedStore> {
        GaussServer::new(SharedStore::new(), "gaussian.tech")
    }

    #[test]
    fn login_mints_a_token_that_then_authenticates() {
        let s = server();
        s.register_account("alice", "pw");

        let grant = s
            .password_login("alice", "pw")
            .expect("correct credentials");
        assert_eq!(grant.user_id.as_str(), "@alice:gaussian.tech");
        // The minted token validates back to the same user — over the one store.
        assert_eq!(s.user_for(&grant.access_token), Some(grant.user_id));
    }

    #[test]
    fn wrong_password_and_unknown_user_do_not_login() {
        let s = server();
        s.register_account("alice", "pw");
        assert!(s.password_login("alice", "nope").is_none());
        assert!(s.password_login("mallory", "pw").is_none());
    }

    #[test]
    fn full_user_id_login_field_is_accepted() {
        let s = server();
        s.register_account("alice", "pw");
        assert!(s.password_login("@alice:gaussian.tech", "pw").is_some());
    }

    #[test]
    fn distinct_logins_mint_distinct_tokens_over_the_shared_store() {
        let s = server();
        s.register_account("alice", "pw");
        let t1 = s.password_login("alice", "pw").unwrap().access_token;
        let t2 = s.password_login("alice", "pw").unwrap().access_token;
        assert_ne!(t1, t2);
        assert!(s.user_for(&t1).is_some());
        assert!(s.user_for(&t2).is_some());
    }

    #[test]
    fn room_state_reads_through_the_composed_server() {
        let s = server();
        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        let name = Pdu {
            event_id: gm_util::EventId::parse("$n").unwrap(),
            room_id: room.clone(),
            sender: UserId::parse("@alice:gaussian.tech").unwrap(),
            kind: events::ROOM_NAME.to_owned(),
            state_key: Some(String::new()),
            origin_server_ts: 1,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{\"name\":\"Ops\"}".to_owned(),
        };
        s.append_event(&name);

        assert_eq!(
            s.room_state_content(&room, events::ROOM_NAME, ""),
            Some("{\"name\":\"Ops\"}".to_owned())
        );
        assert_eq!(s.room_state_content(&room, events::ROOM_TOPIC, ""), None);
    }
}
