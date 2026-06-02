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
use gm_api::events;
use gm_api::{
    Json, Login, LoginGrant, MessageSender, Pdu, RoomCreator, RoomReader, RoomTimeline,
    RoomVersion, TokenAuthority,
};
use gm_store::{cf, Store};
use gm_util::{EventId, RoomId, UserId};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

/// Delimiter for the `(sender, txn_id)` transaction key.
const TXN_SEP: char = '\u{1f}';

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

    /// The room's timeline, oldest first.
    pub fn timeline(&self, room: &RoomId) -> Vec<Pdu> {
        RoomService::new(self.store.clone()).timeline(room)
    }

    /// Mint a fresh room id on this server. Uniqueness (scaffold) comes from the
    /// creator, the live event count and the clock; production uses a CSPRNG.
    fn mint_room_id(&self, creator: &UserId) -> Option<RoomId> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        creator.as_str().hash(&mut h);
        self.store.count(cf::EVENTS).hash(&mut h);
        now_ms().hash(&mut h);
        RoomId::parse(format!("!{:016x}:{}", h.finish(), self.server_name)).ok()
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

impl<S: Store + Clone> RoomTimeline for GaussServer<S> {
    fn room_timeline(&self, room: &RoomId) -> Vec<Pdu> {
        self.timeline(room)
    }
}

impl<S: Store + Clone> RoomCreator for GaussServer<S> {
    fn create_room(
        &self,
        creator: &UserId,
        name: Option<&str>,
        topic: Option<&str>,
    ) -> Option<RoomId> {
        let room = self.mint_room_id(creator)?;

        // The canonical initial state of a new room, in order: create,
        // the creator's join, power levels, then the optional name/topic.
        let mut events: Vec<(&'static str, String, String)> = vec![
            (events::ROOM_CREATE, String::new(), create_content(creator)),
            (
                events::ROOM_MEMBER,
                creator.as_str().to_owned(),
                member_join_content(),
            ),
            (
                events::ROOM_POWER_LEVELS,
                String::new(),
                power_levels_content(creator),
            ),
        ];
        if let Some(name) = name {
            events.push((events::ROOM_NAME, String::new(), single_field("name", name)));
        }
        if let Some(topic) = topic {
            events.push((
                events::ROOM_TOPIC,
                String::new(),
                single_field("topic", topic),
            ));
        }

        let mut rooms = RoomService::new(self.store.clone());
        let mut prev_events: Vec<EventId> = Vec::new();
        for (i, (kind, state_key, content)) in events.into_iter().enumerate() {
            let depth = i as u64 + 1;
            let event_id = EventId::parse(mint_state_event_id(&room, kind, depth)).ok()?;
            let pdu = Pdu {
                event_id: event_id.clone(),
                room_id: room.clone(),
                sender: creator.clone(),
                kind: kind.to_owned(),
                state_key: Some(state_key),
                origin_server_ts: now_ms(),
                depth,
                prev_events,
                auth_events: Vec::new(),
                content_json: content,
            };
            rooms.append(&pdu);
            prev_events = vec![event_id];
        }
        Some(room)
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

impl<S: Store + Clone> MessageSender for GaussServer<S> {
    fn send_message(
        &self,
        sender: &UserId,
        room: &RoomId,
        event_type: &str,
        txn_id: &str,
        content: &str,
    ) -> Option<String> {
        // Idempotency: a repeated (sender, txn_id) returns the original event,
        // never a duplicate (Matrix transaction identifiers).
        let txn_key = format!("{}{TXN_SEP}{}", sender.as_str(), txn_id);
        if let Some(existing) = self.store.get(cf::TRANSACTIONS, &txn_key) {
            return String::from_utf8(existing).ok();
        }

        let mut rooms = RoomService::new(self.store.clone());
        // Link the new event onto the current linear tip of the room DAG.
        let (depth, prev_events) = match rooms.timeline(room).last() {
            Some(tip) => (tip.depth + 1, vec![tip.event_id.clone()]),
            None => (1, Vec::new()),
        };
        let event_id = mint_event_id(room, sender, txn_id, depth);
        let pdu = Pdu {
            event_id: EventId::parse(event_id.clone()).ok()?,
            room_id: room.clone(),
            sender: sender.clone(),
            kind: event_type.to_owned(),
            state_key: None, // a message event, not state
            origin_server_ts: now_ms(),
            depth,
            prev_events,
            auth_events: Vec::new(),
            content_json: content.to_owned(),
        };
        rooms.append(&pdu);

        // Record the transaction so a retry is idempotent.
        let mut store = self.store.clone();
        store.put(cf::TRANSACTIONS, &txn_key, event_id.as_bytes());
        Some(event_id)
    }
}

/// Milliseconds since the Unix epoch (the event's `origin_server_ts`).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Derive a (scaffold, deterministic) event id for a send. Production derives
/// the event id by hashing the event per the room version; this keeps the
/// dependency-free placeholder consistent with the rest of the scaffold.
fn mint_event_id(room: &RoomId, sender: &UserId, txn_id: &str, depth: u64) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    room.as_str().hash(&mut h);
    sender.as_str().hash(&mut h);
    txn_id.hash(&mut h);
    depth.hash(&mut h);
    format!("${:016x}", h.finish())
}

/// Derive a (scaffold) event id for a created room's initial state event.
fn mint_state_event_id(room: &RoomId, kind: &str, depth: u64) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    room.as_str().hash(&mut h);
    kind.hash(&mut h);
    depth.hash(&mut h);
    format!("${:016x}", h.finish())
}

/// `m.room.create` content: the creator and the room version.
fn create_content(creator: &UserId) -> String {
    let mut o = BTreeMap::new();
    o.insert(
        "creator".to_owned(),
        Json::String(creator.as_str().to_owned()),
    );
    o.insert(
        "room_version".to_owned(),
        Json::String(RoomVersion::MAX_SUPPORTED.to_string()),
    );
    Json::Object(o).to_string()
}

/// `m.room.member` content for a join.
fn member_join_content() -> String {
    single_field("membership", "join")
}

/// `m.room.power_levels` content granting the creator full power.
fn power_levels_content(creator: &UserId) -> String {
    let mut users = BTreeMap::new();
    users.insert(creator.as_str().to_owned(), Json::Number(100.0));
    let mut o = BTreeMap::new();
    o.insert("users".to_owned(), Json::Object(users));
    o.insert("users_default".to_owned(), Json::Number(0.0));
    Json::Object(o).to_string()
}

/// A one-field object, e.g. `{"name":"Ops"}`.
fn single_field(field: &str, value: &str) -> String {
    let mut o = BTreeMap::new();
    o.insert(field.to_owned(), Json::String(value.to_owned()));
    Json::Object(o).to_string()
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
    fn create_room_writes_the_canonical_initial_state() {
        let s = server();
        let creator = UserId::parse("@alice:gaussian.tech").unwrap();
        let room = s
            .create_room(&creator, Some("Ops"), Some("On-call"))
            .expect("room created");
        assert!(room.as_str().starts_with("!"));
        assert!(room.as_str().ends_with(":gaussian.tech"));

        // create + member + power_levels + name + topic, linked in a chain.
        let timeline = s.timeline(&room);
        assert_eq!(timeline.len(), 5);
        assert_eq!(timeline[0].kind, events::ROOM_CREATE);
        assert_eq!(timeline[1].kind, events::ROOM_MEMBER);
        assert_eq!(timeline[1].state_key.as_deref(), Some(creator.as_str()));
        assert_eq!(timeline[2].kind, events::ROOM_POWER_LEVELS);
        assert_eq!(timeline[1].prev_events, vec![timeline[0].event_id.clone()]);

        // The state map is readable: the creator has joined and name is set.
        assert_eq!(
            s.room_state_content(&room, events::ROOM_NAME, ""),
            Some(r#"{"name":"Ops"}"#.to_owned())
        );
        let member = s
            .room_state_content(&room, events::ROOM_MEMBER, creator.as_str())
            .unwrap();
        assert!(member.contains("\"membership\":\"join\""));
    }

    #[test]
    fn create_room_without_name_or_topic_writes_three_events() {
        let s = server();
        let creator = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&creator, None, None).unwrap();
        assert_eq!(s.timeline(&room).len(), 3); // create + member + power_levels
        assert_eq!(s.room_state_content(&room, events::ROOM_NAME, ""), None);
    }

    #[test]
    fn distinct_create_calls_make_distinct_rooms() {
        let s = server();
        let creator = UserId::parse("@alice:gaussian.tech").unwrap();
        let r1 = s.create_room(&creator, None, None).unwrap();
        let r2 = s.create_room(&creator, None, None).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn send_message_appends_once_and_is_idempotent_on_txn_id() {
        let s = server();
        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        let sender = UserId::parse("@alice:gaussian.tech").unwrap();

        let id1 = s
            .send_message(
                &sender,
                &room,
                events::ROOM_MESSAGE,
                "txn1",
                r#"{"body":"hi"}"#,
            )
            .unwrap();
        // A retry with the same txn id returns the original event, no duplicate.
        let retry = s
            .send_message(
                &sender,
                &room,
                events::ROOM_MESSAGE,
                "txn1",
                r#"{"body":"hi"}"#,
            )
            .unwrap();
        assert_eq!(id1, retry);
        assert_eq!(s.timeline(&room).len(), 1);

        // A new txn id produces a new event, linked onto the tip.
        let id2 = s
            .send_message(
                &sender,
                &room,
                events::ROOM_MESSAGE,
                "txn2",
                r#"{"body":"yo"}"#,
            )
            .unwrap();
        assert_ne!(id1, id2);
        let timeline = s.timeline(&room);
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[1].prev_events, vec![timeline[0].event_id.clone()]);
        assert_eq!(timeline[1].content_json, r#"{"body":"yo"}"#);
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
