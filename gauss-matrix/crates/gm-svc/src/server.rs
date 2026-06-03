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
    FederationAuth, FederationReceiver, JoinedRoom, Json, Login, LoginGrant, MembershipChanger,
    MessageSender, Pdu, RoomCreator, RoomReader, RoomTimeline, RoomVersion, SyncProvider, SyncView,
    TokenAuthority,
};
use gm_fed::{auth as fed_auth, Transaction};
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

    /// Register `origin`'s federation signing key, so requests it signs verify.
    /// Setup/operational helper standing in for the published-key fetch.
    pub fn register_federation_key(&self, origin: &str, key: &str) {
        let mut store = self.store.clone();
        store.put(cf::FEDERATION_KEYS, origin, key.as_bytes());
    }

    /// The registered federation key for `origin`, if any.
    fn federation_key(&self, origin: &str) -> Option<String> {
        self.store
            .get(cf::FEDERATION_KEYS, origin)
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// The room's timeline, oldest first.
    pub fn timeline(&self, room: &RoomId) -> Vec<Pdu> {
        RoomService::new(self.store.clone()).timeline(room)
    }

    /// Whether `user`'s current `m.room.member` state in `room` is `join`.
    fn is_joined(&self, rooms: &RoomService<S>, room: &RoomId, user: &UserId) -> bool {
        let Some(content) = rooms.state_event_content(room, events::ROOM_MEMBER, user.as_str())
        else {
            return false;
        };
        Json::parse(&content)
            .ok()
            .and_then(|c| {
                c.get("membership")
                    .and_then(Json::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("join")
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

    fn room_state(&self, room: &RoomId) -> Vec<Pdu> {
        RoomService::new(self.store.clone()).current_state_pdus(room)
    }
}

impl<S: Store + Clone> RoomTimeline for GaussServer<S> {
    fn room_timeline(&self, room: &RoomId) -> Vec<Pdu> {
        self.timeline(room)
    }
}

impl<S: Store + Clone> SyncProvider for GaussServer<S> {
    fn sync(&self, user: &UserId, since: Option<&str>) -> SyncView {
        let rooms = RoomService::new(self.store.clone());
        let next_batch = format!("s{}", rooms.stream_len());

        // A `since` token of the form "s{N}" requests an incremental sync from
        // stream position N; anything else (absent or malformed) is initial sync.
        let from = since
            .and_then(|t| t.strip_prefix('s'))
            .and_then(|n| n.parse::<usize>().ok());

        let (joined, left) = match from {
            None => {
                // Initial sync: every joined room, full state + timeline. (A
                // `leave` section is only meaningful relative to a prior token.)
                let joined = rooms
                    .rooms()
                    .into_iter()
                    .filter(|room| self.is_joined(&rooms, room, user))
                    .map(|room| JoinedRoom {
                        state: rooms.current_state_pdus(&room),
                        timeline: rooms.timeline(&room),
                        room,
                    })
                    .collect();
                (joined, Vec::new())
            }
            Some(pos) => {
                // The events that arrived since the token, grouped per room.
                let mut by_room: std::collections::BTreeMap<String, Vec<Pdu>> =
                    std::collections::BTreeMap::new();
                for pdu in rooms.events_since(pos) {
                    by_room
                        .entry(pdu.room_id.as_str().to_owned())
                        .or_default()
                        .push(pdu);
                }

                let mut joined = Vec::new();
                let mut left = Vec::new();
                for (room_str, timeline) in by_room {
                    let Ok(room) = RoomId::parse(room_str) else {
                        continue;
                    };
                    if self.is_joined(&rooms, &room, user) {
                        // If the user's own join lands within this delta they are
                        // seeing the room for the first time, so carry its full
                        // current state (as an initial sync would) rather than only
                        // the state events in the window. Otherwise the client
                        // already holds the prior state, so the delta's state events
                        // suffice.
                        let state = if joined_in_delta(&timeline, user) {
                            rooms.current_state_pdus(&room)
                        } else {
                            timeline.iter().filter(|p| p.is_state()).cloned().collect()
                        };
                        joined.push(JoinedRoom {
                            room,
                            state,
                            timeline,
                        });
                    } else if left_in_delta(&timeline, user) {
                        // The user's own membership became `leave`/`ban` in this
                        // window: report the room as left so the client drops it.
                        left.push(gm_api::LeftRoom { room, timeline });
                    }
                }
                (joined, left)
            }
        };

        SyncView {
            next_batch,
            joined,
            left,
        }
    }
}

impl<S: Store + Clone> FederationReceiver for GaussServer<S> {
    fn receive_transaction(&self, txn: &Json) -> Json {
        let mut results = BTreeMap::new();
        if let Ok(transaction) = Transaction::from_json(txn) {
            let mut rooms = RoomService::new(self.store.clone());
            // Process PDUs in order: each accepted event updates room state, so a
            // later event in the same transaction authorizes against it.
            for pdu in &transaction.pdus {
                let state = rooms.current_state_pdus(&pdu.room_id);
                let outcome = match gm_stateres::auth::check_auth(pdu, &state) {
                    Ok(()) => {
                        rooms.append(pdu);
                        Json::Object(BTreeMap::new())
                    }
                    Err(_) => {
                        // The PDU is not authorized by room state; reject it (the
                        // per-event ack carries the error, the spec's shape for a
                        // rejected event).
                        let mut err = BTreeMap::new();
                        err.insert(
                            "error".to_owned(),
                            Json::String("event not authorized by room state".to_owned()),
                        );
                        Json::Object(err)
                    }
                };
                results.insert(pdu.event_id.as_str().to_owned(), outcome);
            }
        }
        let mut obj = BTreeMap::new();
        obj.insert("pdus".to_owned(), Json::Object(results));
        Json::Object(obj)
    }
}

impl<S: Store + Clone> FederationAuth for GaussServer<S> {
    fn verify_federation_request(
        &self,
        method: &str,
        uri: &str,
        content: Option<&str>,
        authorization: Option<&str>,
    ) -> bool {
        let Some(auth) = authorization.and_then(fed_auth::XMatrixAuth::parse) else {
            return false;
        };
        // The signature must name this server as its destination (anti-replay
        // across servers); reject if it targets someone else.
        if let Some(destination) = &auth.destination {
            if destination != &self.server_name {
                return false;
            }
        }
        let Some(key) = self.federation_key(&auth.origin) else {
            return false; // origin's key is unknown -> cannot verify
        };
        let bytes = fed_auth::signing_bytes(method, uri, &auth.origin, &self.server_name, content);
        fed_auth::verify(&bytes, &auth.signature, &key)
    }
}

impl<S: Store + Clone> MembershipChanger for GaussServer<S> {
    fn change_membership(
        &self,
        actor: &UserId,
        room: &RoomId,
        target: &UserId,
        membership: &str,
    ) -> Option<String> {
        let mut rooms = RoomService::new(self.store.clone());
        let (depth, prev_events) = match rooms.timeline(room).last() {
            Some(tip) => (tip.depth + 1, vec![tip.event_id.clone()]),
            None => (1, Vec::new()),
        };
        let event_id = mint_state_event_id(room, events::ROOM_MEMBER, depth);
        let pdu = Pdu {
            event_id: EventId::parse(event_id.clone()).ok()?,
            room_id: room.clone(),
            sender: actor.clone(),
            kind: events::ROOM_MEMBER.to_owned(),
            state_key: Some(target.as_str().to_owned()),
            origin_server_ts: now_ms(),
            depth,
            prev_events,
            auth_events: Vec::new(),
            content_json: single_field("membership", membership),
        };
        // Authorize the transition against the join-rules / invite / power-level
        // state machine before accepting it.
        if gm_stateres::auth::check_auth(&pdu, &rooms.current_state_pdus(room)).is_err() {
            return None;
        }
        rooms.append(&pdu);
        Some(event_id)
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
        // Authorize the event against current room state before accepting it: a
        // non-member (or insufficiently-powered sender) cannot send.
        if gm_stateres::auth::check_auth(&pdu, &rooms.current_state_pdus(room)).is_err() {
            return None;
        }
        rooms.append(&pdu);

        // Record the transaction so a retry is idempotent.
        let mut store = self.store.clone();
        store.put(cf::TRANSACTIONS, &txn_key, event_id.as_bytes());
        Some(event_id)
    }
}

/// Whether `user`'s own membership becomes `join` within `delta` — i.e. their
/// join landed in this sync window, so they are seeing the room for the first
/// time and the incremental sync should carry its full current state.
fn joined_in_delta(delta: &[Pdu], user: &UserId) -> bool {
    delta.iter().any(|pdu| {
        pdu.kind == events::ROOM_MEMBER
            && pdu.state_key.as_deref() == Some(user.as_str())
            && Json::parse(&pdu.content_json)
                .ok()
                .and_then(|c| {
                    c.get("membership")
                        .and_then(Json::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("join")
    })
}

/// Whether `user`'s own membership becomes `leave` or `ban` within `delta` —
/// i.e. they left (or were kicked/banned) in this sync window, so it belongs in
/// the `leave` section.
fn left_in_delta(delta: &[Pdu], user: &UserId) -> bool {
    delta.iter().any(|pdu| {
        pdu.kind == events::ROOM_MEMBER
            && pdu.state_key.as_deref() == Some(user.as_str())
            && matches!(
                Json::parse(&pdu.content_json)
                    .ok()
                    .and_then(|c| c
                        .get("membership")
                        .and_then(Json::as_str)
                        .map(str::to_owned))
                    .as_deref(),
                Some("leave") | Some("ban")
            )
    })
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
    fn sync_reports_joined_rooms_with_state_and_timeline() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let bob = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();
        s.send_message(
            &alice,
            &room,
            events::ROOM_MESSAGE,
            "t1",
            r#"{"body":"hi"}"#,
        )
        .unwrap();

        // Alice (the creator, joined) sees the room; Bob (not a member) does not.
        let view = s.sync(&alice, None);
        assert_eq!(view.joined.len(), 1);
        assert!(s.sync(&bob, None).joined.is_empty());

        let jr = &view.joined[0];
        assert_eq!(jr.room, room);
        // State carries the create/member/power-levels/name events.
        assert!(jr.state.iter().any(|p| p.kind == events::ROOM_CREATE));
        assert!(jr.state.iter().any(|p| p.kind == events::ROOM_NAME));
        // Timeline carries the message that was sent.
        assert!(jr.timeline.iter().any(|p| p.kind == events::ROOM_MESSAGE));
        assert!(view.next_batch.starts_with('s'));
    }

    #[test]
    fn incremental_sync_returns_only_events_after_the_token() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();

        // Take a token after creation; nothing new since then.
        let token = s.sync(&alice, None).next_batch;
        assert!(s.sync(&alice, Some(&token)).joined.is_empty());

        // Send two messages, then sync incrementally from the token.
        s.send_message(
            &alice,
            &room,
            events::ROOM_MESSAGE,
            "t1",
            r#"{"body":"one"}"#,
        )
        .unwrap();
        s.send_message(
            &alice,
            &room,
            events::ROOM_MESSAGE,
            "t2",
            r#"{"body":"two"}"#,
        )
        .unwrap();

        let delta = s.sync(&alice, Some(&token));
        assert_eq!(delta.joined.len(), 1);
        let jr = &delta.joined[0];
        // Only the two new messages — not the creation events.
        assert_eq!(jr.timeline.len(), 2);
        assert!(jr.timeline.iter().all(|p| p.kind == events::ROOM_MESSAGE));
        // Catching up to the new token yields an empty delta again.
        assert!(s.sync(&alice, Some(&delta.next_batch)).joined.is_empty());
    }

    #[test]
    fn incremental_sync_carries_full_state_when_the_user_first_joins() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let bob = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();

        // Bob takes a token before he is in the room, then alice invites him.
        let token = s.sync(&bob, None).next_batch;
        s.change_membership(&alice, &room, &bob, "invite").unwrap();
        s.change_membership(&bob, &room, &bob, "join").unwrap();
        s.send_message(&bob, &room, events::ROOM_MESSAGE, "t1", r#"{"body":"hi"}"#)
            .unwrap();

        // Bob's first incremental sync after joining must carry the room's full
        // current state (create / power levels / members), not just the invite +
        // join state events that happen to fall in the window — he has never
        // seen the prior state.
        let delta = s.sync(&bob, Some(&token));
        assert_eq!(delta.joined.len(), 1);
        let jr = &delta.joined[0];
        assert_eq!(jr.room, room);
        assert!(jr.state.iter().any(|p| p.kind == events::ROOM_CREATE));
        assert!(jr.state.iter().any(|p| p.kind == events::ROOM_POWER_LEVELS));
        // Full state includes both members (alice's create-time join + bob's).
        let joins = jr
            .state
            .iter()
            .filter(|p| p.kind == events::ROOM_MEMBER)
            .count();
        assert_eq!(joins, 2);

        // A later incremental sync (no new join) carries only the delta's state.
        let token2 = delta.next_batch;
        s.send_message(
            &alice,
            &room,
            events::ROOM_MESSAGE,
            "t2",
            r#"{"body":"yo"}"#,
        )
        .unwrap();
        let delta2 = s.sync(&bob, Some(&token2));
        assert_eq!(delta2.joined.len(), 1);
        // Only the new message arrived; it is not a state event, so no full state.
        assert!(delta2.joined[0].state.is_empty());
        assert_eq!(delta2.joined[0].timeline.len(), 1);
    }

    #[test]
    fn incremental_sync_reports_a_room_the_user_left_in_the_window() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let bob = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();
        s.change_membership(&alice, &room, &bob, "invite").unwrap();
        s.change_membership(&bob, &room, &bob, "join").unwrap();

        // Bob, now a member, takes a token; then alice kicks him (sets leave).
        let token = s.sync(&bob, None).next_batch;
        s.change_membership(&alice, &room, &bob, "leave").unwrap();

        let delta = s.sync(&bob, Some(&token));
        // The room he left is not in `joined`, but is reported in `left`.
        assert!(delta.joined.is_empty());
        assert_eq!(delta.left.len(), 1);
        assert_eq!(delta.left[0].room, room);
        // The window carries the membership change that removed him.
        assert!(
            delta.left[0]
                .timeline
                .iter()
                .any(|p| p.kind == events::ROOM_MEMBER
                    && p.state_key.as_deref() == Some(bob.as_str()))
        );

        // After catching up, the left room no longer appears at all.
        let after = s.sync(&bob, Some(&delta.next_batch));
        assert!(after.joined.is_empty());
        assert!(after.left.is_empty());
    }

    #[test]
    fn verify_federation_request_checks_the_signature_against_the_registered_key() {
        let s = GaussServer::new(SharedStore::new(), "b.tld");
        s.register_federation_key("a.tld", "a-key");

        let uri = "/_matrix/federation/v1/send/t1";
        let body = r#"{"pdus":[]}"#;
        let bytes = gm_fed::auth::signing_bytes("PUT", uri, "a.tld", "b.tld", Some(body));
        let good = gm_fed::auth::XMatrixAuth {
            origin: "a.tld".to_owned(),
            destination: Some("b.tld".to_owned()),
            key_id: "ed25519:1".to_owned(),
            signature: gm_fed::auth::sign(&bytes, "a-key"),
        }
        .to_header();

        // A correctly-signed request from a known origin verifies.
        assert!(s.verify_federation_request("PUT", uri, Some(body), Some(&good)));
        // No header, an unknown origin, a wrong destination, or a bad signature fail.
        assert!(!s.verify_federation_request("PUT", uri, Some(body), None));
        let wrong_sig = gm_fed::auth::XMatrixAuth {
            origin: "a.tld".to_owned(),
            destination: Some("b.tld".to_owned()),
            key_id: "ed25519:1".to_owned(),
            signature: gm_fed::auth::sign(&bytes, "wrong-key"),
        }
        .to_header();
        assert!(!s.verify_federation_request("PUT", uri, Some(body), Some(&wrong_sig)));
        let unknown_origin = gm_fed::auth::XMatrixAuth {
            origin: "evil.tld".to_owned(),
            destination: Some("b.tld".to_owned()),
            key_id: "ed25519:1".to_owned(),
            signature: gm_fed::auth::sign(&bytes, "a-key"),
        }
        .to_header();
        assert!(!s.verify_federation_request("PUT", uri, Some(body), Some(&unknown_origin)));
    }

    #[test]
    fn receive_transaction_authorizes_and_ingests_a_federated_room() {
        let s = server();
        let room = RoomId::parse("!shared:other.tld").unwrap();
        let bob = "@bob:other.tld";
        let mut txn = gm_fed::Transaction::new("other.tld", 1700);
        // A self-consistent federated history: create, the creator's join, then a
        // message — each authorizes against the state the prior events establish.
        let fed = |id: &str, kind: &str, state_key: Option<&str>, content: &str, depth: u64| Pdu {
            event_id: EventId::parse(id).unwrap(),
            room_id: room.clone(),
            sender: UserId::parse(bob).unwrap(),
            kind: kind.to_owned(),
            state_key: state_key.map(str::to_owned),
            origin_server_ts: depth,
            depth,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: content.to_owned(),
        };
        txn.pdus.push(fed(
            "$c",
            events::ROOM_CREATE,
            Some(""),
            r#"{"creator":"@bob:other.tld"}"#,
            1,
        ));
        txn.pdus.push(fed(
            "$m",
            events::ROOM_MEMBER,
            Some(bob),
            r#"{"membership":"join"}"#,
            2,
        ));
        txn.pdus.push(fed(
            "$msg",
            events::ROOM_MESSAGE,
            None,
            r#"{"body":"from afar"}"#,
            3,
        ));

        let result = s.receive_transaction(&txn.to_json());
        // Every event was authorized (its ack is the empty object, no "error").
        for id in ["$c", "$m", "$msg"] {
            let ack = result.get("pdus").and_then(|p| p.get(id)).unwrap();
            assert!(ack.get("error").is_none(), "{id} should be accepted");
        }
        // All three landed in the room timeline.
        assert_eq!(s.timeline(&room).len(), 3);
    }

    #[test]
    fn receive_transaction_rejects_an_unauthorized_federated_pdu() {
        let s = server();
        let room = RoomId::parse("!nope:other.tld").unwrap();
        let mut txn = gm_fed::Transaction::new("other.tld", 1700);
        // A message into a room with no create event: unauthorized.
        txn.pdus.push(Pdu {
            event_id: EventId::parse("$orphan").unwrap(),
            room_id: room.clone(),
            sender: UserId::parse("@bob:other.tld").unwrap(),
            kind: events::ROOM_MESSAGE.to_owned(),
            state_key: None,
            origin_server_ts: 1,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{}".to_owned(),
        });

        let result = s.receive_transaction(&txn.to_json());
        // The ack carries an error, and nothing was ingested.
        let ack = result.get("pdus").and_then(|p| p.get("$orphan")).unwrap();
        assert!(ack.get("error").is_some());
        assert!(s.timeline(&room).is_empty());
    }

    #[test]
    fn invite_then_join_lets_a_second_user_participate() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let bob = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();

        // Bob cannot join an invite-only room, nor send, before being invited.
        assert!(s.change_membership(&bob, &room, &bob, "join").is_none());
        assert!(s
            .send_message(&bob, &room, events::ROOM_MESSAGE, "t0", "{}")
            .is_none());

        // Alice (joined, powered) invites bob; bob then joins and can send.
        assert!(s.change_membership(&alice, &room, &bob, "invite").is_some());
        assert!(s.change_membership(&bob, &room, &bob, "join").is_some());
        assert!(s
            .send_message(&bob, &room, events::ROOM_MESSAGE, "t1", r#"{"body":"hi"}"#)
            .is_some());

        // Alice (power 100) can kick bob (power 0); bob can no longer send.
        assert!(s.change_membership(&alice, &room, &bob, "leave").is_some());
        assert!(s
            .send_message(&bob, &room, events::ROOM_MESSAGE, "t2", "{}")
            .is_none());
    }

    #[test]
    fn a_non_member_cannot_invite() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let mallory = UserId::parse("@mallory:gaussian.tech").unwrap();
        let bob = UserId::parse("@bob:gaussian.tech").unwrap();
        let room = s.create_room(&alice, None, None).unwrap();
        // Mallory is not in the room, so cannot invite anyone.
        assert!(s
            .change_membership(&mallory, &room, &bob, "invite")
            .is_none());
    }

    #[test]
    fn send_is_authorized_against_room_state() {
        let s = server();
        let alice = UserId::parse("@alice:gaussian.tech").unwrap();
        let mallory = UserId::parse("@mallory:gaussian.tech").unwrap();
        // Alice creates (and joins) the room.
        let room = s.create_room(&alice, Some("Ops"), None).unwrap();

        // The joined creator may send.
        assert!(s
            .send_message(
                &alice,
                &room,
                events::ROOM_MESSAGE,
                "t1",
                r#"{"body":"hi"}"#
            )
            .is_some());
        // A non-member is refused (auth: sender not joined) — nothing appended.
        assert!(s
            .send_message(
                &mallory,
                &room,
                events::ROOM_MESSAGE,
                "t2",
                r#"{"body":"x"}"#
            )
            .is_none());
        assert!(s
            .timeline(&room)
            .iter()
            .all(|p| p.sender.as_str() != "@mallory:gaussian.tech"));
    }

    #[test]
    fn send_message_appends_once_and_is_idempotent_on_txn_id() {
        let s = server();
        let sender = UserId::parse("@alice:gaussian.tech").unwrap();
        let room = s.create_room(&sender, None, None).unwrap(); // sender joins

        let messages = |s: &GaussServer<SharedStore>| {
            s.timeline(&room)
                .into_iter()
                .filter(|p| p.kind == events::ROOM_MESSAGE)
                .collect::<Vec<_>>()
        };

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
        assert_eq!(messages(&s).len(), 1);

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
        let msgs = messages(&s);
        assert_eq!(msgs.len(), 2);
        // The second message links onto the first (the prior tip).
        assert_eq!(msgs[1].prev_events, vec![msgs[0].event_id.clone()]);
        assert_eq!(msgs[1].content_json, r#"{"body":"yo"}"#);
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
