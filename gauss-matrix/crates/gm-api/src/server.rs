// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The homeserver service seam the ingress drives.
//!
//! The HTTP ingress (`gm-http`) is transport and routing; the actual work —
//! authenticating tokens, reading room state, (later) persisting events — is the
//! service core (`gm-svc`). Rather than couple the ingress to that core, it is
//! generic over the capability traits defined here, in the shared crate. Each
//! capability is its own small trait ([`TokenAuthority`], [`RoomReader`]) so a
//! component implements only what it provides; [`Homeserver`] bundles the set
//! the ingress needs, with a blanket impl so any type providing them all is a
//! homeserver. The assembled server plugs its composed services in as the `H`.

use crate::auth::TokenAuthority;
use crate::Pdu;
use gm_util::{RoomId, UserId};

/// Read-only access to room state (the CS state-read / federation state paths).
pub trait RoomReader {
    /// The content JSON of the state event filling `(event_type, state_key)` in
    /// `room`, or `None` if that slot is empty.
    fn room_state_content(
        &self,
        room: &RoomId,
        event_type: &str,
        state_key: &str,
    ) -> Option<String>;

    /// The room's full current state as events (the SS `/state` path).
    fn room_state(&self, room: &RoomId) -> Vec<Pdu>;
}

/// Read-only access to a room's timeline (the CS `/messages` path).
pub trait RoomTimeline {
    /// The events of `room`, oldest first.
    fn room_timeline(&self, room: &RoomId) -> Vec<Pdu>;
}

/// One joined room in a [`SyncView`]: its current state and recent timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedRoom {
    /// The room.
    pub room: RoomId,
    /// The room's current state events.
    pub state: Vec<Pdu>,
    /// The room's timeline, oldest first.
    pub timeline: Vec<Pdu>,
}

/// A user's sync view: the rooms they have joined, each with state and timeline,
/// plus the pagination token a subsequent sync resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncView {
    /// The token to pass as `?since=` on the next sync.
    pub next_batch: String,
    /// The rooms the user is joined to.
    pub joined: Vec<JoinedRoom>,
}

/// Build a user's sync view (the CS `/sync` path).
pub trait SyncProvider {
    /// The current sync view for `user` (initial sync: full state + timeline of
    /// every joined room).
    fn sync(&self, user: &UserId) -> SyncView;
}

/// Receive an inbound federation transaction (the SS `PUT /send/{txnId}` path).
///
/// The argument is the transaction's JSON body and the result is the
/// `{"pdus":{event_id:{}}}` per-event acknowledgement object the sending server
/// expects. Implemented over the federation model in `gm-fed`; takes `&self`
/// (the ingress is a shared front) and persists via interior mutability.
pub trait FederationReceiver {
    /// Ingest the transaction `txn` (JSON), returning the per-PDU result object.
    fn receive_transaction(&self, txn: &crate::Json) -> crate::Json;
}

/// Verify an inbound federation request's `X-Matrix` signature (spec §III.E).
///
/// Given the request's method, URI, body and `Authorization` header, the
/// implementation parses the `X-Matrix` signature, reconstructs the canonical
/// signing object (with itself as the destination) and verifies it against the
/// origin server's key. The ingress rejects a request that does not verify with
/// `401` before any handler runs.
pub trait FederationAuth {
    /// Whether the federation request is authentically signed by its claimed
    /// origin.
    fn verify_federation_request(
        &self,
        method: &str,
        uri: &str,
        content: Option<&str>,
        authorization: Option<&str>,
    ) -> bool;
}

/// Create a room (the `POST /createRoom` path).
///
/// Takes `&self` for the same reason as [`Login`]: the ingress is a shared
/// front and a persisting implementation uses interior mutability. Writes the
/// canonical initial state (create, creator membership, power levels, and the
/// optional name/topic) and returns the new room id.
pub trait RoomCreator {
    /// Create a room owned by `creator` with an optional `name` and `topic`,
    /// returning the new room id (or `None` if creation was refused).
    fn create_room(
        &self,
        creator: &UserId,
        name: Option<&str>,
        topic: Option<&str>,
    ) -> Option<RoomId>;
}

/// The result of a successful login: the full user id and a fresh access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginGrant {
    /// The authenticated user.
    pub user_id: UserId,
    /// A freshly-minted access token for the session.
    pub access_token: String,
}

/// Password login (the `POST /login` path).
///
/// Takes `&self` because the ingress is a shared, immutable front; an
/// implementation that mints a session token uses interior mutability (the live
/// server fronts shared state with a lock, as servers do).
pub trait Login {
    /// Authenticate `localpart` + `password`; on success mint a session and
    /// return the grant, else `None`.
    fn password_login(&self, localpart: &str, password: &str) -> Option<LoginGrant>;
}

/// Send a message event into a room (the `PUT …/send/…/{txnId}` path).
///
/// Takes `&self` for the same reason as [`Login`]: the ingress is a shared
/// front and a persisting implementation uses interior mutability. `txn_id`
/// makes the send idempotent — retrying with the same `(sender, txn_id)` returns
/// the originally-created event rather than duplicating it.
pub trait MessageSender {
    /// Append `content` (an event content JSON object) as an `event_type` event
    /// sent by `sender` into `room`, returning the new event id. Returns `None`
    /// if the send is refused. Idempotent on `(sender, txn_id)`.
    fn send_message(
        &self,
        sender: &UserId,
        room: &RoomId,
        event_type: &str,
        txn_id: &str,
        content: &str,
    ) -> Option<String>;
}

/// The full capability set the ingress requires of a homeserver. Blanket-
/// implemented: any type providing all the capability traits is a `Homeserver`.
pub trait Homeserver:
    TokenAuthority
    + RoomReader
    + RoomTimeline
    + RoomCreator
    + Login
    + MessageSender
    + SyncProvider
    + FederationReceiver
    + FederationAuth
{
}

impl<T> Homeserver for T where
    T: TokenAuthority
        + RoomReader
        + RoomTimeline
        + RoomCreator
        + Login
        + MessageSender
        + SyncProvider
        + FederationReceiver
        + FederationAuth
{
}

/// A homeserver that provides nothing — the default for an ingress with no
/// service core wired in. Public endpoints still work; authenticated endpoints
/// reject every token and room reads find nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoServer;

impl TokenAuthority for NoServer {
    fn user_for(&self, _token: &str) -> Option<gm_util::UserId> {
        None
    }
}

impl RoomReader for NoServer {
    fn room_state_content(
        &self,
        _room: &RoomId,
        _event_type: &str,
        _state_key: &str,
    ) -> Option<String> {
        None
    }

    fn room_state(&self, _room: &RoomId) -> Vec<Pdu> {
        Vec::new()
    }
}

impl RoomTimeline for NoServer {
    fn room_timeline(&self, _room: &RoomId) -> Vec<Pdu> {
        Vec::new()
    }
}

impl RoomCreator for NoServer {
    fn create_room(
        &self,
        _creator: &UserId,
        _name: Option<&str>,
        _topic: Option<&str>,
    ) -> Option<RoomId> {
        None
    }
}

impl SyncProvider for NoServer {
    fn sync(&self, _user: &UserId) -> SyncView {
        SyncView {
            next_batch: "s0".to_owned(),
            joined: Vec::new(),
        }
    }
}

impl FederationReceiver for NoServer {
    fn receive_transaction(&self, _txn: &crate::Json) -> crate::Json {
        // Acknowledge with no per-PDU results.
        let mut obj = std::collections::BTreeMap::new();
        obj.insert(
            "pdus".to_owned(),
            crate::Json::Object(std::collections::BTreeMap::new()),
        );
        crate::Json::Object(obj)
    }
}

impl FederationAuth for NoServer {
    fn verify_federation_request(
        &self,
        _method: &str,
        _uri: &str,
        _content: Option<&str>,
        _authorization: Option<&str>,
    ) -> bool {
        // With no federation keys configured, no inbound request verifies.
        false
    }
}

impl Login for NoServer {
    fn password_login(&self, _localpart: &str, _password: &str) -> Option<LoginGrant> {
        None
    }
}

impl MessageSender for NoServer {
    fn send_message(
        &self,
        _sender: &UserId,
        _room: &RoomId,
        _event_type: &str,
        _txn_id: &str,
        _content: &str,
    ) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_homeserver<H: Homeserver>(_: &H) {}

    #[test]
    fn no_server_is_a_homeserver_that_provides_nothing() {
        let s = NoServer;
        is_homeserver(&s); // satisfies the bundle via the blanket impl
        assert_eq!(s.user_for("t"), None);
        assert_eq!(
            s.room_state_content(
                &RoomId::parse("!r:gaussian.tech").unwrap(),
                "m.room.name",
                ""
            ),
            None
        );
    }
}
