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

/// One user's read receipt in a room: the last event they have read, with the
/// timestamp the receipt was recorded (the `m.read` part of `m.receipt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReceipt {
    /// The user the receipt is for.
    pub user: UserId,
    /// The event id the user has read up to.
    pub event_id: String,
    /// When the receipt was recorded (ms since the Unix epoch).
    pub ts: u64,
}

/// One joined room in a [`SyncView`]: its current state, recent timeline, and
/// ephemeral data (the users typing and read receipts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedRoom {
    /// The room.
    pub room: RoomId,
    /// The room's current state events.
    pub state: Vec<Pdu>,
    /// The room's timeline, oldest first.
    pub timeline: Vec<Pdu>,
    /// The users currently typing in the room (the `m.typing` ephemeral EDU).
    pub typing: Vec<UserId>,
    /// The room's read receipts (the `m.receipt` ephemeral EDU).
    pub receipts: Vec<ReadReceipt>,
}

/// One room a user left within a sync window: the timeline up to and including
/// the membership change that removed them, so a client can drop the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftRoom {
    /// The room.
    pub room: RoomId,
    /// The room's timeline within the window, oldest first.
    pub timeline: Vec<Pdu>,
}

/// A user's sync view: the rooms they have joined, each with state and timeline,
/// the rooms they left in this window, plus the pagination token a subsequent
/// sync resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncView {
    /// The token to pass as `?since=` on the next sync.
    pub next_batch: String,
    /// The rooms the user is joined to.
    pub joined: Vec<JoinedRoom>,
    /// The rooms the user left (or was kicked/banned from) within the window.
    pub left: Vec<LeftRoom>,
}

/// Build a user's sync view (the CS `/sync` path).
pub trait SyncProvider {
    /// The sync view for `user`. With `since = None` it is an **initial sync**
    /// (full state + timeline of every joined room); with a `since` token from a
    /// prior `next_batch` it is an **incremental sync** (only the events that
    /// arrived after that token, plus any rooms left in the window). Always
    /// returns the `next_batch` to resume from.
    fn sync(&self, user: &UserId, since: Option<&str>) -> SyncView;
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

/// Publish this server's federation signing keys (the SS `GET /_matrix/key/v2/server`
/// path, spec §III.E).
///
/// Returns the server's key document as JSON — `server_name`, `valid_until_ts`,
/// the `verify_keys` other servers use to check this server's signatures, and a
/// self-`signatures` block — so remote servers can fetch and cache it. A server
/// with no keys configured publishes an empty `verify_keys` map.
pub trait ServerKeys {
    /// This server's published key document (a JSON object).
    fn server_keys(&self) -> crate::Json;
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

/// Apply an `m.room.member` change (the `/join`, `/leave`, `/invite`, `/kick`,
/// `/ban` paths).
///
/// `actor` performs the change, setting `target`'s membership to `membership`
/// (`join` / `leave` / `invite` / `ban` / `knock`). The implementation builds
/// the member event and authorizes it against current room state (join rules,
/// invite, power levels); it returns the new event id, or `None` if the change
/// is not permitted. Takes `&self` (interior mutability), like the other write
/// capabilities.
pub trait MembershipChanger {
    /// Change `target`'s membership in `room` on behalf of `actor`.
    fn change_membership(
        &self,
        actor: &UserId,
        room: &RoomId,
        target: &UserId,
        membership: &str,
    ) -> Option<String>;
}

/// Create a room (the `POST /createRoom` path).///
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

/// Set a user's typing state in a room (the `PUT …/typing/{userId}` path).
///
/// Typing is ephemeral: `typing = true` marks `user` as typing in `room` for
/// `timeout_ms` milliseconds (after which it lapses); `typing = false` clears it
/// immediately. The state surfaces as the `m.typing` ephemeral EDU on the room's
/// sync view. Takes `&self` (interior mutability), like the other writes. Returns
/// whether the change was accepted.
pub trait TypingNotifier {
    /// Set whether `user` is typing in `room`, lapsing after `timeout_ms`.
    fn set_typing(&self, user: &UserId, room: &RoomId, typing: bool, timeout_ms: u64) -> bool;
}

/// Record a user's read receipt in a room (the `POST …/receipt/m.read/{eventId}`
/// path).
///
/// Marks `user` as having read up to `event_id` in `room`; the receipt surfaces
/// as the `m.receipt` ephemeral EDU on the room's sync view. Takes `&self`
/// (interior mutability), like the other writes. Returns whether it was accepted.
pub trait ReceiptSetter {
    /// Record `user`'s `m.read` receipt at `event_id` in `room`.
    fn set_read_receipt(&self, user: &UserId, room: &RoomId, event_id: &str) -> bool;
}

/// The full capability set the ingress requires of a homeserver. Blanket-
/// implemented: any type providing all the capability traits is a `Homeserver`.
pub trait Homeserver:
    TokenAuthority
    + RoomReader
    + RoomTimeline
    + RoomCreator
    + MembershipChanger
    + Login
    + MessageSender
    + TypingNotifier
    + ReceiptSetter
    + SyncProvider
    + FederationReceiver
    + FederationAuth
    + ServerKeys
{
}

impl<T> Homeserver for T where
    T: TokenAuthority
        + RoomReader
        + RoomTimeline
        + RoomCreator
        + MembershipChanger
        + Login
        + MessageSender
        + TypingNotifier
        + ReceiptSetter
        + SyncProvider
        + FederationReceiver
        + FederationAuth
        + ServerKeys
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
    fn sync(&self, _user: &UserId, _since: Option<&str>) -> SyncView {
        SyncView {
            next_batch: "s0".to_owned(),
            joined: Vec::new(),
            left: Vec::new(),
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

impl ServerKeys for NoServer {
    fn server_keys(&self) -> crate::Json {
        // No server name and no keys configured: an empty key document.
        let mut obj = std::collections::BTreeMap::new();
        obj.insert("server_name".to_owned(), crate::Json::String(String::new()));
        obj.insert(
            "verify_keys".to_owned(),
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

impl MembershipChanger for NoServer {
    fn change_membership(
        &self,
        _actor: &UserId,
        _room: &RoomId,
        _target: &UserId,
        _membership: &str,
    ) -> Option<String> {
        None
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

impl TypingNotifier for NoServer {
    fn set_typing(&self, _user: &UserId, _room: &RoomId, _typing: bool, _timeout_ms: u64) -> bool {
        false
    }
}

impl ReceiptSetter for NoServer {
    fn set_read_receipt(&self, _user: &UserId, _room: &RoomId, _event_id: &str) -> bool {
        false
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
