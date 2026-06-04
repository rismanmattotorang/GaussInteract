// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Event authorization (spec §III.D).
//!
//! State resolution decides *which* event fills a slot; authorization decides
//! whether an event is *allowed at all* given the room's state. Before an event
//! is accepted into a room it must pass the auth rules — otherwise a client (or
//! a federated server) could inject events it has no right to send.
//!
//! This implements the foundational subset of the Matrix auth rules:
//!
//! - `m.room.create` is allowed only as the room's first event (no prior
//!   create);
//! - every other event requires the room to have a create event;
//! - `m.room.member` transitions follow the join-rules / invite state machine
//!   (see [`check_auth`]): self-join into a `public` room, to accept an invite,
//!   or into a `restricted`/`knock_restricted` room when a powered member has
//!   authorised it (MSC3083); knocking when the room permits it; invite/kick/ban
//!   by a sufficiently-powered member; leaving oneself; an invite that redeems a
//!   matching `m.room.third_party_invite` token;
//! - a `m.room.redaction` is allowed when it targets an event from the
//!   redactor's own server, otherwise it needs the room's `redact` power level;
//! - any other sender must be **joined**, with sufficient **power level** for
//!   the event — a `power_levels.events` per-type override if set, else the
//!   `state_default` for state events / `events_default` for messages (before
//!   `m.room.power_levels` the room creator has power 100 and everyone else 0).
//!
//! The remaining rules (third-party-invite signature verification, full
//! state-resolution v2 conflict handling) layer on top of this.

use gm_api::{events, Json, Pdu};

/// Why an event was refused by the auth rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// A second `m.room.create` in a room that already has one.
    DuplicateCreate,
    /// A non-create event in a room with no `m.room.create`.
    NoCreateEvent,
    /// The sender is not joined to the room.
    SenderNotJoined,
    /// The sender lacks the power level the event requires.
    InsufficientPower,
    /// The `m.room.member` transition is not permitted (join rules / invite
    /// state machine).
    MembershipForbidden,
    /// An event in the auth chain was not present (an incomplete chain — the
    /// missing events must be fetched/backfilled before the event can be
    /// authorized).
    MissingAuthEvent,
}

/// The default power required to send a state event (no `state_default` set).
const DEFAULT_STATE_POWER: i64 = 50;
/// The default power required to send a message event (no `events_default`).
const DEFAULT_EVENTS_POWER: i64 = 0;
/// Default power to invite / kick / ban when `m.room.power_levels` omits them.
const DEFAULT_INVITE_POWER: i64 = 0;
const DEFAULT_KICK_POWER: i64 = 50;
const DEFAULT_BAN_POWER: i64 = 50;
/// Default power to redact another user's event when `m.room.power_levels`
/// omits `redact`.
const DEFAULT_REDACT_POWER: i64 = 50;
/// The power a room creator holds before `m.room.power_levels` is set.
const CREATOR_POWER: i64 = 100;

/// Check whether `event` is authorized given the room's current `state` events.
///
/// `state` is the resolved current-state event set (as in
/// `gm_svc`'s `current_state_pdus`). For the room's first event (the create),
/// pass an empty slice.
pub fn check_auth(event: &Pdu, state: &[Pdu]) -> Result<(), AuthError> {
    let view = AuthView::new(state);

    if event.kind == events::ROOM_CREATE {
        return if view.create.is_some() {
            Err(AuthError::DuplicateCreate)
        } else {
            Ok(())
        };
    }

    if view.create.is_none() {
        return Err(AuthError::NoCreateEvent);
    }

    // Membership events follow the join-rules / invite state machine.
    if event.kind == events::ROOM_MEMBER {
        return check_member_auth(event, &view);
    }

    let sender = event.sender.as_str();
    if view.membership(sender) != Some("join") {
        return Err(AuthError::SenderNotJoined);
    }

    // A redaction is allowed when the redactor redacts an event from their own
    // server (matching domains), otherwise it needs the room's `redact` power.
    if event.kind == events::ROOM_REDACTION {
        if redaction_targets_own_domain(event) {
            return Ok(());
        }
        return if view.power_level(sender) >= view.redact_level() {
            Ok(())
        } else {
            Err(AuthError::InsufficientPower)
        };
    }

    // Other events: a per-event-type override in `power_levels.events`, else the
    // `state_default` / `events_default`.
    let required = view.event_level(&event.kind, event.is_state());
    if view.power_level(sender) < required {
        return Err(AuthError::InsufficientPower);
    }
    Ok(())
}

/// Whether a redaction targets an event from the redactor's own server: the
/// `redacts` event id carries a `:domain` matching the sender's domain (the
/// "redact your own server's events" auth rule). Falls back to `false` (and thus
/// the power check) when the id carries no domain.
fn redaction_targets_own_domain(event: &Pdu) -> bool {
    let Some(redacts) = Json::parse(&event.content_json)
        .ok()
        .and_then(|c| c.get("redacts").and_then(Json::as_str).map(str::to_owned))
    else {
        return false;
    };
    let Some((_, target_domain)) = redacts.split_once(':') else {
        return false; // no domain component to match
    };
    event
        .sender
        .as_str()
        .split_once(':')
        .map(|(_, sender_domain)| sender_domain == target_domain)
        .unwrap_or(false)
}

/// Authorize an `m.room.member` event against the membership state machine.
fn check_member_auth(event: &Pdu, view: &AuthView<'_>) -> Result<(), AuthError> {
    let sender = event.sender.as_str();
    // The target is the state key (whose membership this event sets).
    let Some(target) = event.state_key.as_deref() else {
        return Err(AuthError::MembershipForbidden);
    };
    let new = Json::parse(&event.content_json).ok().and_then(|c| {
        c.get("membership")
            .and_then(Json::as_str)
            .map(str::to_owned)
    });
    let new = new.as_deref().unwrap_or("");
    let target_current = view.membership(target);

    match new {
        "join" => {
            // Only the user themselves joins; a member is never *joined* by
            // another (that is an invite).
            if target != sender {
                return Err(AuthError::MembershipForbidden);
            }
            // A banned user cannot join (they must be unbanned first).
            if target_current == Some("ban") {
                return Err(AuthError::MembershipForbidden);
            }
            // The room creator's initial join (part of room creation) is allowed.
            if view.creator().as_deref() == Some(sender) && target_current.is_none() {
                return Ok(());
            }
            // Accepting a pending invite is allowed under any join rule.
            if target_current == Some("invite") {
                return Ok(());
            }
            match view.join_rule() {
                "public" => Ok(()),
                // Restricted (and knock_restricted) rooms: a join is allowed when
                // a powered member of the room has authorised it, named in
                // `join_authorised_via_users_server` (MSC3083).
                "restricted" | "knock_restricted" => {
                    if restricted_join_authorised(event, view) {
                        Ok(())
                    } else {
                        Err(AuthError::MembershipForbidden)
                    }
                }
                _ => Err(AuthError::MembershipForbidden),
            }
        }
        "invite" => {
            if view.membership(sender) != Some("join") {
                return Err(AuthError::SenderNotJoined);
            }
            if matches!(target_current, Some("join") | Some("ban")) {
                return Err(AuthError::MembershipForbidden);
            }
            // An invite redeeming a third-party-invite token is allowed without
            // the invite power — but only if its `signed` block carries a valid
            // signature by the public key the matching
            // `m.room.third_party_invite` advertised (that event was itself
            // issued by a powered member).
            if third_party_invite_is_valid(event, view) {
                return Ok(());
            }
            if view.power_level(sender) < view.invite_level() {
                return Err(AuthError::InsufficientPower);
            }
            Ok(())
        }
        "leave" => {
            // Leaving / declining an invite for oneself is always allowed.
            if target == sender {
                return Ok(());
            }
            // Kicking another requires join + the kick power, strictly above the
            // target's power.
            if view.membership(sender) != Some("join") {
                return Err(AuthError::SenderNotJoined);
            }
            if view.power_level(sender) < view.kick_level()
                || view.power_level(sender) <= view.power_level(target)
            {
                return Err(AuthError::InsufficientPower);
            }
            Ok(())
        }
        "ban" => {
            if view.membership(sender) != Some("join") {
                return Err(AuthError::SenderNotJoined);
            }
            if view.power_level(sender) < view.ban_level()
                || view.power_level(sender) <= view.power_level(target)
            {
                return Err(AuthError::InsufficientPower);
            }
            Ok(())
        }
        "knock" => {
            // One may knock on oneself when the room permits knocking, and not
            // if already joined or banned.
            if target == sender
                && matches!(view.join_rule(), "knock" | "knock_restricted")
                && !matches!(target_current, Some("join") | Some("ban"))
            {
                Ok(())
            } else {
                Err(AuthError::MembershipForbidden)
            }
        }
        _ => Err(AuthError::MembershipForbidden),
    }
}

/// Whether a join into a `restricted` room is authorised: the member event names
/// a `join_authorised_via_users_server` user who is currently joined and holds
/// at least the invite power level (MSC3083). The authorising server vouches by
/// signing the event; here we check the cited user can in fact admit members.
fn restricted_join_authorised(event: &Pdu, view: &AuthView<'_>) -> bool {
    let Some(authoriser) = Json::parse(&event.content_json).ok().and_then(|c| {
        c.get("join_authorised_via_users_server")
            .and_then(Json::as_str)
            .map(str::to_owned)
    }) else {
        return false;
    };
    view.membership(&authoriser) == Some("join")
        && view.power_level(&authoriser) >= view.invite_level()
}

/// Whether an `m.room.member` invite validly redeems a third-party invite: its
/// `content.third_party_invite.signed` block names a `token` for which the room
/// holds a matching `m.room.third_party_invite`, and a signature over the
/// canonical (signatures-free) `signed` object verifies against that event's
/// advertised `public_key` (Ed25519). The signature check is what stops anyone
/// forging an invite for an unrelated token.
fn third_party_invite_is_valid(event: &Pdu, view: &AuthView<'_>) -> bool {
    let Some(signed) = Json::parse(&event.content_json).ok().and_then(|c| {
        c.get("third_party_invite")
            .and_then(|t| t.get("signed"))
            .cloned()
    }) else {
        return false;
    };
    let Some(token) = signed.get("token").and_then(Json::as_str) else {
        return false;
    };
    let Some(public_key) = view.third_party_public_key(token) else {
        return false; // no matching m.room.third_party_invite
    };

    // The signing bytes are the `signed` object with its `signatures` removed.
    let mut unsigned = signed.clone();
    let signatures = signed.get("signatures").and_then(Json::as_object).cloned();
    if let Json::Object(map) = &mut unsigned {
        map.remove("signatures");
    }
    let bytes = unsigned.to_string();

    // Accept if any provided signature verifies under the advertised key.
    let Some(signatures) = signatures else {
        return false;
    };
    signatures.values().any(|by_key| {
        by_key
            .as_object()
            .map(|keys| {
                keys.values().any(|sig| {
                    sig.as_str().is_some_and(|s| {
                        gm_util::ed25519::verify_b64(bytes.as_bytes(), s, public_key)
                    })
                })
            })
            .unwrap_or(false)
    })
}

/// A read-only view of the room's current state for the auth checks.
struct AuthView<'a> {
    create: Option<&'a Pdu>,
    power_levels: Option<Json>,
    join_rules: Option<Json>,
    members: Vec<(&'a str, String)>, // (user, membership)
    // outstanding m.room.third_party_invite: (token, advertised public_key)
    third_party_invites: Vec<(String, String)>,
}

impl<'a> AuthView<'a> {
    fn new(state: &'a [Pdu]) -> Self {
        let mut create = None;
        let mut power_levels = None;
        let mut join_rules = None;
        let mut members = Vec::new();
        let mut third_party_invites = Vec::new();
        for pdu in state {
            match pdu.kind.as_str() {
                events::ROOM_CREATE => create = Some(pdu),
                events::ROOM_POWER_LEVELS => power_levels = Json::parse(&pdu.content_json).ok(),
                events::ROOM_JOIN_RULES => join_rules = Json::parse(&pdu.content_json).ok(),
                events::ROOM_THIRD_PARTY_INVITE => {
                    if let Some(token) = pdu.state_key.as_deref() {
                        let public_key = Json::parse(&pdu.content_json)
                            .ok()
                            .and_then(|c| {
                                c.get("public_key")
                                    .and_then(Json::as_str)
                                    .map(str::to_owned)
                            })
                            .unwrap_or_default();
                        third_party_invites.push((token.to_owned(), public_key));
                    }
                }
                events::ROOM_MEMBER => {
                    if let Some(user) = pdu.state_key.as_deref() {
                        if let Some(membership) =
                            Json::parse(&pdu.content_json).ok().and_then(|c| {
                                c.get("membership")
                                    .and_then(Json::as_str)
                                    .map(str::to_owned)
                            })
                        {
                            members.push((user, membership));
                        }
                    }
                }
                _ => {}
            }
        }
        Self {
            create,
            power_levels,
            join_rules,
            members,
            third_party_invites,
        }
    }

    /// The public key advertised by an outstanding `m.room.third_party_invite`
    /// with this token, if one exists.
    fn third_party_public_key(&self, token: &str) -> Option<&str> {
        self.third_party_invites
            .iter()
            .find(|(t, _)| t == token)
            .map(|(_, key)| key.as_str())
    }

    /// The power required for an event of `kind`: a `power_levels.events`
    /// override if present, else the state/events default.
    fn event_level(&self, kind: &str, is_state: bool) -> i64 {
        if let Some(level) = self
            .power_levels
            .as_ref()
            .and_then(|pl| pl.get("events"))
            .and_then(|e| e.get(kind))
            .and_then(Json::as_i64)
        {
            return level;
        }
        if is_state {
            self.state_default()
        } else {
            self.events_default()
        }
    }

    fn membership(&self, user: &str) -> Option<&str> {
        self.members
            .iter()
            .find(|(u, _)| *u == user)
            .map(|(_, m)| m.as_str())
    }

    /// The room's join rule, defaulting to `invite` (the Matrix default when no
    /// `m.room.join_rules` is set).
    fn join_rule(&self) -> &str {
        self.join_rules
            .as_ref()
            .and_then(|j| j.get("join_rule").and_then(Json::as_str))
            .unwrap_or("invite")
    }

    /// A power level from `m.room.power_levels` by key, or `default`.
    fn level(&self, key: &str, default: i64) -> i64 {
        self.power_levels
            .as_ref()
            .and_then(|pl| pl.get(key).and_then(Json::as_i64))
            .unwrap_or(default)
    }

    fn invite_level(&self) -> i64 {
        self.level("invite", DEFAULT_INVITE_POWER)
    }
    fn kick_level(&self) -> i64 {
        self.level("kick", DEFAULT_KICK_POWER)
    }
    fn ban_level(&self) -> i64 {
        self.level("ban", DEFAULT_BAN_POWER)
    }
    fn redact_level(&self) -> i64 {
        self.level("redact", DEFAULT_REDACT_POWER)
    }

    /// The room creator from the create event's content, if present.
    fn creator(&self) -> Option<String> {
        self.create
            .and_then(|c| Json::parse(&c.content_json).ok())
            .and_then(|c| c.get("creator").and_then(Json::as_str).map(str::to_owned))
    }

    fn power_level(&self, user: &str) -> i64 {
        match &self.power_levels {
            Some(pl) => pl
                .get("users")
                .and_then(|u| u.get(user))
                .and_then(Json::as_i64)
                .unwrap_or_else(|| pl.get("users_default").and_then(Json::as_i64).unwrap_or(0)),
            // Before power levels exist, the creator is all-powerful.
            None => {
                if self.creator().as_deref() == Some(user) {
                    CREATOR_POWER
                } else {
                    0
                }
            }
        }
    }

    fn state_default(&self) -> i64 {
        self.power_levels
            .as_ref()
            .and_then(|pl| pl.get("state_default").and_then(Json::as_i64))
            .unwrap_or(DEFAULT_STATE_POWER)
    }

    fn events_default(&self) -> i64 {
        self.power_levels
            .as_ref()
            .and_then(|pl| pl.get("events_default").and_then(Json::as_i64))
            .unwrap_or(DEFAULT_EVENTS_POWER)
    }
}

// ---------------------------------------------------------------------------
// Auth-chain validation (spec §III.D / §V).
// ---------------------------------------------------------------------------

use gm_util::EventId;
use std::collections::{HashMap, HashSet};

/// The transitive **auth chain** of `roots`: every event reachable by following
/// `auth_events` links, resolved through `by_id`. The roots themselves are
/// included. An `auth_events` reference absent from `by_id` is simply not
/// expanded (its absence is surfaced by [`check_auth_with_chain`]).
pub fn auth_chain(roots: &[EventId], by_id: &HashMap<EventId, Pdu>) -> HashSet<EventId> {
    let mut seen = HashSet::new();
    let mut stack: Vec<EventId> = roots.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(pdu) = by_id.get(&id) {
            for parent in &pdu.auth_events {
                if !seen.contains(parent) {
                    stack.push(parent.clone());
                }
            }
        }
    }
    seen
}

/// Authorize `event` against the state selected by its **own `auth_events`**
/// (not the room's current state), validating the auth chain as it goes — the
/// Matrix rule for an event received over federation.
///
/// Every id in `event.auth_events`, and every event transitively reachable
/// through them, must be present in `by_id` (a complete, fetched chain) or this
/// returns [`AuthError::MissingAuthEvent`]. The event is then checked with
/// [`check_auth`] against the state its direct auth events form, and a
/// non-create event whose chain does not reach an `m.room.create` is rejected
/// with [`AuthError::NoCreateEvent`].
pub fn check_auth_with_chain(event: &Pdu, by_id: &HashMap<EventId, Pdu>) -> Result<(), AuthError> {
    // The whole chain behind this event must be present.
    let chain = auth_chain(&event.auth_events, by_id);
    for id in &chain {
        if !by_id.contains_key(id) {
            return Err(AuthError::MissingAuthEvent);
        }
    }

    // The auth state is the set of (state) events this event directly cites.
    let auth_state: Vec<Pdu> = event
        .auth_events
        .iter()
        .filter_map(|id| by_id.get(id).cloned())
        .collect();

    // A non-create event's chain must reach a create event.
    if event.kind != events::ROOM_CREATE
        && !chain
            .iter()
            .filter_map(|id| by_id.get(id))
            .any(|p| p.kind == events::ROOM_CREATE)
    {
        return Err(AuthError::NoCreateEvent);
    }

    check_auth(event, &auth_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_util::{EventId, RoomId, UserId};

    fn pdu(kind: &str, sender: &str, state_key: Option<&str>, content: &str) -> Pdu {
        Pdu {
            event_id: EventId::parse("$e").unwrap(),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse(sender).unwrap(),
            kind: kind.to_owned(),
            state_key: state_key.map(str::to_owned),
            origin_server_ts: 1,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: content.to_owned(),
        }
    }

    fn ops_room_state() -> Vec<Pdu> {
        vec![
            pdu(
                events::ROOM_CREATE,
                "@alice:gaussian.tech",
                Some(""),
                r#"{"creator":"@alice:gaussian.tech"}"#,
            ),
            pdu(
                events::ROOM_MEMBER,
                "@alice:gaussian.tech",
                Some("@alice:gaussian.tech"),
                r#"{"membership":"join"}"#,
            ),
            pdu(
                events::ROOM_POWER_LEVELS,
                "@alice:gaussian.tech",
                Some(""),
                r#"{"users":{"@alice:gaussian.tech":100},"users_default":0}"#,
            ),
        ]
    }

    #[test]
    fn create_is_allowed_only_as_the_first_event() {
        let create = pdu(events::ROOM_CREATE, "@a:gaussian.tech", Some(""), "{}");
        assert_eq!(check_auth(&create, &[]), Ok(()));
        // A second create is refused.
        assert_eq!(
            check_auth(&create, &ops_room_state()),
            Err(AuthError::DuplicateCreate)
        );
    }

    #[test]
    fn an_event_in_a_room_with_no_create_is_refused() {
        let msg = pdu(events::ROOM_MESSAGE, "@a:gaussian.tech", None, "{}");
        assert_eq!(check_auth(&msg, &[]), Err(AuthError::NoCreateEvent));
    }

    #[test]
    fn a_joined_member_may_send_a_message() {
        let msg = pdu(
            events::ROOM_MESSAGE,
            "@alice:gaussian.tech",
            None,
            r#"{"body":"hi"}"#,
        );
        assert_eq!(check_auth(&msg, &ops_room_state()), Ok(()));
    }

    #[test]
    fn a_non_member_may_not_send() {
        let msg = pdu(events::ROOM_MESSAGE, "@mallory:gaussian.tech", None, "{}");
        assert_eq!(
            check_auth(&msg, &ops_room_state()),
            Err(AuthError::SenderNotJoined)
        );
    }

    fn bob_join() -> Pdu {
        pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"join"}"#,
        )
    }

    #[test]
    fn self_join_is_refused_in_an_invite_only_room() {
        // ops_room_state has no join_rules -> default "invite": bob cannot just
        // join without an invite.
        assert_eq!(
            check_auth(&bob_join(), &ops_room_state()),
            Err(AuthError::MembershipForbidden)
        );
    }

    #[test]
    fn self_join_is_allowed_in_a_public_room() {
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_JOIN_RULES,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"join_rule":"public"}"#,
        ));
        assert_eq!(check_auth(&bob_join(), &state), Ok(()));
    }

    #[test]
    fn invited_user_may_accept_the_invite_by_joining() {
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_MEMBER,
            "@alice:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"invite"}"#,
        ));
        assert_eq!(check_auth(&bob_join(), &state), Ok(()));
    }

    #[test]
    fn a_joined_member_may_invite_a_powered_check() {
        // Alice (joined, power 100) invites bob: allowed.
        let invite = pdu(
            events::ROOM_MEMBER,
            "@alice:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"invite"}"#,
        );
        assert_eq!(check_auth(&invite, &ops_room_state()), Ok(()));
        // A non-member cannot invite.
        let by_stranger = pdu(
            events::ROOM_MEMBER,
            "@mallory:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"invite"}"#,
        );
        assert_eq!(
            check_auth(&by_stranger, &ops_room_state()),
            Err(AuthError::SenderNotJoined)
        );
    }

    #[test]
    fn kick_and_ban_need_power_above_the_target() {
        // Bob (joined, power 0) is in the room.
        let mut state = ops_room_state();
        state.push(bob_join());
        // Alice (100) may kick bob (0).
        let kick = pdu(
            events::ROOM_MEMBER,
            "@alice:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"leave"}"#,
        );
        assert_eq!(check_auth(&kick, &state), Ok(()));
        // Bob (0) may not kick alice (100).
        let bob_kicks_alice = pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@alice:gaussian.tech"),
            r#"{"membership":"leave"}"#,
        );
        assert_eq!(
            check_auth(&bob_kicks_alice, &state),
            Err(AuthError::InsufficientPower)
        );
        // Alice may ban bob.
        let ban = pdu(
            events::ROOM_MEMBER,
            "@alice:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"ban"}"#,
        );
        assert_eq!(check_auth(&ban, &state), Ok(()));
    }

    #[test]
    fn a_user_may_always_leave() {
        let mut state = ops_room_state();
        state.push(bob_join());
        let leave = pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"leave"}"#,
        );
        assert_eq!(check_auth(&leave, &state), Ok(()));
    }

    #[test]
    fn a_low_power_member_may_not_send_state() {
        // A room where bob is joined but has default (0) power.
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"join"}"#,
        ));
        // Bob (power 0) tries to set the room name (needs state_default = 50).
        let name = pdu(
            events::ROOM_NAME,
            "@bob:gaussian.tech",
            Some(""),
            r#"{"name":"hijacked"}"#,
        );
        assert_eq!(check_auth(&name, &state), Err(AuthError::InsufficientPower));
        // Alice (power 100) may.
        let name_by_alice = pdu(
            events::ROOM_NAME,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"name":"Ops"}"#,
        );
        assert_eq!(check_auth(&name_by_alice, &state), Ok(()));
    }

    #[test]
    fn creator_has_power_before_power_levels_exist() {
        // Only create + creator's join, no power_levels yet.
        let state = vec![
            pdu(
                events::ROOM_CREATE,
                "@alice:gaussian.tech",
                Some(""),
                r#"{"creator":"@alice:gaussian.tech"}"#,
            ),
            pdu(
                events::ROOM_MEMBER,
                "@alice:gaussian.tech",
                Some("@alice:gaussian.tech"),
                r#"{"membership":"join"}"#,
            ),
        ];
        // The creator can set the name (power 100 >= 50) without power_levels.
        let name = pdu(
            events::ROOM_NAME,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"name":"Ops"}"#,
        );
        assert_eq!(check_auth(&name, &state), Ok(()));
    }

    // Build a PDU with a specific id and auth_events for the chain tests.
    fn chain_pdu(
        id: &str,
        kind: &str,
        sender: &str,
        state_key: Option<&str>,
        content: &str,
        auth: &[&str],
    ) -> Pdu {
        let mut p = pdu(kind, sender, state_key, content);
        p.event_id = EventId::parse(id).unwrap();
        p.auth_events = auth.iter().map(|a| EventId::parse(*a).unwrap()).collect();
        p
    }

    /// A self-consistent chain: create ← creator's join ← a message.
    fn federated_chain() -> (HashMap<EventId, Pdu>, Pdu, Pdu) {
        let create = chain_pdu(
            "$c",
            events::ROOM_CREATE,
            "@carol:a.tld",
            Some(""),
            r#"{"creator":"@carol:a.tld"}"#,
            &[],
        );
        let join = chain_pdu(
            "$m",
            events::ROOM_MEMBER,
            "@carol:a.tld",
            Some("@carol:a.tld"),
            r#"{"membership":"join"}"#,
            &["$c"],
        );
        let msg = chain_pdu(
            "$msg",
            events::ROOM_MESSAGE,
            "@carol:a.tld",
            None,
            r#"{"body":"hi"}"#,
            &["$c", "$m"],
        );
        let mut by_id = HashMap::new();
        by_id.insert(create.event_id.clone(), create.clone());
        by_id.insert(join.event_id.clone(), join.clone());
        (by_id, join, msg)
    }

    #[test]
    fn auth_chain_collects_the_transitive_closure() {
        let (by_id, _join, msg) = federated_chain();
        let chain = auth_chain(&msg.auth_events, &by_id);
        // The message cites $c and $m; $m in turn cites $c.
        assert_eq!(chain.len(), 2);
        assert!(chain.contains(&EventId::parse("$c").unwrap()));
        assert!(chain.contains(&EventId::parse("$m").unwrap()));
    }

    #[test]
    fn check_auth_with_chain_accepts_a_well_formed_event() {
        let (by_id, _join, msg) = federated_chain();
        assert_eq!(check_auth_with_chain(&msg, &by_id), Ok(()));
    }

    #[test]
    fn check_auth_with_chain_rejects_a_missing_auth_event() {
        let (mut by_id, _join, msg) = federated_chain();
        // Drop the create event: the chain is now incomplete.
        by_id.remove(&EventId::parse("$c").unwrap());
        assert_eq!(
            check_auth_with_chain(&msg, &by_id),
            Err(AuthError::MissingAuthEvent)
        );
    }

    #[test]
    fn check_auth_with_chain_rejects_an_unauthorized_sender() {
        let (mut by_id, _join, _msg) = federated_chain();
        // A message from someone who is not joined, but who cites the same
        // (carol's) auth events, is not authorized by that state.
        let mallory = chain_pdu(
            "$bad",
            events::ROOM_MESSAGE,
            "@mallory:b.tld",
            None,
            r#"{"body":"intrude"}"#,
            &["$c", "$m"],
        );
        by_id.insert(mallory.event_id.clone(), mallory.clone());
        assert_eq!(
            check_auth_with_chain(&mallory, &by_id),
            Err(AuthError::SenderNotJoined)
        );
    }

    #[test]
    fn check_auth_with_chain_rejects_a_chain_without_a_create() {
        // A membership event whose auth chain never reaches a create event.
        let orphan_member = chain_pdu(
            "$m",
            events::ROOM_MEMBER,
            "@carol:a.tld",
            Some("@carol:a.tld"),
            r#"{"membership":"join"}"#,
            &[],
        );
        let mut by_id = HashMap::new();
        by_id.insert(orphan_member.event_id.clone(), orphan_member.clone());
        // It cites no auth events, so its chain reaches no create.
        assert_eq!(
            check_auth_with_chain(&orphan_member, &by_id),
            Err(AuthError::NoCreateEvent)
        );
    }

    fn restricted_room_state() -> Vec<Pdu> {
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_JOIN_RULES,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"join_rule":"restricted"}"#,
        ));
        state
    }

    #[test]
    fn restricted_join_needs_authorisation_by_a_powered_member() {
        // Without `join_authorised_via_users_server`, a restricted join fails.
        assert_eq!(
            check_auth(&bob_join(), &restricted_room_state()),
            Err(AuthError::MembershipForbidden)
        );

        // Authorised by alice (joined, power 100 ≥ invite level): allowed.
        let authorised = pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"join","join_authorised_via_users_server":"@alice:gaussian.tech"}"#,
        );
        assert_eq!(check_auth(&authorised, &restricted_room_state()), Ok(()));

        // Authorised by a non-member: not allowed.
        let bogus = pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"join","join_authorised_via_users_server":"@ghost:gaussian.tech"}"#,
        );
        assert_eq!(
            check_auth(&bogus, &restricted_room_state()),
            Err(AuthError::MembershipForbidden)
        );
    }

    #[test]
    fn knock_is_allowed_only_when_the_room_permits_knocking() {
        let knock = pdu(
            events::ROOM_MEMBER,
            "@bob:gaussian.tech",
            Some("@bob:gaussian.tech"),
            r#"{"membership":"knock"}"#,
        );
        // The default (invite) room does not permit knocking.
        assert_eq!(
            check_auth(&knock, &ops_room_state()),
            Err(AuthError::MembershipForbidden)
        );
        // A knock room does.
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_JOIN_RULES,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"join_rule":"knock"}"#,
        ));
        assert_eq!(check_auth(&knock, &state), Ok(()));
    }

    #[test]
    fn redaction_requires_the_redact_power_level() {
        // A joined member with power below `redact` (50) may message but not redact.
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@carol:gaussian.tech"),
            r#"{"membership":"join"}"#,
        ));
        let redaction = pdu(
            events::ROOM_REDACTION,
            "@carol:gaussian.tech",
            None,
            r#"{"redacts":"$x"}"#,
        );
        assert_eq!(
            check_auth(&redaction, &state),
            Err(AuthError::InsufficientPower)
        );
        // Alice (power 100) may redact.
        let by_alice = pdu(
            events::ROOM_REDACTION,
            "@alice:gaussian.tech",
            None,
            r#"{"redacts":"$x"}"#,
        );
        assert_eq!(check_auth(&by_alice, &state), Ok(()));
        // A non-member cannot redact at all.
        let by_stranger = pdu(
            events::ROOM_REDACTION,
            "@mallory:gaussian.tech",
            None,
            r#"{"redacts":"$x"}"#,
        );
        assert_eq!(
            check_auth(&by_stranger, &state),
            Err(AuthError::SenderNotJoined)
        );
    }

    #[test]
    fn a_member_may_redact_their_own_servers_event_without_redact_power() {
        // Carol (joined, power 0 < redact 50) may still redact an event from her
        // own server (matching domains), but not one from another server.
        let mut state = ops_room_state();
        state.push(pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@carol:gaussian.tech"),
            r#"{"membership":"join"}"#,
        ));
        let own = pdu(
            events::ROOM_REDACTION,
            "@carol:gaussian.tech",
            None,
            r#"{"redacts":"$evt:gaussian.tech"}"#,
        );
        assert_eq!(check_auth(&own, &state), Ok(()));
        let foreign = pdu(
            events::ROOM_REDACTION,
            "@carol:gaussian.tech",
            None,
            r#"{"redacts":"$evt:other.tld"}"#,
        );
        assert_eq!(
            check_auth(&foreign, &state),
            Err(AuthError::InsufficientPower)
        );
    }

    #[test]
    fn per_event_type_power_override_is_honoured() {
        // A power_levels.events override raises the bar for one event type.
        let mut state = ops_room_state();
        state.retain(|p| p.kind != events::ROOM_POWER_LEVELS);
        state.push(pdu(
            events::ROOM_POWER_LEVELS,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"users":{"@alice:gaussian.tech":100,"@carol:gaussian.tech":40},
                "users_default":0,"events":{"m.room.message":50}}"#,
        ));
        state.push(pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@carol:gaussian.tech"),
            r#"{"membership":"join"}"#,
        ));
        let msg = |sender: &str| pdu(events::ROOM_MESSAGE, sender, None, r#"{"body":"hi"}"#);
        // Carol (power 40) is below the 50 override; alice (100) is above it.
        assert_eq!(
            check_auth(&msg("@carol:gaussian.tech"), &state),
            Err(AuthError::InsufficientPower)
        );
        assert_eq!(check_auth(&msg("@alice:gaussian.tech"), &state), Ok(()));
    }

    #[test]
    fn third_party_invite_with_a_valid_signature_admits_an_invite() {
        // The identity server's keypair; its public key is advertised in the
        // m.room.third_party_invite, and it signs the `signed` block.
        let seed = gm_util::ed25519::seed_from_material("identity-server");
        let public = gm_util::ed25519::public_key_b64(&seed).unwrap();

        // Carol is joined but lacks invite power (level raised to 50), so only
        // the third-party path can admit dave.
        let mut state = ops_room_state();
        state.retain(|p| p.kind != events::ROOM_POWER_LEVELS);
        state.push(pdu(
            events::ROOM_POWER_LEVELS,
            "@alice:gaussian.tech",
            Some(""),
            r#"{"users":{"@alice:gaussian.tech":100},"users_default":0,"invite":50}"#,
        ));
        state.push(pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@carol:gaussian.tech"),
            r#"{"membership":"join"}"#,
        ));
        state.push(pdu(
            events::ROOM_THIRD_PARTY_INVITE,
            "@alice:gaussian.tech",
            Some("tok-123"),
            &format!(r#"{{"public_key":"{public}"}}"#),
        ));

        // Sign the canonical (signatures-free) `signed` object: {mxid, token}.
        let signing_bytes =
            gm_api::Json::parse(r#"{"mxid":"@dave:gaussian.tech","token":"tok-123"}"#)
                .unwrap()
                .to_string();
        let sig = gm_util::ed25519::sign_b64(signing_bytes.as_bytes(), &seed);
        let invite = pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@dave:gaussian.tech"),
            &format!(
                r#"{{"membership":"invite","third_party_invite":{{"signed":{{"mxid":"@dave:gaussian.tech","token":"tok-123","signatures":{{"identity-server":{{"ed25519:0":"{sig}"}}}}}}}}}}"#
            ),
        );
        assert_eq!(check_auth(&invite, &state), Ok(()));

        // A forged signature (wrong key) does not verify -> falls back to the
        // (failing) invite-power check.
        let forged_sig = gm_util::ed25519::sign_b64(
            signing_bytes.as_bytes(),
            &gm_util::ed25519::seed_from_material("impostor"),
        );
        let forged = pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@dave:gaussian.tech"),
            &format!(
                r#"{{"membership":"invite","third_party_invite":{{"signed":{{"mxid":"@dave:gaussian.tech","token":"tok-123","signatures":{{"identity-server":{{"ed25519:0":"{forged_sig}"}}}}}}}}}}"#
            ),
        );
        assert_eq!(
            check_auth(&forged, &state),
            Err(AuthError::InsufficientPower)
        );

        // An unknown token (no matching third_party_invite) also falls back.
        let unknown = pdu(
            events::ROOM_MEMBER,
            "@carol:gaussian.tech",
            Some("@dave:gaussian.tech"),
            r#"{"membership":"invite","third_party_invite":{"signed":{"token":"nope","signatures":{}}}}"#,
        );
        assert_eq!(
            check_auth(&unknown, &state),
            Err(AuthError::InsufficientPower)
        );
    }
}
