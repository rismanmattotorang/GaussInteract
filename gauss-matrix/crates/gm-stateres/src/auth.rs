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
//!   (see [`check_auth`]): self-join into a `public` room or to accept an
//!   invite; invite/kick/ban by a sufficiently-powered member; leaving oneself;
//! - any other sender must be **joined**, with sufficient **power level** for
//!   the event — the `state_default` for state events, the `events_default` for
//!   messages — read from `m.room.power_levels` (before which the room creator
//!   has power 100 and everyone else 0).
//!
//! The remaining rules (restricted joins, third-party invites, redaction power,
//! per-event-type power overrides) layer on top of this and are the next
//! increment.

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
}

/// The default power required to send a state event (no `state_default` set).
const DEFAULT_STATE_POWER: i64 = 50;
/// The default power required to send a message event (no `events_default`).
const DEFAULT_EVENTS_POWER: i64 = 0;
/// Default power to invite / kick / ban when `m.room.power_levels` omits them.
const DEFAULT_INVITE_POWER: i64 = 0;
const DEFAULT_KICK_POWER: i64 = 50;
const DEFAULT_BAN_POWER: i64 = 50;
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

    let required = if event.is_state() {
        view.state_default()
    } else {
        view.events_default()
    };
    if view.power_level(sender) < required {
        return Err(AuthError::InsufficientPower);
    }
    Ok(())
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
            // The room creator's initial join (part of room creation) is allowed.
            if view.creator().as_deref() == Some(sender) && target_current.is_none() {
                return Ok(());
            }
            // Otherwise: a public room, or accepting a pending invite.
            match view.join_rule() {
                "public" => Ok(()),
                _ if target_current == Some("invite") => Ok(()),
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
            if target == sender && view.join_rule() == "knock" {
                Ok(())
            } else {
                Err(AuthError::MembershipForbidden)
            }
        }
        _ => Err(AuthError::MembershipForbidden),
    }
}

/// A read-only view of the room's current state for the auth checks.
struct AuthView<'a> {
    create: Option<&'a Pdu>,
    power_levels: Option<Json>,
    join_rules: Option<Json>,
    members: Vec<(&'a str, String)>, // (user, membership)
}

impl<'a> AuthView<'a> {
    fn new(state: &'a [Pdu]) -> Self {
        let mut create = None;
        let mut power_levels = None;
        let mut join_rules = None;
        let mut members = Vec::new();
        for pdu in state {
            match pdu.kind.as_str() {
                events::ROOM_CREATE => create = Some(pdu),
                events::ROOM_POWER_LEVELS => power_levels = Json::parse(&pdu.content_json).ok(),
                events::ROOM_JOIN_RULES => join_rules = Json::parse(&pdu.content_json).ok(),
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
}
