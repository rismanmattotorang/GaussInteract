// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Event **redaction** (spec §III.D / room versions).
//!
//! Redaction strips an event down to the keys protocol-critical for
//! authorization and the DAG, dropping everything else (message bodies, profile
//! fields, …). It is applied **before hashing** for the reference-hash event id,
//! so an event's id is invariant under later redaction, and it is the shape a
//! redacted event keeps once its content is struck.
//!
//! The set of preserved keys is **room-version specific**: e.g. from version 8
//! `m.room.join_rules` keeps `allow` (restricted joins), from version 11
//! `m.room.create` keeps *all* content and `m.room.redaction` keeps `redacts`.

use crate::{events, Json};
use std::collections::BTreeMap;

/// Top-level event keys preserved by redaction across all supported versions.
const PRESERVED_TOP_KEYS: &[&str] = &[
    "event_id",
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "prev_state",
    "auth_events",
    "origin",
    "origin_server_ts",
    "membership",
];

/// Redact `event` for `room_version`: keep the protocol-critical top-level keys
/// and, within `content`, only the sub-keys the event type preserves at that
/// version. A non-object input is returned unchanged.
pub fn redact(event: &Json, room_version: u8) -> Json {
    let Some(obj) = event.as_object() else {
        return event.clone();
    };
    let kind = obj.get("type").and_then(Json::as_str).unwrap_or("");

    let mut out = BTreeMap::new();
    for &key in PRESERVED_TOP_KEYS {
        if let Some(value) = obj.get(key) {
            out.insert(key.to_owned(), value.clone());
        }
    }
    out.insert(
        "content".to_owned(),
        Json::Object(redacted_content(kind, obj.get("content"), room_version)),
    );
    Json::Object(out)
}

/// The content kept for an event `kind` at `room_version` (everything else is
/// dropped).
fn redacted_content(
    kind: &str,
    content: Option<&Json>,
    room_version: u8,
) -> BTreeMap<String, Json> {
    let Some(content) = content.and_then(Json::as_object) else {
        return BTreeMap::new();
    };

    // From room version 11 the create event preserves its entire content.
    if kind == events::ROOM_CREATE && room_version >= 11 {
        return content.clone();
    }

    let allowed: &[&str] = match kind {
        events::ROOM_MEMBER => &["membership", "join_authorised_via_users_server"],
        events::ROOM_CREATE => &["creator"],
        events::ROOM_JOIN_RULES if room_version >= 8 => &["join_rule", "allow"],
        events::ROOM_JOIN_RULES => &["join_rule"],
        events::ROOM_POWER_LEVELS => &[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
            "invite",
            "notifications",
        ],
        "m.room.history_visibility" => &["history_visibility"],
        events::ROOM_REDACTION if room_version >= 11 => &["redacts"],
        "m.room.aliases" if room_version < 6 => &["aliases"],
        _ => &[],
    };

    let mut kept = BTreeMap::new();
    for &key in allowed {
        if let Some(value) = content.get(key) {
            kept.insert(key.to_owned(), value.clone());
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(s: &str) -> Json {
        Json::parse(s).unwrap()
    }

    #[test]
    fn member_redaction_keeps_membership_drops_profile() {
        let event = obj(
            r#"{"type":"m.room.member","sender":"@a:x","content":{"membership":"join","displayname":"Al","avatar_url":"mxc://x"}}"#,
        );
        let red = redact(&event, 11);
        let content = red.get("content").unwrap();
        assert_eq!(
            content.get("membership").and_then(Json::as_str),
            Some("join")
        );
        assert!(content.get("displayname").is_none());
        assert!(content.get("avatar_url").is_none());
        // Protocol-critical top-level keys survive.
        assert_eq!(
            red.get("type").and_then(Json::as_str),
            Some("m.room.member")
        );
        assert_eq!(red.get("sender").and_then(Json::as_str), Some("@a:x"));
    }

    #[test]
    fn create_content_is_preserved_from_v11_but_pruned_before() {
        let event = obj(
            r#"{"type":"m.room.create","content":{"creator":"@a:x","room_version":"11","extra":1}}"#,
        );
        // v11: whole content kept.
        assert!(redact(&event, 11)
            .get("content")
            .and_then(|c| c.get("extra"))
            .is_some());
        // v10: only `creator` kept.
        let red10 = redact(&event, 10);
        let c = red10.get("content").unwrap();
        assert_eq!(c.get("creator").and_then(Json::as_str), Some("@a:x"));
        assert!(c.get("room_version").is_none());
    }

    #[test]
    fn join_rules_allow_kept_only_from_v8() {
        let event = obj(
            r#"{"type":"m.room.join_rules","content":{"join_rule":"restricted","allow":[{"x":1}]}}"#,
        );
        assert!(redact(&event, 8)
            .get("content")
            .and_then(|c| c.get("allow"))
            .is_some());
        assert!(redact(&event, 7)
            .get("content")
            .and_then(|c| c.get("allow"))
            .is_none());
    }
}
