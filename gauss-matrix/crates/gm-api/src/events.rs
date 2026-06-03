// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Core Matrix event type identifiers.
//!
//! These are the `type` strings of the state and message events the service
//! core and state-resolution engine handle. (GaussInteract's agentic events
//! live under the `m.gauss.agent.*` namespace, defined in `gm-agent`.)

/// `m.room.create` — the first event of a room; establishes its version.
pub const ROOM_CREATE: &str = "m.room.create";
/// `m.room.member` — a membership state event.
pub const ROOM_MEMBER: &str = "m.room.member";
/// `m.room.power_levels` — the room's authorisation power levels.
pub const ROOM_POWER_LEVELS: &str = "m.room.power_levels";
/// `m.room.join_rules` — who may join the room.
pub const ROOM_JOIN_RULES: &str = "m.room.join_rules";
/// `m.room.name` — the room's display name.
pub const ROOM_NAME: &str = "m.room.name";
/// `m.room.topic` — the room's topic.
pub const ROOM_TOPIC: &str = "m.room.topic";
/// `m.room.message` — a timeline message.
pub const ROOM_MESSAGE: &str = "m.room.message";
/// `m.room.encryption` — enables E2EE for the room.
pub const ROOM_ENCRYPTION: &str = "m.room.encryption";
/// `m.room.encrypted` — an encrypted event payload.
pub const ROOM_ENCRYPTED: &str = "m.room.encrypted";
/// `m.room.redaction` — redacts (strikes) another event.
pub const ROOM_REDACTION: &str = "m.room.redaction";
