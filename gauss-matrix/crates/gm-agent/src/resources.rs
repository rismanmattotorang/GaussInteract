// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! MCP resource exposure — the inbound half of the gateway (spec §IV.B).
//!
//! Outbound, the gateway mediates an agent's tool calls. Inbound, it exposes
//! **scoped** room context to the agent as MCP resources: only the rooms, and
//! only the message history, the agent's capability grant permits. An agent can
//! therefore *read* exactly what it has been given and nothing more, and every
//! access is auditable — the same trust-boundary invariant as the write path.
//!
//! This module models the resource shapes (`resources/list` descriptors and
//! `resources/read` contents) and the room-context source the gateway reads
//! through; the live MCP transport is wired behind the `mcp` feature.

use gm_util::RoomId;
use std::collections::BTreeMap;

/// URI scheme prefix for a room's timeline resource: `gauss://room/{room_id}`.
const ROOM_URI_PREFIX: &str = "gauss://room/";

/// A single message of room context exposed to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The Matrix sender.
    pub sender: String,
    /// The message body.
    pub body: String,
}

impl Message {
    /// Construct a message.
    pub fn new(sender: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            sender: sender.into(),
            body: body.into(),
        }
    }
}

/// The source of room history. Implemented by the homeserver over `gm-store` /
/// `gm-svc`; the gateway only ever reads through this, never around it.
pub trait RoomContext {
    /// The (already access-checked at the room level) message history of `room`.
    fn messages(&self, room: &RoomId) -> Vec<Message>;
}

/// An MCP resource descriptor, as returned by `resources/list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpResource {
    /// The resource URI (`gauss://room/{room_id}`).
    pub uri: String,
    /// A human-readable name.
    pub name: String,
    /// The MIME type of the resource contents.
    pub mime_type: String,
}

/// The contents of a resource, as returned by `resources/read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceContents {
    /// The resource URI this content is for.
    pub uri: String,
    /// The MIME type.
    pub mime_type: String,
    /// The resource body.
    pub text: String,
}

/// The `gauss://room/{id}` URI for a room's timeline resource.
pub fn room_resource_uri(room: &RoomId) -> String {
    format!("{ROOM_URI_PREFIX}{}", room.as_str())
}

/// Parse a room resource URI back into a [`RoomId`], or `None` if it is not a
/// well-formed room resource URI.
pub fn room_from_uri(uri: &str) -> Option<RoomId> {
    let rest = uri.strip_prefix(ROOM_URI_PREFIX)?;
    RoomId::parse(rest).ok()
}

/// Render a room's messages as the plain-text body of a resource.
pub fn render_timeline(messages: &[Message]) -> String {
    messages
        .iter()
        .map(|m| format!("{}: {}", m.sender, m.body))
        .collect::<Vec<_>>()
        .join("\n")
}

/// An in-memory [`RoomContext`] for the scaffold and tests.
#[derive(Debug, Default)]
pub struct MapRoomContext {
    rooms: BTreeMap<String, Vec<Message>>,
}

impl MapRoomContext {
    /// Add a room's messages (builder-style).
    pub fn with_messages(mut self, room: &RoomId, messages: Vec<Message>) -> Self {
        self.rooms.insert(room.as_str().to_owned(), messages);
        self
    }
}

impl RoomContext for MapRoomContext {
    fn messages(&self, room: &RoomId) -> Vec<Message> {
        self.rooms.get(room.as_str()).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_round_trips() {
        let room = RoomId::parse("!r:gaussian.tech").unwrap();
        let uri = room_resource_uri(&room);
        assert_eq!(uri, "gauss://room/!r:gaussian.tech");
        assert_eq!(room_from_uri(&uri), Some(room));
        assert_eq!(room_from_uri("gauss://room/not-a-room"), None);
        assert_eq!(room_from_uri("https://example.org"), None);
    }

    #[test]
    fn render_joins_messages() {
        let text = render_timeline(&[
            Message::new("@a:gaussian.tech", "hello"),
            Message::new("@b:gaussian.tech", "hi"),
        ]);
        assert_eq!(text, "@a:gaussian.tech: hello\n@b:gaussian.tech: hi");
    }
}
