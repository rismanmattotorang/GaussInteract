// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Capability scoping (spec §IV.C). The server is the *authority* for an
//! agent's capability grant; the GaussInteract client mirrors a read-only copy.
//!
//! A grant is least-privilege: an agent may only call explicitly allowed tools
//! in explicitly accessible rooms, within a rate limit, and each tool is
//! classified `auto` / `review` / `forbidden`. The grant is itself room state,
//! so it is visible, versioned, federated and revocable.

use crate::events::{Value, TYPE_CAPABILITY};
use gm_util::{AgentId, RoomId};
use std::collections::BTreeMap;
use std::fmt;

/// How an agent action is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Executed immediately.
    Auto,
    /// Executed only after explicit human approval.
    Review,
    /// Never permitted.
    Forbidden,
}

impl ActionClass {
    /// The wire string for this classification.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionClass::Auto => "auto",
            ActionClass::Review => "review",
            ActionClass::Forbidden => "forbidden",
        }
    }

    /// Parse a classification from its wire string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(ActionClass::Auto),
            "review" => Some(ActionClass::Review),
            "forbidden" => Some(ActionClass::Forbidden),
            _ => None,
        }
    }
}

/// Error decoding a [`CapabilityGrant`] from event content. Because a grant is
/// federated room state (§IV.C), content arriving from another server is
/// untrusted, so every field — especially identifiers — is re-validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present but malformed (bad type, id, or classification).
    InvalidField(&'static str),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::MissingField(k) => write!(f, "missing capability field: {k}"),
            CapabilityError::InvalidField(k) => write!(f, "invalid capability field: {k}"),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// An agent's least-privilege capability grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    /// The agent (a cross-signed Matrix identity) this grant scopes.
    pub agent: AgentId,
    /// Tools the agent may call at all.
    pub allowed_tools: Vec<String>,
    /// Rooms the agent may access.
    pub accessible_rooms: Vec<RoomId>,
    /// Maximum tool calls per minute (0 = unlimited).
    pub rate_limit_per_min: u32,
    /// Default classification for tools without an explicit override.
    pub default_class: ActionClass,
    /// Per-tool classification overrides (high-impact tools default to review).
    pub overrides: Vec<(String, ActionClass)>,
}

impl CapabilityGrant {
    /// A deny-all grant; tools and rooms are added explicitly (least privilege).
    pub fn deny_all(agent: AgentId) -> Self {
        Self {
            agent,
            allowed_tools: Vec::new(),
            accessible_rooms: Vec::new(),
            rate_limit_per_min: 0,
            default_class: ActionClass::Forbidden,
            overrides: Vec::new(),
        }
    }

    /// Allow a tool (builder-style).
    pub fn allow_tool(mut self, tool: impl Into<String>, class: ActionClass) -> Self {
        let tool = tool.into();
        if class != ActionClass::Forbidden {
            self.overrides.push((tool.clone(), class));
        }
        self.allowed_tools.push(tool);
        self
    }

    /// Grant access to a room (builder-style).
    pub fn allow_room(mut self, room: RoomId) -> Self {
        self.accessible_rooms.push(room);
        self
    }

    /// Set the rate limit (builder-style).
    pub fn with_rate_limit(mut self, per_min: u32) -> Self {
        self.rate_limit_per_min = per_min;
        self
    }

    /// Whether the agent may use `tool` at all.
    pub fn permits_tool(&self, tool: &str) -> bool {
        self.allowed_tools.iter().any(|t| t == tool)
    }

    /// Whether the agent may access `room`.
    pub fn permits_room(&self, room: &RoomId) -> bool {
        self.accessible_rooms.iter().any(|r| r == room)
    }

    /// Classify a tool invocation in `room`. A tool that is not allowed, or a
    /// room that is not accessible, resolves to [`ActionClass::Forbidden`].
    pub fn classify(&self, tool: &str, room: &RoomId) -> ActionClass {
        if !self.permits_room(room) || !self.permits_tool(tool) {
            return ActionClass::Forbidden;
        }
        self.overrides
            .iter()
            .find(|(t, _)| t == tool)
            .map(|(_, c)| *c)
            .unwrap_or(self.default_class)
    }

    /// Serialise this grant to `m.gauss.agent.capability` event content, so it
    /// can be stored as room state — visible, versioned, federated, revocable.
    pub fn to_content(&self) -> BTreeMap<String, Value> {
        let mut content = BTreeMap::new();
        content.insert("agent".into(), Value::Str(self.agent.as_str().to_owned()));
        content.insert(
            "rate_limit_per_min".into(),
            Value::U64(u64::from(self.rate_limit_per_min)),
        );
        content.insert(
            "default_class".into(),
            Value::Str(self.default_class.as_str().to_owned()),
        );
        content.insert(
            "allowed_tools".into(),
            Value::List(
                self.allowed_tools
                    .iter()
                    .map(|t| Value::Str(t.clone()))
                    .collect(),
            ),
        );
        content.insert(
            "accessible_rooms".into(),
            Value::List(
                self.accessible_rooms
                    .iter()
                    .map(|r| Value::Str(r.as_str().to_owned()))
                    .collect(),
            ),
        );
        content.insert(
            "overrides".into(),
            Value::List(
                self.overrides
                    .iter()
                    .map(|(tool, class)| {
                        Value::List(vec![
                            Value::Str(tool.clone()),
                            Value::Str(class.as_str().to_owned()),
                        ])
                    })
                    .collect(),
            ),
        );
        content
    }

    /// The grant as a `m.gauss.agent.capability` state event payload.
    pub fn to_event(&self) -> crate::events::ReflectedEvent {
        crate::events::ReflectedEvent {
            event_type: TYPE_CAPABILITY,
            content: self.to_content(),
        }
    }

    /// Decode a grant from (untrusted, possibly federated) event content,
    /// re-validating every identifier and classification.
    pub fn from_content(content: &BTreeMap<String, Value>) -> Result<Self, CapabilityError> {
        let agent_str = field(content, "agent")?
            .as_str()
            .ok_or(CapabilityError::InvalidField("agent"))?;
        let agent =
            AgentId::parse(agent_str).map_err(|_| CapabilityError::InvalidField("agent"))?;

        let rate = field(content, "rate_limit_per_min")?
            .as_u64()
            .ok_or(CapabilityError::InvalidField("rate_limit_per_min"))?;
        let rate_limit_per_min =
            u32::try_from(rate).map_err(|_| CapabilityError::InvalidField("rate_limit_per_min"))?;

        let default_class = field(content, "default_class")?
            .as_str()
            .and_then(ActionClass::parse)
            .ok_or(CapabilityError::InvalidField("default_class"))?;

        let allowed_tools = string_list(content, "allowed_tools")?;

        let mut accessible_rooms = Vec::new();
        for value in list_field(content, "accessible_rooms")? {
            let room = value
                .as_str()
                .and_then(|s| RoomId::parse(s).ok())
                .ok_or(CapabilityError::InvalidField("accessible_rooms"))?;
            accessible_rooms.push(room);
        }

        let mut overrides = Vec::new();
        for value in list_field(content, "overrides")? {
            let pair = value
                .as_list()
                .filter(|p| p.len() == 2)
                .ok_or(CapabilityError::InvalidField("overrides"))?;
            let tool = pair[0]
                .as_str()
                .ok_or(CapabilityError::InvalidField("overrides"))?;
            let class = pair[1]
                .as_str()
                .and_then(ActionClass::parse)
                .ok_or(CapabilityError::InvalidField("overrides"))?;
            overrides.push((tool.to_owned(), class));
        }

        Ok(Self {
            agent,
            allowed_tools,
            accessible_rooms,
            rate_limit_per_min,
            default_class,
            overrides,
        })
    }
}

fn field<'a>(
    content: &'a BTreeMap<String, Value>,
    key: &'static str,
) -> Result<&'a Value, CapabilityError> {
    content.get(key).ok_or(CapabilityError::MissingField(key))
}

fn list_field<'a>(
    content: &'a BTreeMap<String, Value>,
    key: &'static str,
) -> Result<&'a [Value], CapabilityError> {
    field(content, key)?
        .as_list()
        .ok_or(CapabilityError::InvalidField(key))
}

fn string_list(
    content: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Vec<String>, CapabilityError> {
    list_field(content, key)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(CapabilityError::InvalidField(key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_least_privilege_grant() {
        let room = RoomId::parse("!room:gaussian.tech").unwrap();
        let other = RoomId::parse("!other:gaussian.tech").unwrap();
        let grant = CapabilityGrant::deny_all(AgentId::parse("@assistant:gaussian.tech").unwrap())
            .allow_room(room.clone())
            .allow_tool("search", ActionClass::Auto)
            .allow_tool("send_email", ActionClass::Review)
            .with_rate_limit(30);

        assert_eq!(grant.classify("search", &room), ActionClass::Auto);
        assert_eq!(grant.classify("send_email", &room), ActionClass::Review);
        assert_eq!(grant.classify("rm_rf", &room), ActionClass::Forbidden);
        assert_eq!(grant.classify("search", &other), ActionClass::Forbidden);
    }

    fn sample_grant() -> CapabilityGrant {
        CapabilityGrant::deny_all(AgentId::parse("@gauss_agent_x:gaussian.tech").unwrap())
            .allow_room(RoomId::parse("!r:gaussian.tech").unwrap())
            .allow_tool("search", ActionClass::Auto)
            .allow_tool("send_email", ActionClass::Review)
            .with_rate_limit(30)
    }

    #[test]
    fn grant_round_trips_through_event_content() {
        let grant = sample_grant();
        let restored = CapabilityGrant::from_content(&grant.to_content()).unwrap();
        assert_eq!(restored, grant);
        assert_eq!(grant.to_event().event_type, "m.gauss.agent.capability");
    }

    #[test]
    fn decoding_missing_field_fails() {
        let mut content = sample_grant().to_content();
        content.remove("agent");
        assert_eq!(
            CapabilityGrant::from_content(&content),
            Err(CapabilityError::MissingField("agent"))
        );
    }

    #[test]
    fn decoding_rejects_a_malformed_federated_room_id() {
        // A grant arriving from another server carries a bad room id — reject it
        // rather than trusting it (§IV.C federated state is untrusted).
        let mut content = sample_grant().to_content();
        content.insert(
            "accessible_rooms".into(),
            Value::List(vec![Value::Str("not-a-room".into())]),
        );
        assert_eq!(
            CapabilityGrant::from_content(&content),
            Err(CapabilityError::InvalidField("accessible_rooms"))
        );
    }

    #[test]
    fn decoding_rejects_an_unknown_classification() {
        let mut content = sample_grant().to_content();
        content.insert("default_class".into(), Value::Str("sudo".into()));
        assert_eq!(
            CapabilityGrant::from_content(&content),
            Err(CapabilityError::InvalidField("default_class"))
        );
    }
}
