// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Capability scoping (spec §IV.C). The server is the *authority* for an
//! agent's capability grant; the GaussInteract client mirrors a read-only copy.
//!
//! A grant is least-privilege: an agent may only call explicitly allowed tools
//! in explicitly accessible rooms, within a rate limit, and each tool is
//! classified `auto` / `review` / `forbidden`. The grant is itself room state,
//! so it is visible, versioned, federated and revocable.

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

/// An agent's least-privilege capability grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    /// The agent (a cross-signed Matrix identity) this grant scopes.
    pub agent: String,
    /// Tools the agent may call at all.
    pub allowed_tools: Vec<String>,
    /// Rooms the agent may access.
    pub accessible_rooms: Vec<String>,
    /// Maximum tool calls per minute (0 = unlimited).
    pub rate_limit_per_min: u32,
    /// Default classification for tools without an explicit override.
    pub default_class: ActionClass,
    /// Per-tool classification overrides (high-impact tools default to review).
    pub overrides: Vec<(String, ActionClass)>,
}

impl CapabilityGrant {
    /// A deny-all grant; tools and rooms are added explicitly (least privilege).
    pub fn deny_all(agent: impl Into<String>) -> Self {
        Self {
            agent: agent.into(),
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
    pub fn allow_room(mut self, room: impl Into<String>) -> Self {
        self.accessible_rooms.push(room.into());
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
    pub fn permits_room(&self, room: &str) -> bool {
        self.accessible_rooms.iter().any(|r| r == room)
    }

    /// Classify a tool invocation in `room`. A tool that is not allowed, or a
    /// room that is not accessible, resolves to [`ActionClass::Forbidden`].
    pub fn classify(&self, tool: &str, room: &str) -> ActionClass {
        if !self.permits_room(room) || !self.permits_tool(tool) {
            return ActionClass::Forbidden;
        }
        self.overrides
            .iter()
            .find(|(t, _)| t == tool)
            .map(|(_, c)| *c)
            .unwrap_or(self.default_class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_least_privilege_grant() {
        let grant = CapabilityGrant::deny_all("@assistant:gaussian.tech")
            .allow_room("!room:gaussian.tech")
            .allow_tool("search", ActionClass::Auto)
            .allow_tool("send_email", ActionClass::Review)
            .with_rate_limit(30);

        assert_eq!(
            grant.classify("search", "!room:gaussian.tech"),
            ActionClass::Auto
        );
        assert_eq!(
            grant.classify("send_email", "!room:gaussian.tech"),
            ActionClass::Review
        );
        assert_eq!(
            grant.classify("rm_rf", "!room:gaussian.tech"),
            ActionClass::Forbidden
        );
        assert_eq!(
            grant.classify("search", "!other:gaussian.tech"),
            ActionClass::Forbidden
        );
    }
}
