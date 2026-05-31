// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Namespaced agentic Matrix event types (spec §IV.B–C).
//!
//! Every agent action is reflected back into a room as a structured,
//! **namespaced** event so the interaction is visible, replayable and
//! auditable *in-band*. This module defines those event types and their
//! payloads, plus the capability-grant vocabulary that scopes what an agent
//! may do. The grant itself is room state (§IV.C), so it is visible, versioned,
//! federated, and revocable.
//!
//! Wire serialisation (serde / ruma) is added in Phase 3; these are the plain
//! Rust shapes the rest of the core and the FFI layer reason about.

/// `m.gauss.agent.tool_call` — an agent's MCP tool invocation.
pub const TYPE_TOOL_CALL: &str = "m.gauss.agent.tool_call";
/// `m.gauss.agent.tool_result` — the result the gateway reflected back.
pub const TYPE_TOOL_RESULT: &str = "m.gauss.agent.tool_result";
/// `m.gauss.agent.capability` — an agent's capability grant (room state).
pub const TYPE_CAPABILITY: &str = "m.gauss.agent.capability";
/// `m.gauss.agent.approval` — a human approve/deny receipt.
pub const TYPE_APPROVAL: &str = "m.gauss.agent.approval";

/// How an agent action is classified (spec §IV.C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Executed immediately.
    Auto,
    /// Executed only after explicit human approval.
    Review,
    /// Never permitted.
    Forbidden,
}

/// Common behaviour for the namespaced agent events.
pub trait AgentEvent {
    /// The Matrix event type string this payload is carried under.
    fn event_type(&self) -> &'static str;
}

/// Payload of an `m.gauss.agent.tool_call` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Correlates a call with its [`ToolResult`].
    pub call_id: String,
    /// The MCP tool the agent invoked.
    pub tool: String,
    /// Human-readable rendering of the arguments (shown inline, §V.D).
    pub args_summary: String,
}

impl AgentEvent for ToolCall {
    fn event_type(&self) -> &'static str {
        TYPE_TOOL_CALL
    }
}

/// Payload of an `m.gauss.agent.tool_result` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    /// The [`ToolCall::call_id`] this result corresponds to.
    pub call_id: String,
    /// The MCP tool that produced this result.
    pub tool: String,
    /// Whether the tool succeeded.
    pub ok: bool,
    /// Human-readable rendering of the outcome.
    pub summary: String,
}

impl AgentEvent for ToolResult {
    fn event_type(&self) -> &'static str {
        TYPE_TOOL_RESULT
    }
}

/// Payload of an `m.gauss.agent.approval` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalReceipt {
    /// The [`ToolCall::call_id`] the decision concerns.
    pub call_id: String,
    /// The human (Matrix user) who decided.
    pub decided_by: String,
    /// Whether the action was approved.
    pub approved: bool,
}

impl AgentEvent for ApprovalReceipt {
    fn event_type(&self) -> &'static str {
        TYPE_APPROVAL
    }
}

/// An agent's least-privilege capability grant (spec §IV.C), carried as the
/// `m.gauss.agent.capability` room-state event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    /// The agent (a Matrix identity) this grant scopes.
    pub agent: String,
    /// Tools the agent may call at all.
    pub allowed_tools: Vec<String>,
    /// Rooms the agent may access.
    pub accessible_rooms: Vec<String>,
    /// Maximum tool calls per minute.
    pub rate_limit_per_min: u32,
    /// Default classification for tools without an explicit override.
    pub default_class: ActionClass,
    /// Per-tool classification overrides (e.g. high-impact tools → `Review`).
    pub overrides: Vec<(String, ActionClass)>,
}

impl AgentEvent for CapabilityGrant {
    fn event_type(&self) -> &'static str {
        TYPE_CAPABILITY
    }
}

impl CapabilityGrant {
    /// A deny-all grant; tools/rooms are added explicitly (least privilege).
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
    fn event_type_strings() {
        let call = ToolCall {
            call_id: "c1".into(),
            tool: "search".into(),
            args_summary: "q=foo".into(),
        };
        assert_eq!(call.event_type(), "m.gauss.agent.tool_call");
    }

    #[test]
    fn capability_scoping_is_least_privilege() {
        let mut grant = CapabilityGrant::deny_all("@assistant:example.org");
        grant.accessible_rooms.push("!room:example.org".into());
        grant.allowed_tools.push("search".into());
        grant.allowed_tools.push("send_email".into());
        grant.default_class = ActionClass::Auto;
        grant
            .overrides
            .push(("send_email".into(), ActionClass::Review));

        // allowed tool, allowed room, no override -> Auto
        assert_eq!(
            grant.classify("search", "!room:example.org"),
            ActionClass::Auto
        );
        // high-impact override -> Review
        assert_eq!(
            grant.classify("send_email", "!room:example.org"),
            ActionClass::Review
        );
        // tool not granted -> Forbidden
        assert_eq!(
            grant.classify("delete_account", "!room:example.org"),
            ActionClass::Forbidden
        );
        // room not granted -> Forbidden even for an allowed tool
        assert_eq!(
            grant.classify("search", "!other:example.org"),
            ActionClass::Forbidden
        );
    }
}
