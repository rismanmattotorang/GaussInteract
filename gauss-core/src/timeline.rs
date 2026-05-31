// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Timeline item model (spec §V.D, §V.F).
//!
//! A guiding UX principle is that *agentic features are legible*: an agent's
//! tool calls and results appear inline as **first-class** timeline items, and
//! actions awaiting approval render a clear approve/deny prompt. The model
//! therefore treats agent activity as timeline items, not chrome.

/// A single rendered item in a room timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    /// The Matrix sender (a human user *or* a cross-signed agent identity).
    pub sender: String,
    /// What kind of item this is.
    pub kind: TimelineKind,
}

/// The variants of timeline content the UI knows how to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineKind {
    /// An ordinary text message body.
    Message(String),
    /// An agent's MCP tool invocation (`m.gauss.agent.tool_call`, §IV.B),
    /// shown inline and in full.
    AgentToolCall {
        /// The tool the agent invoked.
        tool: String,
        /// A human-readable rendering of the arguments.
        summary: String,
    },
    /// An agent's tool result (`m.gauss.agent.tool_result`, §IV.B).
    AgentToolResult {
        /// The tool that produced this result.
        tool: String,
        /// A human-readable rendering of the outcome.
        summary: String,
    },
    /// A pending human-in-the-loop approval prompt (§IV.C, §V.F).
    ApprovalPrompt {
        /// Identifier linking the prompt to its [`crate::agent`] request.
        request_id: u64,
        /// The proposed action, shown in full.
        proposed_action: String,
    },
}

impl TimelineItem {
    /// Construct a plain message item.
    pub fn message(sender: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            sender: sender.into(),
            kind: TimelineKind::Message(body.into()),
        }
    }

    /// Whether this item was produced by (or concerns) an AI agent — used by
    /// the UI to visually distinguish agent activity (§V.D).
    pub fn is_agentic(&self) -> bool {
        matches!(
            self.kind,
            TimelineKind::AgentToolCall { .. }
                | TimelineKind::AgentToolResult { .. }
                | TimelineKind::ApprovalPrompt { .. }
        )
    }
}
