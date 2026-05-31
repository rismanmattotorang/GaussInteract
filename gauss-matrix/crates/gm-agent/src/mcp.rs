// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Model Context Protocol ingress (spec §IV.B).
//!
//! The gateway is a bidirectional bridge between Matrix events and MCP. Inbound,
//! an agent's tool invocations arrive as MCP tool calls; outbound, scoped room
//! context is exposed as MCP resources. This module models the inbound call and
//! the result a tool executor returns. The live MCP transport (stdio / HTTP+SSE)
//! is wired behind the `mcp` feature.

/// An inbound tool invocation from an agent over MCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// The agent (a cross-signed Matrix identity) making the call.
    pub agent: String,
    /// The room the call targets.
    pub room: String,
    /// The MCP tool being invoked.
    pub tool: String,
    /// A human-readable rendering of the arguments (shown inline to humans).
    pub args_summary: String,
}

impl ToolCall {
    /// Construct an inbound tool call.
    pub fn new(
        agent: impl Into<String>,
        room: impl Into<String>,
        tool: impl Into<String>,
        args_summary: impl Into<String>,
    ) -> Self {
        Self {
            agent: agent.into(),
            room: room.into(),
            tool: tool.into(),
            args_summary: args_summary.into(),
        }
    }
}

/// The outcome of actually executing a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutcome {
    /// Whether the tool succeeded.
    pub ok: bool,
    /// A human-readable rendering of the result.
    pub summary: String,
}

/// Executes an approved tool call. In production this dispatches to the MCP
/// server that backs the tool; the gateway never executes anything that has not
/// passed capability and (where required) human approval.
pub trait ToolExecutor {
    /// Execute `call`, returning its outcome.
    fn execute(&mut self, call: &ToolCall) -> ToolOutcome;
}

/// A stub executor that echoes success, for the scaffold and tests.
#[derive(Debug, Default)]
pub struct EchoExecutor;

impl ToolExecutor for EchoExecutor {
    fn execute(&mut self, call: &ToolCall) -> ToolOutcome {
        ToolOutcome {
            ok: true,
            summary: format!("executed {} ({})", call.tool, call.args_summary),
        }
    }
}
