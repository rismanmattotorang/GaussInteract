// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Model Context Protocol ingress (spec §IV.B).
//!
//! The gateway is a bidirectional bridge between Matrix events and MCP. Inbound,
//! an agent's tool invocations arrive as MCP tool calls; outbound, scoped room
//! context is exposed as MCP resources. This module models the inbound call and
//! the result a tool executor returns. The live MCP transport (stdio / HTTP+SSE)
//! is wired behind the `mcp` feature.

use gm_util::{AgentId, GmError, RoomId};

/// An inbound tool invocation from an agent over MCP. The agent and room are
/// validated [`AgentId`] / [`RoomId`] — a malformed call cannot be constructed,
/// so the gateway never has to defend against bad identifiers at mediation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// The agent (a cross-signed Matrix identity) making the call.
    pub agent: AgentId,
    /// The room the call targets.
    pub room: RoomId,
    /// The MCP tool being invoked.
    pub tool: String,
    /// A human-readable rendering of the arguments (shown inline to humans).
    pub args_summary: String,
}

impl ToolCall {
    /// Construct from already-validated identifiers.
    pub fn new(
        agent: AgentId,
        room: RoomId,
        tool: impl Into<String>,
        args_summary: impl Into<String>,
    ) -> Self {
        Self {
            agent,
            room,
            tool: tool.into(),
            args_summary: args_summary.into(),
        }
    }

    /// Parse the raw identifiers received over MCP, validating them. A malformed
    /// agent or room id is rejected here, at the system's edge.
    pub fn parse(
        agent: &str,
        room: &str,
        tool: impl Into<String>,
        args_summary: impl Into<String>,
    ) -> Result<Self, GmError> {
        Ok(Self::new(
            AgentId::parse(agent)?,
            RoomId::parse(room)?,
            tool,
            args_summary,
        ))
    }
}

/// The outcome of actually executing a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutcome {
    /// Whether the tool succeeded.
    pub ok: bool,
    /// A human-readable rendering of the result.
    pub summary: String,
    /// Tokens the execution consumed (LLM/tool usage), metered against the
    /// agent's daily token budget (spec §IV.C, agentic FinOps). An executor that
    /// does not meter usage reports `0`.
    pub tokens: u64,
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
        // A deterministic, stand-in token meter: one token per byte of the tool
        // name and argument summary, so the budget machinery has a real figure
        // to account against until the live MCP transport reports actual usage.
        let tokens = (call.tool.len() + call.args_summary.len()) as u64;
        ToolOutcome {
            ok: true,
            summary: format!("executed {} ({})", call.tool, call.args_summary),
            tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_validates_identifiers_at_the_edge() {
        assert!(ToolCall::parse("@a:gaussian.tech", "!r:gaussian.tech", "search", "q").is_ok());
        // Room id missing its `!` sigil is rejected before construction.
        assert!(ToolCall::parse("@a:gaussian.tech", "not-a-room", "search", "q").is_err());
        // Agent id missing its `@` sigil is rejected too.
        assert!(ToolCall::parse("a:gaussian.tech", "!r:gaussian.tech", "search", "q").is_err());
    }
}
