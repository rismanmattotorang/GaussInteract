// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Namespaced agent events the gateway reflects into a room (spec §IV.B).
//!
//! An agent's tool invocations and their results are reflected back into the
//! room as structured, namespaced events so the interaction is visible,
//! replayable and auditable *in-band*. The content keys produced here
//! (`call_id`, `tool`, `args_summary`, `ok`, `summary`) are exactly those the
//! GaussInteract client reads when rendering its inline agent bubbles, so the
//! server and client agree on the wire shape without a shared schema crate yet.
//!
//! Wire serialisation (serde / ruma `MessageLikeEventContent`) lands with the
//! `mcp` feature; this is the plain, std-only shape used by the gateway core.

use std::collections::BTreeMap;

/// `m.gauss.agent.tool_call` — an agent's MCP tool invocation.
pub const TYPE_TOOL_CALL: &str = "m.gauss.agent.tool_call";
/// `m.gauss.agent.tool_result` — the result the gateway reflected back.
pub const TYPE_TOOL_RESULT: &str = "m.gauss.agent.tool_result";
/// `m.gauss.agent.approval` — a human approve/deny receipt.
pub const TYPE_APPROVAL: &str = "m.gauss.agent.approval";
/// `m.gauss.agent.capability` — an agent's capability grant (room state, §IV.C).
pub const TYPE_CAPABILITY: &str = "m.gauss.agent.capability";
/// `m.gauss.agent.policy` — a declarative policy set refining grants (room
/// state, §IV.C): allow/deny/require-review rules evaluated per tool call.
pub const TYPE_POLICY: &str = "m.gauss.agent.policy";

/// A JSON-ish content value. Kept minimal (no serde dependency yet) but
/// sufficient to model the strings, booleans, numbers and lists the agent
/// events and capability grants carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string field.
    Str(String),
    /// A boolean field.
    Bool(bool),
    /// An unsigned-integer field.
    U64(u64),
    /// A list of values.
    List(Vec<Value>),
}

impl Value {
    /// The string, if this is a [`Value::Str`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The boolean, if this is a [`Value::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The integer, if this is a [`Value::U64`].
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(n) => Some(*n),
            _ => None,
        }
    }

    /// The elements, if this is a [`Value::List`].
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }
}

/// An event the gateway will send into a room. `content` maps directly onto the
/// Matrix event `content` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedEvent {
    /// The Matrix event type (one of the `TYPE_*` constants).
    pub event_type: &'static str,
    /// The event content.
    pub content: BTreeMap<String, Value>,
}

impl ReflectedEvent {
    /// Build an `m.gauss.agent.tool_call` event.
    pub fn tool_call(call_id: &str, tool: &str, args_summary: &str) -> Self {
        let mut content = BTreeMap::new();
        content.insert("call_id".into(), Value::Str(call_id.into()));
        content.insert("tool".into(), Value::Str(tool.into()));
        content.insert("args_summary".into(), Value::Str(args_summary.into()));
        Self {
            event_type: TYPE_TOOL_CALL,
            content,
        }
    }

    /// Build an `m.gauss.agent.tool_result` event.
    pub fn tool_result(call_id: &str, tool: &str, ok: bool, summary: &str) -> Self {
        let mut content = BTreeMap::new();
        content.insert("call_id".into(), Value::Str(call_id.into()));
        content.insert("tool".into(), Value::Str(tool.into()));
        content.insert("ok".into(), Value::Bool(ok));
        content.insert("summary".into(), Value::Str(summary.into()));
        Self {
            event_type: TYPE_TOOL_RESULT,
            content,
        }
    }

    /// Build an `m.gauss.agent.approval` receipt event.
    pub fn approval(call_id: &str, decided_by: &str, approved: bool) -> Self {
        let mut content = BTreeMap::new();
        content.insert("call_id".into(), Value::Str(call_id.into()));
        content.insert("decided_by".into(), Value::Str(decided_by.into()));
        content.insert("approved".into(), Value::Bool(approved));
        Self {
            event_type: TYPE_APPROVAL,
            content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_carries_client_field_names() {
        let e = ReflectedEvent::tool_call("c1", "search", "q=foo");
        assert_eq!(e.event_type, "m.gauss.agent.tool_call");
        assert_eq!(e.content.get("tool"), Some(&Value::Str("search".into())));
        assert_eq!(
            e.content.get("args_summary"),
            Some(&Value::Str("q=foo".into()))
        );
    }

    #[test]
    fn tool_result_carries_ok_flag() {
        let e = ReflectedEvent::tool_result("c1", "search", true, "done");
        assert_eq!(e.content.get("ok"), Some(&Value::Bool(true)));
    }
}
