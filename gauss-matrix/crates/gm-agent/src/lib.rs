// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-agent
//!
//! The **agentic AI gateway** of GaussMatrix (GaussInteract-SPECS §IV): the
//! sole, mediated, audited channel through which an AI agent affects a room.
//!
//! Its guiding invariant: admitting an agent to a room must never enlarge that
//! room's trust boundary beyond the humans who admitted it. Every agent action
//! is therefore **authenticated, scoped, mediated and auditable**, and there is
//! no out-of-band side effect — the gateway is the only path.
//!
//! ## Mediation pipeline
//!
//! An inbound MCP [`mcp::ToolCall`] is run through [`AgentGateway::handle`]:
//!
//! ```text
//!   tool call ─▶ capability check (§IV.C) ─▶ classify
//!                     │
//!        ┌────────────┼─────────────────────────────┐
//!     Forbidden     Auto                          Review
//!        │            │                              │
//!     deny +       reflect tool_call,            reflect tool_call,
//!     audit        execute, reflect              queue for human
//!                  tool_result, audit            approval, audit
//!                                                     │
//!                                          resolve(approve|deny) ─▶
//!                                          execute + tool_result | denied
//! ```
//!
//! Every branch appends to a durable, hash-chained audit log (`gm_store::audit`,
//! §IV.D), and the events the gateway reflects ([`events::ReflectedEvent`])
//! carry exactly the content the GaussInteract client renders inline.
//!
//! ## Status
//!
//! Phase-3 scaffold: std-only and compilable so the mediation logic and its
//! guarantees are reviewable and tested, with the audit trail already persisted
//! through the pluggable [`gm_store::Store`] (the in-memory backend by default).
//! The remaining live pieces — the Application Service registration that gives
//! agents cross-signed identities, the MCP transport, and E2EE-aware mediation
//! via `gm-e2ee` — are wired behind the `mcp` feature later.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod capability;
pub mod events;
pub mod mcp;

use crate::capability::{ActionClass, CapabilityGrant};
use crate::events::ReflectedEvent;
use crate::mcp::{ToolCall, ToolExecutor};
use gm_store::{audit, MemoryStore, Store};
use std::fmt;

/// The build/version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors returned by the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GatewayError {
    /// No pending approval matches the given request id.
    UnknownRequest(u64),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::UnknownRequest(id) => {
                write!(f, "no pending approval with id {id}")
            }
        }
    }
}

impl std::error::Error for GatewayError {}

/// A `Review`-class action awaiting human approval (spec §IV.C, §V.F).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// Monotonic identifier, surfaced to the human approver in the client.
    pub request_id: u64,
    /// The in-band call id correlating the eventual result.
    pub call_id: String,
    /// The originating tool call.
    pub call: ToolCall,
}

/// The result of running a tool call (or resolving an approval) through the
/// gateway, including the events to reflect into the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Executed; `events` are reflected into the room (tool_call + tool_result,
    /// or just tool_result when resolving an approval).
    Executed {
        /// Namespaced events to send into the room.
        events: Vec<ReflectedEvent>,
    },
    /// Held for human approval; `event` is the reflected `tool_call` so the
    /// proposed action is visible while it waits.
    AwaitingApproval {
        /// The id to pass to [`AgentGateway::resolve`].
        request_id: u64,
        /// The reflected `tool_call` event.
        event: ReflectedEvent,
    },
    /// Refused. `events` is empty for a scope refusal (nothing ever entered the
    /// room) and carries the approval receipt for a human denial.
    Denied {
        /// Why the action was refused.
        reason: String,
        /// Any events to reflect (e.g. the human's denial receipt).
        events: Vec<ReflectedEvent>,
    },
}

/// The agentic gateway. Holds the pending-approval queue and persists the
/// authoritative, tamper-evident audit log through a pluggable
/// [`gm_store::Store`]; it is the single object the homeserver routes agent
/// traffic through. Generic over the backend, defaulting to the in-memory store.
#[derive(Debug)]
pub struct AgentGateway<S: Store = MemoryStore> {
    next_request_id: u64,
    next_call_seq: u64,
    pending: Vec<PendingApproval>,
    store: S,
}

impl AgentGateway<MemoryStore> {
    /// Create an empty gateway backed by an in-memory store.
    pub fn new() -> Self {
        Self::with_store(MemoryStore::default())
    }
}

impl Default for AgentGateway<MemoryStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Store> AgentGateway<S> {
    /// Create an empty gateway over a specific storage backend, so the audit
    /// trail is persisted where the rest of the homeserver's data lives.
    pub fn with_store(store: S) -> Self {
        Self {
            next_request_id: 0,
            next_call_seq: 0,
            pending: Vec::new(),
            store,
        }
    }

    /// Pending approvals the client should render to a human.
    pub fn pending(&self) -> &[PendingApproval] {
        &self.pending
    }

    /// Load the authoritative audit entries, oldest first (read-only).
    pub fn audit_entries(&self) -> Vec<audit::AuditEntry> {
        audit::entries(&self.store)
    }

    /// Verify the durable audit chain (`Ok(())` if intact, else the index of
    /// the first corrupted entry).
    pub fn verify_audit(&self) -> Result<(), usize> {
        audit::verify(&self.store)
    }

    fn next_call_id(&mut self) -> String {
        let id = format!("call-{}", self.next_call_seq);
        self.next_call_seq += 1;
        id
    }

    /// Mediate an inbound tool call against the agent's capability grant.
    pub fn handle<E: ToolExecutor>(
        &mut self,
        grant: &CapabilityGrant,
        call: ToolCall,
        executor: &mut E,
    ) -> Outcome {
        match grant.classify(&call.tool, &call.room) {
            ActionClass::Forbidden => {
                audit::append(
                    &mut self.store,
                    &call.agent,
                    &format!("denied_by_scope: {} in {}", call.tool, call.room),
                );
                Outcome::Denied {
                    reason: format!("{} is not permitted in {}", call.tool, call.room),
                    events: Vec::new(),
                }
            }
            ActionClass::Auto => {
                let call_id = self.next_call_id();
                audit::append(
                    &mut self.store,
                    &call.agent,
                    &format!("auto_allowed: {}", call.tool),
                );
                let call_event =
                    ReflectedEvent::tool_call(&call_id, &call.tool, &call.args_summary);
                let outcome = executor.execute(&call);
                audit::append(
                    &mut self.store,
                    &call.agent,
                    &format!("executed: {} ok={}", call.tool, outcome.ok),
                );
                let result_event =
                    ReflectedEvent::tool_result(&call_id, &call.tool, outcome.ok, &outcome.summary);
                Outcome::Executed {
                    events: vec![call_event, result_event],
                }
            }
            ActionClass::Review => {
                let call_id = self.next_call_id();
                let request_id = self.next_request_id;
                self.next_request_id += 1;
                audit::append(
                    &mut self.store,
                    &call.agent,
                    &format!("approval_requested: {}", call.tool),
                );
                let call_event =
                    ReflectedEvent::tool_call(&call_id, &call.tool, &call.args_summary);
                self.pending.push(PendingApproval {
                    request_id,
                    call_id,
                    call,
                });
                Outcome::AwaitingApproval {
                    request_id,
                    event: call_event,
                }
            }
        }
    }

    /// Resolve a pending approval with a human decision (spec §IV.C).
    pub fn resolve<E: ToolExecutor>(
        &mut self,
        request_id: u64,
        approved: bool,
        decided_by: &str,
        executor: &mut E,
    ) -> Result<Outcome, GatewayError> {
        let pos = self
            .pending
            .iter()
            .position(|p| p.request_id == request_id)
            .ok_or(GatewayError::UnknownRequest(request_id))?;
        let pending = self.pending.remove(pos);
        let receipt = ReflectedEvent::approval(&pending.call_id, decided_by, approved);

        if approved {
            audit::append(
                &mut self.store,
                &pending.call.agent,
                &format!("approved_by {}: {}", decided_by, pending.call.tool),
            );
            let outcome = executor.execute(&pending.call);
            audit::append(
                &mut self.store,
                &pending.call.agent,
                &format!("executed: {} ok={}", pending.call.tool, outcome.ok),
            );
            let result_event = ReflectedEvent::tool_result(
                &pending.call_id,
                &pending.call.tool,
                outcome.ok,
                &outcome.summary,
            );
            Ok(Outcome::Executed {
                events: vec![receipt, result_event],
            })
        } else {
            audit::append(
                &mut self.store,
                &pending.call.agent,
                &format!("denied_by {}: {}", decided_by, pending.call.tool),
            );
            Ok(Outcome::Denied {
                reason: format!("{} denied by {}", pending.call.tool, decided_by),
                events: vec![receipt],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ActionClass, CapabilityGrant};
    use crate::events::TYPE_TOOL_CALL;
    use crate::mcp::EchoExecutor;

    fn grant() -> CapabilityGrant {
        CapabilityGrant::deny_all("@assistant:gaussian.tech")
            .allow_room("!room:gaussian.tech")
            .allow_tool("search", ActionClass::Auto)
            .allow_tool("send_email", ActionClass::Review)
            .with_rate_limit(30)
    }

    fn call(tool: &str) -> ToolCall {
        ToolCall::new(
            "@assistant:gaussian.tech",
            "!room:gaussian.tech",
            tool,
            "args",
        )
    }

    #[test]
    fn auto_tool_executes_and_reflects_both_events() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        let outcome = gw.handle(&grant(), call("search"), &mut exec);
        match outcome {
            Outcome::Executed { events } => {
                assert_eq!(events.len(), 2);
                assert_eq!(events[0].event_type, TYPE_TOOL_CALL);
            }
            other => panic!("expected Executed, got {other:?}"),
        }
        assert!(gw.pending().is_empty());
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn review_tool_waits_for_human_then_executes_on_approve() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        let request_id = match gw.handle(&grant(), call("send_email"), &mut exec) {
            Outcome::AwaitingApproval { request_id, event } => {
                assert_eq!(event.event_type, TYPE_TOOL_CALL);
                request_id
            }
            other => panic!("expected AwaitingApproval, got {other:?}"),
        };
        assert_eq!(gw.pending().len(), 1);

        let resolved = gw
            .resolve(request_id, true, "@boss:gaussian.tech", &mut exec)
            .expect("known request");
        assert!(matches!(resolved, Outcome::Executed { .. }));
        assert!(gw.pending().is_empty());
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn review_tool_denied_by_human_produces_receipt_only() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        let Outcome::AwaitingApproval { request_id, .. } =
            gw.handle(&grant(), call("send_email"), &mut exec)
        else {
            panic!("expected AwaitingApproval");
        };
        let resolved = gw
            .resolve(request_id, false, "@boss:gaussian.tech", &mut exec)
            .expect("known request");
        match resolved {
            Outcome::Denied { events, .. } => assert_eq!(events.len(), 1),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_tool_is_refused_before_entering_the_room() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        let outcome = gw.handle(&grant(), call("delete_account"), &mut exec);
        match outcome {
            Outcome::Denied { events, .. } => assert!(events.is_empty()),
            other => panic!("expected Denied, got {other:?}"),
        }
        // Refusal is still audited.
        assert_eq!(gw.audit_entries().len(), 1);
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn resolving_unknown_request_errors() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        assert_eq!(
            gw.resolve(42, true, "@boss:gaussian.tech", &mut exec),
            Err(GatewayError::UnknownRequest(42)),
        );
    }
}
