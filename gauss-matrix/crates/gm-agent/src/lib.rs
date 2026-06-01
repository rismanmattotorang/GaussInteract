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

pub mod appservice;
pub mod capability;
pub mod catalog;
pub mod clock;
pub mod events;
pub mod mcp;
pub mod replay;
pub mod resources;

use crate::appservice::AppserviceRegistration;
use crate::capability::{ActionClass, CapabilityGrant};
use crate::catalog::{DiscoverableTool, ToolCatalog};
use crate::clock::{Clock, SystemClock};
use crate::events::ReflectedEvent;
use crate::mcp::{ToolCall, ToolExecutor};
use crate::resources::{
    render_timeline, room_from_uri, room_resource_uri, McpResource, ResourceContents, RoomContext,
};
use gm_obs::Metrics;
use gm_store::{audit, MemoryStore, Store};
use std::fmt;

/// The rate-limit window: tool calls per agent are counted over this many
/// seconds against the grant's `rate_limit_per_min` (spec §IV.C).
const RATE_WINDOW_SECS: u64 = 60;

/// The build/version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors returned by the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GatewayError {
    /// No pending approval matches the given request id.
    UnknownRequest(u64),
    /// The agent's grant does not permit the requested resource.
    ResourceAccessDenied(String),
    /// The URI is not a resource this gateway exposes.
    UnknownResource(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::UnknownRequest(id) => {
                write!(f, "no pending approval with id {id}")
            }
            GatewayError::ResourceAccessDenied(uri) => {
                write!(f, "resource access denied: {uri}")
            }
            GatewayError::UnknownResource(uri) => {
                write!(f, "unknown resource: {uri}")
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
/// traffic through. Generic over the storage backend (defaulting to the
/// in-memory store) and the [`Clock`] used for rate limiting.
#[derive(Debug)]
pub struct AgentGateway<S: Store = MemoryStore, C: Clock = SystemClock> {
    next_request_id: u64,
    next_call_seq: u64,
    pending: Vec<PendingApproval>,
    store: S,
    clock: C,
    /// `(agent, unix_secs)` of admitted calls, for sliding-window rate limiting.
    recent_calls: Vec<(String, u64)>,
    /// Per-agent daily usage: `agent -> (unix_day, calls_today, tokens_today)`.
    daily_usage: std::collections::HashMap<String, (u64, u32, u64)>,
    metrics: Metrics,
}

impl AgentGateway<MemoryStore, SystemClock> {
    /// Create an empty gateway backed by an in-memory store and system clock.
    pub fn new() -> Self {
        Self::with_store(MemoryStore::default())
    }
}

impl Default for AgentGateway<MemoryStore, SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Store> AgentGateway<S, SystemClock> {
    /// Create an empty gateway over a specific storage backend, so the audit
    /// trail is persisted where the rest of the homeserver's data lives.
    pub fn with_store(store: S) -> Self {
        Self::with_store_and_clock(store, SystemClock)
    }
}

impl<S: Store, C: Clock> AgentGateway<S, C> {
    /// Create an empty gateway over a specific storage backend and clock.
    pub fn with_store_and_clock(store: S, clock: C) -> Self {
        Self {
            next_request_id: 0,
            next_call_seq: 0,
            pending: Vec::new(),
            store,
            clock,
            recent_calls: Vec::new(),
            daily_usage: std::collections::HashMap::new(),
            metrics: Metrics::new(),
        }
    }

    /// Pending approvals the client should render to a human.
    pub fn pending(&self) -> &[PendingApproval] {
        &self.pending
    }

    /// The gateway's metrics registry (Prometheus-renderable, spec §VIII.A).
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Count one mediation outcome and refresh the pending-approvals gauge.
    fn record_outcome(&mut self, outcome: &str) {
        self.metrics
            .inc_counter("gm_agent_actions_total", &[("outcome", outcome)]);
        self.metrics
            .set_gauge("gm_agent_pending_approvals", &[], self.pending.len() as i64);
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

    /// Reconstruct one agent's session from the audit chain for incident review
    /// (the audit moat): the ordered, structured steps that agent took, flagged
    /// with whether the underlying chain verified intact.
    pub fn replay_session(&self, agent: &str) -> replay::SessionReplay {
        replay::replay_session(&self.store, agent)
    }

    /// Reconstruct every agent's session from the audit chain — one
    /// [`replay::SessionReplay`] per agent, in first-appearance order.
    pub fn replay_all(&self) -> Vec<replay::SessionReplay> {
        replay::replay_all(&self.store)
    }

    /// Stream this gateway's durable audit log to a SIEM sink as structured
    /// records (spec §VIII.A), returning the number emitted.
    pub fn stream_audit<K: gm_obs::SiemSink>(&self, sink: &mut K) -> usize {
        gm_obs::stream_audit(&self.store, sink)
    }

    /// The audit log as structured SIEM records — a convenience over
    /// [`Self::stream_audit`] for callers that just want the records.
    pub fn audit_records(&self) -> Vec<gm_obs::AuditRecord> {
        let mut sink = gm_obs::VecSink::default();
        gm_obs::stream_audit(&self.store, &mut sink);
        sink.records
    }

    /// List the MCP resources an agent may read — one timeline resource per
    /// room in its grant, and no others (spec §IV.B, inbound half).
    pub fn list_resources(&mut self, grant: &CapabilityGrant) -> Vec<McpResource> {
        audit::append(
            &mut self.store,
            grant.agent.as_str(),
            &format!("resources_listed: {}", grant.accessible_rooms.len()),
        );
        self.metrics
            .inc_counter("gm_agent_resource_lists_total", &[]);
        grant
            .accessible_rooms
            .iter()
            .map(|room| McpResource {
                uri: room_resource_uri(room),
                name: format!("Timeline of {room}"),
                mime_type: "text/plain".to_owned(),
            })
            .collect()
    }

    /// Read a room resource for an agent, enforcing its room scope. A request
    /// for a room outside the grant is denied (and audited) before any context
    /// is read; the agent can only ever see what it was granted.
    pub fn read_resource<R: RoomContext>(
        &mut self,
        grant: &CapabilityGrant,
        uri: &str,
        ctx: &R,
    ) -> Result<ResourceContents, GatewayError> {
        let room = match room_from_uri(uri) {
            Some(room) => room,
            None => {
                self.metrics
                    .inc_counter("gm_agent_resource_reads_total", &[("result", "unknown")]);
                return Err(GatewayError::UnknownResource(uri.to_owned()));
            }
        };
        if !grant.permits_room(&room) {
            audit::append(
                &mut self.store,
                grant.agent.as_str(),
                &format!("resource_denied: {uri}"),
            );
            self.metrics
                .inc_counter("gm_agent_resource_reads_total", &[("result", "denied")]);
            return Err(GatewayError::ResourceAccessDenied(uri.to_owned()));
        }
        let text = render_timeline(&ctx.messages(&room));
        audit::append(
            &mut self.store,
            grant.agent.as_str(),
            &format!("resource_read: {uri}"),
        );
        self.metrics
            .inc_counter("gm_agent_resource_reads_total", &[("result", "ok")]);
        Ok(ResourceContents {
            uri: uri.to_owned(),
            mime_type: "text/plain".to_owned(),
            text,
        })
    }

    fn next_call_id(&mut self) -> String {
        let id = format!("call-{}", self.next_call_seq);
        self.next_call_seq += 1;
        id
    }

    /// Mediate a tool call, first confirming the calling agent is one this
    /// Application Service actually provisioned (spec §IV.A). A call from an
    /// identity outside the AS's namespace — unprovisioned or impersonating —
    /// is refused (and audited) before mediation.
    pub fn handle_managed<E: ToolExecutor>(
        &mut self,
        registration: &AppserviceRegistration,
        grant: &CapabilityGrant,
        call: ToolCall,
        executor: &mut E,
    ) -> Outcome {
        if !registration.manages(call.agent.as_user_id()) {
            audit::append(
                &mut self.store,
                call.agent.as_str(),
                &format!("unmanaged_agent: {}", call.agent),
            );
            self.record_outcome("unmanaged");
            return Outcome::Denied {
                reason: format!("{} is not a managed agent identity", call.agent),
                events: Vec::new(),
            };
        }
        self.handle(grant, call, executor)
    }

    /// Whether `agent` has exhausted its rate budget. A limit of `0` means
    /// unlimited. Prunes calls outside the window as a side effect.
    fn is_rate_limited(&mut self, agent: &str, limit_per_min: u32) -> bool {
        if limit_per_min == 0 {
            return false;
        }
        let now = self.clock.now_unix_secs();
        let cutoff = now.saturating_sub(RATE_WINDOW_SECS);
        self.recent_calls.retain(|(_, ts)| *ts > cutoff);
        let count = self.recent_calls.iter().filter(|(a, _)| a == agent).count();
        count >= limit_per_min as usize
    }

    /// Record that `agent` consumed one unit of its rate budget now.
    fn note_call(&mut self, agent: &str) {
        let now = self.clock.now_unix_secs();
        self.recent_calls.push((agent.to_owned(), now));
    }

    fn current_day(&self) -> u64 {
        self.clock.now_unix_secs() / 86_400
    }

    /// Get `agent`'s daily-usage entry, rolling it over (zeroing calls *and*
    /// tokens) if the recorded day is not today, so both budgets reset together.
    fn daily_entry(&mut self, agent: &str) -> &mut (u64, u32, u64) {
        let day = self.current_day();
        let entry = self
            .daily_usage
            .entry(agent.to_owned())
            .or_insert((day, 0, 0));
        if entry.0 != day {
            *entry = (day, 0, 0);
        }
        entry
    }

    /// Whether `agent` has exhausted its *daily call* budget. A limit of `0`
    /// means unlimited. Rolls the counter over at the day boundary.
    fn is_over_daily_budget(&mut self, agent: &str, daily_limit: u32) -> bool {
        if daily_limit == 0 {
            return false;
        }
        self.daily_entry(agent).1 >= daily_limit
    }

    /// Whether `agent` has exhausted its *daily token* budget. A budget of `0`
    /// means unlimited. Checked *before* execution: an agent that has already
    /// spent its budget starts no new work (the budget is a ceiling on
    /// initiating activity, so a single call may finish slightly over it).
    fn is_over_token_budget(&mut self, agent: &str, token_budget: u64) -> bool {
        if token_budget == 0 {
            return false;
        }
        self.daily_entry(agent).2 >= token_budget
    }

    /// Record that `agent` consumed one unit of its daily call budget today.
    fn note_daily_call(&mut self, agent: &str) {
        self.daily_entry(agent).1 += 1;
    }

    /// Record that `agent` consumed `tokens` of its daily token budget today.
    fn note_tokens(&mut self, agent: &str, tokens: u64) {
        let entry = self.daily_entry(agent);
        entry.2 = entry.2.saturating_add(tokens);
    }

    /// The tools an agent may *discover* over MCP: those in `catalog` its grant
    /// permits, each tagged with the grant's classification (spec §IV.B). This
    /// is the inbound mirror of the gateway's least-privilege mediation — an
    /// agent enumerates exactly what it may do, nothing more.
    pub fn list_tools(
        &mut self,
        grant: &CapabilityGrant,
        catalog: &ToolCatalog,
    ) -> Vec<DiscoverableTool> {
        let tools = catalog.list_for(grant);
        audit::append(
            &mut self.store,
            grant.agent.as_str(),
            &format!("tools_listed: {}", tools.len()),
        );
        self.metrics.inc_counter("gm_agent_tool_lists_total", &[]);
        tools
    }

    /// Mediate an inbound tool call against the agent's capability grant.
    ///
    /// Order of checks: capability scope first (a forbidden tool never consumes
    /// rate budget), then the per-agent rate limit, then auto-execute or queue
    /// for human approval.
    pub fn handle<E: ToolExecutor>(
        &mut self,
        grant: &CapabilityGrant,
        call: ToolCall,
        executor: &mut E,
    ) -> Outcome {
        // Identifiers were validated when the ToolCall was constructed
        // (gm_util AgentId/RoomId), so mediation can trust them.
        let class = grant.classify(&call.tool, &call.room);
        if class == ActionClass::Forbidden {
            audit::append(
                &mut self.store,
                call.agent.as_str(),
                &format!("denied_by_scope: {} in {}", call.tool, call.room),
            );
            self.record_outcome("denied_scope");
            return Outcome::Denied {
                reason: format!("{} is not permitted in {}", call.tool, call.room),
                events: Vec::new(),
            };
        }
        if self.is_rate_limited(call.agent.as_str(), grant.rate_limit_per_min) {
            audit::append(
                &mut self.store,
                call.agent.as_str(),
                &format!("rate_limited: {}", call.tool),
            );
            self.record_outcome("rate_limited");
            return Outcome::Denied {
                reason: format!(
                    "rate limit of {}/min exceeded for {}",
                    grant.rate_limit_per_min, call.agent
                ),
                events: Vec::new(),
            };
        }
        if self.is_over_daily_budget(call.agent.as_str(), grant.daily_call_limit) {
            audit::append(
                &mut self.store,
                call.agent.as_str(),
                &format!("daily_budget_exceeded: {}", call.tool),
            );
            self.record_outcome("budget_exceeded");
            return Outcome::Denied {
                reason: format!(
                    "daily budget of {} calls exceeded for {}",
                    grant.daily_call_limit, call.agent
                ),
                events: Vec::new(),
            };
        }
        if self.is_over_token_budget(call.agent.as_str(), grant.daily_token_budget) {
            audit::append(
                &mut self.store,
                call.agent.as_str(),
                &format!("token_budget_exceeded: {}", call.tool),
            );
            self.record_outcome("token_budget_exceeded");
            return Outcome::Denied {
                reason: format!(
                    "daily token budget of {} exceeded for {}",
                    grant.daily_token_budget, call.agent
                ),
                events: Vec::new(),
            };
        }
        self.note_call(call.agent.as_str());
        self.note_daily_call(call.agent.as_str());
        match class {
            ActionClass::Forbidden => unreachable!("handled above"),
            ActionClass::Auto => {
                let call_id = self.next_call_id();
                audit::append(
                    &mut self.store,
                    call.agent.as_str(),
                    &format!("auto_allowed: {}", call.tool),
                );
                let call_event =
                    ReflectedEvent::tool_call(&call_id, &call.tool, &call.args_summary);
                let outcome = executor.execute(&call);
                self.note_tokens(call.agent.as_str(), outcome.tokens);
                audit::append(
                    &mut self.store,
                    call.agent.as_str(),
                    &format!(
                        "executed: {} ok={} tokens={}",
                        call.tool, outcome.ok, outcome.tokens
                    ),
                );
                self.metrics.add_counter(
                    "gm_agent_tokens_total",
                    &[("agent", call.agent.as_str())],
                    outcome.tokens,
                );
                let result_event =
                    ReflectedEvent::tool_result(&call_id, &call.tool, outcome.ok, &outcome.summary);
                self.record_outcome("executed");
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
                    call.agent.as_str(),
                    &format!("approval_requested: {}", call.tool),
                );
                let call_event =
                    ReflectedEvent::tool_call(&call_id, &call.tool, &call.args_summary);
                self.pending.push(PendingApproval {
                    request_id,
                    call_id,
                    call,
                });
                self.record_outcome("review");
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
                pending.call.agent.as_str(),
                &format!("approved_by {}: {}", decided_by, pending.call.tool),
            );
            let outcome = executor.execute(&pending.call);
            self.note_tokens(pending.call.agent.as_str(), outcome.tokens);
            audit::append(
                &mut self.store,
                pending.call.agent.as_str(),
                &format!(
                    "executed: {} ok={} tokens={}",
                    pending.call.tool, outcome.ok, outcome.tokens
                ),
            );
            self.metrics.add_counter(
                "gm_agent_tokens_total",
                &[("agent", pending.call.agent.as_str())],
                outcome.tokens,
            );
            let result_event = ReflectedEvent::tool_result(
                &pending.call_id,
                &pending.call.tool,
                outcome.ok,
                &outcome.summary,
            );
            self.record_outcome("executed");
            Ok(Outcome::Executed {
                events: vec![receipt, result_event],
            })
        } else {
            audit::append(
                &mut self.store,
                pending.call.agent.as_str(),
                &format!("denied_by {}: {}", decided_by, pending.call.tool),
            );
            self.record_outcome("denied_human");
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
    use crate::clock::ManualClock;
    use crate::events::TYPE_TOOL_CALL;
    use crate::mcp::EchoExecutor;
    use gm_store::MemoryStore;
    use gm_util::{AgentId, RoomId};

    const AGENT: &str = "@assistant:gaussian.tech";
    const ROOM: &str = "!room:gaussian.tech";

    fn grant() -> CapabilityGrant {
        CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto)
            .allow_tool("send_email", ActionClass::Review)
            .with_rate_limit(30)
    }

    fn call(tool: &str) -> ToolCall {
        ToolCall::parse(AGENT, ROOM, tool, "args").unwrap()
    }

    fn gateway_at(secs: u64) -> AgentGateway<MemoryStore, ManualClock> {
        AgentGateway::with_store_and_clock(MemoryStore::default(), ManualClock::new(secs))
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

    #[test]
    fn rate_limit_blocks_excess_calls_then_recovers_after_window() {
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto)
            .with_rate_limit(2);
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;
        let c = || ToolCall::parse(AGENT, ROOM, "search", "q").unwrap();

        // Two calls fit the budget.
        assert!(matches!(
            gw.handle(&grant, c(), &mut exec),
            Outcome::Executed { .. }
        ));
        assert!(matches!(
            gw.handle(&grant, c(), &mut exec),
            Outcome::Executed { .. }
        ));
        // The third in the same minute is refused (and audited).
        match gw.handle(&grant, c(), &mut exec) {
            Outcome::Denied { reason, events } => {
                assert!(reason.contains("rate limit"));
                assert!(events.is_empty());
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        // After the window slides past, the budget refreshes.
        gw.clock.advance(61);
        assert!(matches!(
            gw.handle(&grant, c(), &mut exec),
            Outcome::Executed { .. }
        ));
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn zero_rate_limit_means_unlimited() {
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto); // rate_limit defaults to 0
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;
        for _ in 0..5 {
            assert!(matches!(
                gw.handle(&grant, call("search"), &mut exec),
                Outcome::Executed { .. }
            ));
        }
    }

    #[test]
    fn forbidden_tool_does_not_consume_rate_budget() {
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto)
            .with_rate_limit(1);
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;
        // A forbidden tool is refused by scope and must not spend the budget.
        assert!(matches!(
            gw.handle(&grant, call("rm_rf"), &mut exec),
            Outcome::Denied { .. }
        ));
        // The single allowed call still goes through.
        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
    }

    #[test]
    fn identifiers_are_validated_at_construction() {
        // Malformed ids can no longer reach the gateway: they fail to parse.
        assert!(ToolCall::parse(AGENT, "not-a-room", "search", "q").is_err());
        // A well-formed call mediates normally.
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;
        assert!(matches!(
            gw.handle(&grant(), call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn list_resources_exposes_only_granted_rooms() {
        let mut gw = AgentGateway::new();
        let resources = gw.list_resources(&grant());
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "gauss://room/!room:gaussian.tech");
    }

    #[test]
    fn read_resource_returns_scoped_timeline_and_audits() {
        use crate::resources::{MapRoomContext, Message};
        let room = RoomId::parse(ROOM).unwrap();
        let ctx = MapRoomContext::default().with_messages(
            &room,
            vec![
                Message::new("@a:gaussian.tech", "hello"),
                Message::new(AGENT, "on it"),
            ],
        );
        let mut gw = AgentGateway::new();
        let contents = gw
            .read_resource(&grant(), &room_resource_uri(&room), &ctx)
            .expect("granted room");
        assert!(contents.text.contains("hello"));
        assert_eq!(contents.mime_type, "text/plain");
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn read_resource_denies_rooms_outside_the_grant() {
        use crate::resources::MapRoomContext;
        let secret = RoomId::parse("!secret:gaussian.tech").unwrap();
        let ctx = MapRoomContext::default();
        let mut gw = AgentGateway::new();
        let err = gw
            .read_resource(&grant(), &room_resource_uri(&secret), &ctx)
            .unwrap_err();
        assert!(matches!(err, GatewayError::ResourceAccessDenied(_)));
        // The denial is recorded.
        assert_eq!(gw.audit_entries().len(), 1);
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn read_resource_rejects_unknown_uris() {
        use crate::resources::MapRoomContext;
        let ctx = MapRoomContext::default();
        let mut gw = AgentGateway::new();
        let err = gw
            .read_resource(&grant(), "https://example.org/secrets", &ctx)
            .unwrap_err();
        assert!(matches!(err, GatewayError::UnknownResource(_)));
    }

    #[test]
    fn handle_managed_rejects_agents_outside_the_appservice_namespace() {
        use crate::appservice::{AgentNamespace, AppserviceRegistration};
        let reg = AppserviceRegistration::new(
            "gauss-agents",
            "gauss",
            AgentNamespace::new("gaussian.tech", "gauss_agent_"),
        )
        .with_tokens("as-secret", "hs-secret");
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;

        // grant()'s agent (@assistant:…) is not in the gauss_agent_ namespace.
        assert!(matches!(
            gw.handle_managed(&reg, &grant(), call("search"), &mut exec),
            Outcome::Denied { .. }
        ));

        // A properly provisioned agent in the namespace is mediated normally.
        let agent = reg.namespace.mint("assistant").unwrap();
        let room = RoomId::parse(ROOM).unwrap();
        let managed_grant = CapabilityGrant::deny_all(agent.clone())
            .allow_room(room.clone())
            .allow_tool("search", ActionClass::Auto);
        let managed_call = ToolCall::new(agent, room, "search", "q");
        assert!(matches!(
            gw.handle_managed(&reg, &managed_grant, managed_call, &mut exec),
            Outcome::Executed { .. }
        ));
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn metrics_count_mediation_outcomes() {
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;

        gw.handle(&grant(), call("search"), &mut exec); // auto -> executed
        gw.handle(&grant(), call("send_email"), &mut exec); // review -> pending
        gw.handle(&grant(), call("rm_rf"), &mut exec); // forbidden -> denied_scope

        assert_eq!(
            gw.metrics()
                .counter("gm_agent_actions_total", &[("outcome", "executed")]),
            1
        );
        assert_eq!(
            gw.metrics()
                .counter("gm_agent_actions_total", &[("outcome", "review")]),
            1
        );
        assert_eq!(
            gw.metrics()
                .counter("gm_agent_actions_total", &[("outcome", "denied_scope")]),
            1
        );

        // The Prometheus rendering reflects the pending-approvals gauge.
        let text = gw.metrics().render_prometheus();
        assert!(text.contains("# TYPE gm_agent_actions_total counter"));
        assert!(text.contains("gm_agent_pending_approvals 1"));
    }

    #[test]
    fn daily_budget_blocks_excess_calls_then_resets_next_day() {
        use gm_util::{AgentId, RoomId};
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto)
            .with_daily_limit(2);
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;

        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        // Third call today exceeds the daily budget.
        match gw.handle(&grant, call("search"), &mut exec) {
            Outcome::Denied { reason, .. } => assert!(reason.contains("daily budget")),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert_eq!(
            gw.metrics()
                .counter("gm_agent_actions_total", &[("outcome", "budget_exceeded")]),
            1
        );
        // A day later the budget resets.
        gw.clock.advance(86_400);
        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn token_budget_blocks_once_spent_and_resets_next_day() {
        use gm_util::{AgentId, RoomId};
        // EchoExecutor meters len("search") + len("args") = 6 + 4 = 10 tokens
        // per call. A budget of 15 admits the first call (spend 10, still under),
        // then the second sees 10 >= 15? no — so it admits and spends to 20, and
        // the third is refused. Set the budget to 10 so exactly one call fits.
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto)
            .with_daily_token_budget(10);
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;

        // First call: budget not yet spent, executes and consumes 10 tokens.
        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        // Second call: 10 tokens already spent >= budget of 10, refused.
        match gw.handle(&grant, call("search"), &mut exec) {
            Outcome::Denied { reason, .. } => assert!(reason.contains("token budget")),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert_eq!(
            gw.metrics().counter(
                "gm_agent_actions_total",
                &[("outcome", "token_budget_exceeded")]
            ),
            1
        );
        assert_eq!(
            gw.metrics()
                .counter("gm_agent_tokens_total", &[("agent", AGENT)]),
            10
        );
        // A day later the token budget resets and a call goes through again.
        gw.clock.advance(86_400);
        assert!(matches!(
            gw.handle(&grant, call("search"), &mut exec),
            Outcome::Executed { .. }
        ));
        assert_eq!(gw.verify_audit(), Ok(()));
    }

    #[test]
    fn zero_token_budget_means_unlimited() {
        use gm_util::{AgentId, RoomId};
        let grant = CapabilityGrant::deny_all(AgentId::parse(AGENT).unwrap())
            .allow_room(RoomId::parse(ROOM).unwrap())
            .allow_tool("search", ActionClass::Auto); // daily_token_budget defaults to 0
        let mut gw = gateway_at(1_000);
        let mut exec = EchoExecutor;
        for _ in 0..5 {
            assert!(matches!(
                gw.handle(&grant, call("search"), &mut exec),
                Outcome::Executed { .. }
            ));
        }
    }

    #[test]
    fn replay_reconstructs_a_real_gateway_session() {
        use crate::replay::{DenyReason, StepKind};
        let mut gw = AgentGateway::new();
        let mut exec = EchoExecutor;

        // search (auto) executes; rm_rf is denied by scope; send_email queues
        // for review and is then approved + executed.
        gw.handle(&grant(), call("search"), &mut exec);
        gw.handle(&grant(), call("rm_rf"), &mut exec);
        let Outcome::AwaitingApproval { request_id, .. } =
            gw.handle(&grant(), call("send_email"), &mut exec)
        else {
            panic!("expected AwaitingApproval");
        };
        gw.resolve(request_id, true, "@boss:gaussian.tech", &mut exec)
            .expect("known request");

        let session = gw.replay_session(AGENT);
        assert!(session.chain_intact);
        // The classifier matches the gateway's actual audit vocabulary.
        assert_eq!(session.executions(), 2); // search + send_email
        assert_eq!(session.denials(), 1); // rm_rf scope denial
                                          // EchoExecutor meters len(tool)+len("args"): search=6+4=10, send_email=10+4=14.
        assert_eq!(session.total_tokens(), 24);
        assert!(session
            .steps
            .iter()
            .any(|s| s.kind == StepKind::Denied(DenyReason::Scope)));
        assert!(session.steps.iter().any(|s| s.kind == StepKind::Approved));

        // The whole-deployment view groups by agent (here, just the one).
        assert_eq!(gw.replay_all().len(), 1);
    }

    #[test]
    fn list_tools_returns_only_granted_tools_with_grant_classification() {
        use crate::catalog::{ToolCatalog, ToolSpec};
        let catalog = ToolCatalog::new()
            .with_tool(ToolSpec::new("search", "Search", ActionClass::Auto))
            .with_tool(ToolSpec::new("send_email", "Email", ActionClass::Review))
            .with_tool(ToolSpec::new("rm_rf", "Danger", ActionClass::Forbidden));
        let mut gw = AgentGateway::new();
        let discoverable = gw.list_tools(&grant(), &catalog);
        let names: Vec<_> = discoverable.iter().map(|t| t.name.as_str()).collect();
        // grant() permits search (auto) + send_email (review); rm_rf is not granted.
        assert_eq!(names, ["search", "send_email"]);
        assert_eq!(gw.audit_records().len(), 1);
    }
}
