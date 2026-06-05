// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Replayable agent sessions for incident review (the audit moat, §IV.D).
//!
//! Every gateway decision is already written to the durable, hash-chained audit
//! log. This module reconstructs, *per agent*, the ordered sequence of exactly
//! what that agent did — denials, executions, approvals, resource reads — so a
//! reviewer can replay an incident step by step. Because the reconstruction is
//! only as trustworthy as the log it reads, a [`SessionReplay`] carries whether
//! the underlying chain verified: a replay over a tampered chain is flagged, not
//! silently trusted.
//!
//! The gateway emits a small, fixed vocabulary of audit-event strings, so this
//! module classifies each entry into a structured [`StepKind`] by matching that
//! vocabulary while preserving the raw event for the record.

use gm_store::audit::{self, AuditEntry};
use gm_store::Store;

/// Why the gateway refused a call, recovered from the audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The tool/room was outside the agent's capability grant.
    Scope,
    /// The per-minute rate limit was exhausted.
    RateLimit,
    /// The per-day call budget was exhausted.
    DailyCallBudget,
    /// The per-day token budget was exhausted.
    TokenBudget,
    /// A declarative policy rule denied the call.
    Policy,
    /// A human denied a queued review-class call.
    Human,
}

/// The structured classification of one audit entry in an agent's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    /// A call was refused (before or after human review); carries the reason.
    Denied(DenyReason),
    /// An auto-class call was admitted for immediate execution.
    AutoAllowed,
    /// A review-class call was queued for human approval.
    ApprovalRequested,
    /// A human approved a queued call.
    Approved,
    /// A tool executed; carries whether it succeeded and the tokens it spent.
    Executed {
        /// Whether the tool reported success.
        ok: bool,
        /// Tokens the execution consumed (0 if the meter reported none).
        tokens: u64,
    },
    /// An MCP resource read was attempted; `granted` is whether it was allowed.
    ResourceAccess {
        /// Whether the read was permitted by the grant.
        granted: bool,
    },
    /// A tool/resource discovery (`tools/list` or `resources/list`).
    Discovery,
    /// A scoped agent-memory operation (store / recall / forget).
    Memory,
    /// The call was delegated to this agent by another (multi-agent
    /// orchestration); carries the delegating principal.
    Delegated {
        /// The agent that delegated the call.
        by: String,
    },
    /// A call from an identity outside the Application Service namespace.
    UnmanagedAgent,
    /// An entry the replay does not specifically classify.
    Other,
}

/// One reconstructed step in an agent's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStep {
    /// The step's 0-based position in the *global* audit chain, so steps from
    /// different agents can be interleaved back into real time order.
    pub seq: usize,
    /// The structured classification of the entry.
    pub kind: StepKind,
    /// The raw audit-event string, preserved verbatim for the record.
    pub event: String,
}

/// A reconstructed agent session: the ordered steps a single agent took, plus
/// whether the audit chain they were recovered from verified intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReplay {
    /// The agent whose session this is.
    pub agent: String,
    /// The agent's steps, in audit-chain (chronological) order.
    pub steps: Vec<SessionStep>,
    /// Whether the underlying audit chain verified. A replay over a tampered
    /// chain (`false`) must be treated as untrustworthy.
    pub chain_intact: bool,
}

impl SessionReplay {
    /// How many of the agent's calls actually executed.
    pub fn executions(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.kind, StepKind::Executed { .. }))
            .count()
    }

    /// How many of the agent's calls were refused (for any reason).
    pub fn denials(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.kind, StepKind::Denied(_)))
            .count()
    }

    /// Total tokens the agent consumed across all executions in the session —
    /// the FinOps figure recovered straight from the tamper-evident record.
    pub fn total_tokens(&self) -> u64 {
        self.steps
            .iter()
            .map(|s| match s.kind {
                StepKind::Executed { tokens, .. } => tokens,
                _ => 0,
            })
            .sum()
    }
}

/// Classify one audit-event string into a structured [`StepKind`]. The gateway
/// controls this vocabulary, so the matching is exact; order matters where one
/// prefix is a prefix of another (`denied_by_scope` before `denied_by `).
fn classify(event: &str) -> StepKind {
    if event.starts_with("denied_by_scope") {
        StepKind::Denied(DenyReason::Scope)
    } else if event.starts_with("rate_limited") {
        StepKind::Denied(DenyReason::RateLimit)
    } else if event.starts_with("daily_budget_exceeded") {
        StepKind::Denied(DenyReason::DailyCallBudget)
    } else if event.starts_with("token_budget_exceeded") {
        StepKind::Denied(DenyReason::TokenBudget)
    } else if event.starts_with("policy_denied") {
        StepKind::Denied(DenyReason::Policy)
    } else if event.starts_with("denied_by ") {
        StepKind::Denied(DenyReason::Human)
    } else if event.starts_with("approved_by ") {
        StepKind::Approved
    } else if let Some(rest) = event.strip_prefix("delegated_by ") {
        // "delegated_by <orchestrator>: <tool>" -> capture the orchestrator.
        StepKind::Delegated {
            by: rest.split(": ").next().unwrap_or("").to_owned(),
        }
    } else if event.starts_with("auto_allowed") {
        StepKind::AutoAllowed
    } else if event.starts_with("approval_requested") {
        StepKind::ApprovalRequested
    } else if event.starts_with("executed:") {
        StepKind::Executed {
            ok: parse_kv(event, "ok=").map(|v| v == "true").unwrap_or(false),
            tokens: parse_kv(event, "tokens=")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    } else if event.starts_with("resource_read") {
        StepKind::ResourceAccess { granted: true }
    } else if event.starts_with("resource_denied") {
        StepKind::ResourceAccess { granted: false }
    } else if event.starts_with("resources_listed") || event.starts_with("tools_listed") {
        StepKind::Discovery
    } else if event.starts_with("memory_denied") {
        StepKind::Denied(DenyReason::Scope)
    } else if event.starts_with("memory_") {
        StepKind::Memory
    } else if event.starts_with("unmanaged_agent") {
        StepKind::UnmanagedAgent
    } else {
        StepKind::Other
    }
}

/// Extract the whitespace-delimited token following `key` (e.g. `tokens=` ->
/// `"10"` from `executed: search ok=true tokens=10`).
fn parse_kv<'a>(event: &'a str, key: &str) -> Option<&'a str> {
    let rest = &event[event.find(key)? + key.len()..];
    Some(rest.split_whitespace().next().unwrap_or(rest))
}

/// Reconstruct `agent`'s session from `store`'s audit log, preserving global
/// chain order, and record whether the chain verified.
pub fn replay_session<S: Store>(store: &S, agent: &str) -> SessionReplay {
    let chain_intact = audit::verify(store).is_ok();
    let steps = audit::entries(store)
        .into_iter()
        .enumerate()
        .filter(|(_, e)| e.actor == agent)
        .map(|(seq, e)| SessionStep {
            seq,
            kind: classify(&e.event),
            event: e.event,
        })
        .collect();
    SessionReplay {
        agent: agent.to_owned(),
        steps,
        chain_intact,
    }
}

/// Reconstruct every agent's session from `store`, one [`SessionReplay`] per
/// distinct actor, ordered by the actor's first appearance in the chain.
pub fn replay_all<S: Store>(store: &S) -> Vec<SessionReplay> {
    let chain_intact = audit::verify(store).is_ok();
    let entries = audit::entries(store);
    let mut order: Vec<String> = Vec::new();
    for e in &entries {
        if !order.iter().any(|a| a == &e.actor) {
            order.push(e.actor.clone());
        }
    }
    order
        .into_iter()
        .map(|agent| {
            let steps = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.actor == agent)
                .map(|(seq, e)| SessionStep {
                    seq,
                    kind: classify(&e.event),
                    event: e.event.clone(),
                })
                .collect();
            SessionReplay {
                agent,
                steps,
                chain_intact,
            }
        })
        .collect()
}

/// Classify a single already-loaded [`AuditEntry`] — exposed for callers that
/// have entries in hand and only want the structured kind.
pub fn classify_entry(entry: &AuditEntry) -> StepKind {
    classify(&entry.event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_store::MemoryStore;

    const AGENT: &str = "@assistant:gaussian.tech";

    fn log() -> MemoryStore {
        let mut store = MemoryStore::default();
        // A plausible session: a scope denial, an auto execution, a queued
        // review then its human approval + execution, and a token-budget refusal.
        audit::append(
            &mut store,
            AGENT,
            "denied_by_scope: rm_rf in !r:gaussian.tech",
        );
        audit::append(&mut store, AGENT, "auto_allowed: search");
        audit::append(&mut store, AGENT, "executed: search ok=true tokens=10");
        audit::append(&mut store, AGENT, "approval_requested: send_email");
        audit::append(
            &mut store,
            AGENT,
            "approved_by @boss:gaussian.tech: send_email",
        );
        audit::append(&mut store, AGENT, "executed: send_email ok=true tokens=42");
        audit::append(&mut store, AGENT, "token_budget_exceeded: search");
        store
    }

    #[test]
    fn reconstructs_the_ordered_session_with_structured_steps() {
        let store = log();
        let session = replay_session(&store, AGENT);

        assert!(session.chain_intact);
        let kinds: Vec<_> = session.steps.iter().map(|s| s.kind.clone()).collect();
        assert_eq!(
            kinds,
            vec![
                StepKind::Denied(DenyReason::Scope),
                StepKind::AutoAllowed,
                StepKind::Executed {
                    ok: true,
                    tokens: 10
                },
                StepKind::ApprovalRequested,
                StepKind::Approved,
                StepKind::Executed {
                    ok: true,
                    tokens: 42
                },
                StepKind::Denied(DenyReason::TokenBudget),
            ]
        );
        // Global sequence indices are preserved (single agent -> 0..7).
        assert_eq!(session.steps.first().unwrap().seq, 0);
        assert_eq!(session.steps.last().unwrap().seq, 6);
    }

    #[test]
    fn summaries_recover_finops_and_outcome_counts() {
        let session = replay_session(&log(), AGENT);
        assert_eq!(session.executions(), 2);
        assert_eq!(session.denials(), 2); // scope + token budget
        assert_eq!(session.total_tokens(), 52); // 10 + 42
    }

    #[test]
    fn human_denial_is_distinguished_from_scope_denial() {
        let mut store = MemoryStore::default();
        audit::append(
            &mut store,
            AGENT,
            "denied_by @boss:gaussian.tech: send_email",
        );
        let session = replay_session(&store, AGENT);
        assert_eq!(session.steps[0].kind, StepKind::Denied(DenyReason::Human));
    }

    #[test]
    fn replay_is_scoped_to_one_agent_but_keeps_global_seq() {
        let mut store = MemoryStore::default();
        audit::append(&mut store, "@a:gaussian.tech", "auto_allowed: search");
        audit::append(&mut store, "@b:gaussian.tech", "auto_allowed: lookup");
        audit::append(
            &mut store,
            "@a:gaussian.tech",
            "executed: search ok=true tokens=5",
        );

        let a = replay_session(&store, "@a:gaussian.tech");
        assert_eq!(a.steps.len(), 2);
        // @a's second step is global entry #2 (entry #1 belonged to @b).
        assert_eq!(a.steps[0].seq, 0);
        assert_eq!(a.steps[1].seq, 2);

        let all = replay_all(&store);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].agent, "@a:gaussian.tech"); // first appearance order
        assert_eq!(all[1].agent, "@b:gaussian.tech");
    }

    #[test]
    fn replay_over_a_tampered_chain_is_flagged() {
        let mut store = log();
        let orig = audit::entries(&store)[1].clone();
        // gm-store encodes an entry as `actor␟event␟prev_hash␟hash` (unit
        // separator). Re-encode entry #1 with a forged event but its original
        // (now stale) hash, so the chain no longer verifies.
        let forged = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            orig.actor, "auto_allowed: exfiltrate", orig.prev_hash, orig.hash
        );
        store
            .put(
                gm_store::cf::AUDIT_LOG,
                "00000000000000000001",
                forged.as_bytes(),
            )
            .unwrap();

        let session = replay_session(&store, AGENT);
        assert!(!session.chain_intact);
    }
}
