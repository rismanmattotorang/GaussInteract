// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client-side agent surface (spec §IV, §V.F).
//!
//! GaussInteract is the *human end* of the platform agentic loop. It renders
//! agent membership and in-band tool calls/results, surfaces human-in-the-loop
//! approval prompts, and exposes a **read-only** view of the hash-chained,
//! tamper-evident audit log so a supervisor can inspect exactly what an agent
//! saw and did (§IV.D).
//!
//! The guiding invariant (§IV): admitting an agent to a room must never enlarge
//! that room's trust boundary beyond the humans who admitted it. The server's
//! `gm-agent` MCP gateway is the authority; this module models the client view
//! and verification of that authority's record.
//!
//! ## A note on the hash
//!
//! The audit chain here uses the standard-library hasher purely so the scaffold
//! is dependency-free and the *chaining logic* is testable. The production core
//! replaces it with a cryptographic hash (SHA-256 / BLAKE3) — the chaining
//! structure and [`AuditLog::verify`] contract are unchanged. This is the one
//! place where the placeholder must not be mistaken for real tamper-evidence.

use std::hash::{Hash, Hasher};

/// How an agent action is classified (§IV.C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Executed immediately.
    Auto,
    /// Executed only after explicit human approval.
    Review,
    /// Never permitted.
    Forbidden,
}

/// A human decision on a [`ApprovalRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// The human approved the action.
    Approve,
    /// The human denied the action.
    Deny,
}

/// A pending request for human approval of a `Review`-class action (§IV.C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Monotonic identifier, linked to a [`crate::timeline::TimelineKind::ApprovalPrompt`].
    pub id: u64,
    /// The agent (a Matrix identity) requesting the action.
    pub agent: String,
    /// The tool the agent wishes to invoke.
    pub tool: String,
    /// The proposed action, shown to the human in full.
    pub proposed_action: String,
}

/// One entry in the tamper-evident audit log (§IV.D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The agent the entry concerns.
    pub agent: String,
    /// A description of the gateway decision/event being recorded.
    pub event: String,
    /// Hash committing to the *previous* entry (0 for the genesis entry).
    pub prev_hash: u64,
    /// Hash of this entry (over its content and `prev_hash`).
    pub hash: u64,
}

/// An append-only, hash-chained audit log. Each entry commits to the hash of
/// its predecessor, so any retroactive edit is detectable by [`Self::verify`].
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event, chaining it to the current tip.
    pub fn append(&mut self, agent: impl Into<String>, event: impl Into<String>) {
        let agent = agent.into();
        let event = event.into();
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or(0);
        let hash = Self::digest(&agent, &event, prev_hash);
        self.entries.push(AuditEntry {
            agent,
            event,
            prev_hash,
            hash,
        });
    }

    /// All entries, oldest first (read-only view for the supervisor UI).
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Verify the integrity of the whole chain. Returns `Ok(())` if every entry
    /// links correctly to its predecessor and its own hash is consistent;
    /// otherwise the 0-based index of the first corrupted entry.
    pub fn verify(&self) -> Result<(), usize> {
        let mut expected_prev = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            if e.prev_hash != expected_prev {
                return Err(i);
            }
            if e.hash != Self::digest(&e.agent, &e.event, e.prev_hash) {
                return Err(i);
            }
            expected_prev = e.hash;
        }
        Ok(())
    }

    /// Content digest. **Placeholder** std hasher — see module docs.
    fn digest(agent: &str, event: &str, prev_hash: u64) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        agent.hash(&mut h);
        0xFFu8.hash(&mut h); // domain separator between fields
        event.hash(&mut h);
        prev_hash.hash(&mut h);
        h.finish()
    }
}

/// The client agent surface held by [`crate::GaussCore`].
#[derive(Debug, Default)]
pub struct AgentSurface {
    next_id: u64,
    pending: Vec<ApprovalRequest>,
    audit: AuditLog,
}

impl AgentSurface {
    /// Create an empty surface.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `Review`-class action awaiting human approval, recording the
    /// request in the audit log and returning the created request id.
    pub fn request_approval(
        &mut self,
        agent: impl Into<String>,
        tool: impl Into<String>,
        proposed_action: impl Into<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let agent = agent.into();
        let tool = tool.into();
        let proposed_action = proposed_action.into();
        self.audit
            .append(&agent, format!("approval_requested: {tool}"));
        self.pending.push(ApprovalRequest {
            id,
            agent,
            tool,
            proposed_action,
        });
        id
    }

    /// Pending approval prompts the UI should render (§V.F).
    pub fn pending(&self) -> &[ApprovalRequest] {
        &self.pending
    }

    /// Resolve a pending approval. Records the human decision in the audit log
    /// and removes it from the pending set. Returns `true` if found.
    pub fn resolve(&mut self, id: u64, decision: ApprovalDecision) -> bool {
        if let Some(pos) = self.pending.iter().position(|r| r.id == id) {
            let req = self.pending.remove(pos);
            let verb = match decision {
                ApprovalDecision::Approve => "approved",
                ApprovalDecision::Deny => "denied",
            };
            self.audit
                .append(&req.agent, format!("{verb}: {}", req.tool));
            true
        } else {
            false
        }
    }

    /// Read-only access to the audit log for the supervisor view.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_flow_is_audited() {
        let mut surface = AgentSurface::new();
        let id = surface.request_approval(
            "@assistant:example.org",
            "send_external_email",
            "Email the Q3 summary to finance@corp",
        );
        assert_eq!(surface.pending().len(), 1);

        assert!(surface.resolve(id, ApprovalDecision::Approve));
        assert!(surface.pending().is_empty());

        // request + decision both recorded, and the chain is intact.
        assert_eq!(surface.audit().entries().len(), 2);
        assert_eq!(surface.audit().verify(), Ok(()));
    }

    #[test]
    fn tampering_is_detected() {
        let mut log = AuditLog::new();
        log.append("@a:example.org", "read_room");
        log.append("@a:example.org", "tool_call: search");
        log.append("@a:example.org", "tool_result: ok");
        assert_eq!(log.verify(), Ok(()));

        // Forge the content of the middle entry without recomputing the chain.
        log.entries[1].event = "tool_call: exfiltrate".into();
        assert_eq!(log.verify(), Err(1));
    }

    #[test]
    fn resolving_unknown_request_is_noop() {
        let mut surface = AgentSurface::new();
        assert!(!surface.resolve(999, ApprovalDecision::Deny));
    }
}
