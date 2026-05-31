// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The authoritative tamper-evident audit log (spec §IV.D).
//!
//! Every gateway decision — resource access, capability check, approval,
//! execution and result — is appended to a hash-chained log, each entry
//! committing to the hash of its predecessor so any retroactive edit is
//! detectable. This is the *authoritative* log on the server; the GaussInteract
//! client exposes a read-only mirror.
//!
//! ## A note on the hash
//!
//! The chain uses the standard-library hasher purely so this scaffold is
//! dependency-free and the chaining logic is testable. The production gateway
//! replaces it with a cryptographic hash (SHA-256 / BLAKE3) and persists each
//! entry in its own storage column family; the chaining structure and
//! [`AuditLog::verify`] contract are unchanged.

use std::hash::{Hash, Hasher};

/// One entry in the hash-chained audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The principal the entry concerns (the agent identity).
    pub actor: String,
    /// A description of the gateway decision/event being recorded.
    pub event: String,
    /// Hash committing to the previous entry (0 for the genesis entry).
    pub prev_hash: u64,
    /// Hash of this entry, over its content and `prev_hash`.
    pub hash: u64,
}

/// An append-only, hash-chained audit log.
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
    pub fn append(&mut self, actor: impl Into<String>, event: impl Into<String>) {
        let actor = actor.into();
        let event = event.into();
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or(0);
        let hash = Self::digest(&actor, &event, prev_hash);
        self.entries.push(AuditEntry {
            actor,
            event,
            prev_hash,
            hash,
        });
    }

    /// All entries, oldest first.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Verify the whole chain. `Ok(())` if intact, otherwise the 0-based index
    /// of the first corrupted entry.
    pub fn verify(&self) -> Result<(), usize> {
        let mut expected_prev = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            if e.prev_hash != expected_prev {
                return Err(i);
            }
            if e.hash != Self::digest(&e.actor, &e.event, e.prev_hash) {
                return Err(i);
            }
            expected_prev = e.hash;
        }
        Ok(())
    }

    /// Content digest. **Placeholder** std hasher — see module docs.
    fn digest(actor: &str, event: &str, prev_hash: u64) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        actor.hash(&mut h);
        0xFFu8.hash(&mut h); // domain separator between fields
        event.hash(&mut h);
        prev_hash.hash(&mut h);
        h.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tampering() {
        let mut log = AuditLog::new();
        log.append("@a:gaussian.tech", "capability_check");
        log.append("@a:gaussian.tech", "tool_call: search");
        log.append("@a:gaussian.tech", "tool_result: ok");
        assert_eq!(log.verify(), Ok(()));

        log.entries[1].event = "tool_call: exfiltrate".into();
        assert_eq!(log.verify(), Err(1));
    }
}
