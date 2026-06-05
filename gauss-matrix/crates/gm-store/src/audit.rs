// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Durable, tamper-evident audit log (spec §IV.D).
//!
//! Every gateway decision is appended to the [`crate::cf::AUDIT_LOG`] column
//! family, each entry committing to the hash of its predecessor so any
//! retroactive edit is detectable by [`verify`]. Because it lives in the store,
//! the log survives restarts and is the compliance backbone of the platform.
//!
//! ## Notes on the placeholder encoding & hash
//!
//! Entries are serialised with a unit-separator-delimited encoding and chained
//! with the standard-library hasher, purely so this scaffold stays
//! dependency-free and testable. The production store uses a structured
//! serialisation (CBOR/serde) and a cryptographic hash (SHA-256 / BLAKE3); the
//! key ordering, chaining structure and [`verify`] contract are unchanged.

use crate::{cf, Store};
use std::hash::{Hash, Hasher};

const SEP: char = '\u{1f}'; // ASCII unit separator, absent from our fields.

/// One entry in the hash-chained audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The principal the entry concerns (the agent identity).
    pub actor: String,
    /// A description of the recorded gateway decision/event.
    pub event: String,
    /// Hash committing to the previous entry (0 for the genesis entry).
    pub prev_hash: u64,
    /// Hash of this entry, over its content and `prev_hash`.
    pub hash: u64,
}

/// Append an event to the durable audit log, chaining it to the current tip.
pub fn append<S: Store>(store: &mut S, actor: &str, event: &str) {
    let seq = store.count(cf::AUDIT_LOG);
    let prev_hash = entries(store).last().map(|e| e.hash).unwrap_or(0);
    let hash = digest(actor, event, prev_hash);
    let entry = AuditEntry {
        actor: actor.to_owned(),
        event: event.to_owned(),
        prev_hash,
        hash,
    };
    // Zero-padded sequence key keeps Store::scan in append order. Audit logging
    // is best-effort here (the call returns no error); a deployment that must
    // not lose audit entries would propagate a write failure.
    let _ = store.put(cf::AUDIT_LOG, &seq_key(seq), encode(&entry).as_bytes());
}

/// Load all audit entries, oldest first.
pub fn entries<S: Store>(store: &S) -> Vec<AuditEntry> {
    store
        .scan(cf::AUDIT_LOG)
        .into_iter()
        .filter_map(|(_, v)| String::from_utf8(v).ok().and_then(|s| decode(&s)))
        .collect()
}

/// Verify the durable chain. `Ok(())` if intact, otherwise the 0-based index of
/// the first corrupted entry.
pub fn verify<S: Store>(store: &S) -> Result<(), usize> {
    let mut expected_prev = 0u64;
    for (i, e) in entries(store).iter().enumerate() {
        if e.prev_hash != expected_prev {
            return Err(i);
        }
        if e.hash != digest(&e.actor, &e.event, e.prev_hash) {
            return Err(i);
        }
        expected_prev = e.hash;
    }
    Ok(())
}

fn seq_key(seq: usize) -> String {
    format!("{seq:020}")
}

fn encode(e: &AuditEntry) -> String {
    format!(
        "{}{SEP}{}{SEP}{}{SEP}{}",
        e.actor, e.event, e.prev_hash, e.hash
    )
}

fn decode(s: &str) -> Option<AuditEntry> {
    let mut parts = s.split(SEP);
    let actor = parts.next()?.to_owned();
    let event = parts.next()?.to_owned();
    let prev_hash = parts.next()?.parse().ok()?;
    let hash = parts.next()?.parse().ok()?;
    Some(AuditEntry {
        actor,
        event,
        prev_hash,
        hash,
    })
}

fn digest(actor: &str, event: &str, prev_hash: u64) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    actor.hash(&mut h);
    0xFFu8.hash(&mut h); // domain separator between fields
    event.hash(&mut h);
    prev_hash.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;

    #[test]
    fn appends_persist_and_verify() {
        let mut store = MemoryStore::default();
        append(&mut store, "@a:gaussian.tech", "capability_check");
        append(&mut store, "@a:gaussian.tech", "tool_call: search");
        append(&mut store, "@a:gaussian.tech", "tool_result: ok");

        let loaded = entries(&store);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].prev_hash, 0);
        assert_eq!(loaded[1].prev_hash, loaded[0].hash);
        assert_eq!(verify(&store), Ok(()));
    }

    #[test]
    fn tampering_with_a_persisted_entry_is_detected() {
        let mut store = MemoryStore::default();
        append(&mut store, "@a:gaussian.tech", "tool_call: search");
        append(&mut store, "@a:gaussian.tech", "tool_result: ok");

        // Forge entry #1 in the store, leaving the chain hash stale.
        let forged = AuditEntry {
            actor: "@a:gaussian.tech".into(),
            event: "tool_call: exfiltrate".into(),
            prev_hash: entries(&store)[1].prev_hash,
            hash: entries(&store)[1].hash,
        };
        store
            .put(
                cf::AUDIT_LOG,
                "00000000000000000001",
                encode(&forged).as_bytes(),
            )
            .unwrap();
        assert_eq!(verify(&store), Err(1));
    }
}
