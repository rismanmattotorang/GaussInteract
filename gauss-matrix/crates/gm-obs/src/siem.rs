// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Structured emission of the audit log for SIEM ingestion (spec §VIII.A).
//!
//! The durable, hash-chained audit log in `gm-store` is the compliance backbone
//! of the platform. This module turns its entries into structured
//! [`AuditRecord`]s (including the chain hashes, so a SIEM can independently
//! detect gaps or tampering) and streams them to a pluggable [`SiemSink`] —
//! an in-memory [`VecSink`] for tests, or a [`WriterSink`] over any writer
//! (stdout, a file, a syslog/forwarder socket) emitting newline-delimited JSON.

use gm_store::{audit, Store};
use std::io::Write;

/// A structured audit record, one per durable audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Position in the chain (0-based), oldest first.
    pub seq: u64,
    /// The principal the entry concerns (the agent identity).
    pub actor: String,
    /// The recorded gateway decision/event.
    pub action: String,
    /// Hash committing to the previous entry (0 for the genesis entry).
    pub prev_hash: u64,
    /// Hash of this entry.
    pub hash: u64,
}

impl AuditRecord {
    /// Render the record as a single JSON object (one SIEM event).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"seq\":{},\"actor\":{},\"action\":{},\"prev_hash\":{},\"hash\":{}}}",
            self.seq,
            json_string(&self.actor),
            json_string(&self.action),
            self.prev_hash,
            self.hash,
        )
    }
}

/// Encode a string as a JSON string literal (quoted and escaped).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A destination for structured audit records (a SIEM, forwarder, or file).
pub trait SiemSink {
    /// Emit one record.
    fn emit(&mut self, record: &AuditRecord);
}

/// An in-memory sink that collects records, for tests and inspection.
#[derive(Debug, Default)]
pub struct VecSink {
    /// The emitted records, in order.
    pub records: Vec<AuditRecord>,
}

impl SiemSink for VecSink {
    fn emit(&mut self, record: &AuditRecord) {
        self.records.push(record.clone());
    }
}

/// A sink that writes newline-delimited JSON to any writer.
#[derive(Debug)]
pub struct WriterSink<W: Write> {
    writer: W,
}

impl<W: Write> WriterSink<W> {
    /// Wrap a writer (stdout, a file, a socket, …).
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Recover the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> SiemSink for WriterSink<W> {
    fn emit(&mut self, record: &AuditRecord) {
        // Best-effort: a SIEM forwarder must not crash the homeserver. A real
        // sink would buffer/retry; here we drop on a write error.
        let _ = writeln!(self.writer, "{}", record.to_json());
    }
}

/// Stream the durable audit log from `store` to `sink` as structured records,
/// returning the number of records emitted.
pub fn stream_audit<S: Store, K: SiemSink>(store: &S, sink: &mut K) -> usize {
    let entries = audit::entries(store);
    for (seq, entry) in entries.iter().enumerate() {
        sink.emit(&AuditRecord {
            seq: seq as u64,
            actor: entry.actor.clone(),
            action: entry.event.clone(),
            prev_hash: entry.prev_hash,
            hash: entry.hash,
        });
    }
    entries.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_store::MemoryStore;

    #[test]
    fn streams_audit_entries_as_structured_records() {
        let mut store = MemoryStore::default();
        audit::append(
            &mut store,
            "@gauss_agent_x:gaussian.tech",
            "auto_allowed: search",
        );
        audit::append(
            &mut store,
            "@gauss_agent_x:gaussian.tech",
            "executed: search ok=true",
        );

        let mut sink = VecSink::default();
        let n = stream_audit(&store, &mut sink);
        assert_eq!(n, 2);
        assert_eq!(sink.records.len(), 2);
        assert_eq!(sink.records[0].seq, 0);
        assert_eq!(sink.records[0].action, "auto_allowed: search");
        // The chain links are carried through to the SIEM for independent checks.
        assert_eq!(sink.records[1].prev_hash, sink.records[0].hash);
    }

    #[test]
    fn writer_sink_emits_one_json_line_per_record() {
        let mut store = MemoryStore::default();
        audit::append(
            &mut store,
            "@a:gaussian.tech",
            "denied_by_scope: rm_rf in !r:gaussian.tech",
        );

        let mut sink = WriterSink::new(Vec::<u8>::new());
        stream_audit(&store, &mut sink);
        let out = String::from_utf8(sink.into_inner()).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("\"actor\":\"@a:gaussian.tech\""));
        assert!(out.contains("\"action\":\"denied_by_scope: rm_rf in !r:gaussian.tech\""));
    }

    #[test]
    fn json_escapes_quotes_and_controls() {
        let record = AuditRecord {
            seq: 0,
            actor: "@a:gaussian.tech".into(),
            action: "weird \"quote\"\nnewline".into(),
            prev_hash: 0,
            hash: 7,
        };
        let json = record.to_json();
        assert!(json.contains("\\\"quote\\\""));
        assert!(json.contains("\\n"));
    }
}
