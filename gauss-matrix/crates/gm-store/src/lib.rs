// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-store
//!
//! The GaussMatrix pluggable storage abstraction (GaussInteract-SPECS §III.C):
//! a backend-agnostic [`Store`] trait keyed by explicit, per-domain **column
//! families**, behind which a deployment chooses its backend (a tuned RocksDB
//! for the single-node profile, a distributed KV for the sharded profile)
//! without touching the service core.
//!
//! This scaffold ships the in-memory [`MemoryStore`] backend and the durable,
//! tamper-evident [`audit`] log (§IV.D) — the column family the agentic gateway
//! writes every decision to. The RocksDB / distributed backends land behind
//! cargo features later.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod audit;
mod memory;
#[cfg(feature = "rocksdb")]
mod rocks;
mod shared;

pub use memory::MemoryStore;
#[cfg(feature = "rocksdb")]
pub use rocks::RocksStore;
pub use shared::SharedStore;

/// Explicit, per-domain column families (spec §III.C). Named rather than
/// stringly-typed at call sites so the storage domains are enumerable.
pub mod cf {
    /// Persisted room events.
    pub const EVENTS: &str = "events";
    /// Resolved room state.
    pub const ROOM_STATE: &str = "room_state";
    /// Agent capability grants (room state, §IV.C).
    pub const CAPABILITY_GRANTS: &str = "capability_grants";
    /// The hash-chained agent audit log (§IV.D).
    pub const AUDIT_LOG: &str = "audit_log";
    /// Scoped, durable agent memory/context (§IV).
    pub const AGENT_MEMORY: &str = "agent_memory";
    /// Client access tokens → the user/device they authenticate (§II.B).
    pub const ACCESS_TOKENS: &str = "access_tokens";
    /// User accounts → their password verifier (§II.B).
    pub const ACCOUNTS: &str = "accounts";
    /// Per-sender transaction ids → the event they produced, for idempotent
    /// retries of `PUT …/send/…/{txnId}` (§II, transaction identifiers).
    pub const TRANSACTIONS: &str = "transactions";
    /// Origin server name → its federation signing key (§III.E). A stand-in for
    /// the published-key fetch; production caches verified `/key/v2/server` keys.
    pub const FEDERATION_KEYS: &str = "federation_keys";
    /// Global insertion-ordered index of appended events, for incremental sync:
    /// `{seq:020}` → `{room}\u{1f}{event_id}` (§II, sync `since` tokens).
    pub const EVENT_STREAM: &str = "event_stream";
    /// This server's own federation signing keys (§III.E): `key_id` → key
    /// material, published at `GET /_matrix/key/v2/server` and used to sign
    /// outbound requests. A scaffold stand-in for an Ed25519 keypair.
    pub const SERVER_KEYS: &str = "server_keys";
}

/// A backend-agnostic, column-family keyed store.
///
/// Keys and values are opaque byte strings; ordering of [`Store::scan`] is by
/// key, so callers that need ordered iteration (the audit log) encode sortable
/// keys. The trait is deliberately small — the surface a pluggable backend must
/// implement — and writes within a single logical operation are expected to be
/// atomic in real backends (modelled trivially by the in-memory store).
pub trait Store {
    /// Insert or overwrite `key` in column family `cf`.
    fn put(&mut self, cf: &str, key: &str, value: &[u8]);

    /// Remove `key` from column family `cf` (a no-op if absent).
    fn delete(&mut self, cf: &str, key: &str);

    /// Fetch `key` from column family `cf`, if present.
    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>>;

    /// All `(key, value)` pairs in `cf`, ordered by key ascending.
    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)>;

    /// Number of entries currently in `cf`.
    fn count(&self, cf: &str) -> usize;
}
