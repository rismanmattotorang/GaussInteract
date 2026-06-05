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
mod file;
mod memory;
#[cfg(feature = "rocksdb")]
mod rocks;
mod shared;

pub use file::FileStore;
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
    /// Ephemeral typing state: `{room}\u{1f}{user}` → expiry timestamp (ms since
    /// epoch). An entry whose expiry has passed is treated as not typing (§II,
    /// the `m.typing` ephemeral EDU).
    pub const TYPING: &str = "typing";
    /// Read receipts: `{room}\u{1f}{user}` → `{event_id}\u{1f}{ts}`, the last
    /// event a user has read and when (§II, the `m.read` part of `m.receipt`).
    pub const RECEIPTS: &str = "receipts";
    /// User presence: `{user}` → `{presence}\u{1f}{status_msg}`, the user's
    /// status and optional message (§II, the `m.presence` ephemeral EDU).
    pub const PRESENCE: &str = "presence";
    /// Cache of fetched federation verify keys (§III.E): `{origin}\u{1f}{key_id}`
    /// → `{public}\u{1f}{valid_until_ts}`. Populated by ingesting a verified
    /// `/_matrix/key/v2/server` document; an entry past `valid_until_ts` is
    /// stale and must be re-fetched before it is trusted.
    pub const KEY_CACHE: &str = "key_cache";
    /// Published E2EE device keys (§VI.B): `{user}\u{1f}{device_id}` → the
    /// opaque `device_keys` JSON, relayed verbatim (never decrypted).
    pub const DEVICE_KEYS: &str = "device_keys";
    /// Stored one-time keys per device (§VI.B):
    /// `{user}\u{1f}{device_id}\u{1f}{key_id}` → the opaque key JSON, where
    /// `key_id` is `algorithm:id`. `keys/claim` removes one; remaining counts
    /// per algorithm are derived by scanning this family.
    pub const DEVICE_OTK: &str = "device_otk";
    /// Cross-signing keys per user (§VI.B): `{user}\u{1f}{usage}` → the opaque
    /// key JSON, where `usage` is `master` / `self_signing` / `user_signing`.
    pub const CROSS_SIGNING: &str = "cross_signing";
}

/// A backend-agnostic, column-family keyed store.
///
/// Keys and values are opaque byte strings; ordering of [`Store::scan`] is by
/// key, so callers that need ordered iteration (the audit log) encode sortable
/// keys. The trait is deliberately small — the surface a pluggable backend must
/// implement — and writes within a single logical operation are expected to be
/// atomic in real backends (modelled trivially by the in-memory store).
pub trait Store {
    /// Insert or overwrite `key` in column family `cf`. Returns a [`StoreError`]
    /// if a durable backend failed to persist the write (the in-memory backends
    /// never fail).
    fn put(&mut self, cf: &str, key: &str, value: &[u8]) -> Result<(), StoreError>;

    /// Remove `key` from column family `cf` (a no-op if absent). Returns a
    /// [`StoreError`] if a durable backend failed to apply the deletion.
    fn delete(&mut self, cf: &str, key: &str) -> Result<(), StoreError>;

    /// Fetch `key` from column family `cf`, if present. Reads are served from the
    /// resident dataset and are infallible.
    fn get(&self, cf: &str, key: &str) -> Option<Vec<u8>>;

    /// All `(key, value)` pairs in `cf`, ordered by key ascending.
    fn scan(&self, cf: &str) -> Vec<(String, Vec<u8>)>;

    /// Number of entries currently in `cf`.
    fn count(&self, cf: &str) -> usize;

    /// A **page** of `cf`: up to `limit` `(key, value)` pairs whose key is
    /// strictly greater than `after` (or from the start when `after` is `None`),
    /// ordered by key. This is the cursor primitive for streaming a large column
    /// family without materialising it — pass the last key of one page as the
    /// `after` of the next (see [`stream`]).
    ///
    /// The default implementation pages over [`Store::scan`]; backends with
    /// ordered iteration (all of ours) override it to seek directly.
    fn scan_paged(&self, cf: &str, after: Option<&str>, limit: usize) -> Vec<(String, Vec<u8>)> {
        self.scan(cf)
            .into_iter()
            .filter(|(k, _)| after.map_or(true, |a| k.as_str() > a))
            .take(limit)
            .collect()
    }
}

/// Stream every entry of `cf` in key order, fetching `page_size` at a time via
/// [`Store::scan_paged`] so the whole column family is never held in memory at
/// once. `page_size` is clamped to at least 1.
pub fn stream<'a, S: Store + ?Sized>(
    store: &'a S,
    cf: &'a str,
    page_size: usize,
) -> impl Iterator<Item = (String, Vec<u8>)> + 'a {
    let page_size = page_size.max(1);
    let mut buffer: std::collections::VecDeque<(String, Vec<u8>)> =
        std::collections::VecDeque::new();
    let mut cursor: Option<String> = None;
    let mut done = false;
    std::iter::from_fn(move || {
        if buffer.is_empty() && !done {
            let page = store.scan_paged(cf, cursor.as_deref(), page_size);
            if page.len() < page_size {
                done = true; // a short page is the last one
            }
            if let Some((last_key, _)) = page.last() {
                cursor = Some(last_key.clone());
            } else {
                done = true;
            }
            buffer.extend(page);
        }
        buffer.pop_front()
    })
}

/// A failure to apply a write to a durable [`Store`] backend (e.g. an I/O error
/// from the filesystem or embedded KV). Reads are infallible, so this only
/// arises from [`Store::put`] / [`Store::delete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store write failed: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError(e.to_string())
    }
}
