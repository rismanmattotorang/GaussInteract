// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-fed
//!
//! The federation (Server–Server) model of GaussMatrix (GaussInteract-SPECS
//! §III.E). Federation moves [`Transaction`]s between servers: a batch of
//! [`Pdu`]s (room events) and [`Edu`]s (ephemeral data units — typing, receipts,
//! presence, device-list updates).
//!
//! This crate pins those envelopes and the **partial-state join** tracking that
//! lets a user become interactive in a large room before its full state has
//! been fetched and verified (bounding join latency, §III.E). The authenticated
//! SS transport, backfill, and the per-destination sharded sender drive these
//! types; signature verification uses `gm-e2ee`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

use gm_api::Pdu;

/// An Ephemeral Data Unit — non-persistent federation traffic (typing,
/// receipts, presence, device-list updates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edu {
    /// The EDU type, e.g. `m.typing`, `m.receipt`, `m.device_list_update`.
    pub edu_type: String,
    /// Opaque EDU content as JSON.
    pub content_json: String,
}

/// A Server–Server transaction: the unit of federation transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The origin server name.
    pub origin: String,
    /// When the origin created the transaction (ms since the Unix epoch).
    pub origin_server_ts: u64,
    /// Persistent room events (≤ 50 per the SS spec; not enforced here).
    pub pdus: Vec<Pdu>,
    /// Ephemeral data units (≤ 100 per the SS spec; not enforced here).
    pub edus: Vec<Edu>,
}

impl Transaction {
    /// A transaction from `origin` at `origin_server_ts` with no events yet.
    pub fn new(origin: impl Into<String>, origin_server_ts: u64) -> Self {
        Self {
            origin: origin.into(),
            origin_server_ts,
            pdus: Vec::new(),
            edus: Vec::new(),
        }
    }

    /// Whether the transaction carries nothing.
    pub fn is_empty(&self) -> bool {
        self.pdus.is_empty() && self.edus.is_empty()
    }
}

/// The state-completeness of a joined room. A **partial-state** join is
/// interactive immediately; the server backfills and verifies the remaining
/// state in the background, then promotes the room to full state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinState {
    /// Full room state has been fetched and verified.
    Full,
    /// Joined with partial state; `outstanding` state events remain to verify.
    Partial {
        /// Number of state events still to fetch/verify.
        outstanding: usize,
    },
}

impl JoinState {
    /// Whether the room is usable for sending/reading now (true for both full
    /// and partial — that is the point of partial-state joins).
    pub fn is_interactive(&self) -> bool {
        true
    }

    /// Account for `fetched` newly verified state events, promoting to [`Self::Full`]
    /// once nothing remains outstanding.
    pub fn advance(self, fetched: usize) -> Self {
        match self {
            JoinState::Full => JoinState::Full,
            JoinState::Partial { outstanding } => {
                let remaining = outstanding.saturating_sub(fetched);
                if remaining == 0 {
                    JoinState::Full
                } else {
                    JoinState::Partial {
                        outstanding: remaining,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_util::{EventId, RoomId, UserId};

    #[test]
    fn transaction_collects_pdus_and_edus() {
        let mut txn = Transaction::new("gaussian.tech", 1700);
        assert!(txn.is_empty());
        txn.pdus.push(Pdu {
            event_id: EventId::parse("$e").unwrap(),
            room_id: RoomId::parse("!r:gaussian.tech").unwrap(),
            sender: UserId::parse("@a:gaussian.tech").unwrap(),
            kind: "m.room.message".to_owned(),
            state_key: None,
            origin_server_ts: 1700,
            depth: 5,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{}".to_owned(),
        });
        txn.edus.push(Edu {
            edu_type: "m.typing".to_owned(),
            content_json: "{}".to_owned(),
        });
        assert!(!txn.is_empty());
        assert_eq!(txn.pdus.len(), 1);
        assert_eq!(txn.edus.len(), 1);
    }

    #[test]
    fn partial_state_join_is_interactive_and_promotes_to_full() {
        let join = JoinState::Partial { outstanding: 10 };
        assert!(join.is_interactive());
        let join = join.advance(4);
        assert_eq!(join, JoinState::Partial { outstanding: 6 });
        let join = join.advance(100); // more than remaining
        assert_eq!(join, JoinState::Full);
        assert!(join.is_interactive());
    }
}
