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

pub mod auth;
pub mod ed25519;

use gm_api::{Json, Pdu};
use std::collections::BTreeMap;
use std::fmt;

/// An Ephemeral Data Unit — non-persistent federation traffic (typing,
/// receipts, presence, device-list updates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edu {
    /// The EDU type, e.g. `m.typing`, `m.receipt`, `m.device_list_update`.
    pub edu_type: String,
    /// Opaque EDU content as JSON.
    pub content_json: String,
}

impl Edu {
    /// Serialise to `{"edu_type":…,"content":…}`.
    pub fn to_json(&self) -> Json {
        let mut obj = BTreeMap::new();
        obj.insert("edu_type".to_owned(), Json::String(self.edu_type.clone()));
        obj.insert(
            "content".to_owned(),
            Json::parse(&self.content_json).unwrap_or_else(|_| Json::Object(BTreeMap::new())),
        );
        Json::Object(obj)
    }

    /// Parse from `{"edu_type":…,"content":…}`.
    pub fn from_json(value: &Json) -> Result<Self, FedError> {
        let edu_type = value
            .get("edu_type")
            .and_then(Json::as_str)
            .ok_or(FedError::InvalidField("edu_type"))?
            .to_owned();
        let content_json = value
            .get("content")
            .map(|c| c.to_string())
            .unwrap_or_else(|| "{}".to_owned());
        Ok(Edu {
            edu_type,
            content_json,
        })
    }
}

/// An error decoding a [`Transaction`] or [`Edu`] from JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FedError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present but malformed.
    InvalidField(&'static str),
}

impl fmt::Display for FedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FedError::MissingField(k) => write!(f, "missing federation field: {k}"),
            FedError::InvalidField(k) => write!(f, "invalid federation field: {k}"),
        }
    }
}

impl std::error::Error for FedError {}

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

    /// Serialise to the SS transaction JSON shape:
    /// `{"origin":…,"origin_server_ts":…,"pdus":[…],"edus":[…]}`.
    pub fn to_json(&self) -> Json {
        let mut obj = BTreeMap::new();
        obj.insert("origin".to_owned(), Json::String(self.origin.clone()));
        obj.insert(
            "origin_server_ts".to_owned(),
            Json::Number(self.origin_server_ts as f64),
        );
        obj.insert(
            "pdus".to_owned(),
            Json::Array(self.pdus.iter().map(Pdu::to_json).collect()),
        );
        obj.insert(
            "edus".to_owned(),
            Json::Array(self.edus.iter().map(Edu::to_json).collect()),
        );
        Json::Object(obj)
    }

    /// Parse from the SS transaction JSON shape, re-validating every PDU (the
    /// transaction arrives from another, untrusted server). A missing `edus` is
    /// treated as empty; a malformed PDU or EDU rejects the whole transaction.
    pub fn from_json(value: &Json) -> Result<Self, FedError> {
        let origin = value
            .get("origin")
            .and_then(Json::as_str)
            .ok_or(FedError::InvalidField("origin"))?
            .to_owned();
        let origin_server_ts = value
            .get("origin_server_ts")
            .and_then(Json::as_u64)
            .ok_or(FedError::InvalidField("origin_server_ts"))?;

        let mut pdus = Vec::new();
        for value in array_field(value, "pdus")? {
            pdus.push(Pdu::from_json(value).map_err(|_| FedError::InvalidField("pdus"))?);
        }
        let mut edus = Vec::new();
        if let Some(items) = value.get("edus") {
            let items = items.as_array().ok_or(FedError::InvalidField("edus"))?;
            for value in items {
                edus.push(Edu::from_json(value)?);
            }
        }
        Ok(Self {
            origin,
            origin_server_ts,
            pdus,
            edus,
        })
    }
}

fn array_field<'a>(value: &'a Json, key: &'static str) -> Result<&'a [Json], FedError> {
    value
        .get(key)
        .ok_or(FedError::MissingField(key))?
        .as_array()
        .ok_or(FedError::InvalidField(key))
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
    fn transaction_round_trips_through_json() {
        let mut txn = Transaction::new("other.tld", 1700);
        txn.pdus.push(Pdu {
            event_id: EventId::parse("$e").unwrap(),
            room_id: RoomId::parse("!r:other.tld").unwrap(),
            sender: UserId::parse("@bob:other.tld").unwrap(),
            kind: "m.room.message".to_owned(),
            state_key: None,
            origin_server_ts: 1700,
            depth: 5,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: "{\"body\":\"hi\"}".to_owned(),
        });
        txn.edus.push(Edu {
            edu_type: "m.typing".to_owned(),
            content_json: "{\"user_ids\":[]}".to_owned(),
        });

        let restored = Transaction::from_json(&txn.to_json()).unwrap();
        assert_eq!(restored, txn);
    }

    #[test]
    fn decoding_a_transaction_rejects_a_malformed_pdu() {
        let json = Json::parse(
            r#"{"origin":"other.tld","origin_server_ts":1,"pdus":[{"type":"m.room.message"}]}"#,
        )
        .unwrap();
        // The PDU is missing required fields (event_id, room_id, …).
        assert_eq!(
            Transaction::from_json(&json),
            Err(FedError::InvalidField("pdus"))
        );
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
