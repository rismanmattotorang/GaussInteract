// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-api
//!
//! The typed protocol model for GaussMatrix (GaussInteract-SPECS §III.B): the
//! shapes the service core, state-resolution engine and federation reason about
//! — supported room versions, the Matrix Client–Server error model, the core
//! event types, and the **PDU envelope** (the event metadata that auth chains,
//! depth and state resolution operate on).
//!
//! The production crate extends [`ruma`](https://github.com/ruma/ruma) for the
//! full wire types and serde serialisation; this scaffold pins the structural
//! contracts std-only so the rest of the workspace can build against stable
//! types now. Event *content* is carried opaquely (`content_json`) because the
//! homeserver treats most content as an opaque blob until the typed layer lands.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod auth;
pub mod error;
pub mod events;
pub mod json;
pub mod pdu;
pub mod room_version;
pub mod server;

pub use auth::{NoAuthority, TokenAuthority};
pub use error::MatrixError;
pub use json::Json;
pub use pdu::Pdu;
pub use room_version::RoomVersion;
pub use server::{Homeserver, Login, LoginGrant, MessageSender, NoServer, RoomReader};
