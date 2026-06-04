// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-util
//!
//! Shared primitives for the GaussMatrix workspace (GaussInteract-SPECS
//! §III.B): validated Matrix [`UserId`], [`RoomId`] and [`AgentId`] newtypes,
//! the common [`GmError`], and the dependency-free [`ed25519`] signature
//! primitive (RFC 8032). Keeping these in one crate gives every server crate the
//! same typed boundary and crypto instead of passing raw strings around.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod ed25519;
pub mod error;
pub mod ids;

pub use error::GmError;
pub use ids::{AgentId, EventId, RoomId, UserId};
