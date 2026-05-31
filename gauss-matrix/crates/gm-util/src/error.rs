// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The shared error type for the GaussMatrix workspace.

use std::fmt;

/// Errors common to the GaussMatrix crates. Per-crate errors wrap or convert
/// into this as the workspace grows (the production type uses `thiserror`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GmError {
    /// A string was not a valid Matrix user identifier (`@localpart:server`).
    InvalidUserId(String),
    /// A string was not a valid Matrix room identifier (`!opaque:server`).
    InvalidRoomId(String),
}

impl fmt::Display for GmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GmError::InvalidUserId(s) => write!(f, "invalid user id: {s:?}"),
            GmError::InvalidRoomId(s) => write!(f, "invalid room id: {s:?}"),
        }
    }
}

impl std::error::Error for GmError {}
