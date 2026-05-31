// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the core. The real implementation will use `thiserror` and
//! map `matrix_sdk` / `vodozemac` errors into these variants.

use std::fmt;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, GaussError>;

/// Errors surfaced across the FFI boundary to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GaussError {
    /// An operation required an authenticated session but none was present.
    NotAuthenticated,
    /// The homeserver or login parameters were rejected.
    Authentication(String),
    /// A networking / federation transport failure.
    Network(String),
    /// A local persistence failure.
    Store(String),
    /// An end-to-end-encryption failure (key missing, verification failed, …).
    Crypto(String),
    /// An agent action was denied by capability scope or human approval (§IV).
    AgentDenied(String),
    /// The tamper-evident audit log failed verification (§IV.D).
    AuditIntegrity(String),
    /// A feature that is specified but not yet implemented in this phase.
    Unimplemented(&'static str),
}

impl fmt::Display for GaussError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GaussError::NotAuthenticated => write!(f, "no active session"),
            GaussError::Authentication(m) => write!(f, "authentication failed: {m}"),
            GaussError::Network(m) => write!(f, "network error: {m}"),
            GaussError::Store(m) => write!(f, "store error: {m}"),
            GaussError::Crypto(m) => write!(f, "crypto error: {m}"),
            GaussError::AgentDenied(m) => write!(f, "agent action denied: {m}"),
            GaussError::AuditIntegrity(m) => write!(f, "audit integrity error: {m}"),
            GaussError::Unimplemented(what) => write!(f, "not yet implemented: {what}"),
        }
    }
}

impl std::error::Error for GaussError {}
