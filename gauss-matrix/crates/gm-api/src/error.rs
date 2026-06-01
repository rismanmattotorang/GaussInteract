// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The Matrix Client–Server API standard error model.
//!
//! Every CS error response is `{"errcode": "M_...", "error": "..."}`. This type
//! carries that pair and renders it; the HTTP status mapping lives in `gm-http`.

use std::fmt;

/// A Matrix standard error (`errcode` + human-readable `error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixError {
    /// The machine-readable error code, e.g. `M_FORBIDDEN`.
    pub errcode: String,
    /// The human-readable error message.
    pub error: String,
}

impl MatrixError {
    /// Construct an error from a code and message.
    pub fn new(errcode: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            errcode: errcode.into(),
            error: error.into(),
        }
    }

    /// `M_FORBIDDEN` — the request was refused.
    pub fn forbidden(error: impl Into<String>) -> Self {
        Self::new("M_FORBIDDEN", error)
    }

    /// `M_NOT_FOUND` — the resource was not found.
    pub fn not_found(error: impl Into<String>) -> Self {
        Self::new("M_NOT_FOUND", error)
    }

    /// `M_UNKNOWN_TOKEN` — the access token was not recognised.
    pub fn unknown_token(error: impl Into<String>) -> Self {
        Self::new("M_UNKNOWN_TOKEN", error)
    }

    /// `M_MISSING_TOKEN` — no access token was supplied for an authenticated
    /// endpoint.
    pub fn missing_token(error: impl Into<String>) -> Self {
        Self::new("M_MISSING_TOKEN", error)
    }

    /// `M_LIMIT_EXCEEDED` — the client is being rate-limited.
    pub fn limit_exceeded(error: impl Into<String>) -> Self {
        Self::new("M_LIMIT_EXCEEDED", error)
    }

    /// `M_UNRECOGNIZED` — the endpoint is not implemented/known.
    pub fn unrecognized(error: impl Into<String>) -> Self {
        Self::new("M_UNRECOGNIZED", error)
    }

    /// Render as the JSON object a CS error response carries.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"errcode\":{},\"error\":{}}}",
            json_string(&self.errcode),
            json_string(&self.error),
        )
    }
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.errcode, self.error)
    }
}

impl std::error::Error for MatrixError {}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_the_right_codes() {
        assert_eq!(MatrixError::forbidden("no").errcode, "M_FORBIDDEN");
        assert_eq!(MatrixError::not_found("no").errcode, "M_NOT_FOUND");
        assert_eq!(MatrixError::unknown_token("no").errcode, "M_UNKNOWN_TOKEN");
        assert_eq!(MatrixError::missing_token("no").errcode, "M_MISSING_TOKEN");
    }

    #[test]
    fn renders_cs_error_json_with_escaping() {
        let err = MatrixError::forbidden("bad \"token\"");
        assert_eq!(
            err.to_json(),
            "{\"errcode\":\"M_FORBIDDEN\",\"error\":\"bad \\\"token\\\"\"}"
        );
    }
}
