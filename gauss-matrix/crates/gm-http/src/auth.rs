// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Client access-token extraction for the CS API (spec §II.B).
//!
//! Authenticated Client–Server endpoints carry the caller's access token. The
//! Matrix spec accepts it two ways, and prefers the first:
//!
//! 1. `Authorization: Bearer <token>` request header (preferred);
//! 2. an `access_token=<token>` query parameter (legacy, still supported).
//!
//! This module extracts the token from those two places. Validating it — mapping
//! a token to a user/device — is the session layer's job; the ingress turns a
//! *missing* token on an authenticated endpoint into `401 M_MISSING_TOKEN`.

/// Extract the client access token from the `Authorization` header (preferred)
/// or the request target's `access_token` query parameter (legacy fallback).
///
/// `authorization` is the raw header value if present (e.g. `"Bearer abc123"`);
/// `target` is the full request target, which may carry `?access_token=…`.
pub fn access_token(authorization: Option<&str>, target: &str) -> Option<String> {
    if let Some(token) = authorization.and_then(bearer) {
        return Some(token.to_owned());
    }
    query_param(target, "access_token")
}

/// The token from a `Bearer <token>` header value, if it is one. The scheme is
/// matched case-insensitively per RFC 7235; surrounding whitespace is trimmed.
fn bearer(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("Bearer") {
        let token = token.trim();
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    } else {
        None
    }
}

/// The first value of query parameter `name` in a request target, if present.
fn query_param(target: &str, name: &str) -> Option<String> {
    let query = target.split('?').nth(1)?;
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name && !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_the_authorization_header() {
        assert_eq!(
            access_token(Some("Bearer abc123"), "/_matrix/client/v3/sync"),
            Some("abc123".to_owned())
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_trimmed() {
        assert_eq!(
            access_token(Some("bearer  xyz "), "/x"),
            Some("xyz".to_owned())
        );
    }

    #[test]
    fn falls_back_to_the_query_parameter() {
        assert_eq!(
            access_token(None, "/_matrix/client/v3/sync?since=s1&access_token=tok9"),
            Some("tok9".to_owned())
        );
    }

    #[test]
    fn header_wins_over_query_parameter() {
        assert_eq!(
            access_token(Some("Bearer fromheader"), "/x?access_token=fromquery"),
            Some("fromheader".to_owned())
        );
    }

    #[test]
    fn no_token_anywhere_is_none() {
        assert_eq!(access_token(None, "/_matrix/client/v3/sync"), None);
        // A non-Bearer scheme is not an access token.
        assert_eq!(access_token(Some("Basic dXNlcg=="), "/x"), None);
        // An empty bearer token is not a token.
        assert_eq!(access_token(Some("Bearer "), "/x"), None);
    }
}
