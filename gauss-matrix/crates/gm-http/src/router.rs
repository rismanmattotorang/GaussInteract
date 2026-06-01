// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Request routing for the homeserver ingress (spec §III.B).
//!
//! [`Endpoint::surface`](crate::Endpoint::surface) declares *what* the server
//! serves; this module resolves a concrete incoming request — a [`Method`] and a
//! request-target path — to the endpoint that handles it, extracting the
//! path-template parameters (`{roomId}`, `{txnId}`, …) on the way.
//!
//! It is the synchronous routing core the live axum/hyper ingress sits on top
//! of: the async runtime parses the wire request, calls [`Router::resolve`], and
//! dispatches the [`RouteMatch`] (with its decoded parameters) to a handler. By
//! living here, std-only, the routing table and its semantics are testable
//! without a running server.
//!
//! HTTP semantics are honoured: a target that matches no endpoint resolves to
//! [`RouteResolution::NotFound`] (`404`), while one whose *path* matches but
//! whose *method* does not resolves to [`RouteResolution::MethodNotAllowed`]
//! (`405`) carrying the methods that path does allow.

use crate::{Endpoint, Method};
use std::collections::BTreeMap;

/// A resolved route: the matched endpoint and the path parameters extracted from
/// the concrete request target, keyed by template name (e.g. `roomId`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    /// The endpoint that handles the request.
    pub endpoint: Endpoint,
    /// Path-template parameters, percent-decoded, keyed by name.
    pub params: BTreeMap<String, String>,
}

impl RouteMatch {
    /// A path parameter by template name, if present.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
}

/// The outcome of resolving a request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteResolution {
    /// An endpoint handles this method and path.
    Found(RouteMatch),
    /// The path matches one or more endpoints, but none for this method (`405`).
    /// Carries the allowed methods, for the `Allow` response header.
    MethodNotAllowed(Vec<Method>),
    /// No endpoint matches the path (`404`).
    NotFound,
}

/// Routes a request target against a fixed endpoint table.
#[derive(Debug, Clone)]
pub struct Router {
    endpoints: Vec<Endpoint>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    /// A router over the full homeserver surface ([`Endpoint::surface`]).
    pub fn new() -> Self {
        Self {
            endpoints: Endpoint::surface().to_vec(),
        }
    }

    /// A router over a specific set of endpoints (for tests / sub-surfaces).
    pub fn from_endpoints(endpoints: &[Endpoint]) -> Self {
        Self {
            endpoints: endpoints.to_vec(),
        }
    }

    /// Resolve `method` + `target` (which may include a `?query`) to a route.
    ///
    /// Matching is exact on the number of `/`-segments; a template segment
    /// `{name}` captures one segment (percent-decoded), every other segment must
    /// equal the target literally.
    pub fn resolve(&self, method: Method, target: &str) -> RouteResolution {
        let path = target.split(['?', '#']).next().unwrap_or(target);
        let segments: Vec<&str> = split_path(path);

        let mut allowed: Vec<Method> = Vec::new();
        for endpoint in &self.endpoints {
            if let Some(params) = match_template(endpoint.path, &segments) {
                if endpoint.method == method {
                    return RouteResolution::Found(RouteMatch {
                        endpoint: *endpoint,
                        params,
                    });
                }
                if !allowed.contains(&endpoint.method) {
                    allowed.push(endpoint.method);
                }
            }
        }

        if allowed.is_empty() {
            RouteResolution::NotFound
        } else {
            RouteResolution::MethodNotAllowed(allowed)
        }
    }
}

/// Split a path into its non-empty segments, so a leading slash and any trailing
/// slash do not produce empty segments (`/a/b/` -> `["a", "b"]`).
fn split_path(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Match a path template against concrete segments, returning the captured
/// parameters if it matches.
fn match_template(template: &str, segments: &[&str]) -> Option<BTreeMap<String, String>> {
    let template_segments = split_path(template);
    if template_segments.len() != segments.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (tmpl, value) in template_segments.iter().zip(segments.iter()) {
        if let Some(name) = tmpl.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            params.insert(name.to_owned(), percent_decode(value));
        } else if tmpl != value {
            return None;
        }
    }
    Some(params)
}

/// Percent-decode a single path segment (`%21room` -> `!room`). Invalid escapes
/// are passed through verbatim, and `+` is left as-is (it is a literal in path
/// components, unlike query strings).
fn percent_decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // The decoded bytes are valid UTF-8 for well-formed targets; fall back to the
    // original segment rather than lose data on a malformed escape sequence.
    String::from_utf8(out).unwrap_or_else(|_| segment.to_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Api;

    #[test]
    fn resolves_a_static_endpoint() {
        let router = Router::new();
        match router.resolve(Method::Get, "/_matrix/client/versions") {
            RouteResolution::Found(m) => {
                assert_eq!(m.endpoint.api, Api::ClientServer);
                assert!(m.params.is_empty());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn extracts_path_template_parameters() {
        let router = Router::new();
        let target = "/_matrix/client/v3/rooms/!room:gaussian.tech/send/m.room.message/txn42";
        match router.resolve(Method::Put, target) {
            RouteResolution::Found(m) => {
                assert_eq!(m.param("roomId"), Some("!room:gaussian.tech"));
                assert_eq!(m.param("eventType"), Some("m.room.message"));
                assert_eq!(m.param("txnId"), Some("txn42"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn percent_encoded_room_id_is_decoded() {
        let router = Router::new();
        // A client percent-encodes the room id's sigil and colon.
        let target = "/_matrix/client/v3/rooms/%21room%3Agaussian.tech/send/m.room.message/t1";
        match router.resolve(Method::Put, target) {
            RouteResolution::Found(m) => {
                assert_eq!(m.param("roomId"), Some("!room:gaussian.tech"));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn query_string_is_ignored_for_matching() {
        let router = Router::new();
        match router.resolve(
            Method::Get,
            "/_matrix/client/v3/sync?since=s123&timeout=30000",
        ) {
            RouteResolution::Found(m) => {
                assert_eq!(m.endpoint.path, "/_matrix/client/v3/sync");
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn matching_path_wrong_method_is_method_not_allowed() {
        let router = Router::new();
        // /versions exists for GET, not POST.
        match router.resolve(Method::Post, "/_matrix/client/versions") {
            RouteResolution::MethodNotAllowed(allowed) => {
                assert_eq!(allowed, vec![Method::Get]);
            }
            other => panic!("expected MethodNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_path_is_not_found() {
        let router = Router::new();
        assert_eq!(
            router.resolve(Method::Get, "/_matrix/client/v3/nonexistent"),
            RouteResolution::NotFound
        );
    }

    #[test]
    fn trailing_slash_does_not_break_matching() {
        let router = Router::new();
        assert!(matches!(
            router.resolve(Method::Get, "/_matrix/client/versions/"),
            RouteResolution::Found(_)
        ));
    }

    #[test]
    fn a_literal_prefix_must_match_exactly() {
        let router = Router::new();
        // Right shape, wrong literal segment ("rooms" vs "spaces").
        let target = "/_matrix/client/v3/spaces/!r:x/send/m.room.message/t1";
        assert_eq!(
            router.resolve(Method::Put, target),
            RouteResolution::NotFound
        );
    }
}
