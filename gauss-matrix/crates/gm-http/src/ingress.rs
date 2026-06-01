// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The synchronous ingress core (spec §III.B).
//!
//! This is the request→response heart of the homeserver, independent of the
//! async transport. The live axum/hyper layer does three mechanical things:
//! parse the wire request into a [`Method`] + target, call [`Ingress::dispatch`],
//! and write the returned [`Response`] back to the socket. Keeping the decision
//! logic here, std-only, means the routing, status codes and Matrix error
//! envelopes are all testable without a running server.
//!
//! What it serves today: `GET /_matrix/client/versions` returns the advertised
//! [`SUPPORTED_SPEC_VERSIONS`]; an unknown target returns `404 M_UNRECOGNIZED`
//! and a known path with the wrong method returns `405 M_UNRECOGNIZED` with an
//! `Allow` header — both the standard Matrix error shape. Endpoints that are on
//! the [surface](crate::Endpoint::surface) but not yet wired to a handler return
//! `501` with `M_UNRECOGNIZED`, so the contract for the async layer is explicit.

use crate::router::{RouteResolution, Router};
use crate::{Method, SUPPORTED_SPEC_VERSIONS};

/// A response the ingress produces, ready for the transport to write out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (e.g. `Content-Type`, `Allow`).
    pub headers: Vec<(String, String)>,
    /// Response body (JSON).
    pub body: String,
}

impl Response {
    /// A `200 OK` JSON response.
    fn json_ok(body: String) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body,
        }
    }

    /// A Matrix error response (`{"errcode":…,"error":…}`) at `status`.
    fn matrix_error(status: u16, errcode: &str, error: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: format!(
                "{{\"errcode\":\"{}\",\"error\":\"{}\"}}",
                json_escape(errcode),
                json_escape(error)
            ),
        }
    }

    /// A header value by (case-insensitive) name, if set.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The homeserver ingress: resolves a request to a [`Response`].
#[derive(Debug, Clone, Default)]
pub struct Ingress {
    router: Router,
}

impl Ingress {
    /// An ingress over the full homeserver surface.
    pub fn new() -> Self {
        Self {
            router: Router::new(),
        }
    }

    /// Dispatch a request `method` + `target` to a [`Response`].
    pub fn dispatch(&self, method: Method, target: &str) -> Response {
        match self.router.resolve(method, target) {
            RouteResolution::Found(m) => self.serve(&m),
            RouteResolution::MethodNotAllowed(allowed) => {
                let mut resp = Response::matrix_error(
                    405,
                    "M_UNRECOGNIZED",
                    "method not allowed for this endpoint",
                );
                resp.headers
                    .push(("Allow".to_owned(), allow_header(&allowed)));
                resp
            }
            RouteResolution::NotFound => {
                Response::matrix_error(404, "M_UNRECOGNIZED", "unrecognized request")
            }
        }
    }

    /// Produce the response for a matched route. Only the endpoints wired to a
    /// handler return a body; the rest return `501` so the contract is explicit.
    fn serve(&self, m: &crate::router::RouteMatch) -> Response {
        match m.endpoint.path {
            "/_matrix/client/versions" => Response::json_ok(versions_body()),
            _ => Response::matrix_error(501, "M_UNRECOGNIZED", "endpoint not yet implemented"),
        }
    }
}

/// The body of `GET /_matrix/client/versions`: `{"versions":[…]}`, built from the
/// advertised [`SUPPORTED_SPEC_VERSIONS`].
fn versions_body() -> String {
    let list = SUPPORTED_SPEC_VERSIONS
        .iter()
        .map(|v| format!("\"{}\"", json_escape(v)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"versions\":[{list}]}}")
}

/// The `Allow` header value for a set of methods (e.g. `GET, POST`).
fn allow_header(methods: &[Method]) -> String {
    methods
        .iter()
        .map(method_name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn method_name(method: &Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

/// Escape a string for inclusion in a JSON string literal (the small subset our
/// static error/version strings need: quotes, backslashes, control chars).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_versions_endpoint() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/versions");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("Content-Type"), Some("application/json"));
        // Advertises at least v1.11 (spec §II.A).
        assert!(resp.body.contains("\"v1.11\""));
        assert!(resp.body.starts_with("{\"versions\":["));
    }

    #[test]
    fn unknown_target_is_404_m_unrecognized() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/v3/nope");
        assert_eq!(resp.status, 404);
        assert!(resp.body.contains("\"errcode\":\"M_UNRECOGNIZED\""));
    }

    #[test]
    fn wrong_method_is_405_with_allow_header() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Post, "/_matrix/client/versions");
        assert_eq!(resp.status, 405);
        assert_eq!(resp.header("Allow"), Some("GET"));
        assert!(resp.body.contains("M_UNRECOGNIZED"));
    }

    #[test]
    fn declared_but_unimplemented_endpoint_is_501() {
        let ingress = Ingress::new();
        // /sync is on the surface but not yet wired to a handler.
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/v3/sync");
        assert_eq!(resp.status, 501);
        assert!(resp.body.contains("not yet implemented"));
    }

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("x\ny"), "x\\ny");
    }
}
