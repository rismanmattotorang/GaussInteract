// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The synchronous ingress core (spec §III.B).
//!
//! This is the request→response heart of the homeserver, independent of the
//! async transport. The live axum/hyper layer does three mechanical things:
//! build a [`Request`] from the wire, call [`Ingress::handle`], and write the
//! returned [`Response`] back to the socket. Keeping the decision logic here,
//! std-only, means routing, authentication gating, status codes and the Matrix
//! error envelope are all testable without a running server.
//!
//! What it serves today:
//! - `GET /_matrix/client/versions` → the advertised [`SUPPORTED_SPEC_VERSIONS`];
//! - `GET /_matrix/client/v3/login` → the supported login flows.
//!
//! Authentication is gated centrally: a request to an [`Auth::AccessToken`]
//! endpoint without a token is `401 M_MISSING_TOKEN` before any handler runs.
//! Unknown targets are `404 M_UNRECOGNIZED`; a known path with the wrong method
//! is `405 M_UNRECOGNIZED` + an `Allow` header; endpoints on the
//! [surface](crate::Endpoint::surface) without a handler yet are `501`.

use crate::auth::access_token;
use crate::router::{RouteMatch, RouteResolution, Router};
use crate::{Auth, Method, SUPPORTED_SPEC_VERSIONS};
use gm_api::MatrixError;

/// An inbound request, transport-independent.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The HTTP method.
    pub method: Method,
    /// The full request target (path plus any `?query`).
    pub target: &'a str,
    /// The raw `Authorization` header value, if present.
    pub authorization: Option<&'a str>,
}

impl<'a> Request<'a> {
    /// A request with no `Authorization` header.
    pub fn new(method: Method, target: &'a str) -> Self {
        Self {
            method,
            target,
            authorization: None,
        }
    }

    /// Set the `Authorization` header value (builder-style).
    pub fn with_authorization(mut self, value: &'a str) -> Self {
        self.authorization = Some(value);
        self
    }
}

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

    /// A Matrix error response at `status`, carrying the standard envelope.
    fn error(status: u16, err: &MatrixError) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: err.to_json(),
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

    /// Handle a [`Request`], producing a [`Response`].
    pub fn handle(&self, req: &Request<'_>) -> Response {
        match self.router.resolve(req.method, req.target) {
            RouteResolution::Found(m) => {
                // Gate access-token endpoints: a missing token is 401 before any
                // handler runs. (Validating the token is the session layer's job.)
                if m.endpoint.auth == Auth::AccessToken
                    && access_token(req.authorization, req.target).is_none()
                {
                    return Response::error(
                        401,
                        &MatrixError::missing_token("missing access token"),
                    );
                }
                self.serve(&m)
            }
            RouteResolution::MethodNotAllowed(allowed) => {
                let mut resp = Response::error(
                    405,
                    &MatrixError::unrecognized("method not allowed for this endpoint"),
                );
                resp.headers
                    .push(("Allow".to_owned(), allow_header(&allowed)));
                resp
            }
            RouteResolution::NotFound => {
                Response::error(404, &MatrixError::unrecognized("unrecognized request"))
            }
        }
    }

    /// Convenience: handle an unauthenticated `method` + `target`.
    pub fn dispatch(&self, method: Method, target: &str) -> Response {
        self.handle(&Request::new(method, target))
    }

    /// Produce the response for a matched route. Only endpoints wired to a
    /// handler return a body; the rest return `501` so the contract is explicit.
    fn serve(&self, m: &RouteMatch) -> Response {
        match (m.endpoint.method, m.endpoint.path) {
            (Method::Get, "/_matrix/client/versions") => Response::json_ok(versions_body()),
            (Method::Get, "/_matrix/client/v3/login") => Response::json_ok(login_flows_body()),
            _ => Response::error(
                501,
                &MatrixError::unrecognized("endpoint not yet implemented"),
            ),
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

/// The login flows GaussMatrix offers (spec §V.E enterprise surface: password +
/// SSO/OIDC): `{"flows":[{"type":"m.login.password"},{"type":"m.login.sso"}]}`.
fn login_flows_body() -> String {
    let flows = LOGIN_FLOWS
        .iter()
        .map(|t| format!("{{\"type\":\"{}\"}}", json_escape(t)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"flows\":[{flows}]}}")
}

/// The login flow types advertised at `GET /_matrix/client/v3/login`.
const LOGIN_FLOWS: &[&str] = &["m.login.password", "m.login.sso"];

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
/// static version/flow strings need).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
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
        assert!(resp.body.contains("\"v1.11\""));
        assert!(resp.body.starts_with("{\"versions\":["));
    }

    #[test]
    fn serves_the_login_flows_endpoint() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/v3/login");
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"m.login.password\""));
        assert!(resp.body.contains("\"m.login.sso\""));
        assert!(resp.body.starts_with("{\"flows\":["));
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
        // /versions exists only for GET.
        let resp = ingress.dispatch(Method::Post, "/_matrix/client/versions");
        assert_eq!(resp.status, 405);
        assert_eq!(resp.header("Allow"), Some("GET"));
        assert!(resp.body.contains("M_UNRECOGNIZED"));
    }

    #[test]
    fn authenticated_endpoint_without_a_token_is_401_missing_token() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/v3/sync");
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn authenticated_endpoint_with_a_token_passes_the_gate() {
        let ingress = Ingress::new();
        // With a token, the auth gate passes; /sync is on the surface but not yet
        // wired to a handler, so it reaches the 501 contract rather than 401.
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        let resp = ingress.handle(&req);
        assert_eq!(resp.status, 501);
    }

    #[test]
    fn token_via_query_parameter_also_passes_the_gate() {
        let ingress = Ingress::new();
        let resp = ingress.dispatch(Method::Get, "/_matrix/client/v3/sync?access_token=tok123");
        assert_eq!(resp.status, 501); // gate passed, handler not yet wired
    }

    #[test]
    fn public_login_post_needs_no_token() {
        let ingress = Ingress::new();
        // POST /login is public; without a token it reaches the 501 contract
        // (handler not yet wired), not a 401.
        let resp = ingress.dispatch(Method::Post, "/_matrix/client/v3/login");
        assert_eq!(resp.status, 501);
    }
}
