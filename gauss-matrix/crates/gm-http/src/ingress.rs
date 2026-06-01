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
//! What it serves today (all driven by the [`Homeserver`] service it is generic
//! over — the default [`NoServer`] provides nothing, so only the public,
//! state-free endpoints answer):
//! - `GET /_matrix/client/versions` → the advertised [`SUPPORTED_SPEC_VERSIONS`];
//! - `GET /_matrix/client/v3/login` → the supported login flows;
//! - `GET /_matrix/client/v3/account/whoami` → the token's user;
//! - `GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` → the
//!   content of a state event.
//!
//! Authentication is gated centrally: a request to an [`Auth::AccessToken`]
//! endpoint without a token is `401 M_MISSING_TOKEN`, and a token the service
//! does not recognise is `401 M_UNKNOWN_TOKEN`, before any handler runs. Unknown
//! targets are `404 M_UNRECOGNIZED`; a known path with the wrong method is
//! `405 M_UNRECOGNIZED` + an `Allow` header; endpoints on the
//! [surface](crate::Endpoint::surface) without a handler yet are `501`.

use crate::auth::access_token;
use crate::router::{RouteMatch, RouteResolution, Router};
use crate::{Auth, Method, SUPPORTED_SPEC_VERSIONS};
use gm_api::{Homeserver, Json, LoginGrant, MatrixError, NoServer};
use gm_util::{RoomId, UserId};
use std::collections::BTreeMap;

/// An inbound request, transport-independent.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The HTTP method.
    pub method: Method,
    /// The full request target (path plus any `?query`).
    pub target: &'a str,
    /// The raw `Authorization` header value, if present.
    pub authorization: Option<&'a str>,
    /// The request body (JSON), if any.
    pub body: Option<&'a str>,
}

impl<'a> Request<'a> {
    /// A request with no `Authorization` header and no body.
    pub fn new(method: Method, target: &'a str) -> Self {
        Self {
            method,
            target,
            authorization: None,
            body: None,
        }
    }

    /// Set the `Authorization` header value (builder-style).
    pub fn with_authorization(mut self, value: &'a str) -> Self {
        self.authorization = Some(value);
        self
    }

    /// Set the request body (builder-style).
    pub fn with_body(mut self, body: &'a str) -> Self {
        self.body = Some(body);
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

/// The homeserver ingress: resolves a request to a [`Response`], generic over
/// the [`Homeserver`] service that validates tokens and reads room state. With
/// the default [`NoServer`] no token is accepted and no room is found; the
/// assembled server plugs its composed services in via [`Ingress::with_server`].
#[derive(Debug, Clone, Default)]
pub struct Ingress<H: Homeserver = NoServer> {
    router: Router,
    server: H,
}

impl Ingress<NoServer> {
    /// An ingress over the full homeserver surface with no service core wired in
    /// (authenticated endpoints reject every token; room reads find nothing).
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            server: NoServer,
        }
    }
}

impl<H: Homeserver> Ingress<H> {
    /// An ingress backed by a homeserver service (the composed service core).
    pub fn with_server(server: H) -> Self {
        Self {
            router: Router::new(),
            server,
        }
    }

    /// Handle a [`Request`], producing a [`Response`].
    pub fn handle(&self, req: &Request<'_>) -> Response {
        match self.router.resolve(req.method, req.target) {
            RouteResolution::Found(m) => {
                let user = match self.authenticate(&m, req) {
                    Ok(user) => user,
                    Err(resp) => return resp,
                };
                self.serve(&m, user.as_ref(), req)
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

    /// Authenticate a matched route. For an [`Auth::AccessToken`] endpoint a
    /// missing token is `401 M_MISSING_TOKEN` and a token the service does not
    /// recognise is `401 M_UNKNOWN_TOKEN`; on success the authenticated user is
    /// returned. Other auth schemes are not gated here yet (federation signature
    /// verification is a later slice).
    fn authenticate(&self, m: &RouteMatch, req: &Request<'_>) -> Result<Option<UserId>, Response> {
        if m.endpoint.auth != Auth::AccessToken {
            return Ok(None);
        }
        let Some(token) = access_token(req.authorization, req.target) else {
            return Err(Response::error(
                401,
                &MatrixError::missing_token("missing access token"),
            ));
        };
        match self.server.user_for(&token) {
            Some(user) => Ok(Some(user)),
            None => Err(Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            )),
        }
    }

    /// Convenience: handle an unauthenticated `method` + `target`.
    pub fn dispatch(&self, method: Method, target: &str) -> Response {
        self.handle(&Request::new(method, target))
    }

    /// Produce the response for a matched route. `user` is the authenticated
    /// user for access-token endpoints. Only endpoints wired to a handler return
    /// a body; the rest return `501` so the contract is explicit.
    fn serve(&self, m: &RouteMatch, user: Option<&UserId>, req: &Request<'_>) -> Response {
        match (m.endpoint.method, m.endpoint.path) {
            (Method::Get, "/_matrix/client/versions") => Response::json_ok(versions_body()),
            (Method::Get, "/_matrix/client/v3/login") => Response::json_ok(login_flows_body()),
            (Method::Post, "/_matrix/client/v3/login") => self.serve_login(req),
            (Method::Get, "/_matrix/client/v3/account/whoami") => {
                // The auth gate guarantees a user for this access-token endpoint.
                match user {
                    Some(user) => Response::json_ok(whoami_body(user)),
                    None => Response::error(
                        401,
                        &MatrixError::unknown_token("unrecognized access token"),
                    ),
                }
            }
            (Method::Get, "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}")
            | (Method::Get, "/_matrix/client/v3/rooms/{roomId}/state/{eventType}") => {
                self.serve_state_event(m)
            }
            _ => Response::error(
                501,
                &MatrixError::unrecognized("endpoint not yet implemented"),
            ),
        }
    }

    /// `GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}[/{stateKey}]`:
    /// return the content of the state event filling that slot, or `404
    /// M_NOT_FOUND` if it is empty. The state key defaults to `""` when the path
    /// omits it (Matrix's shorter form); a malformed room id is `400`.
    fn serve_state_event(&self, m: &RouteMatch) -> Response {
        let (Some(room_id), Some(event_type)) = (m.param("roomId"), m.param("eventType")) else {
            return Response::error(
                400,
                &MatrixError::new("M_INVALID_PARAM", "missing path parameter"),
            );
        };
        let state_key = m.param("stateKey").unwrap_or("");
        let Ok(room) = RoomId::parse(room_id) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        match self.server.room_state_content(&room, event_type, state_key) {
            // The stored content is already a JSON object; return it verbatim.
            Some(content) => Response::json_ok(content),
            None => Response::error(404, &MatrixError::not_found("state event not found")),
        }
    }

    /// `POST /_matrix/client/v3/login`: authenticate `m.login.password` and, on
    /// success, return the user id and a fresh access token. Bad JSON is `400
    /// M_NOT_JSON`, a missing/Unsupported flow is `400`, and wrong credentials
    /// are `403 M_FORBIDDEN`.
    fn serve_login(&self, req: &Request<'_>) -> Response {
        let Some(body) = req.body else {
            return Response::error(400, &MatrixError::new("M_NOT_JSON", "missing request body"));
        };
        let Ok(parsed) = Json::parse(body) else {
            return Response::error(
                400,
                &MatrixError::new("M_NOT_JSON", "request body is not JSON"),
            );
        };
        if parsed.get("type").and_then(Json::as_str) != Some("m.login.password") {
            return Response::error(
                400,
                &MatrixError::new("M_UNKNOWN", "unsupported login type"),
            );
        }
        // The user is in `identifier.user` (current) or top-level `user` (legacy).
        let user = parsed
            .get("identifier")
            .and_then(|i| i.get("user"))
            .or_else(|| parsed.get("user"))
            .and_then(Json::as_str);
        let password = parsed.get("password").and_then(Json::as_str);
        let (Some(user), Some(password)) = (user, password) else {
            return Response::error(
                400,
                &MatrixError::new("M_BAD_JSON", "missing user or password"),
            );
        };
        match self.server.password_login(user, password) {
            Some(grant) => Response::json_ok(login_response(&grant)),
            None => Response::error(403, &MatrixError::forbidden("invalid username or password")),
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

/// The body of `GET /_matrix/client/v3/account/whoami`: `{"user_id":…}` for the
/// user the access token authenticates.
fn whoami_body(user: &UserId) -> String {
    format!("{{\"user_id\":\"{}\"}}", json_escape(user.as_str()))
}

/// The `POST /_matrix/client/v3/login` success body: `{"user_id":…,
/// "access_token":…}`.
fn login_response(grant: &LoginGrant) -> String {
    let mut obj = BTreeMap::new();
    obj.insert(
        "user_id".to_owned(),
        Json::String(grant.user_id.as_str().to_owned()),
    );
    obj.insert(
        "access_token".to_owned(),
        Json::String(grant.access_token.clone()),
    );
    Json::Object(obj).to_string()
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
    use gm_api::{Login, RoomReader, TokenAuthority};
    use std::collections::BTreeMap;

    /// A test homeserver: one account/token, and some room state.
    #[derive(Default)]
    struct TestServer {
        token: String,
        user: String,
        password: String,
        /// (room, event_type, state_key) -> content JSON.
        state: BTreeMap<(String, String, String), String>,
    }
    impl TokenAuthority for TestServer {
        fn user_for(&self, token: &str) -> Option<UserId> {
            if token == self.token {
                UserId::parse(self.user.clone()).ok()
            } else {
                None
            }
        }
    }
    impl RoomReader for TestServer {
        fn room_state_content(
            &self,
            room: &RoomId,
            event_type: &str,
            state_key: &str,
        ) -> Option<String> {
            self.state
                .get(&(
                    room.as_str().to_owned(),
                    event_type.to_owned(),
                    state_key.to_owned(),
                ))
                .cloned()
        }
    }
    impl Login for TestServer {
        fn password_login(&self, localpart: &str, password: &str) -> Option<LoginGrant> {
            let expected = self.user.trim_start_matches('@').split(':').next()?;
            if !self.password.is_empty() && localpart == expected && password == self.password {
                Some(LoginGrant {
                    user_id: UserId::parse(self.user.clone()).ok()?,
                    access_token: self.token.clone(),
                })
            } else {
                None
            }
        }
    }

    fn authed() -> Ingress<TestServer> {
        Ingress::with_server(TestServer {
            token: "tok123".to_owned(),
            user: "@alice:gaussian.tech".to_owned(),
            password: "pw".to_owned(),
            state: BTreeMap::new(),
        })
    }

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
    fn no_authority_rejects_a_present_token_as_unknown() {
        // The default ingress has no session layer: a token is unrecognised.
        let ingress = Ingress::new();
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        let resp = ingress.handle(&req);
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_UNKNOWN_TOKEN\""));
    }

    #[test]
    fn a_recognised_token_passes_the_gate() {
        // With an authority that knows the token, the gate passes; /sync is on
        // the surface but not yet wired, so it reaches the 501 contract.
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        assert_eq!(authed().handle(&req).status, 501);
    }

    #[test]
    fn token_via_query_parameter_also_passes_the_gate() {
        let resp = authed().dispatch(Method::Get, "/_matrix/client/v3/sync?access_token=tok123");
        assert_eq!(resp.status, 501); // gate passed, handler not yet wired
    }

    #[test]
    fn whoami_returns_the_token_owner() {
        let req = Request::new(Method::Get, "/_matrix/client/v3/account/whoami")
            .with_authorization("Bearer tok123");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"user_id\":\"@alice:gaussian.tech\"}");
    }

    #[test]
    fn whoami_with_an_unknown_token_is_401_unknown_token() {
        let req = Request::new(Method::Get, "/_matrix/client/v3/account/whoami")
            .with_authorization("Bearer wrong");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_UNKNOWN_TOKEN\""));
    }

    #[test]
    fn whoami_without_a_token_is_401_missing_token() {
        let resp = authed().dispatch(Method::Get, "/_matrix/client/v3/account/whoami");
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn public_login_post_needs_no_token() {
        // POST /login is public: with NoServer it reaches the handler (which
        // rejects the credentials, 403), rather than being gated with a 401.
        let body = r#"{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"pw"}"#;
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body);
        let resp = Ingress::new().handle(&req);
        assert_eq!(resp.status, 403);
    }

    fn login_body(user: &str, password: &str) -> String {
        format!(
            r#"{{"type":"m.login.password","identifier":{{"type":"m.id.user","user":"{user}"}},"password":"{password}"}}"#
        )
    }

    #[test]
    fn login_with_correct_password_returns_user_id_and_token() {
        let body = login_body("alice", "pw");
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body(&body);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        let parsed = Json::parse(&resp.body).unwrap();
        assert_eq!(
            parsed.get("user_id").and_then(Json::as_str),
            Some("@alice:gaussian.tech")
        );
        assert_eq!(
            parsed.get("access_token").and_then(Json::as_str),
            Some("tok123")
        );
    }

    #[test]
    fn login_with_wrong_password_is_403() {
        let body = login_body("alice", "nope");
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body(&body);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 403);
        assert!(resp.body.contains("\"errcode\":\"M_FORBIDDEN\""));
    }

    #[test]
    fn login_with_legacy_top_level_user_field_works() {
        let body = r#"{"type":"m.login.password","user":"alice","password":"pw"}"#;
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body);
        assert_eq!(authed().handle(&req).status, 200);
    }

    #[test]
    fn login_with_unsupported_type_is_400() {
        let body = r#"{"type":"m.login.token","token":"x"}"#;
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_UNKNOWN"));
    }

    #[test]
    fn login_with_malformed_json_is_400_not_json() {
        let req = Request::new(Method::Post, "/_matrix/client/v3/login").with_body("{not json");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_NOT_JSON"));
    }

    #[test]
    fn login_obtained_token_then_authenticates_whoami() {
        // End to end: log in, then use the returned token on an authed endpoint.
        let ingress = authed();
        let body = login_body("alice", "pw");
        let login = ingress
            .handle(&Request::new(Method::Post, "/_matrix/client/v3/login").with_body(&body));
        let token = Json::parse(&login.body)
            .unwrap()
            .get("access_token")
            .and_then(Json::as_str)
            .unwrap()
            .to_owned();
        let auth = format!("Bearer {token}");
        let whoami = ingress.handle(
            &Request::new(Method::Get, "/_matrix/client/v3/account/whoami")
                .with_authorization(&auth),
        );
        assert_eq!(whoami.status, 200);
        assert!(whoami.body.contains("@alice:gaussian.tech"));
    }

    fn server_with_room_name() -> Ingress<TestServer> {
        let mut state = BTreeMap::new();
        state.insert(
            (
                "!room:gaussian.tech".to_owned(),
                "m.room.name".to_owned(),
                String::new(),
            ),
            "{\"name\":\"Ops\"}".to_owned(),
        );
        Ingress::with_server(TestServer {
            token: "tok123".to_owned(),
            user: "@alice:gaussian.tech".to_owned(),
            password: "pw".to_owned(),
            state,
        })
    }

    #[test]
    fn state_event_read_returns_the_content() {
        let req = Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/state/m.room.name",
        )
        .with_authorization("Bearer tok123");
        let resp = server_with_room_name().handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"name\":\"Ops\"}");
    }

    #[test]
    fn state_event_read_with_a_url_encoded_room_id_resolves() {
        // A client percent-encodes the room id; the router decodes it.
        let req = Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/%21room%3Agaussian.tech/state/m.room.name",
        )
        .with_authorization("Bearer tok123");
        assert_eq!(server_with_room_name().handle(&req).status, 200);
    }

    #[test]
    fn missing_state_event_is_404_not_found() {
        // A valid room but an empty slot.
        let req = Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/state/m.room.topic",
        )
        .with_authorization("Bearer tok123");
        let resp = server_with_room_name().handle(&req);
        assert_eq!(resp.status, 404);
        assert!(resp.body.contains("\"errcode\":\"M_NOT_FOUND\""));
    }

    #[test]
    fn state_event_read_requires_authentication() {
        // No token -> 401 before any room lookup.
        let resp = server_with_room_name().dispatch(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/state/m.room.name",
        );
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }
}
