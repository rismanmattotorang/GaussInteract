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
//! - `POST /_matrix/client/v3/login` → password login, returning an access token;
//! - `GET /_matrix/client/v3/account/whoami` → the token's user;
//! - `GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}[/{stateKey}]` → the
//!   content of a state event;
//! - `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` → send a
//!   message event, returning its event id (idempotent on the transaction id);
//! - `GET /_matrix/client/v3/rooms/{roomId}/messages` → the room timeline as a
//!   `{"chunk":[…]}` page;
//! - `POST /_matrix/client/v3/createRoom` → originate a room, returning its id;
//! - `POST /_matrix/client/v3/rooms/{roomId}/{join,leave,invite,kick,ban}` →
//!   membership changes (authorized by the join-rules / power state machine);
//! - `GET /_matrix/client/v3/sync[?since=…]` → joined rooms with state and
//!   timeline (full), or only the events since the `?since=` token (incremental);
//! - `PUT /_matrix/federation/v1/send/{txnId}` → ingest an inbound federation
//!   transaction (PDUs/EDUs), returning the per-PDU acknowledgement;
//! - `GET /_matrix/federation/v1/state/{roomId}` → the room's current state as
//!   `{"pdus":[…],"auth_chain":[…]}`.
//!
//! Authentication is gated centrally: a request to an [`Auth::AccessToken`]
//! endpoint without a token is `401 M_MISSING_TOKEN`, and a token the service
//! does not recognise is `401 M_UNKNOWN_TOKEN`; an [`Auth::Federation`] endpoint
//! must carry a valid `X-Matrix` request signature, verified against the origin
//! server's key (`401 M_UNAUTHORIZED` otherwise). All gating runs before any
//! handler. Unknown
//! targets are `404 M_UNRECOGNIZED`; a known path with the wrong method is
//! `405 M_UNRECOGNIZED` + an `Allow` header; endpoints on the
//! [surface](crate::Endpoint::surface) without a handler yet are `501`.

use crate::auth::access_token;
use crate::router::{RouteMatch, RouteResolution, Router};
use crate::{Auth, Method, SUPPORTED_SPEC_VERSIONS};
use gm_api::{Homeserver, Json, LoginGrant, MatrixError, NoServer, Pdu, SyncView};
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
        match m.endpoint.auth {
            Auth::None | Auth::Appservice => Ok(None),
            Auth::AccessToken => {
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
            Auth::Federation => {
                // Verify the `X-Matrix` request signature against the origin
                // server's key (the service reconstructs the canonical signing
                // object and checks it). A missing, malformed, or invalid
                // signature is rejected before any handler runs.
                if self.server.verify_federation_request(
                    method_name(&req.method),
                    req.target,
                    req.body,
                    req.authorization,
                ) {
                    Ok(None)
                } else {
                    Err(Response::error(
                        401,
                        &MatrixError::new("M_UNAUTHORIZED", "invalid federation signature"),
                    ))
                }
            }
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
            (Method::Put, "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}") => {
                self.serve_send(m, user, req)
            }
            (Method::Get, "/_matrix/client/v3/rooms/{roomId}/messages") => self.serve_messages(m),
            (Method::Post, "/_matrix/client/v3/rooms/{roomId}/join") => {
                self.serve_membership_self(m, user, "join")
            }
            (Method::Post, "/_matrix/client/v3/rooms/{roomId}/leave") => {
                self.serve_membership_self(m, user, "leave")
            }
            (Method::Post, "/_matrix/client/v3/rooms/{roomId}/invite") => {
                self.serve_membership_target(m, user, req, "invite")
            }
            (Method::Post, "/_matrix/client/v3/rooms/{roomId}/kick") => {
                self.serve_membership_target(m, user, req, "leave")
            }
            (Method::Post, "/_matrix/client/v3/rooms/{roomId}/ban") => {
                self.serve_membership_target(m, user, req, "ban")
            }
            (Method::Post, "/_matrix/client/v3/createRoom") => self.serve_create_room(user, req),
            (Method::Get, "/_matrix/client/v3/sync") => self.serve_sync(user, req),
            (Method::Put, "/_matrix/federation/v1/send/{txnId}") => self.serve_federation_send(req),
            (Method::Get, "/_matrix/federation/v1/state/{roomId}") => {
                self.serve_federation_state(m)
            }
            _ => Response::error(
                501,
                &MatrixError::unrecognized("endpoint not yet implemented"),
            ),
        }
    }

    /// `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`: send a
    /// message event on behalf of the authenticated user, returning its event
    /// id. The body must be a JSON object (the event content). Idempotent on the
    /// transaction id.
    fn serve_send(&self, m: &RouteMatch, user: Option<&UserId>, req: &Request<'_>) -> Response {
        // The auth gate guarantees a user for this access-token endpoint.
        let Some(sender) = user else {
            return Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            );
        };
        let (Some(room_id), Some(event_type), Some(txn_id)) =
            (m.param("roomId"), m.param("eventType"), m.param("txnId"))
        else {
            return Response::error(
                400,
                &MatrixError::new("M_INVALID_PARAM", "missing path parameter"),
            );
        };
        let Ok(room) = RoomId::parse(room_id) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        // The body must be a JSON object (the event content).
        let body = req.body.unwrap_or("");
        match Json::parse(body) {
            Ok(Json::Object(_)) => {}
            Ok(_) => {
                return Response::error(
                    400,
                    &MatrixError::new("M_BAD_JSON", "content must be an object"),
                )
            }
            Err(_) => {
                return Response::error(400, &MatrixError::new("M_NOT_JSON", "content is not JSON"))
            }
        }
        match self
            .server
            .send_message(sender, &room, event_type, txn_id, body)
        {
            Some(event_id) => Response::json_ok(event_id_body(&event_id)),
            None => Response::error(
                403,
                &MatrixError::forbidden("not permitted to send in this room"),
            ),
        }
    }

    /// `POST /_matrix/client/v3/createRoom`: create a room for the authenticated
    /// user, returning `{"room_id":…}`. Reads optional `name`/`topic` from the
    /// body; an empty body is allowed, a non-object body is `400`.
    fn serve_create_room(&self, user: Option<&UserId>, req: &Request<'_>) -> Response {
        let Some(creator) = user else {
            return Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            );
        };
        // The body is optional; when present it must be a JSON object.
        let (name, topic) = match req.body {
            None | Some("") => (None, None),
            Some(body) => match Json::parse(body) {
                Ok(obj @ Json::Object(_)) => (
                    obj.get("name").and_then(Json::as_str).map(str::to_owned),
                    obj.get("topic").and_then(Json::as_str).map(str::to_owned),
                ),
                Ok(_) => {
                    return Response::error(
                        400,
                        &MatrixError::new("M_BAD_JSON", "request body must be an object"),
                    )
                }
                Err(_) => {
                    return Response::error(
                        400,
                        &MatrixError::new("M_NOT_JSON", "body is not JSON"),
                    )
                }
            },
        };
        match self
            .server
            .create_room(creator, name.as_deref(), topic.as_deref())
        {
            Some(room) => Response::json_ok(room_id_body(room.as_str())),
            None => Response::error(403, &MatrixError::forbidden("room creation refused")),
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/{join,leave}`: change the
    /// authenticated user's own membership. Returns `{"room_id":…}` on success,
    /// `403 M_FORBIDDEN` if the transition is not permitted.
    fn serve_membership_self(
        &self,
        m: &RouteMatch,
        user: Option<&UserId>,
        membership: &str,
    ) -> Response {
        let Some(actor) = user else {
            return Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            );
        };
        let Some(room) = m.param("roomId").and_then(|r| RoomId::parse(r).ok()) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        match self
            .server
            .change_membership(actor, &room, actor, membership)
        {
            Some(_) => Response::json_ok(room_id_body(room.as_str())),
            None => Response::error(
                403,
                &MatrixError::forbidden("membership change not permitted"),
            ),
        }
    }

    /// `POST /_matrix/client/v3/rooms/{roomId}/{invite,kick,ban}`: change another
    /// user's membership (the target is `user_id` in the body). Returns `{}` on
    /// success, `403 M_FORBIDDEN` if not permitted, `400` on a bad body.
    fn serve_membership_target(
        &self,
        m: &RouteMatch,
        user: Option<&UserId>,
        req: &Request<'_>,
        membership: &str,
    ) -> Response {
        let Some(actor) = user else {
            return Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            );
        };
        let Some(room) = m.param("roomId").and_then(|r| RoomId::parse(r).ok()) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        let target = req
            .body
            .and_then(|b| Json::parse(b).ok())
            .and_then(|j| j.get("user_id").and_then(Json::as_str).map(str::to_owned))
            .and_then(|u| UserId::parse(u).ok());
        let Some(target) = target else {
            return Response::error(
                400,
                &MatrixError::new("M_BAD_JSON", "missing or invalid user_id"),
            );
        };
        match self
            .server
            .change_membership(actor, &room, &target, membership)
        {
            Some(_) => Response::json_ok("{}".to_owned()),
            None => Response::error(
                403,
                &MatrixError::forbidden("membership change not permitted"),
            ),
        }
    }

    /// `PUT /_matrix/federation/v1/send/{txnId}`: ingest an inbound federation
    /// transaction (a batch of PDUs/EDUs as JSON), returning the per-PDU
    /// acknowledgement. The X-Matrix signature header is required by the auth
    /// gate; the body must be a JSON object.
    fn serve_federation_send(&self, req: &Request<'_>) -> Response {
        let body = req.body.unwrap_or("");
        match Json::parse(body) {
            Ok(txn @ Json::Object(_)) => {
                Response::json_ok(self.server.receive_transaction(&txn).to_string())
            }
            Ok(_) => Response::error(
                400,
                &MatrixError::new("M_BAD_JSON", "transaction must be an object"),
            ),
            Err(_) => Response::error(400, &MatrixError::new("M_NOT_JSON", "body is not JSON")),
        }
    }

    /// `GET /_matrix/federation/v1/state/{roomId}`: the room's full current
    /// state as `{"pdus":[…],"auth_chain":[…]}`. The auth chain (the events
    /// authorising the state) is derived during full state-resolution, a later
    /// slice; it is empty for now.
    fn serve_federation_state(&self, m: &RouteMatch) -> Response {
        let Some(room_id) = m.param("roomId") else {
            return Response::error(
                400,
                &MatrixError::new("M_INVALID_PARAM", "missing path parameter"),
            );
        };
        let Ok(room) = RoomId::parse(room_id) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        let state = self.server.room_state(&room);
        let mut obj = BTreeMap::new();
        obj.insert(
            "pdus".to_owned(),
            Json::Array(state.iter().map(Pdu::to_json).collect()),
        );
        obj.insert("auth_chain".to_owned(), Json::Array(Vec::new()));
        Response::json_ok(Json::Object(obj).to_string())
    }

    /// `GET /_matrix/client/v3/sync`: the authenticated user's rooms with state
    /// and timeline, plus the `next_batch` token. Without `?since=` it is an
    /// initial (full) sync; with a `?since=` token it returns only the events
    /// that arrived after it.
    fn serve_sync(&self, user: Option<&UserId>, req: &Request<'_>) -> Response {
        let Some(user) = user else {
            return Response::error(
                401,
                &MatrixError::unknown_token("unrecognized access token"),
            );
        };
        let since = crate::auth::query_param(req.target, "since");
        Response::json_ok(sync_body(&self.server.sync(user, since.as_deref())))
    }

    /// `GET /_matrix/client/v3/rooms/{roomId}/messages`: return the room
    /// timeline as a `{"chunk":[…],"start":…,"end":…}` page. Pagination tokens
    /// are placeholders for now; the whole timeline is returned oldest-first.
    fn serve_messages(&self, m: &RouteMatch) -> Response {
        let Some(room_id) = m.param("roomId") else {
            return Response::error(
                400,
                &MatrixError::new("M_INVALID_PARAM", "missing path parameter"),
            );
        };
        let Ok(room) = RoomId::parse(room_id) else {
            return Response::error(400, &MatrixError::new("M_INVALID_PARAM", "invalid room id"));
        };
        Response::json_ok(messages_body(&self.server.room_timeline(&room)))
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

/// The `PUT …/send/…` success body: `{"event_id":…}`.
fn event_id_body(event_id: &str) -> String {
    let mut obj = BTreeMap::new();
    obj.insert("event_id".to_owned(), Json::String(event_id.to_owned()));
    Json::Object(obj).to_string()
}

/// The `POST /createRoom` success body: `{"room_id":…}`.
fn room_id_body(room_id: &str) -> String {
    let mut obj = BTreeMap::new();
    obj.insert("room_id".to_owned(), Json::String(room_id.to_owned()));
    Json::Object(obj).to_string()
}

/// The `GET /sync` body:
/// `{"next_batch":…,"rooms":{"join":{room:{"state":{"events":[…]},
/// "timeline":{"events":[…],"limited":false}}}}}`.
fn sync_body(view: &SyncView) -> String {
    let events_obj = |events: &[Pdu]| {
        let mut o = BTreeMap::new();
        o.insert(
            "events".to_owned(),
            Json::Array(events.iter().map(Pdu::to_json).collect()),
        );
        o
    };

    let mut join = BTreeMap::new();
    for jr in &view.joined {
        let mut timeline = events_obj(&jr.timeline);
        timeline.insert("limited".to_owned(), Json::Bool(false));
        let mut room = BTreeMap::new();
        room.insert("state".to_owned(), Json::Object(events_obj(&jr.state)));
        room.insert("timeline".to_owned(), Json::Object(timeline));
        join.insert(jr.room.as_str().to_owned(), Json::Object(room));
    }

    let mut rooms = BTreeMap::new();
    rooms.insert("join".to_owned(), Json::Object(join));
    let mut top = BTreeMap::new();
    top.insert(
        "next_batch".to_owned(),
        Json::String(view.next_batch.clone()),
    );
    top.insert("rooms".to_owned(), Json::Object(rooms));
    Json::Object(top).to_string()
}

/// The `GET …/messages` body: `{"chunk":[…events…],"start":…,"end":…}`. The
/// chunk is the room timeline (oldest-first) as event JSON; the tokens are
/// placeholders until incremental pagination lands.
fn messages_body(timeline: &[Pdu]) -> String {
    let chunk = Json::Array(timeline.iter().map(Pdu::to_json).collect());
    let mut obj = BTreeMap::new();
    obj.insert("chunk".to_owned(), chunk);
    obj.insert("start".to_owned(), Json::String("start".to_owned()));
    obj.insert("end".to_owned(), Json::String("end".to_owned()));
    Json::Object(obj).to_string()
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
    use gm_api::{
        FederationAuth, FederationReceiver, JoinedRoom, Login, MembershipChanger, MessageSender,
        RoomCreator, RoomReader, RoomTimeline, SyncProvider, TokenAuthority,
    };
    use std::collections::BTreeMap;

    /// A test homeserver: one account/token, some room state, and a timeline.
    #[derive(Default)]
    struct TestServer {
        token: String,
        user: String,
        password: String,
        /// (room, event_type, state_key) -> content JSON.
        state: BTreeMap<(String, String, String), String>,
        /// Events returned by the `/messages` endpoint.
        timeline: Vec<Pdu>,
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

        fn room_state(&self, _room: &RoomId) -> Vec<Pdu> {
            // The double's `/state` returns the timeline events it was seeded with.
            self.timeline.clone()
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
    impl MessageSender for TestServer {
        fn send_message(
            &self,
            _sender: &UserId,
            _room: &RoomId,
            _event_type: &str,
            txn_id: &str,
            _content: &str,
        ) -> Option<String> {
            // The double echoes a deterministic event id keyed by the txn.
            Some(format!("$evt_{txn_id}"))
        }
    }
    impl RoomTimeline for TestServer {
        fn room_timeline(&self, _room: &RoomId) -> Vec<Pdu> {
            self.timeline.clone()
        }
    }
    impl RoomCreator for TestServer {
        fn create_room(
            &self,
            _creator: &UserId,
            name: Option<&str>,
            _topic: Option<&str>,
        ) -> Option<RoomId> {
            // The double echoes a room id derived from the optional name.
            let local = name.unwrap_or("new");
            RoomId::parse(format!("!{local}:gaussian.tech")).ok()
        }
    }
    impl MembershipChanger for TestServer {
        fn change_membership(
            &self,
            _actor: &UserId,
            _room: &RoomId,
            _target: &UserId,
            membership: &str,
        ) -> Option<String> {
            // The double accepts any membership change, echoing an event id.
            Some(format!("$m_{membership}"))
        }
    }
    impl FederationAuth for TestServer {
        fn verify_federation_request(
            &self,
            _method: &str,
            _uri: &str,
            _content: Option<&str>,
            authorization: Option<&str>,
        ) -> bool {
            // The double trusts a well-formed X-Matrix header; real signature
            // verification is exercised against GaussServer.
            authorization.is_some_and(|h| h.trim_start().starts_with("X-Matrix"))
        }
    }
    impl FederationReceiver for TestServer {
        fn receive_transaction(&self, _txn: &Json) -> Json {
            // Echo a fixed per-PDU ack so the ingress wiring is observable.
            let mut pdus = BTreeMap::new();
            pdus.insert("$fed".to_owned(), Json::Object(BTreeMap::new()));
            let mut obj = BTreeMap::new();
            obj.insert("pdus".to_owned(), Json::Object(pdus));
            Json::Object(obj)
        }
    }
    impl SyncProvider for TestServer {
        fn sync(&self, _user: &UserId, _since: Option<&str>) -> gm_api::SyncView {
            // One joined room carrying the double's timeline (no state).
            let joined = if self.timeline.is_empty() {
                Vec::new()
            } else {
                vec![JoinedRoom {
                    room: RoomId::parse("!room:gaussian.tech").unwrap(),
                    state: Vec::new(),
                    timeline: self.timeline.clone(),
                }]
            };
            gm_api::SyncView {
                next_batch: "s1".to_owned(),
                joined,
            }
        }
    }

    fn authed() -> Ingress<TestServer> {
        Ingress::with_server(TestServer {
            token: "tok123".to_owned(),
            user: "@alice:gaussian.tech".to_owned(),
            password: "pw".to_owned(),
            state: BTreeMap::new(),
            timeline: Vec::new(),
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
        // With an authority that knows the token, the gate passes and /sync is
        // served (200) rather than rejected with a 401.
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        assert_eq!(authed().handle(&req).status, 200);
    }

    #[test]
    fn token_via_query_parameter_also_passes_the_gate() {
        let resp = authed().dispatch(Method::Get, "/_matrix/client/v3/sync?access_token=tok123");
        assert_eq!(resp.status, 200); // gate passed via the query-param token
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
            timeline: Vec::new(),
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

    const SEND_TARGET: &str =
        "/_matrix/client/v3/rooms/!room:gaussian.tech/send/m.room.message/txn7";

    #[test]
    fn send_with_object_body_returns_an_event_id() {
        let req = Request::new(Method::Put, SEND_TARGET)
            .with_authorization("Bearer tok123")
            .with_body(r#"{"msgtype":"m.text","body":"hi"}"#);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        // The double keys the event id by the txn id from the path.
        assert_eq!(
            Json::parse(&resp.body)
                .unwrap()
                .get("event_id")
                .and_then(Json::as_str),
            Some("$evt_txn7")
        );
    }

    #[test]
    fn send_without_a_token_is_401() {
        let req = Request::new(Method::Put, SEND_TARGET).with_body("{}");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn send_with_a_non_object_body_is_400() {
        let req = Request::new(Method::Put, SEND_TARGET)
            .with_authorization("Bearer tok123")
            .with_body("[1,2,3]");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_BAD_JSON"));
    }

    #[test]
    fn send_with_invalid_json_is_400_not_json() {
        let req = Request::new(Method::Put, SEND_TARGET)
            .with_authorization("Bearer tok123")
            .with_body("{not json");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_NOT_JSON"));
    }

    fn message_pdu(id: &str, body: &str) -> Pdu {
        Pdu {
            event_id: gm_util::EventId::parse(id).unwrap(),
            room_id: RoomId::parse("!room:gaussian.tech").unwrap(),
            sender: UserId::parse("@alice:gaussian.tech").unwrap(),
            kind: "m.room.message".to_owned(),
            state_key: None,
            origin_server_ts: 1,
            depth: 1,
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            content_json: format!("{{\"body\":\"{body}\"}}"),
        }
    }

    fn server_with_timeline() -> Ingress<TestServer> {
        Ingress::with_server(TestServer {
            token: "tok123".to_owned(),
            user: "@alice:gaussian.tech".to_owned(),
            password: "pw".to_owned(),
            state: BTreeMap::new(),
            timeline: vec![message_pdu("$e1", "hello"), message_pdu("$e2", "world")],
        })
    }

    #[test]
    fn messages_returns_the_timeline_as_a_chunk() {
        let req = Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/messages",
        )
        .with_authorization("Bearer tok123");
        let resp = server_with_timeline().handle(&req);
        assert_eq!(resp.status, 200);
        let parsed = Json::parse(&resp.body).unwrap();
        let chunk = parsed.get("chunk").and_then(Json::as_array).unwrap();
        assert_eq!(chunk.len(), 2);
        // Events carry their Matrix JSON shape, oldest first.
        assert_eq!(chunk[0].get("event_id").and_then(Json::as_str), Some("$e1"));
        assert_eq!(
            chunk[1]
                .get("content")
                .and_then(|c| c.get("body"))
                .and_then(Json::as_str),
            Some("world")
        );
        assert!(parsed.get("start").is_some());
        assert!(parsed.get("end").is_some());
    }

    #[test]
    fn messages_requires_authentication() {
        let resp = server_with_timeline().dispatch(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/messages",
        );
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn create_room_returns_a_room_id() {
        let req = Request::new(Method::Post, "/_matrix/client/v3/createRoom")
            .with_authorization("Bearer tok123")
            .with_body(r#"{"name":"ops"}"#);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(
            Json::parse(&resp.body)
                .unwrap()
                .get("room_id")
                .and_then(Json::as_str),
            Some("!ops:gaussian.tech")
        );
    }

    #[test]
    fn create_room_with_empty_body_is_allowed() {
        // No body at all: the optional name/topic are simply absent.
        let req = Request::new(Method::Post, "/_matrix/client/v3/createRoom")
            .with_authorization("Bearer tok123");
        assert_eq!(authed().handle(&req).status, 200);
    }

    #[test]
    fn join_returns_the_room_id_when_authorized() {
        let req = Request::new(
            Method::Post,
            "/_matrix/client/v3/rooms/!r:gaussian.tech/join",
        )
        .with_authorization("Bearer tok123");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(
            Json::parse(&resp.body)
                .unwrap()
                .get("room_id")
                .and_then(Json::as_str),
            Some("!r:gaussian.tech")
        );
    }

    #[test]
    fn join_requires_authentication() {
        let resp = authed().dispatch(
            Method::Post,
            "/_matrix/client/v3/rooms/!r:gaussian.tech/join",
        );
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn invite_reads_the_target_user_and_returns_empty_object() {
        let req = Request::new(
            Method::Post,
            "/_matrix/client/v3/rooms/!r:gaussian.tech/invite",
        )
        .with_authorization("Bearer tok123")
        .with_body(r#"{"user_id":"@bob:gaussian.tech"}"#);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{}");
    }

    #[test]
    fn invite_without_a_user_id_is_400() {
        let req = Request::new(
            Method::Post,
            "/_matrix/client/v3/rooms/!r:gaussian.tech/invite",
        )
        .with_authorization("Bearer tok123")
        .with_body("{}");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_BAD_JSON"));
    }

    #[test]
    fn create_room_requires_authentication() {
        let resp = authed().dispatch(Method::Post, "/_matrix/client/v3/createRoom");
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn create_room_with_a_non_object_body_is_400() {
        let req = Request::new(Method::Post, "/_matrix/client/v3/createRoom")
            .with_authorization("Bearer tok123")
            .with_body("\"oops\"");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_BAD_JSON"));
    }

    #[test]
    fn sync_requires_authentication() {
        let resp = authed().dispatch(Method::Get, "/_matrix/client/v3/sync");
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("\"errcode\":\"M_MISSING_TOKEN\""));
    }

    #[test]
    fn sync_returns_joined_rooms_with_a_timeline() {
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        let resp = server_with_timeline().handle(&req);
        assert_eq!(resp.status, 200);
        let body = Json::parse(&resp.body).unwrap();
        assert!(body.get("next_batch").and_then(Json::as_str).is_some());
        let room = body
            .get("rooms")
            .and_then(|r| r.get("join"))
            .and_then(|j| j.get("!room:gaussian.tech"))
            .expect("the joined room");
        let events = room
            .get("timeline")
            .and_then(|t| t.get("events"))
            .and_then(Json::as_array)
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].get("event_id").and_then(Json::as_str),
            Some("$e1")
        );
    }

    #[test]
    fn sync_with_no_joined_rooms_is_an_empty_join_map() {
        let req = Request::new(Method::Get, "/_matrix/client/v3/sync")
            .with_authorization("Bearer tok123");
        let resp = authed().handle(&req); // empty timeline -> no joined rooms
        assert_eq!(resp.status, 200);
        let join = Json::parse(&resp.body)
            .unwrap()
            .get("rooms")
            .and_then(|r| r.get("join"))
            .and_then(Json::as_object)
            .map(|o| o.len());
        assert_eq!(join, Some(0));
    }

    const FED_SEND: &str = "/_matrix/federation/v1/send/txn-1";

    #[test]
    fn federation_send_requires_an_x_matrix_signature() {
        // No Authorization header -> the federation gate rejects it.
        let req = Request::new(Method::Put, FED_SEND).with_body(r#"{"origin":"o","pdus":[]}"#);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("M_UNAUTHORIZED"));
    }

    #[test]
    fn federation_send_with_signature_ingests_and_acks() {
        let req = Request::new(Method::Put, FED_SEND)
            .with_authorization("X-Matrix origin=other.tld,key=\"ed25519:1\",sig=\"abc\"")
            .with_body(r#"{"origin":"other.tld","origin_server_ts":1,"pdus":[]}"#);
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 200);
        // The acknowledgement carries the per-PDU result object.
        assert!(Json::parse(&resp.body).unwrap().get("pdus").is_some());
    }

    #[test]
    fn federation_send_with_a_non_object_body_is_400() {
        let req = Request::new(Method::Put, FED_SEND)
            .with_authorization("X-Matrix origin=other.tld")
            .with_body("[]");
        let resp = authed().handle(&req);
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("M_BAD_JSON"));
    }

    #[test]
    fn federation_state_read_requires_a_signature() {
        let resp = server_with_timeline().dispatch(
            Method::Get,
            "/_matrix/federation/v1/state/!room:gaussian.tech",
        );
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("M_UNAUTHORIZED"));
    }

    #[test]
    fn federation_state_read_returns_pdus_and_auth_chain() {
        let req = Request::new(
            Method::Get,
            "/_matrix/federation/v1/state/!room:gaussian.tech",
        )
        .with_authorization("X-Matrix origin=other.tld");
        let resp = server_with_timeline().handle(&req);
        assert_eq!(resp.status, 200);
        let body = Json::parse(&resp.body).unwrap();
        // The double's room_state returns its timeline (two events).
        assert_eq!(
            body.get("pdus").and_then(Json::as_array).map(<[_]>::len),
            Some(2)
        );
        assert!(body.get("auth_chain").and_then(Json::as_array).is_some());
    }

    #[test]
    fn messages_for_an_empty_room_is_an_empty_chunk() {
        let req = Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/!room:gaussian.tech/messages",
        )
        .with_authorization("Bearer tok123");
        let resp = authed().handle(&req); // authed() has an empty timeline
        assert_eq!(resp.status, 200);
        let chunk = Json::parse(&resp.body)
            .unwrap()
            .get("chunk")
            .and_then(Json::as_array)
            .map(<[_]>::len);
        assert_eq!(chunk, Some(0));
    }
}
