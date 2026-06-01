// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! End-to-end: the ingress driving the real composed [`GaussServer`] over one
//! shared store. This is the assembled homeserver answering a client's flow —
//! log in, confirm identity, read room state — exactly as the async transport
//! will once it fronts [`Ingress::handle`].

use gm_api::{events, Json, Pdu};
use gm_http::ingress::{Ingress, Request};
use gm_http::Method;
use gm_store::SharedStore;
use gm_svc::GaussServer;
use gm_util::{EventId, RoomId, UserId};

fn name_event(content: &str) -> Pdu {
    Pdu {
        event_id: EventId::parse("$name").unwrap(),
        room_id: RoomId::parse("!ops:gaussian.tech").unwrap(),
        sender: UserId::parse("@alice:gaussian.tech").unwrap(),
        kind: events::ROOM_NAME.to_owned(),
        state_key: Some(String::new()),
        origin_server_ts: 1,
        depth: 1,
        prev_events: Vec::new(),
        auth_events: Vec::new(),
        content_json: content.to_owned(),
    }
}

#[test]
fn client_logs_in_then_uses_the_token_for_whoami_and_state() {
    // Assemble a real homeserver over one shared store and provision state.
    let server = GaussServer::new(SharedStore::new(), "gaussian.tech");
    server.register_account("alice", "hunter2");
    server.append_event(&name_event(r#"{"name":"Operations"}"#));
    let ingress = Ingress::with_server(server);

    // 1. Log in with password credentials.
    let body = r#"{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"hunter2"}"#;
    let login =
        ingress.handle(&Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body));
    assert_eq!(login.status, 200, "login should succeed: {}", login.body);
    let parsed = Json::parse(&login.body).unwrap();
    assert_eq!(
        parsed.get("user_id").and_then(Json::as_str),
        Some("@alice:gaussian.tech")
    );
    let token = parsed
        .get("access_token")
        .and_then(Json::as_str)
        .expect("a token")
        .to_owned();
    let auth = format!("Bearer {token}");

    // 2. The token authenticates whoami.
    let whoami = ingress.handle(
        &Request::new(Method::Get, "/_matrix/client/v3/account/whoami").with_authorization(&auth),
    );
    assert_eq!(whoami.status, 200);
    assert!(whoami.body.contains("@alice:gaussian.tech"));

    // 3. The token reads room state, returning the provisioned content.
    let state = ingress.handle(
        &Request::new(
            Method::Get,
            "/_matrix/client/v3/rooms/!ops:gaussian.tech/state/m.room.name",
        )
        .with_authorization(&auth),
    );
    assert_eq!(state.status, 200);
    assert_eq!(
        Json::parse(&state.body)
            .unwrap()
            .get("name")
            .and_then(Json::as_str),
        Some("Operations")
    );
}

#[test]
fn wrong_credentials_are_rejected_and_grant_no_access() {
    let server = GaussServer::new(SharedStore::new(), "gaussian.tech");
    server.register_account("alice", "hunter2");
    let ingress = Ingress::with_server(server);

    let body = r#"{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"WRONG"}"#;
    let login =
        ingress.handle(&Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body));
    assert_eq!(login.status, 403);

    // A made-up token authenticates nothing.
    let whoami = ingress.handle(
        &Request::new(Method::Get, "/_matrix/client/v3/account/whoami")
            .with_authorization("Bearer gmt_forged"),
    );
    assert_eq!(whoami.status, 401);
}
