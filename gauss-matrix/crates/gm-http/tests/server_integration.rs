// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! End-to-end: the ingress driving the real composed [`GaussServer`] over one
//! shared store. This is the assembled homeserver answering a client's flow —
//! log in, confirm identity, read room state — exactly as the async transport
//! will once it fronts [`Ingress::handle`].

use gm_api::{events, Json, Pdu};
use gm_http::ingress::{Ingress, Request};
use gm_http::{transport, Method};
use gm_store::SharedStore;
use gm_svc::GaussServer;
use gm_util::{EventId, RoomId, UserId};
use std::net::TcpListener;
use std::thread;

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
fn client_logs_in_creates_a_room_then_sends_a_message_idempotently() {
    let server = GaussServer::new(SharedStore::new(), "gaussian.tech");
    server.register_account("alice", "hunter2");
    let ingress = Ingress::with_server(server);

    // Log in to obtain a token.
    let body = r#"{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"hunter2"}"#;
    let login =
        ingress.handle(&Request::new(Method::Post, "/_matrix/client/v3/login").with_body(body));
    let token = Json::parse(&login.body)
        .unwrap()
        .get("access_token")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();
    let auth = format!("Bearer {token}");

    // Create a room through the API; the response carries the new room id.
    let created = ingress.handle(
        &Request::new(Method::Post, "/_matrix/client/v3/createRoom")
            .with_authorization(&auth)
            .with_body(r#"{"name":"Operations"}"#),
    );
    assert_eq!(created.status, 200);
    let room = Json::parse(&created.body)
        .unwrap()
        .get("room_id")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();

    // The created room's name is immediately readable as state.
    let name = ingress.handle(
        &Request::new(
            Method::Get,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
        )
        .with_authorization(&auth),
    );
    assert_eq!(name.status, 200);
    assert_eq!(
        Json::parse(&name.body)
            .unwrap()
            .get("name")
            .and_then(Json::as_str),
        Some("Operations")
    );

    let send = |txn: &str| {
        let target = format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}");
        ingress.handle(
            &Request::new(Method::Put, &target)
                .with_authorization(&auth)
                .with_body(r#"{"msgtype":"m.text","body":"hello"}"#),
        )
    };

    // First send creates an event.
    let first = send("txnA");
    assert_eq!(first.status, 200);
    let id1 = Json::parse(&first.body)
        .unwrap()
        .get("event_id")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();

    // Retrying the same transaction id returns the same event (idempotent).
    let retry = send("txnA");
    assert_eq!(
        Json::parse(&retry.body)
            .unwrap()
            .get("event_id")
            .and_then(Json::as_str),
        Some(id1.as_str())
    );

    // A different transaction id creates a distinct event.
    let second = send("txnB");
    let id2 = Json::parse(&second.body)
        .unwrap()
        .get("event_id")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();
    assert_ne!(id1, id2);

    // GET /messages returns the whole timeline (creation state + both messages),
    // oldest first.
    let messages = ingress.handle(
        &Request::new(
            Method::Get,
            &format!("/_matrix/client/v3/rooms/{room}/messages"),
        )
        .with_authorization(&auth),
    );
    assert_eq!(messages.status, 200);
    let body = Json::parse(&messages.body).unwrap();
    let chunk = body.get("chunk").and_then(Json::as_array).unwrap();
    // The two m.room.message events are the most recent, in send order.
    let message_ids: Vec<&str> = chunk
        .iter()
        .filter(|e| e.get("type").and_then(Json::as_str) == Some("m.room.message"))
        .filter_map(|e| e.get("event_id").and_then(Json::as_str))
        .collect();
    assert_eq!(message_ids, vec![id1.as_str(), id2.as_str()]);
    // The room began with its create event.
    assert_eq!(
        chunk
            .first()
            .and_then(|e| e.get("type"))
            .and_then(Json::as_str),
        Some("m.room.create")
    );

    // GET /sync shows the joined room with its state and timeline.
    let sync = ingress
        .handle(&Request::new(Method::Get, "/_matrix/client/v3/sync").with_authorization(&auth));
    assert_eq!(sync.status, 200);
    let synced = Json::parse(&sync.body).unwrap();
    let joined_room = synced
        .get("rooms")
        .and_then(|r| r.get("join"))
        .and_then(|j| j.get(&room))
        .expect("alice's joined room");
    // State includes the room name; timeline includes both messages.
    let state_has_name = joined_room
        .get("state")
        .and_then(|s| s.get("events"))
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .any(|e| e.get("type").and_then(Json::as_str) == Some("m.room.name"));
    assert!(state_has_name);
    let timeline_msgs = joined_room
        .get("timeline")
        .and_then(|t| t.get("events"))
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .filter(|e| e.get("type").and_then(Json::as_str) == Some("m.room.message"))
        .count();
    assert_eq!(timeline_msgs, 2);
}

#[test]
fn federation_send_delivers_an_event_between_two_servers_over_tcp() {
    // Node B: a real homeserver listening on an ephemeral port.
    let store_b = SharedStore::new();
    let ingress_b = Ingress::with_server(GaussServer::new(store_b.clone(), "b.tld"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Node A: build a federation transaction carrying one PDU for a B-room, and
    // deliver it to B's /send endpoint from a client thread (the sender side).
    let txn = concat!(
        r#"{"origin":"a.tld","origin_server_ts":1700,"pdus":[{"#,
        r#""event_id":"$fed1","room_id":"!shared:b.tld","sender":"@carol:a.tld","#,
        r#""type":"m.room.message","origin_server_ts":1700,"depth":1,"#,
        r#""prev_events":[],"auth_events":[],"content":{"body":"hello from A"}}]}"#
    );
    let sender = thread::spawn(move || {
        transport::deliver_transaction(
            addr,
            "txn-A-1",
            "X-Matrix origin=a.tld,key=\"ed25519:1\",sig=\"sig\"",
            txn,
        )
    });

    // Node B serves the one inbound connection.
    let (stream, _) = listener.accept().unwrap();
    transport::serve_connection(&stream, &ingress_b).unwrap();
    let (status, body) = sender.join().unwrap().unwrap();

    // B accepted the transaction and acked the PDU.
    assert_eq!(status, 200);
    assert!(Json::parse(&body)
        .unwrap()
        .get("pdus")
        .and_then(|p| p.get("$fed1"))
        .is_some());

    // The federated event is now persisted in B's room timeline.
    let b = GaussServer::new(store_b, "b.tld");
    let timeline = b.timeline(&RoomId::parse("!shared:b.tld").unwrap());
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].event_id.as_str(), "$fed1");
    assert_eq!(timeline[0].sender.as_str(), "@carol:a.tld");
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
