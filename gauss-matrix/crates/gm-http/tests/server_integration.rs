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

/// The federation transaction node A sends: a self-consistent history for a
/// room on a.tld (create -> carol's join -> message), so each PDU authorizes
/// against the state the prior ones establish on the receiver.
const FED_TXN: &str = concat!(
    r#"{"origin":"a.tld","origin_server_ts":1700,"pdus":["#,
    r#"{"event_id":"$c","room_id":"!shared:a.tld","sender":"@carol:a.tld","#,
    r#""type":"m.room.create","state_key":"","origin_server_ts":1,"depth":1,"#,
    r#""prev_events":[],"auth_events":[],"content":{"creator":"@carol:a.tld"}},"#,
    r#"{"event_id":"$m","room_id":"!shared:a.tld","sender":"@carol:a.tld","#,
    r#""type":"m.room.member","state_key":"@carol:a.tld","origin_server_ts":2,"depth":2,"#,
    r#""prev_events":[],"auth_events":[],"content":{"membership":"join"}},"#,
    r#"{"event_id":"$fed1","room_id":"!shared:a.tld","sender":"@carol:a.tld","#,
    r#""type":"m.room.message","origin_server_ts":3,"depth":3,"#,
    r#""prev_events":[],"auth_events":[],"content":{"body":"hello from A"}}]}"#
);
const FED_TARGET: &str = "/_matrix/federation/v1/send/txn-A-1";

/// Build the `X-Matrix` header for the federation transaction, signed with the
/// base64 secret `seed`.
fn signed_fed_header(seed: &str) -> String {
    let bytes = gm_fed::auth::signing_bytes("PUT", FED_TARGET, "a.tld", "b.tld", Some(FED_TXN));
    gm_fed::auth::XMatrixAuth {
        origin: "a.tld".to_owned(),
        destination: Some("b.tld".to_owned()),
        key_id: "ed25519:1".to_owned(),
        signature: gm_fed::auth::sign(&bytes, seed),
    }
    .to_header()
}

#[test]
fn two_users_converse_after_an_invite_and_join() {
    // One server hosts both alice and bob.
    let server = GaussServer::new(SharedStore::new(), "gaussian.tech");
    server.register_account("alice", "pw");
    server.register_account("bob", "pw");
    let ingress = Ingress::with_server(server);

    let login = |user: &str| {
        let body = format!(
            r#"{{"type":"m.login.password","identifier":{{"type":"m.id.user","user":"{user}"}},"password":"pw"}}"#
        );
        let resp = ingress
            .handle(&Request::new(Method::Post, "/_matrix/client/v3/login").with_body(&body));
        format!(
            "Bearer {}",
            Json::parse(&resp.body)
                .unwrap()
                .get("access_token")
                .and_then(Json::as_str)
                .unwrap()
        )
    };
    let alice = login("alice");
    let bob = login("bob");

    // Alice creates a room.
    let created = ingress.handle(
        &Request::new(Method::Post, "/_matrix/client/v3/createRoom").with_authorization(&alice),
    );
    let room = Json::parse(&created.body)
        .unwrap()
        .get("room_id")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();

    let post = |target: String, auth: &str, body: &str| {
        ingress.handle(
            &Request::new(Method::Post, &target)
                .with_authorization(auth)
                .with_body(body),
        )
    };

    // Bob cannot join the invite-only room yet.
    let early_join = ingress.handle(
        &Request::new(
            Method::Post,
            &format!("/_matrix/client/v3/rooms/{room}/join"),
        )
        .with_authorization(&bob),
    );
    assert_eq!(early_join.status, 403);

    // Alice invites bob; bob joins; bob sends a message.
    let invite = post(
        format!("/_matrix/client/v3/rooms/{room}/invite"),
        &alice,
        r#"{"user_id":"@bob:gaussian.tech"}"#,
    );
    assert_eq!(invite.status, 200);
    let join = ingress.handle(
        &Request::new(
            Method::Post,
            &format!("/_matrix/client/v3/rooms/{room}/join"),
        )
        .with_authorization(&bob),
    );
    assert_eq!(join.status, 200);
    let send = ingress.handle(
        &Request::new(
            Method::Put,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/btxn1"),
        )
        .with_authorization(&bob)
        .with_body(r#"{"msgtype":"m.text","body":"hi from bob"}"#),
    );
    assert_eq!(send.status, 200);

    // Bob's /sync now shows the room he joined.
    let sync = ingress
        .handle(&Request::new(Method::Get, "/_matrix/client/v3/sync").with_authorization(&bob));
    assert!(Json::parse(&sync.body)
        .unwrap()
        .get("rooms")
        .and_then(|r| r.get("join"))
        .and_then(|j| j.get(&room))
        .is_some());
}

#[test]
fn federation_send_delivers_a_signed_event_between_two_servers_over_tcp() {
    // Node A holds a secret seed; node B registers A's derived public key.
    let a_seed = gm_fed::ed25519::seed_from_material("a.tld:ed25519:1");
    let a_public = gm_fed::ed25519::public_key_b64(&a_seed).unwrap();
    let store_b = SharedStore::new();
    let server_b = GaussServer::new(store_b.clone(), "b.tld");
    server_b.register_federation_key("a.tld", &a_public);
    let ingress_b = Ingress::with_server(server_b);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Node A signs the transaction with its secret seed and delivers it.
    let header = signed_fed_header(&a_seed);
    let sender =
        thread::spawn(move || transport::deliver_transaction(addr, "txn-A-1", &header, FED_TXN));

    let (stream, _) = listener.accept().unwrap();
    transport::serve_connection(&stream, &ingress_b).unwrap();
    let (status, body) = sender.join().unwrap().unwrap();

    // B verified the signature, authorized the events, and acked each PDU.
    assert_eq!(status, 200);
    let acked = Json::parse(&body).unwrap();
    for id in ["$c", "$m", "$fed1"] {
        let ack = acked.get("pdus").and_then(|p| p.get(id)).unwrap();
        assert!(ack.get("error").is_none(), "{id} should be accepted");
    }

    // The federated history is now persisted in B's room timeline.
    let b = GaussServer::new(store_b, "b.tld");
    let timeline = b.timeline(&RoomId::parse("!shared:a.tld").unwrap());
    assert_eq!(timeline.len(), 3);
    assert_eq!(timeline[2].event_id.as_str(), "$fed1");
    assert_eq!(timeline[2].sender.as_str(), "@carol:a.tld");
}

#[test]
fn federation_send_with_a_bad_signature_is_rejected_and_ingests_nothing() {
    let a_seed = gm_fed::ed25519::seed_from_material("a.tld:ed25519:1");
    let a_public = gm_fed::ed25519::public_key_b64(&a_seed).unwrap();
    let store_b = SharedStore::new();
    let server_b = GaussServer::new(store_b.clone(), "b.tld");
    server_b.register_federation_key("a.tld", &a_public);
    let ingress_b = Ingress::with_server(server_b);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // A signs with the WRONG seed — B's verification fails.
    let wrong_seed = gm_fed::ed25519::seed_from_material("a.tld:wrong");
    let header = signed_fed_header(&wrong_seed);
    let sender =
        thread::spawn(move || transport::deliver_transaction(addr, "txn-A-1", &header, FED_TXN));

    let (stream, _) = listener.accept().unwrap();
    transport::serve_connection(&stream, &ingress_b).unwrap();
    let (status, _) = sender.join().unwrap().unwrap();

    assert_eq!(status, 401);
    // Nothing was ingested.
    let b = GaussServer::new(store_b, "b.tld");
    assert!(b
        .timeline(&RoomId::parse("!shared:a.tld").unwrap())
        .is_empty());
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
