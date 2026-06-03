// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The GaussMatrix homeserver binary.
//!
//! Assembles the composed service core ([`gm_svc::GaussServer`] over a shared
//! store) behind the HTTP ingress ([`gm_http::ingress::Ingress`]) and serves it
//! on a TCP socket with the std-only transport. This is the runnable homeserver
//! that ties together everything the workspace builds — routing, authentication,
//! sessions, accounts, rooms, send/sync — over one dataset.
//!
//! Configuration via environment:
//! - `GM_LISTEN`      — listen address (default `127.0.0.1:8448`);
//! - `GM_SERVER_NAME` — the server name users are hosted on (default
//!   `gaussian.tech`);
//! - `GM_DEMO_ACCOUNT` — optional `localpart:password` to provision at boot, so
//!   the server is usable immediately for a smoke test.
//!
//! The store is the in-memory, thread-safe [`gm_store::SharedStore`]
//! (`Arc<RwLock<…>>`) and the transport serves each connection on its own
//! thread; a persistent backend and an async transport are the production swaps
//! (the ingress and service contracts are unchanged).

use gm_http::ingress::Ingress;
use gm_http::transport;
use gm_store::SharedStore;
use gm_svc::GaussServer;
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listen = std::env::var("GM_LISTEN").unwrap_or_else(|_| "127.0.0.1:8448".to_owned());
    let server_name =
        std::env::var("GM_SERVER_NAME").unwrap_or_else(|_| "gaussian.tech".to_owned());

    let server = GaussServer::new(SharedStore::new(), server_name.clone());

    // Optionally provision a demo account so the server is immediately usable.
    if let Ok(demo) = std::env::var("GM_DEMO_ACCOUNT") {
        if let Some((localpart, password)) = demo.split_once(':') {
            if server.register_account(localpart, password).is_some() {
                eprintln!("provisioned demo account @{localpart}:{server_name}");
            }
        }
    }

    let ingress = Ingress::with_server(server);
    let listener = TcpListener::bind(&listen)?;
    eprintln!("GaussMatrix homeserver listening on {listen} (server name: {server_name})");
    // The transport serves each connection on its own thread, sharing the
    // ingress over the thread-safe store.
    transport::serve(&listener, ingress)
}
