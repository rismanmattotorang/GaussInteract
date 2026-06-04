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
//! - `GM_STORE_DIR`   — a directory for a **persistent** file-backed store
//!   ([`gm_store::FileStore`]); when unset the store is the in-memory
//!   [`gm_store::SharedStore`] (data is lost on exit);
//! - `GM_DEMO_ACCOUNT` — optional `localpart:password` to provision at boot, so
//!   the server is usable immediately for a smoke test.
//!
//! Both stores are thread-safe and the transport serves each connection on its
//! own thread; an embedded-KV backend (`RocksStore`, behind the `rocksdb`
//! feature) and an async transport are the production swaps (the ingress and
//! service contracts are unchanged).

use gm_http::ingress::Ingress;
use gm_http::transport;
use gm_store::{FileStore, SharedStore, Store};
use gm_svc::GaussServer;
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listen = std::env::var("GM_LISTEN").unwrap_or_else(|_| "127.0.0.1:8448".to_owned());
    let server_name =
        std::env::var("GM_SERVER_NAME").unwrap_or_else(|_| "gaussian.tech".to_owned());

    // A persistent file-backed store when GM_STORE_DIR is set, else in-memory.
    match std::env::var("GM_STORE_DIR") {
        Ok(dir) => {
            eprintln!("using persistent store at {dir}");
            run(FileStore::open(&dir)?, &listen, &server_name)
        }
        Err(_) => run(SharedStore::new(), &listen, &server_name),
    }
}

/// Build the homeserver over `store` and serve it (generic over the backend).
fn run<S>(store: S, listen: &str, server_name: &str) -> std::io::Result<()>
where
    S: Store + Clone + Send + Sync + 'static,
{
    let server = GaussServer::new(store, server_name.to_owned());

    // Optionally provision a demo account so the server is immediately usable.
    if let Ok(demo) = std::env::var("GM_DEMO_ACCOUNT") {
        if let Some((localpart, password)) = demo.split_once(':') {
            if server.register_account(localpart, password).is_some() {
                eprintln!("provisioned demo account @{localpart}:{server_name}");
            }
        }
    }

    let ingress = Ingress::with_server(server);
    let listener = TcpListener::bind(listen)?;
    eprintln!("GaussMatrix homeserver listening on {listen} (server name: {server_name})");
    // The transport serves each connection on its own thread, sharing the
    // ingress over the thread-safe store.
    transport::serve(&listener, ingress)
}
