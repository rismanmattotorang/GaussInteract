// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-http
//!
//! The HTTP ingress surface of GaussMatrix (GaussInteract-SPECS §III.B): the
//! supported Matrix spec versions and the Client–Server / Server–Server /
//! Application-Service endpoint set the homeserver must expose.
//!
//! The live ingress — axum/hyper terminating TLS and routing each request to
//! the service core — is the async runtime added on top; this crate pins *what*
//! must be served (the [`Endpoint`] set and [`SUPPORTED_SPEC_VERSIONS`]) so the
//! rest of the server, conformance tests, and clients agree on the surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod auth;
pub mod ingress;
pub mod router;
pub mod transport;

/// Matrix specification versions GaussMatrix advertises at
/// `/_matrix/client/versions` (spec §II.A requires ≥ v1.11).
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["v1.11"];

/// An HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
}

/// Which API an endpoint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Client–Server API.
    ClientServer,
    /// Server–Server (federation) API.
    ServerServer,
    /// Application Service API.
    Appservice,
}

/// The authentication scheme an endpoint requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// No authentication (e.g. `/versions`, `/login`).
    None,
    /// A client access token (`Authorization: Bearer …`), the CS API scheme.
    AccessToken,
    /// A federation request signature (the SS API scheme).
    Federation,
    /// The application-service `hs_token` (the AS API scheme).
    Appservice,
}

/// A homeserver endpoint: which API, method, path template, and auth scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    /// The API this endpoint belongs to.
    pub api: Api,
    /// The HTTP method.
    pub method: Method,
    /// The path template (parameters in `{braces}`).
    pub path: &'static str,
    /// The authentication scheme the endpoint requires.
    pub auth: Auth,
}

impl Endpoint {
    /// A Client–Server endpoint requiring a client access token.
    const fn cs(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ClientServer,
            method,
            path,
            auth: Auth::AccessToken,
        }
    }
    /// A public (unauthenticated) Client–Server endpoint.
    const fn cs_public(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ClientServer,
            method,
            path,
            auth: Auth::None,
        }
    }
    const fn ss(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ServerServer,
            method,
            path,
            auth: Auth::Federation,
        }
    }
    /// A public (unauthenticated) Server–Server endpoint, e.g. key publishing.
    const fn ss_public(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ServerServer,
            method,
            path,
            auth: Auth::None,
        }
    }
    const fn as_(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::Appservice,
            method,
            path,
            auth: Auth::Appservice,
        }
    }

    /// The endpoints GaussMatrix must serve. This is the conformance surface the
    /// live ingress wires to handlers; it grows as endpoints are implemented.
    pub fn surface() -> &'static [Endpoint] {
        SURFACE
    }
}

/// The endpoint conformance surface (see [`Endpoint::surface`]).
static SURFACE: &[Endpoint] = &[
    // Client–Server (public)
    Endpoint::cs_public(Method::Get, "/_matrix/client/versions"),
    Endpoint::cs_public(Method::Get, "/_matrix/client/v3/login"),
    Endpoint::cs_public(Method::Post, "/_matrix/client/v3/login"),
    // Client–Server (access-token authenticated)
    Endpoint::cs(Method::Get, "/_matrix/client/v3/account/whoami"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/createRoom"),
    Endpoint::cs(Method::Get, "/_matrix/client/v3/sync"),
    Endpoint::cs(Method::Get, "/_matrix/client/v3/rooms/{roomId}/state"),
    Endpoint::cs(Method::Get, "/_matrix/client/v3/rooms/{roomId}/members"),
    Endpoint::cs(
        Method::Get,
        "/_matrix/client/v3/rooms/{roomId}/joined_members",
    ),
    Endpoint::cs(
        Method::Get,
        "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
    ),
    Endpoint::cs(
        Method::Get,
        "/_matrix/client/v3/rooms/{roomId}/state/{eventType}",
    ),
    Endpoint::cs(Method::Get, "/_matrix/client/v3/rooms/{roomId}/messages"),
    Endpoint::cs(
        Method::Get,
        "/_matrix/client/v3/rooms/{roomId}/event/{eventId}",
    ),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/rooms/{roomId}/join"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/rooms/{roomId}/leave"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/rooms/{roomId}/invite"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/rooms/{roomId}/kick"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/rooms/{roomId}/ban"),
    Endpoint::cs(
        Method::Put,
        "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
    ),
    Endpoint::cs(
        Method::Put,
        "/_matrix/client/v3/rooms/{roomId}/typing/{userId}",
    ),
    Endpoint::cs(
        Method::Post,
        "/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}",
    ),
    Endpoint::cs(
        Method::Put,
        "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
    ),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/keys/upload"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/keys/query"),
    // Server–Server
    Endpoint::ss_public(Method::Get, "/_matrix/key/v2/server"),
    Endpoint::ss(Method::Put, "/_matrix/federation/v1/send/{txnId}"),
    Endpoint::ss(Method::Get, "/_matrix/federation/v1/state/{roomId}"),
    // Application Service
    Endpoint::as_(Method::Put, "/_matrix/app/v1/transactions/{txnId}"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_at_least_spec_v1_11() {
        assert!(SUPPORTED_SPEC_VERSIONS.contains(&"v1.11"));
    }

    #[test]
    fn surface_covers_all_three_apis_with_matrix_paths() {
        let surface = Endpoint::surface();
        assert!(surface.iter().any(|e| e.api == Api::ClientServer));
        assert!(surface.iter().any(|e| e.api == Api::ServerServer));
        assert!(surface.iter().any(|e| e.api == Api::Appservice));
        assert!(surface.iter().all(|e| e.path.starts_with("/_matrix/")));
    }

    #[test]
    fn sync_endpoint_is_present() {
        let surface = Endpoint::surface();
        assert!(surface
            .iter()
            .any(|e| e.method == Method::Get && e.path == "/_matrix/client/v3/sync"));
    }
}
