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

pub mod ingress;
pub mod router;

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

/// A homeserver endpoint: which API, method, and path template it is served at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    /// The API this endpoint belongs to.
    pub api: Api,
    /// The HTTP method.
    pub method: Method,
    /// The path template (parameters in `{braces}`).
    pub path: &'static str,
}

impl Endpoint {
    const fn cs(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ClientServer,
            method,
            path,
        }
    }
    const fn ss(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::ServerServer,
            method,
            path,
        }
    }
    const fn as_(method: Method, path: &'static str) -> Self {
        Self {
            api: Api::Appservice,
            method,
            path,
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
    // Client–Server
    Endpoint::cs(Method::Get, "/_matrix/client/versions"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/login"),
    Endpoint::cs(Method::Get, "/_matrix/client/v3/sync"),
    Endpoint::cs(
        Method::Put,
        "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
    ),
    Endpoint::cs(
        Method::Put,
        "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
    ),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/keys/upload"),
    Endpoint::cs(Method::Post, "/_matrix/client/v3/keys/query"),
    // Server–Server
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
