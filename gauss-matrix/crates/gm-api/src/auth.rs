// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The authentication seam between the ingress and the session layer.
//!
//! The HTTP ingress (`gm-http`) knows how to *extract* a client access token
//! and gate endpoints on its presence, but resolving a token to the user it
//! authenticates is server state owned by the session layer (`gm-svc`). This
//! trait is the narrow seam between them, defined here in the shared API crate
//! so the ingress can be generic over *any* authority without depending on the
//! service core: the assembled server plugs its session store in as the `A`.

use gm_util::UserId;

/// Resolves a client access token to the user it authenticates.
pub trait TokenAuthority {
    /// The user `token` authenticates, or `None` if the token is unknown,
    /// revoked or expired.
    fn user_for(&self, token: &str) -> Option<UserId>;
}

/// An authority that authenticates no one — every token is unknown.
///
/// The default for an ingress with no session layer wired in: public endpoints
/// still work, and authenticated endpoints reject every token (`M_UNKNOWN_TOKEN`)
/// rather than trusting an unvalidated one.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthority;

impl TokenAuthority for NoAuthority {
    fn user_for(&self, _token: &str) -> Option<UserId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_authority_rejects_every_token() {
        assert_eq!(NoAuthority.user_for("anything"), None);
    }
}
