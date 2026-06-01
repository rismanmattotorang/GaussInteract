// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! The homeserver service seam the ingress drives.
//!
//! The HTTP ingress (`gm-http`) is transport and routing; the actual work —
//! authenticating tokens, reading room state, (later) persisting events — is the
//! service core (`gm-svc`). Rather than couple the ingress to that core, it is
//! generic over the capability traits defined here, in the shared crate. Each
//! capability is its own small trait ([`TokenAuthority`], [`RoomReader`]) so a
//! component implements only what it provides; [`Homeserver`] bundles the set
//! the ingress needs, with a blanket impl so any type providing them all is a
//! homeserver. The assembled server plugs its composed services in as the `H`.

use crate::auth::TokenAuthority;
use gm_util::{RoomId, UserId};

/// Read-only access to room state (the CS state-read / federation state paths).
pub trait RoomReader {
    /// The content JSON of the state event filling `(event_type, state_key)` in
    /// `room`, or `None` if that slot is empty.
    fn room_state_content(
        &self,
        room: &RoomId,
        event_type: &str,
        state_key: &str,
    ) -> Option<String>;
}

/// The result of a successful login: the full user id and a fresh access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginGrant {
    /// The authenticated user.
    pub user_id: UserId,
    /// A freshly-minted access token for the session.
    pub access_token: String,
}

/// Password login (the `POST /login` path).
///
/// Takes `&self` because the ingress is a shared, immutable front; an
/// implementation that mints a session token uses interior mutability (the live
/// server fronts shared state with a lock, as servers do).
pub trait Login {
    /// Authenticate `localpart` + `password`; on success mint a session and
    /// return the grant, else `None`.
    fn password_login(&self, localpart: &str, password: &str) -> Option<LoginGrant>;
}

/// The full capability set the ingress requires of a homeserver. Blanket-
/// implemented: any type that is a [`TokenAuthority`], a [`RoomReader`] and a
/// [`Login`] provider is a `Homeserver`.
pub trait Homeserver: TokenAuthority + RoomReader + Login {}

impl<T: TokenAuthority + RoomReader + Login> Homeserver for T {}

/// A homeserver that provides nothing — the default for an ingress with no
/// service core wired in. Public endpoints still work; authenticated endpoints
/// reject every token and room reads find nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoServer;

impl TokenAuthority for NoServer {
    fn user_for(&self, _token: &str) -> Option<gm_util::UserId> {
        None
    }
}

impl RoomReader for NoServer {
    fn room_state_content(
        &self,
        _room: &RoomId,
        _event_type: &str,
        _state_key: &str,
    ) -> Option<String> {
        None
    }
}

impl Login for NoServer {
    fn password_login(&self, _localpart: &str, _password: &str) -> Option<LoginGrant> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_homeserver<H: Homeserver>(_: &H) {}

    #[test]
    fn no_server_is_a_homeserver_that_provides_nothing() {
        let s = NoServer;
        is_homeserver(&s); // satisfies the bundle via the blanket impl
        assert_eq!(s.user_for("t"), None);
        assert_eq!(
            s.room_state_content(
                &RoomId::parse("!r:gaussian.tech").unwrap(),
                "m.room.name",
                ""
            ),
            None
        );
    }
}
