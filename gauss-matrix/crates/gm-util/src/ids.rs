// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Validated Matrix identifiers (spec §IV.A treats agents as first-class Matrix
//! principals). These newtypes make the difference between a user, a room and a
//! raw string explicit at API boundaries, with parsing that rejects malformed
//! input rather than letting it flow through the system.
//!
//! The validation here is the lightweight sigil/structure check the gateway
//! needs (`@localpart:server`, `!opaque:server`); the full Matrix grammar
//! (length limits, allowed code points, historical room-id rules) is enforced
//! by `ruma` once it is wired in.

use crate::error::GmError;
use std::fmt;

/// Split `s` into `(localpart, server)` if it begins with `sigil` and has a
/// non-empty localpart and server separated by a colon.
fn split_sigil(s: &str, sigil: char) -> Option<(&str, &str)> {
    let rest = s.strip_prefix(sigil)?;
    let (local, server) = rest.split_once(':')?;
    if local.is_empty() || server.is_empty() {
        return None;
    }
    Some((local, server))
}

/// A Matrix user identifier, e.g. `@alice:example.org`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Parse and validate a user id.
    pub fn parse(s: impl Into<String>) -> Result<Self, GmError> {
        let s = s.into();
        match split_sigil(&s, '@') {
            Some(_) => Ok(Self(s)),
            None => Err(GmError::InvalidUserId(s)),
        }
    }

    /// The server (homeserver) component, e.g. `example.org`.
    pub fn server_name(&self) -> &str {
        // Safe: validated at construction.
        self.0.split_once(':').map(|(_, s)| s).unwrap_or_default()
    }

    /// The localpart between `@` and `:`, e.g. `alice`.
    pub fn localpart(&self) -> &str {
        self.0
            .strip_prefix('@')
            .and_then(|rest| rest.split_once(':'))
            .map(|(local, _)| local)
            .unwrap_or_default()
    }

    /// The full id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Matrix room identifier, e.g. `!abcdef:example.org`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoomId(String);

impl RoomId {
    /// Parse and validate a room id.
    pub fn parse(s: impl Into<String>) -> Result<Self, GmError> {
        let s = s.into();
        match split_sigil(&s, '!') {
            Some(_) => Ok(Self(s)),
            None => Err(GmError::InvalidRoomId(s)),
        }
    }

    /// The server (homeserver) component.
    pub fn server_name(&self) -> &str {
        self.0.split_once(':').map(|(_, s)| s).unwrap_or_default()
    }

    /// The full id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Matrix event identifier, e.g. `$abcdef...`. From room version 3 onward an
/// event id is an opaque, sigil-prefixed reference hash with no `:server` part,
/// so only the `$` sigil and non-empty body are required here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(String);

impl EventId {
    /// Parse and validate an event id.
    pub fn parse(s: impl Into<String>) -> Result<Self, GmError> {
        let s = s.into();
        match s.strip_prefix('$') {
            Some(rest) if !rest.is_empty() => Ok(Self(s)),
            _ => Err(GmError::InvalidEventId(s)),
        }
    }

    /// The full id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An AI agent's identity. An agent is provisioned as a Matrix user in a
/// controlled namespace and cross-signed (spec §IV.A), so an `AgentId` is a
/// [`UserId`] with an agent-specific type for clarity at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(UserId);

impl AgentId {
    /// Parse and validate an agent id (a Matrix user id).
    pub fn parse(s: impl Into<String>) -> Result<Self, GmError> {
        Ok(Self(UserId::parse(s)?))
    }

    /// The underlying user id.
    pub fn as_user_id(&self) -> &UserId {
        &self.0
    }

    /// The full id as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids_parse_and_expose_server() {
        let u = UserId::parse("@alice:example.org").unwrap();
        assert_eq!(u.server_name(), "example.org");
        assert_eq!(u.localpart(), "alice");
        assert_eq!(u.as_str(), "@alice:example.org");

        let r = RoomId::parse("!abc:example.org").unwrap();
        assert_eq!(r.server_name(), "example.org");

        let a = AgentId::parse("@assistant:gaussian.tech").unwrap();
        assert_eq!(a.as_user_id().server_name(), "gaussian.tech");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        assert!(matches!(
            UserId::parse("alice:example.org"),
            Err(GmError::InvalidUserId(_))
        ));
        assert!(UserId::parse("@:example.org").is_err());
        assert!(UserId::parse("@alice").is_err());
        assert!(matches!(
            RoomId::parse("@alice:example.org"),
            Err(GmError::InvalidRoomId(_))
        ));
        assert!(RoomId::parse("not-a-room").is_err());
        assert!(AgentId::parse("nope").is_err());
        assert!(EventId::parse("$abc").is_ok());
        assert!(matches!(
            EventId::parse("abc"),
            Err(GmError::InvalidEventId(_))
        ));
        assert!(EventId::parse("$").is_err());
    }
}
