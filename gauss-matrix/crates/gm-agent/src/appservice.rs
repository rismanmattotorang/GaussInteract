// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Application Service registration (spec §IV.A).
//!
//! An agent is not a privileged side channel — it is a Matrix principal. Each
//! agent is provisioned through the Matrix **Application Service (AS)** API as a
//! user in a *controlled, exclusive namespace*, given a device, and cross-signed
//! so other members verify it exactly as they verify a human device.
//!
//! This module models the registration and the agent namespace. The live AS
//! integration — emitting a `registration.yaml`, the `as_token` / `hs_token`
//! handshake, and receiving the homeserver's `/transactions` push — is wired
//! behind the `mcp` feature. To stay dependency-free, the namespace is matched
//! here by localpart prefix rather than the registration's full regex; the
//! intent (an exclusive `@<prefix>…:server` namespace the AS owns) is identical.

use gm_util::{AgentId, GmError, UserId};

/// The controlled namespace that agent identities live in, e.g. all users
/// matching `@gauss_agent_…:gaussian.tech`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentNamespace {
    /// The homeserver the namespace belongs to.
    pub server_name: String,
    /// The localpart prefix every agent in the namespace carries.
    pub localpart_prefix: String,
    /// Whether the AS claims this namespace exclusively (no other client may
    /// register a colliding user). Agent namespaces should be exclusive.
    pub exclusive: bool,
}

impl AgentNamespace {
    /// A new exclusive agent namespace.
    pub fn new(server_name: impl Into<String>, localpart_prefix: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            localpart_prefix: localpart_prefix.into(),
            exclusive: true,
        }
    }

    /// Whether `user` falls within this agent namespace.
    pub fn contains(&self, user: &UserId) -> bool {
        user.server_name() == self.server_name
            && user.localpart().starts_with(&self.localpart_prefix)
    }

    /// Mint an agent identity `@{prefix}{name}:{server}` in this namespace.
    /// `name` must be non-empty and free of the `:` / `@` separators.
    pub fn mint(&self, name: &str) -> Result<AgentId, GmError> {
        if name.is_empty() || name.contains(':') || name.contains('@') {
            return Err(GmError::InvalidUserId(name.to_owned()));
        }
        AgentId::parse(format!(
            "@{}{}:{}",
            self.localpart_prefix, name, self.server_name
        ))
    }
}

/// A Matrix Application Service registration: the gateway's own identity plus
/// the agent namespace it owns. The tokens are secrets configured out-of-band
/// (kept here only so a `registration.yaml` can be emitted later).
#[derive(Debug, Clone)]
pub struct AppserviceRegistration {
    /// The AS id (must be unique on the homeserver).
    pub id: String,
    /// The localpart of the AS's own sender user.
    pub sender_localpart: String,
    /// Token the AS presents to the homeserver (secret).
    pub as_token: String,
    /// Token the homeserver presents to the AS (secret).
    pub hs_token: String,
    /// Where the homeserver pushes transactions to the AS, if set.
    pub url: Option<String>,
    /// The exclusive agent user namespace this AS owns.
    pub namespace: AgentNamespace,
}

impl AppserviceRegistration {
    /// A registration with empty token/url placeholders; set them with the
    /// builder methods (tokens come from secure configuration, not source).
    pub fn new(
        id: impl Into<String>,
        sender_localpart: impl Into<String>,
        namespace: AgentNamespace,
    ) -> Self {
        Self {
            id: id.into(),
            sender_localpart: sender_localpart.into(),
            as_token: String::new(),
            hs_token: String::new(),
            url: None,
            namespace,
        }
    }

    /// Set the AS/HS tokens (builder-style).
    pub fn with_tokens(mut self, as_token: impl Into<String>, hs_token: impl Into<String>) -> Self {
        self.as_token = as_token.into();
        self.hs_token = hs_token.into();
        self
    }

    /// Set the push URL the homeserver delivers transactions to (builder-style).
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// The AS's own sender user id, `@{sender_localpart}:{server}`.
    pub fn sender_user_id(&self) -> Result<AgentId, GmError> {
        AgentId::parse(format!(
            "@{}:{}",
            self.sender_localpart, self.namespace.server_name
        ))
    }

    /// Whether this AS manages `user` — i.e. it is one of our provisioned
    /// agents, not an arbitrary or impersonating identity.
    pub fn manages(&self, user: &UserId) -> bool {
        self.namespace.contains(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace() -> AgentNamespace {
        AgentNamespace::new("gaussian.tech", "gauss_agent_")
    }

    #[test]
    fn mints_agents_inside_the_namespace() {
        let ns = namespace();
        let agent = ns.mint("assistant").unwrap();
        assert_eq!(agent.as_str(), "@gauss_agent_assistant:gaussian.tech");
        assert!(ns.contains(agent.as_user_id()));
    }

    #[test]
    fn mint_rejects_separator_chars() {
        let ns = namespace();
        assert!(ns.mint("").is_err());
        assert!(ns.mint("bad:name").is_err());
        assert!(ns.mint("bad@name").is_err());
    }

    #[test]
    fn namespace_excludes_foreign_and_unprefixed_users() {
        let ns = namespace();
        // A human user, or an agent-looking user on another server, is not ours.
        assert!(!ns.contains(&UserId::parse("@alice:gaussian.tech").unwrap()));
        assert!(!ns.contains(&UserId::parse("@gauss_agent_x:evil.example").unwrap()));
    }

    #[test]
    fn registration_exposes_sender_and_manages_agents() {
        let reg = AppserviceRegistration::new("gauss-agents", "gauss", namespace())
            .with_tokens("as-secret", "hs-secret")
            .with_url("https://gateway.gaussian.tech");
        assert_eq!(
            reg.sender_user_id().unwrap().as_str(),
            "@gauss:gaussian.tech"
        );
        let agent = reg.namespace.mint("assistant").unwrap();
        assert!(reg.manages(agent.as_user_id()));
        assert!(!reg.manages(&UserId::parse("@mallory:gaussian.tech").unwrap()));
    }
}
