// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session and login configuration (spec §V.B, §V.E).
//!
//! GaussInteract supports SSO/OIDC login for the enterprise surface; password
//! login is retained for compatibility. The actual token exchange and device
//! provisioning are owned by `matrix-rust-sdk` in Phase 1.

/// How a user authenticates to a homeserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    /// Username/password (`m.login.password`).
    Password,
    /// Single sign-on via OpenID Connect, the enterprise default (§V.E).
    Oidc,
    /// Restoring a previously persisted session.
    Restore,
}

/// A Matrix user identifier, e.g. `@alice:example.org`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId(pub String);

/// A device identifier issued by the homeserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId(pub String);

/// An authenticated session held by [`crate::GaussCore`].
#[derive(Debug, Clone)]
pub struct Session {
    /// The homeserver base URL this session is bound to.
    pub homeserver: String,
    /// The logged-in user.
    pub user_id: UserId,
    /// This client's device.
    pub device_id: DeviceId,
    /// How the session was established.
    pub method: LoginMethod,
    /// Whether secure server-side key backup is enabled (§V.E enforces it for
    /// managed fleets).
    pub key_backup_enabled: bool,
}

impl Session {
    /// Construct a session descriptor (the token material lives in the SDK /
    /// platform secure storage, never here).
    pub fn new(
        homeserver: impl Into<String>,
        user_id: UserId,
        device_id: DeviceId,
        method: LoginMethod,
    ) -> Self {
        Self {
            homeserver: homeserver.into(),
            user_id,
            device_id,
            method,
            key_backup_enabled: false,
        }
    }
}
