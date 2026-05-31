// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end encryption facade (spec §V.B, §VI.B).
//!
//! **No bespoke cryptography is written here.** All E2EE is delegated to
//! [vodozemac] — the memory-safe re-implementation of Olm/Megolm — exactly as
//! Element X does. This module defines the [`CryptoProvider`] contract the core
//! depends on; the Phase-1 implementation wires it to vodozemac via
//! `matrix-sdk-crypto`. The agentic invariant (§IV) is enforced *here*: an
//! agent device only ever receives the Megolm sessions a room granted it.
//!
//! [vodozemac]: https://github.com/matrix-org/vodozemac

use crate::error::Result;

/// The cryptographic operations the core needs, all backed by vodozemac.
///
/// Deliberately a trait so that (a) the unsafe/audited crypto surface stays
/// isolated, and (b) tests can substitute a fake without touching real keys.
pub trait CryptoProvider: Send + Sync {
    /// Whether cross-signing identity is established for this device.
    fn is_cross_signed(&self) -> bool;

    /// Whether secure server-side key backup is active.
    fn key_backup_active(&self) -> bool;

    /// Encrypt a plaintext payload for a room's current Megolm session.
    fn encrypt(&self, room: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt a payload using the Megolm session shared with this device.
    fn decrypt(&self, room: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Share the current room key with a member device — the single chokepoint
    /// that bounds what an *agent* device can ever read (§IV, §V.F).
    fn share_room_key(&self, room: &str, device_id: &str) -> Result<()>;
}

/// Placeholder provider for the scaffold. Every operation reports
/// [`crate::GaussError::Unimplemented`] until vodozemac is wired in (Phase 1),
/// so it can never silently "succeed" with fake crypto.
#[derive(Debug, Default)]
pub struct VodozemacProvider {
    _private: (),
}

impl VodozemacProvider {
    /// Construct the (not-yet-wired) provider.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CryptoProvider for VodozemacProvider {
    fn is_cross_signed(&self) -> bool {
        false
    }

    fn key_backup_active(&self) -> bool {
        false
    }

    fn encrypt(&self, _room: &str, _plaintext: &[u8]) -> Result<Vec<u8>> {
        // TODO(phase-1): delegate to vodozemac Megolm outbound session.
        Err(crate::GaussError::Unimplemented("e2ee.encrypt (vodozemac)"))
    }

    fn decrypt(&self, _room: &str, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        // TODO(phase-1): delegate to vodozemac Megolm inbound session.
        Err(crate::GaussError::Unimplemented("e2ee.decrypt (vodozemac)"))
    }

    fn share_room_key(&self, _room: &str, _device_id: &str) -> Result<()> {
        // TODO(phase-1): enforce per-device key-sharing controls (§V.E).
        Err(crate::GaussError::Unimplemented("e2ee.share_room_key"))
    }
}
