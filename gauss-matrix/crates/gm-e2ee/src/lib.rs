// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-e2ee
//!
//! The E2EE key-relay surface of GaussMatrix (GaussInteract-SPECS §II.A, §VI.B).
//!
//! The homeserver **never holds plaintext**: clients encrypt with vodozemac and
//! the server only relays opaque key material — device keys, one-time keys,
//! cross-signing keys, and the secure key-backup blobs — so that cross-signing
//! and key backup work end to end without the server decrypting anything. This
//! crate models that relayed material as opaque envelopes; **no cryptography is
//! performed here** (that is vodozemac's job, on the client).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

use gm_util::UserId;
use std::collections::BTreeMap;

/// A device's published public keys (identity + signing), relayed verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeys {
    /// The owning user.
    pub user_id: UserId,
    /// The device identifier.
    pub device_id: String,
    /// Supported encryption algorithms (e.g. `m.olm.v1...`, `m.megolm.v1...`).
    pub algorithms: Vec<String>,
    /// Public keys keyed by `algorithm:device_id`.
    pub keys: BTreeMap<String, String>,
    /// Opaque signatures, keyed by user then key id (relayed, never checked here).
    pub signatures: BTreeMap<String, BTreeMap<String, String>>,
}

/// The count of unclaimed one-time keys a device has on the server, per
/// algorithm — what `/keys/claim` draws down and clients top up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OneTimeKeyCounts {
    /// Algorithm → remaining count.
    pub counts: BTreeMap<String, u32>,
}

/// The purpose of a cross-signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossSigningUsage {
    /// The user's master key.
    Master,
    /// The self-signing key (signs the user's own devices).
    SelfSigning,
    /// The user-signing key (signs other users' master keys).
    UserSigning,
}

/// A cross-signing public key (master / self-signing / user-signing), relayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossSigningKey {
    /// The owning user.
    pub user_id: UserId,
    /// What this key is for.
    pub usage: CrossSigningUsage,
    /// Public keys keyed by `ed25519:base64`.
    pub keys: BTreeMap<String, String>,
}

/// A secure server-side key-backup version. The `auth_data` and the per-room
/// session blobs are opaque to the server (encrypted under the recovery key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBackupVersion {
    /// The backup version identifier the server assigns.
    pub version: String,
    /// The backup algorithm (e.g. `m.megolm_backup.v1.curve25519-aes-sha2`).
    pub algorithm: String,
    /// Opaque auth data (a public key + signatures), stored verbatim.
    pub auth_data_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_keys_relay_opaque_material() {
        let keys = DeviceKeys {
            user_id: UserId::parse("@a:gaussian.tech").unwrap(),
            device_id: "DEV1".to_owned(),
            algorithms: vec!["m.megolm.v1.aes-sha2".to_owned()],
            keys: [("ed25519:DEV1".to_owned(), "base64key".to_owned())].into(),
            signatures: BTreeMap::new(),
        };
        assert_eq!(
            keys.keys.get("ed25519:DEV1").map(String::as_str),
            Some("base64key")
        );
    }

    #[test]
    fn one_time_key_counts_track_per_algorithm() {
        let mut otk = OneTimeKeyCounts::default();
        otk.counts.insert("signed_curve25519".to_owned(), 50);
        assert_eq!(otk.counts.get("signed_curve25519"), Some(&50));
    }

    #[test]
    fn cross_signing_and_backup_envelopes_construct() {
        let csk = CrossSigningKey {
            user_id: UserId::parse("@a:gaussian.tech").unwrap(),
            usage: CrossSigningUsage::Master,
            keys: [("ed25519:base64".to_owned(), "base64".to_owned())].into(),
        };
        assert_eq!(csk.usage, CrossSigningUsage::Master);

        let backup = KeyBackupVersion {
            version: "1".to_owned(),
            algorithm: "m.megolm_backup.v1.curve25519-aes-sha2".to_owned(),
            auth_data_json: "{}".to_owned(),
        };
        assert_eq!(backup.version, "1");
    }
}
