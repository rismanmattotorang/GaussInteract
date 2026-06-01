// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Supported Matrix room versions (spec §II.A: room versions through 12).
//!
//! Matrix room versions are protocol strings; GaussMatrix targets the stable
//! numeric series 1–12. Non-numeric/experimental versions are out of scope here
//! and parse to `None`.

/// A supported room version (1 through [`RoomVersion::MAX_SUPPORTED`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoomVersion(u8);

impl RoomVersion {
    /// The highest room version GaussMatrix implements (spec §II.A).
    pub const MAX_SUPPORTED: u8 = 12;

    /// Parse a room-version string, accepting the stable numeric series 1–12.
    pub fn parse(s: &str) -> Option<Self> {
        s.parse::<u8>()
            .ok()
            .filter(|&v| (1..=Self::MAX_SUPPORTED).contains(&v))
            .map(RoomVersion)
    }

    /// The numeric version.
    pub fn number(&self) -> u8 {
        self.0
    }

    /// The canonical room-version string.
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }

    /// Whether `version` is a room version this server supports.
    pub fn is_supported(version: &str) -> bool {
        Self::parse(version).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_supported_range_and_rejects_the_rest() {
        assert_eq!(RoomVersion::parse("1").map(|v| v.number()), Some(1));
        assert_eq!(RoomVersion::parse("12").map(|v| v.number()), Some(12));
        assert_eq!(RoomVersion::parse("12").unwrap().as_string(), "12");
        assert!(RoomVersion::parse("0").is_none());
        assert!(RoomVersion::parse("13").is_none());
        assert!(RoomVersion::parse("org.matrix.msc1234").is_none());
        assert!(RoomVersion::is_supported("11"));
        assert!(!RoomVersion::is_supported("99"));
    }

    #[test]
    fn versions_order_numerically() {
        assert!(RoomVersion::parse("11") < RoomVersion::parse("12"));
    }
}
