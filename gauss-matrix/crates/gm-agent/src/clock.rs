// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A small clock abstraction so rate-limit enforcement (spec §IV.C) is
//! deterministically testable. Production uses [`SystemClock`]; tests inject a
//! [`ManualClock`] they can advance.

use std::cell::Cell;

/// A monotonic-ish wall clock, in whole seconds since the Unix epoch.
pub trait Clock {
    /// The current time, in seconds since the Unix epoch.
    fn now_unix_secs(&self) -> u64;
}

/// The real system clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A test clock that returns a fixed time until advanced.
#[derive(Debug)]
pub struct ManualClock {
    secs: Cell<u64>,
}

impl ManualClock {
    /// Create a clock starting at `secs`.
    pub fn new(secs: u64) -> Self {
        Self {
            secs: Cell::new(secs),
        }
    }

    /// Advance the clock by `secs` seconds.
    pub fn advance(&self, secs: u64) {
        self.secs.set(self.secs.get() + secs);
    }
}

impl Clock for ManualClock {
    fn now_unix_secs(&self) -> u64 {
        self.secs.get()
    }
}
