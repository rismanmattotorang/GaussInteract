// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Simplified sliding sync (spec §V.C, MSC4186).
//!
//! The client materialises only the *visible window* of rooms and lazily
//! expands, which is what keeps cold start fast and memory bounded. Phase 2
//! drives this from `matrix-sdk`'s sliding-sync; here we model the windowing
//! state machine so the UI contract (visible range → room list) is explicit.

use crate::store::RoomId;

/// The window of rooms the UI currently has materialised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncWindow {
    /// Inclusive start index into the (server-ordered) room list.
    pub start: usize,
    /// Inclusive end index.
    pub end: usize,
}

impl SyncWindow {
    /// Create a window, normalising an inverted range.
    pub fn new(start: usize, end: usize) -> Self {
        if start <= end {
            Self { start, end }
        } else {
            Self {
                start: end,
                end: start,
            }
        }
    }

    /// Number of rooms in the window.
    pub fn len(&self) -> usize {
        self.end - self.start + 1
    }

    /// Whether the window is empty (never, given the inclusive range, but kept
    /// for clippy and API completeness).
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Drives windowed synchronisation. The real engine is async and SDK-backed;
/// this trait pins the surface the Flutter layer scrolls against.
pub trait SyncEngine {
    /// Advance the materialised window (e.g. on scroll).
    fn set_window(&mut self, window: SyncWindow);

    /// The currently materialised, ordered room ids.
    fn visible_rooms(&self) -> &[RoomId];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_normalises_and_measures() {
        let w = SyncWindow::new(20, 0);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 20);
        assert_eq!(w.len(), 21);
    }
}
