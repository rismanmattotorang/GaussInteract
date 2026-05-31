// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # gauss-core
//!
//! The shared, memory-safe Rust core of **GaussInteract**, the agentic-AI
//! Matrix client by Gaussian Technologies.
//!
//! As specified in `GaussInteract-SPECS.pdf` §V, GaussInteract is a *hybrid*
//! client: a single Flutter presentation layer over **one** shared Rust core.
//! The heavy paths — the client–server protocol, the local event store and
//! timeline cache, simplified sliding sync, and end-to-end encryption
//! (delegated to [vodozemac]) — live here, in audited Rust, and are compiled
//! once per native target (Android, iOS, the three desktops) and to
//! WebAssembly for the web. The UI reaches this core through `uniffi`-generated
//! bindings and a thin Dart FFI shim.
//!
//! ## Status
//!
//! This is the **Phase-1 scaffold**: it defines the public surface and the
//! module boundaries described by the specification, with std-only, dependency
//! -free stub implementations so the architecture compiles and can be reviewed.
//! Items that delegate to external crates in the real implementation are marked
//! `// TODO(phase-N)` against the roadmap in [`README.md`](https://github.com/rismanmattotorang/gaussinteract).
//!
//! ## Module map (→ spec §)
//!
//! | Module        | Responsibility                                   | Spec |
//! |---------------|--------------------------------------------------|------|
//! | [`session`]   | Login / SSO-OIDC, homeserver, device identity    | §V.B, §V.E |
//! | [`store`]     | Local event store & incremental timeline cache   | §V.B, §V.C |
//! | [`sync`]      | Simplified sliding sync engine                   | §V.C |
//! | [`e2ee`]      | vodozemac-backed E2EE (Olm/Megolm, cross-signing)| §V.B, §VI.B |
//! | [`timeline`]  | Timeline item model (incl. first-class agent items)| §V.D, §V.F |
//! | [`events`]    | Namespaced `m.gauss.agent.*` events + capability grants | §IV.B–C |
//! | [`agent`]     | Client agent surface: approvals + tamper-evident audit | §IV, §V.F |
//!
//! [vodozemac]: https://github.com/matrix-org/vodozemac

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod agent;
pub mod e2ee;
pub mod error;
pub mod events;
pub mod session;
pub mod store;
pub mod sync;
pub mod timeline;

pub use error::{GaussError, Result};

use crate::agent::AgentSurface;
use crate::session::Session;
use crate::store::{EventStore, MemoryStore};

/// The build/version string the FFI layer can surface to the UI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The single entry point the Flutter layer talks to over FFI.
///
/// In the real implementation this owns a `matrix_sdk::Client`, the crypto
/// machine, and the sliding-sync loop. Here it wires together the scaffolded
/// subsystems so the shape of the API is reviewable.
pub struct GaussCore {
    session: Option<Session>,
    store: Box<dyn EventStore>,
    agents: AgentSurface,
}

impl GaussCore {
    /// Create an unauthenticated core backed by an in-memory store.
    ///
    /// Phase-2 will accept a persistent, encrypted store path instead.
    pub fn new() -> Self {
        Self {
            session: None,
            store: Box::new(MemoryStore::default()),
            agents: AgentSurface::new(),
        }
    }

    /// Whether a session is currently restored/active.
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// Attach a restored or freshly logged-in session.
    pub fn set_session(&mut self, session: Session) {
        self.session = Some(session);
    }

    /// The current session, if any.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Access the local event store.
    pub fn store(&self) -> &dyn EventStore {
        self.store.as_ref()
    }

    /// Mutable access to the local event store.
    pub fn store_mut(&mut self) -> &mut dyn EventStore {
        self.store.as_mut()
    }

    /// The client-side agent surface (approvals + audit view), per spec §V.F.
    pub fn agents(&self) -> &AgentSurface {
        &self.agents
    }

    /// Mutable access to the agent surface.
    pub fn agents_mut(&mut self) -> &mut AgentSurface {
        &mut self.agents
    }
}

impl Default for GaussCore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_starts_unauthenticated() {
        let core = GaussCore::new();
        assert!(!core.is_authenticated());
        assert!(!VERSION.is_empty());
    }
}
