<!--
SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# gauss-core

The shared, memory-safe **Rust core** of GaussInteract — the half of the
[hybrid client architecture](../GaussInteract-SPECS.pdf) (§V) that the single
Flutter UI sits on top of. It owns the client–server protocol, the local event
store and timeline cache, simplified sliding sync, and E2EE delegated to
[vodozemac](https://github.com/matrix-org/vodozemac) — implemented once and
shared across Android, iOS, Web (WASM) and the three desktop targets via
`uniffi`-generated bindings.

> **This is the Phase-1 scaffold.** It is `std`-only and dependency-free so the
> public surface and module boundaries compile and can be reviewed *before* the
> heavy dependencies are wired in. Stub points are marked `// TODO(phase-N)`.
> Crucially, it does **not** ship fake crypto: `e2ee` operations return
> `Unimplemented` rather than pretending to encrypt, and the audit-log hash is
> explicitly flagged as a placeholder for a cryptographic hash.

## Layout

```
gauss-core/
├── Cargo.toml          # stand-alone workspace; deps intentionally empty for now
├── rust-toolchain.toml # stable + rustfmt/clippy; native/WASM targets added later
├── deny.toml           # cargo-deny policy (spec §VI.C supply-chain gate)
└── src/
    ├── lib.rs          # GaussCore facade + module map
    ├── error.rs        # GaussError
    ├── session.rs      # login / SSO-OIDC, device identity        (§V.B/E)
    ├── store.rs        # EventStore trait + in-memory backend      (§V.B/C)
    ├── sync.rs         # simplified sliding-sync windowing          (§V.C)
    ├── e2ee.rs         # CryptoProvider facade over vodozemac    (§V.B,§VI.B)
    ├── timeline.rs     # timeline model incl. first-class agent items (§V.D/F)
    ├── events.rs       # m.gauss.agent.* events + capability grants  (§IV.B/C)
    └── agent.rs        # approvals + tamper-evident audit log    (§IV,§V.F)
```

The `agent` and `events` modules already implement the **capability scoping**
(`CapabilityGrant::classify` → auto / review / forbidden), the
**human-in-the-loop approval flow** (`AgentSurface::evaluate`), and a working
**hash-chained audit log** whose `verify()` detects retroactive tampering — the
structural guarantees of spec §IV.B–D — so the most distinctive part of the
platform is exercisable today. The same surface is mirrored on the Dart side in
[`lib/utils/gauss_core/gauss_core.dart`](../lib/utils/gauss_core/gauss_core.dart),
the integration seam the `uniffi` bindings will replace in Phase 2.

## Build & test

```bash
cd gauss-core
cargo test          # std-only; no network/registry access required
cargo clippy --all-targets
cargo fmt --check
```

## Roadmap mapping (→ `GaussInteract-SPECS.pdf` §V, §VII)

| Phase | Work landing in this crate |
|-------|----------------------------|
| **1** | Wire `matrix-rust-sdk` + `vodozemac` behind `session`/`store`/`sync`/`e2ee`; real CS protocol, encrypted persistent store, cross-signing, key backup. |
| **2** | Compile to native libs per target and to WASM; expose via `uniffi`; meet the `< 1.2 s` cold-start objective; Dart FFI shim in the Flutter app. |
| **3** | Connect `agent` to the server `gm-agent` MCP gateway: live tool-call/result items, capability-scoped approvals, server audit reconciliation. |
| **4** | Enterprise hardening: MDM-driven config, enforced key backup/cross-signing, per-device key-sharing controls, white-label hooks. |

Every phase keeps `#![forbid(unsafe_code)]` outside any future audited
crypto-adjacent module, with `cargo audit` / `cargo deny` gating each merge.

## How the Flutter app will consume it

`GaussCore` (in `lib.rs`) is the single object the UI talks to. Once `uniffi`
is enabled (the `ffi` feature), `cargo` emits a `staticlib`/`cdylib` per target
plus generated Dart bindings; the existing Flutter project calls those through a
thin FFI shim, replacing the Dart-SDK data/crypto path (Phase 2).
