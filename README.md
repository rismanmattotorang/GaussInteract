<!--
SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
SPDX-FileCopyrightText: 2019-Present Christian Kußowski
SPDX-FileCopyrightText: 2019-Present Contributors to FluffyChat

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<p align="center">
  <img src="assets/logo/img/logo_font.png" alt="GaussInteract" height="84">
</p>

<h1 align="center">GaussInteract</h1>

<p align="center">
  <b>The agentic-AI messaging client for sovereign enterprise communication.</b><br>
  <i>A deep-tech product by <a href="https://gaussian.tech">Gaussian Technologies</a>.</i>
</p>

---

GaussInteract is a single, cross-platform [[matrix]](https://matrix.org) client engineered for the era of agentic AI. It pairs the four-platform reach of a single codebase with an audited, memory-safe core and a first-class, end-to-end-encryption-aware surface for AI agents — so an organisation can run its own communication backbone, keep its data sovereign, and put AI agents to work **without ever handing a third party the plaintext.**

It is the client half of the **Gauss** platform. Its companion, **GaussMatrix**, is a Rust-native, horizontally scalable Matrix homeserver. Together they target a structural advantage over centralised commercial messengers (Slack, Microsoft Teams, Discord) and over the heavier self-hosted suites: **data sovereignty, an audited E2EE core, a federated agentic model, a small footprint, and a permissive-where-it-counts licence posture.**

> **Status — early scaffold.** This repository currently builds on the open-source **[FluffyChat](https://github.com/krille-chan/fluffychat)** codebase, rebranded to the GaussInteract identity. It is the agreed starting point for the clean-room engineering described in `GaussInteract-SPECS.pdf`: progressively replacing the Dart data and crypto path with a shared, memory-safe **Rust core (`gauss-core`)** while keeping a single Flutter presentation layer. See the [roadmap](#-development-roadmap).

---

## Why GaussInteract

| Property | GaussInteract / GaussMatrix | Slack · Teams · Discord | Element Server Suite |
| --- | --- | --- | --- |
| **Data sovereignty** | Self-host / sovereign cloud | ✗ Centralised SaaS | ✓ Federated |
| **E2EE (default-capable)** | ✓ vodozemac (Olm/Megolm) | ✗ / partial | ✓ |
| **Federation / interop** | ✓ Matrix native | ✗ | ✓ |
| **Native agentic gateway** | ✓ E2EE-aware, audited | ✗ (cloud side-channel) | ✗ |
| **Tamper-evident agent audit** | ✓ Hash-chained | ✗ | partial |
| **Memory-safe core** | ✓ Rust + vodozemac | n/a (proprietary) | partial |
| **Licence** | AGPL client · permissive core | Proprietary | Mixed |

The advantage is **structural, not a feature**: self-hosting and end-to-end encryption are properties a centralised SaaS cannot grant a customer without becoming a different product, and an assistant that holds your plaintext cannot offer a mediated, auditable, E2EE-bound agent model.

---

## Architecture (target)

GaussInteract is specified as a **hybrid client**: one shared Rust core behind one Flutter UI.

```
┌──────────────────────────────────────────────────────────────┐
│  One Flutter UI  (Material You · accessibility-first)          │
│  · agent membership · in-band tool calls/results              │
│  · human-in-the-loop approval prompts · read-only audit view  │
└───────────────────────────────┬──────────────────────────────┘
                                 │  uniffi bindings · Dart FFI shim
┌────────────────────────────────▼─────────────────────────────┐
│  gauss-core  (shared, memory-safe Rust)                       │
│  · client–server protocol · simplified sliding sync           │
│  · local event store & timeline cache                         │
│  · vodozemac E2EE: Olm/Megolm · cross-signing · key backup    │
└───────────────────────────────────────────────────────────────┘
        Android · iOS · Web (WASM) · Linux · macOS · Windows
```

- **One presentation codebase, one shared core, four native targets.** The heavy paths (sync, state, decryption) run in Rust rather than the Dart VM, so per-platform hand-rolled crypto is excluded by construction.
- **Performance target:** `< 1.2 s` cold-start-to-interactive on mid-range mobile via simplified sliding sync and a persisted, incremental timeline cache.

The Rust core scaffold lives in [`gauss-core/`](./gauss-core) — a compilable, `#![forbid(unsafe_code)]` skeleton of the module boundaries above, already including a working human-in-the-loop approval flow and tamper-evident audit log. See [`gauss-core/README.md`](./gauss-core/README.md).

---

## Agentic AI integration

GaussInteract is the human end of a platform-wide agentic loop in which **AI agents are first-class, cross-signed Matrix identities — never privileged cloud side-channels.** The invariant: *admitting an agent to a room must never enlarge that room's trust boundary beyond the humans who admitted it.*

- **Legible agents.** An agent in a room is visually distinguished; its tool calls and results appear inline as first-class timeline items.
- **Human-in-the-loop.** High-impact actions surface a single-tap approve/deny prompt with the proposed action shown in full.
- **E2EE-bound.** An agent only ever receives the Megolm sessions a room granted it; the client makes that grant visible.
- **Auditable.** A read-only view exposes the hash-chained, tamper-evident record of every agent action — provisioned via the Model-Context-Protocol (MCP) gateway in GaussMatrix.

A first cut of this surface ships today: the **Agent console** (Settings → *AI agents*, or the `/agents` route) renders inline approval cards and the live audit view against the in-app `GaussCore.stub()`, ahead of the FFI wiring. See `lib/pages/agent/`. The server side that *produces* these events — the **`gm-agent`** MCP gateway, with capability scoping, human-in-the-loop mediation and the authoritative tamper-evident audit log — is scaffolded in [`gauss-matrix/`](./gauss-matrix). The client and server already agree on the wire shapes: `lib/utils/gauss_core/gauss_core.dart` parses the exact `m.gauss.agent.capability` content and `gm-obs` audit records the gateway emits (`GaussCapabilityGrant.fromContent`, `GaussAuditRecord.fromJson`).

---

## Enterprise surface

- **SSO / OIDC** login
- **Mobile-device-management** configuration profiles for managed fleets
- Enforced **secure key backup** and **cross-signing**
- Per-device **key-sharing controls** (inherited from the FluffyChat model)
- **White-labelling** hooks for per-tenant re-skinning
- Privacy-preserving push via **UnifiedPush** alongside conventional providers

---

## 🛣️ Development roadmap

Derived from `GaussInteract-SPECS.pdf` (§V, §VII). The platform rewrite proceeds in independently shippable phases; GaussInteract (the client) is delivered in Phases 3–4, on top of a `gauss-core` matured alongside the server work.

> **Phase 0 — Branding & scaffold _(this repository, in progress)_**
> Adopt the FluffyChat codebase, rebrand all identity/credentials to GaussInteract / Gaussian Technologies, and stand up CI. Baseline = a working Flutter + Dart-SDK Matrix client.

- [ ] **Phase 1 — `gauss-core` foundations**
  Stand up the shared Rust core (derived from the Matrix Rust SDK design): client–server protocol, local event store & timeline cache, simplified sliding sync, and **vodozemac** E2EE (Olm/Megolm, cross-signing, secure key backup). Expose it through `uniffi`.
- [ ] **Phase 2 — Core/UI integration**
  Replace FluffyChat's Dart data and crypto path with `gauss-core` via a thin Dart FFI shim, keeping one Flutter UI. Compile the core to a native library per target, and to **WebAssembly** for the web target. Hit the `< 1.2 s` cold-start objective.
- [ ] **Phase 3 — Agent surface**
  Render agent membership, in-band MCP tool calls/results, human-in-the-loop approval prompts, and the read-only tamper-evident **audit view**. Enforce the same E2EE invariant for agents as for humans. (Pairs with the server-side `gm-agent` MCP gateway.)
- [ ] **Phase 4 — Platform parity & enterprise hardening**
  Feature/UX parity on all four targets — spaces & sub-spaces, threads, VoIP via the widget surface, dynamic theming, full keyboard & screen-reader support — plus the enterprise surface: **SSO/OIDC, MDM profiles, enforced key backup/cross-signing, white-labelling, UnifiedPush.**

Cross-cutting, every phase: `forbid(unsafe_code)` outside audited crypto-adjacent crates, reproducible builds, and `cargo audit` / `cargo deny` gates in CI.

See [`GaussInteract-SPECS.pdf`](./GaussInteract-SPECS.pdf) for the full specification and [`GaussMatrix.pdf`](./GaussMatrix.pdf) for the companion baseline survey. The complete, spec-grounded phased plan — covering both the client and the GaussMatrix server end to end — lives in [`ROADMAP.md`](./ROADMAP.md).

---

## Building

> The current scaffold builds exactly like FluffyChat (Flutter + a Rust toolchain for vodozemac). The build surface will change as `gauss-core` lands (see roadmap).

1. Install [Flutter](https://flutter.dev) and [Rust](https://www.rust-lang.org/tools/install).
2. Clone the repository:
   ```bash
   git clone https://github.com/rismanmattotorang/gaussinteract.git
   cd gaussinteract
   ```
3. (Optional) Enable Firebase Cloud Messaging: `./scripts/add-firebase-messaging.sh`
4. Run in debug: `flutter run`

### Per-platform

| Target | Command |
| --- | --- |
| **Android** | `flutter build apk` |
| **iOS / iPadOS** | `./scripts/build-ios.sh` (Xcode + signing required) |
| **Web** | `./scripts/prepare-web.sh` then `flutter build web --release` |
| **Linux** | `flutter build linux --release` |
| **Windows** | `flutter build windows --release` |
| **macOS** | `flutter build macos --release` |

Web builds can be configured by serving a `config.json` (see `config.sample.json`) — only set the keys you actually need.

#### Linux dependencies
```bash
sudo apt install libjsoncpp1 libsecret-1-dev libsecret-1-0 librhash0 libwebkit2gtk-4.0-dev lld
```

### Integration tests
```bash
./scripts/prepare_integration_test.sh   # requires Docker
flutter test integration_test/mobile_test.dart
```

---

## Credits & provenance

GaussInteract is built on the open-source **[FluffyChat](https://github.com/krille-chan/fluffychat)** codebase by **Christian Kußowski** and the FluffyChat contributors, which uniquely reaches all four platforms from a single Flutter codebase. We are deeply grateful for their work — it is the foundation this project starts from.

GaussInteract adapts and re-brands that codebase and will progressively rewrite its data and crypto path as a shared Rust core, per the accompanying specification. Original FluffyChat copyright and `SPDX-FileCopyrightText` attributions are retained throughout the source tree, as required by the licence.

This project also stands on the wider Matrix ecosystem: the [Matrix protocol](https://matrix.org), [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk), [vodozemac](https://github.com/matrix-org/vodozemac), and [ruma](https://github.com/ruma/ruma). Emoji-verification translations are © The Matrix Foundation (Apache-2.0).

---

## Licence

GaussInteract is distributed under the **GNU AGPL-3.0-or-later**, inherited from the FluffyChat codebase it derives from. See [`LICENSE`](./LICENSE).

The forthcoming clean-room `gauss-core` is specified to carry a permissive licence enabling commercial derivatives; the precise licence posture of each component is a gating legal decision tracked alongside the rewrite (see `GaussInteract-SPECS.pdf` §VII). Contributions are accepted under the repository's prevailing licence — see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

<sub>GaussInteract™ and GaussMatrix™ are products of Gaussian Technologies. Built with ❤️ on FluffyChat and the Matrix ecosystem.</sub>
