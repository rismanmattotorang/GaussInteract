<!--
SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# GaussInteract & GaussMatrix — Development Roadmap

This roadmap turns the technical specification in
[`GaussInteract-SPECS.pdf`](./GaussInteract-SPECS.pdf) into an executable,
phased plan that implements **all** of it — the client (**GaussInteract**, this
repo) and its companion homeserver (**GaussMatrix**, [`gauss-matrix/`](./gauss-matrix)).

## How this roadmap is built (engineering principles)

The plan is deliberately incremental and first-principles — *build the thing
from the bottom up, keep every step working, never ship what you haven't run*:

1. **Every phase is independently shippable and independently valuable.** The
   linear, documented dependency between phases mirrors the auditability the
   companion benchmark rewarded (spec §VII.C).
2. **Tests precede merge.** Nothing lands on `main` un-run: Rust gates on
   `cargo test`/`cargo clippy -D warnings`/`cargo fmt --check`/`cargo deny`, and
   Dart gates on `flutter analyze`/`flutter test`/`gen-l10n`. Numeric targets in
   spec Table I are **acceptance criteria**, confirmed on the measurement
   harness of §VIII — not aspirations.
3. **Minimal dependencies, audited cores.** E2EE is *only* vodozemac (§VI.B); no
   hand-rolled crypto. `#![forbid(unsafe_code)]` everywhere outside small,
   audited, documented crypto/storage crates. Reproducible builds; pinned trees.
4. **Two tracks, one protocol.** The **Client** track (AGPL-3.0) and the
   **Server** track (Apache-2.0 permissive core, §VII.A) advance in parallel and
   meet at two seams: the Matrix wire protocol and the `m.gauss.agent.*` agentic
   events. They are kept shape-compatible from day one.
5. **The north star** is spec Table III: an aggregate architectural score of
   **9.97/10**, dominated by sovereignty, memory safety, and a federated,
   E2EE-aware agentic model.

Legend: ✅ done · 🚧 in progress · ⬜ planned.

---

## Phase map

| Phase | Theme | Client (GaussInteract) | Server (GaussMatrix) | Spec |
|------|-------|------------------------|----------------------|------|
| **0** | Foundation & scaffolds | ✅ rebrand, `gauss-core` skeleton, agent UI, brand | ✅ `gm-util`/`gm-store`/`gm-obs`/`gm-agent` scaffolds | §VII |
| **1** | Real shared client core | 🚧 `gauss-core` over matrix-rust-sdk + vodozemac, uniffi, FFI shim | — | §V.B/C, §VI.B |
| **2** | Sovereign server core | — | ⬜ `gm-http/api/svc/stateres/fed/e2ee`, RocksDB single-node, CS/SS conformance | §III, §VII-1 |
| **3** | Horizontal scale | — | ⬜ `gm-shard`, distributed KV, sharded federation, media object store | §III.F, §VII-2 |
| **4** | Agentic layer, productionised | ⬜ real agent surface over live events | ⬜ live AS + MCP transport, E2EE-aware mediation, audit/SIEM | §IV, §VII-3 |
| **5** | Enterprise & platform parity | ⬜ SSO/OIDC, MDM, white-label, spaces/threads/VoIP on 4 targets | ⬜ AS provisioning console, admin | §V.D/E, §VII-4 |
| **6** | Deploy, observe, harden | ⬜ store packaging, UnifiedPush | ⬜ Deb/RPM/Nix/OCI/Helm/K8s, Prometheus/OTel/SIEM, zero-trust config | §VI, §VIII.A |
| **7** | Validation & GA | ⬜ cold-start/UX validation | ⬜ measurement harness, projected→measured, security audit | §VIII.B–D |

---

## Phase 0 — Foundation & scaffolds ✅ (current)

Establish the codebases, identity, and a compilable skeleton of every major
component so the architecture is reviewable before the heavy dependencies land.

- ✅ Adopt the FluffyChat base; rebrand all identity/credentials to
  GaussInteract / Gaussian Technologies; new brand assets; AGPL-3.0 retained.
- ✅ `gauss-core` Rust crate skeleton: `session`/`store`/`sync`/`e2ee`/`timeline`/
  `agent`/`events` modules, `#![forbid(unsafe_code)]`, working hash-chained
  audit + capability scoping, `cargo-deny`, pinned `Cargo.lock`.
- ✅ Client agent UI over an in-app stub: permissions card, inline
  `tool_call`/`tool_result` bubbles in the chat timeline, human-in-the-loop
  approval cards, read-only audit view; typed models matching the server wire
  shapes (`GaussCapabilityGrant`/`GaussAuditRecord`).
- ✅ `gauss-matrix/` workspace: `gm-util` (typed ids/errors), `gm-store`
  (pluggable `Store`, durable tamper-evident audit, in-memory + RocksDB-profile
  layout), `gm-obs` (Prometheus metrics + SIEM audit streaming), `gm-agent`
  (capability-scoped, rate-limited, human-in-the-loop, audited MCP-gateway
  mediation + scoped resources + AS provisioning), with a worked end-to-end test.
- ✅ CI: per-workspace Rust workflows; Flutter PR workflow inherited.

**Exit (met):** every component compiles and is tested; the agentic loop is
demonstrable client-side (stub) and server-side (in-memory).

---

## Phase 1 — Real shared client core 🚧 (§V.B/C, §VI.B)

Replace FluffyChat's Dart data/crypto path with the shared, memory-safe Rust
core — the "partially Rust" mandate — so sync, state and E2EE run once in Rust
across all targets.

**Workstream — `gauss-core`**
- ⬜ Wire `matrix-rust-sdk` behind the `session`/`store`/`sync` traits: real
  client–server protocol, encrypted persistent state store (SQLCipher native,
  IndexedDB on web), **simplified sliding sync** (MSC4186).
- ⬜ Wire **vodozemac** behind `e2ee`: Olm/Megolm, cross-signing, secure
  server-side key backup, key claiming; no plaintext leaves the core.
- ⬜ `uniffi` binding layer (`ffi` feature) → `staticlib`/`cdylib` per native
  target and WASM for web; generated Dart bindings.
- ⬜ Thin Dart FFI shim in the Flutter app; swap the Dart-SDK data path for
  `GaussCore.ffi()` behind the existing `GaussCore` interface.

**Acceptance:** login + sync + E2EE on Android/iOS/Web/Desktop through the Rust
core; persisted incremental timeline cache; **cold start `< 1.2 s` to
interactive on mid-range mobile** (Table I), measured. `forbid(unsafe_code)`
holds outside the vodozemac-adjacent module. **Verify:** `flutter test` +
`cargo test`; on-device cold-start measurement; crypto interop test against a
reference homeserver.

---

## Phase 2 — Sovereign server core ⬜ (§III, §VII Phase 1)

Stand up GaussMatrix's single-node profile as a **drop-in Tuwunel replacement**
with full CS/SS conformance and Conduit-family on-disk compatibility.

**Workstream — `gauss-matrix`**
- ⬜ `gm-http` — CS/SS/AS ingress over axum/hyper; `gm-api` — typed model
  extending `ruma`.
- ⬜ `gm-svc` — rooms, sync, devices, push, account data.
- ⬜ `gm-stateres` — parallelised state resolution, room versions 1–12;
  resolved-state cache; bounded worker pool; deterministic against RV vectors.
- ⬜ `gm-fed` — authenticated SS transport, backfill, **partial-state joins**.
- ⬜ `gm-e2ee` — key relay, cross-signing, key backup (no plaintext server-side).
- ⬜ `gm-store` — promote the RocksDB-profile layout to the real `rocksdb` crate
  with **Conduit-family linear on-disk compatibility**; atomic per-request
  batches; zero-copy reads where possible.
- ⬜ Migration tool: binary-swap import of a Tuwunel/conduwuit data dir;
  forbid unsafe cross-fork migration in the other direction.

**Acceptance (Table I):** CS/SS spec conformance suite green; federates with the
public network; **`< 256 MB` RSS idle** single-node; **p95 local send-to-sync
`< 150 ms`**, **federation propagation p95 `< 800 ms`**. **Verify:** Matrix
spec test suite; the §VIII load harness on fixed hardware; a real conduwuit
data-dir swap test.

---

## Phase 3 — Horizontal scale ⬜ (§III.F, §VII Phase 2)

Lift the single-process ceiling: the same binary scales linearly by room shard.

- ⬜ `gm-shard` — consistent-hash room placement; a coordination service holding
  the placement map; **online rebalancing** with working-set warming and no loss
  of availability; actor-style single-owner-per-room (no cross-shard contention).
- ⬜ Distributed-KV backend implementing the `gm-store` trait (sharded profile).
- ⬜ Sharded federation sender — outbound transactions partitioned by
  destination so one slow peer can't head-of-line-block healthy peers.
- ⬜ Media offloaded to a shared content-addressed **object store** so any
  stateless front-end can serve any blob.

**Acceptance:** linear horizontal scaling demonstrated on the harness; a shard
added/drained with zero downtime; the *same binary* collapses to the single-node
RocksDB profile when configured for one node. **Verify:** scale-out load test;
rebalance chaos test; federation head-of-line-blocking test.

---

## Phase 4 — Agentic layer, productionised ⬜ (§IV, §VII Phase 3)

Promote the scaffolded gateway and client surface to a live, E2EE-bound system
in which agents are governed Matrix principals.

**Server (`gm-agent`)**
- ⬜ Live **Application Service registration** (real `registration.yaml`,
  `as_token`/`hs_token` handshake, `/transactions`); agents minted as
  cross-signed identities in the controlled namespace.
- ⬜ Real **MCP transport** (stdio / HTTP+SSE) for inbound tool calls and
  outbound scoped resources.
- ⬜ **E2EE-aware mediation** via `gm-e2ee`: an agent device is shared only the
  Megolm sessions its rooms granted; removal revokes future sessions by normal
  key rotation.
- ⬜ Persist the hash-chained audit log in `gm-store`; promote the placeholder
  digest to a **cryptographic hash** (SHA-256/BLAKE3); stream to SIEM via `gm-obs`.

**Client (GaussInteract)**
- ⬜ Replace the in-app stub with the live agent surface: agent membership,
  in-band `m.gauss.agent.*` tool calls/results (already rendered), single-tap
  approval prompts that emit `m.gauss.agent.approval`, and the read-only audit
  view fed by the server's records.

**Acceptance:** the full loop runs over a real homeserver with E2EE on — provision
→ grant-as-room-state → scoped read → mediated/approved write → reflected events
rendered in the client → tamper-evident audit verified and streamed. **Verify:**
integration test across `gm-agent` + a live `gauss-core` client; the §IV invariant
(an agent never enlarges a room's trust boundary) asserted.

---

## Phase 5 — Enterprise & platform parity ⬜ (§V.D/E, §VII Phase 4)

Bring GaussInteract to feature/UX parity on all four targets and harden the
enterprise surface a sovereign deployment requires.

- ⬜ **SSO/OIDC** login (OpenID Connect Core); Matrix-native OIDC.
- ⬜ **MDM** configuration profiles for managed fleets; enforced secure key
  backup and cross-signing; per-device **key-sharing controls**.
- ⬜ **White-labelling** hooks (per-tenant re-skin); **UnifiedPush** alongside
  conventional providers so notifications need not route through a third party.
- ⬜ UX parity: spaces & sub-spaces, threads, VoIP via the widget surface,
  dynamic Material-You theming, full keyboard + screen-reader support — one
  Flutter codebase, four native targets.

**Acceptance:** managed enrolment works end-to-end; white-label build produces a
re-skinned client; accessibility audit passes. **Verify:** integration tests per
target; a11y automated checks; an MDM profile round-trip.

---

## Phase 6 — Deployment, observability & hardening ⬜ (§VI, §VIII.A)

Make both products operable and auditable in production.

- ⬜ **Packaging:** static binaries; Deb, RPM, Arch, Alpine, Nix; OCI container
  images; first-party **Helm charts** and Kubernetes manifests for the sharded
  profile.
- ⬜ **Observability (`gm-obs`):** Prometheus HTTP exporter; OpenTelemetry traces
  spanning front-end → shard → store; SIEM audit stream productionised.
- ⬜ **Zero-trust config:** explicit config files over ambient env for
  security-sensitive settings; isolated server signing keys; safe defaults
  (federation allow-lists, rate limits, registration controls on).
- ⬜ **Supply chain:** reproducible builds verifiable against source; `cargo
  audit`/`cargo deny` gating every merge (already in CI); SBOMs.

**Acceptance:** one-command Helm install of a sharded cluster; metrics/traces
visible; a published binary reproducibly rebuilds from source. **Verify:**
deployment smoke tests; reproducible-build diff; supply-chain CI gates.

---

## Phase 7 — Validation & GA ⬜ (§VIII.B–D)

Confirm the spec's targets and the projected comparison, then cut 1.0.

- ⬜ Run the **measurement harness** (§VIII.B): load generator over CS, a peer
  homeserver exercising federation, a collector sampling client-perceived
  latency and server resource use on identical hardware.
- ⬜ Replace every "projected" Table I/III number with a **measured** one;
  publish the comparative evaluation vs Slack/Teams/Discord/Element Server Suite.
- ⬜ Independent **security review** (threat model §II.C, crypto §VI.B); penetration
  test of the federation and agentic surfaces.
- ⬜ GA: signed releases across all packages/targets; documented upgrade path.

**Acceptance:** measured figures meet or beat Table I; aggregate architectural
position holds; security review closed. **Verify:** the reproducible harness; an
external audit report.

---

## Cross-cutting tracks (every phase)

- **Crypto:** vodozemac only; no bespoke cryptography; cross-signing + secure
  key backup end-to-end (§VI.B).
- **Memory safety:** `forbid(unsafe_code)` outside audited crypto/storage crates;
  the trusted unsafe surface stays small and reviewable (§VI.A).
- **Supply chain & CI:** `cargo test`/`clippy -D warnings`/`fmt`/`deny`/`audit`;
  `flutter analyze`/`test`/`gen-l10n`; pinned, reproducible builds (§VI.C).
- **Protocol conformance:** continuously validated against the Matrix spec test
  suite so GaussMatrix federates with the public network throughout the rewrite.
- **Docs & licensing:** per-component licence posture reviewed (AGPL client,
  permissive server core, §VII.A) — a gating legal task tracked, not assumed.

## Requirement-coverage matrix (spec → phase)

| Spec requirement | Phase |
|---|---|
| Matrix ≥ v1.11, room versions → 12; CS/SS/AS/push | 2 |
| Single-node `< 256 MB` idle; p95 send `< 150 ms`; fed `< 800 ms` | 2, 7 |
| Linear horizontal scaling by room shard; single-node preserved | 3 |
| Parallel state resolution; partial-state joins | 2, 3 |
| Pluggable storage; RocksDB single-node + distributed KV | 2, 3 |
| vodozemac E2EE; cross-signing; key backup; no plaintext server-side | 1 (client), 2/4 (server) |
| Agents as cross-signed AS identities; MCP gateway | 4 |
| Capability scoping (auto/review/forbidden); human-in-the-loop | 0 (model), 4 (live) |
| Tamper-evident hash-chained audit; SIEM emission | 0 (model), 4/6 (live) |
| One Flutter UI / one Rust core / four native targets | 1, 5 |
| Client cold start `< 1.2 s`; simplified sliding sync | 1 |
| Spaces, threads, VoIP, widgets, SSO/OIDC, MDM, white-label, UnifiedPush | 5 |
| Memory safety; reproducible builds; cargo deny/audit | all (cross-cutting) |
| Packaging, Helm/K8s, Prometheus/OTel | 6 |
| Measurement harness; projected → measured; comparison | 7 |

---

*This roadmap is a living document; phases are independently shippable and may
overlap across the two tracks. See [`gauss-matrix/README.md`](./gauss-matrix/README.md)
for server-crate status and the top-level [`README.md`](./README.md) for the
product overview.*
