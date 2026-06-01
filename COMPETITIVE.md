<!--
SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Competitive Gap Analysis & Agentic-Superiority Plan

**Goal:** make **GaussInteract** the most advanced, superior Matrix client for
**agentic-AI** use cases, backed by **GaussMatrix**. This document assesses the
gap to every commercial competitor honestly, then sets a plan that wins where
they *structurally cannot follow*.

## TL;DR

There are two different gaps, and conflating them is the trap:

1. **Table-stakes gap (we are behind).** Slack, Microsoft Teams, Discord,
   Mattermost and the Element Server Suite are shipping products with years of
   polish. GaussMatrix is, today, a **tested architectural scaffold** (11 Rust
   crates, 72 tests, clippy/fmt clean) — not yet a deployable homeserver, and
   the client is a rebranded FluffyChat base mid-migration to a Rust core. We
   close this by **execution**, tracked in [`ROADMAP.md`](./ROADMAP.md).
2. **The moat (we leap ahead).** *Agentic AI as a first-class, governed,
   E2EE-bound, federated capability.* **No competitor has this**, and the
   centralised ones cannot get it without becoming a different product. This is
   where we invest disproportionately — and where this pass adds real code.

The strategy is **not to out-Slack Slack** on chat features, but to make
"governed AI agents in a sovereign, encrypted, federated network" a category
the incumbents can't enter.

## Honest current state

| | GaussMatrix / GaussInteract | Reality check |
|---|---|---|
| Deployable today | ❌ scaffold | competitors are GA products |
| Matrix protocol parity | ◦ typed model + state-res core | Element/Synapse is complete |
| Client app polish | ◦ FluffyChat base + agent UI | Slack/Teams are highly polished |
| **Agentic governance** | ✅ **leading** (see below) | competitors: none / bolt-on |
| Sovereignty / self-host | ✅ by design | only Element/Mattermost self-host |
| E2EE (audited, vodozemac) | ✅ by design | Teams/Slack/Discord: not by default |

## Competitor-by-competitor

### Slack · Microsoft Teams · Discord (centralised SaaS)
- **They have:** mature UX, huge integration ecosystems, voice/video at scale,
  enterprise admin, and AI assistants (Slack AI, Copilot) — but those assistants
  run in the vendor cloud **holding the plaintext**.
- **Structural ceiling:** no user-operable federation; no end-to-end encryption
  for ordinary channels; the AI cannot be E2EE-bound or operator-audited because
  the vendor *is* the trust boundary. They cannot offer a mediated, scoped,
  tamper-evidently-audited agent that the customer governs — that would mean not
  holding the plaintext, i.e. a different product.
- **Our gap to them:** chat-feature breadth and polish (catch-up via roadmap).
- **Their gap to us:** the entire agentic-governance + sovereignty + E2EE axis.

### Element Server Suite (the closest competitor)
- **They have:** a complete, federated, E2EE Matrix stack (Synapse + Element X /
  matrix-rust-sdk) — the runner-up on the spec's own evaluation (Table III).
- **Their gap to us:** **no native, E2EE-aware, audited agentic gateway**; built
  on the heavier Synapse rather than a sharded Rust core (footprint).
- **Our gap to them:** a *running, conformant homeserver* — they have one; we
  have the architecture for a better one. Pure execution.

### Mattermost (self-hosted)
- **They have:** solid self-hosted team chat, enterprise features.
- **Their gap:** no E2EE-by-default, no federation, no agentic layer.

## Capability matrix

| Capability | GaussInteract | Slack/Teams/Discord | Element ESS | Mattermost |
|---|---|---|---|---|
| Self-host / sovereign | ✅ | ❌ | ✅ | ✅ |
| Federation (Matrix) | ✅ | ❌ | ✅ | ❌ |
| E2EE, audited core | ✅ vodozemac | ✗ / partial | ✅ | ✗ |
| Agents as governed principals | ✅ | ✗ | ✗ | ✗ |
| Capability grant as room state | ✅ | ✗ | ✗ | ✗ |
| MCP tool mediation + scoped discovery | ✅ | ✗ | ✗ | ✗ |
| Human-in-the-loop approval | ✅ | ✗ | ✗ | ✗ |
| Per-agent rate + daily call budgets | ✅ | ✗ | ✗ | ✗ |
| Per-agent **token/cost budgets** (FinOps) | ✅ | ✗ | ✗ | ✗ |
| Tamper-evident audit → SIEM | ✅ | partial | partial | partial |
| **Replayable agent sessions** (incident review) | ✅ | ✗ | ✗ | ✗ |
| Mature chat UX / ecosystem | ◦ (catch-up) | ✅ | ✅ | ✅ |

## The plan — invest in the moat, execute the catch-up

### Moat (agentic AI — where we win). Status as of this pass:
1. Agents as cross-signed Matrix principals via the AS namespace — ✅ `gm-agent::appservice`
2. Capability grant as validated, federated **room state** — ✅ `gm-agent::capability`
3. MCP tool-call **mediation** (scope → rate → human-in-the-loop → reflect) — ✅ `gm-agent`
4. **MCP tool catalog + capability-scoped discovery** — ✅ **delivered this pass** (`gm-agent::catalog`)
5. **Usage governance: per-minute rate + per-day call budgets** — ✅ `gm-agent`
6. Scoped MCP **resources** (read only granted rooms) — ✅ `gm-agent::resources`
7. **Tamper-evident audit + SIEM streaming + Prometheus** — ✅ `gm-store`/`gm-obs`
8. **Cost/token accounting (agentic FinOps)** — ✅ **delivered this pass**
   (`CapabilityGrant.daily_token_budget`, day-rolling token ledger, denial +
   `gm_agent_tokens_total` metric; client mirror parses and renders it)

9. **Replayable agent sessions** — ✅ **delivered this pass** (`gm-agent::replay`):
   reconstruct exactly what an agent did from the audit chain (incident review),
   flagged with chain integrity.
10. **Resolved-state cache** (§III.D) — ✅ memoised conflict resolution in
    `gm-stateres::CachedResolver`.

### Next moat increments (queued — these widen the lead):
11. **Multi-agent orchestration** — multiple agents in a room with inter-agent
    tool mediation and per-agent attribution in the audit chain.
12. **Declarative policy engine** — grants expressed as policy (allow/deny rules,
    conditions) beyond per-tool classification; versioned as room state.
13. **Agent memory/context rooms** — scoped, durable agent context with the same
    E2EE and audit guarantees.

### Catch-up (table-stakes — via ROADMAP, not a differentiator):
- Phase 1–2: `gauss-core` (matrix-rust-sdk + vodozemac + uniffi); the live
  homeserver (axum ingress, federation transport, full state-res v2).
- Phase 5: enterprise surface (SSO/OIDC, MDM, white-label) + UX parity.
- Phase 6–7: packaging/observability/harness; measured vs projected numbers.

## What this pass executed

**Replayable agent sessions (#9, `gm-agent::replay`)** — incident review built on
the existing tamper-evident audit chain. `replay_session(agent)` /
`replay_all()` reconstruct, per agent, the ordered sequence of structured
[`StepKind`] steps (denials with reason, auto-allows, approval requests, human
approvals, executions with their token cost, resource reads, discovery,
unmanaged-identity rejections) — each tagged with its global chain sequence so
multiple agents' steps can be re-interleaved into real time. Critically, every
replay carries `chain_intact`: a reconstruction over a *tampered* chain is
flagged, not silently trusted. Convenience summaries (`executions()`,
`denials()`, `total_tokens()`) recover the FinOps and outcome figures straight
from the record. A gateway-driven test proves the classifier matches the audit
vocabulary the gateway actually emits.

(Earlier in the same sequence: cost/token accounting (#8) and the resolved-state
cache (#10) shipped in PR #6.)

Verified: **83 workspace tests**, `clippy -D warnings` clean, `rustfmt` clean.

## How we'll know we've won

The spec's Table III projects an aggregate **9.97/10** under enterprise
weighting, dominated by sovereignty, E2EE, and the agentic axis. We win when:
its projected numbers are **measured** on the §VIII harness (Phase 7); the
agentic moat (#1–#12) ships end-to-end over a live homeserver; and an
independent security review closes. The incumbents' positions on sovereignty,
E2EE and agentic governance are capped by their architecture — so the order is
robust to any reweighting, exactly as the spec argues.
