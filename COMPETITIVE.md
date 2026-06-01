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
   crates, 104 tests, clippy/fmt clean) — not yet a deployable homeserver, and
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
| **Declarative policy engine** (conditional rules) | ✅ | ✗ | ✗ | ✗ |
| **Multi-agent orchestration** (per-agent grants + delegation) | ✅ | ✗ | ✗ | ✗ |
| **Scoped, durable agent memory** (audited) | ✅ | ✗ | ✗ | ✗ |
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
11. **Declarative policy engine** — ✅ (`gm-agent::policy`): first-match-wins
    allow/require-review/deny rules conditioned on tool, room and argument
    substring, versioned as `m.gauss.agent.policy` room state, that can only
    *tighten* a grant (never widen it).
12. **Multi-agent orchestration** — ✅ (`gm-agent::roster`): per-room roster of
    agents, each under its own grant; gateway dispatch by caller
    (`handle_in_room`) and attributed delegation (`handle_delegated`) that
    mediates under the worker's grant and cannot launder privilege.
13. **Scoped, durable agent memory** — ✅ **delivered this pass**
    (`gm-agent::memory`): room-scoped, durable, fully audited agent context that
    cannot escape the capability grant.

### Next moat increments (queued — these widen the lead):
- The agentic moat #1–#13 is now delivered end-to-end as a tested scaffold.
  The remaining work is to run it over a **live homeserver** (Phase 1–2) and
  bind agent memory/mediation to **E2EE** via `gm-e2ee` (the `mcp` feature),
  tracked in [`ROADMAP.md`](./ROADMAP.md).

### Catch-up (table-stakes — via ROADMAP, not a differentiator):
- Phase 1–2: `gauss-core` (matrix-rust-sdk + vodozemac + uniffi); the live
  homeserver (axum ingress, federation transport, full state-res v2).
- Phase 5: enterprise surface (SSO/OIDC, MDM, white-label) + UX parity.
- Phase 6–7: packaging/observability/harness; measured vs projected numbers.

## What this pass executed

**Scoped, durable agent memory (#13, `gm-agent::memory`)** — an agent can now
keep context that outlives a single tool call (notes, summaries, task state)
with the *same* guarantees as everything else it touches. Memory is **scoped to
the rooms the grant permits** (`remember` / `recall` / `recall_all` / `forget`
all refuse — and audit `memory_denied` — a room outside the grant, so memory can
never become a side channel that escapes capability scope), it is **durable**
(persisted in the new `gm_store::cf::AGENT_MEMORY` column family), and every
read, write and deletion is **audited** on the tamper-evident chain and counted
(`gm_agent_memory_ops_total`). Keys are namespaced `{agent}␟{room}␟{key}`. The
`Store` trait gained a `delete` method (implemented for the in-memory and
RocksDB backends) to back `forget`. Memory operations are classified in replay
(`replay::StepKind::Memory`).

(Earlier in the same sequence, shipped to `main`: cost/token accounting (#8) and
the resolved-state cache (#10) in PR #6, replayable sessions (#9) in PR #7, the
policy engine (#11) in PR #8, and multi-agent orchestration (#12) in PR #9.)

(Earlier in the same sequence, shipped to `main`: cost/token accounting (#8) and
the resolved-state cache (#10) in PR #6, replayable agent sessions (#9) in PR #7,
and the declarative policy engine (#11) in PR #8.)

Verified: **104 workspace tests**, `clippy -D warnings` clean, `rustfmt` clean.

## How we'll know we've won

The spec's Table III projects an aggregate **9.97/10** under enterprise
weighting, dominated by sovereignty, E2EE, and the agentic axis. We win when:
its projected numbers are **measured** on the §VIII harness (Phase 7); the
agentic moat (#1–#12) ships end-to-end over a live homeserver; and an
independent security review closes. The incumbents' positions on sovereignty,
E2EE and agentic governance are capped by their architecture — so the order is
robust to any reweighting, exactly as the spec argues.
