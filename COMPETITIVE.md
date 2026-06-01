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
| **Declarative policy engine** (conditional rules) | ✅ | ✗ | ✗ | ✗ |
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
11. **Declarative policy engine** — ✅ **delivered this pass** (`gm-agent::policy`):
    first-match-wins allow/require-review/deny rules conditioned on tool, room
    and argument substring, versioned as `m.gauss.agent.policy` room state, that
    can only *tighten* a grant (never widen it).

### Next moat increments (queued — these widen the lead):
12. **Multi-agent orchestration** — multiple agents in a room with inter-agent
    tool mediation and per-agent attribution in the audit chain.
13. **Agent memory/context rooms** — scoped, durable agent context with the same
    E2EE and audit guarantees.

### Catch-up (table-stakes — via ROADMAP, not a differentiator):
- Phase 1–2: `gauss-core` (matrix-rust-sdk + vodozemac + uniffi); the live
  homeserver (axum ingress, federation transport, full state-res v2).
- Phase 5: enterprise surface (SSO/OIDC, MDM, white-label) + UX parity.
- Phase 6–7: packaging/observability/harness; measured vs projected numbers.

## What this pass executed

**Declarative policy engine (#11, `gm-agent::policy`)** — conditional governance
layered over the capability grant. A `PolicySet` is a first-match-wins firewall
of `allow` / `require-review` / `deny` rules, each conditioned on the tool, the
room, and/or a substring of the call's arguments, with a default effect. It is
room state (`m.gauss.agent.policy`) — visible, versioned, federated, revocable —
and round-trips through event content. The new `AgentGateway::handle_with_policy`
funnels through the same mediation core as `handle` (extracted into a shared
`mediate`), consulting the policy *after* the grant: critically, `refine()`
guarantees policy can only **tighten** — a grant-forbidden tool stays forbidden,
an `auto` tool can be forced to `review` or denied, but a `review` tool is never
widened to `auto` and a withheld tool is never admitted. Policy denials are
audited (`policy_denied`), counted (`gm_agent_actions_total{outcome="denied_policy"}`)
and replayable (new `DenyReason::Policy`).

(Earlier in the same sequence, shipped to `main`: cost/token accounting (#8),
the resolved-state cache (#10) in PR #6, and replayable agent sessions (#9) in
PR #7.)

Verified: **92 workspace tests**, `clippy -D warnings` clean, `rustfmt` clean.

## How we'll know we've won

The spec's Table III projects an aggregate **9.97/10** under enterprise
weighting, dominated by sovereignty, E2EE, and the agentic axis. We win when:
its projected numbers are **measured** on the §VIII harness (Phase 7); the
agentic moat (#1–#12) ships end-to-end over a live homeserver; and an
independent security review closes. The incumbents' positions on sovereignty,
E2EE and agentic governance are capped by their architecture — so the order is
robust to any reweighting, exactly as the spec argues.
