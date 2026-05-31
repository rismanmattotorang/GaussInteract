<!--
SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
SPDX-License-Identifier: Apache-2.0
-->

# GaussMatrix

A sovereign, horizontally scalable, **Rust-native Matrix homeserver**
(GaussInteract-SPECS §III) — the server half of the Gauss platform, companion
to the [GaussInteract](../README.md) client. It adopts the architecture and
on-disk/protocol compatibility of the Tuwunel/Conduit lineage and re-implements
it as an eleven-crate workspace with a pluggable store, a parallel
state-resolution engine, partial-state federation, a room-sharded
horizontal-scaling model — and, most distinctively, a first-class **agentic AI
gateway**.

> **Licence.** Unlike the AGPL-3.0 GaussInteract client, the server core is
> **Apache-2.0** — matching its Tuwunel lineage and the spec's intent (§VII) of
> a permissive core enabling commercial derivatives.

## Status — `gm-agent` first

The workspace is being built crate-by-crate. We started with **`gm-agent`**,
the agentic gateway (§IV), because it is the platform's most distinctive
contribution and the *producer* of the `m.gauss.agent.*` events the
GaussInteract client already renders inline (timeline bubbles, the approval
console, and the audit view).

```
gauss-matrix/
├── Cargo.toml            # workspace (members added as crates land)
├── rust-toolchain.toml
├── deny.toml             # cargo-deny policy (spec §VI.C)
└── crates/
    └── gm-agent/         # the agentic AI gateway
        └── src/
            ├── lib.rs        # AgentGateway: the mediation pipeline
            ├── capability.rs # CapabilityGrant + classify (auto/review/forbidden)
            ├── events.rs     # m.gauss.agent.* events the gateway reflects
            ├── audit.rs      # authoritative tamper-evident audit log
            └── mcp.rs        # MCP tool-call ingress + ToolExecutor
```

### What `gm-agent` already does

The gateway is the **sole channel** through which an agent acts. An inbound MCP
tool call runs through one mediation pipeline:

1. **Capability check (§IV.C).** `CapabilityGrant::classify(tool, room)` →
   `auto` / `review` / `forbidden`, least-privilege (deny-all by default).
2. **Forbidden** → refused *before* anything enters the room; still audited.
3. **Auto** → reflect `m.gauss.agent.tool_call`, execute, reflect
   `m.gauss.agent.tool_result`, audit each step.
4. **Review** → reflect the `tool_call` and queue a human-in-the-loop approval;
   on `resolve(approve)` execute + reflect the result, on `resolve(deny)` emit a
   denial receipt. Either way it's audited.

Every branch appends to a **hash-chained, tamper-evident audit log** whose
`verify()` detects retroactive edits (§IV.D), and the reflected events carry
exactly the content the client reads (`call_id`, `tool`, `args_summary`, `ok`,
`summary`) — so server and client already agree on the wire shape.

## Build & test

```bash
cd gauss-matrix
cargo test          # std-only; no network/registry access required
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Remaining crates (spec §III.B)

`gm-http` · `gm-api` · `gm-svc` · `gm-stateres` · `gm-fed` · `gm-e2ee` ·
`gm-store` · `gm-shard` · `gm-obs` · `gm-util` — added as implemented. The live
`gm-agent` wiring (Application Service registration for cross-signed agent
identities, the MCP transport, E2EE-aware mediation via `gm-e2ee`, and audit
persistence in `gm-store`) lands behind the `mcp` feature.
