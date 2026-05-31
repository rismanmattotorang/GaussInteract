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

## Status — `gm-agent` + `gm-store` first

The workspace is being built crate-by-crate. We started with **`gm-agent`**,
the agentic gateway (§IV) — the platform's most distinctive contribution and
the *producer* of the `m.gauss.agent.*` events the GaussInteract client already
renders inline — backed by **`gm-store`**, the pluggable storage abstraction
(§III.C), so the gateway's audit trail is durable from day one.

```
gauss-matrix/
├── Cargo.toml            # workspace (members added as crates land)
├── rust-toolchain.toml
├── deny.toml             # cargo-deny policy (spec §VI.C)
└── crates/
    ├── gm-agent/         # the agentic AI gateway
    │   └── src/
    │       ├── lib.rs        # AgentGateway: mediation pipeline + resource access
    │       ├── capability.rs # CapabilityGrant + classify (auto/review/forbidden)
    │       ├── events.rs     # m.gauss.agent.* events the gateway reflects
    │       ├── mcp.rs        # MCP tool-call ingress + ToolExecutor
    │       ├── resources.rs  # scoped room context as MCP resources (inbound)
    │       └── clock.rs      # Clock abstraction for rate limiting
    ├── gm-store/         # pluggable storage abstraction (§III.C)
    │   └── src/
    │       ├── lib.rs        # Store trait + per-domain column families (cf::*)
    │       ├── memory.rs     # in-memory backend (RocksDB/distributed-KV later)
    │       └── audit.rs      # durable, tamper-evident audit log (§IV.D)
    └── gm-util/          # shared primitives (§III.B)
        └── src/
            ├── ids.rs        # validated UserId / RoomId / AgentId newtypes
            └── error.rs      # the common GmError
```

Agent and room identifiers are validated through `gm-util` at the system's edge
— `ToolCall::parse` rejects a malformed id before a call can even be constructed
— so `CapabilityGrant` and the gateway work entirely in terms of typed
`AgentId` / `RoomId`, and mediation never has to defend against bad identifiers.

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

Every branch appends to a **durable, hash-chained, tamper-evident audit log**
(persisted via `gm-store` in its own `audit_log` column family) whose `verify()`
detects retroactive edits (§IV.D), and the reflected events carry exactly the
content the client reads (`call_id`, `tool`, `args_summary`, `ok`, `summary`) —
so server and client already agree on the wire shape.

The gateway is bidirectional. Inbound (`resources.rs`), it exposes **scoped**
room context to an agent as MCP resources: `list_resources` returns one
timeline resource per granted room and no others, and `read_resource` enforces
the room scope — a request for a room outside the grant is denied (and audited)
before any context is read. An agent can read exactly what it was granted, the
same trust-boundary invariant as the write path.

## Build & test

```bash
cd gauss-matrix
cargo test          # std-only; no network/registry access required
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Remaining crates (spec §III.B)

`gm-http` · `gm-api` · `gm-svc` · `gm-stateres` · `gm-fed` · `gm-e2ee` ·
`gm-shard` · `gm-obs` — added as implemented (`gm-agent`, `gm-store` and
`gm-util` are in place). The remaining live `gm-agent` wiring (Application
Service registration for cross-signed agent identities, the MCP transport, and
E2EE-aware mediation via `gm-e2ee`) lands behind the `mcp` feature; the
RocksDB / distributed-KV `gm-store` backends land behind their own features.
