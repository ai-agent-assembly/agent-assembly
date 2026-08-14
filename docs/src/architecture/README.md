# Architecture

This chapter is the engineering map of `agent-assembly` — the open-source core
that governs AI agents by intercepting their actions at three independent layers
and routing the governed actions through one central **gateway**.

It is written for contributors and integrators who want to understand *how the
system is built*, not just how to operate it. For the system-level overview,
see [System architecture](system-architecture.md); for the
security rationale, see the [Security Model](../security/overview.md).

## Pages in this chapter

- **[System architecture](system-architecture.md)** — the big picture: the 28
  workspace crates, the three interception layers, the gateway / API / runtime /
  storage split, and the gRPC / HTTP / UDS transport topology, with a mermaid
  system diagram.
- **[Component deep-dives](components.md)** — a per-crate tour of responsibilities,
  key types, and dependencies: gateway, policy engine, budgets, runtime, the
  three interception crates, API, CLI, foundation crates, storage, and cache.
- **[Key workflows](workflows.md)** — policy evaluation, agent registration,
  budget tracking & rollup, and the interception/enforcement path, each as a
  mermaid sequence or flow diagram grounded in the real code path.
- **[Data flows](data-flows.md)** — how an intercepted event travels from a layer
  through the gateway, the policy engine, and the write-boundary sanitizer into
  durable, tamper-evident storage.
- **[Building & contributing](building.md)** — build, test, and lint basics for
  working on the workspace.

## Execution isolation

`aasm run --isolation` (Epic AAASM-5702) confines an agent's whole native
process tree at the OS level, on hosts where a backend exists for it. It is
not a new architectural layer — it occupies four elements of the canonical
[ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md)
governance model (E2 Managed Execution Checkpoints, E4 Platform-Specific
Host-Level Interception Adapters, E5 Credential/Capability Boundary, E6
Evidence & Protection-State Pipeline). See
[ADR 0035](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)
for the full decision record and the
[Execution isolation](../security/execution-isolation.md) security page for
the operator-facing mental model, threat boundary, and platform/backend
support matrix.

## The model in one diagram

```mermaid
flowchart LR
    Agent[AI agent] --> Layers["3 interception layers<br/>SDK · proxy · eBPF"]
    Layers --> RT["aa-runtime<br/>chokepoint"]
    RT -->|gRPC :50051| GW["aa-gateway<br/>policy · budget · audit"]
    GW --> Store[("storage")]
    GW --> API["aa-api<br/>HTTP :7700"]
    API --> Dash["dashboard / tooling"]
```

Start with [System architecture](system-architecture.md).
