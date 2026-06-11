# System architecture

This page is the big-picture map of `agent-assembly`: the workspace crates, how
the three interception layers feed one central **gateway**, and which transport
each component speaks. Read it first; the [component deep-dives](components.md),
[key workflows](workflows.md), and [data flows](data-flows.md) pages zoom into
each piece.

For the trust-boundary view of the same system — what each layer is trusted to
do and where the authoritative checks live — see the
[Security Model](../security/README.md).

## The one-sentence model

> Agents act; the three interception layers observe those actions and forward
> them to the gateway; the gateway evaluates **policy**, tracks **budgets**, and
> writes an **audit** record before returning *allow* or *deny*.

The gateway is the single decision-maker. The interception layers differ only in
*where* they sit and *how much* they can bypass — they all converge on the same
protobuf wire format defined in `aa-proto` and the same `PolicyService` RPC.

## Workspace at a glance

The Cargo workspace declares **28 member crates** in the top-level
[`Cargo.toml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/Cargo.toml).
They group into a handful of architectural roles:

| Role | Crates | What they own |
|---|---|---|
| **Foundation** | `aa-core`, `aa-proto`, `aa-security` | Domain types (`AgentId`, `AuditEntry`, policy types), the gRPC/protobuf wire schema, and the credential scanner / redaction primitives. |
| **Storage** | `aa-storage`, `aa-storage-memory`, `aa-storage-postgres`, `aa-storage-redis`, `aa-storage-sqlite-buffer`, `aa-cache` | Storage trait facade + pluggable drivers, plus the in-process L1 cache. |
| **Runtime / interception** | `aa-runtime`, `aa-ebpf`, `aa-ebpf-common`, `aa-proxy`, `aa-sdk-client`, `aa-wasm`, `aa-sandbox` | The per-agent runtime chokepoint, the kernel/proxy/SDK interception layers, the FFI-agnostic SDK client, and the WASM tool sandbox. |
| **Control plane** | `aa-gateway`, `aa-api`, `aa-cli` | The governance gateway (gRPC), the HTTP/OpenAPI read API, and the `aasm` operator CLI. |
| **Dev-tool adapters** | `aa-devtool`, `aa-devtool-claude-code`, `aa-devtool-codex`, `aa-devtool-copilot`, `aa-devtool-windsurf`, `aa-devtool-saas`, plus the `examples/aa-devtool-sample-myeditor` sample | Adapters that wire common AI dev tools into the governance fabric. |
| **Test / conformance** | `conformance`, `aa-integration-tests` | The cross-crate trait conformance harness and the end-to-end integration suite. |

Two further eBPF crates — `aa-ebpf-probes` and `aa-ebpf-programs` — live
alongside the workspace but are intentionally **out of workspace**: they compile
for the `bpfel-unknown-none` BPF target and are built by `aa-ebpf`'s `build.rs`
via `aya-build`, so they cannot be selected with `cargo -p`.

The per-language SDK *shims* (Python / Node / Go) do **not** live in this
monorepo. They wrap `aa-sdk-client` and consume it via a pinned git SHA from the
sibling `python-sdk` / `node-sdk` / `go-sdk` repositories.

## Crate / component map

The diagram highlights the core architectural crates; storage drivers,
dev-tool adapters, and test harnesses are folded into summary nodes for clarity.
Edges follow real `path` dependencies in each crate's `Cargo.toml`.

```mermaid
graph TD
    classDef foundation fill:#e8f1ff,stroke:#5b8def
    classDef storage fill:#eef6ff,stroke:#5b8def
    classDef ebpf fill:#fdecea,stroke:#d75748
    classDef ffi fill:#eaf6ee,stroke:#3aa55b
    classDef control fill:#fff3d6,stroke:#c98a00
    classDef outOfWorkspace fill:#fdecea,stroke:#d75748,stroke-dasharray: 5 3

    %% Foundation
    aa_proto[aa-proto<br/><i>wire schema</i>]:::foundation
    aa_core[aa-core<br/><i>domain types</i>]:::foundation
    aa_security[aa-security<br/><i>scanner / redaction</i>]:::foundation

    %% Storage
    aa_storage[aa-storage<br/><i>trait facade</i>]:::storage
    aa_cache[aa-cache<br/><i>L1 cache</i>]:::storage
    storage_drivers["aa-storage-{memory,postgres,<br/>redis,sqlite-buffer}"]:::storage

    %% Interception / runtime
    aa_runtime[aa-runtime<br/><i>per-agent chokepoint</i>]:::ffi
    aa_sdk_client[aa-sdk-client<br/><i>FFI-agnostic client</i>]:::ffi
    aa_wasm[aa-wasm]:::ffi
    aa_sandbox[aa-sandbox<br/><i>WASI tool sandbox</i>]:::ffi
    aa_proxy[aa-proxy<br/><i>L2 sidecar</i>]:::ebpf
    aa_ebpf[aa-ebpf<br/><i>L3 kernel</i>]:::ebpf
    aa_ebpf_common[aa-ebpf-common]:::ebpf
    aa_probes["aa-ebpf-probes /<br/>aa-ebpf-programs<br/><i>out-of-workspace BPF</i>"]:::outOfWorkspace

    %% Control plane
    aa_gateway[aa-gateway<br/><i>gRPC 50051</i>]:::control
    aa_api[aa-api<br/><i>HTTP / OpenAPI</i>]:::control
    aa_cli[aa-cli<br/><i>aasm</i>]:::control

    aa_core --> aa_security
    aa_storage --> aa_core
    aa_cache --> aa_core
    storage_drivers --> aa_storage

    aa_runtime --> aa_core
    aa_runtime --> aa_proto
    aa_runtime --> aa_ebpf
    aa_sdk_client --> aa_proto
    aa_sdk_client -. preflight .-> aa_security
    aa_wasm --> aa_core

    aa_ebpf --> aa_core
    aa_ebpf --> aa_ebpf_common
    aa_probes --> aa_ebpf_common

    aa_proxy --> aa_core
    aa_proxy --> aa_proto
    aa_proxy --> aa_runtime
    aa_proxy --> aa_sandbox

    aa_gateway --> aa_core
    aa_gateway --> aa_proto
    aa_gateway --> aa_runtime
    aa_gateway --> aa_storage
    aa_gateway --> aa_cache
    aa_api --> aa_core
    aa_api --> aa_gateway
    aa_api --> aa_runtime
    aa_cli --> aa_core
    aa_cli --> aa_gateway
```

`aa-core` and `aa-proto` are the two foundation leaves everything else builds on:
`aa-core` holds the Rust domain model and the storage traits, `aa-proto` holds
the protobuf schema that crosses every process boundary.

## How the layers, gateway, API, runtime, and storage fit together

```mermaid
flowchart TB
    subgraph agent_host["Agent host"]
        Agent[AI agent process]
        subgraph layers["Three interception layers"]
            L1["L1 — In-process SDK<br/>(aa-sdk-client shims, aa-wasm)"]
            L2["L2 — Sidecar proxy<br/>(aa-proxy)"]
            L3["L3 — eBPF<br/>(aa-ebpf, kernel)"]
        end
        RT["aa-runtime<br/>per-agent chokepoint"]
    end

    subgraph control["Control plane"]
        GW["aa-gateway<br/>registry · policy · budget · audit"]
        API["aa-api<br/>HTTP / OpenAPI read API"]
    end

    subgraph persistence["Storage"]
        STORE[("aa-storage drivers<br/>memory / postgres / redis / sqlite-buffer")]
    end

    Dash["Dashboard / operators"]
    CLI["aasm CLI"]

    Agent --> L1 & L2 & L3
    L1 -->|UDS IpcFrame| RT
    L2 -->|forward| RT
    L3 -->|ring buffer| RT
    RT -->|gRPC PolicyService.CheckAction<br/>:50051| GW
    GW --> STORE
    API --> GW
    Dash -->|HTTP / WS| API
    CLI -->|gRPC| GW
```

- The **interception layers** are deployment-independent: a deployment can run
  any subset (SDK only, SDK + proxy, all three). Each layer turns an agent
  action into an event in the `aa-proto` schema.
- **`aa-runtime`** is the per-agent chokepoint. Because the SDK is untrusted, the
  runtime re-scans every event (the enforcement stage in
  `aa-runtime/src/pipeline/enforcement.rs`) before forwarding it.
- **`aa-gateway`** is the brain. It hosts the agent registry, the policy engine,
  per-team budgets, and the audit pipeline, and it serves gRPC on `:50051`.
- **`aa-api`** depends on `aa-gateway` in-process and re-exposes its read surfaces
  over HTTP with an OpenAPI schema (via `utoipa`) for the dashboard and tooling.
- **Storage** is a pluggable trait facade (`aa-storage`) with swappable drivers,
  fronted by an in-process L1 cache (`aa-cache`).

## Transport topology

Every cross-process message rides one of three transports. All gRPC and
Unix-socket payloads share the `aa-proto` schema.

```mermaid
flowchart LR
    SDK["SDK shim<br/>(aa-sdk-client)"] -- "UDS IpcFrame" --> RT["aa-runtime"]
    RT -- "gRPC :50051" --> GW["aa-gateway"]
    PROXY["aa-proxy"] -- "gRPC :50051" --> GW
    EBPF["aa-ebpf"] -- "ring buffer → events" --> RT
    GW -- "in-process dep" --> API["aa-api"]
    DASH["Dashboard"] -- "HTTP / OpenAPI :7700" --> API
    CLI["aasm CLI"] -- "gRPC :50051" --> GW
```

| Transport | Default endpoint | Carries | Who speaks it |
|---|---|---|---|
| **gRPC** | `127.0.0.1:50051` (TCP) or UDS | `PolicyService`, `AuditService`, `AgentLifecycleService`, `TopologyService`, `ApprovalService`, `SecretsService`, `InvalidationService` | `aa-runtime`, `aa-proxy`, `aa-cli` → `aa-gateway` |
| **HTTP / OpenAPI** | `127.0.0.1:7700` (`AA_API_ADDR`) | Read APIs: registry, topology, audit, costs, alerts, traces | Dashboard / tooling → `aa-api` |
| **Unix domain socket (UDS)** | per-agent socket | `IpcFrame` events from the in-process SDK | SDK shim → `aa-runtime` |

The seven gRPC services are registered together in
[`aa-gateway/src/server.rs`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/aa-gateway/src/server.rs);
the gateway can serve them over either TCP (`serve_tcp`) or a Unix socket
(`serve_uds`). The default gRPC listen address is `127.0.0.1:50051`; the HTTP API
default bind is `127.0.0.1:7700` (constant `DEFAULT_ADDR` in
[`aa-api/src/config.rs`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/aa-api/src/config.rs),
overridable via `AA_API_ADDR`).

## Where to go next

- **[Component deep-dives](components.md)** — per-crate responsibilities, key
  types, and dependencies.
- **[Key workflows](workflows.md)** — policy evaluation, agent registration,
  budget rollup, and the enforcement path as sequence diagrams.
- **[Data flows](data-flows.md)** — how an intercepted event travels from a layer
  through the gateway to the audit log and storage.
- **[Security Model](../security/README.md)** — the same system viewed through
  trust boundaries and defense-in-depth.
