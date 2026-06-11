# Component deep-dives

This page walks the major crates one by one: what each owns, its key types, and
who it depends on. For the bird's-eye map and the dependency diagram, start with
[System architecture](system-architecture.md).

All paths link into the
[`master` tree on GitHub](https://github.com/ai-agent-assembly/agent-assembly/tree/master).

---

## `aa-gateway` — the governance brain

`aa-gateway` is the central decision-maker. It hosts the agent registry, the
policy engine, per-team budgets, the audit pipeline, approvals, anomaly
detection, and the seven gRPC services. Its module tree is large; the load-bearing
sub-modules are:

| Module | Responsibility |
|---|---|
| `registry/` | Agent registry — `AgentRecord` / `AgentRegistry` backed by `DashMap`, lineage, orphan handling, token issuance, storage bridge. |
| `policy/` | The policy engine (parse → validate → compile → evaluate). See below. |
| `budget/` | Per-agent and per-team spend tracking, pricing tables, and rollup. See below. |
| `engine/` | Decision caching, rate limiting, scope index, and the policy file watcher. |
| `service/` | gRPC service impls: `policy_service`, `audit_service`, `lifecycle_service`, `topology_service`, `approval_service`, `secrets_service`. |
| `audit.rs`, `audit_consumer.rs`, `audit_reader.rs` | The audit write path (`AuditWriter`), the NATS JetStream consumer, and the read API. |
| `sanitizer/` | The write-boundary `sanitize()` pass that drops "never store" data before persistence. |
| `invalidation/` | The push-invalidation hub that broadcasts policy/approval changes to subscribers. |
| `anomaly/`, `approval/`, `edges/`, `iam/`, `secrets/`, `ops/` | Anomaly baselines + responder, human-in-the-loop approvals, cross-team edge tracking, IAM, secret dispatch, and in-flight ops. |
| `server.rs` | Registers all seven services and serves over TCP (`serve_tcp`) or UDS (`serve_uds`). |

**Key types:** `AgentRecord`, `AgentRegistry`, `AgentStatus`
([`registry/store.rs`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/aa-gateway/src/registry/store.rs)).
**Depends on:** `aa-core`, `aa-proto`, `aa-runtime`, `aa-storage`, `aa-cache`.
**Serves:** gRPC on `127.0.0.1:50051`.

### The policy engine (`aa-gateway/src/policy/`)

The engine turns a YAML/TOML policy bundle into a decision. Entry point is
`validator::PolicyValidator::from_yaml`.

| Module | Role |
|---|---|
| `raw.rs` | Deserialise the policy bundle (raw, untyped shape). |
| `validator.rs` | Structural validation → `PolicyValidator`, `PolicyValidatorOutput`. |
| `expr.rs` | Compile rule predicates into a typed expression tree. |
| `document.rs` | The evaluated `PolicyDocument` and its scoped policies (`ToolPolicy`, `NetworkPolicy`, `BudgetPolicy`, `DataPolicy`, `SchedulePolicy`). |
| `scope.rs` | `PolicyScope` plus `OrgId` / `TeamId` — the org → team → agent → tool cascade. |
| `network.rs` | `check_network_egress` → `EgressDecision` for L2 proxy egress checks. |
| `rbac.rs` | `required_role_for`, `CallerRole`, `MutationKind` — who may mutate which scope. |
| `history/`, `context.rs`, `error.rs` | Version history, evaluation context, and the `PolicyParseError` / `ValidationError` types. |

The evaluation flow is detailed on the [Key workflows](workflows.md#policy-evaluation)
page.

### Budgets (`aa-gateway/src/budget/`)

| Module | Role |
|---|---|
| `tracker.rs` | `BudgetTracker` — per-agent / per-team / global spend, daily + monthly windows, alert thresholds at 80 % / 95 %. |
| `pricing.rs` | `PricingTable` — per-model cost tables used to price an action. |
| `rollup.rs` | `BudgetRollup` / `BudgetRow` — composes agent / team / org / subtree rows for the dashboard, SDK, and CLI. |
| `persistence.rs`, `types.rs` | Durable budget state and the `BudgetAlert` / `BudgetState` / `BudgetWindow` types. |

A request that would breach a budget downgrades from *allow* to *deny*. See
[budget tracking & rollup](workflows.md#budget-tracking--rollup).

---

## `aa-runtime` — the per-agent chokepoint

`aa-runtime` sits between an agent's interception layers and the gateway. It is
the **mandatory chokepoint** on the SDK fast-path (`SDK → UDS → runtime → gateway`).
Because the SDK is untrusted, the runtime re-scans every event before forwarding.

| Module | Role |
|---|---|
| `layer.rs` | `LayerDetector` / `LayerSet` bitflags — detects which of eBPF / proxy / SDK layers are active at startup. |
| `ipc/` | UDS server, length-prefixed `IpcFrame` codec, and the `ResponseRouter`. |
| `pipeline/` | Event aggregation: receive `IpcFrame`s, enrich, batch, fan out; the `enforcement.rs` scan/redact stage; `metrics.rs`. |
| `pipeline/enforcement.rs` | The authoritative scan/redact stage — fail-closed, oversized fields redacted whole, no `already_scanned` wire marker is honoured. |
| `gateway_client.rs` | Optional gRPC `PolicyServiceClient` forwarding `CheckAction` to the gateway. |
| `ebpf_bridge.rs` | Bridges eBPF ring-buffer events into the pipeline. |
| `l1_cache.rs`, `policy.rs` | Local policy cache + `PolicyRules` for offline / local-mode decisions. |
| `approval.rs`, `approval_sink.rs` | Approval queue and the `wait_for_approval` sink (timeout ⇒ `Decision::Pending`). |
| `invalidation_client.rs` | Subscribes to the gateway's push-invalidation stream. |
| `audit_publisher/`, `correlation/`, `health/` | NATS audit publishing, correlation IDs, and health checks. |

**Key types:** `LayerSet`, `EnforcementConfig`, `PipelineEvent`, `EnrichedEvent`.
**Depends on:** `aa-core`, `aa-proto`, `aa-ebpf`.

---

## The three interception layers

### L1 — In-process SDK: `aa-sdk-client` (+ `aa-wasm`)

`aa-sdk-client` is the **FFI-agnostic** SDK runtime client. The per-language
shims (Python / Node / Go, in their own repos) are thin wrappers over it.

| Module | Role |
|---|---|
| `config.rs` | Resolve gateway endpoint / socket path / agent identity. |
| `codec.rs` | Wire codec for `IpcFrame` framing. |
| `ipc.rs` | UDS transport to `aa-runtime`. |
| `client.rs` | Lifecycle + send-event surface. |
| `preflight.rs` | Optional, feature-gated *advisory* credential preflight using `aa-security`. |
| `error.rs` | Client error taxonomy. |

`aa-wasm` is a separate in-workspace target compiling governance components to
WebAssembly (via `wasm-bindgen`) for browser / edge agents without a native
sidecar.

> **Trust note:** the SDK is *not* a security boundary — anything it asserts is
> re-verified by `aa-runtime`. See [trust boundaries](../security/trust-boundaries.md).

### L2 — Sidecar proxy: `aa-proxy`

Intercepts outbound HTTPS via MitM with a per-host CA, enforcing network-egress
policy without code changes.

| Module | Role |
|---|---|
| `tls/` | Per-host CA (`ca.rs`), leaf-cert minting (`cert.rs`), OS keychain integration (`keychain.rs`). |
| `intercept/` | Detect, extract, and classify intercepted requests (`detect.rs`, `extract.rs`, `event.rs`), including MCP traffic (`mcp.rs`). |
| `proxy/` | The HTTP forwarding core (`http.rs`). |
| `mcp_enforce.rs` | MCP-specific enforcement. |
| `audit_jsonl.rs` | Local JSONL audit fallback. |

**Depends on:** `aa-core`, `aa-proto`, `aa-runtime`, `aa-sandbox`.

### L3 — eBPF: `aa-ebpf` (+ `aa-ebpf-common`, out-of-workspace probes)

Kernel hooks watching SSL libraries (uprobes) and process exec / file syscalls.
Linux-only, lowest bypass risk.

| Module | Role |
|---|---|
| `loader.rs`, `maps.rs`, `ringbuf.rs` | Load BPF programs, manage maps, drain the ring buffer to userspace. |
| `uprobe.rs` | Attach `SSL_write` / `SSL_read` uprobes to OpenSSL for plaintext capture. |
| `kprobe.rs`, `kprobes/`, `tracepoint.rs`, `syscall.rs` | Process exec / file syscall hooks. |
| `agent_discover.rs`, `lineage.rs`, `shell_detect.rs` | Discover governed processes, track lineage, detect shells. |
| `events.rs`, `alert.rs`, `error.rs` | Event types, alerts, error taxonomy. |

`aa-ebpf-common` holds types shared between userspace and the BPF programs.
`aa-ebpf-probes` / `aa-ebpf-programs` are the **out-of-workspace** BPF-target
crates built by `aa-ebpf/build.rs` via `aya-build`.

**Depends on:** `aa-core`, `aa-ebpf-common`.

---

## `aa-api` — the HTTP / OpenAPI read API

`aa-api` depends on `aa-gateway` **in-process** and re-exposes its read surfaces
over HTTP (Axum) with an OpenAPI schema (`utoipa`). It is the dashboard's backend.

| Module | Role |
|---|---|
| `routes/` | One module per resource: `agents`, `topology`, `policies`, `audit`, `costs`, `alerts`, `traces`, `approvals`, `edges`, `iam`, `dispatch`, `tools`, `destinations`, `logs`, `ops`, `admin`, `auth`, `capability`. |
| `openapi.rs` | The generated OpenAPI document. |
| `ws/`, `events.rs` | WebSocket streaming + server-sent events for live dashboard updates. |
| `middleware/`, `auth/` | Request middleware and authentication. |
| `trace_store.rs`, `replay.rs`, `pagination.rs` | Trace storage, replay, and paged responses. |
| `server.rs`, `config.rs` | Axum server bootstrap; default bind `127.0.0.1:7700` (`DEFAULT_ADDR`, overridable via `AA_API_ADDR`). |

**Depends on:** `aa-core`, `aa-gateway`, `aa-runtime`.

---

## `aa-cli` — the `aasm` operator front-end

`aa-cli` ships the `aasm` binary. It talks gRPC to the gateway and HTTP to the
API. Common subcommands: `aasm status`, `aasm topology`, `aasm policy`,
`aasm agent`, `aasm cost`, `aasm audit`, `aasm dashboard` (TUI). The full surface
is documented in the [CLI Reference](../cli-reference/README.md).

**Depends on:** `aa-core`, `aa-gateway`.

---

## Foundation crates

### `aa-core` — domain model + storage traits

The leaf everything builds on. Holds the Rust domain types and the storage trait
contracts (std-gated).

| Area | Contents |
|---|---|
| `identity.rs` | `AgentId` — an opaque 16-byte identity newtype. |
| `types/` | The **wire** domain types: `types::AgentId` (a `String` wire id, distinct from `identity::AgentId`), `AuditEvent`, `Credential`, `SessionCtx`, policy types. |
| `audit.rs` | `AuditEntry` — hash-chained, tamper-evident audit record. |
| `policy.rs`, `capability.rs`, `risk_tier.rs`, `dev_tool.rs` | Policy types, capability model, `RiskTier`, `GovernanceLevel`. |
| `storage/` | The six storage traits (`PolicyStore`, `AuditSink`, `CredentialStore`, `LifecycleStore`, `SessionStore`, `RateLimitCounter`), `StorageError`, and a `conformance` harness. |
| `topology/`, `evaluators.rs`, `time.rs`, `config.rs` | Topology edges + cycle detection, evaluators, time abstractions, config. |

### `aa-proto` — the wire schema

Protobuf definitions (under `proto/`, package prefix `assembly.*.v1`) compiled
with `prost` / `tonic`. Defines the seven gRPC services and all wire messages.
Every cross-process payload — gRPC and UDS alike — uses these types.

### `aa-security` — credential scanner + redaction

A small leaf crate (only `aho-corasick` + `serde`) holding `CredentialScanner`,
`CredentialFinding`, and `Redaction`. Extracted out of `aa-core` so both the
runtime enforcement stage and the SDK preflight can depend on it without pulling
in the full core.

---

## Storage & cache

### `aa-storage` — trait facade + driver registry

`aa-storage` re-exports the `aa_core::storage` traits and adds the runtime
**driver registry**: `StorageConfig`, a `Registry`, factory traits, `ConfigError`,
and `register_builtin_drivers` (memory / redis / postgres). It is the loader the
CLI's `aasm config validate` / `aasm config boot` exercise.

### Storage drivers

| Crate | Backend | Notable deps |
|---|---|---|
| `aa-storage-memory` | In-process `DashMap` / `parking_lot` | none beyond `aa-storage` + `aa-core` |
| `aa-storage-postgres` | PostgreSQL via `sqlx` | `sqlx` (postgres), `testcontainers-modules` |
| `aa-storage-redis` | Redis via `redis` + `deadpool-redis` | builds on `aa-storage-memory` for session fallback |
| `aa-storage-sqlite-buffer` | Local SQLite write-buffer | `rusqlite` (bundled) — pinned to share `libsqlite3-sys` with `sqlx-sqlite` |

Each driver implements the `aa-core` storage traits and is verified against the
shared conformance harness.

### `aa-cache` — in-process L1 cache

`L1Cache<S: CacheSource>` — a `DashMap`-backed, TTL'd, cache-aside wrapper over
any store. Concurrent misses for the same key collapse to a single backend load
(stampede protection). The gateway fronts its policy store with this cache.

---

## WASM tool sandbox: `aa-sandbox`

`aa-sandbox` hosts a `wasmtime`-based runtime that executes WASM-marked tools.
It enforces three isolation surfaces — filesystem allowlist (WASI preopened
dirs), CPU budget (wasmtime instruction fuel), and memory ceiling (`Store`
limiter) — each surfaced as a deterministic `SandboxError`. It is consumed by
`aa-proxy` via the tool-dispatch surface.

---

## Test / conformance crates

- **`conformance`** — the cross-crate trait conformance harness; every storage
  driver runs the same suite.
- **`aa-integration-tests`** — end-to-end tests that wire multiple crates
  together (kept separate to avoid dependency cycles).
