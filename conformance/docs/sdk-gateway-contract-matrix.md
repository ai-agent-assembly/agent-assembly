# SDK ↔ gateway registration contract matrix (AAASM-4454)

This document enumerates every **gateway deployment mode** × **SDK
registration / runtime path** combination and states, for each cell, whether an
agent can register and be governed — and which contract test (if any) proves it.

It exists because AAASM-4447 uncovered a silent drift: `aasm start --mode local`
served only REST while the SDK's native path dials **gRPC**
`AgentLifecycleService.Register` on `:50051`, so an agent started against local
mode could never register and nothing in the suite caught it. The
`conformance` integration-surface contract tests
(`conformance/tests/integration_surface_contract.rs`) now police this by reading
the repository's own source as the source of truth. This matrix is the
human-readable index of what those tests cover and — just as importantly — what
is a genuine, documented limitation rather than a silent gap.

## The two orthogonal axes

Registration and enforcement are **independent**:

- **Registration** (does the agent get into the registry?) depends only on
  whether the gateway endpoint the SDK dials serves the gRPC
  `AgentLifecycleService`. The SDK's native client
  (`aa-sdk-client/src/gateway.rs`) always connects an
  `AgentLifecycleServiceClient` to a gateway endpoint (default
  `http://127.0.0.1:50051`) and calls `.register(...)`, regardless of which
  interception layers are active.
- **Enforcement layer** (how are actions intercepted?) is the SDK runtime path —
  the `LayerSet` in `aa-runtime/src/layer.rs`: `SDK` (always available), `PROXY`
  (`aa-proxy`, Linux/macOS), `EBPF` (Linux ≥ 5.8 + BTF + loader daemon). The SDK
  "mode" (`sdk-only` / `auto` / `proxy` / `ebpf`) selects which of these layers
  it activates. It does **not** change the registration path.

So a cell's status is: *registration reachability* (set by the deployment mode)
combined with *enforcement-layer availability* (set by the SDK mode + platform).

## Gateway deployment modes (rows)

| Mode | Launches | Serves the SDK gRPC `AgentLifecycleService`? | Source of truth |
|---|---|---|---|
| `aasm start --mode local` | `aa-api-server` (`aa-api`) | **Yes** — REST `/api/v1/*` **and** gRPC on loopback `:50051` (AAASM-4447) | `aa-api/src/server.rs` (`serve_local` → `serve_lifecycle_grpc`, `.add_service(AgentLifecycleServiceServer::new(...))`) |
| `aasm start --mode remote` | `aa-gateway --listen` | **Yes** — gRPC | `aa-gateway` (`.add_service(...)`, `AgentLifecycleServiceServer`) |
| `aasm gateway start` (legacy-grpc) | `aa-gateway` (default `Mode::LegacyGrpc`, `127.0.0.1:50051`) | **Yes** — gRPC | `aa-gateway/src/main.rs` (`Mode::LegacyGrpc`), `aa-cli/src/commands/gateway/start.rs` (`DEFAULT_LISTEN = "127.0.0.1:50051"`) |
| direct `gateway_url` | *(nothing — SDK dials an existing external gateway, e.g. SaaS/enterprise)* | **Depends on that endpoint** — must serve the same gRPC service | External to this repo; the wire contract is the proto (Test 1) |

## SDK registration / runtime paths (columns)

| SDK mode | Active layers | Platform availability |
|---|---|---|
| `sdk-only` | `SDK` | All platforms (in-process hooks always available) |
| `auto` | `SDK` + `PROXY`/`EBPF` where detected | All platforms; degrades gracefully — absent layers are dropped, `SDK` always remains |
| `proxy` | `SDK` + `PROXY` | Linux / macOS (`aa-proxy` binary); **not supported on Windows** |
| `ebpf` | `SDK` + `EBPF` | **Linux only** (≥ 5.8 + BTF + `aa-ebpf-loaderd`); not supported on macOS / Windows |

## Combined matrix

Legend: **pass** = registration reachable and the layer runs on a supported
platform · **covered-by-test** = a `conformance` contract test proves the
registration surface · **not-supported** = genuine, documented limitation (not a
silent gap).

| Deployment mode ↓ / SDK mode → | `sdk-only` | `auto` | `proxy` | `ebpf` |
|---|---|---|---|---|
| `aasm start --mode local` | pass · covered-by-test¹ | pass · covered-by-test¹ | pass² · covered-by-test¹ | pass (Linux only)³ · covered-by-test¹ |
| `aasm start --mode remote` | pass · covered-by-test⁴ | pass · covered-by-test⁴ | pass² · covered-by-test⁴ | pass (Linux only)³ · covered-by-test⁴ |
| `aasm gateway start` (legacy-grpc) | pass · covered-by-test⁴ | pass · covered-by-test⁴ | pass² · covered-by-test⁴ | pass (Linux only)³ · covered-by-test⁴ |
| direct `gateway_url` | pass-if-endpoint-serves-gRPC⁵ | pass-if-endpoint-serves-gRPC⁵ | pass-if²⁵ | pass-if (Linux only)³⁵ |

### Footnotes — what backs each cell

1. **Local-mode registration surface** is proven by
   `local_mode_server_exposes_sdk_registration_surface`
   (`integration_surface_contract.rs`). It resolves the binary
   `aasm start --mode local` launches (`aa-api-server`, via `start.rs`'s
   `fn binary_name` single source of truth), maps it to the `aa-api` crate, and
   asserts that crate serves `AgentLifecycleServiceServer` (or a REST
   registration route). Passes since AAASM-4447 added the loopback gRPC listener.
2. **`proxy` enforcement is Linux/macOS only** — on Windows the `aa-proxy`
   sidecar is unavailable, so the `PROXY` layer is not-supported there.
   Registration itself is unaffected (still gRPC to the gateway).
3. **`ebpf` enforcement is Linux-only** (`aa-runtime/src/layer.rs` gates it on
   kernel ≥ 5.8 + BTF + the `aa-ebpf-loaderd` socket). On macOS / Windows the
   `EBPF` layer is **not-supported**; the agent still registers and is governed
   by the `SDK` layer. In `auto` mode the eBPF layer is simply dropped where
   unavailable — no failure.
4. **Gateway-served registration surface** (remote mode and legacy-grpc both run
   the `aa-gateway` binary) is proven by `gateway_serves_sdk_registration_service`
   (`integration_surface_contract.rs`), which asserts `aa-gateway` references
   `AgentLifecycleServiceServer` and registers it via `.add_service(...)`.
5. **direct `gateway_url` is a documented limitation of the in-repo suite.** The
   endpoint is external (a SaaS / enterprise / already-running gateway), so no
   `conformance` test can introspect its live surface. What *is* pinned is the
   **wire contract** it must satisfy: `sdk_registration_service_declares_full_lifecycle`
   asserts `proto/agent.proto`'s `AgentLifecycleService` declares the full
   `RequestChallenge / Register / Heartbeat / Deregister / ControlStream`
   lifecycle and that the tonic client/server types generate under that name. An
   external gateway that serves that generated service satisfies the contract;
   verifying a *specific* URL at runtime is out of scope for a source-level
   contract test and is left to deployment-time / e2e checks.

## Summary of genuine limitations (honest, not silent)

- **`ebpf` off Linux** and **`proxy` on Windows** are not-supported enforcement
  layers — registration still works via the always-available `SDK` layer.
- **direct `gateway_url`** cannot be surface-tested in-repo because the endpoint
  lives outside this repository; only the proto wire contract is enforced here.
- Every deployment mode this repo ships (`local`, `remote`, `gateway start`
  legacy-grpc) now serves the SDK's gRPC registration surface — the
  local-mode gap AAASM-4447 found is closed and guarded by a contract test.
