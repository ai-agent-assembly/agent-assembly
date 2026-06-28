# ADR 0011: Cross-Process Op-Control Delivery via a NATS Subject

**Status**: Proposed
**Date**: 2026-06
**Ticket**: [AAASM-3883](https://lightning-dust-mite.atlassian.net/browse/AAASM-3883)

---

## Context

The operator **kill switch** for a running agent is delivered end-to-end by three
pieces that already exist and are component-tested:

- **Emission** ([AAASM-3881](https://lightning-dust-mite.atlassian.net/browse/AAASM-3881)) —
  the HTTP operator endpoints `POST /api/v1/ops/{id}/halt-agent` and
  `POST /api/v1/ops/global/halt` record a halt on `AppState.ops_registry` and call
  `OpsRegistry::halt_agent` / `halt_global`, which publish an op-control signal under
  a **reserved** op-id (`agent:{agent_id}` for an agent-wide halt, `"*"` for a
  fleet-wide halt).
- **Transport** — `OpControlPublisher`, a single `tokio::sync::broadcast` channel.
- **Consumption** ([AAASM-3873](https://lightning-dust-mite.atlassian.net/browse/AAASM-3873)) —
  the gRPC `PolicyService.op_control_stream` RPC subscribes to that broadcast and
  forwards each matching envelope to the runtime, which records it in
  `OpControlStore` and fast-fails / blocks the agent's next per-tool check.

### The topology gap

`OpControlPublisher` is an **in-process** broadcast. In the shipped product the two
halves run in **separate processes** (verified definitively under AAASM-3883):

| Half | Process | Detail |
| --- | --- | --- |
| HTTP halt endpoints (`AppState.ops_registry`) | **aa-api-server** | `aasm start --mode local` launches this |
| gRPC `PolicyService.op_control_stream` | **aa-gateway** | the only process runtimes subscribe to (`aa-runtime/src/op_control.rs`) |

`op_control_stream` reads **only** from the gateway's in-process `ops_publisher`.
There is no shared cross-process bus for op-control today — NATS carries **audit
only** (`assembly.audit.>`), and the L1 invalidation channel does not carry
op-control.

A previous attempt ([PR #1308](https://github.com/ai-agent-assembly/agent-assembly/pull/1308),
reverted) injected one in-process `OpControlPublisher` into both halves. That works
only inside a single process; across the real two-process split, the aa-api publisher
broadcasts to a channel **with no subscriber**, so the HTTP halt would return `200`
while silently dropping the halt — strictly worse than the honest `503` for a kill
switch. The wiring was reverted and the ticket moved back for design.

## Decision

Introduce a **shared NATS subject** that carries op-control signals between the two
processes, mirroring the existing NATS audit subsystem rather than inventing a
parallel one.

### Subject naming

Mirrors the audit convention `assembly.audit.<tenant>.<agent>`:

- Agent-wide / per-op halt → `assembly.opcontrol.<tenant>.<agent>`
  - `<tenant>` = the agent's `org_id`, falling back to `team_id`, then `default`.
  - `<agent>` = the agent id (subject-token-sanitized; non-`[A-Za-z0-9_-]` → `_`).
- Fleet-wide halt → `assembly.opcontrol.global`.

The gateway subscribes with the wildcard `assembly.opcontrol.>`, so subject tokens
are for routing/observability only; the gateway filters per subscriber exactly as it
does for the in-process broadcast.

### Message schema

A small JSON envelope, reusing the existing op-control reserved-key semantics so
producer and consumer can never drift:

```json
{ "org_id": "...", "team_id": "...", "agent_id": "...",
  "op_id": "agent:{id}" | "*" | "{trace}:{span}",
  "signal": 1, "global": false }
```

- `op_id` carries the same reserved key the in-process path uses
  (`aa_runtime::op_control::agent_halt_op_id` / `GLOBAL_HALT_OP_ID`).
- `signal` is the wire `OpControlSignal` discriminant (`Pause` / `Resume` / `Terminate`).
- `global` marks a fleet-wide halt so the gateway forwards it to every subscriber.

### Publish side (aa-api)

`OpsRegistry` gains an optional `OpControlNatsPublisher`. The halt handlers call
`halt_agent_delivery` / `halt_global_delivery`, which:

1. publish the envelope to NATS **and `flush()`** (forcing the write to the server)
   when a NATS publisher is attached, then
2. fall back to the in-process publisher only when **no** NATS publisher is
   configured (single-process / co-located mode).

### Consume side (gateway)

The gateway boot (`serve_tcp` / `serve_uds`) always constructs the in-process
`OpControlPublisher` and attaches it to `PolicyServiceImpl` via `with_ops_publisher`
— this alone un-inerts `op_control_stream` (it no longer returns `Unavailable`). When
NATS is configured it additionally spawns a **bridge** task that subscribes to
`assembly.opcontrol.>` and forwards every received envelope into that same in-process
broadcast (`publish` for per-agent, `publish_global_halt` for global). The runtime
filtering, reserved-key matching, and sticky-terminate semantics are unchanged.

### Configuration

Reuses the existing NATS deployment. Activated by `AA_OPCONTROL_NATS_URL`
(`OpControlNatsConfig::from_env`), exactly mirroring the audit consumer's
`AA_AUDIT_NATS_URL` env activation. When unset, both processes keep their existing
in-process behavior — no new mandatory config, no behavior change for local mode.

### Fail-mode (never a silent-drop 200)

- NATS configured, publish/flush **fails** → the halt endpoint returns a real `503`
  (`HaltDelivery::ChannelError`), never a false `200`.
- No op-control channel configured at all → `503` (`HaltDelivery::NotConfigured`) —
  the pre-existing honest behavior.
- This restores the kill switch's core invariant: an operator is never told an agent
  was halted when it was not.

## Consequences

- **Multi-replica.** Any aa-api replica can publish; every gateway replica's bridge
  subscribes, so a horizontally-scaled gateway delivers the halt to whichever replica
  a given runtime is streamed to. (A runtime is connected to exactly one gateway
  replica's `op_control_stream`; the NATS fan-out reaches all replicas.)
- **Co-located / local mode coexistence.** With no `AA_OPCONTROL_NATS_URL`, a
  single-process deployment uses the in-process publisher unchanged. The two paths
  are mutually exclusive per process (NATS preferred when configured), so a halt is
  never double-delivered from one publisher.
- **Delivery semantics.** Core NATS pub/sub is **at-most-once live** delivery — the
  same semantics as the in-process broadcast it extends (which also drops when no
  subscriber is connected). `flush()` makes NATS *unavailability* an honest error,
  but a halt published while a gateway is momentarily disconnected from NATS is not
  redelivered. A JetStream-durable op-control stream is a deliberate **future**
  enhancement, out of scope for this additive-wiring fix.
- **No new dependency / no new feature flag.** `async-nats` is already a
  non-optional dependency via `aa-runtime` (the audit publisher), so the op-control
  module is always compiled and activated purely by runtime config — matching the
  always-on runtime audit publisher rather than the postgres-coupled, feature-gated
  audit *consumer*.
- **Per-op cross-process delivery is bounded by registry locality.** The op→agent
  map populated by `check_action` lives in the gateway process; the robust operator
  kill path is the agent-wide / global halt, which binds to the server-side agent
  identity and is what this ADR makes cross-process. Per-op `pause`/`terminate`
  remain same-process for now.
