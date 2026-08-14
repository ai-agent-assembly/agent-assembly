# ADR 0011: Cross-Process Op-Control Delivery via a NATS Subject

**Status**: Accepted
**Date**: 2026-06
**Ticket**: [AAASM-3883](https://lightning-dust-mite.atlassian.net/browse/AAASM-3883),
upgraded to durable JetStream by
[AAASM-3885](https://lightning-dust-mite.atlassian.net/browse/AAASM-3885)

> **Update (AAASM-3885).** The original design below shipped over **core NATS**
> (at-most-once). The transport has since been upgraded to **NATS JetStream**
> (durable stream + awaited publish ACK) so a halt `200` means *persisted and will
> be delivered to a gateway that (re)subscribes within retention*, not merely
> *accepted onto the bus*. See the
> [AAASM-3885 update section](#update--aaasm-3885-durable-jetstream-delivery) at the
> end; it supersedes the "Delivery semantics" consequence.

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
- **Delivery semantics.** *(Superseded by AAASM-3885 — see the update section
  below.)* Core NATS pub/sub is **at-most-once live** delivery — the same semantics
  as the in-process broadcast it extends (which also drops when no subscriber is
  connected). `flush()` makes NATS *unavailability* an honest error, but a halt
  published while a gateway is momentarily disconnected from NATS is not
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

---

## Update — AAASM-3885: Durable JetStream Delivery

**Ticket**: [AAASM-3885](https://lightning-dust-mite.atlassian.net/browse/AAASM-3885)
(found in the AAASM-3883 review). This section **supersedes the "Delivery
semantics" consequence** above; everything else (subject naming, envelope schema,
fail-mode, multi-replica, per-op locality) is unchanged.

### Problem

Core NATS is **at-most-once**: a successful publish + `flush()` only confirms bytes
reached the NATS server, not that any gateway bridge consumed the halt or that a
runtime halted. If no gateway is subscribed at that instant (restart / rollout
window, partition), the halt endpoint returns `200` while the halt reaches no
runtime — wrong for a safety kill switch, where `200` should mean "the agent was
provably told to halt."

### Decision

Carry op-control on a **durable NATS JetStream stream** instead of core pub/sub.
The subject scheme, JSON envelope, and reserved keys are unchanged — only the
transport guarantee changes.

#### Stream

- **Name**: `AA_OPCONTROL`.
- **Subjects**: `assembly.opcontrol.>` (the same wildcard the bridge consumed before).
- **Retention**: `Limits` with a bounded **`max_age` = 10 minutes**, **`File`
  storage**. Halts are tiny and time-sensitive: a bounded max-age covers a gateway
  restart / rollout window (a halt published in that gap is redelivered to the
  gateway that resubscribes within it) while keeping the stream small and preventing
  an indefinitely-replayed *stale* kill switch. File storage makes the halt survive
  a NATS server restart as well.
- **Created idempotently at boot** by every process via `create_or_update_stream`
  (`ensure_op_control_stream`). The NATS server **must have JetStream enabled**
  (`-js`) — a deployment requirement; without it, stream setup / publish ACK fails
  and the halt endpoint honestly returns `503`.

#### Publish (aa-api)

`OpControlNatsPublisher` now holds a `jetstream::Context` and **awaits the publish
ACK** (`context.publish(subject, payload).await?.await?`). The second await resolves
the JetStream server ACK, which only arrives once the message is **persisted** in
the stream. The ACK wait is bounded by a timeout so the operator surface never
hangs. The aa-api process does **not** create the stream — that is the gateway's
job — so a publish before the stream is ready is an honest failure (below).

#### Consume (gateway)

The bridge ensures the stream, then reads it via an **ephemeral JetStream consumer**
with `DeliverPolicy::All` and **explicit ack**:

- **Ephemeral, not a shared durable consumer.** A named durable consumer shared by
  all gateway replicas would *queue-group* halts to a single replica, so a runtime
  streamed from a different replica would miss its kill switch. An ephemeral
  consumer per replica gives each replica its **own** copy of every halt —
  preserving the AAASM-3883 multi-replica fan-out.
- **`DeliverPolicy::All`** replays everything still within retention when the
  consumer is (re)created. This is what delivers a halt **published while this
  gateway had no consumer attached** — the durability property of this ticket. The
  *stream's retention*, not consumer durability, is what makes the halt survive; the
  consumer just replays from the start of the retained stream on each (re)subscribe.
- Re-reading an already-applied halt after a gateway restart is **safe** because
  `Terminate` is sticky/idempotent in the runtime `OpControlStore` (and `ack`
  removes it from the consumer's pending set during steady state).

### What a halt `200` now guarantees

The halt was **durably persisted** to the `AA_OPCONTROL` JetStream stream (the
server ACK was received). Every gateway whose bridge is subscribed receives it
live, **and** any gateway that (re)subscribes **within the retention window
(10 min)** is replayed the persisted halt. An operator is never told an agent was
halted when the signal was dropped onto a bus with no consumer.

### Residual caveats

- **Not an end-to-end runtime-ack.** `200` means *durably persisted and will be
  delivered to a (re)subscribing gateway within retention*, **not** a per-runtime
  acknowledgement that a specific agent process applied the halt. A runtime that is
  disconnected for longer than the 10-minute retention, or permanently gone, is not
  tracked. A true end-to-end runtime-level ack would require a return path from the
  runtime and is out of scope.
- **Per-op vs agent-wide.** Unchanged from the base ADR: per-op `pause`/`terminate`
  remain bounded by op→agent registry locality. The durable cross-process path is
  the agent-wide / global halt, which binds to the server-side agent identity.
- **Deployment requirement.** The op-control NATS server must run with JetStream
  enabled (`-js`). This reuses the existing `AA_OPCONTROL_NATS_URL` connection — no
  new config — but a non-JetStream server now degrades op-control to honest `503`s
  rather than the previous best-effort core-NATS delivery.

### Fail-mode (unchanged invariant, JetStream-specific triggers)

- JetStream unavailable / stream not ready / **publish not ACKed** → real `503`
  (`HaltDelivery::ChannelError`), never a false `200`.
- No op-control channel configured at all → `503` (`HaltDelivery::NotConfigured`).

---

## Update — AAASM-3886: Fail Loud on a Stream-Config Mismatch

**Ticket**: [AAASM-3886](https://lightning-dust-mite.atlassian.net/browse/AAASM-3886)
(found in the AAASM-3885 review). Hardens the gateway bridge against an operator
misconfiguration; the transport guarantees above are unchanged.

### Problem

JetStream stream config is **partly immutable** (storage type, retention policy;
subjects are mutable). If an operator **pre-provisions** the `AA_OPCONTROL` stream
with an incompatible immutable config, `create_or_update_stream`
(`ensure_op_control_stream`) can never reconcile it. Before this change the bridge
reconnect loop treated that failure exactly like a transient NATS outage — a quiet
`warn!` + backoff — so it looped on stream/consumer setup **without ever
consuming**, while op-control publishes kept ACKing (`200`) against the existing
stream. Net result: an operator halt is persisted and returns `200`, yet **no
runtime is ever told to halt** — a silent non-delivery of the kill switch.

### Decision

The bridge now **classifies** its setup failures
(`OpControlNatsError::is_stream_setup_failure`): a `Stream` / `Consumer` failure
**after a successful connect** is a non-transient *fail-loud* condition (the
canonical trigger is the incompatible pre-provisioned stream; JetStream-disabled
and otherwise-unconsumable streams land here too), whereas a `Connect` failure
stays the ordinary transient reconnect path.

On the fail-loud condition the bridge:

- emits a prominent, actionable **`tracing::error!`** — it states that *op-control
  delivery is DOWN* (halts may be ACKed yet never reach a runtime) and names the
  likely cause (incompatible immutable stream config / JetStream disabled) and the
  remedy (reconcile the stream);
- records **`BridgeHealthState::StreamUnavailable`** on the new cloneable
  `OpControlBridgeHealth` handle and drives the `aa_op_control_bridge_up` gauge to
  `0`, so the condition is observable (and assertable in tests / wireable to a
  future readiness probe) rather than buried in a retry loop.

It still retries with backoff so that repairing the stream recovers delivery
automatically — but every failed attempt now *screams* instead of whispering.

### Why publish is not made honest-fail in this state

The dangerous case is structurally a **cross-process** one. The publisher lives in
the **aa-api** process and, by this ADR's design, does **not** own or validate the
stream — that is the gateway's job. When an incompatible stream exists whose
subjects still cover `assembly.opcontrol.>`, the publisher's `publish + ACK`
**succeeds** against that present-but-unconsumable stream; the publisher has no way
to know the gateway cannot consume it. (The pre-existing honest-`503` paths still
fire when the stream is *absent* or the publish is genuinely un-ACKed — see the
AAASM-3885 fail-mode above.) Making publish honest-fail here would require the
publisher to validate the gateway's consume-side stream config, which crosses the
process boundary this ADR deliberately keeps clean. The accepted contract is
therefore: **the gateway fails loud / reports unhealthy**; the publisher's `200`
in this specific misconfiguration is a known residual, surfaced by the gateway's
loud error and `StreamUnavailable` health rather than by the publish call.

### Benign per-reconnect full-window replay (note)

`DeliverPolicy::All` on an **ephemeral** consumer means the replay catch-up
described in the AAASM-3885 consume section happens on **every NATS reconnect**,
not only on a process restart: each time `bridge_once` re-creates its consumer it
replays everything still within the stream's retention window (≤ 10 min). This is
**safe and intended**, not a bug:

- `Terminate` is sticky/idempotent in the runtime `OpControlStore`, so re-reading
  an already-applied halt is a no-op;
- `Pause` / `Resume` converge by FIFO order — the stream preserves publish order,
  so replaying the retained window re-applies the last intended state;
- the bounded `max_age` keeps the replayed window small and prevents an
  indefinitely-replayed *stale* kill switch.

So a flapping NATS connection costs at most a brief, idempotent re-application of
the last few minutes of halts — never a missed or contradictory one.
