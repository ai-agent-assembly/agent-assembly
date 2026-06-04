# AAASM-2378 Verification — AAASM-2386 (Approval-result push reuse)

> **Status**: All Story AAASM-2378 acceptance criteria are met. The push
> channel built in AAASM-2377 now also carries human approval verdicts, so an
> agent blocked on an approval subscribes for an `ApprovalResolved` event
> instead of polling. Implementation landed under AAASM-2385 (PR #903); this
> Subtask adds the timeout end-to-end test and this report. **No Bug Subtask
> opened.**

## Subtask roll-up

| Subtask | Title | Status | PR |
|---|---|---|---|
| AAASM-2385 | Wire ApprovalResolved push event + WaitForApproval future | Done | [#903](https://github.com/AI-agent-assembly/agent-assembly/pull/903) |
| AAASM-2386 | Verify ApprovalResolved push event acceptance criteria | in this report | — |

## Walkthrough vs AAASM-2378 acceptance criteria

### ✅ Proto adds `ApprovalResolved { request_id, decision }` to the `InvalidationEvent` oneof

Already shipped by the previous Story (AAASM-2377): `proto/invalidation.proto`
defines the `ApprovalResolved` message (`request_id: string`, `decision: Decision`),
the `Decision` enum (`DECISION_UNSPECIFIED / APPROVED / DENIED / PENDING`), and
the `approval_resolved` arm of the `InvalidationEvent` `oneof payload`.

Evidence: [`proto/invalidation.proto:72-111`](../proto/invalidation.proto)
(generated as `aa_proto::assembly::gateway::v1::{ApprovalResolved, Decision}`).

### ✅ Gateway emits `ApprovalResolved` to subscribed Assemblies when the human responds via the dashboard

The dashboard verdict path is `POST /api/v1/approvals/{id}/approve|reject`
→ `ApprovalQueue::decide` → `resolve`. On every settled request the queue
notifies an installed `ApprovalResolvedNotifier`; `InvalidationHub` implements it
and fans an `ApprovalResolved` event out to subscribers via
`broadcast_approval_resolved`. A timeout is **not** a human verdict and is **not**
broadcast (the hub impl returns early for `TimedOut`). The notifier is installed
on the production queue in both `serve_tcp` and `serve_uds`.

Evidence:
* `aa-api/src/routes/approvals.rs::approve_action` / `reject_action` → `state.approval_queue.decide(...)`.
* `aa-runtime/src/approval.rs` — `ApprovalResolvedNotifier`, `set_resolved_notifier`, notify call in `resolve`.
* `aa-gateway/src/invalidation/hub.rs` — `broadcast_approval_resolved` + `impl ApprovalResolvedNotifier for InvalidationHub`.
* `aa-gateway/src/server.rs` — `approval_queue.set_resolved_notifier(...)` in `serve_tcp` + `serve_uds`.

Design note: the broadcast is wired at `ApprovalQueue::decide` (the single choke
point every approval-decision path funnels through) rather than threaded through
`AppState`, because the REST e2e harness `TopologyTestEnv` is REST-only and does
not serve the gRPC `InvalidationService` (`aa-integration-tests/tests/common/mod.rs:15`).
The end-to-end tests drive `ApprovalQueue::decide` directly — the exact call the
REST handler makes — over a real loopback gRPC channel.

### ✅ Assembly runtime exposes `wait_for_approval(request_id) -> Future<Decision>` that resolves when the matching event arrives

`ApprovalSink` (an `InvalidationSink`) holds a
`DashMap<request_id, oneshot::Sender<Decision>>`. `wait_for_approval` registers a
oneshot **synchronously** on call and returns a future that resolves when the
matching `ApprovalResolved` event is dispatched to `on_approval_resolved`.

Evidence: `aa-runtime/src/approval_sink.rs`; dispatch in
`aa-runtime/src/invalidation_client.rs::subscribe_once` (the `ApprovalResolved`
arm). Covered by the happy-path e2e (below) and unit tests
`wait_resolves_when_event_arrives`, `wait_resolves_with_denied_verdict`.

### ✅ Timeout policy: caller-specified deadline; on timeout the `Future` resolves to `Decision::Pending` (do not auto-deny)

`wait_for_approval` awaits with `tokio::time::timeout(deadline, …)`; on expiry it
drops its registration and resolves to `Decision::Pending` — never `Denied`. The
rustdoc states callers MUST treat `Pending` as "no human response, decide locally".

Evidence: `aa-runtime/src/approval_sink.rs::wait_for_approval`; unit test
`wait_times_out_to_pending_not_denied` (`-p aa-runtime`); end-to-end test
`approval_push_timeout_resolves_pending_not_denied`
(`aa-integration-tests/tests/e2e_approval_push_timeout.rs`), which also asserts the
future does **not** resolve before the 100 ms deadline.

### ✅ Integration test: dashboard approves request; the agent's `wait_for_approval` resolves with `Approved`

`aa-integration-tests/tests/e2e_approval_push.rs::approval_push_wakes_blocked_agent`:
over a loopback gRPC `InvalidationService`, an `ApprovalSink` subscribes and an
agent awaits `wait_for_approval`; a verdict via `ApprovalQueue::decide` (the call
`POST /approvals/{id}/approve` makes) fans out as `ApprovalResolved` and resolves
the agent's future with `Approved` — no polling.

## Test evidence

```text
cargo nextest run -p aa-runtime approval_sink::
    4 passed  (wait_resolves_when_event_arrives, wait_resolves_with_denied_verdict,
               wait_times_out_to_pending_not_denied, event_without_waiter_is_dropped)

cargo nextest run -p aa-gateway invalidation::hub::
    incl. broadcast_approval_resolved_reaches_subscriber — passed

cargo nextest run -p aa-integration-tests --test e2e_approval_push --test e2e_approval_push_timeout
    approval_push_wakes_blocked_agent                  PASS
    approval_push_timeout_resolves_pending_not_denied  PASS
```

Local quality gates green on the AAASM-2385 branch: `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo deny check`,
`cargo doc --workspace --no-deps`.

## Out-of-scope confirmations (per Story)

* Approval **workflow business logic** — untouched; only the resolution → push
  wiring was added.
* Approval **persistence** — unchanged (the in-memory `ApprovalQueue` resolved
  history is pre-existing).
* **Dashboard UI** for emitting approvals — untouched; the existing REST surface
  is reused.

## Conclusion

All five acceptance criteria pass. No defects found; **no Bug Subtask filed**.
