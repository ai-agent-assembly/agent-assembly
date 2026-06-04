# Verification Report — AAASM-2384

**Story:** AAASM-2377 — *Persistent gRPC bidi stream that pushes policy invalidations so cache freshness isn't a TTL race*
**Epic:** AAASM-2349 — *L1 in-process cache + Gateway push-invalidation channel*
**Component / repo:** `agent-assembly`
**Date:** 2026-06-03

## Scope

Verifies the push-invalidation channel delivered across the three implementation
sub-tasks:

| Sub-task | PR | Surface |
|---|---|---|
| AAASM-2381 | #873 | `proto/invalidation.proto` + `aa-proto` codegen (`assembly.gateway.v1`) |
| AAASM-2382 | #875 | `aa-gateway/src/invalidation/` server (hub + Subscribe RPC) |
| AAASM-2383 | #888 | `aa-runtime` `InvalidationClient` + `PolicyL1Cache` sink |

## Acceptance criteria (Story AAASM-2377)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Proto `InvalidationService` with bidi-stream `Subscribe(stream SubscribeRequest) returns (stream InvalidationEvent)` | ✅ Pass | `proto/invalidation.proto`; `cargo check -p aa-proto` generates `InvalidationServiceServer`/`Client`. Package is `assembly.gateway.v1` (repo convention) rather than the literal `aa.gateway.v1`. |
| 2 | `InvalidationEvent` carries `oneof { PolicyInvalidated, ApprovalResolved }` | ✅ Pass | `invalidation_event::Payload` enum; `ApprovalResolved` + `Decision` reserved for the next Story. |
| 3 | Gateway server: a `Sender<InvalidationEvent>` per connected Assembly; broadcast on policy mutation | ✅ Pass | `InvalidationHub` (per-subscriber `broadcast::Sender` + seq + replay ring); `PolicyEngine::apply_yaml` broadcasts after the epoch bump. `engine::tests::apply_yaml_broadcasts_invalidation_within_100ms`. |
| 4 | Assembly client: reconnect with exponential backoff (1s → 32s cap) | ✅ Pass | `InvalidationClient` run loop; `invalidation_client::tests::backoff_doubles_then_caps_at_32s` asserts `1,2,4,8,16,32,32`. |
| 5 | On reconnect, Assembly issues `Resubscribe(last_seq)`; gateway replays anything missed | ✅ Pass | Client opens with `SubscribeInitial.last_seq_seen`; hub replays `seq > last_seq_seen`. `hub::tests::reconnect_replays_only_events_after_last_seq` + e2e `reconnect_replays_invalidation_missed_while_disconnected`. |
| 6 | Integration test: mutate policy → subscribed Assembly L1 invalidated within 100 ms | ✅ Pass | `e2e_invalidation_channel::policy_invalidation_evicts_l1_within_100ms` (real server ↔ real client over loopback gRPC). |

## Commands run

```
cargo check -p aa-proto
cargo nextest run -p aa-gateway -p aa-runtime -p aa-integration-tests invalidation
cargo nextest run -p aa-runtime l1_cache::
```

## Results

```
9 tests run: 9 passed   (invalidation filter: aa-gateway hub ×4, engine apply_yaml ×1,
                         aa-runtime backoff ×1, aa-integration-tests e2e ×2)
4 tests run: 4 passed   (aa-runtime l1_cache::tests — PolicyL1Cache + sink contract)
cargo check -p aa-proto: Finished (assembly.gateway.v1 bindings compile)
```

All green. `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -D warnings`,
and `cargo deny check` are enforced by the lefthook pre-commit hook on every commit in the
three implementation PRs.

## Notes & limitations

- **Replay durability:** the per-subscriber replay ring (1024 events) is in-memory. Reconnect
  *to a live gateway* replays missed events (verified). A full gateway **process restart** drops
  the ring — "no lost invalidations once both sides are up" holds for reconnects, but durable
  cross-restart replay would need a persistent backing store (candidate follow-up, not in this
  Story's scope).
- **Latency metric:** `aa_invalidation_latency_seconds` records the client-side apply latency
  (event receipt → sink dispatch); true wire latency would require a timestamp field on the
  event, which the proto deliberately omits for now.
- **Crate mapping:** the Assembly subscriber lives in `aa-runtime` (no `aa-assembly` crate
  exists); the e2e tests live in `aa-integration-tests` to avoid the `aa-gateway → aa-runtime`
  dependency cycle.

## Verdict

**All acceptance criteria pass.** No blocking defects found; no Bug sub-task filed.
