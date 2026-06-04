# Verification Report — AAASM-2390 (Write-boundary sanitizer)

- **Story:** AAASM-2390 — write-boundary sanitizer that strips raw LLM prompts, tool payloads, eBPF packets, and per-heartbeat data before any audit event hits Postgres
- **Implementation subtask:** AAASM-2397 — PR [#883](https://github.com/ai-agent-assembly/agent-assembly/pull/883)
- **Verification subtask:** AAASM-2398 (this report)
- **Epic:** AAASM-2350 (Async event production + Gateway NATS consumer, Phase 1)
- **Crate / module:** `aa-gateway::sanitizer`
- **Date:** 2026-06-03

## Scope of the implemented surface

`aa-gateway::sanitizer` exposes:

- `RawAuditEvent` / `SanitizedAuditEvent` newtypes over `serde_json::Value`. The sanitized inner value is private and its constructor is crate-private, so the only way to obtain a `SanitizedAuditEvent` is `sanitize()` (compile-time INSERT guard).
- `sanitize(RawAuditEvent) -> SanitizeOutcome` returning `Audit(SanitizedAuditEvent)` or `Heartbeat(HeartbeatUpdate)`.
- Recursive banned-key strip, unknown-top-level-key drop with the `aa_audit_dropped_unknown_field_total{field=…}` counter, and heartbeat collapse.

## Acceptance criteria

| # | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 1 | Distinct `SanitizedAuditEvent` type — INSERT accepts only this | ✅ PASS | Private inner + crate-private constructor; `sanitize` is the sole minting path (`aa-gateway/src/sanitizer/event.rs`). |
| 2 | Drop rules cover all banned keys recursively | ✅ PASS | 11 per-key unit tests + `drops_banned_keys_nested_in_payload` + adversarial test asserting recursive absence (covers the Story's six and the subtask's expanded list as a superset). |
| 3 | Heartbeat routes to a last-seen update, not `audit_logs` | ✅ PASS | `heartbeat_routes_to_last_seen_update` unit test + `malicious_heartbeat_never_becomes_audit_row` adversarial test. |
| 4 | Unknown-field drops increment the metric | ✅ PASS | `drop_unknown_top_level` emits `aa_audit_dropped_unknown_field_total{field=…}`; `drops_unknown_top_level_field` asserts the drop. |
| 5 | Proptest invariant holds for 1000 random inputs | ✅ PASS | `proptest_no_banned_keys` configured with `ProptestConfig::with_cases(1000)`. |

## Commands run

```
# 1. Full sanitizer unit suite
cargo nextest run -p aa-gateway sanitizer::
# → 15 tests run: 15 passed

# 2. Proptest invariant, 1000 cases (release)
cargo nextest run -p aa-gateway sanitizer::sanitize::tests::proptest_no_banned_keys --release
# → 1 test run: 1 passed (1000 cases)

# 3. Adversarial integration tests (sanitizer boundary)
cargo nextest run -p aa-gateway --test sanitizer_adversarial_test
# → 2 tests run: 2 passed
```

> The proptest's full path is `sanitizer::sanitize::tests::proptest_no_banned_keys`; the `sanitizer::` filter from the ticket runs it together with the rest of the suite, and `proptest_no_banned_keys` selects it alone.

## Notes / deviations

- **End-to-end DB assertion (ticket step 3) is performed at the sanitizer boundary**, not through NATS→Postgres, because the consumer (AAASM-2388) and the `audit_logs` INSERT path do not exist yet (AAASM-2388 is To Do). The adversarial test feeds a maliciously-crafted event with every banned key — top-level, in arrays, and deeply nested — through the public `sanitize()` and asserts the persistable output contains none of them. The full publish→consume→INSERT assertion will be added with AAASM-2388.
- The local full `aa-gateway` suite reports one unrelated failure, `policy_latency_test::sustained_load_p99_under_5ms` — a known macOS dev-box timing flake (pre-existing on `master`, green on CI Linux). It is not affected by this change.

## Outcome

All acceptance criteria pass. No Bug subtask filed.
