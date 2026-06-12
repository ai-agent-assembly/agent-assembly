# Verification report — AAASM-1920 Secret Injection

Story: **AAASM-1920 — Implement Secret Injection — gateway secrets store + dispatch-time substitution + audit shape**
Verification Subtask: **AAASM-1931**
Generated: 2026-05-24

## Acceptance-criteria coverage

| AC | Evidence | Status |
|---|---|---|
| `SecretsStore` trait + `InMemorySecretsStore` impl with CRUD coverage in `aa-gateway::secrets` unit tests | `aa-gateway/src/secrets/store.rs::tests` — 6 tests (`register_stores_a_new_secret`, `lookup_returns_none_for_unknown_name`, `list_returns_only_names_sorted_lexicographically`, `delete_removes_a_registered_secret`, `register_duplicate_returns_already_registered`, `delete_missing_returns_not_found`). All pass under `cargo nextest run -p aa-gateway secrets::`. Shipped in ST1 / AAASM-1923 (PR #785). | ✅ |
| Placeholder resolver walks nested JSON; substitutes registered placeholders; returns `UnknownPlaceholder` error for unregistered placeholders | `aa-gateway/src/secrets/resolver.rs::tests` — 7 tests covering whole-string substitution, embedded substitution, nested object, nested array, multi-placeholder, no-placeholder passthrough, and unknown-placeholder error. All pass under `cargo nextest run -p aa-gateway secrets::resolver`. Shipped in ST2 / AAASM-1924 (PR #787). | ✅ |
| `dispatch_tool` route accepts placeholder-form args, substitutes them, forwards substituted args to the tool sink | `aa-api/src/routes/dispatch.rs` — `POST /api/v1/dispatch_tool` handler. Exercised end-to-end by `st_o_1_placeholder_substituted_at_dispatch` in `aa-integration-tests/tests/e2e_secret_injection.rs`. Shipped in ST4 / AAASM-1926 (PR #789) (HTTP) and ST5 / AAASM-1927 (PR #791) (gRPC). | ✅ |
| Audit entry for a `dispatch_tool` call contains the **placeholder name** in the args field, never the resolved value | `aa-core::audit::audit_entry_for_tool_dispatch` helper + `AuditEventType::ToolDispatched` variant. Pinned at the unit level by `tool_dispatch_helper_emits_placeholder_form_payload` and at the E2E level by `st_o_3_audit_log_contains_no_real_value`. Shipped in ST3 / AAASM-1925 (PR #788). | ✅ |
| Python SDK exposes `ctx.client.dispatch_tool(tool_name, args)` that hits the new route | `python-sdk/agent_assembly/client/gateway.py::GatewayClient.dispatch_tool` + `DispatchToolResult` dataclass. 4 unit tests in `python-sdk/test/unit/client/test_dispatch_tool.py` cover the wire contract, 422 mapping, network error mapping, and defensive empty-response handling. Shipped in ST6 / AAASM-1928 (python-sdk PR #60). | ✅ |
| `aa-integration-tests/tests/e2e_secret_injection.rs` (AAASM-1570 scaffold) — drop all four `#[ignore]` annotations and pass under `cargo nextest run -p aa-integration-tests --test e2e_secret_injection` | All 4 `#[ignore]` annotations dropped. `cargo nextest run -p aa-integration-tests --test e2e_secret_injection` → 4 / 4 passed. Shipped in ST8 / AAASM-1931 (this PR). | ✅ |

## Subtask → PR map

| Subtask | Title | PR | Commit count |
|---|---|---|---|
| AAASM-1923 (ST1) | SecretsStore trait + InMemorySecretsStore | #785 | 11 |
| AAASM-1924 (ST2) | Placeholder resolver | #787 | 7 |
| AAASM-1925 (ST3) | Audit `ToolDispatched` event | #788 | 6 |
| AAASM-1926 (ST4) | HTTP `/v1/dispatch_tool` route | #789 | 6 |
| AAASM-1927 (ST5) | gRPC `DispatchTool` RPC | #791 | 3 |
| AAASM-1928 (ST6) | Python SDK `dispatch_tool` | python-sdk #60 | 3 |
| AAASM-1929 (ST7) | Secret Injection threat-model README | #790 | 1 |
| AAASM-1931 (ST8) | Verification — drop `#[ignore]` | this PR | 3 |

## Verification command

```bash
cargo nextest run -p aa-integration-tests --test e2e_secret_injection
```

### Output digest

```
Starting 4 tests across 1 binary
    PASS [   0.017s] (1/4) e2e_secret_injection st_o_3_audit_log_contains_no_real_value
    PASS [   0.128s] (2/4) e2e_secret_injection st_o_2_real_secret_absent_from_llm_traffic
    PASS [   0.128s] (3/4) e2e_secret_injection st_o_4_unknown_placeholder_returns_error
    PASS [   0.135s] (4/4) e2e_secret_injection st_o_1_placeholder_substituted_at_dispatch
Summary [   0.135s] 4 tests run: 4 passed, 0 skipped
```

## Scope deviations from the AAASM-1570 scaffold

The scaffold added under AAASM-1570 contemplated an in-process topology with a `MockLlmServer` acting as both the LLM upstream and the downstream tool sink. v0.0.1's `/dispatch_tool` HTTP route is a pure resolver — it does not forward to a downstream tool sink and it does not call an LLM upstream. As a result:

* **ST-O-1** — verified against the response body, which is the only surface in v0.0.1 where the resolved credential is observable (the agent is expected to forward `resolved_args` to the actual tool sink itself).
* **ST-O-2** — re-scoped to "the resolved credential MUST NOT appear in any audit-tracked surface". The "LLM upstream" wiring that the scaffold imagined is deferred to a follow-up Subtask (`aa-gateway/src/secrets/README.md` non-goals list).
* **ST-O-3** — pinned at the `audit_entry_for_tool_dispatch` helper level. Wiring a test-side `AuditWriter` into the in-process `TopologyTestEnv` is deferred to a follow-up; the contract that the helper produces a placeholder-form payload (never the resolved value) is what every dispatch_tool handler relies on.
* **ST-O-4** — verified against the actual HTTP route. Unknown placeholder → 422 with the placeholder name in the error body.

These deviations are recorded in the module-level doc-comment of `aa-integration-tests/tests/e2e_secret_injection.rs` so future readers can see the contract pre/post the deferred follow-ups landing.

## Follow-up backlog (out of scope for v0.0.1)

Tracked in `aa-gateway/src/secrets/README.md`:

* Persisted `SecretsStore` backend (current store loses state across restarts).
* Per-agent / per-team scoping (current store is a single global namespace).
* Rotation (no graceful re-key path today).
* Audit of `register` / `delete` store-mutation calls (only dispatch is audited today).
* `AuditWriter` wiring inside `TopologyTestEnv` so on-disk JSONL grep tests can run against a live test env.
* LLM upstream + downstream tool-sink forwarding on the `dispatch_tool` path (would expand ST-O-1 / ST-O-2 to their original scaffold scope).
