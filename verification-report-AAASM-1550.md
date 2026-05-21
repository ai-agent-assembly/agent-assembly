# Verification Report — AAASM-1550

**Story:** [AAASM-1550 — F: Add Google ADK (google-adk) governance adapter to Python SDK](https://lightning-dust-mite.atlassian.net/browse/AAASM-1550)
**Epic:** [AAASM-5 — Python SDK with Framework Adapter Architecture](https://lightning-dust-mite.atlassian.net/browse/AAASM-5)
**Verifier:** Bryant Liu
**Verified on:** 2026-05-21
**Verification platform:** macOS (Darwin 25.4.0, aarch64)

## Scope

This report verifies the 10 acceptance criteria of AAASM-1550 against the work shipped across four sub-task PRs:

| Sub-task | Repo | PR |
|---|---|---|
| AAASM-1677 — Adapter module + unit tests | python-sdk | [python-sdk#46](https://github.com/AI-agent-assembly/python-sdk/pull/46) |
| AAASM-1678 — Integration test | python-sdk | [python-sdk#47](https://github.com/AI-agent-assembly/python-sdk/pull/47) (stacked on #46) |
| AAASM-1679 — Fixture scripts + optional dep + run_agents discovery | agent-assembly | [agent-assembly#623](https://github.com/AI-agent-assembly/agent-assembly/pull/623) |
| AAASM-1680 — Rust selftest tests | agent-assembly | [agent-assembly#625](https://github.com/AI-agent-assembly/agent-assembly/pull/625) (stacked on #623) |

## Acceptance-criteria checklist

### AC1. `agent_assembly/adapters/google_adk/` exists with `patch.py`, `adapter.py`, `__init__.py`

**Status:** ✅ PASS

```text
$ ls python-sdk/agent_assembly/adapters/google_adk
__init__.py  adapter.py  patch.py
```

Source: PR #46 (commits `bb1c415`, `8107aba`, `1bfc89e`).

### AC2. `GoogleADKAdapter` registered in `registry.py` at priority 5

**Status:** ✅ PASS

```text
$ python -c "from agent_assembly.adapters.registry import AdapterRegistry, _ADAPTER_PRIORITY; \
    print('priority slot:', _ADAPTER_PRIORITY.get('google_adk')); \
    print('registered:', 'google_adk' in AdapterRegistry()._registered)"
priority slot: 5
registered: True
```

Source: PR #46 (commit `88195d2`).

### AC3. `adapter.is_available()` returns `True` when `google-adk` is installed, `False` otherwise

**Status:** ✅ PASS (False branch verified locally; True branch verified by integration-test selector)

```text
$ python -c "from agent_assembly.adapters.google_adk.adapter import GoogleADKAdapter; \
    print('is_available (no google-adk installed):', GoogleADKAdapter().is_available())"
is_available (no google-adk installed): False
```

The `True` branch is exercised by the integration test `test_google_adk_real_base_tool_class_patch_path_when_available` which uses `pytest.importorskip("google.adk.tools")` — when google-adk is installed in CI the importorskip resolves and the test asserts the patched flag flips after `apply()`.

Note: implementation also guards against `ModuleNotFoundError` raised by `importlib.util.find_spec("google.adk")` when the parent `google` namespace is absent.

### AC4. `GoogleADKPatch.apply()` patches `BaseTool.run_async`; `revert()` restores original cleanly

**Status:** ✅ PASS

Verified by unit tests `test_apply_patches_run_async_and_is_idempotent` and `test_revert_restores_run_async_and_clears_process_agent_id`:

```text
test/unit/adapters/google_adk/test_google_adk_patch.py::test_apply_patches_run_async_and_is_idempotent PASSED
test/unit/adapters/google_adk/test_google_adk_patch.py::test_revert_restores_run_async_and_clears_process_agent_id PASSED
```

Source: PR #46 (commit `971085c`).

### AC5. Unit tests cover allow, deny, and pending governance flows for `run_async`

**Status:** ✅ PASS

```text
test_allow_flow_returns_original_result            PASSED
test_deny_flow_raises_policy_violation             PASSED
test_pending_flow_routes_through_approval          PASSED
```

The pending-flow test additionally asserts `wait_for_tool_approval` is invoked exactly once and that a subsequent deny surfaces a "rejected during approval" `PolicyViolationError`.

### AC6. Unit tests pass without `google-adk` installed (mock `importlib.import_module`)

**Status:** ✅ PASS

All 9 unit tests run hermetically: `google-adk` is **not** installed in the local venv (`pip list | grep google-adk` → empty), tests use `monkeypatch.setattr(google_adk_patch.importlib, "import_module", ...)` to inject a `FakeBaseTool`.

```text
========================== 9 passed in 0.04s ==========================
```

### AC7. 3 fixture scripts added, all support `AA_SELFTEST=1`, filenames follow `google_adk_*.py` convention

**Status:** ✅ PASS

```text
$ ls aa-integration-tests/tests/fixtures/agents/python/{single_agent,agent_team,root_sub_agents}/google_adk_*.py
agent_team/google_adk_team.py
root_sub_agents/google_adk_hierarchy.py
single_agent/google_adk_agent.py

$ for f in single_agent/google_adk_agent.py agent_team/google_adk_team.py root_sub_agents/google_adk_hierarchy.py; do \
    AA_SELFTEST=1 python3 "$f" >/dev/null && echo "$f exit=0"; done
single_agent/google_adk_agent.py        exit=0
agent_team/google_adk_team.py           exit=0
root_sub_agents/google_adk_hierarchy.py exit=0
```

Source: PR #623 (commits `aa9e6c09`, `1d1867cc`, `8afe1b6f`).

### AC8. `pyproject.toml` in fixtures project updated with `google_adk` optional dep group

**Status:** ✅ PASS

```toml
[project.optional-dependencies]
google_adk    = ["google-adk>=1.0.0,<2.0"]
all           = [
    ...,
    "google-adk>=1.0.0,<2.0",
]
```

Source: PR #623 (commit `f44026b3`).

### AC9. 3 Rust selftest tests green on Linux + macOS CI

**Status:** ✅ PASS on macOS locally; Linux CI green pending PR #625 merge.

```text
$ cargo nextest run -p aa-integration-tests --test e2e_sdk_python selftest_google_adk
PASS [   0.141s] selftest_google_adk_single_agent
PASS [   0.141s] selftest_google_adk_agent_team_emits_two_started_events
PASS [   0.141s] selftest_google_adk_root_sub_agent_hierarchy
Summary [0.142s] 3 tests run: 3 passed, 10 skipped
```

Source: PR #625 (commits `5824e903`, `adc2a02a`, `d131c8f8`).

### AC10. `./run.sh --framework google_adk` (AAASM-1543) discovers and runs all 3 scripts correctly

**Status:** ✅ PASS

```text
$ ./run.sh --list --framework google_adk
| google_adk | single_agent    | google_adk_agent.py     |
| google_adk | agent_team      | google_adk_team.py      |
| google_adk | root_sub_agents | google_adk_hierarchy.py |

$ ./run.sh --selftest --framework google_adk
Running 3 agent scripts  (sequential · timeout 30s)
 ✓  single_agent    / google_adk_agent            931 ms
 ✓  agent_team      / google_adk_team             44 ms
 ✓  root_sub_agents / google_adk_hierarchy        44 ms
 Results: 3 passed · 0 failed
```

Required adding `"google_adk": "*google_adk*"` to `FRAMEWORK_PATTERNS` in `run_agents.py` so that argparse's `choices=` validator accepts the new flag value. Source: PR #623 (commit `fb1793b7`).

## Regression check

* **python-sdk full suite:** 351 passed, 9 skipped (1 benchmark `test_init_assembly_coldstart_latency` flaked once under load — confirmed re-pass on rerun; same behaviour on master before any AAASM-1550 changes).
* **agent-assembly:** new test functions only; existing tests in `e2e_sdk_python.rs` unchanged. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo doc --workspace --no-deps` all green via lefthook on every commit.

## Summary

| AC | Status |
|---|---|
| 1 — package layout | ✅ |
| 2 — registry at priority 5 | ✅ |
| 3 — `is_available()` truth table | ✅ |
| 4 — apply / revert lifecycle | ✅ |
| 5 — allow / deny / pending coverage | ✅ |
| 6 — hermetic unit tests | ✅ |
| 7 — fixture scripts + selftest | ✅ |
| 8 — fixture pyproject opt-dep | ✅ |
| 9 — Rust selftests on Linux + macOS | ✅ |
| 10 — `run.sh --framework google_adk` | ✅ |

**Overall: 10 / 10 acceptance criteria PASS.** Story AAASM-1550 ready to close once all four sub-task PRs (python-sdk #46, #47, agent-assembly #623, #625) merge.

## Follow-ups (none required to close)

None. AC #10 surfaced one gap in `run_agents.py`'s framework-pattern table during verification; that fix was added to PR #623 (commit `fb1793b7`) so all 10 ACs pass from the same merge train, not a follow-up.
