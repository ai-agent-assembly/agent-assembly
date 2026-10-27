# J81 Python SDK lease-gate end-to-end harness

`scripts/qa/j81-sdk-lease-e2e.sh` (with the fixture `scripts/qa/j81_sdk_lease_fixture.py`)
exercises the production capability-lease gate (Core ADR 0038 sections 35 to 37,
AAASM-6259) from the real Python SDK. A llama-index `FunctionTool` is called through the
SDK's own interceptor path (`LlamaIndexPatch`, `RuntimeQueryInterceptor`, the native
`RuntimeClient`), so each call arrives at `aa-runtime` as a `TOOL_CALL` and is decided by
`PolicyLeaseGate`. Nothing in the path is mocked.

The tool body writes a sentinel file in a per-run temporary directory. "The forbidden side
effect did not occur" is read from that directory, independently of the verdict the SDK
reports. A denial only counts when its reason is the gate's own ("capability lease
required"). That reason is deliberately generic and does not say which check denied, so the
sentinel file and the positive controls are what tell a gate denial from any other: an
unreachable runtime has a different reason, and an allowed call leaves a sentinel.

This is manual local evidence, not a CI gate: nothing runs it automatically.

```text
scripts/qa/j81-sdk-lease-e2e.sh                   # all scenarios
scripts/qa/j81-sdk-lease-e2e.sh --mutation-check  # gate-absent control: S1 must PASS, gate scenarios must FAIL
```

Prerequisites: a built `aa-runtime` and `aasm` (`J81_RUNTIME_BIN`, `J81_AASM_BIN`, default
`$CARGO_TARGET_DIR/debug`) and a `python-sdk` checkout with `.venv` and its native `_core`
module (`J81_SDK_DIR`, default `../python-sdk`). Each runtime is started with a controlled
environment: `AA_POLICY_PATH` empty, no `AA_GATEWAY_ENDPOINT`, a free `AA_METRICS_ADDR`
port and a unique `AA_AGENT_ID`. `--mutation-check` is a gate-absent control only: it reruns
everything with `AA_LEASE_POLICY` unset and requires S1 to pass and S2 to S7 to fail, which
shows the harness notices a runtime that is not gating. It does not detect subtler gate defects. It prints one `J81_RESULT|<id>|<PASS|FAIL|INFO>|...` line
per scenario and a `J81_SUMMARY` line, and exits non-zero on any FAIL.

| Scenario | Claim checked |
|---|---|
| S1 | Positive control: declared tool with a valid lease is allowed and its side effect occurs. Gates every later scenario. |
| S2, S3 | An undeclared or `allow: false` tool, and a declared class with no lease, are denied before execution. |
| S4 | A lease for one class does not authorize a tool that needs another, or only part of a set. |
| S5 | Capabilities, `action_type` and `agent_id` supplied in the call args do not authorize. Tool names match exactly. S5d: a raw relabel to `llm_call` or `tool_result` that keeps the tool context is denied. S5e: the omit-context relabel, see below. |
| S6 | After `aasm lease revoke --wait-health` returns, the next call is denied, and every call sent at or after the acknowledgement is denied under continuous calling. Calls sent between the revoke write and the `/health` acknowledgement may be allowed by design (the runtime reloads about every 100 ms). A short-TTL lease is denied once the wall clock passes issued_at+ttl; the probes run about 1 s and about 3 s after expiry, so a grace shorter than about 1 s is not excluded here (the runtime wiring test bounds it tighter). |
| S7 | After `kill -9` and a restart on the same state file the decisions are identical, nothing revoked is re-granted, a still-valid lease still permits, and a lease already expired is not refreshed. A corrupt, truncated, empty, missing or other-subject record makes the runtime exit 78. A record corrupted while running denies everything and does not heal. |
| S8 | A second runtime with its own agent id and state is isolated: its revocation does not reach the first. |

S5d covers relabelling with the tool context still attached. The omit-context relabel is
the form Core ADR 0038 section 36 used to document as a residual: the SDK shim can send it
(`query_policy` with `tool_name=None` builds no typed context). Governed mode now admits only
`TOOL_CALL`, so S5e sends it and expects `deny`; with the gate absent (`--mutation-check`) the
runtime answers `allow` and S5e FAILs, which is the intended discrimination. A producer run on main 2c553741d (2026-10-27) had both S5e rows PASS
(`deny`, "capability lease required"), and under `--mutation-check` both FAIL with `allow`.
`--mutation-check` now requires the S5d and S5e rows to FAIL with the gate absent, so its
exit code covers them (before AAASM-6385 its list omitted them). That run is producer
evidence, not independent QA.
