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
required"), so an unreachable runtime cannot pass as a denial.

```text
scripts/qa/j81-sdk-lease-e2e.sh                   # all scenarios
scripts/qa/j81-sdk-lease-e2e.sh --mutation-check  # run with the gate absent; S2a S2b S3 S4a S4b must FAIL
```

Prerequisites: a built `aa-runtime` and `aasm` (`J81_RUNTIME_BIN`, `J81_AASM_BIN`, default
`$CARGO_TARGET_DIR/debug`) and a `python-sdk` checkout with `.venv` and its native `_core`
module (`J81_SDK_DIR`, default `../python-sdk`). Each runtime is started with a controlled
environment: `AA_POLICY_PATH` empty, no `AA_GATEWAY_ENDPOINT`, a free `AA_METRICS_ADDR`
port and a unique `AA_AGENT_ID`. It prints one `J81_RESULT|<id>|<PASS|FAIL|INFO>|...` line
per scenario and a `J81_SUMMARY` line, and exits non-zero on any FAIL.

| Scenario | Claim checked |
|---|---|
| S1 | Positive control: declared tool with a valid lease is allowed and its side effect occurs. Gates every later scenario. |
| S2, S3 | An undeclared or `allow: false` tool, and a declared class with no lease, are denied before execution. |
| S4 | A lease for one class does not authorize a tool that needs another, or only part of a set. |
| S5 | Capabilities, `action_type` and `agent_id` supplied in the call do not authorize. Tool names match exactly. |
| S6 | `aasm lease revoke --wait-health` is followed by denial on the very next call, including under continuous calling; a short-TTL lease denies after expiry. |
| S7 | After `kill -9` and a restart on the same state file the decisions are identical and nothing is re-granted. A corrupt, truncated, empty, missing or other-subject record makes the runtime exit 78. A record corrupted while running denies everything and does not heal. |
| S8 | A second runtime with its own agent id and state is isolated: its revocation does not reach the first. |

S5d records, as `INFO` unless denied, what the runtime answers when a client relabels a
tool call by choosing `action_type` itself. That is the documented residual of admission
control (ADR 0038 section 36), not a claim that it is closed.
