# Test fixtures

Static fixture files consumed by the CLI integration tests under
`tests/cli_*.rs`. Resolved at runtime via
`CliFixture::fixture_path("<subdir>/<file>")` which uses
`CARGO_MANIFEST_DIR` so the lookup works regardless of where
`cargo nextest` is invoked from.

## `policies/`

| File | Used by | Purpose |
| --- | --- | --- |
| `allow_all.yaml` | `cli_policy.rs` ST-3 happy-path tests | Minimal valid policy with empty rule set |
| `deny_websearch.yaml` | `cli_policy.rs` ST-3 deny-path tests | Single deny rule for the `WebSearch` tool |
| `invalid.yaml` | `cli_policy.rs` ST-3 `policy validate` negative-path | Malformed YAML — missing required keys + wrong types |

## `audit/`

| File | Used by | Purpose |
| --- | --- | --- |
| `chain_valid.jsonl` | `cli_audit_alerts.rs` Phase B `audit verify-chain` happy-path | 3 hash-chain-correct audit events |
| `chain_tampered.jsonl` | `cli_audit_alerts.rs` Phase B `audit verify-chain` failure-path | 3 events where event 2's `prev_hash` doesn't match event 1's `hash` |

The chain hashes are illustrative — `aasm audit verify-chain` recomputes
the hash chain from `event_id`, `timestamp`, `agent_id`, `action`,
`result`, and `prev_hash`; the embedded `hash` field is what gets compared.
The `chain_tampered.jsonl` deliberately breaks event 2's `prev_hash`
linkage to event 1.

## Adding new fixtures

Drop the file into the appropriate `<resource>/` subdirectory and reference
it from a test via `CliFixture::fixture_path("policies/my_new.yaml")`.
Add a row to this README so future readers know what it's for.
