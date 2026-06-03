# Verification Report — AAASM-2355 (shared storage types)

- **Story:** AAASM-2355 — stable shared types (`AgentId`, `Policy`, `AuditEvent`, `SessionCtx`, `Credential`) in `aa-core`
- **Implementation subtask:** AAASM-2359 — PR [#850](https://github.com/ai-agent-assembly/agent-assembly/pull/850)
- **Verification subtask:** AAASM-2360 (this report)
- **Component / repo:** `agent-assembly` (OSS monorepo), crate `aa-core`
- **Date:** 2026-06-03

## Scope verified

The five wire types under `aa_core::types`: `AgentId` (+ `AgentIdParseError`), `Policy`
(+ `Rule`), `AuditEvent`, `SessionCtx`, `Credential`.

## Acceptance criteria

| # | Acceptance criterion | Result |
| --- | --- | --- |
| 1 | All five types derive `Serialize`, `Deserialize`, `JsonSchema`, `Debug`, `Clone` | ✅ PASS |
| 2 | Wire format documented in rustdoc with example JSON for each | ✅ PASS |
| 3 | Property tests prove serde round-trip for each | ✅ PASS |
| 4 | `AgentId` constructor rejects malformed input with a typed error | ✅ PASS |
| 5 | `cargo doc -p aa-core --no-deps` renders the example JSON | ✅ PASS |

## Evidence

### AC1 — derives present

Each type carries `#[derive(Debug, Clone, PartialEq, Eq)]` plus feature-gated
`#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]` and
`#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]`. The derives are
feature-gated to keep `aa-core` `no_std`-friendly; they are enabled for the crate's
own test build via a self dev-dependency, so they compile and are exercised in CI's
`cargo nextest run -p aa-core`.

Confirmed building under all three feature combinations:

```
cargo build -p aa-core                                  # default (std)        → ok
cargo build -p aa-core --no-default-features --features alloc   # no_std + alloc → ok
cargo build -p aa-core --no-default-features             # pure no_std (types gated off) → ok
cargo clippy -p aa-core --all-targets --all-features -- -D warnings  → clean
```

### AC2 — rustdoc example JSON

Every type documents its JSON wire shape in a ```json``` block (`AgentId`,
`Policy`/`Rule`, `AuditEvent`, `SessionCtx`, `Credential`). The `AgentId::parse`
rustdoc example is also an executable doctest:

```
cargo test -p aa-core --features serde,schemars --doc
   Doc-tests aa_core
test aa-core/src/types/agent_id.rs - types::agent_id::AgentId::parse (line 33) ... ok
test result: ok. 1 passed; 0 failed
```

### AC3 — serde round-trip property tests

```
cargo nextest run -p aa-core types::
        PASS  types::agent_id::tests::parse_accepts_well_formed_id
        PASS  types::agent_id::tests::parse_rejects_malformed_input_with_typed_error
        PASS  types::agent_id::serde_round_trip::agent_id_round_trips
        PASS  types::session_ctx::serde_round_trip::session_ctx_round_trips
        PASS  types::credential::serde_round_trip::credential_round_trips
        PASS  types::audit_event::serde_round_trip::audit_event_round_trips
        PASS  types::policy::serde_round_trip::policy_round_trips
     Summary  7 tests run: 7 passed
```

Full crate suite (regression check after adding `JsonSchema` to `Timestamp` and
`AuditEventType`): `cargo nextest run -p aa-core` → **261 passed, 0 failed**.

### AC4 — typed-error rejection

`AgentId::parse` returns `AgentIdParseError` for malformed input
(`types::agent_id::tests::parse_rejects_malformed_input_with_typed_error`):

| Input | Error |
| --- | --- |
| `""` | `Empty` |
| `"no-slash"` | `NotExactlyOneSlash` |
| `"a/b/c"` | `NotExactlyOneSlash` |
| `"/agent"` | `EmptyTenant` |
| `"tenant/"` | `EmptyAgent` |

### AC5 — rustdoc renders example JSON

`cargo doc -p aa-core --no-deps` generated `target/doc/aa_core/types/`; the example
JSON strings (e.g. `acme/billing-bot`) are present in the rendered HTML
(`struct.AgentId.html`, `struct.SessionCtx.html`, …).

### Additional smoke test (construct-from-JSON)

A construct-from-JSON fixture for each of the five types — using the exact JSON from
each rustdoc example — was deserialized and field-checked, standing in for the
future `aa-storage-memory` driver. `deny_unknown_fields` was confirmed to reject a
writer that renames `policy_version` → `version`. Both checks passed.

## Outcome

All five acceptance criteria **PASS**. No bug subtasks filed. Implementation PR
[#850](https://github.com/ai-agent-assembly/agent-assembly/pull/850) is ready for review.
