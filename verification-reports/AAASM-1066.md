# F103 Verification — AAASM-1066 (End-to-end topology integration test)

> **Status**: All five sub-tasks (ST-1 through ST-4 + this ST-5
> verification) complete. The full `aa-topology-integration-tests`
> crate passes on Linux + macOS via the new `topology-integration.yml`
> workflow, and locally on macOS. Six AC items land *adapted* against
> the original ticket text — each adaptation is forced by a codebase
> reality discovered during ST-1 recon (no Postgres tier; gateway is
> gRPC-only; SDK package renamed; no DELETE endpoint; cross-crate
> binary discovery) and documented with file:line evidence in the
> sub-task PR descriptions. **No Bug Sub-task opened**.

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| AAASM-1076 | Scaffold crate + testcontainers harness | Done | [#447](https://github.com/AI-agent-assembly/agent-assembly/pull/447) |
| AAASM-1078 | Python SDK driver + LangGraph fixture | Done | [#459](https://github.com/AI-agent-assembly/agent-assembly/pull/459) |
| AAASM-1079 | REST + CLI assertions module | Done | [#462](https://github.com/AI-agent-assembly/agent-assembly/pull/462) |
| AAASM-1081 | CI workflow (Linux + macOS) + Drop cleanup | Done | [#466](https://github.com/AI-agent-assembly/agent-assembly/pull/466) |
| AAASM-1159 | Verify F103 acceptance criteria | in this report | — |

## Walkthrough vs AAASM-1066 acceptance criteria

### ✅ New test crate `aa-topology-integration-tests`

Crate lives at the workspace root (`aa-topology-integration-tests/`),
not under `crates/` — the latter directory does not exist in the
repo. All 20 sibling crates also live at the root. Adapted in
ST-1 PR #447; documented at the time.

Evidence: `aa-topology-integration-tests/Cargo.toml`,
[`Cargo.toml:24`](../Cargo.toml) (workspace member entry).

### ⚠️ Test scenario: spawns gateway + Postgres via testcontainers; runs Python SDK; asserts child AgentRecord lineage

**Adapted — three layers replaced with in-process equivalents** because
the codebase doesn't match the ticket's assumed shape:

* **Postgres + testcontainers** → not used. `AgentRegistry` is a pure
  in-memory `DashMap` (see `aa-gateway/src/registry/store.rs:138`); the
  only SQLite usage is the approval-routing subsystem, which this
  story doesn't exercise.
* **"spawn gateway binary"** → in-process axum server via
  `aa_api::server::build_app` bound to a free TCP port via `portpicker`.
  `aa-gateway` is gRPC-only (`tonic::Server::builder()` at
  `aa-gateway/src/server.rs:301`) and there is no `aa-api` HTTP binary
  in the workspace.
* **Python SDK populates the registry over the wire** → not used.
  The SDK's `GatewayClient.register_agent()` POSTs to
  `/agents/{id}/register`, a route `aa-api` doesn't expose
  (registration is gRPC-only). Tests populate the registry directly
  via the shared `Arc<AgentRegistry>` from Rust
  (`tests/common/scenario.rs::register_parent_child`).

The substance of this AC bullet (a registered parent-child topology
that subsequent tests can read) is satisfied: the
`agent_record_has_correct_parent_and_depth` test reads the child
record back through the registry and asserts `parent_key`,
`parent_agent_id`, `root_agent_id`, `depth == 1`, and
`team_id == "topology-it"`.

### ✅ Test asserts `GET /v1/topology/tree/{root_id}` returns the 2-node tree

`rest_tree_endpoint_returns_two_node_shape` in
`tests/topology_roundtrip.rs` hits `GET /api/v1/topology/tree/<32-hex>`
on the running harness and asserts on the deserialised JSON via
`serde_json::Value`:

* root `id` matches the registered parent ID,
* `children` has exactly 1 entry,
* the child entry's `id` matches the registered child ID and its own
  `children` array is empty.

Real endpoint path is `/api/v1/...` (not `/v1/...`); ticket text
ambiguous — verified the real shape.

### ⚠️ Test asserts `aasm topology tree <root>` CLI output

`cli_topology_tree_renders_both_agents` in
`tests/topology_roundtrip.rs` runs `aasm` via `env!("CARGO") run -p aa-cli`
(`assert_cmd::cargo_bin` doesn't work for cross-crate binaries since
`CARGO_BIN_EXE_aasm` is unset).

* Asserts both agent IDs appear in stdout. ✅
* **Indent check** — adapted. The default table output renders agent
  *names* (e.g. `topology-it-11111111`), not full 32-char IDs, so a
  textual indent assertion is irreconcilable with a full-ID
  assertion. Test uses `--output json` (machine-readable canonical
  format per `aa-cli/src/output.rs:OutputFormat::Json`) and asserts
  IDs.

### ✅ Test runs in CI matrix on Linux + macOS

`.github/workflows/topology-integration.yml` runs the crate on both
runners. Both matrix entries passed in <4 min on the ST-4 PR (#466)
final CI run.

CI runs (PR #466 head SHA `0629bbf3`):

* [Topology integration tests (ubuntu-latest)](https://github.com/AI-agent-assembly/agent-assembly/actions/runs/25964046400/job/76324257585) — 3m25s pass
* [Topology integration tests (macos-latest)](https://github.com/AI-agent-assembly/agent-assembly/actions/runs/25964046400/job/76324257551) — 3m22s pass

### ⚠️ Cleanup tears down all spawned agents + sessions

**Adapted** — `TopologyTestEnv::Drop` calls `cleanup()` which walks
`agent_registry.team_members("topology-it")` and
`deregister(.., OrphanMode::CascadeDeregister)` for every match.
Idempotent via `cleaned: bool`. The ticket text envisages a `DELETE`
HTTP endpoint plus Postgres `TRUNCATE`; both targets don't exist
in this codebase (per ST-1 / ST-3 divergence notes). The in-process
cascade-deregister produces the same end state — every test agent
removed before the next test.

Evidence: `tests/common/mod.rs:118` (`cleanup`),
`tests/common/mod.rs:154` (`Drop::drop` calls `cleanup`).

## Local test transcript (cross-check against CI)

Master at `a6570aaf` (post-ST-4 merge), macOS 25.4.0, rustc stable,
cargo-nextest 0.9:

```text
Nextest run ID d639d3b1-5913-4a89-b184-81f2bbab91bd with nextest profile: default
    Starting 5 tests across 4 binaries
        PASS [   0.176s] (1/5) aa-topology-integration-tests::sdk_driver_selftest selftest_exits_zero_and_emits_agent_id_json
        PASS [   0.035s] (2/5) aa-topology-integration-tests::smoke harness_starts_and_returns_200_on_health
        PASS [   0.034s] (3/5) aa-topology-integration-tests::topology_roundtrip agent_record_has_correct_parent_and_depth
        PASS [  21.400s] (4/5) aa-topology-integration-tests::topology_roundtrip cli_topology_tree_renders_both_agents
        PASS [   0.037s] (5/5) aa-topology-integration-tests::topology_roundtrip rest_tree_endpoint_returns_two_node_shape
     Summary [  21.683s] 5 tests run: 5 passed, 0 skipped
```

The 21 s CLI-test cost is the one-shot `cargo run -p aa-cli` build;
subsequent runs are sub-second (Cargo target cache).

## Six adaptations summary

| # | Ticket text | Real codebase | Forced by |
|---|---|---|---|
| 1 | Crate path `crates/aa-topology-integration-tests/` | Repo root | Workspace layout — no `crates/` dir exists |
| 2 | Spawn `aa-gateway` binary as child process | In-process `axum::serve` on free port | `aa-gateway` is gRPC-only; no `aa-api` HTTP binary |
| 3 | Postgres via testcontainers + sqlx migrations | In-memory `Arc<AgentRegistry>` | `AgentRegistry` is `DashMap`; no Postgres tier |
| 4 | `import aa_sdk` | `import agent_assembly` | Real package name (`agent_assembly`, PyPI `agent-assembly`) |
| 5 | `assert_cmd::Command::cargo_bin("aasm")` | `env!("CARGO") run -p aa-cli` | `CARGO_BIN_EXE_aasm` unset for cross-crate binaries |
| 6 | `DELETE /v1/agents?team_id` + TRUNCATE Postgres tables | `agent_registry.team_members(..)` + `deregister(.., CascadeDeregister)` | No DELETE endpoint; no Postgres |

Plus one minor scope deferral:

* **Shared `OnceCell` fixture across tokio::tests** — deferred. Each
  `#[tokio::test]` runtime is independent, so a shared server task
  spawned in one runtime dies when that runtime drops. A correct
  shared-fixture impl needs a dedicated host thread that owns a
  long-lived runtime (~30 LOC); accepted per-test boot (~50 ms × 3
  tests) for now. Documented in `tests/topology_roundtrip.rs` module
  docstring.

## Sign-off

All AC bullets either ✅ delivered or ⚠️ adapted with file:line evidence
in the relevant sub-task PR description and replicated above.

* Local: 5 / 5 tests pass on macOS.
* CI: both `ubuntu-latest` and `macos-latest` matrix entries pass on
  ST-4 PR #466 (final run before merge).
* All four implementation sub-tasks merged to `master`.
* No Bug Sub-task opened.

Story AAASM-1066 is ready to close as **Done**.

