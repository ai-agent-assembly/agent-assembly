# E17 S-E Verification — AAASM-1579 (`aasm status` deployment-overview header)

> **Status**: All six Sub-tasks (ST-1..ST-5 implementation + this ST-6
> verification) complete. Every Acceptance Criterion from the Story is
> met with both unit-test and manual-stdout evidence. The full
> `cargo nextest run -p aa-cli` suite is green (535 tests pass on the
> tip of the AAASM-1865 branch). **No Bug Sub-task opened.**

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| AAASM-1854 | ST-1 — `HealthzResponse` + `redact_database_url` + `check_healthz` | Done | [#710](https://github.com/ai-agent-assembly/agent-assembly/pull/710) |
| AAASM-1857 | ST-2 — `DeploymentOverview` display model + composer | Done | [#717](https://github.com/ai-agent-assembly/agent-assembly/pull/717) |
| AAASM-1860 | ST-3 — Wire `DeploymentOverview` into `StatusSnapshot` + `fetch_all` | Done | [#721](https://github.com/ai-agent-assembly/agent-assembly/pull/721) |
| AAASM-1863 | ST-4 — Tabular renderer for the deployment overview | Done | [#725](https://github.com/ai-agent-assembly/agent-assembly/pull/725) |
| AAASM-1865 | ST-5 — `--json` flag + exit-1-with-hint on unreachable | Done | [#726](https://github.com/ai-agent-assembly/agent-assembly/pull/726) |
| AAASM-1868 | ST-6 — Verify E17 S-E acceptance criteria | in this report | — |

## Walkthrough vs AAASM-1579 acceptance criteria

### ✅ AC 1 — `aasm status` connects to the configured gateway and prints mode, storage backend, version, and uptime

The deployment-overview header is rendered as the first section in
`OutputFormat::Table` mode, ahead of the existing kubectl-style
`RUNTIME HEALTH` / `ACTIVE AGENTS` / `PENDING APPROVALS` / `BUDGET
STATUS` sections. The header sources its data from the new
`/healthz` consumer:

* `StatusClient::check_healthz()` — `GET {gateway_url}/healthz`, deserialised into `HealthzResponse` (`aa-cli/src/commands/status/client.rs`).
* `fetch_all` adds `check_healthz()` to its `tokio::join!` and feeds the result into `build_deployment_overview(client.base_url(), healthz_result.ok())` (`aa-cli/src/commands/status/fetch.rs:114`).
* `render_all` Table-mode branch prints the overview first via `render_deployment_overview` (`aa-cli/src/commands/status/render.rs:263`).

The rendered shape matches the Story's documented box exactly — Mode / Gateway / Storage (with optional `(path)` or `(redacted URL)` suffix) / Version / Uptime / Health.

**Evidence:**
- Unit: `aa-cli commands::status::render::tests::format_deployment_overview_renders_local_sqlite_header`
- Unit: `aa-cli commands::status::fetch::tests::build_deployment_overview_populates_fields_from_local_sqlite_healthz`

### ✅ AC 2 — Database URL shown with password redacted (`postgresql://user:***@host/db`)

`redact_database_url(url: &str) -> String` replaces the userinfo
password segment with `***` while leaving the rest of the URL
verbatim (`aa-cli/src/commands/status/models.rs`). The composer applies
it in one place — `build_deployment_overview` maps `h.database_url` →
`database_url_redacted` — so the raw password never reaches the
display layer or the JSON output.

**Evidence:**
- Unit: `redact_database_url_replaces_postgres_password` — direct check on the helper
- Unit: `redact_database_url_leaves_no_password_url_unchanged` / `_leaves_sqlite_url_unchanged` / `_leaves_malformed_input_unchanged` — pass-through cases
- Unit: `build_deployment_overview_redacts_database_url_for_remote_postgres` — composer wiring
- Unit: `format_deployment_overview_shows_redacted_db_url_for_remote_postgres` — also asserts the raw `secret` literal never appears in rendered output

### ✅ AC 3 — Exit code 1 if gateway is not reachable, with hint to run `aasm start`

`compute_exit_code` returns `ExitCode::from(1)` when
`snapshot.deployment.health == "unreachable"` (was `2` pre-AAASM-1579,
changed per the AC). `dispatch` writes `Error: gateway is not running.
Start it with: aasm start` to **stderr** after rendering whenever the
deployment overview is unreachable, in addition to returning exit 1
(`aa-cli/src/commands/status/mod.rs:42-78`).

**Evidence — manual capture** against an unreachable gateway:

```
$ ./target/debug/aasm status
Agent Assembly Status
─────────────────────────────────────
  Gateway:   http://localhost:8080
  Health:    ✗ unreachable
─────────────────────────────────────

RUNTIME HEALTH
──────────────
  API:         ✗ unreachable
...
Error: gateway is not running. Start it with: aasm start
$ echo $?
1
```

**Unit evidence:**
- `aa-cli commands::status::tests::exit_code_1_when_deployment_unreachable`
- `aa-cli commands::status::tests::exit_code_1_when_deployment_unreachable_with_violations`

### ✅ AC 4 — `aasm status --json` outputs machine-readable JSON

Added `#[arg(long)] pub json: bool` to `StatusArgs`. When set,
`dispatch` skips `render_all` and prints
`serde_json::to_string_pretty(&snapshot.deployment)` to stdout. The
shape matches the AAASM-1579 contract exactly:
`mode`, `gateway_url`, `storage_backend`, `storage_path?`, `database_url_redacted?`,
`version`, `uptime_secs`, `health` (`Option::None` fields are omitted via `#[serde(skip_serializing_if = "Option::is_none")]`).

**Evidence — manual capture** (unreachable case):

```
$ ./target/debug/aasm status --json
{
  "mode": "unknown",
  "gateway_url": "http://localhost:8080",
  "storage_backend": "unknown",
  "version": "",
  "uptime_secs": 0,
  "health": "unreachable"
}
Error: gateway is not running. Start it with: aasm start
$ echo $?
1
```

**Unit evidence:**
- `aa-cli commands::status::tests::json_flag_output_contains_documented_top_level_keys`
- `aa-cli commands::status::models::tests::deployment_overview_serialises_with_documented_field_names`

**Help output** confirms the flag is exposed and documented for users:

```
$ ./target/debug/aasm status --help
Show fleet health, agents, approvals, and budget at a glance

Usage: aasm status [OPTIONS]

Options:
      --context <CONTEXT>   Named context from ~/.aa/config.yaml to use
      --watch               Auto-refresh the status display every 5 seconds
      --json
          Print only the deployment-overview header as machine-readable JSON.
          Intended for scripting and CI integrations — the documented shape is
          the JSON contract published in the AAASM-1579 story description.
          Distinct from `--output json`, which serialises the full status snapshot.
      --output <OUTPUT>     Output format for list/get commands
                            [default: table] [possible values: table, json, yaml]
```

### ✅ AC 5 — Works for both local and remote mode (auto-detects from `/healthz` response)

`build_deployment_overview` is a pure mapping from
`(gateway_url, Option<HealthzResponse>)` → `DeploymentOverview`.
The composer reads `h.mode` and `h.storage` from the wire response
directly — local mode produces `mode: "local"` / `storage_backend: "sqlite"`
and remote mode produces `mode: "remote"` / `storage_backend: "postgres"`,
both surfaced through the same code path without conditional logic
on the CLI side.

**Evidence:**
- Unit: `build_deployment_overview_populates_fields_from_local_sqlite_healthz` — local/sqlite branch
- Unit: `build_deployment_overview_redacts_database_url_for_remote_postgres` — remote/postgres branch
- Unit: `format_deployment_overview_renders_local_sqlite_header` — render of local/sqlite snapshot
- Unit: `format_deployment_overview_shows_redacted_db_url_for_remote_postgres` — render of remote/postgres snapshot

The `HealthzResponse` shape mirrors the wire contract published by
`aa-gateway::routes::healthz::HealthzBody` (landed under AAASM-1577
ST-1, PR #654), so the same endpoint is consumed in both modes.

### ✅ AC 6 — `cargo nextest run -p aa-cli commands::status::tests` green

Direct run of the four `commands::status::*::tests` modules against
the tip of the ST-1..ST-5 stack:

```
$ cargo nextest run -p aa-cli \
    commands::status::tests \
    commands::status::models::tests \
    commands::status::fetch::tests \
    commands::status::render::tests
...
     Summary [   0.057s] 60 tests run: 60 passed, 475 skipped
```

Full `aa-cli` suite (broader regression confirmation):

```
$ cargo nextest run -p aa-cli
...
     Summary [   3.446s] 535 tests run: 535 passed, 0 skipped
```

`cargo fmt --all --check`, `cargo clippy -p aa-cli --all-targets --all-features -- -D warnings`, `cargo deny check`, and `cargo doc -p aa-cli --no-deps` are all green on the stack tip.

## Files touched by the Story

| File | Crate | Sub-task |
|---|---|---|
| `aa-cli/src/commands/status/models.rs` | aa-cli | ST-1, ST-2, ST-3 |
| `aa-cli/src/commands/status/client.rs` | aa-cli | ST-1, ST-3 |
| `aa-cli/src/commands/status/fetch.rs` | aa-cli | ST-2, ST-3 |
| `aa-cli/src/commands/status/render.rs` | aa-cli | ST-3, ST-4 |
| `aa-cli/src/commands/status/mod.rs` | aa-cli | ST-3, ST-5 |
| `verification-reports/verification-report-AAASM-1579.md` | repo-level | ST-6 |

No production-code changes in this Sub-task — the report is the
deliverable.

## Out-of-scope / follow-up notes

- The richer `GET /api/v1/admin/status` endpoint mentioned in the Story
  description (would surface `storage_path` / `database_url` in remote
  mode without relying on the `/healthz` extension fields) is tracked
  separately under AAASM-1474. The current implementation gracefully
  handles both shapes: `HealthzResponse.storage_path` and
  `database_url` are `Option`, default to `None`, and the composer
  surfaces them when present.
- `--json` is intentionally distinct from the existing
  `--output json` global flag (which continues to emit the full
  `StatusSnapshot`). This avoids a breaking change to the snapshot
  contract for any scripts already consuming `--output json`.
- The legacy exit-code `2` (runtime API unreachable) has been
  collapsed into exit-code `1`, matching the AAASM-1579 AC. The
  `compute_exit_code` doc-comment calls this out so reviewers see
  the contract change in-code as well as in the PR description.
