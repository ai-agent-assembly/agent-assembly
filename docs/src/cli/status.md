# aasm status

Show fleet health, agents, approvals, and budget at a glance. `aasm status`
fetches the deployment overview, runtime health, agent list, pending
approvals, cost rollup, and storage health from the gateway in one shot and
renders a dashboard-style summary.

## Synopsis

```text
aasm status [OPTIONS]
```

This command has no subcommands.

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--watch` | flag | off | Auto-refresh the status display every 5 seconds. Runs until interrupted (Ctrl-C). |
| `--json` | flag | off | Print only the deployment-overview header as machine-readable JSON (the AAASM-1579 contract). Distinct from `--output json`, which serializes the full snapshot. |

Plus the [global options](overview.md#global-options).

## Exit code

- `0` — all healthy.
- non-zero — the gateway is unreachable, at least one agent has violations, or
  the storage health probe reports `unavailable`. All failure modes collapse
  to a single non-zero code so shell scripts can gate on it.

## Examples

Show the full status summary:

```bash
aasm status
```

```text
Agent Assembly Status
─────────────────────────────────────
  Mode:      local
  Gateway:   http://localhost:7391
  Storage:   sqlite  (~/.aasm/local.db)
  Version:   0.0.1
  Uptime:    2h 15m 33s
  Health:    ✓ ok
─────────────────────────────────────

ACTIVE AGENTS
─────────────
┌──────────┬──────────────┬───────────┬───────────┬──────────┬──────────────────┬──────────────────┬───────┐
│ AGENT_ID │ NAME         │ STATUS    │ FRAMEWORK │ SESSIONS │ LAST_EVENT       │ VIOLATIONS_TODAY │ LAYER │
╞══════════╪══════════════╪═══════════╪═══════════╪══════════╪══════════════════╪══════════════════╪═══════╡
│ a1b2c3d4 │ research-bot │ ● Running │ langgraph │ 3        │ 2m ago tool_call │ 0                │ sdk   │
└──────────┴──────────────┴───────────┴───────────┴──────────┴──────────────────┴──────────────────┴───────┘

PENDING APPROVALS
─────────────────
  Count:  1
  Oldest: 2m ago

BUDGET STATUS
─────────────
  Daily spend : $12.50 / $50.00  █████░░░░░░░░░░░░░░░  25%
  Date:           2026-04-30
  (no per-agent data)
```

Continuously refresh:

```bash
aasm status --watch
```

Machine-readable deployment header for CI:

```bash
aasm status --json
```

```json
{
  "mode": "local",
  "gateway_url": "http://localhost:7391",
  "storage_backend": "sqlite",
  "storage_path": "~/.aasm/local.db",
  "version": "0.0.1",
  "uptime_secs": 8133,
  "health": "ok"
}
```

Full snapshot as JSON (every section):

```bash
aasm status --output json
```
