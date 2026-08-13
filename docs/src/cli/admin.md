# aasm admin

Gateway administrative operations. The current scope is manual retention; more
admin subcommands are added as the operator surface grows.

## Synopsis

```text
aasm admin <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`run-retention`](#aasm-admin-run-retention) | Trigger one manual retention pass against the running gateway. |

The subcommand accepts the [global options](overview.md#global-options),
honoring `--output yaml` (defaults to pretty JSON).

---

## aasm admin run-retention

Trigger one manual retention pass (`POST /api/v1/admin/retention-policy/run`).
Exits `0` on a successful pass, non-zero when the gateway is unreachable or
returns a non-2xx status (the error chain is printed to stderr).

| Flag | Type | Default | Description |
|---|---|---|---|
| `--dry-run` | flag | off | Log what would be retained/dropped without taking any action. |

```bash
aasm admin run-retention --dry-run
```

```json
{
  "ran_at": "2026-06-09T14:05:00Z",
  "hot_rows": 14293,
  "compressed_rows": 512,
  "archived_rows": 128,
  "dropped_rows": 0,
  "freed_bytes": 0,
  "dry_run": true
}
```
