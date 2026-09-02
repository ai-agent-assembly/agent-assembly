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

### Retention window and scope

`warm_days` is a **span** that follows the hot window, not an absolute age —
the cold action fires once a row's total age reaches `hot_days + warm_days`.
At the shipped defaults (`hot_days: 30`, `warm_days: 90`) that is **120
days**, not 90.

`cold_action: archive` is **rejected** at configuration time — neither the
Postgres nor the SQLite backend implements archival, so `drop` is the only
supported cold action. Selecting `archive` fails validation before any
retention pass runs (`aasm admin run-retention` and the gateway's own
scheduled sweep alike); it does not fall back to `drop` or take any other
implicit action.

This command only ever touches the `audit_events` table — retention here has
no effect on any other audit record the gateway or its adjacent services
produce. See [Audit assurance](../security/audit-assurance.md#what-is-retained-and-what-is-deleted)
for the full inventory of the four distinct audit records, their individual
bounds, and what deletes each one.
