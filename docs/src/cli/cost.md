# aasm cost

Query cost summary and forecast spending.

## Synopsis

```text
aasm cost <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`summary`](#aasm-cost-summary) | Show cost summary for the current period. |
| [`forecast`](#aasm-cost-forecast) | Forecast monthly spend from the current daily rate. |

Both subcommands accept the [global options](overview.md#global-options).

---

## aasm cost summary

Show the cost summary for a time period, optionally grouped by a dimension.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--period <PERIOD>` | `today` \| `month` | `today` | Time period to report on. |
| `--group-by <GROUP_BY>` | `agent` | — | Group spend by dimension. |

```bash
aasm cost summary --period month --group-by agent
```

```text
AGENT_ID   DAILY_SPEND   MONTHLY_SPEND
a1b2c3…    $6.00         $180.10
d4e5f6…    $4.41         $132.30

COST SUMMARY (Monthly)
──────────────────
  Monthly spend: $312.40
  Budget limit:  $1,000.00
  Utilization:   31.2%
  Date:          2026-06
```

With `--group-by agent`, the per-agent table (always three columns:
`AGENT_ID`, `DAILY_SPEND`, `MONTHLY_SPEND`) prints first, followed by the
global summary. The spend and limit labels read `Daily` for `--period today`
and `Monthly` for `--period month`.

---

## aasm cost forecast

Forecast monthly spending by extrapolating the current daily rate over the
remaining days of the month. Takes no flags of its own (uses the global
`--output`).

```bash
aasm cost forecast
```

```text
COST FORECAST
─────────────
  Date:              2026-06-09
  Day of month:      9/30
  Current daily:     $12.50
  Projected monthly: $375.00
  Monthly limit:     $1,000.00
  Projected util:    37.5%
```
