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
Cost Summary (month, 2026-06)
  Total: $312.40 / $1,000.00  (31.2%)

  AGENT      MONTHLY SPEND
  a1b2c3…    $180.10
  d4e5f6…    $132.30
```

---

## aasm cost forecast

Forecast monthly spending by extrapolating the current daily rate over the
remaining days of the month. Takes no flags of its own (uses the global
`--output`).

```bash
aasm cost forecast
```

```text
Cost Forecast (2026-06-09, day 9 of 30)
  Current daily spend:      $12.50
  Projected monthly spend:  $375.00
  Monthly limit:            $1,000.00
  Projected utilization:    37.5%
```
