# aasm alerts

Manage governance alerts — list, inspect, and resolve.

## Synopsis

```text
aasm alerts <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`list`](#aasm-alerts-list) | List governance alerts. |
| [`get`](#aasm-alerts-get) | Show full detail for one alert. |
| [`resolve`](#aasm-alerts-resolve) | Resolve an alert. |

All subcommands accept the [global options](overview.md#global-options).

---

## aasm alerts list

List governance alerts as a color-coded table, with optional filters.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--agent <AGENT>` | string | — | Filter by agent ID. |
| `--severity <SEVERITY>` | string | — | Filter by severity (`critical`, `warning`, `info`). |
| `--status <STATUS>` | string | `unresolved` | Filter by status (`unresolved`, `acknowledged`, `resolved`). |

```bash
aasm alerts list --severity critical
```

```text
ID       SEVERITY   CATEGORY          STATUS       MESSAGE
al-301   critical   budget            unresolved   team:research over daily cap
al-298   warning    policy_violation  unresolved   file_write denied (agent a1b2c3…)
```

---

## aasm alerts get

Render a detailed key-value view of one alert.

| Argument | Type | Description |
|---|---|---|
| `<ALERT_ID>` | string | Alert ID to inspect. |

```bash
aasm alerts get al-301
```

---

## aasm alerts resolve

Resolve an alert, optionally attaching a note.

| Name | Type | Default | Description |
|---|---|---|---|
| `<ALERT_ID>` | string (arg) | — | Alert ID to resolve. |
| `--reason <REASON>` | string | — | Optional resolution note. |
| `--force` | flag | off | Skip the confirmation prompt. |

```bash
aasm alerts resolve al-301 --reason "raised team cap" --force
```

```text
Alert al-301 resolved.
```
