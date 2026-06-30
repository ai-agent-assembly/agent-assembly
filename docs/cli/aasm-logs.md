# `aasm logs`

<a id="cmd-aasm-logs"></a>

Query and stream audit log events

## Synopsis

```text
Usage: aasm logs [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `-f`, `--follow` |  | Stream events in real-time (like `tail -f`). Connects via WebSocket |
| `--agent` | `<AGENT>` | Filter by agent identifier |
| `--type` | `<TYPE>` (`violation`, `approval`, `budget`) | Filter by event type (comma-separated). Accepted: violation, approval, budget |
| `--since` | `<SINCE>` | Show events after this duration or ISO 8601 timestamp (e.g. `30m`, `2h`, `2026-04-30T10:00:00Z`) |
| `--until` | `<UNTIL>` | Show events before this ISO 8601 timestamp |
| `--limit` | `<LIMIT>` | Maximum number of entries to return in non-follow mode [default: 50] |
| `--no-color` |  | Disable colour output |
| `--output` | `<OUTPUT>` (`table`, `json`, `yaml`) | Override the global output format for this command |

