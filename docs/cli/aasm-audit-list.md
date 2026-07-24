# `aasm audit list`

<a id="cmd-aasm-audit-list"></a>

Query audit log entries with optional filters

## Synopsis

```text
Usage: aasm audit list [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--agent` | `<AGENT>` | Filter by agent identifier |
| `--action` | `<ACTION>` | Filter by action type (e.g. `ToolCallIntercepted`, `PolicyViolation`) |
| `--result` | `<RESULT>` (`allow`, `deny`, `pending`) | Filter by policy decision result |
| `--since` | `<SINCE>` | Show events after this duration or ISO 8601 timestamp (e.g. `30m`, `2h`, `2026-04-30T10:00:00Z`) |
| `--until` | `<UNTIL>` | Show events before this ISO 8601 timestamp |
| `--limit` | `<LIMIT>` | Maximum number of entries to return [default: 50] |
| `--dry-run-only` |  | Show only sandbox / observe-mode shadow events — entries the gateway recorded with `dry_run: true` because policy was evaluated in observe mode (AAASM-1564). When this flag is OFF (the default), shadow events are hidden so operators see only live enforcement decisions |

