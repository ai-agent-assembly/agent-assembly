# aasm logs

Query and stream audit-log events. In default mode it fetches recent entries
over HTTP; with `--follow` it streams events live over the gateway WebSocket
(like `tail -f`).

## Synopsis

```text
aasm logs [OPTIONS]
```

This command has no subcommands.

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --follow` | flag | off | Stream events in real time over WebSocket. |
| `--agent <AGENT>` | string | — | Filter by agent identifier. |
| `--type <TYPE>` | comma-separated | — | Filter by event type(s). Accepted: `violation`, `approval`, `budget`. |
| `--since <SINCE>` | string | — | Show events after this duration (`30m`, `2h`, `1d`) or ISO 8601 timestamp. |
| `--until <UNTIL>` | string | — | Show events before this ISO 8601 timestamp. |
| `--limit <LIMIT>` | integer | `50` | Maximum number of entries in non-follow mode. |
| `--no-color` | flag | off | Disable colored output. |
| `--output <FORMAT>` | `table` \| `json` \| `yaml` | global default | Per-command output override. |

Plus the [global options](overview.md#global-options).

## Examples

Show the last 50 entries:

```bash
aasm logs
```

```text
2026-06-09T14:01:00Z [VIOLATION] a1b2c3…  file_write denied: /etc/passwd
2026-06-09T14:01:05Z [APPROVAL]  a1b2c3…  network_egress pending: api.openai.com
```

Filter to violations and budget events for one agent:

```bash
aasm logs --agent a1b2c3… --type violation,budget --since 1h
```

Stream live (Ctrl-C to stop):

```bash
aasm logs --follow --type violation
```

Emit JSON for piping into `jq`:

```bash
aasm logs --output json --limit 200 | jq '.[].message'
```
