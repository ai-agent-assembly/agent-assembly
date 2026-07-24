# `aasm proxy logs`

<a id="cmd-aasm-proxy-logs"></a>

Tail the proxy log file

## Synopsis

```text
Usage: aasm proxy logs [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `-f`, `--follow` |  | Stream new log entries continuously (like `tail -f`) |
| `--lines` | `<LINES>` | Number of lines to show from the end of the log (default 50) [default: 50] |
| `--level` | `<LEVEL>` | Filter to lines at or above this level: error, warn, info, debug |
| `--since` | `<DURATION>` | Show only entries since a relative duration (e.g., `5m`, `1h`, `30s`) |

