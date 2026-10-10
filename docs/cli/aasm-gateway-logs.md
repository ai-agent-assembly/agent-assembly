# `aasm gateway logs`

<a id="cmd-aasm-gateway-logs"></a>

Tail the gateway log file

## Synopsis

```text
Usage: aasm gateway logs [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `-f`, `--follow` |  | Stream new log entries in real time (like `tail -f`) |
| `--lines` | `<LINES>` | Number of lines to show from the end of the log (default 50) [default: 50] |
| `--level` | `<LEVEL>` (`error`, `warn`, `info`, `debug`) | Filter log entries by minimum severity level |
| `--log-file` | `<LOG_FILE>` | Path to the log file (default ~/.aasm/logs/gateway.log) |

