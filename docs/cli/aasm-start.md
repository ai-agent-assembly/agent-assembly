# `aasm start`

<a id="cmd-aasm-start"></a>

Start the locally-managed Agent Assembly gateway process

## Synopsis

```text
Usage: aasm start [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--mode` | `<MODE>` (`local`, `remote`) | Deployment mode to start [default: local] |
| `--port` | `<PORT>` | TCP port the gateway should listen on [default: 7391] |
| `--config` | `<CONFIG>` | Path to the YAML config file consumed by the gateway [default: ~/.aasm/config.yaml] |
| `--foreground` |  | Stay in the foreground; do not daemonize |
| `--no-dashboard` |  | Disable dashboard serving even in local mode |

