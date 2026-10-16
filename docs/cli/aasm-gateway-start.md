# `aasm gateway start`

<a id="cmd-aasm-gateway-start"></a>

Spawn aa-gateway as a detached background process

## Synopsis

```text
Usage: aasm gateway start [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--policy` | `<POLICY>` | Path to the policy YAML file (overrides $AA_POLICY and default locations) |
| `--listen` | `<LISTEN>` | TCP listen address (e.g. "127.0.0.1:50051") [default: 127.0.0.1:50051] |
| `--socket` | `<SOCKET>` | Unix domain socket path. When set, takes precedence over --listen |
| `--no-detach` |  | Block the caller rather than detaching the gateway to the background |
| `--log-file` | `<LOG_FILE>` | Log file path for aa-gateway stdout/stderr (default ~/.aasm/logs/gateway.log) |

