# `aasm proxy start`

<a id="cmd-aasm-proxy-start"></a>

Spawn the aa-proxy sidecar in the background (or foreground with --no-detach)

## Synopsis

```text
Usage: aasm proxy start [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--listen` | `<LISTEN>` | Address the proxy should listen on [default: 127.0.0.1:8899] |
| `--gateway` | `<GATEWAY>` | Gateway URL to forward policy decisions to |
| `--ca-dir` | `<CA_DIR>` | Directory for CA certificate and key storage |
| `--no-detach` |  | Run in the foreground instead of daemonizing |
| `--log-file` | `<LOG_FILE>` | File to redirect proxy stdout/stderr to (background mode only) |

