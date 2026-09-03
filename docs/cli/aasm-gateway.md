# `aasm gateway`

<a id="cmd-aasm-gateway"></a>

Manage the aa-gateway governance daemon — agent registry, policy engine, audit log

## Synopsis

```text
Usage: aasm gateway <COMMAND>
```

## Subcommands

| Command | Description |
|---------|-------------|
| [`aasm gateway start`](aasm-gateway-start.md#cmd-aasm-gateway-start) | Spawn aa-gateway as a detached background process |
| [`aasm gateway stop`](aasm-gateway-stop.md#cmd-aasm-gateway-stop) | Terminate a running aa-gateway gracefully (SIGTERM → SIGKILL fallback) |
| [`aasm gateway status`](aasm-gateway-status.md#cmd-aasm-gateway-status) | Report whether aa-gateway is running and serving gRPC |
| [`aasm gateway logs`](aasm-gateway-logs.md#cmd-aasm-gateway-logs) | Tail the gateway log file |

