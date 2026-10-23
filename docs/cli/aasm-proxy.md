# `aasm proxy`

<a id="cmd-aasm-proxy"></a>

Manage the aa-proxy sidecar — lifecycle, CA trust, and log tailing

## Synopsis

```text
Usage: aasm proxy <COMMAND>
```

## Subcommands

| Command | Description |
|---------|-------------|
| [`aasm proxy start`](aasm-proxy-start.md#cmd-aasm-proxy-start) | Spawn the aa-proxy sidecar in the background (or foreground with --no-detach) |
| [`aasm proxy stop`](aasm-proxy-stop.md#cmd-aasm-proxy-stop) | Stop the running aa-proxy sidecar |
| [`aasm proxy status`](aasm-proxy-status.md#cmd-aasm-proxy-status) | Show whether the aa-proxy sidecar is running |
| [`aasm proxy install-ca`](aasm-proxy-install-ca.md#cmd-aasm-proxy-install-ca) | Install the proxy CA certificate into the OS trust store |
| [`aasm proxy uninstall-ca`](aasm-proxy-uninstall-ca.md#cmd-aasm-proxy-uninstall-ca) | Remove the proxy CA certificate from the OS trust store |
| [`aasm proxy logs`](aasm-proxy-logs.md#cmd-aasm-proxy-logs) | Tail the proxy log file |

