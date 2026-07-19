# aasm gateway

Manage the `aa-gateway` governance daemon directly — the process that holds
the agent registry, evaluates the policy engine, and writes the audit log.

> `aasm gateway start` runs the gateway with low-level flags (listen address,
> socket, policy path). For the higher-level local developer workflow
> (deployment mode + dashboard), see [`aasm start`](start-stop.md).

## Synopsis

```text
aasm gateway <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`start`](#aasm-gateway-start) | Spawn `aa-gateway` as a detached background process. |
| [`stop`](#aasm-gateway-stop) | Terminate a running gateway (SIGTERM → SIGKILL fallback). |
| [`status`](#aasm-gateway-status) | Report whether the gateway is running and serving gRPC. |
| [`logs`](#aasm-gateway-logs) | Tail the gateway log file. |

---

## aasm gateway start

Spawn `aa-gateway` in the background (or foreground with `--no-detach`). The
binary is resolved in priority order (highest first): alongside the `aasm`
executable itself (a sibling `aa-gateway`), then `$PATH`, then `~/.cargo/bin`,
then `./target/release`, then `./target/debug`.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--policy <POLICY>` | path | `$AA_POLICY` → `~/.aasm/policy.yaml` → `/etc/aasm/policy.yaml` | Policy YAML file. |
| `--listen <LISTEN>` | string | `127.0.0.1:50051` | TCP listen address. |
| `--socket <SOCKET>` | path | — | Unix domain socket path. Takes precedence over `--listen`. |
| `--no-detach` | flag | off | Block the caller instead of detaching to the background. |
| `--log-file <LOG_FILE>` | path | `~/.aasm/logs/gateway.log` | Log file for gateway stdout/stderr. |

```bash
aasm gateway start --listen 127.0.0.1:50051 --policy ./policy.yaml
```

---

## aasm gateway stop

Terminate a running gateway gracefully (SIGTERM, escalating to SIGKILL). Takes
no flags.

```bash
aasm gateway stop
```

---

## aasm gateway status

Report whether `aa-gateway` is running and serving gRPC.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--json` | flag | off | Emit machine-readable JSON instead of human-readable text. |

```bash
aasm gateway status --json
```

```json
{ "running": true, "pid": 48213, "listen": "127.0.0.1:50051", "uptime_seconds": 8133 }
```

---

## aasm gateway logs

Tail the gateway log file, with optional level filtering. Non-JSON lines pass
through so operator notes are preserved.

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --follow` | flag | off | Stream new log entries in real time (like `tail -f`). |
| `--lines <LINES>` | integer | `50` | Number of lines to show from the end of the log. |
| `--level <LEVEL>` | log level | — | Filter entries by minimum severity. |
| `--log-file <LOG_FILE>` | path | `~/.aasm/logs/gateway.log` | Path to the log file. |

```bash
aasm gateway logs --follow --level warn
```
