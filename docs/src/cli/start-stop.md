# aasm start / aasm stop

Start and stop the locally-managed Agent Assembly gateway. These are the
high-level developer-laptop commands: `aasm start` picks a deployment mode,
binds the right address, runs the gateway in the background, and (in local
mode) enables the dashboard. `aasm stop` terminates it gracefully and cleans
up the PID file.

> For low-level gateway control (explicit listen address, Unix socket, policy
> path), see [`aasm gateway`](gateway.md).

---

## aasm start

### Synopsis

```text
aasm start [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mode <MODE>` | `local` \| `remote` | `local` | Deployment mode. `local` binds `127.0.0.1` (loopback only); `remote` binds `0.0.0.0`. |
| `--port <PORT>` | integer | `7391` | TCP port the gateway listens on. |
| `--config <CONFIG>` | path | `~/.aasm/config.yaml` | Accepted for a stable operator surface but **not yet wired** — the value is currently a no-op and is not read by the spawned process. |
| `--foreground` | flag | off | Stay in the foreground; do not daemonize. |
| `--no-dashboard` | flag | off | Accepted for a stable operator surface but **not yet wired** — currently a no-op. Dashboard serving is determined by the mode: local mode runs `aa-api-server`, which always serves the dashboard. |

### Behavior

1. Resolve the listen address from `mode` + `port`.
2. Exit early (idempotent) if a gateway is already running at that address —
   verified by a live PID file **and** a successful TCP probe.
3. Spawn the entrypoint binary for the selected mode (background, or foreground
   with `--foreground`): local mode launches `aa-api-server` (which serves the
   dashboard SPA **and** the full `/api/v1/*` REST surface from a single process);
   remote mode launches `aa-gateway` via `--listen`.
4. In background mode, write the PID file and wait for the listener before
   printing the success banner.

Exit `0` on a normal start, an idempotent "already running" path, or a clean
foreground exit. Exit non-zero if the readiness probe times out or the spawn
fails.

### Example

```bash
aasm start --mode local --port 7391
```

```text
✓ Agent Assembly gateway started
  Mode:    local
  Address: http://localhost:7391
  PID:     48213
```

---

## aasm stop

### Synopsis

```text
aasm stop [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--timeout <TIMEOUT>` | integer (seconds) | `30` | Seconds to wait for graceful shutdown before sending SIGKILL. |

### Behavior

Resolves the PID file (`~/.aasm/gateway.pid`) and chooses one of four terminal
states — no PID file, stale PID file, graceful SIGTERM, or escalated SIGKILL —
always cleaning up the PID file so the next `aasm start` sees a clean slate.

### Example

```bash
aasm stop --timeout 15
```

```text
Gateway stopped (PID 48213).
```