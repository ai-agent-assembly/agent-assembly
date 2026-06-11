# aasm dashboard

Real-time governance monitoring. With no subcommand, `aasm dashboard` opens an
interactive terminal (TUI) dashboard. The subcommands manage an embedded
single-page-app (SPA) web server instead.

## Synopsis

```text
aasm dashboard [SUBCOMMAND] [OPTIONS]
```

| Form | Purpose |
|---|---|
| `aasm dashboard` (no subcommand) | Open the interactive TUI dashboard. |
| [`start`](#aasm-dashboard-start) | Serve the embedded SPA over HTTP. |
| [`open`](#aasm-dashboard-open) | Open the browser to an already-running dashboard. |
| [`stop`](#aasm-dashboard-stop) | Stop a dashboard server started with `start`. |

The TUI streams status over HTTP polling plus a WebSocket event feed. Panels:
fleet health + agents, event log, budget bars, and the pending-approvals queue
with countdown timers. Keyboard shortcuts (Tab/Shift-Tab to cycle panels,
arrows to select, `a`/`r` to approve/reject, `p` policy viewer, `?` help,
`q` quit).

The dashboard port resolves from (highest first): `AASM_DASHBOARD_PORT` env
var → `--port` flag → `dashboard.port` in `~/.aa/config.yaml` (default
`3000`).

---

## aasm dashboard start

Serve the embedded SPA at `http://127.0.0.1:<port>`. Blocks until Ctrl-C.
Reverse-proxies `/api/*` to the configured gateway.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port <PORT>` | integer | `3000` (config) | Port to listen on. Overrides config; also reads `AASM_DASHBOARD_PORT`. |
| `--open` | flag | off | Open the system browser once the server is ready. |

```bash
aasm dashboard start --port 8088 --open
```

```text
Dashboard serving at http://127.0.0.1:8088  (Ctrl-C to stop)
```

---

## aasm dashboard open

Open the system browser to an already-running dashboard server.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port <PORT>` | integer | `3000` (config) | Port to connect to. Overrides config; also reads `AASM_DASHBOARD_PORT`. |

```bash
aasm dashboard open --port 8088
```

---

## aasm dashboard stop

Stop a dashboard server previously started with `aasm dashboard start`. Takes
no flags.

```bash
aasm dashboard stop
```

```text
Dashboard server stopped.
```
