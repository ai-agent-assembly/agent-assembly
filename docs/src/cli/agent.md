# aasm agent

Manage monitored agent processes registered with the gateway.

## Synopsis

```text
aasm agent <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`list`](#aasm-agent-list) | List all registered agents. |
| [`inspect`](#aasm-agent-inspect) | Show detailed information about one agent. |
| [`suspend`](#aasm-agent-suspend) | Suspend a running agent. |
| [`resume`](#aasm-agent-resume) | Resume a suspended agent. |
| [`kill`](#aasm-agent-kill) | Deregister and terminate an agent. |

All subcommands accept the [global options](overview.md#global-options),
including `--output table|json|yaml`.

---

## aasm agent list

List all registered agents, with optional client-side filters.

### Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--status <STATUS>` | string | — | Filter by agent status (e.g. `Active`, `Suspended`, `Deregistered`). |
| `--framework <FRAMEWORK>` | string | — | Filter by agent framework (e.g. `langgraph`, `crewai`). |
| `--watch` | flag | off | Auto-refresh the table every 2 seconds. |

### Example

```bash
aasm agent list --status Active --framework langgraph
```

```text
ID        NAME           FRAMEWORK   VERSION   STATUS    TOOLS
a1b2c3…   research-bot   langgraph   1.2.0     Active    search, fetch
```

---

## aasm agent inspect

Render a detailed key-value view of a single agent: identity, status, tools,
metadata, active sessions, recent events, and recent trace session IDs.

### Arguments

| Argument | Type | Description |
|---|---|---|
| `<AGENT_ID>` | string | Hex-encoded agent UUID to inspect. |

### Example

```bash
aasm agent inspect a1b2c3d4e5f600112233445566778899
```

```text
Agent a1b2c3d4…
  Name:        research-bot
  Framework:   langgraph 1.2.0
  Status:      Active
  PID:         48213
  Sessions:    3
  Violations:  0
  Tools:       search, fetch, summarize
  Recent traces:
    7f3a…  2026-06-09T14:02:11Z   (aasm trace 7f3a…)
```

---

## aasm agent suspend

Suspend a running agent. The reason is logged for audit.

### Arguments / options

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Hex-encoded agent UUID to suspend. |
| `--reason <REASON>` | string | _required_ | Reason for suspending (logged for audit). |
| `--force` | flag | off | Skip the confirmation prompt. |

### Example

```bash
aasm agent suspend a1b2c3… --reason "investigating cost spike" --force
```

```text
Suspended a1b2c3… : Active → Suspended
```

---

## aasm agent resume

Resume a previously suspended agent.

### Arguments

| Argument | Type | Description |
|---|---|---|
| `<AGENT_ID>` | string | Hex-encoded agent UUID to resume. |

### Example

```bash
aasm agent resume a1b2c3…
```

```text
Resumed a1b2c3… : Suspended → Active
```

---

## aasm agent kill

Deregister and terminate an agent.

### Arguments / options

| Name | Type | Default | Description |
|---|---|---|---|
| `<AGENT_ID>` | string (arg) | — | Hex-encoded agent UUID to kill. |
| `--force` | flag | off | Skip the confirmation prompt. |

### Example

```bash
aasm agent kill a1b2c3… --force
```

```text
Killed a1b2c3… — deregistered and terminated.
```
