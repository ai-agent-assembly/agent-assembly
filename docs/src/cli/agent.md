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

All subcommands accept the [global options](overview.md#global-options).
`list`, `inspect`, `suspend`, and `resume` honor `--output table|json|yaml`;
`kill` ignores `--output` and always prints a plain-text confirmation.

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
AGENT_ID   NAME           FRAMEWORK   VERSION   STATUS   PID     SESSIONS   LAST_EVENT
a1b2c3…    research-bot   langgraph   1.2.0     Active   48213   3          2026-06-09T14:02:11Z
```

Columns that the server did not supply render as `-` (e.g. `PID`, `SESSIONS`,
`LAST_EVENT` for an agent with no live process or events).

---

## aasm agent inspect

Render a detailed view of a single agent as a two-column `Field | Value` table
(identity, status, tools, PID, sessions, last event, policy violations, and
metadata when present), followed by separate tables for active sessions, recent
events, and recent traces when the agent has any.

### Arguments

| Argument | Type | Description |
|---|---|---|
| `<AGENT_ID>` | string | Hex-encoded agent UUID to inspect. |

### Example

```bash
aasm agent inspect a1b2c3d4e5f600112233445566778899
```

```text
┌───────────────────┬──────────────────────────────────┐
│ Field             ┆ Value                            │
╞═══════════════════╪══════════════════════════════════╡
│ ID                ┆ a1b2c3d4e5f600112233445566778899 │
│ Name              ┆ research-bot                     │
│ Framework         ┆ langgraph                        │
│ Version           ┆ 1.2.0                            │
│ Status            ┆ Active                           │
│ Tools             ┆ search, fetch, summarize         │
│ PID               ┆ 48213                            │
│ Sessions          ┆ 3                                │
│ Last Event        ┆ 2026-06-09T14:02:11Z             │
│ Policy Violations ┆ 0                                │
└───────────────────┴──────────────────────────────────┘

Recent Traces:
┌────────────┬──────────────────────┐
│ SESSION_ID ┆ TIMESTAMP            │
╞════════════╪══════════════════════╡
│ 7f3a…      ┆ 2026-06-09T14:02:11Z │
└────────────┴──────────────────────┘
Tip: run `aasm trace <session-id>` to visualize a trace
```

`Framework` and `Version` are separate rows. When the agent has metadata,
active sessions, or recent events, those render as their own rows/tables above
the traces section.

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
Agent a1b2c3… suspended.
  Previous status: Active
  New status:      Suspended(Manual)
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
Agent a1b2c3… resumed.
  Previous status: Suspended(Manual)
  New status:      Active
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
Agent a1b2c3… has been killed.
```
