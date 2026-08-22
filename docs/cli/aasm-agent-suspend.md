# `aasm agent suspend`

<a id="cmd-aasm-agent-suspend"></a>

Suspend a running agent

## Synopsis

```text
Usage: aasm agent suspend [OPTIONS] --reason <REASON> <AGENT_ID>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<AGENT_ID>` | `<AGENT_ID>` | Hex-encoded agent UUID to suspend *(required)* |
| `--reason` | `<REASON>` | Reason for suspending the agent (logged for audit) *(required)* |
| `--force` |  | Skip the confirmation prompt |

