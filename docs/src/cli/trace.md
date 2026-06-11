# aasm trace

Visualize a single agent session trace as an indented tree or a horizontal
timeline. The trace is fetched from the gateway and the flat span list is
folded into a hierarchy (LLM calls, tool calls, tool results, policy
allow/deny).

## Synopsis

```text
aasm trace [OPTIONS] <SESSION_ID>
```

This command has no subcommands.

## Arguments

| Argument | Type | Description |
|---|---|---|
| `<SESSION_ID>` | string | Session ID to retrieve the trace for. |

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format <FORMAT>` | `tree` \| `timeline` | `tree` | Visualization format. `tree` = indented box-drawing tree; `timeline` = horizontal ASCII duration bars. |

Plus the [global options](overview.md#global-options).

## Examples

Tree view (default):

```bash
aasm trace 7f3a1c2b
```

```text
session 7f3a1c2b
├─ 🧠 llm: gpt-4 (1200ms)
│  ├─ 🔧 tool_call: search (340ms)
│  │  └─ 📥 tool_result: search (12ms)
│  └─ ⛔ deny: file_write — path outside allowlist
└─ 🧠 llm: gpt-4 (800ms)
```

Timeline view:

```bash
aasm trace 7f3a1c2b --format timeline
```

```text
llm: gpt-4        ████████████████████  1200ms
tool_call: search ██████                 340ms
llm: gpt-4        █████████████          800ms
```
