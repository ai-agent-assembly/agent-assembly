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
Trace: 7f3a1c2b
├─ ●  LLM gpt-4  1200ms
│  ├─ ●  TOOL search  340ms
│  │  └─ ←  RESULT search  12ms
│  └─ ❌ DENY file_write  0ms  (path outside allowlist)
└─ ●  LLM gpt-4  800ms
```

Each event line is `<icon> <label>  <duration>`, where the icon encodes the
event kind (`●  LLM`, `●  TOOL`, `←  RESULT`, `✅ ALLOW`, `❌ DENY`). Policy
denials still carry a duration and are printed in red with the violation reason
appended in parentheses.

Timeline view:

```bash
aasm trace 7f3a1c2b --format timeline
```

The timeline flattens every event (including nested ones) into one row each,
prefixed with a `Timeline: <session_id>` header. Each row is a fixed-width
uppercase kind tag and label, an ASCII bar sized relative to the longest event,
and the duration:

```text
Timeline: 7f3a1c2b
LLM    gpt-4                ████████████████████████████████████████  1200ms
TOOL   search              ███████████                                340ms
RESULT search              █                                          12ms
DENY   file_write                                                     0ms
LLM    gpt-4               ███████████████████████████                800ms
```
