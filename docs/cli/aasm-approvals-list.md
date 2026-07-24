# `aasm approvals list`

<a id="cmd-aasm-approvals-list"></a>

List all pending approval requests

## Synopsis

```text
Usage: aasm approvals list [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--output` | `<OUTPUT>` (`table`, `json`, `yaml`) | Output format override for this subcommand |
| `--status` | `<STATUS>` (`pending`, `approved`, `rejected`) | Filter by approval status: `pending`, `approved`, or `rejected`. Omitted ⇒ pending only (matches pre-AAASM-1477 behavior) |
| `--agent` | `<AGENT>` | Filter to approvals submitted by this agent id (exact match) |

