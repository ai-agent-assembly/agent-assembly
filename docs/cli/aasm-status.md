# `aasm status`

<a id="cmd-aasm-status"></a>

Show fleet health, agents, approvals, and budget at a glance

## Synopsis

```text
Usage: aasm status [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--watch` |  | Auto-refresh the status display every 5 seconds |
| `--json` |  | Print only the deployment-overview header as machine-readable JSON.  Intended for scripting and CI integrations — the documented shape is the JSON contract published in the AAASM-1579 story description. Distinct from `--output json`, which serialises the full status snapshot. |

