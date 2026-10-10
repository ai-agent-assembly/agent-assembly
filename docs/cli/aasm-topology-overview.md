# `aasm topology overview`

<a id="cmd-aasm-topology-overview"></a>

Show fleet-wide topology overview

## Synopsis

```text
Usage: aasm topology overview [OPTIONS]
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--status` | `<STATUS>` | Filter agents by status (active, suspended, deregistered) |
| `--show-budget` |  | Include governance level in agent nodes |

## Examples

```text
  aasm topology overview
  aasm topology overview --output json
  aasm topology overview --status active
```

