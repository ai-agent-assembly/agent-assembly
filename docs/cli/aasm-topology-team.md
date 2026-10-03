# `aasm topology team`

<a id="cmd-aasm-topology-team"></a>

Show all agents in a team

## Synopsis

```text
Usage: aasm topology team [OPTIONS] <TEAM_ID>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<TEAM_ID>` | `<TEAM_ID>` | Team ID *(required)* |
| `--status` | `<STATUS>` | Filter members by status |
| `--show-budget` |  | Include governance level in agent nodes |

## Examples

```text
  aasm topology team team-abc123
  aasm topology team team-abc123 --output json
  aasm topology team team-abc123 --status active
  aasm topology team team-abc123 --show-budget
```

