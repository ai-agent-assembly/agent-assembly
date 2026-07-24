# `aasm policy show`

<a id="cmd-aasm-policy-show"></a>

Show an agent's effective policy view (use `--show-permissions`)

## Synopsis

```text
Usage: aasm policy show [OPTIONS] <AGENT_ID>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<AGENT_ID>` | `<AGENT_ID>` | Hex-encoded agent UUID (32 hex characters) *(required)* |
| `--show-permissions` |  | Print the agent's effective capability set with cascade provenance |
| `--show-budget` |  | Print the agent's budget rollup across agent / team / org / subtree |

## Examples

```text
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-budget
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-permissions --show-budget
  aasm policy show aabbccdd00112233aabbccdd00112233 --show-budget --output json
```

