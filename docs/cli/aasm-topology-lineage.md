# `aasm topology lineage`

<a id="cmd-aasm-topology-lineage"></a>

Show ancestry chain for a given agent

## Synopsis

```text
Usage: aasm topology lineage [OPTIONS] <AGENT_ID>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<AGENT_ID>` | `<AGENT_ID>` | Agent ID (hex-encoded UUID) *(required)* |
| `--show-permissions` |  | After the lineage, also print the agent's effective capability set with cascade provenance |

## Examples

```text
  aasm topology lineage aabbccdd00112233aabbccdd00112233
  aasm topology lineage aabbccdd00112233aabbccdd00112233 --output json
  aasm topology lineage aabbccdd00112233aabbccdd00112233 --show-permissions
```

