# `aasm topology tree`

<a id="cmd-aasm-topology-tree"></a>

Render a subtree rooted at a given agent

## Synopsis

```text
Usage: aasm topology tree [OPTIONS] <AGENT_ID>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `<AGENT_ID>` | `<AGENT_ID>` | Root agent ID (hex-encoded UUID) *(required)* |
| `--max-depth` | `<DEPTH>` | Maximum traversal depth from the root (default 10) |
| `--status` | `<STATUS>` | Filter tree nodes by status |
| `--show-budget` |  | Include governance level in tree nodes |

