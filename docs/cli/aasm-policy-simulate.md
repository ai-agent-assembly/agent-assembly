# `aasm policy simulate`

<a id="cmd-aasm-policy-simulate"></a>

Simulate a policy against historical events or live traffic (dry-run)

## Synopsis

```text
Usage: aasm policy simulate [OPTIONS] --policy <POLICY>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--policy` | `<POLICY>` | Path to the policy YAML file to simulate *(required)* |
| `--against` | `<AGAINST>` | Path to an audit log JSONL file to replay against the policy |
| `--live` |  | Observe live agent traffic instead of replaying a file [default: false] |
| `--duration` | `<DURATION>` | Duration for live simulation (e.g. "60s", "5m") |
| `--output-file` | `<OUTPUT_FILE>` | Path to write the simulation report JSON.  Named `--output-file` (not `--output`) to avoid collision with the top-level global `--output <OutputFormat>` flag. |

