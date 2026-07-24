# `aasm audit export`

<a id="cmd-aasm-audit-export"></a>

Export audit data in CSV or JSON format

## Synopsis

```text
Usage: aasm audit export [OPTIONS] --format <FORMAT>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--format` | `<FORMAT>` (`csv`, `json`, `jsonl`) | Export file format *(required)* |
| `--compliance` | `<COMPLIANCE>` (`eu-ai-act`, `soc2`) | Compliance report format (adds metadata headers) |
| `--output-file` | `<OUTPUT_FILE>` | Write output to a file instead of stdout.  Renamed from `--output` to `--output-file` to avoid a clap matches-store id collision with the top-level `Cli::output: OutputFormat` global flag — the duplicate id used to panic on downcast at every `aasm audit export` invocation (AAASM-1479). |
| `--agent` | `<AGENT>` | Filter by agent identifier |
| `--action` | `<ACTION>` | Filter by action type |
| `--result` | `<RESULT>` (`allow`, `deny`, `pending`) | Filter by policy decision result |
| `--since` | `<SINCE>` | Show events after this duration or ISO 8601 timestamp |
| `--until` | `<UNTIL>` | Show events before this ISO 8601 timestamp |
| `--limit` | `<LIMIT>` | Maximum number of entries to fetch [default: 1000] |

