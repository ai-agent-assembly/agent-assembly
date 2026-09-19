# `aasm audit compliance-export`

<a id="cmd-aasm-audit-compliance-export"></a>

Full-fidelity compliance export of a local JSONL audit log file.

Preserves the SHA-256 hash chain, credential findings, and delegation lineage for SIEM ingestion and regulatory review.

## Synopsis

```text
Usage: aasm audit compliance-export [OPTIONS] --input <INPUT>
```

## Options

| Option | Value | Description |
|--------|-------|-------------|
| `--input` | `<INPUT>` | Path to a per-session audit JSONL file produced by the gateway *(required)* |
| `--format` | `<FORMAT>` (`csv`, `json`, `jsonl`) | Export file format. Defaults to JSONL for SIEM/regulator ingestion [default: jsonl] |
| `--compliance` | `<COMPLIANCE>` (`eu-ai-act`, `soc2`) | Compliance framework header to prepend (EU AI Act or SOC 2) |
| `--output-file` | `<OUTPUT_FILE>` | Write output to a file instead of stdout |
| `--agent` | `<AGENT>` | Filter by hex-encoded agent identifier (32 hex chars) |
| `--event-type` | `<EVENT_TYPE>` | Filter by audit event type label (e.g. `PolicyViolation`) |
| `--since` | `<SINCE>` | Include entries after this duration shorthand (`30m`, `2h`, `1d`) or ISO 8601 timestamp |
| `--until` | `<UNTIL>` | Include entries before this ISO 8601 timestamp |

