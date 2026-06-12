# aasm audit

Query audit log entries and export tamper-evident compliance reports.

## Synopsis

```text
aasm audit <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`list`](#aasm-audit-list) | Query audit log entries with filters. |
| [`export`](#aasm-audit-export) | Export audit data fetched from the gateway as CSV/JSON/JSONL. |
| [`verify-chain`](#aasm-audit-verify-chain) | Verify the SHA-256 hash chain of a local JSONL audit file. |
| [`compliance-export`](#aasm-audit-compliance-export) | Full-fidelity compliance export of a local JSONL audit file. |

All subcommands accept the [global options](overview.md#global-options).

> **Time filters.** `--since` accepts a duration shorthand (`30m`, `2h`, `1d`)
> or an ISO 8601 timestamp; `--until` accepts an ISO 8601 timestamp.

---

## aasm audit list

Query audit log entries from the gateway (`GET /api/v1/logs`) with optional
filters, rendered as a table (or `--output json|yaml`). The `result` column is
color-coded: allow=green, deny=red, pending=yellow.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--agent <AGENT>` | string | — | Filter by agent identifier. |
| `--action <ACTION>` | string | — | Filter by action type (e.g. `ToolCallIntercepted`, `PolicyViolation`). |
| `--result <RESULT>` | `allow` \| `deny` \| `pending` | — | Filter by policy decision result. |
| `--since <SINCE>` | string | — | Show events after this duration or ISO 8601 timestamp. |
| `--until <UNTIL>` | string | — | Show events before this ISO 8601 timestamp. |
| `--limit <LIMIT>` | integer | `50` | Maximum number of entries to return. |
| `--dry-run-only` | flag | off | Show **only** observe-mode shadow events (`dry_run: true`). When off (default), shadow events are hidden so you see live enforcement decisions only. |

```bash
aasm audit list --result deny --since 2h --limit 20
```

```text
SEQ   TIMESTAMP             AGENT     EVENT             RESULT
142   2026-06-09T14:01:00Z  a1b2c3…   PolicyViolation   deny
```

---

## aasm audit export

Export audit entries fetched from the gateway to CSV/JSON/JSONL, with optional
compliance metadata headers. Writes to stdout unless `--output-file` is given.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format <FORMAT>` | `csv` \| `json` \| `jsonl` | _required_ | Export file format. JSONL is preferred for SIEM ingestion. |
| `--compliance <COMPLIANCE>` | `eu-ai-act` \| `soc2` | — | Prepend a compliance metadata header. |
| `--output-file <OUTPUT_FILE>` | string | _(stdout)_ | Write output to a file. (Named `--output-file` to avoid colliding with the global `--output`.) |
| `--agent <AGENT>` | string | — | Filter by agent identifier. |
| `--action <ACTION>` | string | — | Filter by action type. |
| `--result <RESULT>` | `allow` \| `deny` \| `pending` | — | Filter by policy decision result. |
| `--since <SINCE>` | string | — | Show events after this duration or ISO 8601 timestamp. |
| `--until <UNTIL>` | string | — | Show events before this ISO 8601 timestamp. |
| `--limit <LIMIT>` | integer | `1000` | Maximum number of entries to fetch. |

```bash
aasm audit export --format jsonl --compliance soc2 --since 1d \
  --output-file audit-2026-06-09.jsonl
```

---

## aasm audit verify-chain

Verify the SHA-256 hash chain of a **local** JSONL audit log file. Exits
non-zero if the chain is broken (tamper evidence).

| Argument | Type | Description |
|---|---|---|
| `<PATH>` | path | Path to the JSONL audit log file to verify. |

```bash
aasm audit verify-chain ./audit/session-7f3a.jsonl
```

```text
✓ chain valid — 412 entries, genesis → entry 0xab12…
```

---

## aasm audit compliance-export

Full-fidelity compliance export of a **local** JSONL audit file. Preserves the
SHA-256 hash chain anchors, credential findings (kind + offset only — never
the raw secret), and delegation lineage for SIEM ingestion and regulatory
review.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--input <INPUT>` | path | _required_ | Per-session audit JSONL file produced by the gateway. |
| `--format <FORMAT>` | `csv` \| `json` \| `jsonl` | `jsonl` | Export format. JSONL is preferred for SIEM/regulator ingestion. |
| `--compliance <COMPLIANCE>` | `eu-ai-act` \| `soc2` | — | Prepend a compliance framework header. |
| `--output-file <OUTPUT_FILE>` | path | _(stdout)_ | Write output to a file. |
| `--agent <AGENT>` | string | — | Filter by hex-encoded agent identifier (32 hex chars). |
| `--event-type <EVENT_TYPE>` | string | — | Filter by audit event-type label (e.g. `PolicyViolation`). |
| `--since <SINCE>` | string | — | Include entries after this duration shorthand or ISO 8601 timestamp. |
| `--until <UNTIL>` | string | — | Include entries before this ISO 8601 timestamp. |

```bash
aasm audit compliance-export --input ./audit/session-7f3a.jsonl \
  --format jsonl --compliance eu-ai-act --output-file compliance.jsonl
```
