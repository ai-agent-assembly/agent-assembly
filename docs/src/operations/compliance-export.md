# Compliance Export

`aasm audit compliance-export` produces a full-fidelity export of a
per-session audit JSONL file for downstream regulatory review and SIEM
ingestion. Unlike `aasm audit export` (which queries the live gateway
through `/api/v1/logs` and emits a slim summary view), this command reads
directly from the on-disk JSONL files written by the gateway's
`AuditWriter`, preserving the hash chain, credential findings, and
delegation lineage that an auditor needs to verify integrity offline.

## When to use

Use `aasm audit compliance-export` whenever the produced bytes will leave
the gateway operator's trust boundary — for example:

- Annual EU AI Act / SOC 2 evidence packs.
- Continuous SIEM ingestion (Splunk, ELK, Datadog) where each entry is
  treated as one log line.
- Cold-storage archives that must survive a future schema upgrade.

Use `aasm audit export` for the operational summary view (CSV / JSON
array of the slim REST shape) when you only need a quick at-a-glance
report and the consumer does not need the hash chain.

## Output format

The default `--format jsonl` emits one [`ComplianceRecord`][record] per
line. Each record carries:

| Field | Meaning |
|---|---|
| `seq` | Monotonic sequence within the session. |
| `timestamp` | ISO 8601 UTC. |
| `event_type` | `ToolCallIntercepted`, `PolicyViolation`, etc. |
| `agent_id`, `session_id` | Hex-encoded 16-byte identifiers. |
| `payload` | Pre-serialised JSON of the decision context. |
| `previous_hash`, `entry_hash` | Hex-encoded SHA-256 anchors of the tamper-evident chain. |
| `credential_findings` | Detected credential kinds + byte offsets (never the raw secret). |
| `redacted_payload` | Post-redaction text when the gateway substituted secrets, `null` when clean. |
| `root_agent_id`, `parent_agent_id`, `team_id`, `delegation_reason`, `spawned_by_tool`, `depth` | Lineage fields when the originating entry recorded them. |

`--format json` produces a pretty-printed JSON array of the same records
for human review. `--format csv` produces a flat spreadsheet view with
the regulator-relevant columns plus a `credential_findings_count` and a
boolean `redacted` flag; the payload body and lineage are dropped from
CSV to keep the file approachable in spreadsheet tools — use JSONL for
full fidelity.

## Common invocations

Export an entire session in JSONL to a file:

```bash
aasm audit compliance-export \
  --input  /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --format jsonl \
  --output-file ./session.jsonl
```

Restrict to `PolicyViolation` entries in the last 24 hours and write to
stdout (pipe-friendly):

```bash
aasm audit compliance-export \
  --input      /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --event-type PolicyViolation \
  --since      24h
```

Generate an EU AI Act evidence pack with a regulatory header:

```bash
aasm audit compliance-export \
  --input      /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --format     jsonl \
  --compliance eu-ai-act \
  --output-file ./eu-ai-act-evidence.jsonl
```

The `--compliance` header lines begin with `#` so JSONL ingestors that
treat `#` as a comment skip them automatically; ingestors that do not
should be configured to strip the header band on the way in.

## Verifying the export

The export carries the same hash chain as the source JSONL. To verify
chain integrity offline, run:

```bash
aasm audit verify-chain /var/lib/aa-gateway/audit/session-<hex>.jsonl
```

`verify-chain` consumes the raw on-disk file rather than the export, so
the verifier sees exactly the bytes the gateway wrote. An auditor with
the export and a SHA-256 implementation can independently re-hash each
record's canonical input (see the [audit module
documentation](../api-reference.md) for the canonical bytes layout) and
compare against the embedded `entry_hash`.

## Security invariants

- The export never carries raw credential values. `credential_findings`
  records only `kind`, `offset`, and the `[REDACTED:<Kind>]` label.
- `redacted_payload` (when present) is the scanner's substitution
  output, with raw secret bytes already replaced by
  `[REDACTED:<Kind>]` markers.
- `payload` retains the original (pre-redaction) string only when the
  source entry did so; the gateway's default policy is to replace
  `payload` with `redacted_payload` on persistence when findings exist,
  so by default the export carries no raw secret. Operators who pipe
  pre-redaction payloads downstream do so explicitly via configuration.

[record]: ../api-reference.md#compliancerecord
