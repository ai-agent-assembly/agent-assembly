# Proxy Prevention-Evidence Retention

The sidecar proxy (`aa-proxy`) can persist the refusals it makes — egress
denylist, egress allowlist, SSRF-blocked address, plaintext LLM downgrade, and
MCP `tools/call` denials — to a local JSONL file. These are the proxy's
strongest prevention evidence: each refusal is applied before any dial exists on
the code path, so the 403 is written *instead of* the bytes going.

This page states what that file holds, how long it holds it, what is deleted,
how to configure all of it, and which side of the SaaS/open-source line owns
durable retention.

> **Read this first.** The proxy's JSONL sink is **bounded local operational
> storage** — a fixed-size ring of recent evidence on one host. It is not a
> compliance-grade archive. Rotation deletes earlier prevention records, and
> nothing in the open-source build replicates them off the host. That deletion
> is counted and published, so it is visible rather than silent, but it is real.
>
> This sink is also **not** the gateway's hash-chained, tamper-evident audit
> tier. That is a separate record with separate guarantees and its own retention
> settings — see [Audit](../introduction/concepts.md#audit) and
> [Compliance Export](compliance-export.md). Byte offsets are confined to that
> tier (ADR 0032 §9) and never appear here.

## Enabling the sink

Persistence is opt-in. With `AA_PROXY_AUDIT_JSONL_PATH` unset, the proxy
persists nothing and the data path is unchanged.

```bash
export AA_PROXY_AUDIT_JSONL_PATH=/var/lib/aasm/proxy-audit.jsonl
```

A configured path that cannot be opened is a startup error, not a silent
downgrade: an operator who believes an audit trail exists and has none is the
situation this whole surface exists to prevent.

## What is retained

One JSON object per line, per intercepted request:

| Field | Content |
|---|---|
| `ts_ms`, `agent_id`, `host`, `method`, `path` | When, which agent, and what it addressed. The path is redacted before it is written. |
| `decision` | `forwarded`, `forwarded_redacted`, `blocked`, or `answered_locally`. |
| `refusal_rule` | Which control refused it, when a rule did. |
| `execution` | What was observed about whether the payload left the process. |
| `probe_correlation` | Set when the request was a protection probe's own synthetic traffic. |
| `credential_findings` | Category and redaction label per match — `{kind, matched}`. |
| `redacted_body` | The post-scan body, capped at 8 KiB. |

### What is never written

- **No raw sensitive value.** The body persisted is the post-scan projection. If
  re-inspection reports the post-scan bytes as still carrying a secret, the body
  is omitted entirely rather than written.
- **No byte offsets.** ADR 0032 §9 permits offsets only in the tamper-evident
  tier, and this sink is not that tier. File permissions are access control; §9
  is about what may exist in the record at all, and the two are not substitutes.

### File permissions

The sink, every rotated segment, the completeness sidecar, every exported
segment, and every temporary staging file are `0600`; a configured export
directory is `0700`. An existing file's mode is re-asserted on open, so a file
left behind by an older build is tightened rather than inherited.

## What is deleted, and when

The proxy rotates the file itself rather than leaving it to `logrotate`. It has
to: the writer holds the file descriptor for the lifetime of the process and
never reopens it, so an external tool that renames or unlinks the file would
leave the proxy appending to an unlinked inode. An operator who configured
external rotation would end up with *less* evidence than one who configured
none, and no way to notice.

The live file is `<path>`; rotated segments are `<path>.1` (most recent) through
`<path>.N`.

### Two bounds, both ceilings

| Bound | Setting | Default | Deletes when |
|---|---|---|---|
| Size | `AA_PROXY_AUDIT_MAX_SEGMENT_BYTES`, `AA_PROXY_AUDIT_RETAINED_SEGMENTS` | 32 MiB × 3 | A segment falls past the retained count. |
| Age | `AA_PROXY_AUDIT_RETENTION_DAYS` | unset — no age bound | A segment's newest record is older than the period. |

A segment is kept only if it satisfies **both**. Deletion is the union of the
two triggers; retention is their intersection. Neither bound is a floor.

### The rule when the two disagree: size wins

`AA_PROXY_AUDIT_RETENTION_DAYS` is a **maximum age, not a reservation of
disk**. Setting it to 90 does not guarantee ninety days of evidence — it
guarantees that nothing older than ninety days survives. Under enough traffic
the size bound will discard a segment the age bound would have kept.

That case is not left to be inferred. It increments `retention_shortfalls` in
the completeness sidecar and logs a warning naming the segment, so an operator
who configured ninety days and is actually getting six hours learns it then,
rather than at the quarter-end question they cannot answer.

The converse never happens: the age bound only ever deletes, so it cannot push
the sink past its size bound.

To actually retain ninety days you must size the ring for ninety days of your
traffic, export the segments off the host, or both. `retention_shortfalls`
staying at zero is the check that you have.

### Granularity of the age bound

Segments are deleted whole. A rotated segment expires once its *newest* record
is past the period, so no record is deleted before its age is up; the live
segment is rotated once its *oldest* record reaches the period, so a quiet proxy
cannot hold a segment open indefinitely. A single record therefore survives at
least the configured period and at most roughly twice it. The age bound is
re-checked on a timer, so it is honoured on an idle host and not only when
traffic arrives.

## Getting evidence off the host

```bash
export AA_PROXY_AUDIT_EXPORT_DIR=/var/lib/aasm/proxy-audit-spool
```

Each rotated segment is copied into that directory, whole, staged through a
dotted `.part` sibling and renamed so a collector never reads a half-copied
file. Delivery is **at-least-once**: every segment still in the ring is
re-offered on every rotation and every sweep, including after a restart, and the
target name is derived from the segment's own content so re-offering an
already-delivered segment is a no-op rather than a duplicate.

Export runs in the writer task and never touches the enforcement path — a slow
or wedged collector costs audit latency and nothing else.

A failed export is counted in `export_failures` and left outstanding in
`pending_exports`; it is never reported as delivered. This matters more than it
may look: an exporter that fails silently is *worse* than none, because it turns
a known-lossy local ring into an assumed-complete remote record.

**What is not promised:** that every segment is exported before the ring
discards it. Guaranteeing that would mean blocking rotation on the collector,
and rotation is what keeps the disk from filling. A segment discarded while
still pending leaves `export_failures` non-zero and the window lossy.

## Reading the sink honestly

Beside the sink the proxy publishes `<path>.completeness.json`, rewritten
whenever the figures move.

```json
{
  "updated_ms": 1765000000000,
  "dropped_entries": 0,
  "discarded_segments": 2,
  "expired_segments": 0,
  "retention_shortfalls": 2,
  "write_failures": 0,
  "export": "local_ring_only",
  "export_failures": 0,
  "pending_exports": 0,
  "window": "lossy",
  "retention": { "max_segment_bytes": 33554432, "retained_segments": 3, "max_age_secs": 7776000 },
  "oldest_retained_ms": 1764900000000
}
```

| Field | Means |
|---|---|
| `window` | `complete` = every record this sink accepted is still in it. `lossy` = records are missing and what remains is a lower bound. |
| `dropped_entries` | Records the data path produced that never reached the writer, because the queue was full and the proxy chose to drop rather than stall a request. |
| `discarded_segments` | Segments the **size** bound deleted. |
| `expired_segments` | Segments the **age** bound deleted — the deletion you asked for. |
| `retention_shortfalls` | Segments the size bound took while the age bound would have kept them: the configured period was not met. |
| `write_failures` | Appends, flushes or rotations the sink could not complete — a full disk, or a record torn by an interrupted process. |
| `export` | `local_ring_only` or `directory`. |
| `export_failures` / `pending_exports` | Handoffs that failed, and segments still outstanding. |
| `oldest_retained_ms` | The window's actual left edge: a rate computed from this file covers this instant onward. |

Three states, not two:

- **`window: "complete"`** — nothing was lost. A zero refusal count here is an
  absence of refusals.
- **`window: "lossy"`** — records were removed. A zero refusal count here means
  nothing; the denominator is unknown.
- **No sidecar file at all** — *unknown*. The sink may never have been opened.
  Do not read a missing file as either of the other two.

An expiry counts as loss even though it is the deletion you configured. From a
consumer's side the record is gone either way, and "the deletion was intended"
is not an argument that the remaining window is the whole one — which is the
only question `window` answers.

The counters describe **the file, not the process**: the baseline is read back
at open, so restarting the proxy does not erase an earlier window's loss.

## Failure behaviour

| Situation | Behaviour |
|---|---|
| **Disk full** | The failed append, flush or rotation increments `write_failures` and the window becomes lossy. The proxy does **not** stall the data path and does **not** exit — an intercepted request must not fail because the audit disk filled, and a proxy that quits on a full disk turns a recording problem into an outage. |
| **Restart** | The sink is reopened in append mode and the completeness baseline is read back, so loss recorded by an earlier process is carried forward, not reset. Segments already in the ring are re-offered to the exporter. |
| **Crash mid-append** | The torn final line is closed on the next open, so the damage stays confined to the record that was actually torn and the next record starts clean. That record is counted in `write_failures`. A line-by-line reader recovers everything else; rotation never splits a record across two segments. |
| **Writer falling behind** | The data path uses a non-blocking send on a 1024-slot queue and drops rather than stalling an intercepted request. Drops increment `dropped_entries`. |
| **Misconfigured setting** | Rejected at startup. An unparseable retention period is an error, not a fallback to the default. |

## SaaS and open source

Per project policy, complete functionality is delivered as SaaS and
limited-function self-hosting is supported. For this surface specifically:

| Capability | Owner |
|---|---|
| Bounded local ring, configurable by size and by age | Open source |
| Counting and publishing every deletion and every failure | Open source |
| Sealing rotated segments into a local directory for a collector | Open source |
| Durable replication that outlives the host, managed retention, long-horizon compliance evidence | SaaS |

The open-source default is `export: "local_ring_only"`, and it is published as a
named state rather than an omitted field on purpose. "No exporter configured"
and "retention is fine" are different facts, and an operator must not read the
first as the second. The proxy also logs this at startup whenever no export
target is set.

## Sizing

A record is roughly 250 bytes with no body and no findings. The two unbounded
parts are capped — 8 KiB of post-scan body and 256 finding rows — so about
24 KiB is the worst case for one line. The defaults hold on the order of 500k
typical records and bound the sink at
`(retained_segments + 1) × max_segment_bytes` = 128 MiB whatever the traffic.

To size for a period rather than a volume, measure your refusal rate, multiply,
and then verify by checking that `retention_shortfalls` stays at zero.

## Settings reference

| Variable | Default | Purpose |
|---|---|---|
| `AA_PROXY_AUDIT_JSONL_PATH` | unset | Path to the sink. Unset means no persistence. |
| `AA_PROXY_AUDIT_MAX_SEGMENT_BYTES` | `33554432` (32 MiB) | Bytes a segment may reach before rotating. Must be at least 8192. |
| `AA_PROXY_AUDIT_RETAINED_SEGMENTS` | `3` | Rotated segments kept beside the live file. |
| `AA_PROXY_AUDIT_RETENTION_DAYS` | unset | Maximum age of a segment. Unset means no age bound. |
| `AA_PROXY_AUDIT_EXPORT_DIR` | unset | Directory sealed segments are copied into. Unset means the local ring is the only copy. |

Every default reproduces the behaviour that shipped before these settings
existed, so an upgrade changes nothing until you change something.
