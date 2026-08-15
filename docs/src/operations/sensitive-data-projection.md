# Sensitive-Data Projection: enabling, reverting and failure behaviour

The sensitive-data projection is the durable table behind the sensitive-data
analytics surface. It records classification decisions and their findings
alongside the existing audit path.

This page is the operator contract for turning it on, turning it back off, and
knowing what happens when it cannot start. It exists because a revert mechanism
nobody can find is not a revert mechanism ([AAASM-5739](https://lightning-dust-mite.atlassian.net/browse/AAASM-5739)).

## Only the legacy-gRPC serve paths read this setting

Read this before the rest of the page, because setting the variable under the
wrong mode looks like success and produces nothing.

The projection is wired in `serve_tcp` and `serve_uds`, and those are reached
only from `aa-gateway`'s **`legacy-grpc`** mode — the default when neither
`--mode` nor `AA_MODE` is set. `--mode local` and `--mode remote` dispatch to
different entry points that never read this variable:

| Invocation | Reads `AA_SENSITIVE_DATA_PROJECTION_DB`? |
| --- | --- |
| `aa-gateway --policy <path>` (default: `legacy-grpc`) | **Yes** |
| `aasm gateway start --policy <path>` | **Yes** — it spawns `aa-gateway --policy … --listen …` and passes no `--mode` |
| `aasm start --mode remote` | **Yes** — it spawns `aa-gateway --listen …`, also with no `--mode` |
| `aa-gateway --mode local` | No |
| `aa-gateway --mode remote` | No |
| `aasm start --mode local` | No — it spawns `aa-api-server`, not `aa-gateway` |

The two `aasm` rows that read it do so because neither passes `--mode` to the
child, and neither clears the child's environment: the spawned `aa-gateway`
inherits the variable you exported and resolves its own mode from `AA_MODE`.
Exporting `AA_MODE=local` in that shell therefore moves those rows to *No*
without changing the command you typed.

Under the modes that do not read it, an unset, misspelled or unwritable path
produces no error and no warning, because nothing tries to open it.

## It is off unless you turn it on

The projection is disabled by default. The gateway wires nothing when the
database path is unset **or empty**:

```rust
let Some(path) = std::env::var_os(SENSITIVE_DATA_PROJECTION_DB_ENV)
    .filter(|p| !p.is_empty())
else {
    return Ok((engine, None));
};
```

That early return is the operative mechanism. `SensitiveDataProjectionConfig`
also derives `Default` with `enabled: false`, which is consistent but is not
what gates the tier.

The default is deliberate, but it is not ADR 0032's. §8 decides the *shape* of
the tier — that a `SensitiveDataDecisionEvent` and its normalized finding rows
are written **alongside** the existing `audit_entry_to_storage_event` bridge,
"which is left untouched". It records no switch, no default and no opt-in. (The
one "off by default" in ADR 0032 is at its Operational-guidance section and
governs the deep provider path, a post-v1 item unrelated to this projection.)

Defaulting off is this subsystem's own choice, made where the switch was built
(AAASM-5440) and stated in the rustdoc on
`SENSITIVE_DATA_PROJECTION_DB_ENV`. The reasoning is that a new writer against a
path an operator has not chosen is a surprise on upgrade, so the state that
requires no decision is the state that writes nothing. What §8 supports is the
weaker property the revert then rests on: because the projection sits beside the
audit bridge rather than replacing it, switching it off is a decision about this
table alone.

## Enabling it

Set the database path and start the gateway in its default mode:

```console
$ export AA_SENSITIVE_DATA_PROJECTION_DB=/var/lib/agent-assembly/sensitive-data.db
$ aa-gateway --policy /etc/agent-assembly/policy.yaml --listen 127.0.0.1:50051
```

The tables are created if absent — `CREATE TABLE IF NOT EXISTS`, applied at boot
by `migrate_sensitive_data_projection`. That is the extent of it: **there is no
in-place schema evolution.** Against a database whose tables already exist the
statements are a no-op, so a table left over from an earlier build is left as it
stands — its columns and its uniqueness key are not altered to match the build
now writing to it.

Rows already at that path therefore survive because nothing rewrites them, not
because a migration ran. The code records the same position beside the
statements (`aa-gateway/src/storage/sensitive_data/sqlite.rs`, *Migration
position*), where it was excused on the grounds that the tier had no producer
and so no deployed data to migrate. That excuse expired when the producer was
wired: changing the key now needs a migration that recreates the tables, and
none is written.

## Reverting it

Unset the variable and restart in the same mode:

```console
$ unset AA_SENSITIVE_DATA_PROJECTION_DB
$ aa-gateway --policy /etc/agent-assembly/policy.yaml --listen 127.0.0.1:50051
```

Writes to this table stop, and the revert rests on how narrow that is: the
projection is a **separate table written alongside the existing audit bridge,
which this subsystem does not modify**. There is no back-migration to run,
because nothing was migrated away from. What the gateway does outside this table
— detection, evaluation, the audit path — is reached by other code and is not
switched by this variable.

### What happens to rows already written

They stay, and they stay readable. The writer stamps
`SENSITIVE_DATA_SCHEMA_VERSION` onto the decision-event and finding rows it
persists, and the read path compares the **major** only — `check_readable`, in
`aa-gateway/src/storage/sensitive_data/rows.rs`:

```rust
if stored.major != SENSITIVE_DATA_SCHEMA_VERSION.major {
    return Err(ProjectionError::UnreadableSchemaVersion { .. });
}
```

So a gateway rolled back to an earlier build can still read rows a later build
wrote, as long as the major has not moved. A major mismatch is refused loudly:
the error propagates out of `row_to_event` and short-circuits the whole query,
rather than being filtered away into an empty result that would read as "no
sensitive data".

`aa-core`'s `SchemaVersion::is_readable_by` states the same rule and is covered
by tests, but it is not what runs on the read path; `check_readable` is.

### What "disabled" looks like, honestly

There is a `WriteOutcome::Disabled` variant in the storage layer, and its
meaning is *"the flag is off; nothing was written and nothing was validated"*.
It is an internal distinction: the composition root only ever builds an enabled
writer, and the one production consumer discards the variant. When the variable
is unset, no sink is attached at all, so no write is attempted and no `Disabled`
outcome is produced.

That means the operator-visible signal for a disabled projection is an **absent
database file** — not a table full of "disabled" markers. Check for the file
rather than querying for rows, because an empty table and a switched-off tier
are not distinguishable from the data alone. This is the same class of
distinction that rotated evidence windows (AAASM-5660) and unmeasured
transmission (AAASM-5359) had to make explicit; here it is carried by the
filesystem, not by the schema.

An enabled projection also produces an empty table when nothing was found.
`PolicyEngine::project_sensitive_data` returns before minting an event whenever
`result.canonical_findings` is empty, which is deliberate — a zero-finding row
for each governed call would bury the rows the dashboards read. So "the file
exists and the table has no rows" carries one meaning less than it looks like it
does: the tier ran and found nothing to record. The next section covers the case
where it did find something and the row still did not arrive.

## The third state: recording, but this decision was dropped

The two states above — switched off, and switched on with nothing found — are
not the whole set. A projection that is enabled, healthy and writing can still
be **incomplete**, and a reader who knows only the first two will read a gap as
"nothing was found here".

Recording is best-effort by construction. `SensitiveDataProjectionSink::record`
offers each decision to the drain with a non-blocking `try_send` over a channel
of `DEFAULT_PROJECTION_CAPACITY` = 4096 slots — the audit channel's size, so the
two tiers shed load at comparable points instead of one masking the other's
backlog. The alternative was rejected for a stated reason: blocking the
enforcement path on a slow database would turn a reporting tier into unbounded
memory growth inside the process that makes decisions.

Three ways a decision fails to reach the table, each counted and logged:

| Path | Counter | Log |
| --- | --- | --- |
| Channel full | `dropped` | `WARN` — *sensitive-data projection queue full — decision dropped, the projection is incomplete* |
| Channel closed (the drain is gone) | `dropped` | `ERROR` — *sensitive-data projection channel closed — the drain task is gone and every further decision will be lost* |
| Refused as undescribable | `refused` | `WARN` — *sensitive-data decision not projected — the projection is incomplete for this action* |

A **refusal** is the one that is not about load. `project_decision` returns
`Err(ProjectionRefusal)` when it cannot describe the evaluation truthfully, and
declines to write rather than write something false: an agent with no
authoritative `org_id` (no tenant-scoped query could return the row, and
inventing a tenant would surface it under someone else's), an action whose
`OperationKind` ADR 0032's vocabulary cannot name, a guarded field the shape
check or credential scan rejected, an agent id that will not render as
`<tenant>/<agent>`, and tallies that do not add up. A fourth counter,
`write_failures`, covers a row the store itself rejected.

### What that means for a reader of this table

In ADR 0033 §6's terms, a dropped or refused decision was **Evaluated**, and its
findings were **Detected** — the control ran and reached a verdict. It was not
**Observed** by this projection, because *Observed* needs a durable event
attributed to the action and that is exactly what was lost. The action is not
*Unmeasured*: something did inspect it. The measurement simply was not recorded
here.

So the absence of a row means one of three things, and the table cannot tell you
which: the tier was off, the tier ran and found nothing, or the tier ran, found
something, and shed it.

### Where to look

The counters are **not exported as metrics and are not queryable over the API**.
They surface in one place: the gateway reports them when it drains the
projection at shutdown, and only the shape of the line distinguishes a clean run
from a lossy one.

```
INFO  sensitive-data projection drained written=<n>
WARN  the sensitive-data projection is incomplete for this run
      written=<n> write_failures=<n> dropped=<n> refused=<n> drain_panicked=<bool>
```

The `WARN` is emitted whenever any of `write_failures`, `dropped`, `refused` or
`drain_panicked` is non-zero. Treat it as the authority on whether a run's table
is complete, and keep the gateway's logs for as long as you intend to draw
conclusions from the rows — a table read without them is a table whose gaps
cannot be interpreted. Sustained `dropped` counts mean the drain is not keeping
up with the database behind it, and the number lost is the number in the line,
not an estimate.

## Per-event evidence: what a row can and cannot prove

The state above is about whether a decision reached the table at all. This
section is about what a **row that did arrive** is allowed to say about the
action it describes — specifically, whether it proves the action's bytes were
actually kept from their destination.

There is no `prevented: bool` field anywhere in this evidence, by design. The
runtime's own event is named `CredentialLeakBlocked`, and it does not mean
blocked — it means *redact*, and redaction **forwards** the scrubbed bytes
upstream. A boolean read from that event name alone would be wrong for the
single most common outcome, silently.

Instead each row carries two independent evidence fields, and a prevention
claim requires a specific combination of both plus the decision:

* **`EnforcementPoint`** — where in the request's life the decision was
  applied: `pre_transmission` (before the payload could leave the process or
  host), `post_transmission` (an observer that saw a completed write, e.g. an
  eBPF uprobe or a post-hoc scan — too late to have stopped anything), or
  `not_recorded` (the producing layer did not say).
* **`TransmissionEvidence`** — what was actually observed about the bytes
  that would have gone to the destination: `not_forwarded` (the request was
  refused — the only value that can support a prevention claim),
  `forwarded_clean` (sent, and re-inspection found nothing sensitive — a
  successful *redaction*, not a prevented transmission), `forwarded_carrying_sensitive_value`
  (sent, and still sensitive), `forwarded_not_inspected` (sent, nobody
  re-checked what was in it), or `not_recorded` (no execution evidence
  captured at all).

A decision counts as **prevented transmission** only when all of: the
enforcement point is `pre_transmission`, the disposition was a deny or a
transforming action, the transmission evidence is `not_forwarded`, and the
action was not running in observe mode. `not_recorded` on either field fails
the test — an unwired producer cannot claim prevention by saying nothing, and
absence of evidence is deliberately not evidence of either transmission or
its absence.

**Most rows do not yet carry this evidence.** The observable this is built on
— `aa_proxy::probe_adjudication::ForwardedPayload` — exists but is produced on
only one of the two upstream-dialing call sites today, and is not yet
persisted end-to-end; generalizing that is separate, unstarted work. Until
then, most rows report `TransmissionEvidence::NotRecorded`, and a dashboard or
API reader must treat that as *no prevention evidence*, not as a zero
incident count. A `0` in a prevention metric backed by unmeasured evidence
means the denominator was not measured, not that nothing happened.

## Failure behaviour: the gateway refuses to start — in the modes that read it

In `serve_tcp` and `serve_uds` — the legacy-gRPC paths, and the only ones that
read this variable — a configured database that cannot be opened, or whose
schema cannot be applied, **fails the boot**. It does not warn and continue.

Under `--mode local` and `--mode remote` there is no such guarantee, and there
is nothing to guarantee: those paths never open the database, so a bad path is
neither opened nor reported. That is the reason the mode table at the top of
this page comes first.

```
sensitive-data projection database /var/lib/.../sensitive-data.db could not be opened: <cause>
sensitive-data projection schema could not be applied to /var/lib/.../sensitive-data.db: <cause>
```

The reasoning is recorded next to the code: warning-and-continue would leave a
governance surface empty for as long as nobody read the log, and an empty table
is indistinguishable from a quiet period. An operator who has asked for the
projection gets it or gets a failure, not a gateway that looks healthy while
recording nothing.

If you need the gateway up while the database is unavailable, unset the variable
deliberately — that is the revert path above, and it is visible in the process
environment rather than inferred from a log line.

## What this switch is not

Stating the boundary precisely matters more than stating it flatteringly.

- **It does not turn detection on or off.** The credential scanner runs
  regardless of this setting. It predates this subsystem — it has been in the
  product since AAASM-24 (2026-04-27) — and this projection is a consumer of its
  results, not a gate on them. Reverting the projection stops *recording*
  classifications; it does not stop the gateway from *making* them. The policy
  verdict is computed on a path this variable is not read on, so switching the
  projection does not move it.
- **It is not a staged or percentage rollout.** The setting is per-process and
  binary: a gateway either writes the projection or does not. There is no canary
  percentage, no per-org enablement, and no gradual ramp.
- **It is not a replacement switch.** There is no prior implementation being
  cut over from. This subsystem was added alongside existing behaviour, so
  reverting returns the deployment to what it did before the subsystem existed
  rather than to some earlier version of it. The next section is why that last
  point is load-bearing rather than incidental.

## Why there is no shadow comparison to run

A rollout gate normally has three legs: rollout, shadow comparison, rollback.
Two of them are on this page. The third has nothing to attach to, and the
reason is worth recording where an auditor will find it rather than leaving it
to be re-derived. This section is [AAASM-5270](https://lightning-dust-mite.atlassian.net/browse/AAASM-5270)
exit criterion 10's shadow-comparison leg.

**A shadow comparison needs a prior implementation to run beside.** There is
none. The detector was not replaced:

- `CredentialScanner` has been in the product since AAASM-24 (`6acc74247`,
  2026-04-27), months before this Epic.
- `git log --diff-filter=D --since=2026-07-25 -- aa-security/src
  aa-core/src/types aa-gateway/src/engine` returns nothing. No detector was
  removed for a new one to stand in for.
- `aa-security/src/canonical/lift.rs` describes the layer this Epic added as
  "a pure projection … it does not scan, does not allocate, and is not called by
  the scanner", whose fast path is "untouched by design".
- ADR 0032 §8 says the same at the storage end: written alongside the existing
  bridge, "which is left untouched".

There was no cutover moment, so there is no pair of live implementations whose
outputs could be compared.

### "Shadow" in this codebase means something else

Three symbols look like criterion-10 evidence and none of them is. All three mean
**observe / dry-run enforcement mode** (AAASM-1564, ADR 0021) — what a decision
*would* have been — not a comparison of two implementations:

| Symbol | What it means |
| --- | --- |
| `ShadowEvent` | the decision that would have been reached under `Enforce`, while the agent runs in `Observe` |
| `shadow_expiry_watcher.rs` | auto-reverting an agent's expired shadow *enforcement* window |
| `PolicyReasonCode::ShadowEvaluationOnly` | decision computed but not applied — the agent is in observe mode |

`git grep ShadowEvent` over `aa-security/`,
`aa-core/src/types/sensitive_data/`, `engine/sensitive_data.rs` and
`engine/detection.rs` returns nothing. Observe mode does not even carry
sensitive-data findings — it rewrites the result with `canonical_findings:
vec![]`. Citing any of the three as a sensitive-data shadow comparison would be
false.

### What evidence does exist, and what it is called

`aa-security/tests/canonical_no_behaviour_change.golden` pins the scanner's
observable output to `main` at `95dbafe7` — a baseline captured before the
canonical layer existed — and the test requires the current tree to reproduce it
character for character. It has one commit (`699ca92ab`), so it has never been
regenerated to match a change, and it rejected a candidate implementation during
the 2026-08-07 detector work (`aa-security/src/scanner.rs`, the
`overlaps_earlier_finding` rationale). Around it sit pinned false-positive
ceiling and recall-floor thresholds over a named seeded corpus with a
non-vacuity control, per-change suites for AAASM-5450 and AAASM-5441, and frozen
conformance vectors.

That is regression evidence against a pre-migration baseline. It is not a shadow
comparison of two live implementations, and this page does not present it as
one.

## Related

- ADR 0032 — local-first sensitive-data architecture. §8 defines the event and
  projection this page operates, and establishes that they are written alongside
  an audit bridge left untouched. It does not decide the switch or its default;
  those are AAASM-5440's, recorded in the rustdoc on
  `SENSITIVE_DATA_PROJECTION_DB_ENV`.
- [Proxy Prevention-Evidence Retention](proxy-audit-retention.md) — the
  proxy-tier sink, which is a different store under a different retention bound.
- [Audit assurance](../security/audit-assurance.md) — what is retained and what
  is deleted, per tier.
