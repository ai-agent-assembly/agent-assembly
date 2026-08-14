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

The default is deliberate. ADR 0032 §8 asks for a projection that is switchable
without touching existing audit behaviour, and defaulting it on would make the
conservative state the one an operator has to opt into.

## Enabling it

Set the database path and start the gateway in its default mode:

```console
$ export AA_SENSITIVE_DATA_PROJECTION_DB=/var/lib/agent-assembly/sensitive-data.db
$ aa-gateway --policy /etc/agent-assembly/policy.yaml --listen 127.0.0.1:50051
```

The tables are created at boot if absent — `CREATE TABLE IF NOT EXISTS`, applied
by `migrate_sensitive_data_projection`. An existing database at that path keeps
its rows because nothing rewrites them, not because a migration runs: there is
no schema-migration machinery here yet, and a future change to the table key
will need one written.

## Reverting it

Unset the variable and restart in the same mode:

```console
$ unset AA_SENSITIVE_DATA_PROJECTION_DB
$ aa-gateway --policy /etc/agent-assembly/policy.yaml --listen 127.0.0.1:50051
```

Writes stop. Nothing else changes, and that is the property the revert rests on:
the projection is a **separate table written alongside the existing audit
bridge, which this subsystem does not modify**. There is no back-migration to
run, because nothing was migrated away from.

### What happens to rows already written

They stay, and they stay readable. Each persisted decision event and finding row
carries `SENSITIVE_DATA_SCHEMA_VERSION`, and the rule enforced on every read
compares the **major** only — `check_readable`, in
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
  classifications; it does not stop the gateway from *making* them, and it does
  not change any policy decision.
- **It is not a staged or percentage rollout.** The setting is per-process and
  binary: a gateway either writes the projection or does not. There is no canary
  percentage, no per-org enablement, and no gradual ramp.
- **It is not a replacement switch.** There is no prior implementation being
  cut over from. This subsystem was added alongside existing behaviour, so
  reverting returns the deployment to what it did before the subsystem existed
  rather than to some earlier version of it.

## Related

- ADR 0032 — local-first sensitive-data architecture; §8 defines the
  switchability requirement this page documents.
- [Proxy Prevention-Evidence Retention](proxy-audit-retention.md) — the
  proxy-tier sink, which is a different store under a different retention bound.
- [Audit assurance](../security/audit-assurance.md) — what is retained and what
  is deleted, per tier.
