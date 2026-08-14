# Sensitive-Data Projection: enabling, reverting and failure behaviour

The sensitive-data projection is the durable table behind the sensitive-data
analytics surface. It records classification decisions and their findings
alongside the existing audit path.

This page is the operator contract for turning it on, turning it back off, and
knowing what happens when it cannot start. It exists because a revert mechanism
nobody can find is not a revert mechanism ([AAASM-5739](https://lightning-dust-mite.atlassian.net/browse/AAASM-5739)).

## It is off unless you turn it on

The projection is disabled by default. `SensitiveDataProjectionConfig` derives
`Default` with `enabled: false`, and the gateway wires nothing when the database
path is unset:

```rust
let Some(path) = std::env::var_os(SENSITIVE_DATA_PROJECTION_DB_ENV)
    .filter(|p| !p.is_empty())
else {
    return Ok((engine, None));
};
```

The default is deliberate. ADR 0032 §8 asks for a projection that is switchable
without touching existing audit behaviour, and defaulting it on would make the
conservative state the one an operator has to opt into.

## Enabling it

Set the database path and restart the gateway:

```console
$ export AA_SENSITIVE_DATA_PROJECTION_DB=/var/lib/agent-assembly/sensitive-data.db
$ aa-gateway --mode local
```

The schema is applied at boot; there is no separate migration step. An existing
database at that path is migrated in place and its rows are retained.

## Reverting it

Unset the variable and restart:

```console
$ unset AA_SENSITIVE_DATA_PROJECTION_DB
$ aa-gateway --mode local
```

Writes stop. Nothing else changes, and that is the property the revert rests on:
the projection is a **separate table written alongside the existing audit
bridge, which this subsystem does not modify**. There is no back-migration to
run, because nothing was migrated away from.

### What happens to rows already written

They stay, and they stay readable. Every persisted decision event and finding
row carries `SENSITIVE_DATA_SCHEMA_VERSION`, and the compatibility rule compares
the **major** only:

```rust
/// True exactly when the majors agree. The minor is deliberately not
/// compared: a newer minor only adds fields, and refusing it would make an
/// additive change breaking
pub const fn is_readable_by(self, reader: Self) -> bool {
    self.major == reader.major
}
```

So a gateway rolled back to an earlier build can still read rows a later build
wrote, as long as the major has not moved. A major mismatch is refused loudly,
as `ProjectionError::UnreadableSchemaVersion`, rather than being read as an
empty result.

### Disabled is distinguishable from empty

When the flag is off, a write returns `WriteOutcome::Disabled` — *"the flag is
off; nothing was written and nothing was validated"* — rather than a silent
success. This matters for the same reason it did for rotated evidence windows
(AAASM-5660) and unmeasured transmission (AAASM-5359): a reader has to be able
to tell *"no sensitive data was found"* from *"nothing was recording"*. An empty
table alone cannot carry that distinction.

## Failure behaviour: the gateway refuses to start

If the configured database cannot be opened, or its schema cannot be applied,
**boot fails**. It does not warn and continue.

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
