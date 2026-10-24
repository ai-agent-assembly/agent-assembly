# aasm lease

Create, revoke against and inspect the **capability-lease state record**: a
small JSON file that records which policy digest a governed run is bound to and
which lease ids have been revoked since.

> **Status.** A runtime started with `AA_LEASE_POLICY` set reads this record: at
> startup (it refuses to start if the record is missing, corrupt, or bound to a
> different agent or policy digest) and every ~100 ms afterwards, so `revoke` takes
> effect there on the next reload. A runtime started without `AA_LEASE_POLICY`
> ignores the record entirely. See Core ADR 0038 section 37 for exactly what is and is
> not enforced; this is admission control for cooperative SDK tool calls, not
> confinement.

## Synopsis

```text
aasm lease <SUBCOMMAND> --state <PATH> [OPTIONS]
```

`--state` may instead be supplied through the `AA_LEASE_STATE` environment
variable.

| Subcommand | Purpose |
|---|---|
| [`init`](#aasm-lease-init) | Create the record for a new run. |
| [`revoke`](#aasm-lease-revoke) | Add lease ids to an existing record. |
| [`status`](#aasm-lease-status) | Print the record as JSON. |

Every refusal exits non-zero with a message on stderr.

## The record

```json
{
  "version": 1,
  "subject": "agent-1",
  "policy_digest": "0123456789abcdef0123456789abcdef",
  "run_id": "00112233445566778899aabbccddeeff",
  "issued_at": 1760000000,
  "generation": 1,
  "revoked": []
}
```

| Field | Meaning |
|---|---|
| `version` | Record format version. Only `1` is understood. |
| `subject` | The agent id the run's leases are issued to. No whitespace or control characters; `:` is allowed (`did:key:...`). |
| `policy_digest` | Lowercase hex digest (12-128 characters) of the policy the run is bound to. |
| `run_id` | Random 128-bit identifier (32 lowercase hex characters) minted when the run is created. |
| `issued_at` | Unix seconds at which the run was created. Lease lifetimes count from here, so a restart does not refresh them. |
| `generation` | Starts at `1`; increases by one each time the revocation set grows. |
| `revoked` | Revoked lease ids, sorted and without duplicates. |

The record is parsed strictly: unknown fields, a wrong version, truncated or
trailing data, unsorted or duplicate `revoked` entries, a malformed `run_id`
and an empty `subject` are all rejected. A missing record and a corrupt record
are different errors, and neither is ever repaired or recreated implicitly. The
file must be a regular file owned by you with mode `0600`, in a directory that
is not a symlink and not group- or world-writable; anything else is refused.
That includes a state file placed directly under macOS `/tmp`, which is a
symlink to `/private/tmp`: use the resolved path.

Limits: the record is at most 1 MiB and holds at most 10,000 revoked ids. A
revocation that would exceed either is refused before anything is written.

### Lease ids

A lease id is derived, not stored:

```text
{subject}:{digest12}:{run_id}:{issued_at}:{domain}
```

`digest12` is the first 12 characters of `policy_digest`. `domain` is a word
naming what the lease covers, 1-64 characters of `[a-z0-9_-]`. In `subject`,
`%` and `:` are percent-encoded (`%25`, `%3A`), so the id is unambiguous even
for `did:key:...` subjects.

Uniqueness across runs comes from `run_id`, which is random and does not depend
on the clock. A new run (`init --force`, or `init` after the record was
deleted) therefore cannot reuse an id revoked in an earlier run, even if the
earlier record was unreadable or the clock went backwards.

### What the record does not protect

* Deleting the record and running `init` starts a new run and drops every
  revocation. That is by design, and it is why a consumer of the record must
  refuse to start when it is missing rather than create one.
* A restored older but valid record is accepted when loaded; rollback is not
  detected across loads (AAASM-5533).
* Anyone who can write to the state directory as your user can alter the
  record. A running governed runtime trips to deny-all on a shrunk revocation
  set, a changed anchor or a corrupt or missing file, and stays denied until it
  is restarted; it cannot detect an older valid record put back *before* a
  restart.

---

## aasm lease init

```text
aasm lease init --state <PATH> --subject <ID> (--policy <FILE> | --policy-digest <HEX>) [--force]
```

Creates the record with generation `1` and nothing revoked, and prints the lease
id prefix for the run (everything before the domain word). The directory of `--state` must already exist.

Without `--force`, an existing record is **never** overwritten. With `--force`
the command starts a new run: generation `1`, an empty revocation set, and a
fresh `run_id`, so every earlier lease id is retired.

`--policy <FILE>` computes the digest from the policy file exactly as the runtime
does at startup (the file must resolve to an enforced policy), so the two cannot
disagree. `--policy-digest` takes a digest as given and is mutually exclusive with
`--policy`. `--subject` must equal the runtime's `AA_AGENT_ID`.

## aasm lease revoke

```text
aasm lease revoke --state <PATH> --lease-id <ID>... [--wait-health <URL> [--wait-timeout-secs <N>]]
```

Adds one or more lease ids (`--lease-id` may be repeated) to an existing record,
under an exclusive lock on `<PATH>.lock`, and prints the new generation.
Revoking ids that are all already revoked is a no-op and leaves the generation
unchanged. A missing or corrupt record is an error; `revoke` never creates one.

Without `--wait-health` the command returns once the record is written; a running
governed runtime applies it within about 100 ms but gives no acknowledgement. With
`--wait-health http://127.0.0.1:8080` (the runtime's `AA_METRICS_ADDR`; also read from
`AA_LEASE_HEALTH_URL`) it polls `GET /health` and returns only when
`lease_governance.generation` reaches the new generation, or `state` is `denied_all`
(everything is already denied). It exits non-zero if that does not happen within
`--wait-timeout-secs` (default 5), or if the runtime reports no `lease_governance`
(not in governed mode). The revocation is recorded in every case.

## aasm lease status

```text
aasm lease status --state <PATH>
```

Prints the record as JSON. Fails if the record is missing, corrupt or insecure.
