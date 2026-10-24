# aasm lease

Create, revoke against and inspect the **capability-lease state record**: a
small JSON file that records which policy digest a governed run is bound to and
which lease ids have been revoked since.

> **Status: storage and operator commands only.** The runtime does not read
> this record yet, so creating, revoking or deleting it does not change what any
> running agent may do. This page documents the record and the commands that
> maintain it, not an enforcement behaviour.

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
| `issued_at` | Unix seconds at which the run was created. Informational. |
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
  record.

---

## aasm lease init

```text
aasm lease init --state <PATH> --subject <ID> --policy-digest <HEX> [--force]
```

Creates the record with generation `1` and nothing revoked, and prints the lease
id prefix for the run (everything before the domain word). The directory of `--state` must already exist.

Without `--force`, an existing record is **never** overwritten. With `--force`
the command starts a new run: generation `1`, an empty revocation set, and a
fresh `run_id`, so every earlier lease id is retired.

`--policy-digest` is taken as given for now; it is not yet computed from a
policy file.

## aasm lease revoke

```text
aasm lease revoke --state <PATH> --lease-id <ID>...
```

Adds one or more lease ids (`--lease-id` may be repeated) to an existing record,
under an exclusive lock on `<PATH>.lock`, and prints the new generation.
Revoking ids that are all already revoked is a no-op and leaves the generation
unchanged. A missing or corrupt record is an error; `revoke` never creates one.

## aasm lease status

```text
aasm lease status --state <PATH>
```

Prints the record as JSON. Fails if the record is missing, corrupt or insecure.
