# reference — sensitive-value safety (read this before running `terraform plan`)

A `terraform plan` (and its JSON form, `terraform show -json`) can carry
values that must never appear in agent context, a transcript, a commit, a
PR description, or CI output. This document is the operational procedure
for summarizing a plan safely. It does not restate the company's
non-waivable secret-handling invariant — see
`governance/engineering/security.md`'s "Secrets — opaque-capability
model" section, which this procedure implements for the Terraform case,
not replaces.

## Why "just read the plan" is not safe

- **Provider `sensitive = true` marking is real but incomplete.**
  Terraform redacts attributes a provider schema explicitly marks
  sensitive when rendering the human-readable plan (`(sensitive value)`).
  That marking is provider-authored, not company-controlled — a provider
  can fail to mark a field that is, in practice, sensitive (a generated
  password returned as a plain string attribute, a connection string
  assembled from non-sensitive parts, a newly-added provider attribute
  the schema hasn't caught up on yet). Absence of the `(sensitive value)`
  marker is not proof the value is safe to show.
- **`terraform show -json` is worse, not better, if dumped naively.**
  The JSON plan format includes an `unknown_values`/sensitivity metadata
  structure, but naively piping the full JSON into a summary, a file, or
  model context reproduces every attribute value verbatim — including
  ones a human-readable plan would have redacted, depending on Terraform
  and provider version. **Never dump raw `terraform show -json` output
  into a transcript, commit, PR, or report.** Treat the entire JSON plan
  as potentially secret-bearing from the moment it's produced.
- **Outputs are a common leak path.** An output marked `sensitive = true`
  is redacted in the human-readable plan, but an *unmarked* output that
  happens to expose a secret (a generated password passed straight
  through as a module output without the flag set) is not. Treat any
  output whose value you have not personally confirmed is non-sensitive
  as sensitive by default.

## The safe pattern: metadata-only summarization

Treat the plan JSON the same way the company treats any other
secret-bearing artifact — as opaque content to be *used* (to compute
metadata) without exposing its content:

```
terraform plan -out=tfplan
terraform show -json tfplan > /tmp/plan.json   # local, ephemeral, never committed
<filter script> /tmp/plan.json                  # emits ONLY the metadata below
```

The filter step must be a deterministic script (not a manual read-and-
retype by the agent) that extracts and emits **only**:

- **Action counts**: number of resources to create / update in place /
  destroy / replace (destroy-then-create).
- **Resource addresses**: `type.name` (module path + resource type +
  name), never attribute values — an address like
  `module.network.google_compute_instance.web` is safe; the instance's
  `metadata_startup_script` value is not.
- **Action per resource**: which of create/update/destroy/replace applies
  to each listed address.
- **A destructive/high-risk flag**: any `destroy` or `replace` (especially
  one triggered by `forces_replacement` on an attribute) surfaced
  prominently and first in the summary — a reviewer must never have to
  scroll past routine updates to find the one deletion.
- **A "sensitive value present" note, not the value**: if a resource
  carries a marked-sensitive attribute or a sensitive output, say so —
  "output `db_password` changed (sensitive, not shown)" — never the value
  itself, never even a partial/truncated fragment of it.

Nothing else from the plan JSON should reach the summary: no attribute
values (before or after), no raw JSON blobs, no `terraform show` (non-
JSON) output pasted verbatim if it wasn't first checked for the same
leak paths above.

## What a safe summary looks like

```
Plan: 4 to add, 1 to change, 0 to destroy, 1 to replace

⚠ REPLACE (destructive): google_sql_database_instance.primary
    forces_replacement: database_version

Create:
  google_storage_bucket.assets
  google_storage_bucket_iam_member.assets_reader
  google_cloud_run_v2_service.api
  google_cloud_run_v2_service_iam_member.public_invoker

Update in place:
  google_project_iam_member.deploy_sa

Sensitive values present, not shown: output "api_signing_key" (marked
sensitive), google_sql_user.app.password (marked sensitive).
```

This is enough for a reviewer to authorize or reject the change without
ever seeing a value that could be a credential.

## If no filter script exists yet in a target repo

Per `engineering-loop`'s optional-tool fallback semantics, a missing
filter script is not license to skip filtering — build the summary by
hand from `terraform plan`'s own human-readable output (which already
redacts provider-marked-sensitive values), applying the same discipline:
report counts/addresses/actions/risk, and explicitly flag "human-readable
plan output was used; provider-unmarked sensitive values may not have
been redacted — treat outputs and freeform string attributes with
suspicion" rather than silently asserting the summary is exhaustive.

## Do not overwrite this care after the fact

Even a safe plan summary should not be pasted into a Jira comment, commit
message, or PR body without re-checking it still contains no raw value —
a summary built correctly once can still be edited by hand later in a way
that reintroduces a value (e.g. someone "adds context" by pasting the
actual output). Verify the final artifact before it's shared, not just
the intermediate filter step.
