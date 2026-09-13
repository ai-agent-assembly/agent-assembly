# example — fmt, validate, and a safe plan review

Worked example: adding a Cloud Storage bucket and a Cloud Run service to
an existing root module (`environments/staging/`).

## Change made

```hcl
# environments/staging/storage.tf
resource "google_storage_bucket" "assets" {
  name          = "horonom-staging-assets-<REDACTED>"
  location      = "US"
  force_destroy = false
}

# environments/staging/cloud_run.tf
resource "google_cloud_run_v2_service" "api" {
  name     = "staging-api"
  location = "us-central1"

  template {
    containers {
      image = "us-central1-docker.pkg.dev/<REDACTED>/api:staging"
      env {
        name  = "SIGNING_KEY"
        value = var.signing_key # sensitive — passed via tfvars, never hardcoded
      }
    }
  }
}

output "signing_key_fingerprint" {
  value     = var.signing_key
  sensitive = true
}
```

`var.signing_key` is supplied via an untracked `*.auto.tfvars` file or CI
secret injection — never committed, never typed into config as a literal.
`<REDACTED>` above stands in for a real project/bucket suffix; it is a
placeholder, not a real value, per this skill's fake-placeholder
convention.

## 1. Format check

```
$ terraform fmt -check -recursive
```

No output — exit 0. Config is already correctly formatted. (If this had
failed, the fix is `terraform fmt -recursive`, then re-run `-check` to
confirm, before moving on.)

## 2. Validate

```
$ terraform validate
Success! The configuration is valid.
```

This confirms the config is internally consistent — types match, required
arguments are present, provider schemas are satisfied. It does **not**
confirm the plan will be safe or that these resources don't already exist
under different management — that's what `plan` is for next.

## 3. Identity verification (staging, not production, but still checked)

```
$ gcloud config list --format='value(core.project)'
horonom-staging
```

Confirms the active gcloud context targets the intended `horonom-staging`
project before planning against it — not the production project.

## 4. Plan

```
$ terraform plan -out=tfplan
$ terraform show -json tfplan > /tmp/plan.json
```

The JSON file stays local and ephemeral — it is never committed, never
pasted into a transcript, and is deleted after the filter step runs
(`rm /tmp/plan.json`). It is piped through this repo's plan-summary filter
(or, if none exists, hand-built per
`references/sensitive-value-safety.md`'s fallback guidance) to produce the
safe summary below.

## 5. Safe plan summary (what actually gets reported/reviewed)

```
Plan: 2 to add, 0 to change, 0 to destroy, 0 to replace

Create:
  google_storage_bucket.assets
  google_cloud_run_v2_service.api

No destructive changes.

Sensitive values present, not shown: output "signing_key_fingerprint"
(marked sensitive), google_cloud_run_v2_service.api env var "SIGNING_KEY"
(value sourced from var.signing_key, treated as sensitive even though the
provider schema does not mark container env values sensitive by default —
see references/sensitive-value-safety.md on unmarked sensitive fields).
```

This is what goes into the PR description and any status report — counts,
resource addresses, action types, and an explicit note that a sensitive
value existed and was withheld. At no point does `***`-shaped or
real-looking secret text appear anywhere in this transcript; the actual
signing key value was never read, echoed, or reconstructed by the agent.

## 6. What happens next is outside this skill's automatic scope

Applying this plan (`terraform apply tfplan`) requires explicit task
authorization per SKILL.md's "Apply, destroy, import, and state mutation"
section — this example stops at the reviewed, safely-summarized plan.
