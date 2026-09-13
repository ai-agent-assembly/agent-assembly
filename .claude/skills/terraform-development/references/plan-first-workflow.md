# reference — plan-first workflow

The full progression `terraform-development`'s SKILL.md points to, plus
the discovery and identity-verification work that must happen before any
stage that touches real provider state.

## 1. Discover the root, workspace, and backend before running anything

Terraform commands operate on the *root module* you invoke them from, not
the whole repo. Before running `fmt`/`validate`/`plan`:

- Locate the root module(s) actually affected by the change — a repo may
  have several independent roots (`environments/staging/`,
  `environments/production/`, `modules/*` consumed by both). Editing a
  shared module means every root that consumes it is potentially affected;
  don't assume the root you're sitting in is the only one.
- Identify the configured backend (`terraform { backend "..." { ... } }`
  or a `.tfbackend`/partial-config file) — this determines where state
  lives and therefore what a `plan` diffs against.
- Identify the active **workspace** (`terraform workspace show`). The
  same root module can represent different environments across
  workspaces; running a check in the wrong workspace produces a
  plan/diff against the wrong environment's state.

## 2. Provider and init/lockfile behavior

- Run `terraform init` before `validate`/`plan` if `.terraform/` is
  absent, providers changed, or the lockfile (`.terraform.lock.hcl`) is
  out of date relative to `required_providers`. `init` without
  `-upgrade` respects the existing lockfile — do not pass `-upgrade`
  casually, since it can silently widen provider version constraints
  beyond what was reviewed.
- A lockfile change is a real, reviewable diff (it pins provider
  checksums per platform) — treat it the same as any other dependency
  lock change: intentional, reviewed, not incidental.
- `init` and `validate` do not require provider credentials for most
  providers' schema/syntax checks, but some providers validate against
  live API metadata even during `init` (schema fetch) — if `init` fails
  for an auth reason, that's expected without credentials configured, not
  a bug in the config.

## 3. The progression

1. **`terraform fmt -check`** (add `-recursive` for a multi-root repo) —
   catches formatting drift with zero provider/state interaction. Fastest
   possible signal; always run first.
2. **`terraform validate`** — checks internal consistency (types,
   required arguments, provider schema conformance) against the current
   config only. It does **not** contact real infrastructure state and
   does **not** prove a plan will succeed or that the change is safe to
   apply — a config can validate cleanly and still fail at plan time
   (state drift, provider auth) or produce a destructive plan. Treat a
   green `validate` as "config is well-formed," nothing stronger.
3. **Lint / static analysis** — run whatever the repo has configured
   (e.g. `tflint`, a policy-as-code check). Per the optional-tool
   fallback semantics in
   `agents/skills/engineering-loop/references/optional-tool-fallback.md`, a missing linter means "note
   its absence and proceed with the remaining stages," never "skip
   static analysis silently and call the stage passed."
4. **`terraform plan`** — the only stage that actually diffs the proposed
   config against real state. Always run with an explicit `-out=<file>`
   when the plan will later be reviewed or (once authorized) applied, so
   the exact reviewed plan is what executes — never re-derive a fresh
   plan at apply time and assume it matches what was reviewed. Summarize
   the plan output per `references/sensitive-value-safety.md` before it
   ever appears in a transcript, PR, or report.

## 4. State, drift, import, and moved-resource caveats

- **Drift**: real infrastructure can diverge from state (manual console
  changes, another pipeline). A `plan` showing unexpected changes to
  resources nobody edited is a drift signal, not necessarily a bug in
  this change — investigate before assuming the diff is wrong.
- **`terraform import`** brings an existing real resource under Terraform
  management. It mutates state and is squarely inside "state mutation" —
  outside this skill's automatic scope; it always needs explicit task
  authorization (see SKILL.md).
- **`moved` blocks** (or legacy `terraform state mv`) let a resource be
  renamed/refactored in config without a destroy+recreate plan. When
  refactoring existing resource addresses, check for and use `moved`
  blocks in config rather than manually mutating state — but adding a
  `moved` block is a config change reviewable via the normal
  fmt→validate→plan progression; running `state mv` directly is not.
- A plan showing an unexpected `destroy`/`replace` where only a rename
  was intended is almost always a missing `moved` block, not a real
  requirement to recreate the resource — escalate and investigate before
  treating that plan as expected.

## 5. Identity verification before anything production-sensitive

Before running `plan` (and certainly before any authorized `apply`)
against a root module whose backend/workspace maps to a production-like
environment, verify — using non-secret metadata only — that the active
credentials/context actually target the intended:

- **Cloud account/project** (e.g. `aws sts get-caller-identity`,
  `gcloud config list`, `az account show` — identity/account-id output
  only, never a token).
- **Region** — many resource types are region-scoped; a correct account
  with a wrong default region silently plans against the wrong region's
  existing state.
- **Backend target** — confirm the backend config's bucket/key/table (or
  equivalent) resolves to the environment you intend, especially in a
  repo with multiple environments sharing similar naming.

A plan run against the wrong account/project/region is not "safe because
nothing applied" — the read calls it makes during planning can themselves
be a genuine cross-environment credential-scope mistake worth catching
before it becomes a habit.
