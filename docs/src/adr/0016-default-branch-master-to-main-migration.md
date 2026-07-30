# ADR 0016: Organization-wide Default Branch — `master` → `main`

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-4955](https://lightning-dust-mite.atlassian.net/browse/AAASM-4955)

This ADR makes `main` the canonical default branch for every active `ai-agent-assembly`
repository, and records the standing reference contract that outlives the migration —
which URL and ref forms survive a rename and which must be written a particular way from
now on. It updates the recorded convention (the tooling previously said "base branch
always `master`").

> **The migration procedure is not here.** How to migrate a repo — the both-directions
> reference audit, the lockstep downstream `base:` flip, branch-protection re-verification,
> rollback, migration ordering, and the per-repo evidence checklist — is development
> process, not a durable decision, and lives in the internal
> `internal-docs` runbook `docs/runbooks/default-branch-migration.md`. This ADR records
> only what is decided and what constrains future authors.

---

## Context

The org's default branch was split: of 18 repos, 7 already defaulted to `main` while 11
still used `master`. That is inconsistent, and `master` diverges from GitHub's default.

A default-branch rename is deceptively cross-cutting, and that is what makes the decision
below more than cosmetic. GitHub's rename API atomically moves the default pointer, moves
branch protection, re-targets open PRs, and installs a `master`→`main` redirect for
supported repository URLs — but it does **not** touch workflow branch filters, references
from *other* repos, hardcoded raw/blob/commits URLs and badges, local checkouts, or
documentation prose. A pilot migration of one low-risk public repo
([AAASM-4957](https://lightning-dust-mite.atlassian.net/browse/AAASM-4957)) confirmed the
sharp edge: the release-breaking coupling was not in the migrated repo at all but in a
*consumer* workflow that opened a PR into it with a hardcoded `base: master`. The pilot
evidence in full is recorded with the runbook.

### Threat/adversary framing

Not adversarial — the risk is **operational breakage** (a release, a CI trigger, a
deploy, or a doc link silently breaking) from an incomplete rename, especially on
release- and deploy-critical repos.

---

## Decision

### `main` is the canonical org-wide default branch

Every **active** repo defaults to `main`. **Exceptions:** archived repos
(`agent-assembly-spec`); none others are exempt. Already-`main` repos are no-ops
(verify only).

Two consequences of that choice are themselves standing constraints, binding on anyone
writing a cross-repo link or a cross-repo automation from now on — not merely steps in
the one-time migration:

#### Legacy `master` is a GitHub-managed redirect, not a retained branch

A GitHub branch rename does **not** leave `master` as a separate branch that is later
deleted. The old name becomes a **GitHub-managed redirect for *supported* repository
URLs only** (the web `blob`/`tree`/`commits`/`pull` paths, and `git clone`/`push` that
resolve the default branch). There is no `master` branch to keep or remove.

- **Do NOT recreate `master`** after a rename — that would re-introduce a real,
  divergent branch and defeat the migration. (One narrow, separately-approved,
  documented and time-bounded exception exists for a repo that *publishes* a GitHub
  Action consumed via `@master`; its approval procedure is in the runbook.)
- The redirect does **NOT** cover the following, so each must be written explicitly and
  never left pointing at `master`:
  - **`raw.githubusercontent.com/<repo>/master/…`** — raw content URLs do not follow a
    rename; they 404. Use `raw.githubusercontent.com/<repo>/HEAD/…` or a literal `/main/`.
  - **`git pull`/`git fetch` targeting `master`** — a command naming the `master`
    ref explicitly does not follow the rename; the ref is gone.
  - **GitHub Actions refs such as `uses: <org>/<action>@master`** — an action pinned to
    an `@master` ref does not follow the rename; the consuming workflow must update it.
  - **CI branch filters, release/dispatch targets, `actions/checkout` refs, and
    downstream PR-`base:` refs** — the redirect does not fix workflow logic.

Therefore **cross-repo links must use the default-branch-tracking `HEAD` form**
(`/blob/HEAD/`, `raw…/HEAD/`) so they survive this rename and any future one.

#### A consumer's PR `base:` must track the target repo's current default branch

Any `base:` a *consumer* workflow uses to open a PR into another repo must name that
repo's current default branch. This is a permanent coupling, not a migration artifact: it
is wrong the moment the target's default branch differs, whatever the reason. It is
machine-checked — `scripts/check-release-completeness.sh` pins each downstream bot-PR
`base:` to its target's default branch and fails CI on a mismatch.

---

## Accepted risks

- `github.com` web links redirect, so stale `blob/master`/`commits/master` badges are
  cosmetically wrong but non-breaking until swept. This does **not** extend to
  `raw.githubusercontent.com/…/master`, `git fetch master`, or `@master` action refs —
  those are hard breakage and are migrated, not deferred.

## Explicitly forbidden designs

- **Do not** recreate `master` after a rename — except the narrow, separately-approved,
  documented, time-bounded compatibility case for a repo that *publishes* a GitHub
  Action consumed via `@master`.
- **Do not** write a new cross-repo link, action ref, or PR `base:` against `master`, or
  against a hardcoded branch name where the `HEAD` form would track the default.

## Consequences

- **Operators/contributors**: uniform `main`; old clones keep working via the redirect but
  should re-point.
- **Anyone writing a cross-repo reference**: the `HEAD` form is the default choice, and
  the redirect is not a safety net for raw URLs, `@master` action refs, or workflow logic.
- **Release owner**: each downstream `release.yml` `base:` tracks its target's default
  branch, enforced by the drift guard rather than by memory.

## Reconsideration triggers

A new repo added to the org (must default to `main` via the `.github` starter templates);
a new cross-repo automation that pins a branch ref; GitHub changing what its rename
redirect covers.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4955](https://lightning-dust-mite.atlassian.net/browse/AAASM-4955) | The migration Epic this ADR governs |
| [AAASM-4957](https://lightning-dust-mite.atlassian.net/browse/AAASM-4957) | homebrew-tap pilot — evidence source |
| [AAASM-5294](https://lightning-dust-mite.atlassian.net/browse/AAASM-5294) | Split that moved the migration procedure to the internal runbook |
| `internal-docs` `docs/runbooks/default-branch-migration.md` | The migration procedure this ADR's decision is executed by |
| [ADR 0014](0014-canonical-metadata-registry-and-drift-gate.md) | Related — `.github` registry/org-profile inbound refs |
| `scripts/check-release-completeness.sh` | Enforces the downstream PR-`base:` rule above |
| Implementation | homebrew-tap #50, agent-assembly #1620 (pilot + release-base guard) |
