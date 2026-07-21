# ADR 0016: Organization-wide Default Branch — `master` → `main`

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-4955](https://lightning-dust-mite.atlassian.net/browse/AAASM-4955)

This ADR makes `main` the canonical default branch for every active `ai-agent-assembly`
repository and defines the migration mechanics — so the remaining per-repo migrations
(AAASM-4958…4967) execute against a single reviewed procedure rather than ad-hoc.
It is grounded in the **homebrew-tap pilot** ([AAASM-4957](https://lightning-dust-mite.atlassian.net/browse/AAASM-4957)),
which migrated one low-risk public repo end-to-end and surfaced a release-breaking
cross-repo coupling that a naive per-repo rename would have missed. It updates the
recorded convention (the tooling currently says "base branch always `master`").

---

## Context

The org's default branch is split: 7 repos already default to `main`
(`arena`, `docs`, `official-website`, `saas-infra`, `internal-docs`, `.github-private`,
archived `agent-assembly-spec`), while 11 still use `master`
(`.github`, `agent-assembly`, `agent-assembly-enterprise`, `cloud`, `e2e-private`,
`e2e-public`, `examples`, `go-sdk`, `homebrew-tap`→now migrated, `node-sdk`,
`python-sdk`). Inconsistent, and `master` diverges from GitHub's default.

A default-branch rename is deceptively cross-cutting. GitHub's rename API atomically
moves the default pointer, moves branch protection, re-targets open PRs, and installs a
`master`→`main` redirect for Git operations — but it does **not** touch:

- workflow branch filters (`on.{push,pull_request}.branches`),
- **references from *other* repos** — the class that broke in the pilot,
- hardcoded raw/blob/commits URLs and badges,
- local developer checkouts,
- documentation and skill/runbook prose.

### Pilot evidence (AAASM-4957 — homebrew-tap)

- The tap's **own** `git grep master` found only 4 files (its two workflow filters +
  a doc). Migrating just those looked complete.
- **But the release-breaking coupling lived in a *different* repo**:
  `agent-assembly/.github/workflows/release.yml` opened the tap's version-bump bot PR
  via `peter-evans/create-pull-request` with a hardcoded **`base: master`**. After the
  rename, the next release would have failed to open the tap PR. This was invisible
  from inside the tap — only found by auditing the *consumer*.
- Fix + guard: the tap step was flipped to `base: main` and a **drift guard** added to
  `scripts/check-release-completeness.sh` (each downstream bot-PR `base:` is pinned to
  its repo's current default branch; a mismatch fails CI). Positive + negative tested.
- Further inbound refs found by an org-wide audit: `.github`'s org-profile
  (`metadata/org-profile.yaml` + generated `profile/README.md`) links to
  `homebrew-tap/blob/master` and `/commits/master` (redirect-covered, non-breaking),
  and agent-assembly skill docs (`homebrew-tap-merge`, `release-validate-channels`)
  name the tap's `master`.
- `pull_request` triggers filtered by **`paths:`** (not `branches:`) are unaffected by
  the rename; only `branches:`/`push` filters need edits.
- Rollback (rename `main`→`master` back) was confirmed available and clean.

### Threat/adversary framing

Not adversarial — the risk is **operational breakage** (a release, a CI trigger, a
deploy, a doc link silently breaking) from an incomplete rename, especially on
release- and deploy-critical repos.

---

## Decision

### 1. `main` is the canonical org-wide default branch

Every **active** repo defaults to `main`. **Exceptions:** archived repos
(`agent-assembly-spec`); none others are exempt. Already-`main` repos are no-ops (verify only).

### 2. A repo migration MUST audit both directions

Per repo, before/at rename, discover and flip **both**:

- **Outbound** (the repo's own tree): `git grep` for `master` — workflow `branches:`
  filters, hardcoded self-URLs, `CONTRIBUTING`/`.claude/CLAUDE.md`/PR-template text.
- **Inbound** (every *other* repo that reaches into this one): org-wide grep for
  `<repo>/blob/master`, `<repo>/commits/master`, `raw.githubusercontent.com/<repo>/master`,
  and — critically — any workflow that **opens PRs into**, **`repository_dispatch`es
  into**, **fetches raw files from**, or **pins a branch ref to** this repo (e.g. a
  hardcoded `base: master` in another repo's `create-pull-request`). The tap's own grep
  did not reveal the release break; the consumer's did.

### 3. Downstream PR-base refs move in lockstep (guarded)

Any `base:` a *consumer* workflow uses to open a PR into the migrating repo MUST flip
to `main` **in the same window** as the rename — a release/automation run in the gap
breaks. Where a machine-checkable list exists, add a **drift guard** (done:
`check-release-completeness.sh` pins each downstream bot-PR `base:` to the target's
default branch). `agent-assembly/release.yml` currently hardcodes `base:` for
homebrew-tap (already `main`) + the three SDKs (still `master`) — each flips with its repo.

### 4. Reference classes to update (checklist)

- **CI**: `on.{push,pull_request}.branches` filters; `github.base_ref`/`github.ref`
  conditionals. (`paths:`-filtered `pull_request` triggers need no change.)
- **Release/fan-out**: hardcoded `base:` in cross-repo `create-pull-request`;
  `repository_dispatch` branch targets; the release-train workflows.
- **Deployment**: CD/deploy workflows keyed on `master` (e.g. `cloud`, `official-website`).
- **Documentation**: `blob/master`/`commits/master` web links + badges on `github.com`
  are redirect-covered (cosmetic), but **`raw.githubusercontent.com/…/master` does NOT
  redirect** (404) — migrate those. Prefer the default-branch-tracking `HEAD` form
  (`/blob/HEAD/`, `raw…/HEAD/`) for cross-repo links so they survive a future rename.
  Update skill/runbook prose naming a branch.
- **Local checkout**: `git branch -m master main; git fetch <remote>;
  git branch -u <remote>/main main; git remote set-head <remote> -a`.

### 5. Branch protection & open-PR handling

The GitHub rename **moves protection rules and re-targets open PRs automatically**.
After each rename, **re-verify** the required checks + approval count landed on `main`.
In-flight PRs are auto-retargeted; note any that need a manual CI re-run (a `branches:`
filter still on `master` won't fire until step 4 lands). Migrate a repo when no PR is
mid-review where feasible.

### 6. Legacy `master` — a GitHub-managed redirect, not a retained branch

A GitHub branch rename does **not** leave `master` as a separate branch that is later
deleted. The old name becomes a **GitHub-managed redirect for *supported* repository
URLs only** (the web `blob`/`tree`/`commits`/`pull` paths, and `git clone`/`push` that
resolve the default branch). There is no `master` branch to keep or remove.

- **Do NOT recreate `master`** after the rename (that would re-introduce a real,
  divergent branch and defeat the migration).
- The redirect does **NOT** cover — these break and MUST be explicitly migrated:
  - **`raw.githubusercontent.com/<repo>/master/…`** — raw content URLs do not follow
    the rename (they 404). Use `raw.githubusercontent.com/<repo>/HEAD/…` or update to
    `/main/`.
  - **`git pull`/`git fetch` targeting `master`** — a command naming the `master`
    ref/branch explicitly does not follow the rename (the ref is gone).
  - **GitHub Actions refs such as `uses: <org>/<action>@master`** — an action pinned to
    an `@master` ref does not follow the rename; the consuming workflow must update it.
  - **CI branch filters, release/dispatch targets, `actions/checkout` refs, and
    downstream PR-`base:` refs** — all must be explicitly repointed to `main`
    (per §3–§4); the redirect does not fix workflow logic.
- **Temporary compatibility `master` branch — narrow exception.** Recreating a
  short-lived `master` is permitted **only** when a repo *publishes a GitHub Action that
  external consumers reference via `@master`* (so removing the ref would break those
  consumers before they migrate). Such a branch must be **separately approved,
  documented (why it exists + which consumers), and time-bounded** (an explicit removal
  date), and tracked to deletion. It is not a general transition cushion.

### 7. Rollback

Reversible up to the point references are broadly rewritten. Rolling back is itself
**another rename** —
`gh api -X POST repos/<owner>/<repo>/branches/main/rename -f new_name=master` — which
moves the default + protection back and installs a fresh `main`→`master` redirect (it
does *not* "restore" a retained branch, because none was kept); then revert the
reference-update PR(s). The point-of-no-return is when downstream consumers + external
links have been repointed to `main` en masse — past that, roll *forward* (fix), don't
roll back.

### 8. Migration ordering & private-repository gates

1. **Pilot** — `homebrew-tap` (done, AAASM-4957).
2. **Remaining public, low-risk first** — `examples`, `e2e-public`, then the SDKs
   (`python-sdk`, `node-sdk`, `go-sdk` — each flips its `release.yml` `base:` in
   lockstep), then `.github` (also fixes the org-profile inbound links + starter
   templates so new repos default to `main`).
3. **Private repos** — `cloud`, `agent-assembly-enterprise`, `e2e-private` — **gated on
   this ADR being Accepted**; coordinate `cloud`'s deploy pipeline with its owner.
4. **`agent-assembly` LAST** — highest-traffic, most cross-referenced, drives the
   release fan-out; migrate only after the SDK/tap `base:` lockstep is proven.

---

## Accepted risks

- A brief transitional window per repo where a `branches:`-filtered CI job doesn't fire
  until its filter PR merges — bounded, visible, and cushioned by the redirect.
- `github.com` web links redirect, so stale `blob/master`/`commits/master` badges
  (e.g. `.github` org-profile) are cosmetically wrong but non-breaking until swept.
  Note this does **not** extend to `raw.githubusercontent.com/…/master`, `git fetch
  master`, or `@master` action refs — those are hard breakage and are migrated, not
  deferred.

## Explicitly forbidden designs

- **Do not** migrate a repo by only grepping its *own* tree — the release-breaking
  coupling is in consumers (the pilot's central lesson).
- **Do not** flip a downstream `base:`/dispatch ref out of lockstep with the target's
  rename — a release/automation run in the gap breaks.
- **Do not** recreate `master` after a rename — except the narrow, separately-approved,
  documented, time-bounded compatibility case for a repo that *publishes* a GitHub
  Action consumed via `@master` (§6).
- **Do not** migrate `agent-assembly` before the SDK/tap `base:` lockstep is done.
- **Do not** start the private repos before this ADR is Accepted.

## Consequences

- **Operators/contributors**: uniform `main`; old clones keep working via redirect but
  should re-point. **Release owner**: must migrate each SDK's `release.yml` `base:` with
  its repo. **Future contributors**: one reviewed procedure + a drift guard, not tribal
  knowledge.

## Operational guidance

Update the tooling conventions that hardcode `master` **as part of this ADR's landing**:
the workspace `.claude/CLAUDE.md` ("PR base branch always master" / "never push to
master/release branches"), `.claude/rules/02-git-workflow.md`, branch-naming docs, and
per-repo `CONTRIBUTING.md`/PR templates → `main`.

## Validation requirements

Per migrated repo, evidence that: default = `main`; protection re-verified on `main`;
outbound refs swept (`git grep master` clean of branch refs); inbound refs swept
(org-wide grep for that repo's `blob/master`/`commits/master`/`raw…/master`/`@master`/
`base:`); the redirect-uncovered refs (`raw.githubusercontent…/master`, `git fetch
master`, `@master` action refs) are explicitly migrated; CI fires on `main`;
release/deploy paths validated; local checkout re-pointed; **no `master` branch was
recreated** (and any narrow `@master`-published-Action compatibility branch is
documented, time-bounded, and tracked to removal). The
`check-release-completeness.sh` downstream-base guard stays green.

## Reconsideration triggers

A new repo added to the org (must default to `main` via the `.github` starter
templates); a new cross-repo automation that pins a branch ref; discovery of a
reference class this checklist misses.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-4955](https://lightning-dust-mite.atlassian.net/browse/AAASM-4955) | The migration Epic this ADR governs |
| [AAASM-4957](https://lightning-dust-mite.atlassian.net/browse/AAASM-4957) | homebrew-tap pilot — evidence source |
| [AAASM-4958…4967](https://lightning-dust-mite.atlassian.net/browse/AAASM-4955) | Per-repo migration tasks that follow this ADR |
| [ADR 0014](0014-canonical-metadata-registry-and-drift-gate.md) | Related — `.github` registry/org-profile inbound refs |
| Implementation | homebrew-tap #50, agent-assembly #1620 (pilot + release-base guard) |
