# release-tag-cut — detailed reference

The step-by-step detail behind the concise plan in [SKILL.md](SKILL.md). Each
section below expands one step of the Executable plan with the exact commands,
edge-cases, and the no-op guard rationale. For a concrete end-to-end run, see
[EXAMPLES.md](EXAMPLES.md).

## Contents

- [Pre-conditions](#pre-conditions)
- [Executable plan](#executable-plan)
  - [1. Resolve the current version literal](#1-resolve-the-current-version-literal)
  - [2. Bump every Cargo.toml version literal + regenerate Cargo.lock](#2-bump-every-cargotoml-version-literal--regenerate-cargolock)
  - [3. Commit the version bump — Cargo.toml diff only](#3-commit-the-version-bump--cargotoml-diff-only)
  - [4. Commit `Cargo.lock` separately — reviewable in isolation](#4-commit-cargolock-separately--reviewable-in-isolation)
  - [5. Finalize release notes](#5-finalize-release-notes)
  - [6. Run the release gate — `scripts/release-readiness.sh`](#6-run-the-release-gate--scriptsrelease-readinesssh)
  - [7. Create and push the annotated tag — `scripts/release-tag-guard.sh`](#7-create-and-push-the-annotated-tag--scriptsrelease-tag-guardsh)
- [Post-conditions](#post-conditions)
- [What's expected when done](#whats-expected-when-done)
- [What's auto-handled (do NOT manually run)](#whats-auto-handled-do-not-manually-run)

## Pre-conditions

All of the following MUST hold before any step below runs. If any fails,
stop and report — do not attempt to remediate from inside this skill.

1. **Working tree clean** — `git status --porcelain` returns no output.
2. **On `main`, up to date with `remote/main`** —
   `git rev-parse --abbrev-ref HEAD` is `main`, and
   `git rev-list --count remote/main..HEAD` and
   `git rev-list --count HEAD..remote/main` both return `0`.
   (Run `git fetch remote` first.)
3. **Most recent CI run on main is green** — query via
   `gh run list --branch main --limit 1 --json conclusion,status`
   and confirm `status=completed` and `conclusion=success`.
4. **Target version provided** — the operator supplies `<X>` (e.g.
   `0.0.1-alpha.10`). The skill does not invent or bump version numbers.
5. **Security sign-off PASS for `<X>`** — `docs/release/security-signoff/v<X>.md`
   exists and its verdict line is `Verdict: PASS` (stage 0,
   `/release-security-gate <X>`). Mirrored by `scripts/release-readiness.sh`
   check 11, re-verified in step 6 below.
6. **QA sign-off PASS for `<X>`** — `docs/release/qa-signoff/v<X>.md` exists
   and its verdict line is `Verdict: PASS` (stage 0, `/release-qa-gate <X>` in
   `release` depth). Mirrored by `scripts/release-readiness.sh` check 12,
   independently of check 5/11 above — re-verified in step 6 below.

## Executable plan

The whole sequence runs inside the main `agent-assembly/` repository checkout
(not a worktree). Substitute the operator-supplied `<X>` for the target
version throughout.

### 1. Resolve the current version literal

Extract the current workspace version from `Cargo.toml`:

```bash
CURRENT="$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)"/\1/')"
echo "current=$CURRENT target=<X>"
```

`$CURRENT` is the literal that must be replaced everywhere. Refuse to proceed
if `$CURRENT` equals `<X>` (no-op release) or if the value cannot be parsed.

### 2. Bump every Cargo.toml version literal + regenerate Cargo.lock

Run the helper script — it enumerates `**/Cargo.toml` declaring `$CURRENT`,
sed-replaces each, bumps `sonar.projectVersion`, regenerates `Cargo.lock`, and
refuses no-op invocations:

```bash
./scripts/release-tag-cut.sh "$CURRENT" "<X>"
```

The script prints the file list before mutating (sanity check it), then
runs `cargo update --workspace`. For reference, the AAASM-2849 alpha-9 cut
touched **~16 crates with ~43 literal occurrences**.

It also bumps `sonar.projectVersion` in `sonar-project.properties` from
`$CURRENT` to `<X>` so SonarCloud's reported project version tracks the release
instead of going stale (AAASM-3819). The static value is the source of truth /
local-scan fallback; `ci.yml` additionally overrides it dynamically from the
Cargo version at scan time, so the line only needs to match `$CURRENT` for the
helper to rewrite it — if it has drifted, the helper warns and leaves it
untouched rather than failing the release.

### 3. Commit the version bump — manifests + sonar

```bash
git add '**/Cargo.toml' Cargo.toml sonar-project.properties
git commit -m "🔧 (release): Bump workspace to v<X>"
```

Verify with `git grep -l "^version = \"$CURRENT\""` returning empty.

### 4. Commit `Cargo.lock` separately — reviewable in isolation

```bash
git add Cargo.lock
git commit -m "🔧 (release): Regenerate Cargo.lock for v<X>"
```

If the helper's `cargo update --workspace` failed (network sandbox, etc.),
fall back to `cargo generate-lockfile` and re-resolve before committing.

### 5. Finalize release notes

Create the release-notes file if missing — copy from the previous release
and edit to reflect the new version's changeset — and commit it. This is
the last content commit before the gate in step 6; version metadata,
CHANGELOG, and release notes must all be finalized on this exact commit,
because step 7's guard requires the release-evidence record's
`candidate_sha` to equal it with zero drift.

```bash
NOTES="docs/release/v<X>.md"
if [ ! -f "$NOTES" ]; then
  PREV="docs/release/v$CURRENT.md"
  cp "$PREV" "$NOTES"
  $EDITOR "$NOTES"   # update title + changeset
  git add "$NOTES"
  git commit -m "📝 (release): Add release notes for v<X>"
fi
```

Do not push intermediate commits to main from inside this skill — the
bump PR (RUNBOOK section 1) should already be merged before invocation.
This skill's only push is the tag itself (step 7).

### 6. Run the release gate — `scripts/release-readiness.sh`

```bash
bash scripts/release-readiness.sh "<X>"
```

Run this from the exact commit produced by step 5. All 14 checks must
report ✓: working tree/branch/CI mechanical state, version/CHANGELOG/notes
literals, required secrets, no stale Homebrew tap PR, the pinned-pip-install
check, the security sign-off `Verdict: PASS` (check 11, pre-condition 5
above), the QA sign-off `Verdict: PASS` (check 12, pre-condition 6 above,
independently of check 11), every published crate has a README, and
release-evidence binding to HEAD via `check-release-evidence.py` (check 14).
Any ✗ stops the run here — this step exists specifically because, before
AAASM-5879, nothing in this skill ever invoked this script, so a tag could
be created and pushed in step 7 (formerly step 6) without any of these 14
checks having run at all. Resolve the failing check(s) and re-run before
proceeding; do not skip a check to reach a green run.

### 7. Create and push the annotated tag — `scripts/release-tag-guard.sh`

```bash
bash scripts/release-tag-guard.sh "<X>"
```

This is the only sanctioned way this skill creates/pushes the tag — it is
not a convenience wrapper around step 6, it is independent enforcement:

- Refuses if the configured push remote does not resolve to
  `ai-agent-assembly/agent-assembly` (no `--remote` override in this call).
- Refuses on a dirty working tree, or if `git fetch remote` fails.
- Refuses if `v<X>` already exists locally or on the remote.
- Re-runs `scripts/release-readiness.sh <X>` itself — step 6 above is not a
  cache the guard trusts; every invocation of this script re-verifies all
  14 checks fresh.
- Enforces a **strict** `candidate_sha == HEAD` binding by reading
  `docs/release/qa-signoff/v<X>.evidence.json` directly and comparing it to
  `git rev-parse HEAD` byte-for-byte. This is *stricter* than readiness
  check 14's own R1 rule inside `check-release-evidence.py`, which
  deliberately tolerates mechanical-only drift (e.g. a version-bump commit
  made after QA captured its candidate) between `candidate_sha` and the tag
  target — correct for that checker's purpose, but not for the literal
  commit this script is seconds from tagging. A `HEAD~1` candidate that R1
  would still pass is still refused here.
- Has **no skip flag of any kind** — an operator/agent that wants to bypass
  a check here has to edit this reviewable script, not flip an env var.
- Only once every check above passes does it `git tag -a "v<X>"` and
  `git push remote "v<X>"`, which triggers `release.yml`.

**No `LEFTHOOK=0`.** A prior version of this step used
`LEFTHOOK=0 git push remote "v<X>"` to bypass the local `cargo doc`
pre-push hook. Measured (AAASM-5879, throwaway local bare-repo push):
`lefthook.toml`'s `pre-push.commands.doc` gates on `files = git diff
--name-only HEAD @{push}` (with the AAASM-5838 merge-base fallback) — a
tag-only push never moves the branch ref, so that diff is empty both before
and after the push, which is exactly the "pushing a ref that is not HEAD ...
computes an empty file set and skips" gap `lefthook.toml`'s own comment
block already documents (AAASM-5726/5838). The doc hook is therefore
already a no-op for a tag-only push without any bypass — `LEFTHOOK=0` was a
governed-but-unnecessary hook bypass in a skill whose contract says it has
no bypass authority, so it is removed rather than kept as a "governed
exception."

## Post-conditions

After step 7 completes, all of the following MUST hold:

1. **Tag exists on remote** —
   `git ls-remote --tags remote "v<X>"` returns one line referencing the
   tag SHA.
2. **`release.yml` run is `in_progress` or `queued`** —
   `gh run list --workflow release.yml --limit 1 --json status,headBranch`
   shows `headBranch=v<X>` and `status` in `{queued, in_progress}`.

Surface both confirmations to the operator, then suggest:

> Tag `v<X>` is live. Once `release.yml` finishes
> (`gh run watch --workflow release.yml`), invoke
> `/release-validate-channels v<X>` to walk through the downstream channel
> matrix (GH Release, crates.io, Homebrew tap PR, ghcr.io images, npm,
> PyPI) per `docs/release/RUNBOOK.md` sections 3–5.

Then **advance the Jira Fix Version ladder** (SKILL.md → "advance the Jira Fix
Version ladder"): mark the just-cut version released and create the next one for
the `agent-assembly` core train and each affected SDK/component train, per
`ticket-authoring`'s `references/fix-versions.md`. Reminder only — the operator
(or a credentialed release job) creates the versions.

## What's expected when done

When this skill exits cleanly, the operator should be able to confirm
success by running these two commands directly:

```bash
# 1. Tag is visible on the remote.
git ls-remote --tags remote v<X>
# Expected: one line — <sha>\trefs/tags/v<X>

# 2. release.yml is queued, in-progress, or already succeeded for this tag.
gh run list --workflow release.yml --limit 1
# Expected: a row with HEAD BRANCH=v<X> and STATUS in
#           {queued, in_progress, completed} (conclusion=success if completed).
```

If either check returns empty / not-found, the skill did not complete the
push — re-run step 7 (`scripts/release-tag-guard.sh <X>`) or investigate the failure before declaring done.

Once `release.yml` has finished (watch with
`gh run watch --workflow release.yml`), the operator's next move is:

```text
/release-validate-channels v<X>
```

That skill walks the downstream channel matrix (GH Release artifacts,
crates.io propagation, Homebrew tap PR review, ghcr.io image push, npm and
PyPI publish) per `docs/release/RUNBOOK.md` sections 3–5.

## What's auto-handled (do NOT manually run)

Once the tag is pushed, `release.yml` and its downstream jobs perform the
following actions automatically. The operator MUST NOT replicate any of
these by hand — doing so will either duplicate publishes or break the
workflow's idempotency assumptions:

- **GitHub Release creation** — the `publish` job in `release.yml` auto-runs
  `gh release create` against `v<X>` with the generated artifacts and the
  body sourced from `docs/release/v<X>.md`. Do NOT run `gh release create`
  manually.
- **`cargo publish` for every workspace crate** — the `publish-crates` job
  walks the crate dependency order and publishes each crate to crates.io in
  the right sequence. Do NOT run `cargo publish` on any crate by hand.
- **Homebrew tap PR** — the `update-homebrew-tap` job auto-opens a bump PR
  against `ai-agent-assembly/homebrew-tap`. The operator's only job is to
  merge it via the `/homebrew-tap-merge` skill once it's green; do NOT open
  the tap PR manually.
- **Downstream SDK fanout** — the `notify-downstream-sdks` job fires a
  `repository_dispatch` event into `node-sdk` and `python-sdk` (and any
  future SDK repo on the dispatch list). Do NOT manually `gh workflow run`
  or open SDK PRs for the version bump.
- **FFI source-pin bump PRs on the SDKs** (post-AAASM-2883) — the
  `update-node-sdk-ffi-pin` and `update-python-sdk-ffi-pin` jobs auto-open
  PRs against `node-sdk` and `python-sdk` to advance the `aa-ffi-*` git-SHA
  pin to the freshly tagged revision. Do NOT push manual pin-bump commits;
  the bot PRs are the source of truth.

If a job listed above fails inside `release.yml`, fix the workflow (or
re-run via the GH Actions UI) — do NOT compensate by running the underlying
command locally. Local compensation will diverge from the workflow's audit
log and is explicitly out of scope for this skill.
