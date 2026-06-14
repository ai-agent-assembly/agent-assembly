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
  - [5. Create the annotated tag](#5-create-the-annotated-tag)
  - [6. Push the tag — triggers `release.yml`](#6-push-the-tag--triggers-releaseyml)
- [Post-conditions](#post-conditions)
- [What's expected when done](#whats-expected-when-done)
- [What's auto-handled (do NOT manually run)](#whats-auto-handled-do-not-manually-run)

## Pre-conditions

All of the following MUST hold before any step below runs. If any fails,
stop and report — do not attempt to remediate from inside this skill.

1. **Working tree clean** — `git status --porcelain` returns no output.
2. **On `master`, up to date with `remote/master`** —
   `git rev-parse --abbrev-ref HEAD` is `master`, and
   `git rev-list --count remote/master..HEAD` and
   `git rev-list --count HEAD..remote/master` both return `0`.
   (Run `git fetch remote` first.)
3. **Most recent CI run on master is green** — query via
   `gh run list --branch master --limit 1 --json conclusion,status`
   and confirm `status=completed` and `conclusion=success`.
4. **Target version provided** — the operator supplies `<X>` (e.g.
   `0.0.1-alpha.10`). The skill does not invent or bump version numbers.

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
sed-replaces each, regenerates `Cargo.lock`, and refuses no-op invocations:

```bash
./scripts/release-tag-cut.sh "$CURRENT" "<X>"
```

The script prints the file list before mutating (sanity check it), then
runs `cargo update --workspace`. For reference, the AAASM-2849 alpha-9 cut
touched **~16 crates with ~43 literal occurrences**.

### 3. Commit the version bump — Cargo.toml diff only

```bash
git add '**/Cargo.toml' Cargo.toml
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

### 5. Create the annotated tag

The tag is annotated and references the release-notes file. Create the
notes file first if missing — copy from the previous release and edit
to reflect the new version's changeset.

```bash
NOTES="docs/release/v<X>.md"
if [ ! -f "$NOTES" ]; then
  PREV="docs/release/v$CURRENT.md"
  cp "$PREV" "$NOTES"
  $EDITOR "$NOTES"   # update title + changeset
  git add "$NOTES"
  git commit -m "📝 (release): Add release notes for v<X>"
fi

git tag -a "v<X>" -m "Release v<X>

See docs/release/v<X>.md for details."
```

Do not push intermediate commits to master from inside this skill — the
bump PR (RUNBOOK section 1) should already be merged before invocation.
This skill's only push is the tag itself.

### 6. Push the tag — triggers `release.yml`

```bash
LEFTHOOK=0 git push remote "v<X>"
```

`LEFTHOOK=0` bypasses the local `cargo doc` pre-push hook which fails on
macOS due to the eBPF target — this is the project convention, not a
security bypass. The push is tag-only and does not touch a branch.

## Post-conditions

After step 6 completes, all of the following MUST hold:

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
push — re-run step 6 or investigate the failure before declaring done.

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
