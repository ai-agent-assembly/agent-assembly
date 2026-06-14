---
name: release-tag-cut
description: Cut a coordinated agent-assembly release tag — bump workspace Cargo version literals, regenerate Cargo.lock, tag, and push.
---

# release-tag-cut

Executable contract for cutting an agent-assembly release tag from a clean
`master`. The canonical prose, recovery procedure, manual gates, and downstream
channel matrix live in [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md);
this SKILL.md only encodes the steps Claude Code itself runs.

> This skill ends at `git push remote v<X>`. The post-tag verification loop
> (Homebrew tap PR merge, crates.io / PyPI / npm propagation, ghcr.io image
> push) is owned by `/release-validate-channels`, invoked by the operator once
> `release.yml` finishes.

## When to use

Pick this skill when **all** of the following hold:

- The operator has decided agent-assembly is ready for a new pre-release tag
  in the alpha series (e.g. cutting `0.0.1-alpha.10` after `0.0.1-alpha.9`).
- The most recent CI run on `master` is green.
- Draft release notes exist (or the operator is prepared to write them inline
  during step 5).
- The working tree is clean and `master` is up to date with `remote/master`.

The triggering operator phrasing is typically:

> "Cut alpha-N+1", "Tag v0.0.1-alpha.10", "Release the next alpha".

## When NOT to use

This skill is **alpha-series, agent-assembly-monorepo, full-fanout** specific.
Pick a different path in any of the following cases:

- **SDK-only release** — use `/sdk-only-release` (or the equivalent skill) in
  the target SDK repo (`python-sdk`, `node-sdk`, `go-sdk`). Cutting an
  `agent-assembly` tag for an SDK-only change wastes a full crates.io publish
  cycle.
- **GA or non-pre-release tag** (`v1.0.0`, `v0.1.0`, etc.) — this skill is
  intentionally scoped to the alpha pre-release cadence. A GA cut needs the
  release-readiness checklist + manual review, not this autopilot path.
- **Hotfix to an already-tagged release** — use the SDK-only path (if the fix
  is SDK-side) or a follow-up patch tag coordinated via the RUNBOOK; do not
  re-cut the same tag.
- **Pre-conditions not met** — if `master` is dirty, behind `remote/master`,
  or has a red CI run, stop and surface the gap to the operator instead of
  running this skill.

## How to use

**Invocation**:

```text
/release-tag-cut <X>
```

where `<X>` is the target version literal exactly as it will appear in
`Cargo.toml` and in the git tag (e.g. `0.0.1-alpha.10`, NOT `v0.0.1-alpha.10`
— the leading `v` is added only at tag time).

**Required context**:

- Repository checkout is the main `agent-assembly/` working tree, not a
  worktree. Tags are pushed from the main checkout per project convention.
- `remote` is the configured remote name pointing at
  `ai-agent-assembly/agent-assembly` (project convention — not `origin`).
- The operator has supplied `<X>`; the skill never invents a version number.

**Parameter substitution**:

Every `<X>` placeholder in the Executable plan below binds to the
operator-supplied version. Treat each `<X>` as a literal string replacement
applied at the start of execution; do not derive or increment versions
mid-run.

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

## Worked example

Concrete walk-through of cutting `0.0.1-alpha.10` from a baseline of
`0.0.1-alpha.9`. Use this as the executable template; substitute your own
`<X>` and current literal.

### Step 1 — resolve the current literal

```bash
$ CURRENT="$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)"/\1/')"
$ echo "current=$CURRENT target=0.0.1-alpha.10"
current=0.0.1-alpha.9 target=0.0.1-alpha.10
```

### Step 2 — enumerate the file set

```bash
$ git grep -l '^version = "0.0.1-alpha.9"' -- '**/Cargo.toml' Cargo.toml | sort -u
Cargo.toml
crates/aa-api/Cargo.toml
crates/aa-cli/Cargo.toml
crates/aa-cli-ent/Cargo.toml
crates/aa-core/Cargo.toml
crates/aa-ebpf/Cargo.toml
crates/aa-ffi-go/Cargo.toml
crates/aa-ffi-python/Cargo.toml
crates/aa-gateway/Cargo.toml
crates/aa-proto/Cargo.toml
crates/aa-proxy/Cargo.toml
crates/aa-runtime/Cargo.toml
crates/aa-sdk-client/Cargo.toml
crates/aa-security/Cargo.toml
crates/aa-storage/Cargo.toml
crates/aa-wasm/Cargo.toml
# 16 files; ~43 literal occurrences (matches AAASM-2849)
```

### Steps 2-4 — run the helper, then commit in two atomic stages

```bash
$ ./scripts/release-tag-cut.sh 0.0.1-alpha.9 0.0.1-alpha.10
==> Enumerating Cargo.toml files declaring version = "0.0.1-alpha.9"
==> Found 16 file(s):
    Cargo.toml
    crates/aa-api/Cargo.toml
    ... (14 more)
==> Replacing version literal in each file
==> Cleaning up .bak sidecars
==> Regenerating Cargo.lock via cargo update --workspace
    Updating crates.io index
==> Done. Bumped 16 Cargo.toml file(s): 0.0.1-alpha.9 -> 0.0.1-alpha.10
    Cargo.lock regenerated.
    Next: review the diff, commit, tag, push.

$ git diff --stat
 Cargo.toml                       | 2 +-
 Cargo.lock                       | 86 ++++++++++++++++++++--------------------
 crates/aa-api/Cargo.toml         | 2 +-
 ... (14 more Cargo.toml files)
 17 files changed, 87 insertions(+), 87 deletions(-)

# Stage 1: bump commit (Cargo.toml only)
$ git add '**/Cargo.toml' Cargo.toml
$ git commit -m "🔧 (release): Bump workspace to v0.0.1-alpha.10"

# Stage 2: lock regen commit (Cargo.lock only)
$ git add Cargo.lock
$ git commit -m "🔧 (release): Regenerate Cargo.lock for v0.0.1-alpha.10"
```

### Step 5 — release notes + annotated tag

```bash
$ NOTES="docs/release/v0.0.1-alpha.10.md"
$ [ -f "$NOTES" ] || cp docs/release/v0.0.1-alpha.9.md "$NOTES"
$ $EDITOR "$NOTES"   # update title, changeset
$ git add "$NOTES"
$ git commit -m "📝 (release): Add release notes for v0.0.1-alpha.10"

$ git tag -a "v0.0.1-alpha.10" -m "Release v0.0.1-alpha.10

See docs/release/v0.0.1-alpha.10.md for details."
```

### Step 6 — push the tag, then watch `release.yml`

```bash
$ LEFTHOOK=0 git push remote v0.0.1-alpha.10
To github.com:ai-agent-assembly/agent-assembly.git
 * [new tag]         v0.0.1-alpha.10 -> v0.0.1-alpha.10

$ gh run watch --workflow release.yml
✓ release.yml · 9876543210
Triggered via push about 5s ago

JOBS
* build                  in_progress
* publish-crates         queued
* publish-docker         queued
* update-homebrew-tap    queued
* notify-downstream-sdks queued
```

At this point the skill is done. The remainder of the release flow runs
inside `release.yml` and is verified by `/release-validate-channels`.

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

## What this skill explicitly does not do

- Open the bump PR (that is the operator's job, per RUNBOOK section 1).
- Merge the Homebrew tap PR (RUNBOOK section 4, operator-gated).
- Re-trigger failed `release-*.yml` workflows (RUNBOOK section 6).
- Cut an `agent-assembly` tag for an SDK-only hotfix (RUNBOOK section 7;
  use the per-SDK runbook instead).
- Touch repos other than `ai-agent-assembly/agent-assembly`.
