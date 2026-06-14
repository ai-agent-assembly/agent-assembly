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

### 2. Compute the per-crate file set

The version literal appears in the workspace `Cargo.toml` and in every
member crate's `Cargo.toml`. Enumerate them:

```bash
git grep -l "^version = \"$CURRENT\"" -- '**/Cargo.toml' Cargo.toml | sort -u
```

For reference, the AAASM-2849 alpha-9 bump touched **~16 crates with ~43
literal occurrences**. Expect a file count in that order of magnitude. Surface
the file list to the operator before mutating.

### 3. `sed` each literal in place; commit

Replace in every enumerated file, then create one atomic commit:

```bash
git grep -l "^version = \"$CURRENT\"" -- '**/Cargo.toml' Cargo.toml \
  | xargs sed -i.bak -E "s/^version = \"$CURRENT\"$/version = \"<X>\"/"
find . -name 'Cargo.toml.bak' -delete

git add -A
git commit -m "🔧 (release): Bump workspace to v<X>"
```

After this commit, every Cargo.toml that previously declared `$CURRENT`
must now declare `<X>` exactly. Verify with
`git grep -l "^version = \"$CURRENT\"" -- '**/Cargo.toml' Cargo.toml`
returning empty.

### 4. Regenerate `Cargo.lock` — separate commit

`Cargo.lock` is regenerated separately so the diff is reviewable in isolation
and the version-bump commit stays minimal:

```bash
cargo update --workspace
git add Cargo.lock
git commit -m "🔧 (release): Regenerate Cargo.lock for v<X>"
```

If `cargo update --workspace` is unavailable in the environment (network
sandbox, etc.) fall back to `cargo generate-lockfile` and re-resolve.

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

## What this skill explicitly does not do

- Open the bump PR (that is the operator's job, per RUNBOOK section 1).
- Merge the Homebrew tap PR (RUNBOOK section 4, operator-gated).
- Re-trigger failed `release-*.yml` workflows (RUNBOOK section 6).
- Cut an `agent-assembly` tag for an SDK-only hotfix (RUNBOOK section 7;
  use the per-SDK runbook instead).
- Touch repos other than `ai-agent-assembly/agent-assembly`.
