---
name: homebrew-tap-merge
description: Verify + merge the auto-opened homebrew-agent-assembly bot PR for a new agent-assembly release.
---

# SKILL.md — homebrew-tap-merge

## Purpose
Codify the bot-PR-to-merge flow on the `ai-agent-assembly/homebrew-agent-assembly`
tap. After each `agent-assembly` release, the `update-homebrew-tap` job in
`release.yml` (see `docs/release/RUNBOOK.md` § "Manual gate — merge the
Homebrew tap PR") opens a `bot/aasm-<version>` PR that updates `Formula/aasm.rb`
with the new version + 4 SHA256 sums. Merging is mechanically simple but has
gotchas worth codifying — this skill owns that flow.

The skill lives in `agent-assembly` because the `homebrew-agent-assembly` tap
repo has no Jira component; the skill is logically owned by the upstream that
publishes to it.

## When to use

Invoke this skill when `agent-assembly`'s `release.yml` has finished its
`update-homebrew-tap` job and a `bot/aasm-<version>` PR is now open on
`ai-agent-assembly/homebrew-agent-assembly`, and the operator (or
`release-watch`) wants to verify the bot diff and merge it so `brew install
aasm` picks up the new release.

## When NOT to use

- **Tap PR not yet open** — `release.yml` hasn't finished `update-homebrew-tap`
  yet. Wait for the upstream release workflow rather than opening a manual PR.
- **Tap PR has manual edits beyond the bot's diff** — anything outside the
  version line + 4 sha256 lines is out of scope for this skill. Escalate; do
  not auto-merge a hand-edited formula.
- **AAASM-2871 (Homebrew/brew#22719) is patched upstream** — if the tap's
  `brew install + test` workflow no longer needs `HOMEBREW_NO_REQUIRE_TAP_TRUST=1`,
  the stale-master rebase shortcut may no longer be required; re-evaluate the
  step 3 branch before relying on this skill verbatim.

## Type
Command-like. Invoked manually after a release tag is pushed, or by
`release-watch` / `/release-preparation` when the Homebrew channel is still
red in `scripts/check-release.sh` output.

## Pre-conditions
- Bot PR number provided (resolve via
  `gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open`).
- Upstream `agent-assembly` release for the same tag is published.
- `SHA256SUMS` asset exists on the upstream release.

## How to use

Invoke from a shell or via the slash command:

```text
/homebrew-tap-merge <PR_NUMBER>
```

Example: `/homebrew-tap-merge 16` — verify + merge tap PR #16 for
`aasm 0.0.1-alpha.9`.

**Required inputs**:

- `<PR_NUMBER>` — the bot PR number on
  `ai-agent-assembly/homebrew-agent-assembly`. Resolve with
  `gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open`.
- Upstream `agent-assembly` release for the matching tag must already be
  published with the `SHA256SUMS` asset attached (the helper script
  `scripts/verify-tap-sha256.sh` downloads this).

## Do Not Assume
- Do not assume the 4 sha256 lines in `Formula/aasm.rb` are correct — verify
  every one against the upstream `SHA256SUMS` asset.
- Do not assume a red `brew install + test (macOS)` check is a real failure
  — check if the PR is on a stale master first (see step 3 below).
- Do not assume Homebrew/brew#22719 has shipped — the AAASM-2871 quirk is
  still live as of this skill's authoring.

## Executable plan

### 1. Verify PR scope

```bash
gh pr view <n> --repo ai-agent-assembly/homebrew-agent-assembly \
  --json files,additions,deletions
```

Expected: single file `Formula/aasm.rb`, ~5 additions and ~5 deletions
(version line + 4 sha256 lines). Reject anything broader as out-of-scope.

### 2. Cross-verify all 4 sha256 lines vs upstream

Run the helper:

```bash
./scripts/verify-tap-sha256.sh <tag> [<pr>]
# e.g. ./scripts/verify-tap-sha256.sh v0.0.1-alpha.9 16
```

Exits 0 iff all 4 sha256s in the formula match the upstream `SHA256SUMS`
asset (one per platform — `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`). Non-zero exit
prints a mismatch table — **escalate; do not merge**.

For ad-hoc inspection, the equivalent manual flow is:

```bash
gh release download <tag> -A SHA256SUMS \
  --repo ai-agent-assembly/agent-assembly --dir /tmp/aasm-<tag>
gh pr diff <n> --repo ai-agent-assembly/homebrew-agent-assembly
```

### 3. Handle red `brew install + test (macOS)` check

Check whether the PR is on stale master:

```bash
gh pr view <n> --repo ai-agent-assembly/homebrew-agent-assembly \
  --json baseRefOid,mergeable,mergeStateStatus
```

- **If `mergeStateStatus` is `BEHIND` or the base SHA is older than master's tip**
  — trigger a server-side rebase (avoids local force-push, works through the
  classifier):

  ```bash
  gh api -X PUT \
    /repos/ai-agent-assembly/homebrew-agent-assembly/pulls/<n>/update-branch \
    -f update_method=rebase
  ```

  The endpoint takes an optional `expected_head_sha` for safety. Wait for CI
  to re-run, then re-evaluate.

- **If the PR is up to date** — surface the failure log:

  ```bash
  gh run view --repo ai-agent-assembly/homebrew-agent-assembly \
    --job <id> --log-failed
  ```

  Look for the AAASM-2871 fingerprint: `sandbox-exec` exits with status 1
  silently inside the `brew install + test` step. See memory entry
  `project_homebrew_tap_sandbox_kills_install` for full context.

### 4. Merge

Once CI is green and sha256s are verified:

```bash
gh pr merge <n> --repo ai-agent-assembly/homebrew-agent-assembly --squash
```

Use the tap's configured strategy (squash, per `docs/release/RUNBOOK.md`).

## Worked example — alpha-9 (2026-06-14)

PR [#16](https://github.com/ai-agent-assembly/homebrew-agent-assembly/pull/16)
on `ai-agent-assembly/homebrew-agent-assembly`, titled `🤖 (formula): aasm
0.0.1-alpha.9`, opened by the release-bot at 2026-06-13 18:09 UTC after the
upstream `v0.0.1-alpha.9` tag push triggered `release.yml`'s
`update-homebrew-tap` job.

**Initial state**: `brew install + test (macOS)` check RED with the
AAASM-2871 silent `sandbox-exec` SIGKILL fingerprint (PR was based on a
pre-`HOMEBREW_NO_REQUIRE_TAP_TRUST=1` master tip).

**Step 1 — Scope check**:

```bash
gh pr view 16 --repo ai-agent-assembly/homebrew-agent-assembly \
  --json files,additions,deletions
# → single file Formula/aasm.rb, ~5 additions, ~5 deletions  ✓
```

**Step 2 — Cross-verify 4 sha256s**:

```bash
./scripts/verify-tap-sha256.sh v0.0.1-alpha.9 16
# OK: all 4 sha256 entries match upstream SHA256SUMS for v0.0.1-alpha.9.
```

The four sha256 values pinned in the PR diff (also present in upstream
`SHA256SUMS`):

| Platform                       | sha256 (alpha-9)                                                   |
|--------------------------------|--------------------------------------------------------------------|
| `aarch64-apple-darwin`         | `1e08c94b…` (darwin-arm)                                           |
| `x86_64-apple-darwin`          | `047e0cb5…` (darwin-intel)                                         |
| `aarch64-unknown-linux-gnu`    | `95b7f7ca…` (linux-arm)                                            |
| `x86_64-unknown-linux-gnu`     | `311be632…` (linux-x64)                                            |

**Step 3 — Detect stale-master + server-side rebase**:

```bash
gh pr view 16 --repo ai-agent-assembly/homebrew-agent-assembly \
  --json mergeStateStatus
# → "BEHIND"

gh api -X PUT \
  /repos/ai-agent-assembly/homebrew-agent-assembly/pulls/16/update-branch \
  -f update_method=rebase
```

This pulls in the `HOMEBREW_NO_REQUIRE_TAP_TRUST=1` env applied to the tap's
`brew install + test` workflow on master, so the CI re-run no longer trips
the AAASM-2871 sandbox quirk.

**Step 4 — Wait for CI re-run + merge**:

```bash
# brew install + test (macOS) goes green; the success log contains:
#   Pouring … Cellar/aasm/0.0.1-alpha.9: 3 files, 21.5MB, built in 1 second

gh pr merge 16 --repo ai-agent-assembly/homebrew-agent-assembly --squash
```

Verifies the AAASM-2871 workaround is active in workflow env, then squashes
in the formula bump.

## Post-conditions
- Tap `master` branch's `Formula/aasm.rb` has the new version + 4 sha256s.
- `brew install aasm` (on a fresh `brew update`) now resolves to the new
  version. Until the merge happens, `brew install aasm` still resolves to
  the previous version — the bot branch is invisible to `brew install`.
- Suggest follow-up: invoke `/release-validate-channels` (or re-run
  `scripts/check-release.sh v<version>`) to confirm the Homebrew row goes
  green.

## What's expected when done

When this skill completes successfully, all of the following must hold:

- Tap `master`'s `Formula/aasm.rb` shows the new `version "<X>"` line and
  the 4 sha256s that match upstream `SHA256SUMS` for the corresponding tag.
- The bot PR is **closed and merged** (squash), not just approved.
- The operator can immediately follow up with
  `/release-validate-channels v<X>` and see the Homebrew row report ✓.

Quick verification command from any shell with `gh` configured:

```bash
gh api /repos/ai-agent-assembly/homebrew-agent-assembly/contents/Formula/aasm.rb \
  -H "Accept: application/vnd.github.raw" | grep -E "^  version |^      sha256"
```

The output should print one `version "<X>"` line and four `sha256 "<hash>"`
lines matching the upstream release.

## What's auto-handled (do NOT manually run)

These steps are owned by the release pipeline or are explicitly forbidden
inside this skill — do not attempt them manually:

- **Opening the bot PR** — handled by `release.yml`'s `update-homebrew-tap`
  job, triggered on every `agent-assembly` tag push. Wait for it; do not
  hand-open a tap PR.
- **Editing `Formula/aasm.rb` by hand** — never. Any manual edit will be
  undone by the next bot rebase, and a mismatched sha256 indicates a real
  release-artifact problem upstream (escalate, do not "fix" the formula).
- **`brew update-bottles` / `brew bottle …`** — not part of this tap's
  lifecycle. The tap installs from binary tarballs (no bottle DSL); there
  is nothing to bottle here.
- **Local `git push --force` to the bot branch** — use the server-side
  `gh api … /pulls/<n>/update-branch -f update_method=rebase` pattern from
  step 3. The classifier blocks local force-push to active PRs without
  explicit auth, and a force-push would also break the bot's audit trail.

## AAASM-2871 quirk (live until Homebrew/brew#22719 ships)

The `brew install + test (macOS)` check requires
`HOMEBREW_NO_REQUIRE_TAP_TRUST=1` in the workflow env. If a bot PR pre-dates
this fix being applied to the tap's CI workflow, it needs a rebase against
master first (step 3 above). Once Homebrew/brew#22719 ships and the workaround
is removed, this requirement can be dropped from this skill.

## Output

Report the merge with:

```
### Homebrew tap merge
- PR #<n> — verified 4 sha256s vs upstream SHA256SUMS — merged via squash
- Follow-up: re-run scripts/check-release.sh v<version> to confirm Homebrew row
```

## Safe-Fix Guidance
- Do not edit `Formula/aasm.rb` by hand to "fix" a mismatched sha256 — the
  upstream release artifact is the source of truth; if hashes don't match,
  the release tarball or the bot is broken, not the formula. Escalate.
- Do not bypass a red `brew install + test (macOS)` check by merging anyway
  — Homebrew users will hit the same failure on `brew install`.
- Do not local-rebase + force-push the bot branch; use the server-side
  `update-branch` API call to keep the audit trail clean.
- Limit to one rebase attempt before escalating — repeated failures indicate
  a real formula or release-artifact problem.

## Cross-links
- `docs/release/RUNBOOK.md` § "Manual gate — merge the Homebrew tap PR"
- `.github/workflows/release.yml` § `update-homebrew-tap` job (the producer
  of these PRs)
- Memory entry `project_homebrew_tap_sandbox_kills_install` (AAASM-2871
  background)
