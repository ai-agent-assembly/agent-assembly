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

## Post-conditions
- Tap `master` branch's `Formula/aasm.rb` has the new version + 4 sha256s.
- `brew install aasm` (on a fresh `brew update`) now resolves to the new
  version. Until the merge happens, `brew install aasm` still resolves to
  the previous version — the bot branch is invisible to `brew install`.
- Suggest follow-up: invoke `/release-validate-channels` (or re-run
  `scripts/check-release.sh v<version>`) to confirm the Homebrew row goes
  green.

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
