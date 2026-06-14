---
name: homebrew-tap-merge
description: Verify + merge the auto-opened homebrew-agent-assembly bot PR for a new agent-assembly release.
---

# SKILL.md — homebrew-tap-merge

## Purpose

After each `agent-assembly` release, `release.yml`'s `update-homebrew-tap` job
opens a `bot/aasm-<version>` PR on `ai-agent-assembly/homebrew-agent-assembly`
that bumps `Formula/aasm.rb` (version line + 4 SHA256 sums). This skill owns the
verify-and-merge flow for that PR so `brew install aasm` picks up the release.

The skill lives in `agent-assembly` because the tap repo has no Jira component;
it is logically owned by the upstream that publishes to it.

## When to use

Invoke when `release.yml`'s `update-homebrew-tap` job has finished and a
`bot/aasm-<version>` PR is open on `ai-agent-assembly/homebrew-agent-assembly`,
and the operator (or `release-watch`) wants to verify the bot diff and merge it.

## When NOT to use

- **Tap PR not yet open** — wait for `release.yml`; do not hand-open a PR.
- **Tap PR has manual edits beyond the bot's diff** — anything outside the
  version line + 4 sha256 lines is out of scope. Escalate; do not auto-merge a
  hand-edited formula.
- **AAASM-2871 (Homebrew/brew#22719) is patched upstream** — if the tap's `brew
  install + test` workflow no longer needs `HOMEBREW_NO_REQUIRE_TAP_TRUST=1`,
  the step-3 rebase shortcut may no longer be required; re-evaluate.

## How to use

```text
/homebrew-tap-merge <PR_NUMBER>
```

Example: `/homebrew-tap-merge 16`. Resolve the PR number with
`gh pr list --repo ai-agent-assembly/homebrew-agent-assembly --state open`. The
matching upstream `agent-assembly` release must already be published with its
`SHA256SUMS` asset attached.

## Executable plan

### 1. Verify PR scope

```bash
gh pr view <n> --repo ai-agent-assembly/homebrew-agent-assembly \
  --json files,additions,deletions
```

Expected: single file `Formula/aasm.rb`, ~5 additions and ~5 deletions. Reject
anything broader as out-of-scope.

### 2. Cross-verify all 4 sha256 lines vs upstream

```bash
.claude/skills/homebrew-tap-merge/scripts/verify-tap-sha256.sh <tag> [<pr>]
# e.g. .claude/skills/homebrew-tap-merge/scripts/verify-tap-sha256.sh v0.0.1-alpha.9 16
```

Exits 0 iff all 4 sha256s match the upstream `SHA256SUMS` asset (one per
platform: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`). Non-zero exit prints a
mismatch table — **escalate; do not merge**.

### 3. Handle red `brew install + test (macOS)` check

```bash
gh pr view <n> --repo ai-agent-assembly/homebrew-agent-assembly \
  --json baseRefOid,mergeable,mergeStateStatus
```

- If `mergeStateStatus` is `BEHIND` (stale master), trigger a **server-side**
  rebase (no local force-push):

  ```bash
  gh api -X PUT \
    /repos/ai-agent-assembly/homebrew-agent-assembly/pulls/<n>/update-branch \
    -f update_method=rebase
  ```

  Wait for CI to re-run, then re-evaluate. See the AAASM-2871 note below.

- If the PR is up to date, surface the failure log with
  `gh run view --repo ai-agent-assembly/homebrew-agent-assembly --job <id> --log-failed`.

### 4. Merge

Once CI is green and sha256s are verified:

```bash
gh pr merge <n> --repo ai-agent-assembly/homebrew-agent-assembly --squash
```

## AAASM-2871 quirk (live until Homebrew/brew#22719 ships)

The tap's `brew install + test (macOS)` check needs
`HOMEBREW_NO_REQUIRE_TAP_TRUST=1` in the workflow env. A bot PR on stale master
predates that fix and fails with a silent `sandbox-exec` SIGKILL — the step-3
server-side rebase pulls in the env and clears it. Limit to one rebase attempt
before escalating. Background: memory entry
`project_homebrew_tap_sandbox_kills_install`.

## Do NOT (auto-handled or forbidden)

- **Opening the bot PR** — owned by `release.yml`'s `update-homebrew-tap` job.
- **Editing `Formula/aasm.rb` by hand** — never. A mismatched sha256 means a
  real upstream release-artifact problem; escalate, do not "fix" the formula.
- **Local `git push --force` to the bot branch** — use the server-side
  `update-branch` API (step 3); force-push breaks the bot's audit trail.
- **Merging past a red `brew install + test` check** — users hit the same
  failure on `brew install`.

## Post-conditions

- Tap `master`'s `Formula/aasm.rb` has the new version + 4 verified sha256s.
- The bot PR is **closed and merged** (squash), not just approved.
- Follow up with `/release-validate-channels v<version>` (or re-run
  `scripts/check-release.sh v<version>`) and confirm the Homebrew row goes green.

## Detailed references

- [EXAMPLES.md](EXAMPLES.md) — full worked alpha-9 walk-through of all 4 steps,
  including the stale-master rebase path and the verified sha256 table.
- `scripts/verify-tap-sha256.sh` — the step-2 cross-verification helper.
- `docs/release/RUNBOOK.md` § "Manual gate — merge the Homebrew tap PR".
- `.github/workflows/release.yml` § `update-homebrew-tap` job (PR producer).
