# EXAMPLES — homebrew-tap-merge

A full end-to-end walk-through of the skill's 4-step plan against a real
release. Use this to see what each step looks like in practice, including the
AAASM-2871 stale-master rebase path. The lean plan lives in
[SKILL.md](SKILL.md).

## Contents

- [Worked example — alpha-9 (2026-06-14)](#worked-example--alpha-9-2026-06-14)
  - [Step 1 — Scope check](#step-1--scope-check)
  - [Step 2 — Cross-verify 4 sha256s](#step-2--cross-verify-4-sha256s)
  - [Step 3 — Detect stale-master + server-side rebase](#step-3--detect-stale-master--server-side-rebase)
  - [Step 4 — Wait for CI re-run + merge](#step-4--wait-for-ci-re-run--merge)

## Worked example — alpha-9 (2026-06-14)

PR [#16](https://github.com/ai-agent-assembly/homebrew-agent-assembly/pull/16)
on `ai-agent-assembly/homebrew-agent-assembly`, titled `🤖 (formula): aasm
0.0.1-alpha.9`, opened by the release-bot at 2026-06-13 18:09 UTC after the
upstream `v0.0.1-alpha.9` tag push triggered `release.yml`'s
`update-homebrew-tap` job.

**Initial state**: `brew install + test (macOS)` check RED with the
AAASM-2871 silent `sandbox-exec` SIGKILL fingerprint (PR was based on a
pre-`HOMEBREW_NO_REQUIRE_TAP_TRUST=1` master tip).

### Step 1 — Scope check

```bash
gh pr view 16 --repo ai-agent-assembly/homebrew-agent-assembly \
  --json files,additions,deletions
# → single file Formula/aasm.rb, ~5 additions, ~5 deletions  ✓
```

### Step 2 — Cross-verify 4 sha256s

```bash
.claude/skills/homebrew-tap-merge/scripts/verify-tap-sha256.sh v0.0.1-alpha.9 16
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

### Step 3 — Detect stale-master + server-side rebase

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

### Step 4 — Wait for CI re-run + merge

```bash
# brew install + test (macOS) goes green; the success log contains:
#   Pouring … Cellar/aasm/0.0.1-alpha.9: 3 files, 21.5MB, built in 1 second

gh pr merge 16 --repo ai-agent-assembly/homebrew-agent-assembly --squash
```

Verifies the AAASM-2871 workaround is active in workflow env, then squashes
in the formula bump.
