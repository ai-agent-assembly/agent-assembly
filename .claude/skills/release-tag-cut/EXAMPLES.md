# release-tag-cut — worked example

Concrete, end-to-end walk-through of cutting `0.0.1-alpha.10` from a baseline
of `0.0.1-alpha.9`. Use this as the executable template; substitute your own
`<X>` and current literal. The step numbers map 1:1 to the Executable plan in
[REFERENCE.md](REFERENCE.md).

## Contents

- [Step 1 — resolve the current literal](#step-1--resolve-the-current-literal)
- [Step 2 — enumerate the file set](#step-2--enumerate-the-file-set)
- [Steps 2-4 — run the helper, then commit in two atomic stages](#steps-2-4--run-the-helper-then-commit-in-two-atomic-stages)
- [Step 5 — release notes + annotated tag](#step-5--release-notes--annotated-tag)
- [Step 6 — push the tag, then watch `release.yml`](#step-6--push-the-tag-then-watch-releaseyml)

## Step 1 — resolve the current literal

```bash
$ CURRENT="$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)"/\1/')"
$ echo "current=$CURRENT target=0.0.1-alpha.10"
current=0.0.1-alpha.9 target=0.0.1-alpha.10
```

## Step 2 — enumerate the file set

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

## Steps 2-4 — run the helper, then commit in two atomic stages

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

## Step 5 — release notes + annotated tag

```bash
$ NOTES="docs/release/v0.0.1-alpha.10.md"
$ [ -f "$NOTES" ] || cp docs/release/v0.0.1-alpha.9.md "$NOTES"
$ $EDITOR "$NOTES"   # update title, changeset
$ git add "$NOTES"
$ git commit -m "📝 (release): Add release notes for v0.0.1-alpha.10"

$ git tag -a "v0.0.1-alpha.10" -m "Release v0.0.1-alpha.10

See docs/release/v0.0.1-alpha.10.md for details."
```

## Step 6 — push the tag, then watch `release.yml`

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

## Downstream SDK verification (after `git push remote v<X>`)

> The tag-cut skill ends at the push above. Before dispatching any SDK
> release workflow for the matching version, the operator MUST verify the
> downstream fan-out completed per the SOP in `SKILL.md` § "Downstream SDK
> coordination" (AAASM-3007).

**1. Confirm `notify-downstream` and the three pin-bumper jobs ran green.**

```bash
$ RUN_ID=$(gh run list --repo ai-agent-assembly/agent-assembly --workflow release.yml \
    --branch v0.0.1-alpha.10 --limit 1 --json databaseId --jq '.[0].databaseId')

$ gh api "repos/ai-agent-assembly/agent-assembly/actions/runs/$RUN_ID/jobs" \
    --jq '.jobs[] | {name, conclusion}'
# Each of these jobs MUST be conclusion: success before proceeding:
#   "Notify downstream SDK repos"             (AAASM-2336)
#   "Update node-sdk aa-ffi-node pin"         (AAASM-2883)
#   "Update python-sdk aa-ffi-python pin"     (AAASM-2883)
#   "Update go-sdk aa-ffi-go pin"             (AAASM-3006)
```

**2. Confirm the `bot/aa-ffi-pin-v<X>` PR was opened on each SDK.**

```bash
$ for repo in node-sdk python-sdk go-sdk; do
    echo "--- $repo ---"
    gh pr list --repo ai-agent-assembly/$repo --head bot/aa-ffi-pin-v0.0.1-alpha.10 \
      --json number,title,mergedAt
  done
# Each repo should show exactly one PR matching the branch. If any is
# missing, investigate the corresponding pin-bumper job before proceeding.
```

**3. Wait until each auto-bump PR is reviewed + merged.**

Only after all three (or two, if go-sdk is out of scope this cycle) have
merged is the SDK side allowed to dispatch its release workflow for `v<X>`.
Pre-dispatching against the previous agent-assembly content burns the
npm / PyPI version slot and ships stale code to users — see AAASM-3007 for
the 2026-06-15 incident that motivated this gate.
