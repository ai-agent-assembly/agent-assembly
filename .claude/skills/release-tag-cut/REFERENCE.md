# release-tag-cut — detailed reference

The step-by-step detail behind the concise plan in [SKILL.md](SKILL.md). Each
section below expands one step of the Executable plan with the exact commands,
edge-cases, and the no-op guard rationale. For a concrete end-to-end run, see
[EXAMPLES.md](EXAMPLES.md).

## Contents

- [Pre-conditions](#pre-conditions)
- [Executable plan](#executable-plan)
  - [1. Verify the bump PR already landed on `remote/main`](#1-verify-the-bump-pr-already-landed-on-remotemain)
  - [2. Confirm security + QA sign-offs are for this exact `<X>`](#2-confirm-security--qa-sign-offs-are-for-this-exact-x)
  - [3. Run the release gate — `scripts/release-readiness.sh`](#3-run-the-release-gate--scriptsrelease-readinesssh)
  - [4. Create and push the annotated tag — `scripts/release-tag-guard.sh`](#4-create-and-push-the-annotated-tag--scriptsrelease-tag-guardsh)
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
   check 11, re-verified in step 3 below.
6. **QA sign-off PASS for `<X>`** — `docs/release/qa-signoff/v<X>.md` exists
   and its verdict line is `Verdict: PASS` (stage 0, `/release-qa-gate <X>` in
   `release` depth). Mirrored by `scripts/release-readiness.sh` check 12,
   independently of check 5/11 above — re-verified in step 3 below.

## Executable plan

The whole sequence runs inside the main `agent-assembly/` repository checkout
(not a worktree). Substitute the operator-supplied `<X>` for the target
version throughout.

### 1. Verify the bump PR already landed on `remote/main`

```bash
CURRENT="$(awk -F'"' '/^\[workspace\.package\]/{p=1; next} /^\[/{p=0} p && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
if [ "$CURRENT" != "<X>" ]; then
  echo "refuse: Cargo.toml workspace version is $CURRENT, expected <X> — open/merge the bump PR (RUNBOOK section 1) first"
  exit 1
fi
grep -qE '^## \[<X>\]' CHANGELOG.md || { echo "refuse: CHANGELOG.md has no ## [<X>] section"; exit 1; }  # substitute <X> literally, same convention as elsewhere in this doc
[ -f "docs/release/v<X>.md" ] || { echo "refuse: docs/release/v<X>.md missing"; exit 1; }
```

**Why this replaced the old inline bump.** A prior version of this step
bumped every `Cargo.toml` version literal, regenerated `Cargo.lock`,
committed both, and committed the release notes — all as *local* commits
made by this skill, never pushed anywhere before the tag (REFERENCE.md said
so explicitly: "This skill's only push is the tag itself"). That is
self-defeating for two reasons this Story's own checks would have caught
immediately: step 3's readiness check 3 (`local main` == `remote/main`)
fails the moment those local-only commits exist, and step 4's guard
requires the release-evidence's `candidate_sha` to equal `HEAD` — but the
QA/security gates (pre-conditions 5/6) necessarily captured their evidence
*before* this skill ran, i.e. against whatever commit was HEAD before these
local bump commits were added, not after. Between "gates captured evidence"
and "tag is pushed," nothing may change locally — the only way to satisfy
that is for the bump to already be on `remote/main` before this skill (and
before the gates) run, exactly as RUNBOOK section 1 already prescribes. This
skill verifies that happened; it does not do the bumping itself.
`scripts/release-tag-cut.sh` (the old bundled helper) is still available for
whoever drives the *separate* bump-PR step, but this skill no longer invokes
it.

### 2. Confirm security + QA sign-offs are for this exact `<X>`

Pre-conditions 5 and 6 above must already hold at this point — this step is
just naming that the commit verified in step 1 is the one those sign-offs
(and the evidence record step 4 will bind to) actually cover. If either
sign-off predates the bump-PR commit verified in step 1, stop and re-run
`/release-security-gate <X>` / `/release-qa-gate <X>` on the current
`remote/main` tip before continuing — do not proceed on stale evidence.

### 3. Run the release gate — `scripts/release-readiness.sh`

```bash
bash scripts/release-readiness.sh "<X>"
```

Run this from the exact commit verified in step 1 (nothing has changed
locally since — that is the point). All 14 checks must report ✓: working
tree/branch/CI mechanical state, version/CHANGELOG/notes literals, required
secrets, no stale Homebrew tap PR, the pinned-pip-install check, the
security sign-off `Verdict: PASS` (check 11, pre-condition 5 above), the QA
sign-off `Verdict: PASS` (check 12, pre-condition 6 above, independently of
check 11), every published crate has a README, and release-evidence binding
to HEAD via `check-release-evidence.py` (check 14). Any ✗ stops the run
here — this step exists specifically because, before AAASM-5879, nothing in
this skill ever invoked this script, so a tag could be created and pushed
without any of these 14 checks having run at all. Resolve the failing
check(s) and re-run before proceeding; do not skip a check to reach a green
run.

### 4. Create and push the annotated tag — `scripts/release-tag-guard.sh`

```bash
bash scripts/release-tag-guard.sh "<X>"
```

This is the only sanctioned way this skill creates/pushes the tag — it is
not a convenience wrapper around step 3, it is independent enforcement:

- Refuses if the configured push remote does not resolve to
  `ai-agent-assembly/agent-assembly` (no `--remote` override in this call).
- Refuses on a dirty working tree, or if `git fetch remote` fails.
- Refuses if `v<X>` already exists locally or on the remote.
- Re-runs `scripts/release-readiness.sh <X>` itself — step 3 above is not a
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

After step 4 completes, all of the following MUST hold:

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
push — re-run step 4 (`scripts/release-tag-guard.sh <X>`) or investigate the failure before declaring done.

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
