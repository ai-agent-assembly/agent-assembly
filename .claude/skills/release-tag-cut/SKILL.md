---
name: release-tag-cut
description: Cut a coordinated agent-assembly release tag: bump every workspace Cargo version literal, regenerate Cargo.lock, create the annotated tag, and push it to trigger release.yml. Use when an operator is ready to cut a new pre-release agent-assembly tag (the current cadence is the 0.0.1-beta.N series; earlier cuts were 0.0.1-alpha.N) on a green master and wants the version bump, tag, release-notes, and downstream fan-out handled in the correct order.
---

# release-tag-cut

Executable contract for cutting an agent-assembly release tag from a clean
`master`. This SKILL.md is a lean overview; the per-step detail lives in
[REFERENCE.md](REFERENCE.md) and a concrete walk-through in
[EXAMPLES.md](EXAMPLES.md). The canonical prose, recovery procedure, manual
gates, and downstream channel matrix live in
[`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md).

## Release-flow index (cut → fan-out → validate → tap-merge)

A full release is a relay across sibling skills. WHY this is split: each stage
has a different write-authority and a different owner, so collapsing them invites
an LLM to "fix" downstream channels from inside the cut. Run them in order:

0. **`/release-security-gate <X>`** (stage 0, pre-cut gate) — run the release-gate
   security review scaled by release type and commit the PASS sign-off artifact
   under `docs/release/security-signoff/`. The gate wraps the built-in
   `/security-review` scanner (and, at major tier, the
   `anthropics/claude-code-security-review` Action). A **BLOCK** verdict (or any
   unaddressed High/Critical) stops the release *before* this skill runs;
   `scripts/release-readiness.sh` check 11 enforces it. See
   [`release-security-gate/SKILL.md`](../release-security-gate/SKILL.md).
1. **`release-tag-cut`** (this skill, write) — bump the workspace version, tag,
   push the tag. Ends the moment `git push remote v<X>` fires `release.yml`.
2. **fan-out** (automatic, owned by `release.yml`) — the pushed tag triggers
   GitHub Release + cosign signing, `cargo publish` of the workspace,
   `notify-downstream` `repository_dispatch` to node-sdk + python-sdk, the
   `update-{node,python,go}-sdk-ffi-pin` auto-bump PRs, and the
   `update-homebrew-tap` bot PR. The operator runs none of these by hand.
3. **`/release-validate-channels v<X>`** (read-only) — once `release.yml` is
   green, confirm every channel actually caught up. Emits a green/red matrix.
4. **`/homebrew-tap-merge <PR>`** (write, on the tap repo) — verify the bot's
   sha256s against the release `SHA256SUMS` and merge the tap PR so
   `brew install aasm` serves the new version.

The cadence is currently the `0.0.1-beta.N` pre-release series (the latest cut
is `v0.0.1-beta.2`); the same relay served the earlier `0.0.1-alpha.N` cuts and
is version-string-agnostic — the operator always supplies the exact literal.

> This skill ends at `git push remote v<X>`. The post-tag verification loop
> (Homebrew tap PR merge, crates.io / PyPI / npm propagation, ghcr.io image
> push) is owned by `/release-validate-channels`, invoked by the operator once
> `release.yml` finishes.

## When to use

Pick this skill when **all** of the following hold:

- The operator has decided agent-assembly is ready for a new pre-release tag
  (current cadence: the beta series, e.g. cutting `0.0.1-beta.3` after
  `0.0.1-beta.2`; the same path served the earlier `0.0.1-alpha.N` cuts).
- The most recent CI run on `master` is green.
- Draft release notes exist (or the operator is prepared to write them inline
  during step 5).
- The working tree is clean and `master` is up to date with `remote/master`.

The triggering operator phrasing is typically:

> "Cut beta-N+1", "Tag v0.0.1-beta.3", "Release the next beta".

## When NOT to use

This skill is **pre-release-series, agent-assembly-monorepo, full-fanout**
specific. Pick a different path in any of the following cases:

- **SDK-only release** — use `/sdk-only-release` in the target SDK repo.
  Cutting an `agent-assembly` tag for an SDK-only change wastes a full
  crates.io publish cycle.
- **GA or non-pre-release tag** (`v1.0.0`, `v0.1.0`, etc. — any tag with no
  `-alpha`/`-beta`/`-rc` suffix) — this skill is intentionally scoped to the
  pre-release cadence; a GA cut needs the release-readiness checklist + manual
  review, not this autopilot path.
- **Hotfix to an already-tagged release** — use the SDK-only path or a
  follow-up patch tag coordinated via the RUNBOOK; do not re-cut the same tag.
- **Pre-conditions not met** — if `master` is dirty, behind `remote/master`,
  or has a red CI run, stop and surface the gap to the operator.
- **No PASS security sign-off for `<X>`** — if
  `docs/release/security-signoff/v<X>.md` is missing or its verdict is not
  `PASS`, stop. Run `/release-security-gate <X>` (stage 0) first; do not cut a tag
  past an unaddressed High/Critical finding.

## Downstream SDK coordination

After this skill ends (`git push remote v<X>`), agent-assembly's `release.yml` will publish the GitHub Release and fire two automation jobs:

- `notify-downstream` — `repository_dispatch` so node-sdk and python-sdk know `aasm-*` binaries are downloadable (AAASM-2336).
- `update-{node|python|go}-sdk-ffi-pin` — opens an auto-bump PR on each SDK that aligns the `aa-sdk-client` git-SHA pin on master with this tag's commit (AAASM-2883 + AAASM-3006).

### Operator rule for the SDK side (codified in each SDK's `sdk-only-release` skill — AAASM-3007)

Until **all three** of the following are true for this tag, operators MUST NOT dispatch the SDK release workflows (`release-node.yml` or `release-python.yml`) for the matching version:

1. agent-assembly's `Release` workflow has reached the `notify-downstream` step.
2. The auto-bump PR (`bot/aa-ffi-pin-v<X>`) has been opened on each SDK repo.
3. The auto-bump PR has been reviewed and merged.

Pre-dispatching the SDK release with `npm_version=<X>` / `pypi_version=<X>` against the previous agent-assembly release content burns the version slot on npm + PyPI and ships stale content to users. See AAASM-3007 for the 2026-06-15 incident that motivated this SOP.

## How to use

**Invocation**:

```text
/release-tag-cut <X>
```

where `<X>` is the target version literal exactly as it appears in
`Cargo.toml` and in the git tag (e.g. `0.0.1-alpha.10`, NOT
`v0.0.1-alpha.10` — the leading `v` is added only at tag time).

**Required context**:

- Run from the main `agent-assembly/` working tree, not a worktree — tags are
  pushed from the main checkout per project convention.
- `remote` is the configured remote pointing at
  `ai-agent-assembly/agent-assembly` (project convention — not `origin`).
- The operator supplies `<X>`; the skill never invents a version number.

## Pre-conditions

All MUST hold before any step runs; if any fails, stop and report — do not
remediate from inside this skill. Full detail in
[REFERENCE.md → Pre-conditions](REFERENCE.md#pre-conditions).

1. **Working tree clean** (`git status --porcelain` empty).
2. **On `master`, in sync with `remote/master`** (fetch first; zero ahead/behind).
3. **Most recent CI run on master is green** (`gh run list --branch master …`).
4. **Target version `<X>` provided** — the skill does not invent or bump it.
5. **Security sign-off PASS for `<X>`** — `docs/release/security-signoff/v<X>.md`
   exists and contains `Verdict: PASS` (stage 0, `/release-security-gate <X>`).
   `scripts/release-readiness.sh` check 11 enforces this.

## Executable plan

Runs inside the main `agent-assembly/` checkout. Substitute the
operator-supplied `<X>` throughout. Per-step commands, edge-cases, and the
no-op guard rationale are in
[REFERENCE.md → Executable plan](REFERENCE.md#executable-plan).

1. **Resolve the current literal** — read the workspace version from
   `Cargo.toml` into `$CURRENT`; refuse the run if `$CURRENT == <X>` (no-op).
2. **Bump version literals + regenerate lockfile** — run
   `./scripts/release-tag-cut.sh "$CURRENT" "<X>"`. The bundled helper
   enumerates every `**/Cargo.toml` declaring `$CURRENT`, sed-replaces each,
   bumps `sonar.projectVersion` in `sonar-project.properties` from `$CURRENT`
   to `<X>` (so SonarCloud's reported version tracks the release — AAASM-3819),
   regenerates `Cargo.lock`, and refuses no-op invocations.
3. **Commit the bump (manifests + sonar)** —
   `🔧 (release): Bump workspace to v<X>` — stage the `Cargo.toml` files and
   `sonar-project.properties`; verify the old literal is gone.
4. **Commit `Cargo.lock` separately** —
   `🔧 (release): Regenerate Cargo.lock for v<X>` (reviewable in isolation).
5. **Create the annotated tag** — ensure `docs/release/v<X>.md` exists (copy
   from the previous release + edit), commit it, then
   `git tag -a "v<X>"` referencing the notes file.
6. **Push the tag** — `LEFTHOOK=0 git push remote "v<X>"` (the `LEFTHOOK=0`
   bypasses the macOS `cargo doc` pre-push hook; tag-only, touches no branch).
   This triggers `release.yml`.

## Post-conditions

After step 6, both MUST hold (full detail in
[REFERENCE.md → Post-conditions](REFERENCE.md#post-conditions)):

1. **Tag exists on remote** — `git ls-remote --tags remote "v<X>"` returns one line.
2. **`release.yml` run is `queued` or `in_progress`** for `headBranch=v<X>`.

Surface both confirmations, then point the operator at
`/release-validate-channels v<X>` for the downstream channel matrix.

## Reminder — advance the Jira Fix Version ladder

Cutting `v<X>` ships everything targeted at that version, so the **next** dev work
needs a target. The release skills do **not** manage Jira versions, so after the cut
remind the operator to, in Jira (project AAASM):

1. Mark the just-cut version **released** (`released:true` + release date).
2. **Create the next** Fix Version — for the `agent-assembly` **core** train *and*
   each affected repo/component train (`python-sdk` / `node-sdk` / `go-sdk`) that
   participates in this coordinated release — so their tickets have a target.

Use `ticket-authoring`'s `references/fix-versions.md` for the exact REST
create/release calls. This is a **manual reminder**: the Atlassian MCP has no
version tool and version writes need a manage-versions token, so the operator (or a
credentialed release job) does it. Automating this in `release.yml` is a separate
follow-up, blocked on a CI manage-versions token.

## What's auto-handled (do NOT manually run)

Once the tag is pushed, `release.yml` auto-runs GitHub Release creation,
`cargo publish` for every crate, the Homebrew tap bump PR, the downstream SDK
`repository_dispatch` fanout, and the FFI source-pin bump PRs. The operator
MUST NOT replicate any of these by hand — see
[REFERENCE.md → What's auto-handled](REFERENCE.md#whats-auto-handled-do-not-manually-run)
for the full list and rationale.

## What this skill explicitly does not do

- Open the bump PR (operator's job, per RUNBOOK section 1).
- Merge the Homebrew tap PR (RUNBOOK section 4, operator-gated).
- Re-trigger failed `release-*.yml` workflows (RUNBOOK section 6).
- Cut an `agent-assembly` tag for an SDK-only hotfix (RUNBOOK section 7).
- Touch repos other than `ai-agent-assembly/agent-assembly`.
- Create or release Jira Fix Versions — it **reminds** the operator (see
  "advance the Jira Fix Version ladder"); the operator (or a credentialed release
  job) creates/releases them. The Atlassian MCP has no version tool.

## Detailed references

One level deep from this SKILL.md:

- **Worked example** (concrete alpha-10 walk-through) → [EXAMPLES.md](EXAMPLES.md)
- **Step-by-step detail** (per-step commands, edge-cases, pre/post-conditions,
  auto-handled rationale) → [REFERENCE.md](REFERENCE.md)
- **Helper script** (the version-bump + lockfile regenerator) →
  `scripts/release-tag-cut.sh` (bundled inside this skill dir)
