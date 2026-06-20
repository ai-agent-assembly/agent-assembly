---
name: release-validate-channels
description: Validate a published agent-assembly release across every distribution channel — GitHub Release, crates.io, npm, PyPI, Homebrew tap, the python-sdk and node-sdk repository_dispatch fan-outs, docs sites, and GHCR. Use after a release tag's release.yml run completes to confirm the tag propagated to every channel, or when an operator asks whether a published release is fully live. Read-only: it probes and reports a green/red matrix but never modifies any registry, repository, or tap.
---

# release-validate-channels

Executable contract for verifying that an agent-assembly tag has propagated
cleanly across every downstream distribution channel. The canonical prose
runbook (recovery procedure, immutability guarantees, SDK decoupling notes)
lives in [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md) section 5
("Verification"); this SKILL.md encodes the cross-channel matrix that Claude
Code itself runs after each tag push.

> This skill picks up where `/release-tag-cut` ends. It assumes `release.yml`
> has already fired and is responsible for confirming that what `release.yml`
> *intended* to publish actually landed on every channel it owns.

## When to use

Invoke this skill when **all** of the following are true:

- The operator has just cut a tag via `/release-tag-cut` (or the tag arrived
  via the equivalent CI path).
- `release.yml` on `ai-agent-assembly/agent-assembly` for that tag shows
  `status=completed` and `conclusion=success`.
- The operator wants a deterministic, paste-ready confirmation that every
  downstream channel caught up with the new tag.

The skill is the read-only counterpart to `/release-tag-cut`: tag-cut writes
the tag and lets the publish workflows fan out; this skill confirms the
fan-out landed.

## When NOT to use

- **`release.yml` has not finished yet.** Wait for `conclusion=success`; the
  pre-condition check fails fast with the run URL. Channels 2–9 mid-flight
  make the result meaningless.
- **The tag is non-published or withdrawn.** Tags that never triggered
  `release.yml` have no channel state to validate.
- **The operator wants to fix a broken channel.** This skill is *read-only*:
  it surfaces deviations but does NOT retry publishes, merge tap PRs, or yank
  versions. Recovery lives in [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md)
  section 6. Re-running after a manual retry is fine; using it *as* the retry
  is not.

## How to use

```text
/release-validate-channels v<X>      # e.g. /release-validate-channels v0.0.1-alpha.9
```

**Required inputs.** `<TAG>` (a published agent-assembly tag the skill does
not invent), and a `release.yml` run for that tag at `status=completed` /
`conclusion=success`.

**Behaviour.** Read-only and idempotent. Runs the nine channel probes in
order and emits a single green / red Markdown table. It mutates no registry,
repository, tap, or workflow. Safe to re-run.

**Typical operator flow.** Cut the tag → watch `release.yml` go green → run
this skill → paste the matrix into the post-release note or follow-up ticket.
Each red row carries the literal failing command and its output so triage
needs no re-run.

## Pre-conditions

Both MUST hold before any probe runs. If either fails, stop and surface the
failure with exact command output and the run URL — do not remediate inside
this skill.

1. **Target tag provided** — the operator supplies `<TAG>`. The skill does
   not invent or guess tags.
2. **`release.yml` run for that tag is `completed/success`** — query via:

   ```bash
   gh run list --workflow release.yml \
     --repo ai-agent-assembly/agent-assembly \
     --branch "<TAG>" --limit 1 \
     --json status,conclusion,url,databaseId
   ```

   The result must show `status=completed` / `conclusion=success`, else stop
   and report the run URL — propagation cannot complete if `release.yml` did
   not finish successfully.

## The nine channels

`VERSION="${TAG#v}"`; `PEP440`: `-alpha.N`→`aN`, `-beta.N`→`bN`, `-rc.N`→`rcN`
(e.g. current cadence `0.0.1-beta.2` → `0.0.1b2`; canonical sed in
`scripts/check-release.sh` `to_pep440()`). Probe in this order, recording
green / red per channel:

| # | Channel              | One-line check |
|---|----------------------|----------------|
| 1 | GitHub Release       | 6 expected assets present, `isPrerelease=true`, `isDraft=false` |
| 2 | crates.io            | All 9 published crates' sparse-index latest `vers` = `$VERSION` |
| 3 | npm                  | `@agent-assembly/sdk` + 4 runtime sub-packages exist at `$VERSION` |
| 4 | PyPI                 | `agent-assembly==$PEP440` active with 4 wheels + 1 sdist; no yanked higher shadow |
| 5 | Homebrew tap         | `Formula/aasm.rb` `version "$VERSION"` + 4 `sha256` literals match `SHA256SUMS` |
| 6 | python-sdk fanout    | Latest `release-python.yml` `repository_dispatch` run succeeded |
| 7 | node-sdk fanout      | Latest `release-node.yml` `repository_dispatch` run succeeded |
| 8 | Docs sites           | `Docs` (agent-assembly) + `pages-build-deployment` (python-sdk / node-sdk) succeeded post-tag |
| 9 | GHCR                 | `ghcr.io/ai-agent-assembly/{python,go}:$VERSION` manifests exist |

Full per-channel probe commands and pass criteria are in
[REFERENCE.md](REFERENCE.md). Soft reds (do not block, only annotate): PyPI
yanked-shadow, Docs staleness, deferred GHCR.

## Output — the green/red matrix

Emit a single Markdown table the operator can paste into a ticket. One row
per channel; the `Detail` column carries the success summary or the literal
red-flagging command output.

```text
Release validation for <TAG>:

| Channel              | Status | Detail                                          |
|----------------------|--------|-------------------------------------------------|
| GitHub Release       | ✓      | 6 assets, isPrerelease=true                     |
| crates.io (9 crates) | ✓      | all latest line vers = <VERSION>                |
| npm (5 packages)     | ✓      | sdk + 4 runtime sub-packages at <VERSION>       |
| PyPI                 | ✓      | <PEP440> active, 4 wheels + 1 sdist, no shadows |
| Homebrew tap         | ✓      | Formula version <VERSION>, sha256s match        |
| python-sdk fanout    | ✓      | release-python.yml run #N success               |
| node-sdk fanout      | ✓      | release-node.yml run #N success                 |
| Docs sites           | ✓      | Docs + 2× pages-build-deployment success        |
| GHCR                 | ✓      | python:<VERSION> + go:<VERSION> present         |

  All channels green for <TAG>.
```

Replace `✓` with `✗` for any red channel and, on the line beneath, append the
exact failing command and its literal output. A fully worked alpha-9 run is
in [EXAMPLES.md](EXAMPLES.md).

## What's expected when done

A successful invocation produces, in order:

1. **A paste-ready Markdown matrix** in the format above.
2. **Every anomaly named with the literal command output that surfaced it** —
   never "channel X looks off" without the exact `gh` / `curl` / `npm view`
   invocation and its stdout / stderr.
3. **Specific follow-up per red row** (the skill names the next action, does
   not perform it): GitHub Release → re-check `build-artifacts` / `sign-release`;
   crates.io → `Publish workspace to crates.io` job log (immutable, recovery
   is a fresh tag); npm → `release-node.yml` run; PyPI → `release-python.yml`
   run (yanked shadow = soft red); Homebrew with open bot PR → `/homebrew-tap-merge`,
   no PR → `update-homebrew-tap` job; SDK fanout → surface run URL; Docs →
   soft red; GHCR → confirm whether this cut publishes GHCR. Full table in
   [REFERENCE.md](REFERENCE.md).
4. **A definitive go / no-go last line**, one of:
   - `All channels green for <TAG>.`
   - `<TAG> validated with <N> soft notes — see annotations.`
   - `<TAG> has <N> hard red channels — operator action required.`

The operator should be able to act on the matrix and final line alone.

## What's auto-handled — read-only boundary (do NOT manually run)

This callout exists so neither the operator nor an LLM driving this skill is
tempted to "fix" things from inside the validation loop.

- **The skill never modifies any registry, repository, tap, or workflow.**
  Every probe is a read-only `gh`, `curl`, `npm view`, or
  `docker manifest inspect`. Any write (re-publish, retry, yank, merge, tag,
  push) is out of scope.
- **The skill does not retry failed publishes.** Retry mechanics live in
  [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md) section 6. The
  skill surfaces the failing run URL; the operator (or `/homebrew-tap-merge`)
  drives the retry.
- **The skill does not gate `release.yml`'s `release-status-aggregator`
  job.** That aggregator decides whether the cut itself succeeded; this skill
  is the *external* cross-channel confirmation that runs after it. The two
  complement each other; the skill does not block the workflow.
- **go-sdk has no distribution channel to validate here.** The Go SDK ships
  via the Go module proxy off its own `goreleaser`-driven tag on its own
  cadence (RUNBOOK § 7), so there is no `release-go.yml` binary fan-out and no
  registry row to probe. Do **not** add go-sdk to the matrix or flag it as a
  missing channel — the 9-channel matrix is complete as-is. (Note: go-sdk's
  `aa-sdk-client` source pin IS now kept in lockstep with each tag via
  `release.yml`'s `update-go-sdk-ffi-pin` auto-bump PR, AAASM-3006 — but that
  is a source-pin PR on go-sdk, not a published channel, so it is verified by
  merging the bump PR, not by this read-only channel matrix.)

If a fix is required, exit with the matrix, then invoke the appropriate
write-side skill or RUNBOOK procedure separately, and re-run this skill to
confirm.

## Detailed references

- Full per-channel probe commands, pass criteria, sparse-index prefix table,
  and the load-bearing institutional quirks → [REFERENCE.md](REFERENCE.md).
- Complete worked alpha-9 walk-through with real run IDs and the canonical
  filled-in matrix → [EXAMPLES.md](EXAMPLES.md).
- Human-narrative verification loop, immutability guarantees, SDK decoupling
  rationale → [`docs/release/RUNBOOK.md`](../../../docs/release/RUNBOOK.md)
  section 5.

## What this skill explicitly does not do

- Cut, edit, or push tags (that is `/release-tag-cut`).
- Re-trigger failed `release-*.yml` workflows (RUNBOOK section 6, operator-
  driven; the skill surfaces the run URL but does not call `gh workflow run`).
- Merge the Homebrew tap PR (RUNBOOK section 4, operator-gated).
- Yank PyPI / npm / crates.io versions (immutable in practice; recovery is a
  fresh tag, not a republish).
- Validate go-sdk channels (decoupled, RUNBOOK section 7).
- Touch repos other than `ai-agent-assembly/{agent-assembly,python-sdk,
  node-sdk,homebrew-agent-assembly}`.
