# Campaign worktree/process cleanup and CI-waiting protocol

Codifies, as durable governance rather than ad-hoc session behavior, the
mandatory teardown of campaign-created infrastructure after each merge, and
the rule that waiting on CI must use a real, provable mechanism rather than
a passive claim. Applies to `/release-qa-gate` (AAASM-5821) and any
remediation loop it triggers (`qa/FINDING-VERIFICATION-PROTOCOL.md`'s
autonomous remediation loop, AAASM-5845), and to any other campaign that
creates worktrees, background processes, or CI-watching state under this
repo's governance workflows.

## Why this exists

The AAASM-5819/5831/5832/5833 campaigns each created multiple git worktrees
and background processes (gateways, API servers, CI pollers). Cleanup was
performed manually and inconsistently — some worktrees were removed
immediately after merge, others (e.g. the original `post-merge-dogfood`
worktree) were left until a concurrent session incidentally cleaned them up.
Stale worktrees consume disk — this machine has a documented history of
disk-pressure incidents from exactly this pattern (see
`~/Bryant-Developments/AI-agent-assembly/CLAUDE.md`'s "Incident: Disk
Pressure from Per-Worktree Rust Build Artifacts") — and stale registrations
pollute `git worktree list`.

Separately, a prior session in this same Epic's lineage was directly
challenged mid-campaign for claiming to be "monitoring CI" without a
verifiably real background watcher — the background shell commands cited as
evidence of "monitoring" were never actually verified to still be running.
That was a real gap in stated practice versus documented policy, since no
policy existed to violate. The CI-waiting policy below exists to close it.

## Worktree and process cleanup

Per merged PR, follow this exact ordered sequence:

```text
MERGE -> resync canonical main -> post-merge verify -> confirm no
valuable uncommitted work remains in the worktree -> stop any
dependent campaign-started processes (gateway/API-server/CI pollers)
-> `git worktree remove <path>` -> `git worktree prune` -> verify the
physical folder is gone -> verify no stale worktree metadata remains
(`git worktree list`)
```

- **Resync canonical main** — fetch the push remote (`remote`, not `origin`)
  and confirm the merge landed on the canonical default branch.
- **Post-merge verify** — reproduce the fix/change against the merged base,
  not just the pre-merge branch (this is the same discipline the autonomous
  remediation loop already requires for confirmed-defect fixes).
- **Confirm no valuable uncommitted work remains** — `git status` in the
  worktree; anything uncommitted that matters is either committed, stashed
  into a clearly labeled location, or explicitly confirmed disposable before
  the worktree is removed. Never remove a worktree with unreviewed
  uncommitted changes.
- **Stop dependent campaign-started processes** — any gateway, API server,
  or CI-poller process the campaign started for this ticket's work is
  terminated before the worktree is removed.
- **Remove and prune** — `git worktree remove <path>`, then
  `git worktree prune` to clear any registration left behind by a path that
  no longer exists.
- **Verify** — confirm the physical folder is actually gone (not just
  unregistered) and that `git worktree list` shows no stale entry for it.

**Never remove a worktree or branch that the current campaign did not
create.** If a worktree's origin is unclear, leave it and escalate rather
than guessing.

## CI-waiting policy

Never state "monitoring" or "watching" CI without a real, checkable
mechanism behind the claim. Only two mechanisms count:

1. **A scheduled wakeup that re-queries on each firing** — the wakeup's
   identity (PR number *and* HEAD SHA) is recorded, and every firing runs a
   fresh query. A harness-tracked background task also counts, provided it
   is not merely sleeping; see the freshness invariant below, which rules
   out `gh pr checks --watch` and `sleep`-loop shells as the mechanism.
2. **Continued active re-polling within the same turn** — repeated,
   observable polling calls, not a single check followed by a claim of
   ongoing monitoring.

If challenged on a "monitoring" claim, the completed or in-flight background
task's process/task ID must be citable as proof. A claim that cannot produce
that citation was not a real watch and must not be made again the same way.

### Freshness invariant

A real background task satisfies "is this a real watch" (above) but not
"is what it reports still true" — a long-lived polling loop can itself go
stale: it keeps re-checking, but nothing forces it to distinguish "GitHub
still says pending" from "GitHub reached a terminal state several polls ago
and I haven't looked since." AAASM-5930's own campaign hit exactly this: a
`gh pr checks` background poller was treated as authoritative for tens of
minutes without a fresh query being re-verified against it.

* **No CI status may be trusted across wakeups without a fresh query.**
  Re-querying the checks/runs API for the current PR is what makes a status
  claim current — a prior poll result, however recently it looked "still
  pending," is not evidence of the present state on its own.
* **Terminal GitHub state immediately cancels local wait state.** A
  check-run's `status` field, not just its `conclusion`, is what's
  authoritative here — a `conclusion` only exists once `status:
  "completed"`. The Checks API's completed-conclusion values are `success`,
  `failure`, `neutral`, `cancelled`, `skipped`, `timed_out`, `action_required`,
  and `stale`; all of them are terminal. (`startup_failure` is a
  workflow-*run*-level conclusion, not a check-run conclusion — don't
  conflate the two API shapes when scripting a query.) The moment a fresh
  query returns a completed status for a required check, stop waiting on it
  — do not keep a background
  poller alive "just in case," and do not wait for every non-required job
  to also finish.
* **The watcher's identity must include the current PR HEAD SHA**, not just
  the PR number. A PR whose branch was amended, rebased, or force-pushed
  mid-wait invalidates observations bound to the old SHA — a query that
  does not name the SHA it's asking about can't tell an in-progress old run
  from a completed new one. Re-derive the HEAD SHA before trusting a result.
* **Do not use a long blocking wait shell.** An earlier version of this
  section said a `run_in_background` command that blocks until a condition
  becomes true was "fine as a mechanism" provided the condition was a fresh
  query. In practice that permission is what got used: campaign sessions ran
  `sleep 110` loops and 10-minute command timeouts.

  Note what is and is not the objection, because the numbers alone look
  identical: waiting ~2 minutes between queries is the prescribed cadence
  below, so the duration of the sleep is not the defect. **Where the sleep
  lives is.** A `sleep` inside the poll shell puts the waiting and the
  deciding in the same process, and that process holds the decision until it
  wakes: it cannot notice a terminal state, cannot be corrected by anything
  the session learns meanwhile, and cannot be reasoned about by a session
  that has moved on — the shell reports what was true when it last looked,
  which is exactly how a failed run kept being described as pending. A sleep
  between wakeups puts the waiting outside the decision, so each decision is
  made from a query taken at the moment it is made.

  So the shape that works is query → act if terminal → otherwise schedule a
  short wakeup → query again, each wakeup performing its own query and each
  ending. First ~10 minutes at a ~2–3 minute cadence, then ~5 minutes; never
  go more than ~10 minutes without a fresh authoritative state. One
  `scripts/qa/ci-watch.py poll` per wakeup satisfies this by construction —
  it cannot sleep, because it exits.
* **A failed required check ends the wait immediately and starts
  triage** (`qa/FINDING-VERIFICATION-PROTOCOL.md` classifies and drives the
  fix) — it is never a reason to keep polling in case it changes back.
* **A terminal state that is not `success` is still not a failure to
  triage blindly.** `stale` means the result no longer applies to the
  current head; `neutral` is non-blocking without being a pass. Stop
  waiting is one conclusion; treat as passed is a different one.
* **Only the repository's actual required contexts gate a merge.** On this
  repo `required_status_checks.contexts` for `main` is exactly
  `["CI Success"]`. Every other job — including
  `Integration tests (macos-latest)` — is a non-required evidence job, and a
  non-required job still in flight or `cancelled` (AAASM-5943) is not a
  reason to keep waiting. Read the protection rules; do not infer required
  status from a job's name or apparent importance.

**Enforcement (AAASM-5960).** Everything above is executable, not just
written down: `scripts/qa/ci-watch.py poll` performs exactly one fresh
observation and exits with a verdict the caller has to act on — `0` pass,
`20` fail, `21` running, `22` head-changed, `23` query-error. It holds no
observation state across invocations at all, which is the freshness
invariant expressed as an absence rather than as a rule someone has to
remember. `scripts/qa/ci-watch-negative-control.sh` runs each rule against
both the real implementation and a deliberately wrong watcher in
`qa/tests/fixtures/ci-watch/`, and fails any case where the two agree — so
a rule that stopped being load-bearing reddens `CI-watcher freshness gate`
instead of quietly becoming prose again. There are two wrong watchers, not
one: the rules have a direction, and a rule can be broken by over-repair as
well as by neglect, which a single wrong implementation cannot demonstrate
both of. A handful of cases are asserted against the real implementation
only, and each says so at the point of assertion rather than being counted
as though it discriminated. Prefer the tool over hand-rolled `gh` calls; if
this section and the tool ever disagree, the negative control is the
tiebreaker.

## Final-completion bar

A campaign using this policy is not complete until all of the following
hold:

- **0** campaign-created stale worktrees.
- **0** unnecessary campaign background processes.
- **0** leftover test listeners/servers.
- **0** leftover campaign temp folders, where safe to remove.

This is a literal exit condition, not a target to approximate — a campaign
that reports completion while any of the above is nonzero has not actually
finished.
