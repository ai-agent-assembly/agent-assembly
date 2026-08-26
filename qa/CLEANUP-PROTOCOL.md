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

1. **A harness-tracked background task** — a `run_in_background` command, or
   a blocking watch command (e.g. `gh pr checks --watch`) moved to
   background by the harness, whose process/task ID is recorded.
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
* **Prefer short, bounded, re-query polling over one long blocking wait.**
  A single `run_in_background` command that blocks until some condition
  becomes true is fine as a mechanism (see above), but the condition it
  blocks on must itself be "did a fresh query just now return terminal,"
  checked on a short cadence (low single-digit minutes) — not a one-shot
  check taken once and then trusted for the command's entire runtime.
* **A failed required check ends the wait immediately and starts
  triage** (`qa/FINDING-VERIFICATION-PROTOCOL.md` classifies and drives the
  fix) — it is never a reason to keep polling in case it changes back.

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
