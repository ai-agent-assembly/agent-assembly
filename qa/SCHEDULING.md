# Resource-aware scheduling for QA-campaign background jobs

AAASM-5891. Governs how the release-QA coordinator (an LLM, following this
policy — see `qa/ORCHESTRATION.md`) runs machine-heavy background jobs
during a campaign: `git push` (and the pre-push `cargo doc --workspace` it
can trigger), `cargo build`/`cargo nextest run`, lint/typecheck, and macOS
security-sensitive operations (`security add-trusted-cert`,
`VZVirtualMachine.start()`).

## The incident this exists to fix

Three duplicate `git push` invocations for the same branch, each spawning
its own pre-push `cargo doc --workspace --no-deps` (~50 minutes measured
per `lefthook.toml`'s own comment), all contending for the shared
`CARGO_TARGET_DIR` lock at once. Not a scheduling-order failure — it was
the *same push repeated*, and each repetition escalated into the most
expensive local gate in the repository. See AAASM-5891 and AAASM-5890
(the narrower "is the local hook even still needed" question this Story
does not answer).

## What this is not

Not a change to `qa/ORCHESTRATION.md`'s 10-worker agent/reasoning ceiling —
that stays exactly as AAASM-5845 left it. This governs *machine-resource*
concurrency (builds, docs, pushes, security ops) independently from
*agent/reasoning* concurrency, which was never the problem.

Not a daemon. `qa/scheduler/aa-sched` is a single bash script; every
subcommand is one-shot. `run` blocks for a job's entire lifecycle (queue
wait → execute → supervise → cleanup) inside the caller's own process.
There is nothing left running after it returns and nothing to leak if the
caller itself is killed — a `reap`/`cleanup` call recovers from that case.

Not a cargo-built binary. It must keep working when the toolchain it is
guarding is itself wedged, so it cannot depend on that toolchain to exist
as a compiled `aa-*` crate would.

## Resource classes

See `qa/scheduler/classes.conf` for the authoritative, commented table.
Summary:

| class | limit | pool scope | retried on stall |
|---|---|---|---|
| `readonly` | 10 | unsupervised (no semaphore) | n/a |
| `write_repo` | 1 per worktree | per git worktree | no |
| `lint_fast` | 4 | machine-global | yes |
| `cargo_build` | 1 per `CARGO_TARGET_DIR` | per resolved target dir | yes |
| `heavy_test` | 1 (shares `cargo_build`'s pool) | per resolved target dir | yes |
| `cargo_doc_workspace` | 1 | machine-global | yes |
| `macos_security` | 1 | machine-global | no |

`readonly` (Jira/`gh`/file reads, LLM reasoning) is deliberately
*unwrapped* — its real ceiling is the agent ceiling in
`qa/ORCHESTRATION.md`, not a semaphore here.

## Coordinator call pattern

Every machine-heavy shell command the coordinator would otherwise run
directly goes through `aa-sched run` instead, launched as a Bash tool call
with `run_in_background: true`:

```
qa/scheduler/aa-sched run --class cargo_doc_workspace --campaign <id> \
    --id <job-id> --worktree <path> -- git push remote HEAD
```

`aa-sched run` blocks inside that background task through the full
lifecycle — queue wait, execution, supervision, cleanup. Consequences for
the coordinator:

- the harness's own background-task-completion notification is the
  progress signal; **do not poll with `ScheduleWakeup`** for this — it
  costs a turn to do what the harness already does for free.
- `BashOutput` on that task id is the log read when one is wanted.
- there is no separate watchdog process to track or clean up: the
  supervision loop runs as a co-process inside `aa-sched run`'s own
  process tree, torn down with it.

### Exit-code contract

| code | meaning | coordinator action |
|---|---|---|
| the command's own code | ran to completion normally | proceed |
| `75` | class breaker open at its floor | **the one point an LLM enters monitoring** — spawn a diagnostic sub-agent with the job's `status`/`log` |
| `76` | blocked on a lock held by a process this scheduler did not start | do not retry; the block is external, not this job's fault |
| `77` | stalled and terminated by the watchdog | breaker-tracked; retried automatically if the class is retry-safe |
| `78` | ownership could not be reproven before acting | treat as unknown; do not assume success or failure |

## Fingerprint dedupe (the actual fix)

Scoped deliberately to `git push` invocations only — not every command.
A coordinator legitimately running several distinct jobs that happen to
share identical argv (the same test binary invoked with the same flags as
two different campaign steps) must never be silently collapsed into one;
that would be a correctness bug, not a safety feature. `git push` is
special because the actual incident was the *same* push repeated, and its
fingerprint (`class | argv | pool_key | HEAD sha`) includes the resolved
commit — a legitimate re-push after a new commit is never suppressed.

A second `aa-sched run` matching a still-registered fingerprint **attaches**
to the first rather than running: it waits for the winner's job to finish
and exits with the winner's own exit code. This is the primary fix for the
incident; the `cargo_doc_workspace` semaphore (limit 1) is the safety net
for the case where dedupe does not apply (two *different* branches pushed
concurrently, each legitimately triggering its own doc build).

## Mechanical watchdog

Runs entirely in-process inside `aa-sched run`, polling at the class's
configured interval. A job is a stall *candidate* once three independent
signals are simultaneously flat for `stall_polls` consecutive polls:
cumulative CPU seconds across the process group, the job's own log size,
and the sorted multiset of the process group's child command names.
Requiring all three flat (not any one) is deliberate — CPU alone
false-positives on a legitimately I/O-blocked job, log growth alone
false-positives on a quiet build, and the child-set delta is what catches
a compiler driving one translation unit after another with a flat log.

Before a candidate stall is acted on:

1. **Foreign-lock discrimination.** If a `cargo_build`/`heavy_test`/
   `cargo_doc_workspace`-class job's process group is not what holds the
   relevant `.cargo-lock` file (checked via `lsof`), the job is not killed
   or retried — it exits `76`. A job genuinely blocked on cargo's own OS
   lock held by a process this scheduler did not start has an *identical*
   mechanical signature to a wedged job; that signature is the incident
   this Story exists to fix, so treating it as "stalled" would kill
   healthy work exactly under the conditions that produced the bug.
2. **Ownership reproof.** The recorded pid's `lstart` (process start time)
   must still match before any signal is sent — a pid can be reused by an
   unrelated process between polls, and this scheduler must never signal
   a process it did not start.

Only past both checks does the watchdog send `SIGTERM` to the job's
process group, wait the class's configured grace period, then `SIGKILL`
if it is still alive.

## Circuit breaker

Per resource class, not global. A confirmed stall lowers the class's
effective concurrency limit by one (floor 1, never 0 — a class can never
become permanently unschedulable). Reaching the class's configured
`breaker_threshold` of *consecutive* stalls opens the breaker. Once open
with the effective limit already at the class's floor, further `run`
calls for that class refuse immediately (exit `75`) rather than queueing
— this is the one place a mechanical failure hands off to an LLM (a
diagnostic sub-agent reads the job's log/status and decides what to do;
the breaker itself never invokes one).

One success after a 900-second cooldown raises the effective limit by one
step (half-open); reaching the class default closes the breaker. A human
or coordinator can also force it closed: `aa-sched breaker reset <class>`.

A breaker opening on one class never affects any other class's pool or
breaker state — each is tracked and gated independently
(`qa/tests/scheduler/sched_isolation.bats`).

## Cleanup

`aa-sched cleanup [--campaign ID]` terminates every still-live job's
process group (owned jobs only — it iterates this scheduler's own
recorded jobs, never a system-wide process sweep) and reclaims whatever
ports/temp directories that job self-reported via `$AA_SCHED_JOB_META`
(a `KEY=VALUE` line appended to the job's own metadata file — the only
way this scheduler can learn what an arbitrary wrapped command allocated).
Runs on both the success and the failure/stall path — a killed job's
owned state is cleaned immediately by the watchdog itself, and an
explicit `cleanup` call is idempotent on top of that.

## Stale-state recovery

`aa-sched reap` (also run automatically inside every `acquire_slot` call
before waiting) reclaims a semaphore slot whose recorded pid is dead, or
whose pid is alive but its `lstart` no longer matches the recorded value
(a recycled pid) — reclaimed without ever signaling that pid, since it is
not this scheduler's process.

## Known gaps — tracked, not hidden

- **Enforcement only applies when the coordinator uses `aa-sched run`.**
  A `git push` issued outside the wrapper — another Claude session, a
  human, a nested hook — is not gated by any of this. The
  push-to-resource-class mapping (mirroring `lefthook.toml`'s own doc-hook
  glob) is instructional, not a git hook itself; nothing prevents an
  un-wrapped push.
- **Dependency-DAG scheduling was scoped out.** "A blocked resource class
  must not block unrelated work" falls out structurally from independent
  per-class pools and independent per-class breakers plus one background
  harness task per job — there is no shared queue for one class's
  blockage to occupy. `qa/tests/scheduler/sched_isolation.bats` is the
  test evidence for this, not a separate scheduling mechanism.
- **AAASM-5870** (concurrent `VZVirtualMachine.start()` races on the
  shared `rootfs.img`) reserves the `macos_security` class here but is not
  wired to it — actually routing `aasm-macos-vm` boot serialization
  through `aa-sched` is that ticket's own follow-up work.
- **`lefthook.toml` itself is unchanged.** Making the pre-push doc hook
  self-dedupe (rather than relying on the coordinator to route pushes
  through `aa-sched`) is a different, wider-blast-radius change — it
  touches every contributor's push path, not only this campaign's.
- **No CI job runs `qa/tests/scheduler/*.bats` yet.** `make test-scheduler`
  makes the suite runnable by one command; wiring it into a GitHub Actions
  job is a follow-up, not part of this Story's own acceptance evidence
  (which was established by running it locally and in this PR's review).
