# Release-QA orchestration policy

Governs how `/release-qa-gate` (AAASM-5821) uses the five reusable roles in
`.claude/agents/qa-*.md` (AAASM-5826).

## The role set (5, intentionally small)

| Role | Covers |
|---|---|
| `qa-functional` | CLI/gateway/policy/config, non-browser non-SDK-journey behavior |
| `qa-sdk-journey` | SDK install/Quick-Start/golden-journey, scoped per run to whichever SDK(s) are in scope |
| `qa-design` | Browser/dashboard/design, anything `browser_required: true` |
| `qa-reliability-docs` | Doc/command integrity + reliability/failure-recovery — combined because either workload alone is usually too small for a dedicated worker |
| `qa-finding-verifier` | Independent reproduction only — reserved, not routinely launched |

No one-agent-per-repo explosion: `qa-sdk-journey` is one role covering up to
three SDK repos per run, scoped by what the manifest says is in scope for
*this* release — not three permanent per-language agents that mostly sit
idle on a release that only touches one SDK.

## Hard ceiling

**Maximum 10 concurrent QA sub-agents for this workflow.** Ten is a ceiling,
not a target — most runs should use far fewer, sized to the actual scope of
the release, and a narrow patch should still often use 2-3, not reflexively
fill available slots.

### Dynamic sizing

| Scope | Workers |
|---|---|
| Narrow work (e.g. a single surface, a doc-only change) | 2-4 |
| Several independent surfaces | 4-6 |
| Broad/high-risk release QA | 6-8 |
| Up to the ceiling, only when genuinely independent work benefits | 10 |

Pick the smallest size that covers the scope — going higher only pays off
when the additional workers cover genuinely independent surfaces/journeys,
not when it just adds contention over the same discovery. Sizing above 5
means instantiating one of the five roles more than once in the same wave,
each instance scoped to a disjoint surface/journey slice (e.g. two
`qa-sdk-journey` instances covering different SDK repos) — never two
instances of the same role assigned overlapping scope, which is exactly what
"no duplicate scans" already forbids.

- **No nested spawning.** Every `qa-*` agent's own tool scope (see each
  file's frontmatter `tools:` line) excludes the Task/Agent-spawning
  capability — a worker cannot launch its own sub-agents. This is enforced by
  which tools the coordinator equips each role with, not by an instruction
  the worker could ignore.
- **The coordinator owns shared discovery once.** The verification manifest
  (AAASM-5825) and the risk-mapper output (AAASM-5829) are built once by the
  coordinator and sliced per worker — workers never independently re-query
  Jira/repo state for context the coordinator already resolved.
- **Reserve verifier capacity.** When a run's first wave produces a suspected
  High/Critical or P0-blocker finding, the coordinator does not launch a
  wave-1 worker merely to fill the ceiling — it holds a slot (or the next
  available one) for `qa-finding-verifier`, per AAASM-5827.
- **No duplicate scans.** Two workers are never assigned the same
  surface/journey in the same wave unless one of them is explicitly the
  independent verifier reproducing a specific finding.

## Shared runtime reuse

Workers verifying against the same gateway/policy/API-server configuration
should reuse one standing, coordinator-provisioned instance rather than each
starting its own. This is grounded in a real, observed problem: during the
AAASM-5832/AAASM-5833 dogfood session, multiple independent gateway/
api-server instances were started ad hoc on different ports, causing
port-collision confusion and wasted setup/teardown time.

- The coordinator provisions the shared instance once, up front, the same
  way it resolves the verification manifest once.
- **Mutable state must still be isolated per concurrent worker**, even when
  the base binary/instance is shared — PID files, listen ports, and
  `AA_DATA_DIR` are never shared across workers that mutate state. Give each
  worker a distinct `--listen`/`AA_DATA_DIR`, or, for verification that is
  genuinely read-only, point every worker at the one shared instance instead
  of standing up N copies of the same thing.
- The choice between "one shared read-only instance" and "one instance per
  worker with isolated mutable state" is made per surface, based on whether
  that surface's verification mutates state — not applied blanket across the
  whole run.

## Resource classes

A different axis from the role/worker ceiling above: the 10-worker cap
bounds *reasoning* concurrency (Agent-tool sub-agents), and applies whether
or not any of them ever touch a machine resource. Some of the shell
commands a worker or the coordinator itself runs — a workspace-wide
`cargo build`/`cargo doc`, a `cargo nextest` run, a macOS Keychain
operation — contend on a genuinely limited *machine* resource (one shared
`CARGO_TARGET_DIR`, one Keychain, one VM rootfs) independent of how many
Agent-tool workers are in flight. AAASM-5891/5893-5895 is the mechanism for
that second axis: `scripts/qa/resource-lock.py` (the pool/slot
registry, `qa/resource-classes.yaml`) plus `scripts/qa/qa-watchdog.py`
(progress-aware stall detection and a per-class circuit breaker).

- **Wrap, don't reimplement.** A command that already has a registered
  `class` in `qa/resource-classes.yaml` (`cargo-doc`,
  `cargo-build-workspace`, `cargo-nextest-workspace`, `macos-security`,
  `vm-start`, `dashboard-build`, `lint-unit`) should be invoked through
  `resource-lock.py run --class <name> -- <cmd...>`, not run bare — this is
  how the pre-push `cargo doc` hook itself is wired
  (`lefthook.toml`'s `pre-push.commands.doc`, AAASM-5895).
- **Fail-fast, not queue-and-block.** Every class's `wait_secs` defaults to
  0 (`qa/resource-classes.yaml`'s `defaults`) — a saturated pool returns
  immediately with a distinct exit code (`EXIT_SATURATED=75`,
  `EXIT_DUPLICATE=76`), never blocks a foreground shell waiting for the
  slot to free. Do not pass `--wait` with a nonzero value to make a
  campaign command block instead — see the next point for what to do with
  the busy signal instead.
- **RESOURCE_BUSY is not QA_FAILED.** A worker or coordinator step that
  gets `EXIT_SATURATED`/`EXIT_DUPLICATE` back has not failed its actual
  work — it hit resource contention. Do not report it as a QA finding,
  retry it as if it were a flaky test, or (worst) fall back to running the
  command unwrapped/bare to "just get it done." The correct response is
  the auto-retry pattern below.
- **Automatic agent-side retry belongs to the orchestration layer, not the
  hook.** On `EXIT_SATURATED`/`EXIT_DUPLICATE`: record the retryable state,
  continue other dependency-ready work in the same wave, and retry the
  command on a later poll once the slot is likely free — do not stop and
  ask a human merely because another worktree/session currently holds a
  shared-resource slot. This mirrors the campaign's own dynamic-`/loop`
  polling pattern (poll, do other work, come back) rather than introducing
  a second waiting mechanism.
- **Fairness is informal, by design.** There is no queue, no priority, no
  new locking primitive here — a worktree that loses a race for a slot
  simply retries on its own next poll. This is the simplest mechanism
  consistent with `wait_secs: 0` fail-fast semantics; it has not needed
  anything stronger in practice, and adding one is out of scope unless a
  real starvation pattern is observed (see `qa-watchdog.py breaker` for
  the one piece of state this system *does* keep across attempts — a
  repeatedly-stalling class's circuit breaker, not a fairness queue).
- **Stale-lock recovery is already handled** — `resource-lock.py sweep`
  (dead-pid/reused-pid-safe, AAASM-5893) plus `qa-watchdog.py`'s ownership
  re-verification (AAASM-5949/5951) before every stall-termination signal.
  Nothing in this section reimplements that; it only documents where to
  look.

## Typical wave shape

- **Patch, narrow scope** (e.g. only `docs/src/qa/*` changed): 1 worker
  (`qa-reliability-docs`) — no need to fill remaining slots.
- **Patch, one HIGH-risk surface** (e.g. `aa-gateway/src/policy/`): 2-3
  workers (`qa-functional` + `qa-reliability-docs`), with slots free for
  `qa-finding-verifier` if something suspicious surfaces.
- **RC/minor**, broader scope: up to 4 workers in wave 1
  (`qa-functional`, `qa-sdk-journey`, `qa-design`, `qa-reliability-docs`),
  always keeping a slot open for verification rather than launching another
  investigator.
- **Broad/high-risk release QA**: the higher ceiling (6-10 workers) is
  available when the scope genuinely spans that many independent surfaces —
  still with verifier capacity reserved, never filling every slot with
  investigators.

## Demonstration (AAASM-5826 AC)

`qa/orchestration-demo.md` records one concrete run showing two independent
roles executing in the same wave without overlapping file edits or
duplicated investigation, and a slot correctly left open (recorded under the
then-5-worker ceiling — the demo itself is history, not renumbered here).
