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
