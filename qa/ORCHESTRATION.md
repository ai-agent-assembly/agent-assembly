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

**Maximum 5 concurrent QA sub-agents for this workflow.** Five is a ceiling,
not a target — a patch release with a narrow risk-mapper scope should often
use 2-3 (e.g. `qa-functional` alone, or `qa-functional` + `qa-reliability-
docs`), not reflexively fill all five slots.

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
  High/Critical or P0-blocker finding, the coordinator does not launch a 5th
  wave-1 worker merely to fill the ceiling — it holds that slot (or the next
  available one) for `qa-finding-verifier`, per AAASM-5827.
- **No duplicate scans.** Two workers are never assigned the same
  surface/journey in the same wave unless one of them is explicitly the
  independent verifier reproducing a specific finding.

## Typical wave shape

- **Patch, narrow scope** (e.g. only `docs/src/qa/*` changed): 1 worker
  (`qa-reliability-docs`) — no need to fill remaining slots.
- **Patch, one HIGH-risk surface** (e.g. `aa-gateway/src/policy/`): 2-3
  workers (`qa-functional` + `qa-reliability-docs`), with 1-2 slots free for
  `qa-finding-verifier` if something suspicious surfaces.
- **RC/minor**, broader scope: up to 4 workers in wave 1
  (`qa-functional`, `qa-sdk-journey`, `qa-design`, `qa-reliability-docs`),
  always keeping the 5th slot open for verification rather than launching a
  5th investigator.

## Demonstration (AAASM-5826 AC)

`qa/orchestration-demo.md` records one concrete run showing two independent
roles executing in the same wave without overlapping file edits or
duplicated investigation, and the 5th slot correctly left open.
