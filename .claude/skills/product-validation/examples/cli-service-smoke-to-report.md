# examples/cli-service-smoke-to-report.md — product-validation

**Status: illustrative worked example, not a real dogfood run.** This
walks through the mechanics — smoke journey, a seeded defect, its Jira
Bug, the fix, the rerun, the report excerpt — using a plausible CLI/
service product so the shape is concrete. It is deliberately generic
rather than borrowed from one specific Horonom product, and it does not
claim any of these events actually happened. For a *real*, dogfooded
example of this same shape, see `references/defect-lifecycle.md` and
`references/validation-tracks.md`, both of which cite the real
`circinus/docs/hardening/HORO-406-fresh-user-dogfood-report.md`
end-to-end. A real product-validation run against an actual Horonom
product, producing a real report and a real filed Bug, is HORO-983's
rollout scope, not this ticket's.

## The product (illustrative)

`atlasd` — a small CLI-driven service: `atlasd install`, `atlasd start`,
`atlasd status`, `atlasd stop`, `atlasd uninstall`. Installed via a
package manager, runs as a local daemon, exposes a status CLI.

## Smoke-test journey (Track 1)

Scenario record:

```yaml
scenario_id: smoke-001-fresh-install-and-status
persona: new operator, first time installing atlasd
problem: "does a first-time install actually work end to end"
preconditions: none — genuinely fresh machine/container
environment: Linux, fresh container image, no prior atlasd state
starting_point: package not installed
surface: CLI
actions:
  - "atlasd install"
  - "atlasd configure --minimal"
  - "atlasd start"
  - "atlasd status"
  - "atlasd stop"
  - "atlasd uninstall"
expected_states:
  - after install: `atlasd --version` resolves
  - after configure: `atlasd config show` reflects the minimal profile
  - after start: `atlasd status` reports `running`
  - after stop: `atlasd status` reports `stopped`, exit code reflects it
  - after uninstall: binary and state directory are gone
expected_outcome: all six commands succeed in sequence with no manual
  intervention, and the machine is left as clean as it started
evidence: full terminal transcript, exit codes for each command
cleanup: container discarded after run
mapped_features_jira_docs: ATLAS-Story install-uninstall-flow, docs/quickstart.md
```

## Seeded defect discovered during the run

Running the scenario, `atlasd status` after `atlasd stop` reports
`running` instead of `stopped` — the status command reads a stale PID
file that `atlasd stop` never cleaned up. The scenario's expected state
for that step is not met: **FAIL**.

## Jira Bug filed (per `references/defect-lifecycle.md`)

```
Problem: `atlasd status` reports `running` after a successful `atlasd stop`
Affected scope: smoke-001-fresh-install-and-status, install/status/stop path
Severity: High — status is the primary way an operator checks daemon
  state; a false "running" after a real stop could cause an operator to
  skip a needed restart or investigate a non-issue
Environment: Linux, fresh container, atlasd v0.3.1
Repro:
  1. atlasd install && atlasd start
  2. atlasd stop
  3. atlasd status   # reports "running", expected "stopped"
Expected vs actual: docs/status.md says status reflects the daemon's real
  process state; actual behavior reflects only whether the PID file
  exists, not whether the process is alive
Impact: operator cannot trust `status` after a stop
Evidence: terminal transcript (linked in the run's CI artifact), showing
  exit code and full output of each command
```

Filed as, illustratively, `ATLAS-412`, linked to `smoke-001-fresh-install-and-status`.

## Fix

`atlasd stop` is changed to remove the PID file (not just send the
termination signal) before returning success; a regression test is added
asserting `status` reads live-process state rather than PID-file
existence alone. This fix goes through the repo's own `engineering-loop`
cycle (Narrow → Validate → Full Gate) like any other code change — this
skill does not replace that.

## Rerun through the original scenario

`smoke-001-fresh-install-and-status` is rerun in full, from a fresh
container again (not just the new regression test) — install through
uninstall, same five commands, same evidence capture. Result: **PASS**,
`status` now reports `stopped` correctly after `stop`.

`ATLAS-412` is resolved, linked to the fix commit and to the PASS rerun
evidence.

## Resulting quality report excerpt

```markdown
## Scenarios executed
| scenario_id | track | persona | outcome | evidence link |
|---|---|---|---|---|
| smoke-001-fresh-install-and-status | smoke | new operator | PASS (after fix; FAIL on first run) | ci-artifact://atlasd-smoke-001-run2 |

## Defects
| Jira key | severity | scenario | status | rerun result |
|---|---|---|---|---|
| ATLAS-412 | High | smoke-001-fresh-install-and-status | fixed | PASS |

## Final recommendation
READY. One High-severity defect (stale PID file causing a false
"running" status after stop) was found during smoke validation, fixed,
and the original scenario reran clean from a fresh install. No other
defects found in this pass.
```
