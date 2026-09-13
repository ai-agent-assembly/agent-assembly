<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/governance-doctor/SKILL.md. Provisional Codex projection shape — see agents/common/README.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — governance-doctor

## Purpose

Check a Horonom repo (or the local `$HORONOM_WORKSPACE_ROOT`) for drift
between its adopted governance projection and the current canonical
content in `horonomy/.github`, and report it as PASS/WARN/FAIL —
mirroring the `horonom doctor` CLI this skill wraps (HORO-510).

## Type

Auto-used. Invoke before starting work in an adopted repo, and periodically
during a long-running session.

## When to use

Any repo that has adopted Horonom governance (has a generated `.claude/`
or `.codex/` projection, or a workspace-root `CLAUDE.md`/`AGENTS.md`).

## When NOT to use

- A repo that has not adopted Horonom governance at all — there is nothing
  to check drift against. Use `repo-bootstrap` first.
- A repo whose own governance is intentionally ahead of what's projected
  (e.g. mid-adoption of a newer `governance_version` not yet regenerated
  everywhere) — report the drift, don't treat "ahead" as a failure to fix
  by reverting.

## Procedure

1. Run `python3 scripts/doctor.py --repo <path> [--workspace-root <path>] [--product <name>]`
   from a `horonomy/.github` checkout (HORO-510). It reports PASS/WARN/FAIL/
   NOT_APPLICABLE per check with an actionable `fix` hint — read the `fix`
   field before doing any manual investigation.
2. Compare each generated file's provenance header
   (`governance_version=<N>`) against `metadata/governance.yaml`'s current
   `governance_version` in `horonomy/.github`.
   - Same version, content matches what regenerating would produce → PASS.
   - Recorded version behind current, but content still matches what *that
     older* version would have produced → WARN (merely stale, not corrupt).
   - Content differs from what regenerating the recorded version would
     produce → FAIL (someone hand-edited a generated file).
3. Check for the security invariants in `governance/engineering/security.md`
   mechanically where practical (no secret-shaped content in a generated
   file; no broad-kill patterns in any script under `agents/`).
4. Report findings; do not silently "fix" a FAIL by regenerating without
   telling the operator what was overwritten — a FAIL on a generated file
   means someone edited generated content, which is itself worth surfacing
   before it's clobbered.

## References

- `governance/README.md` — the drift/adoption contract (decision #9 in
  ADR-0005).
- `governance/engineering/security.md` — the mechanical enforcement bar
  for a "non-waivable" claim.
- `scripts/doctor.py` + `scripts/doctor_checks.py` — the real implementation
  (HORO-510); see `governance/workspace/doctor.md` for the full check list.
- `scripts/horonom_workspace.py status` — the workspace-root half of this
  check (HORO-506), which `doctor.py` delegates to.
