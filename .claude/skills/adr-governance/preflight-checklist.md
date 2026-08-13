# adr-governance — pre-flight checklist

Tick every box (or mark N/A with a reason) before opening a PR that embeds a
material decision.

## Discovery
- [ ] Judged materiality against the Step 1 criteria (cross-cutting / contract /
      boundary / long-lived constraint / expensive-to-reverse).
- [ ] Searched `docs/src/adr/` (+ `docs/architecture/`, `docs/security/`,
      `docs/decisions/` where present).
- [ ] Searched `SECURITY.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `.claude/` rules.
- [ ] Searched relevant Jira issues and merged PRs.
- [ ] Emitted an **Existing Decision Summary** before editing.

## Decision
- [ ] Chose exactly ONE ADR action (none / follow / amend / create / supersede /
      record-accepted-risk).
- [ ] Any **conflict** with a recorded decision was **surfaced/escalated**, not
      silently overridden.
- [ ] If `supersede`: the old ADR's status was set to `Superseded by NNNN` and the
      new ADR links back.
- [ ] If `record-accepted-risk`: assumptions **and** reconsideration triggers are
      written down.

## Record
- [ ] ADR written from the template with all required sections (Context/threat
      models, Decision, Accepted risks, Forbidden designs, Consequences,
      Operational guidance, Validation requirements, Reconsideration triggers,
      Traceability).
- [ ] Sequential number; no shipped ADR's history rewritten (amended/superseded
      instead).
- [ ] ADR added to `docs/src/adr/README.md` index **and** `docs/src/SUMMARY.md`
      TOC.

## Linkage (Jira → ADR → PR → evidence)
- [ ] PR description references the applicable ADR.
- [ ] ADR Traceability table references the Jira ticket(s) and the implementation
      PR(s).
- [ ] Jira ticket references the ADR.
- [ ] Validation requirements in the ADR are backed by real tests/checks in the PR
      (or the ADR says why not yet).
