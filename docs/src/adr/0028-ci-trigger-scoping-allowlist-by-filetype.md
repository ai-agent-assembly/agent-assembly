# ADR 0028: CI Trigger-Scoping — Path Filters Must Allow-List by File Type

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-5257](https://lightning-dust-mite.atlassian.net/browse/AAASM-5257)

This ADR ratifies a durable, org-wide rule for how CI workflows gate expensive jobs
by changed paths. It was surfaced by an audit that started as a single-repo bug
report ([AAASM-5256](https://lightning-dust-mite.atlassian.net/browse/AAASM-5256))
and was widened to every repo in both the `ai-agent-assembly` (18 repos) and
`horonomy` (4 repos) GitHub orgs before any fix was written, because the same
defect *shape* — not just the same bug — recurred independently across repos. This
ADR does not itself change any workflow file; the mechanical fixes are tracked and
already merged under separate tickets (see Traceability).

---

## Context

`agent-assembly/ci.yml`'s `dorny/paths-filter` blocks gated the dashboard job set
(including a 5-7 minute Playwright e2e job) on bare directory wildcards —
`dashboard/*`, `aa-*/*`, and similar — with no file-extension or filename
qualifier. A directory wildcard matches *any* future addition under that tree,
including non-code artifacts (screenshots, generated reports, fixtures, docs), so
a commit that touches only such files still re-triggers the full expensive job.
AAASM-5256 reproduced this misfire on 3 real commits before the audit began.

Because `dorny/paths-filter` is a copy-pasted mechanism, not a first-class
abstraction shared across repos, the same authoring mistake was free to recur
anywhere it was copied. The audit (2026-07-27, via GitHub API, both orgs) found it
had:

**`ai-agent-assembly` — the over-triggering pattern (bare `dir/**`, no type qualifier):**

- `agent-assembly/ci.yml` — confirmed misfiring today; all 7 `dorny/paths-filter`
  blocks affected (AAASM-5256, 3 reproduced commit SHAs).
- `agent-assembly-enterprise/ci.yml` — the identical `dorny/paths-filter`
  mechanism gates `cargo test --workspace` build/lint on a bare `crates/**`.
  Dormant only because that tree happens to be pure Rust today; it will misfire
  the moment any non-code file lands there.
- `cloud/fe-e2e.yml` — Playwright e2e gated by a bare `apps/web/**`, structurally
  identical to the dashboard-e2e problem that started this audit. Not yet fired,
  but the risk is equivalent, and the audit separately found `cloud/fe.yml` had
  the same gap (a miss in the original single-repo audit, corrected once the scope
  widened).
- Lower-cost instances of the same shape: `go-sdk` (`native-ffi.yml`,
  `docs-site.yml`), `node-sdk` (`publish-docs.yml`), `python-sdk`
  (`native-core-build.yml`, `quickstart-tabs-check.yml`, `documentation.yaml`),
  `examples` (per-language verify workflows), `homebrew-tap`, `arena`.

**`ai-agent-assembly` — the opposite failure, same org:** part of `arena`'s
workflows and (see below) all of `horonomy/official-website` have *no* path
filtering at all — every job runs unconditionally regardless of what changed.

**`horonomy` — the inverse failure mode, not the AAASM-5256 pattern:** none of
its 4 repos use `dorny/paths-filter` or `on.paths` at all. `official-website` and
`GearMeshing-AI` run their full build/typecheck or pytest/ruff/mypy job
unconditionally on every push/PR — the same wasted-CI-minutes outcome as the
over-triggering repos, reached by *absence* of filtering rather than a
*miswritten* filter. `horonomy/.github` (the org-profile repo) has no
`workflow-templates/` directory, so there is currently nowhere in that org to
centrally encode a shared rule.

**Best-practice counter-examples already in the org** — evidence the rule below
is achievable, not aspirational: `e2e-private/preview-e2e.yml` gates its
expensive preview-deploy Playwright job with `paths-ignore: ['docs/*',
'*/*.md']`; most of `python-sdk`'s core CI qualifies every filter entry by
extension or exact filename rather than a bare directory.

Two failure modes, one root cause: nothing in either org states that a path
filter's *shape* (extension/filename-qualified vs. bare directory) is itself
something to get right, or that the absence of any filter on an expensive job is
equally out of policy. Each repo's CI author was free to reinvent the answer, and
mostly reinvented the wrong one.

## Decision

1. **A path filter must allow-list by file extension or exact filename — never by
   a bare `dir/**` or `dir/*` with no type qualifier.** A directory wildcard
   admits every future non-code addition under that tree (screenshots, generated
   reports, fixtures, docs) as if it were a source change that must re-run the
   gated job. Filters must instead enumerate the file types or exact filenames
   that constitute a real change to the gated surface (e.g. `dashboard/**/*.{ts,tsx,css}`
   or `paths-ignore: ['**/*.md', 'docs/**']`, following the `preview-e2e.yml` /
   `python-sdk` counter-examples above).

2. **Every job whose cost is non-trivial (e2e/integration suites, native builds,
   Docker builds) must have some form of change-based gating.** Unconditional
   full-suite runs on every push/PR — the `horonomy` failure mode — are equally
   out of policy, just reached by omission rather than by a wrong pattern. A job
   is not exempt from this rule merely because it currently has no filter at all.

3. **Exception, stated explicitly:** a repo whose entire purpose IS non-code
   content (e.g. a docs site where `docs/**`/`*.md` legitimately *is* the source,
   such as `internal-docs`) is not in scope for rule 1's file-type qualification —
   for such a repo, the "content" directory itself is the correct trigger surface
   and requires no further qualification. This exception exists so rule 1 is not
   miscited against a repo where a bare content-directory match is the correct
   design, not a defect.

4. **Where a shared/reusable workflow-templates location exists or is created
   (e.g. `<org>/.github/workflow-templates/`), this rule must be encoded there so
   new repos inherit it instead of re-discovering it per-repo.** At the time of
   this audit, `ai-agent-assembly/.github` has no such shared location and
   `horonomy/.github` has no `workflow-templates/` directory either — this
   decision does not itself create one, but any future shared workflow template
   in either org must comply with points 1-3 from the start.

## Accepted risks

- The lower-cost instances named in the audit (`go-sdk`, `node-sdk`, `python-sdk`,
  `examples`, `homebrew-tap`, `arena`) are **not** fixed by this ADR or by any of
  the four implementation tickets below. They are named as evidence of the
  pattern's spread, not as remediated. Each remains non-compliant with point 1
  until a follow-up ticket addresses it. The risk accepted here is that this ADR
  ratifies the rule before every known instance is fixed — deliberately, so the
  rule exists to hold new CI authoring to, rather than waiting for full remediation.
- `horonomy/official-website` and `horonomy/GearMeshing-AI`'s under-gating (point 2)
  is flagged, not fixed, by this ADR. See "Out of scope" below.

## Explicitly forbidden designs

- **Do not gate an expensive job with a bare directory wildcard** (`dir/**`,
  `dir/*`) on the theory that "it's all code in there today" — rule 1 exists
  precisely because that assumption is what silently breaks the first time a
  non-code file lands in the tree (the AAASM-5256 defect).
- **Do not leave an expensive job (e2e/integration/native/Docker) completely
  unfiltered** as a way to sidestep getting the filter's file-type qualifier
  right — that trades one policy violation (rule 1) for the other (rule 2).
- **Do not apply rule 1's file-type qualification to a repo where the tracked
  content itself is the source** (the internal-docs-style exception, rule 3) —
  over-qualifying such a repo's filter would exclude legitimate changes.

## Consequences

- **CI authors / future contributors**: a directory-only path filter is no longer
  an acceptable first draft for a new or edited workflow in either org. New
  filters must be written extension/filename-qualified from the start, and
  existing bare-wildcard filters are known debt (see Traceability) rather than an
  invisible default.
- **`ai-agent-assembly` org**: the four highest-value instances (agent-assembly,
  agent-assembly-enterprise, cloud's `fe-e2e.yml` and `fe.yml`) are already fixed
  — this ADR ratifies the rule those fixes already implement, rather than
  proposing untested policy. The remaining lower-cost instances stay open debt
  until separately ticketed.
- **`horonomy` org**: this ADR's rule 2 applies there too, but `horonomy` is a
  different GitHub org from the one this repo's Jira project (AAASM) tracks — see
  "Out of scope."
- **Cost**: writing a compliant filter requires the author to know which file
  types genuinely affect the gated job, which is marginally more work than typing
  `dir/**`. That is the intended trade — the whole failure mode this ADR closes is
  the "wildcard now, discover the gap later" default.

## Operational guidance

- When writing or editing a `dorny/paths-filter` (or `on.paths` / `paths-ignore`)
  block for a job that is not trivially cheap, qualify every path entry by file
  extension or exact filename before merging — do not defer the qualification to
  a follow-up.
- When introducing a new expensive job (e2e, integration, native/Docker build)
  with no filter at all, add one at introduction time rather than waiting for a
  wasted-minutes complaint to force it retroactively.
- Point to `e2e-private/preview-e2e.yml` and `python-sdk`'s core CI as the
  in-tree examples of a compliant filter shape.

## Validation requirements

- The four already-merged fixes are the validation that this rule is achievable
  in practice, not just in theory: AAASM-5256 (PR #1765, all 7 filter blocks in
  `agent-assembly/ci.yml`), AAASM-5258 (PR #77, `agent-assembly-enterprise/ci.yml`),
  AAASM-5259 (PR #503, `cloud/fe-e2e.yml`), AAASM-5260 (PR #504, `cloud/fe.yml`).
- This ADR does not itself add a lint/CI check that enforces the rule
  automatically (e.g. a meta-workflow that rejects a bare `dir/**` filter). That
  is a natural follow-up once a shared workflow-templates location exists (rule
  4) but is not required for this ADR's ratification.

## Reconsideration triggers

- A shared `workflow-templates/` location is created in either org's `.github`
  repo — at that point rule 4 should be executed, not just stated, and this ADR
  should be amended with a link to the concrete template.
- Any of the lower-cost named instances (`go-sdk`, `node-sdk`, `python-sdk`,
  `examples`, `homebrew-tap`, `arena`) is found to have actually misfired in
  production, which would upgrade it from "named as evidence" to "needs its own
  ticket" ahead of a routine sweep.
- `horonomy` gains its own equivalent of this ADR set (or its own tracker adopts
  this rule explicitly) — at that point this ADR's `horonomy` findings can be
  marked resolved-elsewhere rather than open flags.

## Out of scope

- **This ADR does not change any workflow file.** All four mechanical fixes it
  cites were implemented and merged under their own tickets before this ADR was
  written (see Traceability) — this document ratifies the rule those fixes
  already apply, and gives future CI authoring a rule to comply with rather than
  a pattern to copy without understanding.
- **`horonomy/official-website` and `horonomy/GearMeshing-AI`'s under-gating
  (the inverse failure, rule 2) is flagged here but not ticketed against AAASM.**
  `horonomy` is a separate GitHub org from `ai-agent-assembly`, and per the
  source ticket's own instruction, no Jira ticket has been created for it in
  this project — `horonomy` may have its own issue tracker, and filing there is
  an engineer decision, not one this ADR makes unilaterally.
- **The remaining lower-cost `ai-agent-assembly` instances** (`go-sdk`,
  `node-sdk`, `python-sdk`, `examples`, `homebrew-tap`, `arena`) are not ticketed
  by this ADR either; they are named as audit evidence of the pattern's spread,
  left for a routine sweep to pick up individually.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5257](https://lightning-dust-mite.atlassian.net/browse/AAASM-5257) | This ADR's own ticket — records the org-wide rule the audit surfaced |
| [AAASM-5256](https://lightning-dust-mite.atlassian.net/browse/AAASM-5256) / [PR #1765](https://github.com/ai-agent-assembly/agent-assembly/pull/1765) | Originating defect and fix — `agent-assembly/ci.yml`, all 7 filter blocks |
| [AAASM-5258](https://lightning-dust-mite.atlassian.net/browse/AAASM-5258) / PR #77 | Fix — `agent-assembly-enterprise/ci.yml` |
| [AAASM-5259](https://lightning-dust-mite.atlassian.net/browse/AAASM-5259) / PR #503 | Fix — `cloud/fe-e2e.yml` |
| [AAASM-5260](https://lightning-dust-mite.atlassian.net/browse/AAASM-5260) / PR #504 | Fix — `cloud/fe.yml` (gap missed by the original audit, caught once scope widened) |
| `e2e-private/preview-e2e.yml` | In-org counter-example already following rule 1 (`paths-ignore`) |
| `python-sdk` core CI | In-org counter-example already following rule 1 (extension/filename-qualified) |
