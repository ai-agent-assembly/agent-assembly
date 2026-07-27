# ADR 0028: The Dashboard E2E Suite Is a Merge Gate, Not an Advisory Signal

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-5192](https://lightning-dust-mite.atlassian.net/browse/AAASM-5192)

This ADR records that the dashboard Playwright suite blocks merge, and — more
durably — the rule that decides which CI jobs block and which do not. That rule
existed only as a comment in `ci.yml` and had never been written down anywhere a
future contributor would look.

**This ADR confers no authority on any other ADR.** An earlier draft claimed it
gave ADRs [0025](0025-design-v2-authoritative-visual-spec.md) and
[0027](0027-accessibility-floor-overrides-visual-spec.md) "a standing
enforcement mechanism". That was measured and is wrong on both counts, so it has
been removed rather than softened — see *What this gate does not prove* below.
It matters because 0025 is **Proposed** and says explicitly that it *"requires
product/design sign-off before it is treated as binding"*: a Proposed ADR is
evidence, not implementation authority, and a merge gate must not hand it teeth
by the back door.

---

## Context

Until AAASM-5192, **no workflow referenced Playwright at all.** The dashboard e2e
suite ran nowhere in CI. Every e2e result in the programme was author-run or
reviewer-run evidence, produced locally and attached by hand.

The cost of that arrived as AAASM-5191: commit `d68a0d63` (AAASM-4322) moved the
auth token from `localStorage` to `sessionStorage` and did not update the specs
that seeded it. 31 files stopped authenticating. Nothing noticed for **19 days**,
and the only reason it was ever found is that a reviewer went looking by hand.
The specs did not fail loudly — they timed out before the app mounted, so the
failure did not even name auth as the cause.

Two facts made this a decision rather than a bug fix:

1. **"Green CI" in this repo already means less than it appears.** `ci.yml`
   records coverage and Sonar as deliberately advisory, and branch protection
   currently requires *no* status contexts at all. Adding another job without
   deciding its status would inherit "advisory" by default — and an advisory
   e2e job is functionally identical to the state that produced AAASM-5191.
2. **The suite is not green.** Measured on `main` with the seed fixed: 433 tests,
   300 passing — **131 failures across 41 of 86 files** (AAASM-5195). 16 of those
   41 were never touched by the seed bug at all, so the rot substantially
   predates it. A gate cannot simply be pointed at the suite as it stands.

The forcing constraint is that these two pull in opposite directions: the lesson
of AAASM-5191 says *block*, and the state of the suite says *you cannot block on
this*. Any answer that only honours one of them is wrong.

## Decision

1. **The dashboard e2e suite blocks merge.** The `dashboard-e2e` job is a member
   of the `ci-success` aggregate — the single status intended to be the required
   branch-protection check (AAASM-2599). A red e2e run fails `ci-success`.

2. **The blocking/advisory rule is: does the job assert *behaviour* or *quality*?**
   Jobs asserting functional behaviour (does it compile, do the tests pass, does
   the rendered app still work) are members of `ci-success` and block. Jobs
   producing quality or acceptance *metrics* (coverage percentages, Sonar
   findings) are excluded and are advisory. E2E specs assert that routes render,
   that client-side behaviour holds, and that the rendered app still works
   against a stubbed backend — the same category as the `dashboard-test` vitest
   job, which already blocks. It goes in the same bucket. A job's status is
   chosen by applying this rule, never inherited from whichever job it was copied
   from.

3. **The gate is credible only if it is green, so known-red specs are quarantined
   explicitly, not skipped.** `dashboard/playwright.ci.config.ts` is the normal
   config plus a `testIgnore` quarantine list. **Specs are gated by default** — a
   file must be named to be excluded — so a spec added by anyone else is covered
   automatically and cannot opt out by accident. The list only ever shrinks;
   removing an entry needs no approval.

4. **Quarantine is not deletion and not `.skip`.** Every quarantined spec remains
   intact and runs on `pnpm test:e2e` locally. The exclusion lives in one
   reviewable file with a stated cause per group, not hidden inside the specs.

5. **Snapshot specs stay out of CI.** `theme-visual` and
   `responsive-viewport-visual` have platform-specific `-chromium-darwin`
   baselines and no Linux equivalents; they remain the local visual gate that
   `tests/e2e/README.md` already described. No gated spec calls
   `toHaveScreenshot`, so the gate is platform-independent.

6. **The token is seeded into `sessionStorage`.** Specs must seed `aa_token` where
   `src/auth/tokenStorage.ts` reads it. This is the invariant AAASM-5191 broke.

## What this gate does not prove

Stating this precisely matters more than stating it flatteringly — an
overclaiming gate is how "green CI" quietly stops meaning anything.

- **It is not an API-contract check.** 43 of the 44 gated specs stub every
  network call with `page.route(...)`. The gate compares the frontend against
  *its own hand-written mocks*, so it cannot observe the real API and cannot
  detect backend contract drift. The pagination-envelope breakage
  (AAASM-4892) is the proof: the app had already been updated and the **mocks**
  were what went stale. The one spec that does assert a genuine round-trip
  against a live `aa-api` — `hitl-approval` — is quarantined precisely because
  this job does not provision a Rust toolchain to boot it.
- **It does not enforce ADR 0025.** Ten gated specs pin values sourced from
  `design/v1/` (ADR 0017, Accepted). Exactly one — `review-aaasm-5149` — cites
  `design/v2/`, and even that asserts three literal RGB constants committed in
  the spec file rather than reading the design source. Nothing in the gate reads
  `design/**` at runtime, so it is a regression check on current rendered
  behaviour, not an assertion of 0025's authority.
- **It does not enforce ADR 0027.** The accessibility floor is enforced by
  `AppShell.contrast.test.ts`, a **vitest** test in the `dashboard-test` job. No
  gated e2e spec makes a contrast or WCAG assertion.

## Accepted risks

- **The gate covers 44 of 86 files (240 of 433 tests).** A regression in a
  quarantined spec is not caught. This is accepted because the alternative —
  gating on a suite with 131 known failures — produces a permanently red check
  that everyone learns to bypass, which is strictly worse than a smaller check
  that is believed. The quarantine is tracked in AAASM-5195 and shrinks.
  *Assumption:* the list is actually worked down rather than becoming permanent
  furniture. `QUARANTINE_CEILING` (below) turns the "only shrinks" half of that
  assumption into a check; the "is worked down" half remains a commitment.
- **Two quarantine entries pass locally.** `review-aaasm-5150` (Linux-red only,
  AAASM-5199) and `hitl-approval` (needs `cargo` on the runner) are excluded for
  stated environmental reasons rather than for failing. They are the two cases
  where "quarantined" does not mean "rotten", and both say so at the entry. Any
  future entry of this kind must state its reason the same way — an entry whose
  comment does not survive re-measurement is the defect this list exists to
  avoid, and a review pass found exactly one (`review-aaasm-5110`, which was
  listed as drift, passes 3/3, and has been un-quarantined).
- **A macOS-green spec can still be Linux-red.** The first CI run proved this:
  `review-aaasm-5150` passed locally and failed 3/3 on the runner, because its
  console-error assertion caught a CSP violation whose lazy import had not fired
  in time on faster hardware (AAASM-5199 — a real product defect, not test rot).
  Timing-sensitive assertions can therefore hide platform-independent bugs. The
  gate is the mitigation; this is it working on day one.
- **Blocking is not yet enforced end to end.** Branch protection requires no
  status contexts today, so this ADR makes the job blocking *within* `ci-success`;
  making `ci-success` a required check is a repo-admin action outside this change.
  Until that happens the gate is advisory in practice regardless of what this ADR
  says.

## Explicitly forbidden designs

- **Do not add an e2e job as advisory.** That is the state AAASM-5191 already
  proved does not work.
- **Do not use `test.skip` / `test.fixme` / deletion to make the suite green.** A
  failing spec is a finding. Quarantine is visible and reviewable in one file;
  `.skip` is invisible and rots silently.
  *Pre-existing exceptions, not grandfathered by this rule:*
  `governance-dashboard.spec.ts:123,130` hold two `test.skip`s from the
  AgentsPage→FleetPage rename. They predate this ADR and sit inside a
  quarantined file, so nothing regressed — but they are the forbidden pattern
  and are filed under AAASM-5195 for removal, not left as silent precedent.
- **Do not quarantine a spec to unblock your own PR.** The list is for specs
  already red at the gate's introduction. A spec your change breaks is your
  change's problem.
  *The one exception, stated rather than hidden:* `review-aaasm-5150` was
  quarantined by the PR that introduced this gate. It is admissible only because
  the defect it catches (AAASM-5199) is a pre-existing product bug that the
  change did not cause; blocking the gate's introduction on an unrelated High
  defect would have been self-defeating. The distinction that makes this legal
  is **"my change did not cause it"**, not **"it is inconvenient"**. Note the
  real cost: while that entry stands, the gate no longer watches the
  console-error / CSP regression class it had just proved it was good at
  catching.
- **Do not gate snapshot specs on Linux runners** without committing
  `-chromium-linux` baselines first; a `--update-snapshots` run on CI hardware
  launders a real visual regression into a new baseline.
- **Do not rebuild the bundle inside the e2e job.** It consumes
  `dashboard-build`'s artifact so a failed build cannot leave `vite preview`
  serving a stale `dist/` that the suite then passes against.

## Consequences

- **Contributors**: a dashboard change that breaks a gated spec now fails CI
  instead of merging. Failures are diagnosable from build artifacts (HTML report,
  failure screenshots, retry traces, JUnit XML) without a local reproduction.
- **Rust-only PRs**: unaffected. The job is behind the same `dorny/paths-filter`
  `dashboard` filter as the other dashboard jobs, and skips cleanly — `ci-success`
  treats a skipped job as passing. That skip is sound *for this job* because every
  gated spec exercises only code under `dashboard/`, and the filter includes
  `dashboard/**` and `ci.yml`, so the gate cannot be edited or weakened without
  itself running. It is not a general licence: `skipped` counting as pass is a
  repo-wide `ci-success` property (AAASM-2599), and any future job whose inputs
  fall outside its own filter would need a different guard.
- **Cost**: roughly 4–5 minutes of runner time on dashboard PRs (measured: 4m06s
  wall on the first green run, 3.1m of it the suite itself at 2 workers).
- **ADRs 0025 / 0027**: unchanged by this decision. See *What this gate does not
  prove* — neither contract is enforced by the gated set, and 0025 is Proposed
  in any case.

## Operational guidance

- Adding a spec requires no CI change — it is gated automatically.
- To remove a quarantine entry: fix the spec or the product bug it exposes,
  confirm it passes, delete the line.
- To make the gate actually blocking, a repo admin must add **CI Success** to the
  required status checks for `main` (see ADR 0016 for the re-verification step
  after any branch-protection change).

## Validation requirements

A validation requirement that is only ever checked by hand is a claim, not a
requirement — the first draft of this ADR asserted the `localStorage` rule below
while two **gated** specs were violating it on the same commit. Each item now
names the mechanism that enforces it, or is marked as a manual check.

| Requirement | Enforced by |
| --- | --- |
| `dashboard-e2e` appears in `ci-success`'s `needs:` list | manual (review) |
| `playwright.ci.config.ts` selects every spec not named in its quarantine list | `playwright test --config=playwright.ci.config.ts --list` |
| The gated set passes with no failures on a Linux runner | the `dashboard-e2e` job itself |
| No gated spec calls `toHaveScreenshot` | manual (`grep -rl toHaveScreenshot tests/e2e/` must return only the two quarantined snapshot specs) |
| **No spec seeds `aa_token` into `localStorage`** | **`pnpm e2e:check-seeds`**, run as its own step in `dashboard-e2e` |
| **The quarantine list never grows** | **`QUARANTINE_CEILING` in `playwright.ci.config.ts`**, evaluated on every config load, local and CI |

## Reconsideration triggers

- The AAASM-5195 quarantine reaches zero — fold `playwright.ci.config.ts` back
  into the base config and delete this mechanism.
- The quarantine stops shrinking, or grows — the gate is being used to defer work
  rather than to stay credible, and the decision should be re-argued.
- `-chromium-linux` baselines are committed — snapshot specs can then join the
  gate and sub-decision 5 is revisited.
- Suite runtime stops being sane on a dashboard PR — split into a fast blocking
  lane plus a slower scheduled lane rather than quietly reducing coverage.
- Auth moves off `sessionStorage` (e.g. to HttpOnly cookies, which
  `tokenStorage.ts` names as preferable) — sub-decision 6 and every seeding call
  site must move together, which is the failure this ADR exists to prevent.

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5192](https://lightning-dust-mite.atlassian.net/browse/AAASM-5192) | The ticket this ADR records — wire the e2e suite into CI |
| [AAASM-5191](https://lightning-dust-mite.atlassian.net/browse/AAASM-5191) | The 19-day silent breakage that motivated it |
| [AAASM-5195](https://lightning-dust-mite.atlassian.net/browse/AAASM-5195) | The 41 quarantined files; the backlog this decision depends on shrinking |
| [AAASM-5198](https://lightning-dust-mite.atlassian.net/browse/AAASM-5198) | The one quarantined spec that is racy rather than rotten |
| [AAASM-5199](https://lightning-dust-mite.atlassian.net/browse/AAASM-5199) | The live CSP/Monaco defect this gate caught on its first run |
| [AAASM-4322](https://lightning-dust-mite.atlassian.net/browse/AAASM-4322) | The `localStorage` → `sessionStorage` migration that broke the seeds |
| [AAASM-2599](https://lightning-dust-mite.atlassian.net/browse/AAASM-2599) | Established `ci-success` as the single required aggregate check |
| [ADR 0016](0016-default-branch-master-to-main-migration.md) | Branch-protection required-check handling |
| [ADR 0025](0025-design-v2-authoritative-visual-spec.md) | Visual spec whose enforcement depends on these specs running |
| [ADR 0027](0027-accessibility-floor-overrides-visual-spec.md) | Accessibility floor, same dependency |
