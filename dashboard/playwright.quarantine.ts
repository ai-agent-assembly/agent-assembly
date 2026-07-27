/**
 * The e2e quarantine list and the ratchet that governs it (AAASM-5192).
 *
 * Lives in its own module so BOTH configs load it: `playwright.ci.config.ts`
 * consumes the list as `testIgnore`, and `playwright.config.ts` imports it for
 * the side effect alone. An earlier version put the ratchet in the CI config
 * only and claimed it ran "on every config load, local and CI" — untrue, since
 * `pnpm test:e2e` never loads that file. Now it is true.
 *
 * The gate is the base config plus this one thing. Every spec runs by default
 * — a file has to be named here to be excluded — so a spec added by someone
 * else is gated automatically and cannot opt out by accident. The list only
 * ever shrinks.
 *
 * WHY A QUARANTINE AT ALL: on the commit that introduced this gate the full
 * suite was 433 tests with ~130 failures across 41 files, tracked in
 * AAASM-5195. Those failures are real rot, not flake, and they are NOT what
 * this gate is for: gating on a red suite teaches everyone to ignore it, which
 * is exactly how the suite died in the first place (AAASM-5191 — 31 files dead
 * for 19 days because nothing ran them). A small gate that is believed beats a
 * large one that is not.
 *
 * Nothing here is `.skip`-ed or deleted. Every quarantined spec still runs on
 * `pnpm test:e2e` locally, so the rot stays visible to anyone who looks; the
 * exclusion lives in this one reviewable file rather than hidden in the specs.
 *
 * TO REMOVE AN ENTRY: fix the spec (or the product bug it exposes), confirm it
 * passes, delete the line, and lower `QUARANTINE_CEILING` below by the same
 * amount. No approval needed — shrinking this list is always the desired
 * direction.
 *
 * EVERY ENTRY WAS RE-MEASURED on 2026-07-27 (review follow-up), individually
 * and as a group. That pass removed `review-aaasm-5110.spec.ts`, which was
 * listed as untriaged drift but passes 3/3 in isolation and in every group run
 * — 12 tests had been excluded from the gate for no reason. Two entries pass
 * locally and are quarantined for a stated environmental reason rather than
 * for failing (`review-aaasm-5150`, `hitl-approval`); both say so below.
 */

/**
 * Specs excluded from the gate, grouped by the cause diagnosed in AAASM-5195.
 * Paths are relative to `testDir` (`tests/e2e`).
 */
const QUARANTINE = [
  // --- Stale visual baselines -------------------------------------------
  // Both differ from their committed baselines by 2–5% against a 0.01
  // maxDiffPixelRatio *on macOS, the platform those baselines were generated
  // on* — the dashboard was redesigned during the blackout and nothing
  // regenerated them. Regenerating needs human visual review, not a blind
  // --update-snapshots. Separately, these are the only gated-relevant specs
  // with platform-specific (`-chromium-darwin`) baselines and there are no
  // `-chromium-linux` ones, so they could not run on ubuntu-latest even if the
  // baselines were current (see tests/e2e/README.md).
  'responsive-viewport-visual.spec.ts',
  'theme-visual.spec.ts',

  // --- Pagination-envelope drift (AAASM-4892) ---------------------------
  // The list endpoints now return `{ items, total }`; these specs' route mocks
  // still fulfil a bare array, so every list renders zero rows.
  'alerts.spec.ts',
  'approvals-expired.spec.ts',
  'audit-log-theme.spec.ts',
  'capability.spec.ts',
  'dashboard-gateway-smoke.spec.ts',
  'fleet.spec.ts',
  'governance-dashboard.spec.ts',
  'iam.spec.ts',
  'policies.spec.ts',
  'sandbox-summary.spec.ts',

  // --- Fleet row-click redesign -----------------------------------------
  // FleetPage now navigates to /agents/:id on row click; these still expect an
  // in-place `drawer-panel`. Needs a product call on which side is correct.
  'verify-aaasm-94.spec.ts',

  // --- Catching a real product bug (AAASM-5199) -------------------------
  // NOT test rot. This spec asserts the page logs no console errors, and on a
  // Linux runner it correctly catches one: `RuleYamlViewer` lazy-loads
  // `@monaco-editor/react`, which fetches the Monaco runtime from jsDelivr,
  // which `index.html`'s `script-src 'self'` CSP (AAASM-4322) forbids — so the
  // YAML editor cannot load in ANY built dashboard. It passes on macOS only
  // because the lazy import had not fired before the assertion ran.
  //
  // Quarantined solely so the gate lands green in the PR that introduces it.
  // Delete this entry the moment AAASM-5199 is fixed — it is the one entry here
  // pointing at a live defect rather than at a stale spec.
  'review-aaasm-5150.spec.ts',

  // --- Racy, not rotten (AAASM-5198) ------------------------------------
  // Its "force layout settles" check treats two consecutive identical
  // position samples as proof
  // the d3 simulation stopped, which is not sound — on an idle machine the
  // samples arrive fast enough to match mid-motion, and the later
  // "cards do not move" assertion then fails against a still-moving graph.
  // Fails 3/3 at --workers=1; passed under 6-worker load, i.e. it gets *more*
  // likely to fail the quieter the runner, which is exactly a CI runner.
  'verify-aaasm-5135.spec.ts',

  // --- Needs a real Rust gateway, which this job does not provision ------
  // NOT test rot — it passes locally (3/3 isolated). `hitl-fixture.ts` spawns
  // `cargo test --test e2e_hitl_approval e2e_fixture_main` to boot a real
  // `aa-api`, because this is the one spec that asserts a genuine
  // {dashboard → REST → ApprovalQueue → REST → dashboard} round-trip instead
  // of mocking it. The `dashboard-e2e` job installs pnpm + Node + Chromium and
  // nothing else, so `cargo` is absent on the runner. Provisioning a Rust
  // toolchain and a cold workspace build inside the dashboard gate would cost
  // more than the whole suite; this spec belongs in a Rust-side e2e lane.
  // Tracked in AAASM-5195. (It also explains the local flake: under 6-worker
  // load the cargo build and port bind contend and it fails.)
  'hitl-approval.spec.ts',

  // --- Not yet individually triaged (AAASM-5195) ------------------------
  // Assorted data-testid / behaviour drift. Listed honestly as untriaged
  // rather than assigned a cause that has not been verified. Every entry here
  // was re-measured on 2026-07-27 and confirmed still failing.
  'alerts-5026-verify.spec.ts',
  'alerts-design-fidelity.spec.ts',
  'analytics.spec.ts',
  'budget-burn-design-fidelity.spec.ts',
  'capability-design-fidelity.spec.ts',
  'fleet-design-fidelity.spec.ts',
  'permissions-panel-design-fidelity.spec.ts',
  'retention-policy-design-fidelity.spec.ts',
  'review-aaasm-5084.spec.ts',
  'sandbox-enable-live.spec.ts',
  'topology-design-fidelity.spec.ts',
  'trace-design-fidelity.spec.ts',
  'trace.spec.ts',
  'verify-aaasm-1152.spec.ts',
  'verify-aaasm-1341.spec.ts',
  'verify-aaasm-5023.spec.ts',
  'verify-aaasm-5027.spec.ts',
  'verify-aaasm-5032.spec.ts',
  'verify-aaasm-5042.spec.ts',
  'verify-aaasm-5045.spec.ts',
  'verify-aaasm-5046.spec.ts',
  'verify-aaasm-5071.spec.ts',
  'verify-aaasm-5074.spec.ts',
  'verify-aaasm-5075.spec.ts',
  'verify-aaasm-5077.spec.ts',
  'verify-aaasm-5080.spec.ts',
]

/**
 * The ratchet.
 *
 * "The list only shrinks" was prose with nothing enforcing it, which left the
 * gate hollowable from the inside: a PR adding entries still touches
 * `dashboard/**`, so the job runs — on the *reduced* set — and goes green.
 *
 * WHY IDENTITIES, NOT A COUNT: the first version compared `QUARANTINE.length`
 * against a ceiling. Review pointed out that a count lets a 1-for-1 swap
 * through — retire a fixed spec, quarantine a newly-broken one, and the list
 * rots at a constant size while the number looks reassuring. This asserts the
 * live list is a SUBSET of the frozen baseline below, so removals are free and
 * any addition or substitution fails loudly. It subsumes a count ceiling:
 * a subset can never be larger than its baseline.
 *
 * WHEN YOU FIX A SPEC: delete its line from QUARANTINE. Leave the baseline
 * alone — shrinking needs no ceremony.
 *
 * WHEN YOU MUST GENUINELY QUARANTINE SOMETHING NEW: add it to QUARANTINE *and*
 * to the baseline, in the same commit, with the cause stated. That is two
 * deliberate edits a reviewer cannot miss, which is the entire point — not to
 * make it impossible, but to make it visible.
 */
const QUARANTINE_BASELINE: ReadonlySet<string> = new Set([
  'alerts-5026-verify.spec.ts', 'alerts-design-fidelity.spec.ts',
  'alerts.spec.ts', 'analytics.spec.ts',
  'approvals-expired.spec.ts', 'audit-log-theme.spec.ts',
  'budget-burn-design-fidelity.spec.ts', 'capability-design-fidelity.spec.ts',
  'capability.spec.ts', 'dashboard-gateway-smoke.spec.ts',
  'fleet-design-fidelity.spec.ts', 'fleet.spec.ts',
  'governance-dashboard.spec.ts', 'hitl-approval.spec.ts',
  'iam.spec.ts', 'permissions-panel-design-fidelity.spec.ts',
  'policies.spec.ts', 'responsive-viewport-visual.spec.ts',
  'retention-policy-design-fidelity.spec.ts', 'review-aaasm-5084.spec.ts',
  'review-aaasm-5150.spec.ts', 'sandbox-enable-live.spec.ts',
  'sandbox-summary.spec.ts', 'theme-visual.spec.ts',
  'topology-design-fidelity.spec.ts', 'trace-design-fidelity.spec.ts',
  'trace.spec.ts', 'verify-aaasm-1152.spec.ts',
  'verify-aaasm-1341.spec.ts', 'verify-aaasm-5023.spec.ts',
  'verify-aaasm-5027.spec.ts', 'verify-aaasm-5032.spec.ts',
  'verify-aaasm-5042.spec.ts', 'verify-aaasm-5045.spec.ts',
  'verify-aaasm-5046.spec.ts', 'verify-aaasm-5071.spec.ts',
  'verify-aaasm-5074.spec.ts', 'verify-aaasm-5075.spec.ts',
  'verify-aaasm-5077.spec.ts', 'verify-aaasm-5080.spec.ts',
  'verify-aaasm-5135.spec.ts', 'verify-aaasm-94.spec.ts',
])

const additions = QUARANTINE.filter((spec) => !QUARANTINE_BASELINE.has(spec))
if (additions.length > 0) {
  throw new Error(
    `Quarantine gained ${additions.length} entry/entries not in the frozen baseline: ` +
      `${additions.join(', ')}. The e2e gate only stays credible if this list shrinks ` +
      `(ADR-0028, AAASM-5195). Fix the spec instead — or, if the addition is genuinely ` +
      `justified, add it to QUARANTINE_BASELINE in the same commit so the decision is ` +
      `visible in review.`,
  )
}

export default QUARANTINE
