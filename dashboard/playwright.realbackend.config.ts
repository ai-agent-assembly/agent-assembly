import { defineConfig } from '@playwright/test'

import base from './playwright.config'

/**
 * The real-backend e2e lane (AAASM-5694).
 *
 * # Why this is a separate config and not an entry in the CI one
 *
 * `playwright.ci.config.ts` applies `playwright.quarantine.ts`, and
 * `hitl-approval.spec.ts` is *in* that quarantine list — quarantined precisely
 * because it needs a live gateway the `dashboard-e2e` job cannot provide (that
 * job body contains zero matches for `rust`, `cargo` or `toolchain`). Adding
 * these specs to the CI config would either un-quarantine a spec that still
 * cannot run there, or run it against nothing.
 *
 * So the split is along the axis that actually matters: **whether the lane
 * provisions a backend**. This config runs only the specs that need one, and
 * only in the job that starts one.
 *
 * # No quarantine list here, on purpose
 *
 * A quarantine is a list of specs allowed to be absent. This lane's whole
 * premise is that absence is the failure being fixed, so it does not get one.
 * If a spec here is broken, it goes red.
 */
export default defineConfig({
  ...base,

  testMatch: [
    // Asserts the paginated envelope against the live server — the AAASM-4892
    // drift class the mocked gate structurally cannot see.
    '**/real-backend-contract.spec.ts',
    // AAASM-5360's acceptance evidence: proxies /api/v1/** to the live server.
    '**/verify-aaasm-5360.spec.ts',
    // The one pre-existing spec that asserts a genuine round trip.
    '**/hitl-approval.spec.ts',
  ],

  // Retries hide a flaky backend boot, which is the one failure this lane must
  // report rather than paper over.
  retries: 0,

  use: {
    ...base.use,
    // The base config uses `on-first-retry`, and with `retries: 0` there is
    // never a first retry — so the slowest, most environment-dependent lane in
    // the repository produced no trace at all. `retain-on-failure` is what makes
    // a CI-only failure diagnosable from the artifact, which is the base
    // config's own stated reason for enabling traces.
    trace: 'retain-on-failure',
  },

  // NOTE: this budget is deliberately config-wide even though only
  // `hitl-approval` needs it. A per-spec `test.setTimeout` would be tighter, but
  // it lives in a file this PR does not own; revisit together.
  //
  // `hitl-approval` spawns its own gateway through `cargo test`, and
  // `hitl-fixture.ts` budgets `READY_TIMEOUT_MS = 4 minutes` for a cold build.
  // A Playwright hook inherits the *test* timeout, so under the inherited 30s
  // the `beforeAll` was killed at 30s — three and a half minutes before the
  // fixture itself would have given up. Measured locally: the spec failed with
  // "beforeAll hook timeout of 30000ms exceeded" while every other spec passed.
  //
  // That is why simply listing the spec in this config was not enough to make
  // it run: it executed and went red, which the AC ("both execute rather than
  // skip") would have been satisfied by while the lane stayed permanently
  // broken. The budget here is the fixture's own, plus room for the assertions.
  timeout: 5 * 60 * 1000,

  reporter: [
    ['list'],
    // Consumed by `scripts/assert-e2e-actually-ran.mjs`. The exit code alone
    // cannot distinguish "passed" from "skipped everything", which is the
    // defect AAASM-5694 reports; the JSON report can.
    ['json', { outputFile: 'test-results/real-backend-report.json' }],
  ],
})
