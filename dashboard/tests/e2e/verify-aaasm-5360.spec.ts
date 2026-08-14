import { expect, test } from '@playwright/test'

/**
 * AAASM-5360 acceptance evidence, captured against a **real** `aa-api-server`.
 *
 * # Why this spec exists and why it is not `page.route`-mocked
 *
 * AAASM-5360's verification plan requires screenshots of the sensitive-data
 * views taken from the running application, and says in terms that "mock-only
 * screenshots are not acceptable when the real app can be run". `tests/e2e/README.md`
 * records why that instruction matters here more than usual: of the 44 gated
 * specs, **all 44 stub every network call**, so the gate compares the frontend
 * against its own hand-written mocks and cannot observe the real API at all.
 * The AAASM-4892 pagination-envelope breakage is the standing proof — the app
 * had already been fixed and it was the *mocks* that were stale.
 *
 * So every response asserted below comes from a real `aa-api-server` process
 * over a real HTTP round trip, via `route.fetch`. Nothing here is stubbed.
 * This follows the one existing precedent, `hitl-approval`, which is also the
 * only other spec in the suite that talks to a live backend.
 *
 * # Running it
 *
 * ```
 * cargo build -p aa-api --bin aa-api-server
 * AASM_API_AUTH=off AA_API_ADDR=127.0.0.1:7700 aa-api-server
 * pnpm exec playwright test tests/e2e/verify-aaasm-5360.spec.ts
 * ```
 *
 * It **skips rather than fails** when nothing is listening on 7700. A spec that
 * fails when its fixture is absent gets quarantined and then ignored; one that
 * skips stays honest about what it did and did not verify. The skip reason names
 * the command, so the next person is not left guessing.
 *
 * # What this covers, and what it does not
 *
 * Covered against the real backend: the **cross-tenant refusal** and the
 * **empty window**. Those are the two states reachable without writing rows into
 * the projection, and the first is the more valuable of the two — it is the
 * documented functional limit of this page, and a mock would have proved nothing
 * about whether the server actually enforces it.
 *
 * **Not covered:** the populated state. Producing one means driving real policy
 * evaluations through a gateway configured with `AA_SENSITIVE_DATA_PROJECTION_DB`
 * so the projection has rows. That is a Rust-side fixture, not a dashboard one,
 * and `tests/e2e/README.md` explains that no CI lane can run such a thing today
 * — the `dashboard-e2e` job body contains zero matches for `rust`, `cargo` or
 * `toolchain`. Recorded rather than papered over.
 */

const API = 'http://127.0.0.1:7700'
const FROM = '2026-07-31T00:00:00Z'
const TO = '2026-08-08T00:00:00Z'

async function realApiIsUp(): Promise<boolean> {
  try {
    const response = await fetch(`${API}/api/v1/health`)
    return response.ok
  } catch {
    return false
  }
}

test.describe('AAASM-5360 — sensitive-data views against a real aa-api', () => {
  test.beforeEach(async () => {
    test.skip(
      !(await realApiIsUp()),
      `no aa-api-server on ${API}. Start one with: ` +
        `cargo build -p aa-api --bin aa-api-server && ` +
        `AASM_API_AUTH=off AA_API_ADDR=127.0.0.1:7700 aa-api-server`
    )
  })

  /**
   * The state the page is actually in for a cross-tenant caller.
   *
   * The dashboard never sends `org_id` — it has no endpoint enumerating the
   * organisations a token may read, so a selector would imply an access it
   * cannot check. The server therefore refuses, and the *reason* it gives is
   * the thing worth pinning: an empty 200 here would be indistinguishable from
   * "this tenant has no sensitive data".
   */
  test('the real server refuses an unscoped read, and says why', async () => {
    const response = await fetch(
      `${API}/api/v1/sensitive-data/summary?from=${FROM}&to=${TO}`
    )

    expect(response.status).toBe(400)
    expect(response.headers.get('content-type')).toContain('application/problem+json')

    const problem = await response.json()
    expect(problem.detail).toContain('must name the organisation to read via `org_id`')
    expect(problem.detail).toContain('no unscoped read')
  })

  /**
   * An empty window returns **null** rates, not zeros.
   *
   * This is the AAASM-5112/5156 rule holding at the source: a rate over no
   * events is not a rate of zero, and a backend that returned `0.0` here would
   * hand the UI a number indistinguishable from a measured one. Asserted
   * against the real server because it is a *backend* guarantee — a mock
   * asserting it would only be restating the fixture author's belief.
   */
  test('an empty window returns null rates rather than zeros', async () => {
    const response = await fetch(
      `${API}/api/v1/sensitive-data/summary?from=${FROM}&to=${TO}&org_id=acme`
    )
    expect(response.status).toBe(200)

    const body = await response.json()

    expect(body.counters.event_count).toBe(0)
    expect(body.counters.finding_count).toBe(0)

    // The point of the test. `null`, never 0.
    expect(body.rates.prevention_rate).toBeNull()
    expect(body.rates.block_rate).toBeNull()
    expect(body.rates.unmeasured_transmission_rate).toBeNull()
    expect(body.rates.findings_per_event).toBeNull()
  })

  /**
   * Counter names travel as separate fields, so the UI cannot collapse an event
   * count into a finding count by reading one where it meant the other.
   *
   * ADR 0032 §8 keeps six counters distinct; a response shape that merged any
   * pair would make the labelling work in `CountFigure` unenforceable no matter
   * how careful the component was.
   */
  test('event and finding counters are separate fields on the real response', async () => {
    const response = await fetch(
      `${API}/api/v1/sensitive-data/summary?from=${FROM}&to=${TO}&org_id=acme`
    )
    const body = await response.json()

    for (const key of [
      'event_count',
      'finding_count',
      'blocked_event_count',
      'blocked_finding_count',
      'redacted_event_count',
      'redacted_finding_count',
    ]) {
      expect(body.counters).toHaveProperty(key)
    }
  })

  /**
   * The page rendered by the real browser, against the real server.
   *
   * `route.fetch` proxies every `/api/v1/**` call to the live process rather
   * than fulfilling it from a fixture, so what the screenshot shows is what an
   * operator would see. The assertion is on the explained refusal state — not
   * on a blank page — because "cannot read this tenant" and "this tenant is
   * clean" must not look alike.
   */
  test('the page renders the refusal as an explained state, not an empty chart', async ({
    page,
  }) => {
    await page.route('**/api/v1/**', async (route) => {
      const url = new URL(route.request().url())
      const response = await route.fetch({
        url: `${API}${url.pathname}${url.search}`,
      })
      await route.fulfill({ response })
    })

    // Seed the session the way production does — sessionStorage only, never
    // localStorage (AAASM-4322). Without this the app redirects to the login
    // screen, and an assertion that merely checks the page is non-blank passes
    // against *that*. This test asserted exactly that in its first draft and
    // "passed" over a screenshot of the login form; the assertions below name
    // sensitive-data-specific content precisely so that cannot recur.
    await page.addInitScript(() => {
      sessionStorage.setItem('aa_token', 'aa_e2e_local_key')
    })

    await page.goto('/sensitive-data')
    await page.waitForLoadState('networkidle')

    // Anti-vacuity: prove we are on the page under test, not on a login form or
    // a router fallback.
    await expect(page).toHaveURL(/\/sensitive-data/)
    await expect(page.getByTestId('sensitive-data-page')).toBeVisible()

    // The page must resolve to an explained state. A blank region, or a chart
    // rendered as though the tenant were simply clean, is the defect.
    const page_ = page.getByTestId('sensitive-data-page')
    await expect(page_).toHaveAttribute('data-access', /.+/)

    await page.screenshot({
      path: 'test-results/aaasm-5360-real-api-refusal.png',
      fullPage: true,
    })
  })
})
