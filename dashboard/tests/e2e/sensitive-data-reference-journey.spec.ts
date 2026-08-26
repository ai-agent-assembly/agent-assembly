// AAASM-5904 — the browser-level leg of the sensitive-data reference journey
// (AAASM-5875 Subtask C, registry row J65).
//
// `aa-integration-tests/tests/e2e_sensitive_data_reference_journey.rs`
// (AAASM-5903) proves the chain up through the live `aa-api-server`'s REST
// surface: a real canary reaches a real `aa-proxy`, is redacted before
// forwarding, and the resulting alert is observable via `/api/v1/alerts`.
// That file's own `e2e_fixture_main` (`#[ignore]`) drives the same canary
// request and idles with the alert already seeded — all orchestration stays
// in Rust. This spec's only job is the two forbidden-destination checks the
// Rust suite structurally cannot make: that the redacted alert is actually
// visible to an operator looking at the real dashboard (destination 6), and
// that the raw canary reaches neither the rendered DOM nor any network
// response the browser captures while getting there (destination 7).
//
// Companion negative control: AAASM-5903's
// `alert_only_forwards_the_canary_and_produces_no_alert` proves the *absence*
// of an alert when the proxy is configured to not act on a detection —
// proving this spec's "the alert is visible" assertion is load-bearing
// rather than vacuously true regardless of what the proxy actually does
// (the security-lane registry rule, AAASM-5877).

import { test, expect } from '@playwright/test'

import { type FixtureHandle, killFixture, spawnFixture } from './sensitive-data-fixture'

let fixture: FixtureHandle | undefined

test.beforeAll(async () => {
  fixture = await spawnFixture()
})

test.afterAll(async () => {
  killFixture(fixture)
  fixture = undefined
})

test.describe('Alerts — AAASM-5904: sensitive-data reference journey via real gateway', () => {
  test('the redacted secret alert is visible; the raw canary reaches neither the DOM nor a captured response', async ({
    page,
  }) => {
    const { baseUrl, canaryValue } = fixture!

    // Project-wide auth shim — see `hitl-approval.spec.ts` (AAASM-4322 /
    // AAASM-5191): the dashboard reads `aa_token` from sessionStorage.
    await page.addInitScript(() => {
      sessionStorage.setItem('aa_token', 'e2e-test-token')
    })

    // No event-broadcast plumbing in the fixture; fall back to the
    // polling/optimistic path, same as `hitl-approval.spec.ts`.
    await page.route('**/api/v1/ws/events*', (route) => route.abort())

    // Every response body this page receives while navigating, checked at
    // the end against the raw canary — destination 7 of the forbidden-
    // destination checklist. Collected via the page's own response event
    // (not `route.fetch`'s return value) so this also covers requests this
    // spec did not explicitly proxy. Each entry is a pending read, awaited
    // together after the page settles.
    const pendingBodies: Promise<string>[] = []
    page.on('response', (response) => {
      // Binary/opaque bodies (e.g. fonts, images) can't carry a text canary
      // and `.text()` on them would just add noise here — swallow read
      // failures to an empty string instead of failing the check.
      pendingBodies.push(response.text().catch(() => ''))
    })

    // Proxy `/api/v1/**` to the live fixture, same pattern as
    // `hitl-approval.spec.ts`.
    await page.route('**/api/v1/**', async (route) => {
      const url = new URL(route.request().url())
      const proxiedUrl = `${baseUrl}${url.pathname}${url.search}`
      const postData = route.request().postData()

      const response = await route.fetch({
        url: proxiedUrl,
        method: route.request().method(),
        headers: route.request().headers(),
        ...(postData !== null ? { postData } : {}),
      })

      await route.fulfill({ response })
    })

    // The fixture's `secret_detected` alert fires directly from the
    // telemetry ingest, with no rule engine involved (`rule_context: None`,
    // `aa-api/src/alerts/mod.rs::stored_secret_alert_from`) — so a fresh
    // `aa-api-server` genuinely has zero alert rules configured. That is not
    // a gap this spec exists to cover: `AlertsFeedBody`'s own precedence
    // (`noRulesConfigured`, checked before "no rows matched") takes over the
    // whole page with an onboarding empty state whenever the rules list is
    // empty, regardless of whether alerts exist — real behaviour a rules-page
    // journey should assert, not this one. Stubbed after the broad proxy
    // route above (Playwright matches the most-recently-registered handler
    // first) so this journey can isolate what it actually tests: the alert
    // itself. `decodeAlertRules` only requires `id: string` per row
    // (`schema.ts`), so this is the minimal shape that clears the check.
    await page.route('**/api/v1/alerts/rules', (route) => route.fulfill({ json: [{ id: 'stub-rule' }] }))

    await page.goto('/alerts')

    // Destination 6: the redacted alert is visible to an operator on the
    // real Alerts view. The fixture seeds exactly one alert (a fresh
    // `aa-api-server` per run), so an exact count is a genuine assertion,
    // not an approximation — and `severity-badge-CRITICAL` is the one
    // dashboard-visible fact `aa-api` always sets for a `secret_detected`
    // alert (`stored_secret_alert_from`, `aa-api/src/alerts/mod.rs`),
    // unlike `ruleName`/`destination`, which are empty for this alert
    // category (`rule_context: None` — no rule fired, the telemetry ingest
    // recorded it directly).
    const alertRow = page.getByTestId('alert-row')
    await expect(alertRow).toHaveCount(1, { timeout: 15_000 })
    await expect(alertRow.getByTestId('severity-badge-CRITICAL')).toBeVisible()

    // Destination 6 (DOM leak check): the raw canary must not be anywhere in
    // the rendered page, even outside the table (e.g. a stray tooltip or an
    // unescaped error message). `page.content()` (full serialized HTML), not
    // `locator('body').innerText()` — independent review, AAASM-5904:
    // `innerText()` returns only rendered *visible text*, so it cannot see a
    // leak carried in an attribute (`title=`, `aria-label=`, `data-*`) or a
    // `display:none` subtree, exactly the "stray tooltip" case this check
    // claims to cover.
    const pageHtml = await page.content()
    expect(pageHtml).not.toContain(canaryValue)

    // Destination 7: no response body captured during this navigation may
    // carry the raw canary either — the API's own redaction, not just the
    // dashboard's rendering, is what is under test here.
    //
    // Positive control before trusting the absence — independent review,
    // AAASM-5904: every body read above swallows its own failure to `''`, so
    // a broad read failure across every captured response would leave
    // `bodies` all-empty and the loop below would assert nothing while still
    // going green. Confirms at least one body was genuinely read and carries
    // real content from this journey before trusting that none carry the
    // canary.
    const bodies = await Promise.all(pendingBodies)
    expect(
      bodies.some((body) => body.includes('secret_detected')),
      'no captured response body contained real alert content — response reading failed silently, so the absence check below would prove nothing',
    ).toBe(true)
    for (const body of bodies) {
      expect(body).not.toContain(canaryValue)
    }
  })
})
