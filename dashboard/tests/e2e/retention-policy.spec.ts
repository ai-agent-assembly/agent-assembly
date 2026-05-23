// AAASM-1592 S-K (AAASM-1869) — functional acceptance verification for the
// Settings → Storage → Retention Policy page. Each test walks one AC from
// the parent story against the running app, with the gateway mocked at the
// network layer via `page.route()` for deterministic runs.

import { test, expect, type Page, type Request, type Route } from '@playwright/test'

// Navigate to the Retention Policy page via the Settings shell. We can't
// `page.goto('/settings/storage/retention')` directly because the dashboard
// is built with `base: './'` so deep URLs resolve relative-asset paths
// (e.g. `./assets/foo.js`) against the URL's path segments — only the
// first nesting level works. Loading `/settings` and then clicking the
// nav link sidesteps that and matches how users reach the page.
async function gotoRetentionPolicy(page: Page) {
  await page.goto('/settings')
  await page.getByTestId('settings-nav-link-storage-retention').click()
}

interface RetentionDocOverrides {
  hot_days?: number
  warm_days?: number
  cold_action?: 'drop' | 'archive'
  archive_url?: string | null
  last_run?: ReturnType<typeof makeStats> | null
}

function makeDoc(overrides: RetentionDocOverrides = {}) {
  return {
    hot_days: overrides.hot_days ?? 30,
    warm_days: overrides.warm_days ?? 90,
    cold_action: overrides.cold_action ?? 'drop',
    archive_url: overrides.archive_url ?? null,
    dry_run: false,
    schedule: '0 0 3 * * *',
    last_run: overrides.last_run === undefined ? null : overrides.last_run,
  }
}

function makeStats(overrides: Partial<ReturnType<typeof makeStatsRaw>> = {}) {
  return { ...makeStatsRaw(), ...overrides }
}

function makeStatsRaw() {
  return {
    ran_at: '2026-05-20T03:00:12Z',
    hot_rows: 1234,
    compressed_rows: 1452,
    archived_rows: 0,
    dropped_rows: 388,
    freed_bytes: 127 * 1024 * 1024,
    dry_run: false,
  }
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

interface MockState {
  doc: ReturnType<typeof makeDoc>
  putRequests: unknown[]
  postRunRequests: unknown[]
}

async function mockBackend(page: Page, state: MockState) {
  // Quiesce the shell-level chatter that fires on every page nav.
  await page.route('**/api/v1/approvals**', (route: Route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route: Route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/ws/events*', (route: Route) => route.abort())

  // Retention policy GET / PUT — both bound to the same path.
  await page.route('**/api/v1/admin/retention-policy', async (route: Route, request: Request) => {
    const method = request.method()
    if (method === 'GET') {
      return route.fulfill({ status: 200, json: state.doc })
    }
    if (method === 'PUT') {
      const body = JSON.parse(request.postData() ?? '{}')
      state.putRequests.push(body)
      state.doc = {
        ...state.doc,
        hot_days: body.hot_days,
        warm_days: body.warm_days,
        cold_action: body.cold_action,
        archive_url: body.archive_url ?? null,
      }
      return route.fulfill({ status: 200, json: state.doc })
    }
    return route.fallback()
  })

  // POST /run — return the canned stats and stash the request body so the
  // dry-run AC can be asserted on.
  await page.route('**/api/v1/admin/retention-policy/run', async (route: Route, request: Request) => {
    const body = JSON.parse(request.postData() ?? '{}')
    state.postRunRequests.push(body)
    const stats = { ...makeStatsRaw(), dry_run: Boolean(body.dry_run), hot_rows: 9999, dropped_rows: 222 }
    state.doc = { ...state.doc, last_run: stats }
    return route.fulfill({ status: 200, json: stats })
  })
}

test.describe('AAASM-1592 S-K — Retention Policy admin page (functional AC)', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
  })

  test('AC1 — page renders at /settings/storage/retention with values from GET', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc({ hot_days: 30, warm_days: 90, cold_action: 'drop' }),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)

    const hotInput = page.getByTestId('retention-policy-hot-days')
    const warmInput = page.getByTestId('retention-policy-warm-days')
    const coldSelect = page.getByTestId('retention-policy-cold-action')

    await expect(hotInput).toHaveValue('30')
    await expect(warmInput).toHaveValue('90')
    await expect(coldSelect).toHaveValue('drop')
  })

  test('AC2 — changing hot_days to 15 and saving fires PUT with that value', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc({ hot_days: 30, warm_days: 90, cold_action: 'drop' }),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)
    const hotInput = page.getByTestId('retention-policy-hot-days')
    await hotInput.fill('15')
    await page.getByTestId('retention-policy-save').click()

    await expect(page.getByTestId('retention-policy-status')).toContainText(/updated/i)
    expect(state.putRequests.length).toBeGreaterThan(0)
    const sent = state.putRequests[0] as { hot_days: number; warm_days: number }
    expect(sent.hot_days).toBe(15)
    expect(sent.warm_days).toBe(90)
  })

  test('AC3 — warm_days <= hot_days shows inline error and disables Save', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc({ hot_days: 30, warm_days: 90 }),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)
    await page.getByTestId('retention-policy-warm-days').fill('30')

    await expect(page.getByTestId('retention-policy-warm-days-error')).toBeVisible()
    await expect(page.getByTestId('retention-policy-save')).toBeDisabled()
  })

  test('AC4 — cold_action=archive without archive_url shows inline error', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc(),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)
    await page.getByTestId('retention-policy-cold-action').selectOption('archive')

    await expect(page.getByTestId('retention-policy-archive-field')).toBeVisible()
    await expect(page.getByTestId('retention-policy-archive-url-error')).toContainText(/required/)
    await expect(page.getByTestId('retention-policy-save')).toBeDisabled()
  })

  test('AC5 — Run Now (Dry Run) fires POST /run {dry_run:true} and shows returned stats', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc(),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)
    await page.getByTestId('retention-policy-dry-run').click()

    await expect(page.getByTestId('retention-policy-stat-hot')).toHaveText('9,999')
    await expect(page.getByTestId('retention-policy-last-run-dry-run-tag')).toBeVisible()
    expect(state.postRunRequests).toEqual([{ dry_run: true }])
  })

  test('AC6 — last-run stats panel renders timestamp and counts from the GET response', async ({ page }) => {
    const lastRun = makeStats({ hot_rows: 5000, dropped_rows: 200, compressed_rows: 0 })
    const state: MockState = {
      doc: makeDoc({ last_run: lastRun }),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)

    await expect(page.getByTestId('retention-policy-stat-hot')).toHaveText('5,000')
    await expect(page.getByTestId('retention-policy-stat-dropped')).toHaveText('200')
    await expect(page.getByTestId('retention-policy-last-run')).toContainText('20 May 2026')
  })

  test('AC7 — PUT response carries the updated config (live read-back path)', async ({ page }) => {
    const state: MockState = {
      doc: makeDoc({ hot_days: 30, warm_days: 90 }),
      putRequests: [],
      postRunRequests: [],
    }
    await mockBackend(page, state)

    await gotoRetentionPolicy(page)
    await page.getByTestId('retention-policy-warm-days').fill('45')
    await page.getByTestId('retention-policy-save').click()

    // After the success status, the inputs must reflect the PUT response
    // (the page calls setForm(docToFormState(updated)) on save success).
    await expect(page.getByTestId('retention-policy-status')).toContainText(/updated/i)
    await expect(page.getByTestId('retention-policy-warm-days')).toHaveValue('45')
  })
})
