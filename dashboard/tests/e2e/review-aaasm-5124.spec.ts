/**
 * Review pass for the capability bulk-override lane (AAASM-5124).
 *
 * The regression is driven end to end rather than assumed. The wire is made to
 * serve a matrix shaped the way the live projection actually shapes it — every
 * cell `allow` / `deny` / `na`, because `narrow` and `approval` are decided by
 * policy stages the projection does not run — and the override POST is held
 * open, so the browser sits in exactly the window where the page had painted
 * its optimistic edit but had no answer from the gateway yet.
 *
 * What each run re-derives:
 *
 *  1. the decision dropdown offers nothing `POST /capability/override` answers
 *     with a 400, **and pre-selects nothing at all** — the primary control is
 *     disabled, with its reason on it, until an operator chooses a decision. An
 *     earlier revision defaulted to `deny` to avoid the guaranteed 400, which
 *     turned the same unconsidered click into a successful bulk write with no
 *     undo in the UI (AAASM-5124 review);
 *  2. the write is gated behind a confirmation that names how many agents it
 *     affects and which decision it records — and dismissing that confirmation
 *     sends no request at all;
 *  3. the legend keys only the states the projection can emit; `narrow` and
 *     `approval` appear in no legend entry and no control (ADR 0026 Decision 2);
 *  4. neither the control nor the success toast claims an enforcement change:
 *     the override store has never fed enforcement, so both must read as a
 *     dashboard annotation (AAASM-5178);
 *  5. across the whole override flow — before, during and after the round-trip
 *     — no cell ever carries `narrow` or `approval`. This is recorded by a
 *     `MutationObserver` installed before any app code runs, so a decision that
 *     existed only for one frame is still caught; polling alone could step over
 *     it;
 *  6. the optimistic edit really does run — `deny` is observed on the grid while
 *     the POST is still unanswered — so (5) is a property of what the page can
 *     paint, not of a page that painted nothing;
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the matrix and
 * the override are injected with `page.route` and the token is seeded with
 * `addInitScript` before any module runs — a fetch shim installed later would
 * never be seen.
 *
 * Screenshots land in dashboard/verify/5124/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5124')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** The two decisions `apply_override` rejects with a 400. */
const REJECTED_BY_GATEWAY = ['narrow', 'approval'] as const

const RESOURCES = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: ['gmail/*'] },
  { id: 'pg', name: 'Postgres', group: 'data', paths: ['pg.public.*'] },
]

/**
 * Two agents, in the vocabulary the projection can actually emit.
 *
 * `trust` is `null` and the optional columns are omitted, which is what the
 * live endpoint sends today — no reason for this run to hand the page richer
 * data than production does.
 */
const AGENTS = [
  {
    id: 'research-bot-04',
    name: 'research-bot-04',
    framework: 'LangChain',
    owner: 'data-platform',
    trust: null,
    status: 'active',
    lastSeen: new Date().toISOString(),
    caps: {
      gmail: { read: 'allow', write: 'allow', delete: 'allow', exec: 'na' },
      pg: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
    },
  },
  {
    id: 'support-triage',
    name: 'support-triage',
    framework: 'CrewAI',
    owner: 'cx-tools',
    trust: null,
    status: 'active',
    lastSeen: new Date().toISOString(),
    caps: {
      gmail: { read: 'allow', write: 'allow', delete: 'deny', exec: 'na' },
      pg: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
    },
  },
]

const MATRIX = {
  resources: RESOURCES,
  agents: AGENTS,
  policies: [
    {
      id: 'P-021',
      name: 'inbox-scope',
      scope: 'team:data-platform',
      status: 'active',
      affects: ['research-bot-04'],
      rules: [{ resource: 'gmail', verb: ['write'], action: 'deny', condition: '' }],
    },
  ],
  sampleCalls: [],
}

/** The matrix as the gateway would return it once the override is replayed. */
function overriddenMatrix() {
  return {
    ...MATRIX,
    agents: AGENTS.map((a) => ({
      ...a,
      caps: { ...a.caps, gmail: { ...a.caps.gmail, write: 'deny' } },
    })),
  }
}

interface Harness {
  errors: string[]
  /** Resolves the held-open override POST. */
  releaseOverride: () => void
  /** Body the page sent to `POST /capability/override`. */
  overrideBody: () => Record<string, unknown> | null
}

/**
 * Minimal unsigned JWT. The claim is `scope` (an array), which is what
 * `parseScopesFromJwt` reads; the signature is irrelevant because the dashboard
 * never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5124', scope: scopes })}.`
}

declare global {
  interface Window {
    /** Every `data-decision` value this document has ever carried. */
    __seenDecisions?: string[]
  }
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  let release!: () => void
  const held = new Promise<void>((r) => (release = r))
  let body: Record<string, unknown> | null = null
  const harness: Harness = {
    errors: [],
    releaseOverride: () => release(),
    overrideBody: () => body,
  }

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted sockets are the run's own doing, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', (e) => harness.errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)

      // Record every decision the document ever renders, including one that
      // survives a single frame. This runs before any app module, so nothing
      // the page paints happens outside the observer's view.
      const seen = new Set<string>()
      window.__seenDecisions = []
      const remember = (value: string | null) => {
        if (!value || seen.has(value)) return
        seen.add(value)
        window.__seenDecisions?.push(value)
      }
      const scan = (node: Node) => {
        if (!(node instanceof Element)) return
        remember(node.getAttribute('data-decision'))
        node.querySelectorAll('[data-decision]').forEach((e) => {
          remember(e.getAttribute('data-decision'))
        })
      }
      new MutationObserver((records) => {
        for (const r of records) {
          if (r.type === 'attributes') scan(r.target)
          else r.addedNodes.forEach(scan)
        }
      // The target is `document`, not `documentElement`: this script runs at
      // document-creation time, when the root element does not exist yet.
      }).observe(document, {
        subtree: true,
        childList: true,
        attributes: true,
        attributeFilter: ['data-decision'],
      })
    },
    { themeKey: THEME_KEY, theme, token: makeToken(['read', 'write', 'admin']) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) =>
    r.fulfill({ json: { ticket: 'e2e-5124-ticket' } }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())

  await page.route('**/api/v1/capability/matrix**', (r: Route) =>
    r.fulfill({ json: body === null ? MATRIX : overriddenMatrix() }),
  )

  await page.route('**/api/v1/capability/override', async (r: Route) => {
    body = r.request().postDataJSON()
    // Hold the answer so the assertions can run inside the optimistic window.
    await held
    return r.fulfill({
      json: {
        overrideId: '8b1d2c34-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
        updated: overriddenMatrix().agents,
      },
    })
  })

  return harness
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

/** Decisions the document has carried at any point since it was created. */
function seenDecisions(page: Page): Promise<string[]> {
  return page.evaluate(() => window.__seenDecisions ?? [])
}

const APPLY = 'Record display-only override'

test.describe('AAASM-5124 review — the bulk override writes only on a deliberate, disclosed choice', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`nothing is pre-selected and the write is unreachable until it is — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()

      await page.getByRole('checkbox', { name: 'select all agents' }).check()
      const bar = page.getByRole('region', { name: 'bulk override' })
      await expect(bar).toBeVisible()

      const select = bar.getByLabel('decision')
      const offered = await select.locator('option').evaluateAll((os) =>
        os.map((o) => (o as HTMLOptionElement).value),
      )
      // First regression: `narrow` and `approval` were offered and `narrow` was
      // pre-selected — one click was a guaranteed 400. Second: pre-selecting
      // `deny` instead made that same click a real bulk write.
      expect(offered).toEqual(['', 'allow', 'deny', 'na'])
      for (const rejected of REJECTED_BY_GATEWAY) {
        expect(offered).not.toContain(rejected)
      }
      await expect(select).toHaveValue('')

      const apply = bar.getByRole('button', { name: APPLY })
      await expect(apply).toBeDisabled()
      await expect(apply).toHaveAttribute('title', /select a decision/i)
      await shot(page, `bulk-no-selection-${theme}`)

      // A disabled control cannot be clicked into a request; force the click
      // past the pointer-events guard to prove the handler itself writes nothing.
      await apply.click({ force: true })
      expect(harness.overrideBody()).toBeNull()

      await select.selectOption('deny')
      await expect(apply).toBeEnabled()

      harness.releaseOverride()
      expect(harness.errors).toEqual([])
    })

    test(`the confirmation names the count and the decision, and cancelling writes nothing — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()

      await page.getByRole('checkbox', { name: 'select all agents' }).check()
      const bar = page.getByRole('region', { name: 'bulk override' })
      await bar.getByLabel('decision').selectOption('deny')
      await bar.getByLabel('resource').selectOption('gmail')
      await bar.getByRole('button', { name: APPLY }).click()

      const confirm = bar.getByLabel('confirm override')
      await expect(confirm).toBeVisible()
      await expect(confirm).toContainText('deny')
      await expect(confirm).toContainText('2 agents')
      // AAASM-5178: the disclosure sits at the point of action, not in a footnote.
      await expect(confirm).toContainText(/does not change what the gateway enforces/i)
      await shot(page, `override-confirm-${theme}`)

      // Opening the confirmation is not the write.
      expect(harness.overrideBody()).toBeNull()
      await confirm.getByRole('button', { name: 'Cancel' }).click()
      await expect(confirm).toBeHidden()
      expect(harness.overrideBody()).toBeNull()

      harness.releaseOverride()
      expect(harness.errors).toEqual([])
    })

    test(`the legend keys only the states the projection emits — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()

      const legend = page.getByRole('list', { name: 'decision legend' })
      await expect(legend).toBeVisible()
      expect(
        await legend.locator('.cap-legend-item').evaluateAll((ls) =>
          ls.map((l) => l.textContent?.trim()),
        ),
      ).toEqual(['allow', 'deny', 'n/a'])

      // ADR 0026 Decision 2: neither removed state survives anywhere on the page
      // as a legend entry, a swatch, or a selectable control value.
      await page.getByRole('checkbox', { name: 'select all agents' }).check()
      const decisionOptions = await page
        .getByRole('region', { name: 'bulk override' })
        .getByLabel('decision')
        .locator('option')
        .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))
      for (const removed of REJECTED_BY_GATEWAY) {
        await expect(legend.getByText(removed, { exact: true })).toHaveCount(0)
        await expect(legend.locator(`.cap-legend-sw--${removed}`)).toHaveCount(0)
        expect(decisionOptions).not.toContain(removed)
      }
      await shot(page, `legend-${theme}`)

      harness.releaseOverride()
      expect(harness.errors).toEqual([])
    })

    test(`a confirmed override paints no impossible decision and reports only what changed — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()

      const grid = page.getByRole('grid', { name: 'capability matrix' })
      await expect(grid).toBeVisible()
      // Since AAASM-5125 the page lands on the verb the projection populates
      // most; this fixture ties read/write/delete at four cells each, so it
      // opens on READ (first in VERBS order). This override lane is about the
      // gmail *write* policy (`inbox-scope` denies gmail write), so select WRITE
      // explicitly: gmail is then two allow and pg two deny → two allow cells.
      await page.getByRole('radio', { name: 'write' }).click()
      await expect(grid.locator('.cap-mx-cell[data-decision="allow"]')).toHaveCount(2)

      await page.getByRole('checkbox', { name: 'select all agents' }).check()
      const bar = page.getByRole('region', { name: 'bulk override' })
      await bar.getByLabel('decision').selectOption('deny')
      await bar.getByLabel('resource').selectOption('gmail')
      await bar.getByRole('button', { name: APPLY }).click()
      await bar.getByLabel('confirm override').getByRole('button', { name: 'Confirm' }).click()

      // ── inside the optimistic window ──────────────────────────────────
      // The POST is held open, so the page is showing its pre-answer edit.
      await expect.poll(() => harness.overrideBody() !== null).toBe(true)
      expect(harness.overrideBody()?.decision).toBe('deny')
      await expect(grid.locator('.cap-mx-cell[data-decision="deny"]')).toHaveCount(4)
      for (const rejected of REJECTED_BY_GATEWAY) {
        await expect(grid.locator(`[data-decision="${rejected}"]`)).toHaveCount(0)
      }
      await shot(page, `override-in-flight-${theme}`)

      // ── after the gateway answers and the refetch lands ───────────────
      harness.releaseOverride()
      // AAASM-5178: the report says the annotation landed and says enforcement
      // did not follow it. `override applied to 2 agents` said neither.
      const toast = page.getByText(/display-only override recorded for 2 agents/)
      await expect(toast).toBeVisible()
      await expect(toast).toContainText(/gateway enforcement did not/)
      for (const rejected of REJECTED_BY_GATEWAY) {
        await expect(grid.locator(`[data-decision="${rejected}"]`)).toHaveCount(0)
      }
      await shot(page, `override-settled-${theme}`)

      // ── and at no single frame in between ─────────────────────────────
      const seen = await seenDecisions(page)
      // Proves the optimistic paint happened at all, so the absence below is a
      // real property rather than an artefact of a grid that never changed.
      expect(seen).toContain('deny')
      expect(seen).toContain('allow')
      for (const rejected of REJECTED_BY_GATEWAY) {
        expect(seen).not.toContain(rejected)
      }

      expect(harness.errors).toEqual([])
    })
  }
})
