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
 *     with a 400, and what it pre-selects is a value the endpoint accepts — so
 *     applying without touching the dropdown is a request that can succeed;
 *  2. across the whole override flow — before, during and after the round-trip
 *     — no cell ever carries `narrow` or `approval`. This is recorded by a
 *     `MutationObserver` installed before any app code runs, so a decision that
 *     existed only for one frame is still caught; polling alone could step over
 *     it;
 *  3. the optimistic edit really does run — `deny` is observed on the grid while
 *     the POST is still unanswered — so (2) is a property of what the page can
 *     paint, not of a page that painted nothing;
 *  4. neither theme produces console errors or uncaught exceptions.
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

test.describe('AAASM-5124 review — the bulk override only offers decisions the gateway accepts', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`the decision dropdown offers no guaranteed rejection — ${theme}`, async ({ page }) => {
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
      // The regression: `narrow` and `approval` were both offered, and `narrow`
      // was pre-selected — one click on Apply was a guaranteed 400.
      expect(offered).toEqual(['allow', 'deny', 'na'])
      for (const rejected of REJECTED_BY_GATEWAY) {
        expect(offered).not.toContain(rejected)
      }
      await expect(select).not.toHaveValue('narrow')
      await expect(select).not.toHaveValue('approval')
      expect(offered).toContain(await select.inputValue())

      await shot(page, `bulk-options-${theme}`)
      harness.releaseOverride()
      expect(harness.errors).toEqual([])
    })

    test(`no impossible decision is ever painted during an override — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()

      const grid = page.getByRole('grid', { name: 'capability matrix' })
      await expect(grid).toBeVisible()
      const gmailWrite = grid.locator('.cap-mx-cell[data-decision="allow"]')
      await expect(gmailWrite).toHaveCount(2)

      await page.getByRole('checkbox', { name: 'select all agents' }).check()
      const bar = page.getByRole('region', { name: 'bulk override' })
      await bar.getByLabel('resource').selectOption('gmail')

      // Apply without touching the decision dropdown — the interaction that
      // used to submit `narrow`.
      await bar.getByRole('button', { name: 'Apply override' }).click()

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
      await expect(page.getByText(/override applied to 2 agents/)).toBeVisible()
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
