/**
 * The Scrub page's truthfulness contract (AAASM-5112 / AAASM-5156 / AAASM-5347).
 *
 * Two headline assertions, pulling in opposite directions, and the page has to
 * satisfy both:
 *
 *  - **Nothing unmeasured is announced.** A screen-reader user was once told, as
 *    live status, that there had been `0 leaks (30d)` on a surface that measured
 *    no such thing. These tests fail if any all-clear — or any removed literal —
 *    reaches the live region again.
 *  - **Nothing measured is withheld.** The page also spent a release declining to
 *    answer questions `/scrub/patterns`, `/scrub/pattern-counts` and
 *    `/scrub/posture` can answer, and justifying the refusal with the claim that
 *    those routes did not exist. These tests fail if it goes back to that.
 *
 * The queries are driven through a mocked `api.GET` rather than mocked hooks, so
 * the fold from HTTP outcome to rendered text is exercised end to end, and the
 * four states — loading, empty, populated, error — are produced by four
 * different HTTP outcomes rather than by four different props.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ReactElement } from 'react'
import { ScrubPage } from './ScrubPage'
import { ToastProvider } from '../components/ToastProvider'

const getMock = vi.fn()

vi.mock('../api/client', () => ({
  api: {
    GET: (...args: unknown[]) => getMock(...args),
  },
}))

/** Every literal AAASM-5112 removed, in the forms a regression would take. */
const FABRICATIONS = [
  '0 leaks',
  'leaks (30d)',
  'P-100',
  'default-allow with scrub',
  'http egress',
  'gmail',
  '192 stripped',
]

const CATALOGUE = {
  patterns: [
    {
      kind: 'AwsAccessKey',
      redaction_label: '[REDACTED:AwsAccessKey]',
      category: 'api_key',
      severity: 'critical',
      builtin: true,
    },
    {
      kind: 'EmailAddress',
      redaction_label: '[REDACTED:EmailAddress]',
      category: 'pii',
      severity: 'low',
      builtin: true,
    },
    {
      kind: 'SsnPattern',
      redaction_label: '[REDACTED:SsnPattern]',
      category: 'pii',
      severity: 'critical',
      builtin: true,
    },
  ],
  total: 3,
}

const EMPTY_COUNTS = { counts: [], total_hits: 0, window_seconds: 86_400 }
const EMPTY_POSTURE = {
  leaks_intercepted: 0,
  distinct_kinds: 0,
  rate_computed: false,
  window_seconds: 2_592_000,
}

/**
 * Route each mocked `api.GET` by path.
 *
 * `undefined` for a path means "answer it the way an idle install would", which
 * is what makes the *empty* state the default and keeps every other test honest
 * about which figures it actually supplied.
 */
const routeGet = (over: Partial<Record<string, { data?: unknown; error?: unknown }>> = {}) => {
  getMock.mockImplementation((path: string) => {
    if (path in over) return Promise.resolve(over[path])
    switch (path) {
      case '/api/v1/scrub/patterns':
        return Promise.resolve({ data: CATALOGUE, error: undefined })
      case '/api/v1/scrub/pattern-counts':
        return Promise.resolve({ data: EMPTY_COUNTS, error: undefined })
      case '/api/v1/scrub/posture':
        return Promise.resolve({ data: EMPTY_POSTURE, error: undefined })
      default:
        return Promise.resolve({ data: [], error: undefined })
    }
  })
}

const renderPage = (ui: ReactElement = <ScrubPage />) =>
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      {ui}
    </QueryClientProvider>,
  )

/** Wait for the catalogue to arrive so the page leaves its loading state. */
const renderLoaded = async (ui?: ReactElement) => {
  const result = renderPage(ui)
  await screen.findByTestId('scrub-patterns')
  return result
}

const liveRegion = () => screen.getByTestId('scrub-stats-measured')

beforeEach(() => {
  getMock.mockReset()
  routeGet()
})

describe('ScrubPage — the four states', () => {
  it('renders the loading skeleton while the catalogue is in flight', () => {
    renderPage()
    expect(screen.getByTestId('scrub-page')).toBeInTheDocument()
    expect(screen.queryByTestId('scrub-patterns')).toBeNull()
    expect(document.querySelector('.state-page')).toBeInTheDocument()
  })

  it('renders the retry panel when the catalogue request fails', async () => {
    routeGet({ '/api/v1/scrub/patterns': { data: undefined, error: { message: 'boom' } } })
    renderPage()
    await screen.findByTestId('error-state-generic')
    expect(screen.queryByTestId('scrub-patterns')).toBeNull()
  })

  it('renders an absence — not a retry panel — for a 200 carrying no detectors', async () => {
    // Nothing failed, so there is nothing to retry; offering a retry button
    // would misdescribe an impossible catalogue as a transient outage.
    routeGet({ '/api/v1/scrub/patterns': { data: { patterns: [], total: 0 }, error: undefined } })
    renderPage()
    const marker = await screen.findByTestId('scrub-catalogue-absent-marker')
    expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    expect(screen.queryByTestId('error-state-generic')).toBeNull()
  })

  it('renders the catalogue, and empty windows as absences, on an idle install', async () => {
    await renderLoaded()
    // The catalogue is populated even though both windows are empty: the routes
    // are independent, and one empty aggregation must not blank the other.
    expect(screen.getByTestId('scrub-patterns-row-AwsAccessKey')).toBeInTheDocument()
    expect(screen.getByTestId('scrub-stats-intercepted-value')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
    expect(screen.getByTestId('scrub-patterns-hits-AwsAccessKey')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
  })

  it('renders the measured figures when both windows report activity', async () => {
    routeGet({
      '/api/v1/scrub/pattern-counts': {
        data: {
          counts: [
            { kind: 'AwsAccessKey', hits: 4 },
            { kind: 'SsnPattern', hits: 1 },
          ],
          total_hits: 5,
          window_seconds: 86_400,
        },
        error: undefined,
      },
      '/api/v1/scrub/posture': {
        data: {
          leaks_intercepted: 5,
          distinct_kinds: 2,
          rate_computed: false,
          window_seconds: 2_592_000,
        },
        error: undefined,
      },
    })
    await renderLoaded()
    expect(screen.getByTestId('scrub-stats-intercepted-value')).toHaveTextContent('5')
    expect(screen.getByTestId('scrub-stats-kinds-value')).toHaveTextContent('2')
    expect(screen.getByTestId('scrub-patterns-hits-AwsAccessKey')).toHaveTextContent('4')
    // A kind a populated tally omits contributed no alert — a real zero.
    expect(screen.getByTestId('scrub-patterns-hits-EmailAddress')).toHaveTextContent('0')
  })
})

describe('ScrubPage — the aria-live region', () => {
  it('is the only live region on the page, and holds only fetched figures', async () => {
    await renderLoaded()
    const live = document.querySelectorAll('[aria-live]')
    expect(live).toHaveLength(1)
    expect(live[0]).toBe(liveRegion())
    expect(liveRegion()).toHaveTextContent('redactions / 24h')
    expect(liveRegion()).toHaveTextContent('leaks intercepted')
    // The unsourced statements must stay outside it: announcing "the API cannot
    // answer this" as a status update is how the all-clear reached assistive
    // tech in the first place.
    for (const testId of [
      'scrub-stats-posture',
      'scrub-stats-covers',
      'scrub-stats-policy',
      'scrub-stats-rate',
    ]) {
      expect(liveRegion()).not.toContainElement(screen.getByTestId(testId))
    }
  })

  it('never announces an unmeasured all-clear', async () => {
    await renderLoaded()
    const announced = liveRegion().textContent ?? ''
    for (const fabrication of FABRICATIONS) {
      expect(announced).not.toContain(fabrication)
    }
    // Nor any of the affirmative words the standing rule names.
    expect(announced).not.toMatch(/\b(safe|healthy|verified|clean|secure|all clear)\b/i)
  })

  it('announces "Unavailable" — not a number — when a fetch fails', async () => {
    routeGet({
      '/api/v1/analytics/agent-enforcement': { data: undefined, error: { message: 'boom' } },
      '/api/v1/scrub/posture': { data: undefined, error: { message: 'boom' } },
    })
    await renderLoaded()
    await waitFor(() =>
      expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      ),
    )
    const value = screen.getByTestId('scrub-stats-stripped-value')
    expect(value).toHaveTextContent('—')
    expect(value.querySelector('.truth-absent__glyph')?.textContent).toBe('—')
    expect(value).toHaveTextContent('the request for this value failed')
    expect(screen.getByTestId('scrub-stats-intercepted-value')).toHaveAttribute(
      'data-truth-state',
      'unavailable',
    )
  })

  it('announces "Unknown" for an empty response rather than reporting zero', async () => {
    await renderLoaded()
    await waitFor(() =>
      expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveAttribute(
        'data-truth-state',
        'unknown',
      ),
    )
    expect(liveRegion()).not.toHaveTextContent('0 redactions')
    expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveTextContent(
      'could not be determined',
    )
  })

  it('announces the real fleet total when the API reports one', async () => {
    routeGet({
      '/api/v1/analytics/agent-enforcement': {
        data: [
          { agent_id: 'a1', blocked: 2, scrubbed: 5 },
          { agent_id: 'a2', blocked: 0, scrubbed: 4 },
        ],
        error: undefined,
      },
    })
    await renderLoaded()
    await waitFor(() =>
      expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveAttribute(
        'data-truth-state',
        'known',
      ),
    )
    expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveTextContent('9')
  })

  it('asks each route for the window it states', async () => {
    await renderLoaded()
    expect(getMock).toHaveBeenCalledWith('/api/v1/analytics/agent-enforcement', {
      params: { query: { window: '24h' } },
    })
    expect(getMock).toHaveBeenCalledWith('/api/v1/scrub/pattern-counts', {
      params: { query: { range: '24h' } },
    })
    expect(getMock).toHaveBeenCalledWith('/api/v1/scrub/posture', {
      params: { query: { range: '30d' } },
    })
    // The catalogue is not tenant- or window-specific, so it takes no range.
    expect(getMock).toHaveBeenCalledWith('/api/v1/scrub/patterns')
  })
})

describe('ScrubPage — the stat strip', () => {
  it('keeps the values no route sources as explicit absences', async () => {
    await renderLoaded()
    for (const testId of [
      'scrub-stats-posture-value',
      'scrub-stats-covers-value',
      'scrub-stats-policy-value',
      'scrub-stats-running-value',
      'scrub-stats-rate-value',
    ]) {
      const el = screen.getByTestId(testId)
      expect(el).toHaveAttribute('data-truth-state', 'not-supported')
      expect(el).toHaveTextContent('—')
    }
  })

  it('distinguishes leaks intercepted from leaks escaped', async () => {
    // The posture route counts payloads the scanner *caught*. Reporting that as
    // "leak posture" would answer the opposite question — and a zero would then
    // read as an all-clear nothing measured.
    await renderLoaded()
    expect(screen.getByTestId('scrub-stats-intercepted')).toHaveTextContent('leaks intercepted')
    expect(screen.getByTestId('scrub-stats-posture')).toHaveTextContent('escaped-leak posture')
    expect(screen.getByTestId('scrub-stats-posture-value')).toHaveAttribute(
      'data-truth-state',
      'not-supported',
    )
  })

  it('states the posture window the server reported', async () => {
    await renderLoaded()
    expect(screen.getByTestId('scrub-stats-posture-window')).toHaveTextContent('30d')
  })

  it('contains none of the removed literals anywhere on the page', async () => {
    await renderLoaded()
    const page = screen.getByTestId('scrub-page').textContent ?? ''
    for (const fabrication of FABRICATIONS) {
      expect(page, `"${fabrication}" must not reappear`).not.toContain(fabrication)
    }
  })

  it('counts detectors from the served catalogue rather than an "enabled" tally', async () => {
    await renderLoaded()
    expect(screen.getByTestId('scrub-stats-detectors')).toHaveTextContent('3 detectors served')
    expect(screen.getByTestId('scrub-stats-detectors')).not.toHaveTextContent('enabled')
  })

  it('describes the catalogue in the sub-header without claiming any are active', async () => {
    await renderLoaded()
    const sub = screen.getByTestId('scrub-page-sub')
    expect(sub).toHaveTextContent('3 built-in detectors')
    expect(sub).not.toHaveTextContent(/patterns active/)
    expect(sub).not.toHaveTextContent(/hits today/)
  })
})

describe('ScrubPage — no raw sensitive value reaches the DOM', () => {
  it('renders only kinds, labels and counts from the scrub responses', async () => {
    routeGet({
      '/api/v1/scrub/pattern-counts': {
        data: {
          counts: [{ kind: 'AwsAccessKey', hits: 4 }],
          total_hits: 4,
          window_seconds: 86_400,
        },
        error: undefined,
      },
    })
    await renderLoaded()
    // Scoped to the API-fed regions on purpose. The payload editor below them is
    // *operator input* — it is seeded with documentation placeholders precisely
    // so the local preview has something to redact — so sweeping the whole page
    // would assert against the wrong thing and fail on a fixture that is
    // supposed to look like a credential.
    const apiFed = [
      screen.getByTestId('scrub-stats-measured'),
      screen.getByTestId('scrub-patterns'),
      screen.getByTestId('scrub-detail'),
    ]
      .map((el) => el.textContent ?? '')
      .join('\n')
    // None of the three scrub responses carries a detected value at all — the
    // alert store persists only `redacted_value` — so a credential-shaped
    // literal in these regions could only have come from the page itself.
    expect(apiFed).not.toMatch(/AKIA[0-9A-Z]{8,}/)
    expect(apiFed).not.toMatch(/sk-ant-[A-Za-z0-9_-]{8,}/)
    expect(apiFed).not.toMatch(/ghp_[A-Za-z0-9_]{8,}/)
    expect(apiFed).not.toMatch(/[0-9]{3}-[0-9]{2}-[0-9]{4}/)
    // The redaction label is what the surface teaches instead.
    expect(apiFed).toContain('[REDACTED:AwsAccessKey]')
  })
})

describe('ScrubPage — actions with no production path', () => {
  it('disables export config, which no endpoint can serve completely', async () => {
    await renderLoaded()
    expect(screen.getByTestId('scrub-export-config')).toBeDisabled()
  })

  it('keeps the add-pattern affordance, which routes to the real authoring surface', async () => {
    await renderLoaded(
      <ToastProvider>
        <ScrubPage />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByTestId('scrub-add-pattern'))
    // By test id, not by text: the catalogue note names the same authoring
    // surface, so matching on the phrase would find two elements.
    expect(screen.getByTestId('toast')).toHaveTextContent(/data.sensitive_patterns/)
  })

  it('never claims a detector was tested against traffic', async () => {
    await renderLoaded(
      <ToastProvider>
        <ScrubPage />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByTestId('scrub-detail-test'))
    expect(screen.queryByText(/Tested .* against the last 24h of traffic/)).toBeNull()
    expect(screen.queryByTestId('toast')).toBeNull()
  })

  it('no-ops rather than throwing when rendered outside a ToastProvider', async () => {
    await renderLoaded()
    fireEvent.click(screen.getByTestId('scrub-add-pattern'))
    fireEvent.click(screen.getByTestId('scrub-detail-edit'))
    expect(screen.queryByTestId('toast')).toBeNull()
    expect(screen.getByTestId('scrub-page')).toBeInTheDocument()
  })
})

describe('ScrubPage — catalogue interaction', () => {
  it('selects the first served detector by default', async () => {
    await renderLoaded()
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent('AwsAccessKey')
  })

  it('selecting a different detector updates the detail panel', async () => {
    await renderLoaded()
    fireEvent.click(screen.getByTestId('scrub-patterns-row-SsnPattern'))
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent('SsnPattern')
    expect(screen.getByTestId('scrub-detail-replace')).toHaveTextContent('[REDACTED:SsnPattern]')
  })

  it('collapsing the detail panel flips its data-collapsed flag', async () => {
    await renderLoaded()
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'false')
    fireEvent.click(screen.getByTestId('scrub-detail-collapse'))
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'true')
  })

  it('offers no way to toggle a detector on or off', async () => {
    await renderLoaded()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
  })
})
