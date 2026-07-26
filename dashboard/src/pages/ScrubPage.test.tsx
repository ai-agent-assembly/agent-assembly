/**
 * The Scrub page's truthfulness contract (AAASM-5112 / AAASM-5156).
 *
 * The headline assertion is the `aria-live` one: a screen-reader user was being
 * told, as live status, that there had been `0 leaks (30d)` on a surface that
 * measures no such thing. These tests fail if any all-clear — or any of the
 * removed literals — reaches that region again.
 *
 * The query is driven through a mocked `api.GET` rather than a mocked hook, so
 * the fold from HTTP outcome to rendered text is exercised end to end.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ReactElement } from 'react'
import { ScrubPage } from './ScrubPage'
import { ToastProvider } from '../components/ToastProvider'
import { BUILT_IN_DETECTORS, COMPILED_IN_DETECTORS } from '../features/scrub/detectors'

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
  'slack',
  '192 stripped',
]

const renderPage = (ui: ReactElement = <ScrubPage />) =>
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      {ui}
    </QueryClientProvider>,
  )

const liveRegion = () => screen.getByTestId('scrub-stats-stripped')

beforeEach(() => {
  getMock.mockReset()
  getMock.mockResolvedValue({ data: [], error: undefined })
})

describe('ScrubPage — the aria-live region', () => {
  it('is the only live region on the page, and holds only the fetched figure', () => {
    renderPage()
    const live = document.querySelectorAll('[aria-live]')
    expect(live).toHaveLength(1)
    expect(live[0]).toBe(liveRegion())
    expect(liveRegion()).toHaveTextContent('redactions / 24h')
  })

  it('never announces an unmeasured all-clear', async () => {
    renderPage()
    await waitFor(() => expect(getMock).toHaveBeenCalled())
    const announced = liveRegion().textContent ?? ''
    for (const fabrication of FABRICATIONS) {
      expect(announced).not.toContain(fabrication)
    }
    // Nor any of the affirmative words the standing rule names.
    expect(announced).not.toMatch(/\b(safe|healthy|verified|clean|secure|all clear)\b/i)
  })

  it('announces "Unavailable" — not a number — when the request fails', async () => {
    getMock.mockResolvedValue({ data: undefined, error: { message: 'boom' } })
    renderPage()
    // Re-query inside waitFor: the marker element is replaced, not mutated,
    // when the query settles, so a captured node would go stale.
    await waitFor(() =>
      expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      ),
    )
    const value = screen.getByTestId('scrub-stats-stripped-value')
    expect(value).toHaveTextContent('—')
    // The absence itself carries no digit — no count survives the failure.
    expect(value.querySelector('.truth-absent__glyph')?.textContent).toBe('—')
    expect(value).toHaveTextContent('the request for this value failed')
  })

  it('announces "Unknown" for an empty response rather than reporting zero', async () => {
    getMock.mockResolvedValue({ data: [], error: undefined })
    renderPage()
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
    getMock.mockResolvedValue({
      data: [
        { agent_id: 'a1', blocked: 2, scrubbed: 5 },
        { agent_id: 'a2', blocked: 0, scrubbed: 4 },
      ],
      error: undefined,
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveAttribute(
        'data-truth-state',
        'known',
      ),
    )
    expect(screen.getByTestId('scrub-stats-stripped-value')).toHaveTextContent('9')
  })

  it('asks the agent-enforcement route for a 24h window', async () => {
    renderPage()
    await waitFor(() => expect(getMock).toHaveBeenCalled())
    expect(getMock).toHaveBeenCalledWith('/api/v1/analytics/agent-enforcement', {
      params: { query: { window: '24h' } },
    })
  })
})

describe('ScrubPage — the stat strip', () => {
  it('renders posture, coverage, policy and runtime state as explicit absences', () => {
    renderPage()
    for (const testId of [
      'scrub-stats-posture-value',
      'scrub-stats-covers-value',
      'scrub-stats-policy-value',
      'scrub-stats-running-value',
    ]) {
      const el = screen.getByTestId(testId)
      expect(el).toHaveAttribute('data-truth-state', 'not-supported')
      expect(el).toHaveTextContent('—')
    }
  })

  it('contains none of the removed literals anywhere on the page', async () => {
    renderPage()
    await waitFor(() => expect(getMock).toHaveBeenCalled())
    const page = screen.getByTestId('scrub-page').textContent ?? ''
    for (const fabrication of FABRICATIONS) {
      expect(page, `"${fabrication}" must not reappear`).not.toContain(fabrication)
    }
  })

  it('counts detectors from the shipped catalogue rather than an "enabled" tally', () => {
    renderPage()
    expect(screen.getByTestId('scrub-stats-detectors')).toHaveTextContent(
      `${COMPILED_IN_DETECTORS.length} detectors shipped`,
    )
    expect(screen.getByTestId('scrub-stats-detectors')).not.toHaveTextContent('enabled')
  })

  it('describes the catalogue in the sub-header without claiming any are active', () => {
    renderPage()
    const sub = screen.getByTestId('scrub-page-sub')
    expect(sub).toHaveTextContent(`${COMPILED_IN_DETECTORS.length} detectors ship`)
    expect(sub).not.toHaveTextContent(/patterns active/)
    expect(sub).not.toHaveTextContent(/hits today/)
  })
})

describe('ScrubPage — actions with no production path', () => {
  it('disables export config, which has no configuration endpoint to read', () => {
    renderPage()
    expect(screen.getByTestId('scrub-export-config')).toBeDisabled()
  })

  it('keeps the add-pattern affordance, which routes to the real authoring surface', () => {
    renderPage(
      <ToastProvider>
        <ScrubPage />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByTestId('scrub-add-pattern'))
    expect(screen.getByText(/data.sensitive_patterns/)).toBeInTheDocument()
  })

  it('never claims a detector was tested against traffic', () => {
    renderPage(
      <ToastProvider>
        <ScrubPage />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByTestId('scrub-detail-test'))
    expect(screen.queryByText(/Tested .* against the last 24h of traffic/)).toBeNull()
    expect(screen.queryByTestId('toast')).toBeNull()
  })

  it('no-ops rather than throwing when rendered outside a ToastProvider', () => {
    renderPage()
    fireEvent.click(screen.getByTestId('scrub-add-pattern'))
    fireEvent.click(screen.getByTestId('scrub-detail-edit'))
    expect(screen.queryByTestId('toast')).toBeNull()
    expect(screen.getByTestId('scrub-page')).toBeInTheDocument()
  })
})

describe('ScrubPage — catalogue interaction', () => {
  it('selects the first shipped detector by default', () => {
    renderPage()
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent(BUILT_IN_DETECTORS[0].name)
  })

  it('selecting a different detector updates the detail panel', () => {
    renderPage()
    const target = BUILT_IN_DETECTORS.find((d) => d.id === 'SsnPattern')!
    fireEvent.click(screen.getByTestId(`scrub-patterns-row-${target.id}`))
    expect(screen.getByTestId('scrub-detail')).toHaveTextContent(target.name)
    expect(screen.getByTestId('scrub-detail-replace')).toHaveTextContent('[REDACTED:SsnPattern]')
  })

  it('collapsing the detail panel flips its data-collapsed flag', () => {
    renderPage()
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'false')
    fireEvent.click(screen.getByTestId('scrub-detail-collapse'))
    expect(screen.getByTestId('scrub-detail')).toHaveAttribute('data-collapsed', 'true')
  })

  it('offers no way to toggle a detector on or off', () => {
    renderPage()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
  })
})
