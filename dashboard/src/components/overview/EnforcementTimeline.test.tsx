import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { EnforcementTimeline } from './EnforcementTimeline'
import type { EnforcementTimeline as EnforcementTimelineData } from '../../features/overview/api'

function makeData(overrides: Partial<EnforcementTimelineData> = {}): EnforcementTimelineData {
  return {
    window: '24h',
    bucketSecs: 3600,
    buckets: [
      { ts: 1_700_000_000_000, allow: 10, narrow: 4, deny: 2, scrub: 5 },
      { ts: 1_700_003_600_000, allow: 8, narrow: 0, deny: 1, scrub: 3 },
      { ts: 1_700_007_200_000, allow: 12, narrow: 6, deny: 0, scrub: 2 },
      { ts: 1_700_010_800_000, allow: 6, narrow: 2, deny: 3, scrub: 1 },
    ],
    ...overrides,
  }
}

const base = { window: '24h', isLoading: false, isError: false } as const

describe('EnforcementTimeline', () => {
  it('renders the header window and a legend for every verdict lane', () => {
    render(<EnforcementTimeline {...base} data={makeData()} />)
    expect(screen.getByText(/enforcement timeline · 24h/i)).toBeInTheDocument()
    for (const lane of ['allow', 'narrow', 'deny', 'scrub']) {
      expect(screen.getByText(`● ${lane}`)).toBeInTheDocument()
    }
  })

  it('draws one mini bar per lane per bucket for a populated window', () => {
    const { container } = render(<EnforcementTimeline {...base} data={makeData()} />)
    expect(screen.getByTestId('overview-enforcement-timeline-chart')).toBeInTheDocument()
    // 4 lanes, each an <svg> of 4 <rect> bars = 16 bars.
    expect(container.querySelectorAll('svg.etl-bar')).toHaveLength(4)
    expect(container.querySelectorAll('svg.etl-bar rect')).toHaveLength(16)
    // Time axis ends with the "now" tick.
    expect(screen.getByText('now')).toBeInTheDocument()
  })

  it('colours bars with theme tokens, never literal hex', () => {
    const { container } = render(<EnforcementTimeline {...base} data={makeData()} />)
    const fills = [...container.querySelectorAll('svg.etl-bar rect')].map((r) => r.getAttribute('fill'))
    expect(fills.every((f) => f?.startsWith('var(--'))).toBe(true)
  })

  it('shows an empty note when there are no buckets', () => {
    render(<EnforcementTimeline {...base} data={makeData({ buckets: [] })} />)
    expect(screen.getByTestId('overview-enforcement-timeline-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('overview-enforcement-timeline-chart')).not.toBeInTheDocument()
  })

  it('treats an all-zero window as empty rather than drawing flat bars', () => {
    const zeros = makeData({
      buckets: [{ ts: 1_700_000_000_000, allow: 0, narrow: 0, deny: 0, scrub: 0 }],
    })
    render(<EnforcementTimeline {...base} data={zeros} />)
    expect(screen.getByTestId('overview-enforcement-timeline-empty')).toBeInTheDocument()
  })

  it('renders a loading state while the query is in flight', () => {
    render(<EnforcementTimeline {...base} data={undefined} isLoading />)
    expect(screen.getByTestId('overview-enforcement-timeline-loading')).toBeInTheDocument()
  })

  it('renders an error state when the query fails', () => {
    render(<EnforcementTimeline {...base} data={undefined} isError />)
    expect(screen.getByTestId('overview-enforcement-timeline-error')).toBeInTheDocument()
  })

  it('formats axis ticks as dates for multi-day windows', () => {
    render(<EnforcementTimeline {...base} window="7d" data={makeData({ window: '7d' })} />)
    // A date-formatted tick (contains a slash) proves the 7d/30d branch ran.
    expect(screen.getAllByText(/\d+\/\d+/).length).toBeGreaterThan(0)
  })
})
