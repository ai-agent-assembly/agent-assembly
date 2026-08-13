/**
 * The trend, breakdown and offender panels (AAASM-5360).
 *
 * ## Falsification record
 *
 *  - **M-L — collapse the breakdown's two columns.** Delete the
 *    `sd-breakdown-events-*` cell, leaving one "count" column, which is what a
 *    breakdown table normally has. **2 failed, 12 passed (14):**
 *    `renders each group's finding count and action count as separate labelled figures`
 *    and `keeps a group whose two counts differ legible as two numbers`.
 *  - **M-M — render `new` as an increase.** Map `'new'` to `'Up'` in
 *    `TREND_LABELS`. **1 failed, 13 passed (14):**
 *    `distinguishes a first appearance from a rise`. A different mutation from
 *    M-L killing a different test.
 *  - **M-N — offer a forbidden grouping.** Add `'agent_id'` to
 *    `GROUP_BY_DIMENSIONS`. **1 failed, 13 passed (14):**
 *    `offers exactly the six groupings ADR 0032 §9 permits`. Worth having,
 *    because the API's `400` would otherwise be the only thing stopping it and
 *    the operator would meet it as an error rather than as an absent option.
 */
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { BreakdownPanel } from './BreakdownPanel'
import { GROUP_BY_DIMENSIONS } from './dimensions'
import { TopOffendersPanel } from './TopOffendersPanel'
import { TrendPanel } from './TrendPanel'
import { SCOPE, UNMEASURED_COUNTERS, ZERO_COUNTERS } from './__tests__/fixtures'

describe('TrendPanel', () => {
  const series = known({
    scope: SCOPE,
    bucket_seconds: 86_400,
    points: [
      { start_ns: 1_760_000_000_000_000_000, end_ns: 1_760_086_400_000_000_000, counters: ZERO_COUNTERS },
      {
        start_ns: 1_760_086_400_000_000_000,
        end_ns: 1_760_172_800_000_000_000,
        counters: UNMEASURED_COUNTERS,
      },
    ],
  })

  it('renders an empty bucket as an explicit zero in both units, not as a gap in a line', () => {
    render(<TrendPanel timeseries={series} activeFilterCount={0} />)
    // The quiet bucket is a row, and both of its figures carry their unit.
    expect(screen.getByTestId('sd-trend-events-1760000000000000000')).toHaveTextContent('0 actions')
    expect(screen.getByTestId('sd-trend-findings-1760000000000000000')).toHaveTextContent(
      '0 findings',
    )
  })

  it('gives each bucket an action figure and a finding figure that are never the same string', () => {
    render(<TrendPanel timeseries={series} activeFilterCount={0} />)
    const events = screen.getByTestId('sd-trend-events-1760086400000000000')
    const findings = screen.getByTestId('sd-trend-findings-1760086400000000000')
    expect(events).toHaveTextContent('12 actions')
    expect(findings).toHaveTextContent('37 findings')
    expect(events).toHaveAttribute('data-unit', 'event')
    expect(findings).toHaveAttribute('data-unit', 'finding')
  })

  it('states the bucket width rather than leaving the reader to infer it', () => {
    render(<TrendPanel timeseries={series} activeFilterCount={0} />)
    expect(screen.getByTestId('sd-trend')).toHaveTextContent('1 day buckets')
  })

  it('separates an all-zero series from a filtered-out one', () => {
    const quiet = known({
      scope: SCOPE,
      bucket_seconds: 86_400,
      points: [
        { start_ns: 1, end_ns: 2, counters: ZERO_COUNTERS },
      ],
    })
    const { unmount } = render(<TrendPanel timeseries={quiet} activeFilterCount={0} />)
    expect(screen.getByTestId('sd-trend-empty')).toHaveTextContent(
      'No sensitive data recorded in this window',
    )
    unmount()

    render(<TrendPanel timeseries={quiet} activeFilterCount={2} />)
    expect(screen.getByTestId('sd-trend-empty')).toHaveTextContent('No action matched these filters')
  })

  it('draws no series at all when the response could not be read', () => {
    render(<TrendPanel timeseries={absent('unavailable', 'gateway timeout')} activeFilterCount={0} />)
    expect(screen.queryByTestId('sd-trend-table')).toBeNull()
    expect(screen.getByTestId('sd-trend-absent')).toHaveTextContent('The trend could not be read')
  })
})

describe('BreakdownPanel', () => {
  const breakdown = known({
    scope: SCOPE,
    group_by: 'category' as const,
    buckets: [
      { value: 'email_address', finding_count: 24, event_count: 9 },
      { value: 'aws_access_key', finding_count: 13, event_count: 13 },
    ],
  })

  it('offers exactly the six groupings ADR 0032 §9 permits', () => {
    render(
      <BreakdownPanel
        breakdown={breakdown}
        groupBy="category"
        onGroupByChange={vi.fn()}
        activeFilterCount={0}
      />,
    )
    const options = [...screen.getByTestId('sd-breakdown-group-by').querySelectorAll('option')].map(
      (option) => option.getAttribute('value'),
    )
    expect(options).toEqual([
      'category',
      'severity',
      'confidence_band',
      'outcome',
      'detection_method',
      'provider_id',
    ])
    expect(options).toEqual([...GROUP_BY_DIMENSIONS])
    // The forbidden dimensions are absent rather than present-and-rejected.
    for (const forbidden of ['agent_id', 'destination', 'session_id', 'trace_id']) {
      expect(options).not.toContain(forbidden)
    }
  })

  it("renders each group's finding count and action count as separate labelled figures", () => {
    render(
      <BreakdownPanel
        breakdown={breakdown}
        groupBy="category"
        onGroupByChange={vi.fn()}
        activeFilterCount={0}
      />,
    )
    expect(screen.getByTestId('sd-breakdown-findings-email_address')).toHaveTextContent(
      '24 findings',
    )
    expect(screen.getByTestId('sd-breakdown-events-email_address')).toHaveTextContent('9 actions')
  })

  it('keeps a group whose two counts differ legible as two numbers', () => {
    render(
      <BreakdownPanel
        breakdown={breakdown}
        groupBy="category"
        onGroupByChange={vi.fn()}
        activeFilterCount={0}
      />,
    )
    const row = screen.getByTestId('sd-breakdown-row-email_address')
    // 24 findings across 9 actions. A single "count" column would have to drop
    // one of those, and either choice misreports the other.
    expect(row).toHaveTextContent('24 findings')
    expect(row).toHaveTextContent('9 actions')
  })

  it('reports the grouping the server actually used, not the one requested', () => {
    // The response echoes `group_by`; the header reads it back so a server that
    // grouped differently cannot be mislabelled by the control's own state.
    render(
      <BreakdownPanel
        breakdown={known({ ...breakdown.value, group_by: 'severity' as const })}
        groupBy="category"
        onGroupByChange={vi.fn()}
        activeFilterCount={0}
      />,
    )
    expect(screen.getByTestId('sd-breakdown-table')).toHaveTextContent('Severity')
  })

  it('changes grouping through its callback', () => {
    const onGroupByChange = vi.fn()
    render(
      <BreakdownPanel
        breakdown={breakdown}
        groupBy="category"
        onGroupByChange={onGroupByChange}
        activeFilterCount={0}
      />,
    )
    fireEvent.change(screen.getByTestId('sd-breakdown-group-by'), { target: { value: 'severity' } })
    expect(onGroupByChange).toHaveBeenCalledWith('severity')
  })
})

describe('TopOffendersPanel', () => {
  const offenders = known({
    scope: SCOPE,
    comparison_from_ns: 1_759_395_200_000_000_000,
    comparison_to_ns: 1_760_000_000_000_000_000,
    dimension: 'agent',
    entries: [
      {
        key: 'research-bot-04',
        counters: UNMEASURED_COUNTERS,
        previous: ZERO_COUNTERS,
        finding_count_delta: 37,
        trend: 'new' as const,
      },
      {
        key: 'analytics-runner',
        counters: { ...UNMEASURED_COUNTERS, finding_count: 8, event_count: 4 },
        previous: { ...ZERO_COUNTERS, finding_count: 20, event_count: 6 },
        finding_count_delta: -12,
        trend: 'down' as const,
      },
    ],
  })

  const renderOffenders = () =>
    render(
      <TopOffendersPanel
        offenders={offenders}
        dimension="agent"
        onDimensionChange={vi.fn()}
        activeFilterCount={0}
      />,
    )

  it('distinguishes a first appearance from a rise', () => {
    renderOffenders()
    const trend = screen.getByTestId('sd-offender-trend-research-bot-04')
    expect(trend).toHaveAttribute('data-trend', 'new')
    expect(trend).toHaveTextContent('First appearance')
    expect(trend.textContent).not.toContain('Up')
    // ...and says what "first appearance" means rather than showing +37.
    expect(screen.getByTestId('sd-offender-row-research-bot-04')).toHaveTextContent(
      'no findings in the preceding window',
    )
  })

  it('renders a fall as a signed change in findings, with the unit', () => {
    renderOffenders()
    const row = screen.getByTestId('sd-offender-row-analytics-runner')
    expect(row).toHaveTextContent('Down')
    expect(row).toHaveTextContent('−12 findings')
  })

  it('ranks by an agent while saying why that is allowed here and not on the breakdown', () => {
    renderOffenders()
    expect(screen.getByTestId('sd-offenders')).toHaveTextContent(
      'A ranked list over the event store, not a time series',
    )
    expect(screen.getByTestId('sd-offender-findings-research-bot-04')).toHaveTextContent(
      '37 findings',
    )
    expect(screen.getByTestId('sd-offender-events-research-bot-04')).toHaveTextContent('12 actions')
  })

  it('shows no ranking at all when the response could not be read', () => {
    render(
      <TopOffendersPanel
        offenders={absent('unknown', 'entries.0.trend: Invalid option')}
        dimension="agent"
        onDimensionChange={vi.fn()}
        activeFilterCount={0}
      />,
    )
    expect(screen.queryByTestId('sd-offenders-table')).toBeNull()
    expect(screen.getByTestId('sd-offenders-absent')).toHaveTextContent(
      'entries.0.trend: Invalid option',
    )
  })
})
