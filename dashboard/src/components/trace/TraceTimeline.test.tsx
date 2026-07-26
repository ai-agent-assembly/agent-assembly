import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TraceTimeline } from './TraceTimeline'
import { absent, known } from '../../lib/truthfulness'
import type { TraceEvent, TraceSeverity } from '../../features/trace/types'

const NO_FIELD = 'TraceSpan has no such field'

const BASE_EVENT: Omit<TraceEvent, 'id' | 'severity' | 'type'> = {
  timestamp: '2026-04-23T14:23:01Z',
  agent: 'support-agent',
  parentSpanId: null,
  durationMs: known(100),
  decision: absent<string>('not-evaluated', 'no decision recorded'),
  payloadPreview: known('preview text'),
  payload: absent<unknown>('not-supported', NO_FIELD),
  redactedFields: absent<readonly string[]>('not-supported', NO_FIELD),
  violationReason: absent<string>('not-supported', NO_FIELD),
}

const sev = (s: TraceSeverity) => known<TraceSeverity>(s)
const NO_SEVERITY = absent<TraceSeverity>('not-supported', NO_FIELD)

const MIXED_EVENTS: TraceEvent[] = [
  { ...BASE_EVENT, id: 'e1', type: 'PolicyViolation', severity: sev('critical') },
  { ...BASE_EVENT, id: 'e2', type: 'CredentialLeakBlocked', severity: sev('warning') },
  { ...BASE_EVENT, id: 'e3', type: 'ApprovalGranted', severity: sev('info') },
  { ...BASE_EVENT, id: 'e4', type: 'ToolCallIntercepted', severity: NO_SEVERITY },
]

describe('TraceTimeline', () => {
  it('renders one row per event with timestamp, agent, preview, duration', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const rows = screen.getAllByTestId('trace-event')
    expect(rows).toHaveLength(4)
    expect(rows[0]).toHaveTextContent('support-agent')
    expect(rows[0]).toHaveTextContent('preview text')
    expect(rows[0]).toHaveTextContent('100')
  })

  it('reflects severity on each row via data-severity', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const rows = screen.getAllByTestId('trace-event')
    expect(rows[0]).toHaveAttribute('data-severity', 'critical')
    expect(rows[1]).toHaveAttribute('data-severity', 'warning')
    expect(rows[2]).toHaveAttribute('data-severity', 'info')
    // An absent severity is neutral — not a severity of its own.
    expect(rows[3]).toHaveAttribute('data-severity', 'neutral')
  })

  it('exposes the event type on each row via data-event-type', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const rows = screen.getAllByTestId('trace-event')
    expect(rows[0]).toHaveAttribute('data-event-type', 'PolicyViolation')
    expect(rows[1]).toHaveAttribute('data-event-type', 'CredentialLeakBlocked')
  })

  it('renders a compact verdict chip on rows whose operation carries an outcome', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const rows = screen.getAllByTestId('trace-event')
    expect(rows[0].querySelector('[data-testid="verdict-chip"]')).toHaveAttribute('data-verdict', 'denied')
    expect(rows[1].querySelector('[data-testid="verdict-chip"]')).toHaveAttribute('data-verdict', 'denied')
    expect(rows[2].querySelector('[data-testid="verdict-chip"]')).toHaveAttribute('data-verdict', 'allowed')
    // Ratified square corners for the Trace surface (AAASM-5075).
    for (const row of rows.slice(0, 3)) {
      expect(row.querySelector('[data-testid="verdict-chip"]')).toHaveAttribute('data-shape', 'square')
    }
  })

  it('renders an empty <ol> when given no events', () => {
    render(<TraceTimeline events={[]} />)
    expect(screen.getByTestId('trace-timeline')).toBeInTheDocument()
    expect(screen.queryAllByTestId('trace-event')).toHaveLength(0)
  })

  it('shows the violation reason in a tooltip when one was recorded', async () => {
    const events: TraceEvent[] = [
      {
        ...BASE_EVENT,
        id: 'pv',
        type: 'PolicyViolation',
        severity: sev('critical'),
        violationReason: known('refund > $100 requires human approval'),
      },
    ]
    render(<TraceTimeline events={events} />)

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    const row = screen.getByTestId('trace-event')
    await userEvent.hover(row.querySelector('.trace-event__icon-circle')!)
    expect(screen.getByRole('tooltip')).toHaveTextContent('refund > $100 requires human approval')
  })

  it('does not wrap the icon in a tooltip when no reason was recorded', () => {
    const events: TraceEvent[] = [
      { ...BASE_EVENT, id: 'pv-no-reason', type: 'PolicyViolation', severity: sev('critical') },
    ]
    render(<TraceTimeline events={events} />)

    // An empty tooltip on hover would suggest a reason exists and is blank.
    expect(screen.getByTestId('trace-event').querySelector('.tooltip-wrapper')).toBeNull()
  })

  it('truncates payloadPreview to 500 characters with an ellipsis when longer', () => {
    const longText = 'x'.repeat(750)
    const events: TraceEvent[] = [
      {
        ...BASE_EVENT,
        id: 'long',
        type: 'ToolCallIntercepted',
        severity: sev('info'),
        payloadPreview: known(longText),
      },
    ]
    render(<TraceTimeline events={events} />)

    const preview = screen.getByTestId('trace-event-detail')
    expect(preview.textContent).toHaveLength(501)
    expect(preview.textContent?.endsWith('…')).toBe(true)
    expect(preview.textContent?.slice(0, 500)).toBe('x'.repeat(500))
  })

  it('leaves payloadPreview untouched when it is ≤ 500 chars', () => {
    const exactlyFiveHundred = 'y'.repeat(500)
    const events: TraceEvent[] = [
      {
        ...BASE_EVENT,
        id: 'edge',
        type: 'ToolCallIntercepted',
        severity: sev('info'),
        payloadPreview: known(exactlyFiveHundred),
      },
    ]
    render(<TraceTimeline events={events} />)

    expect(screen.getByTestId('trace-event-detail').textContent).toBe(exactlyFiveHundred)
  })

  it('does not assign clickable role/tabIndex when onSelectEvent is omitted', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const row = screen.getAllByTestId('trace-event')[0]
    expect(row).not.toHaveAttribute('role')
    expect(row).not.toHaveAttribute('tabindex')
    expect(row.className).not.toContain('trace-event--clickable')
  })

  it('renders rows as buttons and fires onSelectEvent on click + Enter/Space', async () => {
    const onSelect = vi.fn()
    render(<TraceTimeline events={[MIXED_EVENTS[0]]} onSelectEvent={onSelect} />)

    const row = screen.getByTestId('trace-event')
    expect(row).toHaveAttribute('role', 'button')
    expect(row).toHaveAttribute('tabindex', '0')
    expect(row.className).toContain('trace-event--clickable')

    await userEvent.click(row)
    expect(onSelect).toHaveBeenLastCalledWith(MIXED_EVENTS[0])

    row.focus()
    await userEvent.keyboard('{Enter}')
    expect(onSelect).toHaveBeenCalledTimes(2)
    await userEvent.keyboard(' ')
    expect(onSelect).toHaveBeenCalledTimes(3)
  })
})

/**
 * AAASM-5165. `{event.durationMs} ms` was interpolated unguarded, so an absent
 * duration rendered `null ms` and a derived one `NaN ms`. After AAASM-5109 the
 * wire's `end_time` is null on every reconstructed span, making the absent case
 * the one an operator actually sees.
 */
describe('a duration the gateway never measured', () => {
  const unmeasured: TraceEvent = {
    ...BASE_EVENT,
    id: 'no-duration',
    type: 'ToolCallIntercepted',
    severity: NO_SEVERITY,
    durationMs: absent<number>('unknown', 'This span recorded no end time'),
  }

  it('renders the shared absence rather than the word null', () => {
    render(<TraceTimeline events={[unmeasured]} />)

    const cell = screen.getByTestId('trace-event-duration')
    expect(cell).toHaveAttribute('data-truth-state', 'unknown')
    expect(cell).toHaveTextContent('—')
    expect(cell.textContent).not.toContain('null')
    expect(cell.textContent).not.toContain('NaN')
  })

  it('puts no "null ms" or "NaN ms" anywhere in the row', () => {
    render(<TraceTimeline events={[unmeasured]} />)

    const row = screen.getByTestId('trace-event').textContent ?? ''
    expect(row).not.toContain('null')
    expect(row).not.toContain('NaN')
    expect(row).not.toContain('undefined')
  })

  it('still prints a duration that was measured', () => {
    // The guard must not swallow real measurements — including a real zero.
    render(
      <TraceTimeline
        events={[{ ...unmeasured, id: 'zero', durationMs: known(0) }]}
      />,
    )
    const cell = screen.getByTestId('trace-event-duration')
    expect(cell).toHaveAttribute('data-truth-state', 'known')
    expect(cell).toHaveTextContent('0 ms')
  })
})

describe('an operation with no recorded verdict', () => {
  it('shows an absence marker instead of a fabricated ALLOWED chip', () => {
    // The old deriver defaulted to `allowed`, so an unruled span wore a green
    // ✓ ALLOWED chip — a governance claim the response never made.
    render(
      <TraceTimeline
        events={[
          {
            ...BASE_EVENT,
            id: 'unruled',
            type: 'ToolCallIntercepted',
            severity: NO_SEVERITY,
          },
        ]}
      />,
    )

    expect(screen.queryByTestId('verdict-chip')).not.toBeInTheDocument()
    const marker = screen.getByTestId('trace-event-verdict-absent')
    expect(marker).toHaveAttribute('data-truth-state', 'not-evaluated')
    expect(screen.getByTestId('trace-event').textContent).not.toContain('ALLOWED')
  })
})
