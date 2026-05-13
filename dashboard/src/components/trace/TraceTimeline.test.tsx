import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TraceTimeline } from './TraceTimeline'
import type { TraceEvent } from '../../features/trace/types'

const BASE_EVENT: Omit<TraceEvent, 'id' | 'severity' | 'type'> = {
  timestamp: '2026-04-23T14:23:01Z',
  agent: 'support-agent',
  durationMs: 100,
  payloadPreview: 'preview text',
  payload: {},
}

const MIXED_EVENTS: TraceEvent[] = [
  { ...BASE_EVENT, id: 'e1', type: 'policy_violation', severity: 'critical' },
  { ...BASE_EVENT, id: 'e2', type: 'credential_leak', severity: 'warning' },
  { ...BASE_EVENT, id: 'e3', type: 'llm_call', severity: 'info' },
  { ...BASE_EVENT, id: 'e4', type: 'tool_call' },
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
    expect(rows[3]).toHaveAttribute('data-severity', 'neutral')
  })

  it('exposes the event type on each row via data-event-type', () => {
    render(<TraceTimeline events={MIXED_EVENTS} />)
    const rows = screen.getAllByTestId('trace-event')
    expect(rows[0]).toHaveAttribute('data-event-type', 'policy_violation')
    expect(rows[1]).toHaveAttribute('data-event-type', 'credential_leak')
  })

  it('renders an empty <ol> when given no events', () => {
    render(<TraceTimeline events={[]} />)
    expect(screen.getByTestId('trace-timeline')).toBeInTheDocument()
    expect(screen.queryAllByTestId('trace-event')).toHaveLength(0)
  })

  it('shows the violation reason in a tooltip on policy_violation rows when hovered', async () => {
    const events: TraceEvent[] = [
      {
        ...BASE_EVENT,
        id: 'pv',
        type: 'policy_violation',
        severity: 'critical',
        violationReason: 'refund > $100 requires human approval',
      },
    ]
    render(<TraceTimeline events={events} />)

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    const row = screen.getByTestId('trace-event')
    await userEvent.hover(row.querySelector('.trace-event__icon')!)
    expect(screen.getByRole('tooltip')).toHaveTextContent('refund > $100 requires human approval')
  })

  it('does not wrap the icon in a tooltip when violationReason is missing', () => {
    const events: TraceEvent[] = [
      { ...BASE_EVENT, id: 'pv-no-reason', type: 'policy_violation', severity: 'critical' },
    ]
    render(<TraceTimeline events={events} />)

    const row = screen.getByTestId('trace-event')
    expect(row.querySelector('.tooltip-wrapper')).toBeNull()
  })

  it('does not wrap non-violation events in a tooltip even with violationReason set', () => {
    const events: TraceEvent[] = [
      // Defensive: violationReason set but type isn't a policy violation — should be ignored
      { ...BASE_EVENT, id: 'llm', type: 'llm_call', severity: 'info', violationReason: 'noise' },
    ]
    render(<TraceTimeline events={events} />)

    const row = screen.getByTestId('trace-event')
    expect(row.querySelector('.tooltip-wrapper')).toBeNull()
  })

  it('flags credential leak events for the warning tone via data-event-type', () => {
    const events: TraceEvent[] = [
      { ...BASE_EVENT, id: 'cl', type: 'credential_leak', severity: 'info' },
    ]
    render(<TraceTimeline events={events} />)

    // The CSS rule keys off data-event-type to override the severity background
    // (severity stays on data-severity so the filter can still find/hide the row).
    const row = screen.getByTestId('trace-event')
    expect(row).toHaveAttribute('data-event-type', 'credential_leak')
    expect(row).toHaveAttribute('data-severity', 'info')
  })

  it('truncates payloadPreview to 500 characters with an ellipsis when longer', () => {
    const longText = 'x'.repeat(750)
    const events: TraceEvent[] = [
      { ...BASE_EVENT, id: 'long', type: 'llm_call', severity: 'info', payloadPreview: longText },
    ]
    render(<TraceTimeline events={events} />)

    const row = screen.getByTestId('trace-event')
    const preview = row.querySelector('.trace-event__preview')!
    expect(preview.textContent).toHaveLength(501)
    expect(preview.textContent?.endsWith('…')).toBe(true)
    expect(preview.textContent?.slice(0, 500)).toBe('x'.repeat(500))
  })

  it('leaves payloadPreview untouched when it is ≤ 500 chars', () => {
    const exactlyFiveHundred = 'y'.repeat(500)
    const events: TraceEvent[] = [
      { ...BASE_EVENT, id: 'edge', type: 'llm_call', severity: 'info', payloadPreview: exactlyFiveHundred },
    ]
    render(<TraceTimeline events={events} />)

    const preview = screen.getByTestId('trace-event').querySelector('.trace-event__preview')!
    expect(preview.textContent).toBe(exactlyFiveHundred)
    expect(preview.textContent?.endsWith('…')).toBe(false)
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
