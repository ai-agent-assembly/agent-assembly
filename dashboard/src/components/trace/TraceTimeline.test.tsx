import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
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
})
