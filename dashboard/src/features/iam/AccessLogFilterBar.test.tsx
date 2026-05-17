import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AccessLogFilterBar } from './AccessLogFilterBar'
import type { AccessLogFilter } from './accessLog'

const IDENTITIES = ['alice@example.com', 'gateway-ci', 'observability-exporter']

describe('AccessLogFilterBar (AAASM-1398)', () => {
  it('renders the three required controls inside the filter bar', () => {
    render(
      <AccessLogFilterBar identities={IDENTITIES} value={{}} onChange={vi.fn()} />,
    )
    expect(screen.getByTestId('access-log-filter-bar')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-filter-identity')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-filter-event-type')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-filter-time-range')).toBeInTheDocument()
    // Custom date inputs only show up when 'custom' is selected.
    expect(screen.queryByTestId('access-log-filter-custom-from')).not.toBeInTheDocument()
    expect(screen.queryByTestId('access-log-filter-custom-to')).not.toBeInTheDocument()
  })

  it('changing identity emits onChange with the new identity', async () => {
    const onChange = vi.fn<(next: AccessLogFilter) => void>()
    render(
      <AccessLogFilterBar identities={IDENTITIES} value={{}} onChange={onChange} />,
    )
    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-identity'),
      'gateway-ci',
    )
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ identity: 'gateway-ci' }),
    )
  })

  it('selecting the empty identity option clears the identity filter to null', async () => {
    const onChange = vi.fn<(next: AccessLogFilter) => void>()
    render(
      <AccessLogFilterBar
        identities={IDENTITIES}
        value={{ identity: 'gateway-ci' }}
        onChange={onChange}
      />,
    )
    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-identity'),
      '',
    )
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ identity: null }),
    )
  })

  it('changing event type emits onChange with the typed event_type value', async () => {
    const onChange = vi.fn<(next: AccessLogFilter) => void>()
    render(
      <AccessLogFilterBar identities={IDENTITIES} value={{}} onChange={onChange} />,
    )
    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-event-type'),
      'key_rotate',
    )
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'key_rotate' }),
    )
  })

  it('selecting custom time range reveals from / to date inputs', async () => {
    const onChange = vi.fn<(next: AccessLogFilter) => void>()
    function Harness() {
      return (
        <AccessLogFilterBar
          identities={IDENTITIES}
          value={{ timeRange: { kind: 'custom', from: '2026-05-10', to: '2026-05-17' } }}
          onChange={onChange}
        />
      )
    }
    render(<Harness />)
    expect(screen.getByTestId('access-log-filter-custom-from')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-filter-custom-to')).toBeInTheDocument()
  })

  it('selecting custom from "Any time" defaults the range to last 7 days', async () => {
    const onChange = vi.fn<(next: AccessLogFilter) => void>()
    render(
      <AccessLogFilterBar identities={IDENTITIES} value={{}} onChange={onChange} />,
    )
    await userEvent.selectOptions(
      screen.getByTestId('access-log-filter-time-range'),
      'custom',
    )
    expect(onChange).toHaveBeenCalledTimes(1)
    const next = onChange.mock.calls[0][0]
    expect(next.timeRange).toMatchObject({ kind: 'custom' })
    // The defaulted from/to span ~7 days.
    if (next.timeRange?.kind !== 'custom') throw new Error('expected custom')
    const fromMs = new Date(next.timeRange.from).getTime()
    const toMs = new Date(next.timeRange.to).getTime()
    const days = (toMs - fromMs) / (24 * 60 * 60 * 1000)
    expect(days).toBeGreaterThanOrEqual(6.5)
    expect(days).toBeLessThanOrEqual(7.5)
  })
})
