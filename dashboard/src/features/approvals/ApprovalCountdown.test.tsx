import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { ApprovalCountdown } from './ApprovalCountdown'

const FIXED_NOW = new Date('2026-05-20T12:00:00Z').getTime()

function plus(ms: number): string {
  return new Date(FIXED_NOW + ms).toISOString()
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(FIXED_NOW)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('ApprovalCountdown', () => {
  it('renders mm:ss with low-tier colour when remaining > 5min', () => {
    render(<ApprovalCountdown expiresAt={plus(10 * 60 * 1000)} />)
    const el = screen.getByTestId('approval-countdown')
    expect(el).toHaveTextContent('10:00')
    expect(el.getAttribute('data-tier')).toBe('low')
    expect((el as HTMLElement).style.color).toBe('var(--ink-3)')
  })

  it('renders medium-tier colour when 1min <= remaining < 5min', () => {
    render(<ApprovalCountdown expiresAt={plus(3 * 60 * 1000)} />)
    const el = screen.getByTestId('approval-countdown')
    expect(el.getAttribute('data-tier')).toBe('medium')
    expect((el as HTMLElement).style.color).toBe('var(--warn)')
  })

  it('renders high-tier colour when remaining < 1min', () => {
    render(<ApprovalCountdown expiresAt={plus(30 * 1000)} />)
    const el = screen.getByTestId('approval-countdown')
    expect(el).toHaveTextContent('00:30')
    expect(el.getAttribute('data-tier')).toBe('high')
    expect((el as HTMLElement).style.color).toBe('var(--danger)')
  })

  it('ticks every 10s while remaining > 60s', () => {
    render(<ApprovalCountdown expiresAt={plus(2 * 60 * 1000)} />)
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('02:00')

    // After 9s, no tick has fired yet.
    act(() => { vi.advanceTimersByTime(9_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('02:00')

    // At 10s, the slow timer fires.
    act(() => { vi.advanceTimersByTime(1_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('01:50')
  })

  it('switches to 1s cadence once remaining drops below 60s', () => {
    render(<ApprovalCountdown expiresAt={plus(65 * 1000)} />)
    // First slow tick at 10s — drops to 55s remaining, fast cadence engages.
    act(() => { vi.advanceTimersByTime(10_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('00:55')

    // From now on, tick every 1s.
    act(() => { vi.advanceTimersByTime(1_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('00:54')
    act(() => { vi.advanceTimersByTime(1_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('00:53')
  })

  it('fires onExpire exactly once when remaining reaches zero', () => {
    const onExpire = vi.fn()
    render(<ApprovalCountdown expiresAt={plus(2_000)} onExpire={onExpire} />)

    // Two 1s ticks bring remaining to zero. Stepping per-tick lets React
    // re-render between firings so the next setTimeout is installed.
    act(() => { vi.advanceTimersByTime(1_000) })
    act(() => { vi.advanceTimersByTime(1_000) })
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('00:00')
    expect(onExpire).toHaveBeenCalledTimes(1)

    // Subsequent ticks are no-ops; no timers remain, but the once-only
    // guard would still prevent a duplicate call if any fired.
    act(() => { vi.advanceTimersByTime(10_000) })
    expect(onExpire).toHaveBeenCalledTimes(1)
  })

  it('fires onExpire immediately for an already-expired timestamp', () => {
    const onExpire = vi.fn()
    render(<ApprovalCountdown expiresAt={plus(-5_000)} onExpire={onExpire} />)
    expect(onExpire).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('approval-countdown')).toHaveTextContent('00:00')
  })
})
