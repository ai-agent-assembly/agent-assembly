import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BudgetBar } from './BudgetBar'

describe('BudgetBar', () => {
  it('buckets ok / warn / danger by burn ratio', () => {
    const { rerender } = render(<BudgetBar used={50} limit={100} label="daily" />)
    expect(screen.getByTestId('costs-budget-bar').dataset.thresholdBucket).toBe('ok')

    rerender(<BudgetBar used={85} limit={100} label="daily" />)
    expect(screen.getByTestId('costs-budget-bar').dataset.thresholdBucket).toBe('warn')

    rerender(<BudgetBar used={99} limit={100} label="daily" />)
    expect(screen.getByTestId('costs-budget-bar').dataset.thresholdBucket).toBe('danger')
  })

  it('clamps an over-budget bar to 100% rather than overflowing', () => {
    render(<BudgetBar used={210} limit={100} label="daily" />)
    const bar = screen.getByTestId('costs-budget-bar')
    expect(bar.getAttribute('aria-label')).toBe('daily 100%')
    expect(bar.dataset.thresholdBucket).toBe('danger')
  })

  it('a measured $0 spend against a real limit is a real 0% — not an absence', () => {
    render(<BudgetBar used={0} limit={100} label="daily" />)
    const bar = screen.getByTestId('costs-budget-bar')
    expect(bar.getAttribute('aria-label')).toBe('daily 0%')
    expect(bar.dataset.thresholdBucket).toBe('ok')
    expect(bar.dataset.truthState).toBeUndefined()
  })

  describe('AAASM-5127 — an unknown ceiling is never painted as headroom', () => {
    it('does not bucket, fill or claim a percentage when no limit is configured', () => {
      render(<BudgetBar used={42} limit={null} label="daily" />)
      const bar = screen.getByTestId('costs-budget-bar')

      expect(bar.dataset.truthState).toBe('unconfigured')
      // The regression: `bucket = hasLimit ? … : 'ok'` painted this green.
      expect(bar.dataset.thresholdBucket).toBeUndefined()
      expect(bar.getAttribute('aria-label')).not.toContain('%')
      expect(bar.getAttribute('aria-label')).toBe('daily unknown — no limit is configured')
      // A zero-width fill is still a rendered measurement of zero.
      expect(bar.querySelector('.costs-budget-bar__fill')).toBeNull()
    })

    it('reports an absent spend figure as unknown rather than as no burn', () => {
      render(<BudgetBar used={null} limit={5000} label="monthly" />)
      const bar = screen.getByTestId('costs-budget-bar')

      expect(bar.dataset.truthState).toBe('unknown')
      expect(bar.dataset.thresholdBucket).toBeUndefined()
      expect(bar.getAttribute('aria-label')).toBe('monthly unknown — no spend figure is available')
      expect(bar.querySelector('.costs-budget-bar__fill')).toBeNull()
    })

    it('treats a configured $0 ceiling as fully burnt, not as ok', () => {
      // A real ceiling, not an absent one: the gateway denies on
      // `spent >= limit`, so $0 has already been reached. `bucketForBudget`
      // maps `limit <= 0` to `ok`, which is the same false green.
      render(<BudgetBar used={12} limit={0} label="daily" />)
      const bar = screen.getByTestId('costs-budget-bar')

      expect(bar.dataset.truthState).toBeUndefined()
      expect(bar.dataset.thresholdBucket).toBe('danger')
      expect(bar.getAttribute('aria-label')).toBe('daily 100%')
    })
  })
})
