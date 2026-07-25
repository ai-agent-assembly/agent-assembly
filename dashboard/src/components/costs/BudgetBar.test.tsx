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

  it('renders an empty ok track when no limit is configured', () => {
    render(<BudgetBar used={42} limit={null} label="daily" />)
    const bar = screen.getByTestId('costs-budget-bar')
    expect(bar.getAttribute('aria-label')).toBe('daily 0%')
    expect(bar.dataset.thresholdBucket).toBe('ok')
  })
})
